import json

from tollguard.contain import CodeBook, Ledger, MemoryNotifier, Policy


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def book():
    n, c = MemoryNotifier(), Clock()
    return CodeBook(n, ttl_s=600, max_attempts=3, clock=c), n, c


def test_code_is_single_use_and_bound_to_the_exact_request():
    b, n, _ = book()
    assert b.issue("a@x", "lock_users", "t.example", "users=102|pbx=new", "d")[0]
    code = n.last("a@x")
    for who, act, dom, scope in [("b@x", "lock_users", "t.example", "users=102|pbx=new"),
                                 ("a@x", "lock_domain", "t.example", "users=102|pbx=new"),
                                 ("a@x", "lock_users", "u.example", "users=102|pbx=new"),
                                 ("a@x", "lock_users", "t.example", "users=103|pbx=new"),
                                 ("a@x", "lock_users", "t.example", "users=102|pbx=old+new")]:
        ok, why = b.redeem(who, act, dom, scope, code)
        assert not ok and "no code is waiting" in why
    assert b.redeem("A@X", "lock_users", "T.example", "users=102|pbx=new", code) == (True, "verified")
    assert not b.redeem("a@x", "lock_users", "t.example", "users=102|pbx=new", code)[0]


def test_expiry_and_attempt_limit():
    b, n, clock = book()
    b.issue("a@x", "act", "d", "s", "")
    clock.t += 601
    assert "expired" in b.redeem("a@x", "act", "d", "s", n.last("a@x"))[1]
    b.issue("a@x", "act", "d", "s", "")
    code = n.last("a@x")
    wrong = "000000" if code != "000000" else "111111"
    assert "2 attempt" in b.redeem("a@x", "act", "d", "s", wrong)[1]
    assert "1 attempt" in b.redeem("a@x", "act", "d", "s", wrong)[1]
    assert "0 attempt" in b.redeem("a@x", "act", "d", "s", wrong)[1]
    assert not b.redeem("a@x", "act", "d", "s", code)[0]        # cancelled after three


def test_reissue_replaces_and_delivery_failure_issues_nothing():
    b, n, _ = book()
    b.issue("a@x", "act", "d", "s", "")
    first = n.last("a@x")
    b.issue("a@x", "act", "d", "s", "")
    second = n.last("a@x")
    if first != second:
        assert not b.redeem("a@x", "act", "d", "s", first)[0]
    n.fail = True
    ok, why = b.issue("a@x", "act2", "d", "s", "")
    assert not ok and "could not be sent" in why
    assert "no code is waiting" in b.redeem("a@x", "act2", "d", "s", "123456")[1]


def test_ledger_sequence_open_locks_and_first_value_wins(tmp_path):
    lg = Ledger(tmp_path / "l.jsonl")
    ch = lambda old, ok=True: [{"pbx": "new", "user": "102", "old": old, "new": "Deny All", "ok": ok}]
    lg.append({"action": "lock_users", "domain": "T.example", "by": "a", "changes": ch("International")})
    lg.append({"action": "lock_users", "domain": "t.example", "by": "a", "changes": ch("Deny All")})
    lg.append({"action": "lock_users", "domain": "t.example", "by": "a",
               "changes": [{"pbx": "new", "user": "103", "old": "X", "new": "Deny All", "ok": False}]})
    locks = lg.open_user_locks("t.example")
    assert list(locks) == [("new", "t.example", "102")]
    assert locks[("new", "t.example", "102")]["restore_to"] == "International"
    assert [e["seq"] for e in lg.history()] == [1, 2, 3]
    lg.append({"action": "restore_users", "domain": "t.example", "by": "a",
               "changes": [{"pbx": "new", "user": "102", "old": "Deny All", "new": "International", "ok": True}]})
    assert lg.open_user_locks() == {}


def test_corrupt_ledger_line_is_skipped_loudly(tmp_path):
    p = tmp_path / "l.jsonl"
    p.write_text(json.dumps({"seq": 1, "action": "lock_domain", "domain": "t.example",
                             "changes": [{"pbx": "new", "old": "active", "new": "locked", "ok": True}]})
                 + "\n{not json\n", encoding="utf-8")
    lg = Ledger(p)
    assert list(lg.open_domain_locks()) == [("new", "t.example")]
    assert lg.corrupt_lines == [2]
    assert lg.append({"action": "unlock_domain", "domain": "t.example", "changes": [
        {"pbx": "new", "old": "locked", "new": "active", "ok": True}]})["seq"] == 2
    assert lg.open_domain_locks() == {}


def test_policy_fails_closed():
    p = Policy.of(allowed=["Eng@x"], domain_allowed=["lead@x"], gateways=["gw-app"])
    assert p.may_act("eng@x", "direct")[0]
    assert p.may_act("anyone@x", "gw-app")[0]                 # the gateway's group decides
    assert not p.may_act("anyone@x", "direct")[0]
    assert not p.may_act("anonymous", "gw-app")[0]           # no identity, no action
    assert p.may_lock_domain("lead@x", "direct")[0]
    assert not p.may_lock_domain("lead@x", "gw-app")[0]      # never through a gateway
    assert not p.may_lock_domain("eng@x", "direct")[0]
    assert "disabled" in Policy.of(allowed=["eng@x"]).may_lock_domain("eng@x", "direct")[1]
