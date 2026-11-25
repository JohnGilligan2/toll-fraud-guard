import pytest

from tollguard.contain import CodeBook, Containment, Ledger, MemoryNotifier, Policy
from tollguard.contain import actions
from tollguard.pbx import DENY_ALL, ActiveCall, FakePbx

D = "t.example"
ENG, LEAD = "eng@x", "lead@x"


def estate(**new_kw):
    old, new = FakePbx(), FakePbx(**new_kw)
    for p in (old, new):
        p.add_user(D, "102", "International")
        p.add_user(D, "103", "US and Canada")
    new.add_user(D, "104", "US and Canada")              # only on the new switch
    return {"old": old, "new": new}


def guard(clients, tmp_path, tries=4):
    n = MemoryNotifier()
    g = Containment(clients, Ledger(tmp_path / "l.jsonl"), CodeBook(n),
                    Policy.of(allowed=[ENG], domain_allowed=[LEAD], gateways=["gw"]),
                    readback_tries=tries, sleep=lambda s: None)
    return g, n


def approve(g, n, method, caller, *args, **kw):
    """Steps 2 and 3: say yes, get the code, type it."""
    r = getattr(g, method)(caller, *args, confirm=True, **kw)
    assert r["status"] == "passcode_sent", r
    return getattr(g, method)(caller, *args, confirm=True, passcode=n.last(caller), **kw)


def test_full_lock_and_restore_round_trip_on_both_switches(tmp_path):
    c = estate()
    g, n = guard(c, tmp_path)
    pre = g.lock_users(ENG, D, ["102", "104"])
    assert pre["status"] == "confirm_required" and pre["to_change"] == 3
    assert {(t["pbx"], t["user"], t["action"]) for t in pre["targets"]} >= {
        ("old", "104", "skip_not_on_this_switch"), ("new", "104", "set_deny_all")}
    assert c["new"].writes == [] and c["old"].writes == []          # preview changed nothing
    done = approve(g, n, "lock_users", ENG, D, ["102", "104"], ticket="T1", reason="r")
    assert done["status"] == "done" and done["changed"] == 3 and done["ledger_seq"] == 1
    assert c["old"].get_user(D, "102")["dial_policy"] == DENY_ALL
    c["new"].users[(D, "104")]["dial_policy"] = "Permit All"       # someone edits it by hand
    back = approve(g, n, "restore_users", ENG, D, ["102", "104"])
    assert back["status"] == "done" and back["changed"] == 2
    assert c["old"].get_user(D, "102")["dial_policy"] == "International"
    assert c["new"].get_user(D, "102")["dial_policy"] == "International"
    assert [t["action"] for t in back["skipped"]] == ["skip_changed_since_lock"]
    assert c["new"].get_user(D, "104")["dial_policy"] == "Permit All"


def test_a_bare_confirm_or_a_planted_code_changes_nothing(tmp_path):
    c = estate()
    g, n = guard(c, tmp_path)
    r = g.lock_users(ENG, D, ["102"], confirm=True, passcode="123456")
    assert r["status"] == "passcode_rejected"
    assert c["new"].writes == [] and g.ledger.history() == [] and n.sent == []


def test_a_code_for_one_user_cannot_lock_another_or_another_switch(tmp_path):
    c = estate()
    g, n = guard(c, tmp_path)
    g.lock_users(ENG, D, ["102"], confirm=True)
    code = n.last(ENG)
    assert g.lock_users(ENG, D, ["103"], confirm=True, passcode=code)["status"] == "passcode_rejected"
    assert g.lock_users(ENG, D, ["102"], confirm=True, passcode=code,
                        pbx="new")["status"] == "passcode_rejected"
    assert g.lock_users(ENG, D, ["102"], confirm=True, passcode=code)["status"] == "done"


def test_unauthorised_caller_learns_nothing_about_the_switch(tmp_path):
    c = estate(unreachable=True)
    g, _ = guard(c, tmp_path)
    r = g.lock_users("stranger@x", D, ["102"])
    assert r["status"] == "not_authorised" and "targets" not in r
    assert g.lock_users("someone@x", D, ["102"], via="gw")["status"] != "not_authorised"


def test_unreachable_switch_is_unknown_not_missing(tmp_path):
    c = estate()
    c["old"].unreachable = True
    g, n = guard(c, tmp_path)
    pre = g.lock_users(ENG, D, ["102"])
    assert pre["complete"] is False and "old: could not read" in pre["errors"][0]
    assert "not_found_anywhere" not in pre
    done = approve(g, n, "lock_users", ENG, D, ["102"])
    assert done["status"] == "done" and done["changed"] == 1 and done["errors"]


def test_read_after_write_lag_is_retried_and_verified(tmp_path):
    c = estate(read_lag=2)
    g, n = guard(c, tmp_path, tries=4)
    done = approve(g, n, "lock_users", ENG, D, ["104"])
    assert done["status"] == "done" and done["results"][0]["verified"] == DENY_ALL


def test_lag_longer_than_the_retries_is_a_failure_not_a_success(tmp_path):
    c = estate(read_lag=5)
    g, n = guard(c, tmp_path, tries=2)
    done = approve(g, n, "lock_users", ENG, D, ["104"])
    assert done["status"] == "PARTIAL_FAILURE" and "NOT changed" in done["results"][0]["error"]


def test_write_accepted_but_not_kept_is_reported_and_not_restorable(tmp_path):
    c = estate(drop_writes={"102@t.example"})
    g, n = guard(c, tmp_path, tries=1)
    done = approve(g, n, "lock_users", ENG, D, ["102"])
    assert done["status"] == "PARTIAL_FAILURE" and done["changed"] == 1
    assert ("new", D, "102") not in g.ledger.open_user_locks()   # failed rows are not undo-able
    assert ("old", D, "102") in g.ledger.open_user_locks()


def test_budget_leaves_rows_not_attempted(tmp_path):
    c = estate()
    preview = actions.plan_lock_users(c, D, ["102", "103"])
    res = actions.apply(c, D, preview, budget_s=-1, sleep=lambda s: None)
    assert all("NOT ATTEMPTED" in r["error"] for r in res) and c["new"].writes == []


def test_ledger_write_failure_is_surfaced(tmp_path):
    c = estate()
    g, n = guard(c, tmp_path)
    (tmp_path / "blocked").mkdir()
    g.ledger.path = tmp_path / "blocked"            # a directory: the append raises OSError
    done = approve(g, n, "lock_users", ENG, D, ["103"])
    assert "LEDGER_ERROR" in done and "cannot undo" in done["LEDGER_ERROR"]


@pytest.mark.parametrize("users,msg", [(["*"], "wildcards"), ([" "], "no users"),
                                       ([str(i) for i in range(26)], "limit is 25")])
def test_user_list_validation(tmp_path, users, msg):
    g, _ = guard(estate(), tmp_path)
    r = g.lock_users(ENG, D, users)
    assert r["status"] == "error" and msg in r["message"]


def test_domain_lock_needs_its_own_allowlist_and_unlock_only_reopens_our_locks(tmp_path):
    c = estate()
    c["new"].add_user("closed.example", "1")
    c["new"].domains["closed.example"]["policy"] = "locked"
    g, n = guard(c, tmp_path)
    assert g.lock_domain(ENG, D)["status"] == "not_authorised"
    assert g.lock_domain(LEAD, D, via="gw")["status"] == "not_authorised"
    done = approve(g, n, "lock_domain", LEAD, D)
    assert done["status"] == "done" and done["changed"] == 2
    r = g.unlock_domain(ENG, "closed.example")
    assert r["status"] == "nothing_to_do"
    assert r["targets"][0]["action"] == "refused_locked_outside_this_tool"
    back = approve(g, n, "unlock_domain", ENG, D)
    assert back["status"] == "done" and c["old"].get_domain(D)["policy"] == "active"


def test_hang_up_verifies_the_call_is_gone(tmp_path):
    c = estate()
    c["new"].calls = {"c1": ActiveCall("c1", D, "102", "011442079460000")}
    g, n = guard(c, tmp_path)
    assert g.hang_up(ENG, "nope")["status"] == "nothing_to_do"
    done = approve(g, n, "hang_up", ENG, "c1")
    assert done["status"] == "done" and c["new"].calls == {}
    c["new"].calls = {"c2": ActiveCall("c2", D, "102", "011442079460001")}
    c["new"].drop_writes.add("call:c2")
    assert approve(g, n, "hang_up", ENG, "c2")["status"] == "PARTIAL_FAILURE"


def test_nothing_to_do_never_sends_a_code(tmp_path):
    c = estate()
    for p in c.values():
        p.users[(D, "102")]["dial_policy"] = DENY_ALL
    g, n = guard(c, tmp_path)
    assert g.lock_users(ENG, D, ["102"], confirm=True)["status"] == "nothing_to_do" and n.sent == []
    assert g.restore_users(ENG, D, ["102"])["no_lock_record"] == ["102"]
