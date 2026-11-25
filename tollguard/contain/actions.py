"""Plan, apply and verify containment on one or more switches.

Plans only read. Each target gets an `action`; only the change actions are
applied, and everything else (already locked, not on this switch, changed since
the lock, switch unreachable) is reported, never silently dropped.

Apply writes, then READS BACK: a write the switch accepted but did not keep is
a failure, not a success. Reads are retried because some switches lag after a
write. A wall-clock budget stops a long batch, and anything not reached comes
back as NOT ATTEMPTED.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable

from ..pbx import DENY_ALL, DOMAIN_ACTIVE, DOMAIN_LOCKED, Pbx
from .ledger import Ledger

logger = logging.getLogger("tollguard.contain")

MAX_USERS = 25
CHANGE_ACTIONS = ("set_deny_all", "restore", "lock_domain", "unlock_domain", "hang_up")


def normalise_users(users: Any) -> list[str]:
    """Explicit extensions only, de-duplicated, order kept. Raises ValueError."""
    raw = [users] if isinstance(users, (str, int)) else list(users or [])
    out: list[str] = []
    for u in raw:
        s = str(u).strip()
        if not s:
            continue
        if s.lower() == "all" or "*" in s:
            raise ValueError("wildcards are not allowed; list the extensions.")
        if s not in out:
            out.append(s)
    if not out:
        raise ValueError("no users given; pass the extension(s), e.g. [\"204\"].")
    if len(out) > MAX_USERS:
        raise ValueError(f"{len(out)} users in one call; the limit is {MAX_USERS}.")
    return out


def _summary(domain: str, targets: list[dict], errors: list[str], change: str) -> dict[str, Any]:
    out: dict[str, Any] = {"domain": domain, "targets": targets,
                           "to_change": sum(t["action"] == change for t in targets)}
    if errors:
        out["errors"] = errors
        out["complete"] = False
    return out


def _unreachable(label: str, what: str, e: Exception, errors: list[str]) -> None:
    errors.append(f"{label}: could not read {what} ({str(e)[:160]})")


def plan_lock_users(clients: dict[str, Pbx], domain: str, users: list[str]) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    errors: list[str] = []
    for label, pbx in clients.items():
        for u in users:
            try:
                row = pbx.get_user(domain, u)
            except Exception as e:  # noqa: BLE001 - one switch failing must not hide the other
                _unreachable(label, f"{u}@{domain}", e, errors)
                targets.append({"pbx": label, "user": u, "found": None,
                                "action": "unknown_switch_unreachable"})
                continue
            if row is None:
                targets.append({"pbx": label, "user": u, "found": False,
                                "action": "skip_not_on_this_switch"})
                continue
            cur = row.get("dial_policy") or ""
            targets.append({"pbx": label, "user": u, "found": True, "name": row.get("name"),
                            "current": cur, "new": DENY_ALL,
                            "action": "already_deny_all" if cur == DENY_ALL else "set_deny_all"})
    out = _summary(domain, targets, errors, "set_deny_all")
    out["already_locked"] = sum(t["action"] == "already_deny_all" for t in targets)
    missing = [u for u in users if not any(t["user"] == u and t["found"] is not False
                                           for t in targets)]
    if missing:
        out["not_found_anywhere"] = missing
    return out


def plan_restore_users(clients: dict[str, Pbx], domain: str, users: list[str],
                       ledger: Ledger) -> dict[str, Any]:
    locks = ledger.open_user_locks(domain)
    dom = domain.lower()
    targets: list[dict[str, Any]] = []
    errors: list[str] = []
    for label, pbx in clients.items():
        for u in users:
            rec = locks.get((label, dom, u))
            if rec is None:
                continue
            base = {"pbx": label, "user": u, "new": rec["restore_to"], "locked_by": rec["by"],
                    "locked_at": rec["at_utc"], "ledger_seq": rec["seq"]}
            try:
                row = pbx.get_user(domain, u)
            except Exception as e:  # noqa: BLE001 - per switch, loudly
                _unreachable(label, f"{u}@{domain}", e, errors)
                targets.append(dict(base, action="unknown_switch_unreachable"))
                continue
            if row is None:
                targets.append(dict(base, current=None, action="skip_user_no_longer_exists"))
                continue
            cur = row.get("dial_policy") or ""
            # Changed by a person since the lock: writing the old value back would
            # silently undo their change, so leave it and say so.
            targets.append(dict(base, name=row.get("name"), current=cur,
                                action="restore" if cur == DENY_ALL else "skip_changed_since_lock"))
    out = _summary(domain, targets, errors, "restore")
    no_record = [u for u in users if not any(t["user"] == u for t in targets)]
    if no_record:
        out["no_lock_record"] = no_record
    return out


def plan_lock_domain(clients: dict[str, Pbx], domain: str) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    errors: list[str] = []
    for label, pbx in clients.items():
        try:
            row = pbx.get_domain(domain)
        except Exception as e:  # noqa: BLE001 - per switch, loudly
            _unreachable(label, f"domain {domain}", e, errors)
            targets.append({"pbx": label, "action": "unknown_switch_unreachable"})
            continue
        if row is None:
            targets.append({"pbx": label, "action": "skip_not_on_this_switch"})
            continue
        cur = str(row.get("policy") or "").lower()
        targets.append({"pbx": label, "current": cur, "new": DOMAIN_LOCKED,
                        "action": "already_locked" if cur == DOMAIN_LOCKED else "lock_domain"})
    return _summary(domain, targets, errors, "lock_domain")


def plan_unlock_domain(clients: dict[str, Pbx], domain: str, ledger: Ledger) -> dict[str, Any]:
    locks = ledger.open_domain_locks(domain)
    dom = domain.lower()
    targets: list[dict[str, Any]] = []
    errors: list[str] = []
    for label, pbx in clients.items():
        rec = locks.get((label, dom))
        try:
            row = pbx.get_domain(domain)
        except Exception as e:  # noqa: BLE001 - per switch, loudly
            _unreachable(label, f"domain {domain}", e, errors)
            targets.append({"pbx": label, "action": "unknown_switch_unreachable"})
            continue
        if row is None:
            if rec:
                targets.append({"pbx": label, "action": "skip_domain_no_longer_exists"})
            continue
        cur = str(row.get("policy") or "").lower()
        t: dict[str, Any] = {"pbx": label, "current": cur, "new": DOMAIN_ACTIVE}
        if rec:
            t.update(locked_by=rec["by"], locked_at=rec["at_utc"], ledger_seq=rec["seq"])
        if cur != DOMAIN_LOCKED:
            t["action"] = "skip_not_locked"
        elif not rec:
            t["action"] = "refused_locked_outside_this_tool"
        else:
            t["action"] = "unlock_domain"
        targets.append(t)
    return _summary(domain, targets, errors, "unlock_domain")


def plan_hang_up(clients: dict[str, Pbx], call_id: str) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    errors: list[str] = []
    domain = ""
    for label, pbx in clients.items():
        try:
            live = {c.call_id: c for c in pbx.list_active_calls()}
        except Exception as e:  # noqa: BLE001 - per switch, loudly
            _unreachable(label, "active calls", e, errors)
            continue
        c = live.get(call_id)
        if c is not None:
            domain = c.domain
            targets.append({"pbx": label, "call_id": call_id, "user": c.user,
                            "dialed": c.dialed, "current": "live", "new": "ended",
                            "action": "hang_up"})
    out = _summary(domain, targets, errors, "hang_up")
    if not targets:
        out["not_found"] = call_id
    return out


def _verify(read_now: Callable[[], Any], want: Any, tries: int, delay_s: float,
            sleep: Callable[[float], None]) -> tuple[Any, str | None]:
    now: Any = None
    err: str | None = None
    for i in range(max(1, tries)):
        if i:
            sleep(delay_s)
        try:
            now, err = read_now(), None
        except Exception as e:  # noqa: BLE001 - a failed read-back is UNVERIFIED, never success
            now, err = None, f"written, but the read-back failed ({str(e)[:160]}); UNVERIFIED"
        if now == want:
            break
    return now, err


def apply(clients: dict[str, Pbx], domain: str, preview: dict[str, Any], *,
          readback_tries: int = 4, readback_delay_s: float = 1.5,
          sleep: Callable[[float], None] = time.sleep,
          budget_s: float | None = None) -> list[dict[str, Any]]:
    deadline = None if budget_s is None else time.monotonic() + budget_s
    results: list[dict[str, Any]] = []
    for t in preview["targets"]:
        act = t["action"]
        if act not in CHANGE_ACTIONS:
            continue
        label, pbx = t["pbx"], clients[t["pbx"]]
        kind = {"set_deny_all": "user", "restore": "user", "hang_up": "call"}.get(act, "domain")
        res: dict[str, Any] = {"pbx": label, "target": kind, "user": t.get("user"),
                               "old": t.get("current"), "new": t.get("new"), "ok": False}
        if kind == "call":
            res["call_id"] = t["call_id"]
        if deadline is not None and time.monotonic() > deadline:
            res["error"] = "NOT ATTEMPTED: ran out of time. Run the same request again."
            results.append(res)
            continue
        try:
            if kind == "user":
                pbx.set_dial_policy(domain, t["user"], t["new"])
            elif kind == "domain":
                pbx.set_domain_policy(domain, t["new"])
            else:
                pbx.hang_up(t["call_id"])
        except Exception as e:  # noqa: BLE001 - reported per item; one failure never aborts the batch
            res["error"] = f"write failed: {str(e)[:200]}"
            logger.error("CONTAIN WRITE FAILED action=%s pbx=%s target=%s domain=%s: %s",
                         act, label, t.get("user") or t.get("call_id") or "(domain)", domain, e)
            results.append(res)
            continue
        if kind == "user":
            def read_now(p=pbx, u=t["user"]):
                row = p.get_user(domain, u)
                return None if row is None else (row.get("dial_policy") or "")
        elif kind == "domain":
            def read_now(p=pbx):
                row = p.get_domain(domain)
                return None if row is None else str(row.get("policy") or "").lower()
        else:
            def read_now(p=pbx, cid=t["call_id"]):
                return "live" if any(c.call_id == cid for c in p.list_active_calls()) else "ended"
        now, err = _verify(read_now, t["new"], readback_tries, readback_delay_s, sleep)
        res["verified"] = now
        res["ok"] = now == t["new"]
        if err:
            res["error"] = err
        elif not res["ok"]:
            res["error"] = f"the switch accepted the write but reads back {now!r}; NOT changed"
        results.append(res)
    return results


def record(ledger: Ledger, caller: str, via: str, action: str, domain: str,
           results: list[dict[str, Any]], ticket: str | None,
           reason: str | None) -> dict[str, Any]:
    for r in results:
        logger.warning("CONTAIN action=%s by=%s via=%s pbx=%s domain=%s target=%s %r -> %r ok=%s",
                       action, caller, via, r["pbx"], domain,
                       r.get("user") or r.get("call_id") or "(domain)", r["old"], r["new"], r["ok"])
    if not results:
        return {}
    try:
        return ledger.append({"action": action, "by": caller, "via": via, "domain": domain,
                              "ticket": ticket, "reason": reason, "changes": results})
    except OSError as e:
        logger.error("LEDGER WRITE FAILED action=%s domain=%s: %s", action, domain, e)
        return {"ledger_error": (f"the change was made but could NOT be written to the ledger "
                                 f"({e}); the tool cannot undo it. Record the old values shown.")}
