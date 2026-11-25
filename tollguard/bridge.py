"""Findings in, proposals out. Never acts.

This is the seam between detection and containment. Detection runs unattended
on a schedule; containment changes a customer's phone service and needs a
person. So the detectors produce proposals, each naming the exact preview call
to make (confirm=False), and a person (or an agent working with one) takes it
from there through the code-gated flow.

What gets proposed:
  * lock_users for every open compromised device's user, per domain, and for
    the users a flagged call pattern points at;
  * hang_up for any live call by one of those users that is leaving the country
    or the caller's state;
  * lock_domain only when one tenant has more compromised users than a user
    lock can sensibly cover (config: domain_lock_at), because a domain lock
    takes every user offline.
A repeat offender (compromised again after a resolved reset) raises severity:
the leak is upstream of the phone, so a password change alone will not hold.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .calls import CallScan, caller_home_state, classify_call
from .config import Config
from .pbx import ActiveCall
from .state import open_devices


@dataclass
class Proposal:
    action: str                      # lock_users | lock_domain | hang_up
    domain: str
    severity: str                    # high | critical
    users: list[str] = field(default_factory=list)
    call_id: str = ""
    evidence: list[str] = field(default_factory=list)

    def preview_call(self) -> dict[str, Any]:
        """The exact first (read-only) call to make. confirm stays False."""
        if self.action == "hang_up":
            return {"tool": "hang_up_call", "arguments": {"call_id": self.call_id, "confirm": False}}
        args: dict[str, Any] = {"domain": self.domain, "confirm": False}
        if self.action == "lock_users":
            args["users"] = self.users
        return {"tool": self.action, "arguments": args}


def propose(state: dict[str, Any], calls: CallScan | None, cfg: Config,
            live_calls: Iterable[ActiveCall] = (), domain_lock_at: int = 10) -> list[Proposal]:
    by_domain: dict[str, Proposal] = {}

    def lock(domain: str) -> Proposal:
        return by_domain.setdefault(domain, Proposal("lock_users", domain, "high"))

    for d in open_devices(state):
        p = lock(d["domain"])
        user = d.get("user") or d["device"]
        if user not in p.users:
            p.users.append(user)
        how = "still registering" if d.get("registering") else "stopped, password never reset"
        p.evidence.append(f"device {d['device']} (user {user}) registered from {d['ip']}: {how}")
        if d.get("repeat"):
            p.severity = "critical"
            p.evidence.append(f"device {d['device']} is a REPEAT offender (compromised again after "
                              f"a reset): the leak is upstream of the phone")
    for f in (calls.flagged if calls else []):
        p = lock(f.domain)
        for u in f.callers:
            if u not in p.users:
                p.users.append(u)
        p.evidence.append(f"{f.count} suspicious connected calls in the window "
                          f"({f.intl} international, {f.out_of_state} out of state); "
                          f"threshold {calls.threshold}")
        for u in f.callers:
            uc = f.users[u]
            if uc.off_switch:
                p.evidence.append(f"user {u}: INVITEs from {sorted(uc.source_ips)}, not a "
                                  f"registered address of theirs")
        if f.linked_fraud_ips:
            p.severity = "critical"
            p.evidence.append(f"calls came from IPs the registration scan already flagged: "
                              f"{sorted(f.linked_fraud_ips)}")

    out: list[Proposal] = []
    for dom, p in sorted(by_domain.items()):
        if not p.users:
            continue
        if len(p.users) >= domain_lock_at:
            out.append(Proposal("lock_domain", dom, "critical", list(p.users),
                                evidence=[f"{len(p.users)} users compromised in one tenant; a "
                                          f"domain lock stops all of them at once"] + p.evidence))
        out.append(p)
    suspects = {(p.domain, u) for p in out for u in p.users}
    for c in live_calls:
        if (c.domain.lower(), c.user) not in suspects:
            continue
        home = caller_home_state("", cfg.call_home_state_by_domain.get(c.domain.lower()),
                                 cfg.call_default_home_state)
        cls = classify_call(c.dialed, home)
        if cls in ("intl", "out_of_state"):
            out.append(Proposal("hang_up", c.domain.lower(), "critical", [c.user], c.call_id,
                                [f"live {cls} call by suspect user {c.user} to {c.dialed}"]))
    return out
