"""Scan-to-scan memory: which IPs are flagged, and which devices are compromised.

The unit that matters is the DEVICE, not the IP. One bad IP can carry several
devices, and the fix is per device: change its SIP password. So a device is
cleared only when BOTH are true:

    its password was reset during the current episode   AND   it stopped registering

    stopped, not reset     -> stays open: it will be back when the attacker retries
    registering, reset     -> stays open: the reset did not take (wrong device, cached creds)
    stopped and reset      -> resolved

A device that comes back after being resolved is a REPEAT OFFENDER: the new
credentials leaked too, which usually means the leak is upstream of the phone
(a reused password, a compromised provisioning file, a staff laptop).

The IP flag is simpler: an IP that no longer registers is cleared, and a flag is
announced once per flagging, not every scan.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .registrations import Verdict


def empty() -> dict[str, Any]:
    return {"ips": {}, "devices": {}, "resets": []}


def load(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return empty()
    data = json.loads(p.read_text(encoding="utf-8"))
    for k, v in empty().items():
        data.setdefault(k, v)
    return data


def save(state: dict[str, Any], path: str | Path) -> None:
    """Write-then-rename, so a crash mid-write never leaves half a state file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=p.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1, sort_keys=True)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def record_reset(state: dict[str, Any], domain: str, device: str, at: str,
                 user: str = "", by: str = "") -> None:
    """Log that a device's SIP password was changed (by a person, or by a tool)."""
    state["resets"].append({"domain": domain.lower(), "device": device, "user": user,
                            "at": at, "by": by, "undone": False})


@dataclass
class Events:
    new_flags: list[str] = field(default_factory=list)          # IPs flagged and not yet announced
    cleared_ips: list[str] = field(default_factory=list)        # flagged IPs no longer registering
    new_compromised: list[str] = field(default_factory=list)    # device keys, new episode
    repeats: list[str] = field(default_factory=list)            # back after a resolved reset
    resolved: list[str] = field(default_factory=list)
    open_not_registering: list[str] = field(default_factory=list)   # stopped, but never reset
    open_reset_ineffective: list[str] = field(default_factory=list)  # reset, still registering


def _latest_reset(state: dict[str, Any], domain: str, device: str, user: str,
                  since: str) -> str | None:
    best = None
    for r in state["resets"]:
        if r.get("undone") or r["domain"] != domain.lower():
            continue
        if r["device"] not in (device, user) and (not r.get("user") or r["user"] != user):
            continue
        if r["at"] >= since and (best is None or r["at"] > best):
            best = r["at"]
    return best


def advance(state: dict[str, Any], verdicts: Iterable[Verdict], now: str) -> Events:
    """Fold one scan's verdicts into the state. `now` is an ISO-8601 UTC string.
    Mutates and returns events; the caller saves."""
    ev = Events()
    verdicts = list(verdicts)
    seen = {v.ip for v in verdicts}
    ips = state["ips"]
    for v in verdicts:
        e = ips.setdefault(v.ip, {"first_seen": now, "notified": False})
        was = e.get("flagged", False)
        e.update(flagged=v.is_fraud, reasons=list(v.reasons), last_seen=now,
                 watchlisted=v.watchlisted)
        if was and not v.is_fraud:
            e["notified"] = False
        if v.is_fraud and not e.get("notified"):
            e["notified"] = True
            e["notified_at"] = now
            ev.new_flags.append(v.ip)
    for ip, e in ips.items():
        if e.get("flagged") and ip not in seen:
            e.update(flagged=False, notified=False, cleared_at=now,
                     cleared_reason="no longer registering")
            ev.cleared_ips.append(ip)

    devices = state["devices"]
    active_now: dict[str, dict[str, Any]] = {}
    for v in verdicts:
        if not v.is_fraud:
            continue
        for r in v.devices:
            key = f"{r.device}@{r.domain.lower()}"
            active_now[key] = {"device": r.device, "user": r.user, "domain": r.domain.lower(),
                               "ip": v.ip, "user_agent": r.user_agent,
                               "watchlisted": v.watchlisted}
    for key, info in active_now.items():
        rec = devices.setdefault(key, {"episodes": 0, "first_seen": now})
        prior, prior_reset = rec.get("status"), rec.get("reset_at")
        rec.update(info)
        if prior != "active":
            rec["episodes"] += 1
            rec["episode_started_at"] = now
            rec["repeat"] = False
            if prior == "resolved" and prior_reset:
                rec["repeat"] = True
                rec["repeat_count"] = rec.get("repeat_count", 0) + 1
                ev.repeats.append(key)
            else:
                ev.new_compromised.append(key)
        rec.update(status="active", registering=True, last_seen=now, resolved_at=None)
        rec["reset_at"] = _latest_reset(state, info["domain"], info["device"], info["user"],
                                        rec["episode_started_at"])
        if rec["reset_at"]:
            ev.open_reset_ineffective.append(key)
    for key, rec in devices.items():
        if rec.get("status") != "active" or key in active_now:
            continue
        rec["registering"] = False
        rec["reset_at"] = rec.get("reset_at") or _latest_reset(
            state, rec["domain"], rec["device"], rec.get("user", ""), rec["episode_started_at"])
        if rec["reset_at"]:
            rec.update(status="resolved", resolved_at=now)
            ev.resolved.append(key)
        else:
            ev.open_not_registering.append(key)
    return ev


def open_devices(state: dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(rec, key=k) for k, rec in sorted(state["devices"].items())
            if rec.get("status") == "active"]
