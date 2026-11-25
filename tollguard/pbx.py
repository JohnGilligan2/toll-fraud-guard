"""The PBX surface this package needs, and an in-memory fake for tests and the demo.

A real adapter implements `Pbx` against your switch's API. A multi-tenant
hosted PBX keeps a dial policy per user and a policy per domain (tenant); a
migration can leave one tenant on two switches at once, which is why the
containment code takes a dict of switches, not one.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

DENY_ALL = "Deny All"
DOMAIN_ACTIVE = "active"
DOMAIN_LOCKED = "locked"


class PbxUnavailable(RuntimeError):
    """The switch did not answer. Callers report this as unknown, never as 'not found'."""


@dataclass(frozen=True)
class Registration:
    domain: str
    user: str
    device: str
    received_from: str          # "ip:port" the REGISTER arrived from
    user_agent: str = ""
    expires_at: datetime | None = None   # UTC
    mode: str = "registered"
    pbx: str = "main"


@dataclass(frozen=True)
class Cdr:
    domain: str
    calling_user: str
    caller_id: str
    dialed: str
    talk_seconds: int
    source_host: str = ""       # host part of the From URI: the domain on-net, an IP if off-switch
    start: int = 0              # epoch seconds


@dataclass(frozen=True)
class ActiveCall:
    call_id: str
    domain: str
    user: str
    dialed: str
    started: int = 0


class Pbx(Protocol):
    def list_registrations(self) -> list[Registration]: ...
    def list_cdrs(self, minutes: int) -> list[Cdr]: ...
    def get_user(self, domain: str, user: str) -> dict[str, Any] | None: ...
    def set_dial_policy(self, domain: str, user: str, policy: str) -> None: ...
    def get_domain(self, domain: str) -> dict[str, Any] | None: ...
    def set_domain_policy(self, domain: str, policy: str) -> None: ...
    def list_active_calls(self) -> list[ActiveCall]: ...
    def hang_up(self, call_id: str) -> None: ...


@dataclass
class FakePbx:
    """In-memory switch with the failure modes that matter for containment.

    read_lag      reads after a write keep returning the old value this many times
                  (a real switch with read-after-write lag)
    drop_writes   keys whose writes are accepted but not kept: "user@domain" or
                  "domain:<name>"
    unreachable   every call raises PbxUnavailable
    """
    users: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    domains: dict[str, dict[str, Any]] = field(default_factory=dict)
    registrations: list[Registration] = field(default_factory=list)
    cdrs: list[Cdr] = field(default_factory=list)
    calls: dict[str, ActiveCall] = field(default_factory=dict)
    read_lag: int = 0
    drop_writes: set[str] = field(default_factory=set)
    unreachable: bool = False
    writes: list[tuple[str, ...]] = field(default_factory=list)
    _stale: dict[str, tuple[Any, int]] = field(default_factory=dict)

    # --- setup helpers ---
    def add_user(self, domain: str, user: str, dial_policy: str = "US and Canada",
                 name: str = "") -> None:
        self.users[(domain.lower(), user)] = {"domain": domain.lower(), "user": user,
                                              "dial_policy": dial_policy, "name": name}
        self.domains.setdefault(domain.lower(), {"domain": domain.lower(),
                                                 "policy": DOMAIN_ACTIVE, "description": ""})

    def _up(self) -> None:
        if self.unreachable:
            raise PbxUnavailable("switch did not answer")

    def _read(self, key: str, value: Any) -> Any:
        stale = self._stale.get(key)
        if stale is not None:
            old, left = stale
            if left > 0:
                self._stale[key] = (old, left - 1)
                return old
            del self._stale[key]
        return value

    # --- Pbx ---
    def list_registrations(self) -> list[Registration]:
        self._up()
        return list(self.registrations)

    def list_cdrs(self, minutes: int) -> list[Cdr]:
        self._up()
        return list(self.cdrs)

    def get_user(self, domain: str, user: str) -> dict[str, Any] | None:
        self._up()
        row = self.users.get((domain.lower(), user))
        if row is None:
            return None
        out = dict(row)
        out["dial_policy"] = self._read(f"{user}@{domain.lower()}", row["dial_policy"])
        return out

    def set_dial_policy(self, domain: str, user: str, policy: str) -> None:
        self._up()
        key = f"{user}@{domain.lower()}"
        row = self.users[(domain.lower(), user)]
        self.writes.append(("dial_policy", key, policy))
        if key in self.drop_writes:
            return
        if self.read_lag:
            self._stale[key] = (row["dial_policy"], self.read_lag)
        row["dial_policy"] = policy

    def get_domain(self, domain: str) -> dict[str, Any] | None:
        self._up()
        row = self.domains.get(domain.lower())
        if row is None:
            return None
        out = dict(row)
        out["policy"] = self._read(f"domain:{domain.lower()}", row["policy"])
        return out

    def set_domain_policy(self, domain: str, policy: str) -> None:
        self._up()
        key = f"domain:{domain.lower()}"
        row = self.domains[domain.lower()]
        self.writes.append(("domain_policy", key, policy))
        if key in self.drop_writes:
            return
        if self.read_lag:
            self._stale[key] = (row["policy"], self.read_lag)
        row["policy"] = policy

    def list_active_calls(self) -> list[ActiveCall]:
        self._up()
        return list(self.calls.values())

    def hang_up(self, call_id: str) -> None:
        self._up()
        self.writes.append(("hang_up", call_id))
        if f"call:{call_id}" in self.drop_writes:
            return
        self.calls.pop(call_id, None)
