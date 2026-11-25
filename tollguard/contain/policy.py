"""Who may contain what. Fails closed.

Two tiers, on purpose:

  lock users / restore users / unlock a domain / hang up a call
      anyone on `allowed_users`, or anyone arriving through a trusted team
      gateway (the gateway's own group membership is that team's access list)

  lock a whole domain
      only `domain_allowed_users`, and NEVER through a team gateway, whoever
      the person is. A gateway profile that lists this tool by mistake must
      still not be able to run it. An empty list disables domain locks.

Every action needs a readable identity, so an unauthenticated deployment can
read findings and do nothing else.
"""
from __future__ import annotations

from dataclasses import dataclass, field

DIRECT = "direct"


def _norm(xs) -> frozenset[str]:
    return frozenset(x.strip().lower() for x in xs if x and x.strip())


@dataclass(frozen=True)
class Policy:
    allowed_users: frozenset[str] = field(default_factory=frozenset)
    domain_allowed_users: frozenset[str] = field(default_factory=frozenset)
    gateways: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def of(cls, allowed=(), domain_allowed=(), gateways=()) -> "Policy":
        return cls(_norm(allowed), _norm(domain_allowed), _norm(gateways))

    @staticmethod
    def _identity_problem(caller: str) -> str | None:
        if (caller or "").strip().lower() in ("", "anonymous", "unknown"):
            return ("no identity could be read for this caller, so the change cannot be "
                    "authorised or logged against a name.")
        return None

    def may_act(self, caller: str, via: str) -> tuple[bool, str]:
        problem = self._identity_problem(caller)
        if problem:
            return False, problem
        if caller.strip().lower() in self.allowed_users:
            return True, "allowlist"
        if (via or "").strip().lower() in self.gateways:
            return True, f"gateway {via}"
        return False, f"{caller} is not authorised to make containment changes."

    def may_lock_domain(self, caller: str, via: str) -> tuple[bool, str]:
        if (via or DIRECT).strip().lower() != DIRECT:
            return False, ("locking a whole domain is not available through a team gateway. "
                           "Lock the compromised users one at a time instead.")
        if not self.domain_allowed_users:
            return False, "no one is configured to lock domains, so domain locks are disabled."
        problem = self._identity_problem(caller)
        if problem:
            return False, problem
        if caller.strip().lower() not in self.domain_allowed_users:
            return False, f"{caller} is not authorised to lock a domain."
        return True, "domain allowlist"
