"""Every list and threshold the detectors use, loaded from one JSON file.

Nothing here is a production rule set. The allowlists in particular are the map
of what never gets flagged, so they belong in your own config, not in code.
`config.example.json` holds documentation-range addresses and placeholder names.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Config:
    # --- registration source scoring ---
    high_risk_countries: frozenset[str] = frozenset()
    country_scores: dict[str, int] = field(default_factory=dict)
    default_country_score: int = 5
    # Provider (ISP / org / AS) substrings tied to confirmed fraud: flagged outright.
    provider_watchlist: tuple[str, ...] = ()
    # Org substrings whose registrations are expected from datacenters (an
    # integration partner's gateways, say): reasons are kept but not flagged.
    org_allowlist: tuple[str, ...] = ()
    # Your own SBCs, carriers and gateways: never evaluated.
    infra_ips: frozenset[str] = frozenset()
    infra_prefixes: tuple[str, ...] = ()
    # Softphone push relays register from the cloud on the app's behalf. A push
    # user agent is only trusted from one of these providers; from any other
    # datacenter it is a spoofed user agent.
    push_relay_ua_patterns: tuple[str, ...] = ()
    trusted_push_providers: tuple[str, ...] = ()
    # "user@domain" or "device@domain" pairs known to travel (never flagged).
    device_allowlist: frozenset[str] = frozenset()
    # How stale a registration expiry may be and still count as live.
    registration_grace_seconds: int = 45

    # --- call pattern scoring ---
    call_window_minutes: int = 5
    call_flag_floor: int = 5
    # A known, legitimate heavy caller: its suspicious-call count is the ceiling
    # other tenants are measured against. Empty means the floor alone decides.
    call_baseline_domain: str = ""
    call_include_international: bool = True
    call_default_home_state: str = "CA"
    call_home_state_by_domain: dict[str, str] = field(default_factory=dict)
    call_exclude_domains: frozenset[str] = frozenset()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Config":
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(raw) - known - {"_comment"})
        if unknown:
            raise ValueError(f"unknown config keys: {unknown}")
        kw: dict[str, Any] = {}
        for f in fields(cls):
            if f.name not in raw:
                continue
            v = raw[f.name]
            if f.name in ("high_risk_countries",):
                kw[f.name] = frozenset(str(x).upper() for x in v)
            elif f.name in ("infra_ips",):
                kw[f.name] = frozenset(str(x) for x in v)
            elif f.name in ("device_allowlist", "call_exclude_domains"):
                kw[f.name] = frozenset(str(x).strip().lower() for x in v)
            elif f.name in ("provider_watchlist", "org_allowlist", "push_relay_ua_patterns",
                            "trusted_push_providers"):
                kw[f.name] = tuple(str(x).strip().lower() for x in v if str(x).strip())
            elif f.name == "infra_prefixes":
                kw[f.name] = tuple(str(x) for x in v)
            elif f.name == "country_scores":
                kw[f.name] = {str(k).upper(): _score(s, k) for k, s in v.items()}
            elif f.name == "call_home_state_by_domain":
                kw[f.name] = {str(k).strip().lower(): str(s).strip().upper() for k, s in v.items()}
            elif f.name == "call_default_home_state":
                kw[f.name] = str(v).strip().upper()
            else:
                kw[f.name] = v
        return cls(**kw)

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _score(v: Any, key: Any) -> int:
    s = int(v)
    if not 1 <= s <= 10:
        raise ValueError(f"country score for {key} must be 1-10, got {s}")
    return s
