"""Where is each phone registering from, and should that worry us?

A stolen SIP password shows up first as a registration from somewhere the
customer has never been: a datacenter, a VPN, a country with no staff in it.
This module groups live registrations by source IP and classifies each IP.

Rules, in order:
  1. A push-relay user agent on a trusted push provider is legitimate (softphone
     push relays register from the cloud on the app's behalf). Stop.
  2. A provider on the watchlist is flagged outright.
  3. A datacenter IP is flagged. If its user agent claims to be a push relay,
     the reason says the user agent is probably spoofed.
  4. A proxy or VPN is flagged.
  5. A high-risk country is flagged.
  6. An allowlisted org keeps its reasons, marked, and is not flagged.
Infra IPs, private addresses and allowlisted devices are never evaluated.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Protocol

from .config import Config
from .pbx import Registration

_IP_PORT = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))?")


@dataclass(frozen=True)
class Geo:
    country: str = ""          # ISO-3166 alpha-2
    isp: str = ""
    org: str = ""
    asn: str = ""
    hosting: bool = False
    proxy: bool = False
    mobile: bool = False

    @property
    def provider(self) -> str:
        return " ".join((self.isp, self.org, self.asn)).lower()


class GeoLookup(Protocol):
    def lookup(self, ips: list[str]) -> dict[str, Geo]: ...


@dataclass(frozen=True)
class Verdict:
    ip: str
    is_fraud: bool
    reasons: tuple[str, ...]
    country_score: int | None
    provider_score: int
    devices: tuple[Registration, ...] = field(default=())

    @property
    def watchlisted(self) -> bool:
        return any(r.startswith("watchlisted provider") for r in self.reasons)


def source_ip(reg: Registration) -> str | None:
    m = _IP_PORT.search(reg.received_from or "")
    return m.group(1) if m else None


# Sources that cannot be a remote attacker's address: the LAN, carrier NAT,
# loopback, link-local, multicast. Listed explicitly rather than using
# ipaddress.is_private, which also counts the documentation ranges (192.0.2/24,
# 198.51.100/24, 203.0.113/24); those never appear in real traffic, and the
# tests and demo use them as stand-in public addresses.
_NOT_EXTERNAL = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"))


def is_public_ipv4(s: str | None) -> bool:
    try:
        ip = ipaddress.ip_address(s or "")
    except ValueError:
        return False
    return isinstance(ip, ipaddress.IPv4Address) and not any(ip in n for n in _NOT_EXTERNAL)


def is_infra(ip: str, cfg: Config) -> bool:
    return ip in cfg.infra_ips or any(ip.startswith(p) for p in cfg.infra_prefixes)


def is_live(reg: Registration, now: datetime, cfg: Config) -> bool:
    """Registering right now. The expiry is the evidence; a mode field can lie
    in both directions (a re-registering device reported as unregistered, a
    long-expired one still reported as registered), so mode is only the fallback."""
    if not reg.received_from:
        return False
    if reg.expires_at is not None:
        exp = reg.expires_at if reg.expires_at.tzinfo else reg.expires_at.replace(tzinfo=timezone.utc)
        return exp >= now - timedelta(seconds=cfg.registration_grace_seconds)
    return reg.mode == "registered"


def device_allowlisted(reg: Registration, cfg: Config) -> bool:
    d = reg.domain.lower()
    return f"{reg.user}@{d}".lower() in cfg.device_allowlist or \
        f"{reg.device}@{d}".lower() in cfg.device_allowlist


def group_by_source(regs: Iterable[Registration], now: datetime,
                    cfg: Config) -> dict[str, list[Registration]]:
    """Live registrations from public, non-infra addresses, keyed by source IP."""
    out: dict[str, list[Registration]] = {}
    for r in regs:
        if not is_live(r, now, cfg) or device_allowlisted(r, cfg):
            continue
        ip = source_ip(r)
        if ip is None or not is_public_ipv4(ip) or is_infra(ip, cfg):
            continue
        out.setdefault(ip, []).append(r)
    return out


def country_score(cc: str, cfg: Config) -> int | None:
    cc = (cc or "").strip().upper()
    if not cc:
        return None
    return cfg.country_scores.get(cc, cfg.default_country_score)


def provider_score(geo: Geo, cfg: Config) -> int:
    p = geo.provider
    if any(w in p for w in cfg.provider_watchlist):
        return 10
    if any(a in p for a in cfg.org_allowlist):
        return 1
    if geo.hosting:
        return 7
    if geo.proxy:
        return 6
    return 3


def _all_push(devices: list[Registration], cfg: Config) -> bool:
    if not devices or not cfg.push_relay_ua_patterns:
        return False
    return all(any(p in d.user_agent.lower() for p in cfg.push_relay_ua_patterns)
               for d in devices)


def classify(ip: str, geo: Geo, devices: list[Registration], cfg: Config) -> Verdict:
    provider = geo.provider
    push_ua = _all_push(devices, cfg)
    cs, ps = country_score(geo.country, cfg), provider_score(geo, cfg)
    if push_ua and any(t in provider for t in cfg.trusted_push_providers):
        return Verdict(ip, False, ("push relay on trusted infrastructure",), cs, ps, tuple(devices))
    reasons: list[str] = []
    hit = next((w for w in cfg.provider_watchlist if w in provider), None)
    if hit:
        reasons.append(f"watchlisted provider: {hit}")
    if geo.hosting:
        who = f"{geo.isp} / {geo.org}".strip(" /")
        reasons.append(f"push user agent from a non-push datacenter ({who}); likely spoofed"
                       if push_ua else f"hosting/datacenter ({who})")
    if geo.proxy:
        reasons.append("proxy/VPN")
    if geo.country and geo.country.upper() in cfg.high_risk_countries:
        reasons.append(f"high-risk country: {geo.country.upper()}")
    if reasons and any(a in provider for a in cfg.org_allowlist):
        return Verdict(ip, False, tuple(r + " (allowlisted org)" for r in reasons), cs, ps,
                       tuple(devices))
    return Verdict(ip, bool(reasons), tuple(reasons), cs, ps, tuple(devices))


def scan(regs: Iterable[Registration], geo: GeoLookup, now: datetime,
         cfg: Config) -> tuple[list[Verdict], list[str]]:
    """Classify every live public source IP. Returns (verdicts, ips_without_geo).

    An IP the lookup did not answer for is returned separately and is NOT
    treated as clean: absent data is unknown, never the all-clear."""
    groups = group_by_source(regs, now, cfg)
    answers = geo.lookup(sorted(groups)) if groups else {}
    verdicts, missing = [], []
    for ip in sorted(groups):
        g = answers.get(ip)
        if g is None:
            missing.append(ip)
            continue
        verdicts.append(classify(ip, g, groups[ip], cfg))
    return verdicts, missing
