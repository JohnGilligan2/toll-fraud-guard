"""A small synthetic PBX estate with one live toll-fraud incident in it.

Two switches ("old" and "new"), because a tenant mid-migration exists on both
and containment has to cover both copies. Every name, number and address is
made up: documentation IP ranges, 555-01xx numbers, the 020 7946 0xxx range
reserved for fiction, and ISO user-assigned country codes.

The incident, in harbor-clinic.example:
  * device 102a registers from a datacenter on a watchlisted provider in XA;
  * user 102 has placed nine connected international calls in the window,
    from that same IP, off the switch;
  * user 102 is on a live international call right now.
Noise that must NOT be flagged: a softphone push relay on trusted cloud
infrastructure, a front-desk phone on a residential line, and a busy call
center whose out-of-state volume is the baseline.
Also flagged: northside-law.example user 201, whose "push" user agent comes
from a budget datacenter (a spoofed user agent).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tollguard.config import Config
from tollguard.pbx import ActiveCall, Cdr, FakePbx, Registration
from tollguard.registrations import Geo

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 20, 18, 0, tzinfo=timezone.utc)

GEO = {
    "198.51.100.20": Geo("US", "Example Residential Broadband", "", "AS64500"),
    "192.0.2.10": Geo("US", "Example Cloud", "Example Cloud LLC", "AS64501", hosting=True),
    "203.0.113.66": Geo("XA", "Shady VPS Co", "Shady VPS Co", "AS64502", hosting=True),
    "203.0.113.80": Geo("US", "Budget Hosting", "Budget Hosting", "AS64503", hosting=True),
    "198.51.100.44": Geo("US", "Example Mobile", "", "AS64504", mobile=True),
}


class StaticGeo:
    def __init__(self, table: dict[str, Geo]):
        self.table = table

    def lookup(self, ips: list[str]) -> dict[str, Geo]:
        return {ip: self.table[ip] for ip in ips if ip in self.table}


def config() -> Config:
    return Config.from_dict(json.loads((ROOT / "config.example.json").read_text(encoding="utf-8")))


def _reg(domain, user, device, ip, ua, pbx, expires):
    return Registration(domain, user, device, f"{ip}:5060", ua, expires, "registered", pbx)


def build(now: datetime = NOW) -> dict[str, FakePbx]:
    """The estate as it looks at `now` (registrations expire five minutes later)."""
    live = now + timedelta(minutes=5)
    old, new = FakePbx(), FakePbx(read_lag=1)   # the old switch is consistent; the new one lags a read
    for pbx in (old, new):
        pbx.add_user("harbor-clinic.example", "101", "US and Canada", "Front Desk")
        pbx.add_user("harbor-clinic.example", "102", "International", "Billing")
        pbx.add_user("harbor-clinic.example", "103", "US and Canada", "Dr. Example")
    new.add_user("northside-law.example", "201", "US and Canada", "Reception")
    new.add_user("busy-callcenter.example", "301", "US and Canada", "Agent 1")
    new.add_user("archived-tenant.example", "401", "US and Canada", "Former customer")
    new.domains["archived-tenant.example"]["policy"] = "locked"   # locked for billing, not fraud

    hc = "harbor-clinic.example"
    new.registrations = [
        _reg(hc, "101", "101a", "198.51.100.20", "DeskPhone-X 2.1", "new", live),
        _reg(hc, "102", "102a", "203.0.113.66", "DeskPhone-X 2.1", "new", live),
        _reg(hc, "103", "103m", "192.0.2.10", "ExampleSoftphone Push Server", "new", live),
        _reg("northside-law.example", "201", "201m", "203.0.113.80",
             "ExampleSoftphone Push Server", "new", live),
        _reg("busy-callcenter.example", "301", "301a", "198.51.100.44", "Headset-App 4", "new", live),
        _reg(hc, "101", "101b", "192.0.2.250", "Gateway", "new", live),     # our own SBC: ignored
    ]
    cdrs = []
    for i in range(9):
        cdrs.append(Cdr(hc, "102", "3105550142", f"011442079460{100 + i}", 240 + i,
                        "203.0.113.66", 1_700_000_000 + i * 30))
    cdrs.append(Cdr(hc, "101", "3105550101", "4155550188", 60, hc))            # in state
    cdrs.append(Cdr(hc, "101", "3105550101", "8005550100", 60, hc))            # toll-free
    cdrs.append(Cdr(hc, "101", "3105550101", "011442079460999", 0, hc))       # never connected
    for i in range(6):                                                         # the baseline
        cdrs.append(Cdr("busy-callcenter.example", "301", "3105550199", f"21255501{10 + i}", 90,
                        "busy-callcenter.example"))
    cdrs.append(Cdr("northside-law.example", "201", "2125550111", "3105550123", 120,
                    "northside-law.example"))
    cdrs.append(Cdr(hc, "101", "3105550101", "2125550100", 30, "192.0.2.250"))  # inbound via SBC
    new.cdrs = cdrs
    new.calls = {"c-7781": ActiveCall("c-7781", hc, "102", "011442079460555", 1_700_000_400),
                 "c-7782": ActiveCall("c-7782", hc, "101", "4155550101", 1_700_000_410)}
    return {"old": old, "new": new}
