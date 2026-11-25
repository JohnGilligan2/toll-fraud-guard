"""One detection pass over every switch: registrations, state, calls, proposals.

Read-only against the PBX. Run it on a schedule (every few minutes for calls,
hourly is enough for registrations) and send the report wherever your team
looks. A switch that cannot be read is reported as unscanned, never as clean.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import bridge, state as st
from .calls import scan_calls
from .config import Config
from .pbx import Pbx, Registration
from .registrations import GeoLookup, scan, source_ip


@dataclass
class Watch:
    cfg: Config
    clients: dict[str, Pbx]
    geo: GeoLookup
    state_path: Path
    domain_lock_at: int = 10
    last: dict[str, Any] = field(default_factory=dict)

    def run(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        stamp = now.replace(microsecond=0).isoformat()
        regs: list[Registration] = []
        cdrs = []
        live = []
        unscanned: dict[str, str] = {}
        for label, pbx in self.clients.items():
            try:
                regs += pbx.list_registrations()
                cdrs += pbx.list_cdrs(self.cfg.call_window_minutes)
                live += pbx.list_active_calls()
            except Exception as e:  # noqa: BLE001 - one switch down must not hide the others; reported below
                unscanned[label] = str(e)[:200]
        verdicts, no_geo = scan(regs, self.geo, now, self.cfg)
        state = st.load(self.state_path)
        events = st.advance(state, verdicts, stamp)
        st.save(state, self.state_path)

        reg_ips: dict[tuple[str, str], set[str]] = {}
        for r in regs:
            ip = source_ip(r)
            if ip:
                reg_ips.setdefault((r.domain.lower(), r.user), set()).add(ip)
        fraud_ips = {ip for ip, e in state["ips"].items() if e.get("flagged")}
        calls = scan_calls(cdrs, self.cfg, reg_ips, fraud_ips)
        proposals = bridge.propose(state, calls, self.cfg, live, self.domain_lock_at)
        self.last = {
            "at_utc": stamp,
            "complete": not unscanned and not no_geo,
            "unscanned_switches": unscanned,
            "ips_without_geo": no_geo,
            "flagged_ips": [{"ip": v.ip, "reasons": list(v.reasons), "country_score": v.country_score,
                             "provider_score": v.provider_score,
                             "devices": [f"{d.device}@{d.domain}" for d in v.devices]}
                            for v in verdicts if v.is_fraud],
            "events": events.__dict__,
            "open_devices": st.open_devices(state),
            "call_flags": [{"domain": f.domain, "count": f.count, "intl": f.intl,
                            "out_of_state": f.out_of_state, "callers": f.callers,
                            "linked_fraud_ips": sorted(f.linked_fraud_ips)}
                           for f in calls.flagged],
            "call_threshold": calls.threshold,
            "proposals": [dict(p.__dict__, preview_call=p.preview_call()) for p in proposals],
        }
        return self.last
