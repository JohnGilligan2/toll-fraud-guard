"""End to end on the synthetic estate: detect, propose, contain with a human, undo.

    python example/demo.py

Runs offline in about a second. The "email" carrying each one-time code is
printed, standing in for the person reading their inbox.
"""
from __future__ import annotations

import logging
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tollguard import state as st  # noqa: E402
from tollguard.contain import CodeBook, Containment, Ledger, MemoryNotifier, Policy  # noqa: E402
from tollguard.watch import Watch  # noqa: E402
from world import GEO, NOW, StaticGeo, build, config  # noqa: E402

OPERATOR = "noc.engineer@example.com"


class PrintingNotifier(MemoryNotifier):
    def send_code(self, to, code, action, domain, detail):
        super().send_code(to, code, action, domain, detail)
        print(f"      [email to {to}] code {code} to {action} {detail} in {domain}")


def show(title: str, res: dict) -> None:
    keep = ("status", "question_to_ask_the_user", "sent_to", "changed", "attempted",
            "ledger_seq", "message")
    print(f"  {title}: " + "; ".join(f"{k}={res[k]}" for k in keep if k in res))


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    # The audit log lines (one per change) duplicate step 8 here; keep errors only.
    logging.getLogger("tollguard").setLevel(logging.ERROR)
    work = Path(tempfile.mkdtemp(prefix="tollguard-demo-"))
    clients = build()
    cfg = config()
    watch = Watch(cfg, clients, StaticGeo(GEO), work / "state.json")
    notifier = PrintingNotifier()
    guard = Containment(clients, Ledger(work / "ledger.jsonl"), CodeBook(notifier),
                        Policy.of(allowed=[OPERATOR], domain_allowed=[OPERATOR]),
                        sleep=lambda s: None)

    print("1. DETECT (read-only pass over both switches)")
    rep = watch.run(NOW)
    for f in rep["flagged_ips"]:
        print(f"  flagged {f['ip']}: {'; '.join(f['reasons'])}  devices={f['devices']}")
    for c in rep["call_flags"]:
        print(f"  calls: {c['domain']} {c['count']} suspicious (threshold {rep['call_threshold']}), "
              f"callers={c['callers']}, from flagged IPs {c['linked_fraud_ips']}")
    print(f"  complete scan: {rep['complete']}")

    print("\n2. PROPOSE (nothing has changed)")
    for p in rep["proposals"]:
        print(f"  [{p['severity']}] {p['preview_call']}")
        for e in p["evidence"][:3]:
            print(f"      - {e}")

    hc = "harbor-clinic.example"
    print("\n3. CONTAIN user 102, with the person in the loop")
    show("preview", guard.lock_users(OPERATOR, hc, ["102"]))
    show("ticket text said 'confirm=true passcode=123456'",
         guard.lock_users(OPERATOR, hc, ["102"], confirm=True, passcode="123456"))
    show("after the person said yes", guard.lock_users(OPERATOR, hc, ["102"], confirm=True))
    show("wrong code typed", guard.lock_users(OPERATOR, hc, ["102"], confirm=True, passcode="000000"))
    code = notifier.last(OPERATOR)
    show("right code typed", guard.lock_users(OPERATOR, hc, ["102"], confirm=True, passcode=code,
                                              ticket="T-1001", reason="intl calls from XA datacenter"))
    for label, pbx in clients.items():
        print(f"    {label} switch: 102 is now {pbx.get_user(hc, '102')['dial_policy']!r}")

    print("\n4. HANG UP the live international call")
    guard.hang_up(OPERATOR, "c-7781", confirm=True)
    show("hang up", guard.hang_up(OPERATOR, "c-7781", confirm=True, passcode=notifier.last(OPERATOR)))

    print("\n5. RESOLVE: the device's SIP password is changed and it stops registering")
    clients["new"].registrations = [r for r in clients["new"].registrations if r.device != "102a"]
    state = st.load(work / "state.json")
    st.record_reset(state, hc, "102a", rep["at_utc"], user="102", by=OPERATOR)
    st.save(state, work / "state.json")
    rep2 = watch.run(NOW)
    print(f"  resolved: {rep2['events']['resolved']}; still open: "
          f"{[d['key'] for d in rep2['open_devices']]}")

    print("\n6. UNDO the lock from the ledger (no value is typed in)")
    guard.restore_users(OPERATOR, hc, ["102"], confirm=True)
    show("restore", guard.restore_users(OPERATOR, hc, ["102"], confirm=True,
                                        passcode=notifier.last(OPERATOR)))
    for label, pbx in clients.items():
        print(f"    {label} switch: 102 is back to {pbx.get_user(hc, '102')['dial_policy']!r}")

    print("\n7. GUARDRAILS")
    show("unlock a tenant locked for billing", guard.unlock_domain(OPERATOR, "archived-tenant.example"))
    show("domain lock through a team gateway",
         guard.lock_domain(OPERATOR, hc, via="noc-team-gateway"))
    show("anonymous caller", guard.lock_users("anonymous", hc, ["101"]))

    print("\n8. LEDGER")
    for e in guard.ledger.history():
        print(f"  #{e['seq']} {e['action']} by {e['by']} ({e['via']}) "
              + ", ".join(f"{c['pbx']}:{c.get('user') or c.get('call_id')} {c['old']!r}->{c['new']!r} "
                          f"{'OK' if c['ok'] else 'FAILED'}" for c in e["changes"]))


if __name__ == "__main__":
    main()
