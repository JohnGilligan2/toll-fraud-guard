import asyncio
import json

from tollguard import state as st
from tollguard.bridge import propose
from tollguard.calls import CallScan, DomainFlag, UserCalls
from tollguard.geo_ipapi import IpApiLookup
from tollguard.pbx import ActiveCall
from tollguard.watch import Watch
from world import GEO, NOW, StaticGeo, build, config


def test_watch_on_the_synthetic_estate(tmp_path):
    w = Watch(config(), build(), StaticGeo(GEO), tmp_path / "s.json")
    rep = w.run(NOW)
    assert rep["complete"]
    assert sorted(f["ip"] for f in rep["flagged_ips"]) == ["203.0.113.66", "203.0.113.80"]
    assert [c["domain"] for c in rep["call_flags"]] == ["harbor-clinic.example"]
    assert rep["call_threshold"] == 6                     # the busy call center's 6 calls
    tools = [p["preview_call"]["tool"] for p in rep["proposals"]]
    assert tools == ["lock_users", "lock_users", "hang_up_call"]
    assert all(p["preview_call"]["arguments"]["confirm"] is False for p in rep["proposals"])
    json.dumps(rep)                                      # the report is plain data


def test_unreachable_switch_and_missing_geo_make_the_scan_incomplete(tmp_path):
    clients = build()
    clients["old"].unreachable = True
    geo = dict(GEO)
    del geo["203.0.113.80"]
    rep = Watch(config(), clients, StaticGeo(geo), tmp_path / "s.json").run(NOW)
    assert not rep["complete"] and "old" in rep["unscanned_switches"]
    assert rep["ips_without_geo"] == ["203.0.113.80"]


def test_many_compromised_users_also_propose_a_domain_lock_and_repeat_is_critical():
    s = st.empty()
    for i in range(3):
        s["devices"][f"{i}a@t.example"] = {"status": "active", "device": f"{i}a", "user": str(i),
                                           "domain": "t.example", "ip": "203.0.113.1",
                                           "registering": True, "repeat": i == 0}
    ps = propose(s, None, config(), domain_lock_at=3)
    assert [p.action for p in ps] == ["lock_domain", "lock_users"]
    assert ps[1].severity == "critical" and "REPEAT" in " ".join(ps[1].evidence)


def test_live_call_by_a_suspect_is_proposed_only_when_it_leaves_state_or_country():
    f = DomainFlag("t.example", 9, 9, 0, {"102": UserCalls("102", 9)})
    scan = CallScan(9, 0, 0, 5, [f])
    calls = [ActiveCall("c1", "t.example", "102", "011442079460000"),
             ActiveCall("c2", "t.example", "102", "4155550100"),
             ActiveCall("c3", "t.example", "101", "011442079460000")]
    ps = propose(st.empty(), scan, config(), calls)
    assert [(p.action, p.call_id) for p in ps] == [("lock_users", ""), ("hang_up", "c1")]


def test_geo_adapter_parses_batches_and_reports_failures_as_missing():
    seen = []

    def post(url, payload, timeout):
        seen.append(len(payload))
        if len(seen) == 2:
            raise OSError("timed out")
        return [{"status": "success", "query": p["query"], "countryCode": "US", "isp": "X",
                 "hosting": True} for p in payload] + [{"status": "fail", "query": "bad"}]

    ips = [f"203.0.113.{i}" for i in range(150)]
    out = IpApiLookup(post=post, pause_s=0).lookup(ips)
    assert seen == [100, 50] and len(out) == 100 and out["203.0.113.0"].hosting


def test_mcp_server_boots_and_write_tools_are_marked_destructive():
    from tollguard import mcp_server
    srv = mcp_server._demo()

    async def go():
        tools = {t.name: t for t in await srv.list_tools()}
        assert set(tools) == {"fraud_findings", "run_detection", "lock_users", "restore_users",
                              "lock_domain", "unlock_domain", "hang_up_call", "containment_history"}
        for name in ("lock_users", "restore_users", "lock_domain", "unlock_domain", "hang_up_call"):
            assert tools[name].annotations.destructiveHint is True
            assert "never use a code" in tools[name].description
        r = await srv.call_tool("lock_users", {"domain": "harbor-clinic.example", "users": ["102"],
                                               "confirm": True, "passcode": "123456"})
        assert r.structured_content["status"] == "passcode_rejected"
        r = await srv.call_tool("fraud_findings", {})
        assert len(r.structured_content["proposals"]) == 3
    asyncio.run(go())


def test_token_identity_without_a_request_is_anonymous():
    from tollguard.mcp_server import token_identity
    assert token_identity(frozenset())() == ("anonymous", "direct")
