import pytest

from tollguard.calls import caller_home_state, classify_call, scan_calls, us_area_code
from tollguard.config import Config
from tollguard.pbx import Cdr

CFG = Config.from_dict({"call_flag_floor": 3, "call_baseline_domain": "busy.example",
                        "infra_prefixes": ["192.0.2.25"],
                        "call_home_state_by_domain": {"ny.example": "NY"}})


@pytest.mark.parametrize("dialed,home,cls", [
    ("4155550100", "CA", "in_state"), ("+14155550100", "CA", "in_state"),
    ("2125550100", "CA", "out_of_state"), ("12125550100", "NY", "in_state"),
    ("011442079460000", "CA", "intl"), ("+442079460000", "CA", "intl"),
    ("8005550100", "CA", "tollfree"), ("204", "CA", "internal"), ("*97", "CA", "internal"),
    ("", "CA", "internal"), ("5555550100", "CA", "unknown"), ("442079460000", "CA", "intl"),
])
def test_classify(dialed, home, cls):
    assert classify_call(dialed, home) == cls


def test_area_code_and_home_state():
    assert us_area_code("+1 (310) 555-0100") == "310"
    assert us_area_code("+442079460000") is None
    assert caller_home_state("2125550100", None, "CA") == "NY"
    assert caller_home_state("2125550100", "tx", "CA") == "TX"     # tenant override wins
    assert caller_home_state("204", None, "CA") == "CA"            # extension: default


def cdr(dom, dialed, talk=60, user="102", cid="3105550100", src=""):
    return Cdr(dom, user, cid, dialed, talk, src or dom)


def test_baseline_sets_the_ceiling_and_floor_stops_small_counts():
    cdrs = [cdr("busy.example", "2125550100")] * 4 + \
           [cdr("a.example", "011442079460000")] * 5 + [cdr("b.example", "011442079460000")] * 4
    r = scan_calls(cdrs, CFG)
    assert r.baseline_count == 4 and r.threshold == 4
    assert [f.domain for f in r.flagged] == ["a.example"]          # 5 > 4; 4 is not


def test_only_connected_outbound_suspicious_calls_count():
    cdrs = ([cdr("a.example", "011442079460000", talk=0)] * 9 +            # never connected
            [cdr("a.example", "4155550100")] * 9 +                         # in state
            [cdr("a.example", "011442079460000", src="192.0.2.251")] * 9)  # inbound via our SBC
    r = scan_calls(cdrs, CFG)
    assert r.flagged == [] and r.skipped_inbound == 9


def test_home_state_comes_from_the_caller_not_from_us():
    # A New York tenant calling New York is in state; calling California is not.
    cdrs = [cdr("ny.example", "2125550100", cid="2125550111")] * 5
    assert scan_calls(cdrs, CFG).flagged == []
    cdrs = [cdr("ny.example", "3105550100", cid="2125550111")] * 5
    assert [f.domain for f in scan_calls(cdrs, CFG).flagged] == ["ny.example"]


def test_off_switch_invites_and_links_to_flagged_registration_ips():
    cdrs = [cdr("a.example", "011442079460000", src="203.0.113.66")] * 4 + \
           [cdr("a.example", "011442079460001", user="103", src="198.51.100.7")]
    r = scan_calls(cdrs, CFG, registered_ips={("a.example", "103"): {"198.51.100.7"}},
                   fraud_ips={"203.0.113.66"})
    f = r.flagged[0]
    assert f.callers == ["102", "103"] and f.linked_fraud_ips == {"203.0.113.66"}
    assert f.users["102"].off_switch and not f.users["103"].off_switch


def test_excluded_domain_and_international_toggle():
    cfg = Config.from_dict({"call_flag_floor": 1, "call_exclude_domains": ["a.example"],
                            "call_include_international": False})
    cdrs = [cdr("a.example", "2125550100")] * 3 + [cdr("b.example", "011442079460000")] * 3
    assert scan_calls(cdrs, cfg).flagged == []
