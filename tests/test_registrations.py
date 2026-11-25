from datetime import datetime, timedelta, timezone

import pytest

from tollguard.config import Config
from tollguard.pbx import Registration
from tollguard.registrations import (Geo, classify, country_score, group_by_source, is_live,
                                     is_public_ipv4, provider_score, scan)

NOW = datetime(2026, 11, 20, 18, 0, tzinfo=timezone.utc)
CFG = Config.from_dict({
    "high_risk_countries": ["XA"], "country_scores": {"US": 1, "XA": 9},
    "provider_watchlist": ["shady vps"], "org_allowlist": ["partner gateway"],
    "infra_ips": ["192.0.2.250"], "infra_prefixes": ["198.51.100.2"],
    "push_relay_ua_patterns": ["push server"], "trusted_push_providers": ["example cloud"],
    "device_allowlist": ["105@travel.example"],
})


def reg(ip="203.0.113.5", ua="Desk", user="101", device="101a", domain="t.example",
        expires=NOW + timedelta(minutes=5), mode="registered"):
    return Registration(domain, user, device, f"{ip}:5060" if ip else "", ua, expires, mode)


def test_trusted_push_relay_is_legitimate_even_from_a_datacenter():
    v = classify("192.0.2.10", Geo("US", "Example Cloud", hosting=True), [reg(ua="Push Server 2")], CFG)
    assert not v.is_fraud and "push relay" in v.reasons[0]


def test_push_user_agent_from_an_untrusted_datacenter_is_a_spoofed_ua():
    v = classify("203.0.113.8", Geo("US", "Budget Hosting", hosting=True), [reg(ua="Push Server")], CFG)
    assert v.is_fraud and "likely spoofed" in v.reasons[0]


def test_push_ua_only_counts_when_every_device_on_the_ip_has_it():
    devs = [reg(ua="Push Server"), reg(ua="Desk", user="102")]
    v = classify("192.0.2.10", Geo("US", "Example Cloud", hosting=True), devs, CFG)
    assert v.is_fraud and v.reasons[0].startswith("hosting/datacenter")


def test_watchlisted_provider_is_flagged_without_any_other_signal():
    v = classify("203.0.113.9", Geo("US", "Shady VPS Co"), [reg()], CFG)
    assert v.is_fraud and v.watchlisted and v.provider_score == 10


@pytest.mark.parametrize("geo,reason", [
    (Geo("US", "Resi", proxy=True), "proxy/VPN"),
    (Geo("XA", "Resi"), "high-risk country: XA"),
])
def test_single_signals(geo, reason):
    v = classify("203.0.113.1", geo, [reg()], CFG)
    assert v.is_fraud and v.reasons == (reason,)


def test_residential_home_country_is_clean():
    v = classify("203.0.113.2", Geo("US", "Example Residential"), [reg()], CFG)
    assert not v.is_fraud and v.reasons == () and v.country_score == 1 and v.provider_score == 3


def test_allowlisted_org_keeps_reasons_but_is_not_flagged():
    v = classify("203.0.113.3", Geo("US", "Partner Gateway Inc", hosting=True), [reg()], CFG)
    assert not v.is_fraud and v.reasons[0].endswith("(allowlisted org)")
    assert provider_score(Geo("US", "Partner Gateway Inc", hosting=True), CFG) == 1


def test_unknown_country_gets_the_default_and_blank_is_none():
    assert country_score("ZZ", CFG) == 5
    assert country_score("", CFG) is None


@pytest.mark.parametrize("ip,public", [
    ("203.0.113.4", True), ("10.1.2.3", False), ("192.168.1.1", False), ("100.64.0.9", False),
    ("127.0.0.1", False), ("169.254.1.1", False), ("224.0.0.5", False), ("not-an-ip", False),
    ("2001:db8::1", False),
])
def test_public_address_test(ip, public):
    assert is_public_ipv4(ip) is public


def test_liveness_trusts_expiry_over_mode():
    assert is_live(reg(mode="unregistered"), NOW, CFG)                       # re-registering
    assert not is_live(reg(expires=NOW - timedelta(minutes=10)), NOW, CFG)   # stale but "registered"
    assert is_live(reg(expires=NOW - timedelta(seconds=30)), NOW, CFG)       # inside the grace
    assert is_live(reg(expires=None, mode="registered"), NOW, CFG)            # no expiry: fall back
    assert not is_live(reg(ip=""), NOW, CFG)


def test_grouping_skips_infra_private_and_allowlisted_devices():
    regs = [reg("203.0.113.5"), reg("203.0.113.5", user="102", device="102a"),
            reg("192.0.2.250"), reg("198.51.100.25"), reg("10.0.0.4"),
            reg("203.0.113.7", user="105", device="105m", domain="travel.example")]
    g = group_by_source(regs, NOW, CFG)
    assert list(g) == ["203.0.113.5"] and len(g["203.0.113.5"]) == 2


def test_scan_reports_missing_geo_as_unknown_not_clean():
    class HalfGeo:
        def lookup(self, ips):
            return {"203.0.113.5": Geo("US", "Resi")}
    verdicts, missing = scan([reg("203.0.113.5"), reg("203.0.113.6", user="2")], HalfGeo(), NOW, CFG)
    assert [v.ip for v in verdicts] == ["203.0.113.5"] and missing == ["203.0.113.6"]


def test_config_rejects_unknown_keys_and_bad_scores():
    with pytest.raises(ValueError, match="unknown config keys"):
        Config.from_dict({"high_risk_country": ["XA"]})
    with pytest.raises(ValueError, match="1-10"):
        Config.from_dict({"country_scores": {"XA": 11}})
