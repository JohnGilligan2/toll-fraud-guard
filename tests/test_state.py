from tollguard import state as st
from tollguard.pbx import Registration
from tollguard.registrations import Verdict

D = "t.example"


def bad(ip="203.0.113.5", device="102a", user="102", watch=False):
    reasons = ("watchlisted provider: x",) if watch else ("hosting/datacenter (x)",)
    return Verdict(ip, True, reasons, 9, 7, (Registration(D, user, device, f"{ip}:5060"),))


def clean(ip="198.51.100.9"):
    return Verdict(ip, False, (), 1, 3, (Registration(D, "101", "101a", f"{ip}:5060"),))


def test_new_flag_is_announced_once():
    s = st.empty()
    assert st.advance(s, [bad()], "t1").new_flags == ["203.0.113.5"]
    assert st.advance(s, [bad()], "t2").new_flags == []


def test_ip_that_stops_registering_is_cleared_and_can_be_announced_again():
    s = st.empty()
    st.advance(s, [bad()], "t1")
    ev = st.advance(s, [], "t2")
    assert ev.cleared_ips == ["203.0.113.5"] and not s["ips"]["203.0.113.5"]["flagged"]
    assert st.advance(s, [bad()], "t3").new_flags == ["203.0.113.5"]


def test_stopped_without_a_reset_stays_open():
    s = st.empty()
    assert st.advance(s, [bad()], "t1").new_compromised == ["102a@t.example"]
    ev = st.advance(s, [], "t2")
    assert ev.open_not_registering == ["102a@t.example"] and ev.resolved == []
    assert s["devices"]["102a@t.example"]["status"] == "active"


def test_reset_while_still_registering_is_reported_as_ineffective():
    s = st.empty()
    st.advance(s, [bad()], "t1")
    st.record_reset(s, D, "102a", "t2")
    ev = st.advance(s, [bad()], "t3")
    assert ev.open_reset_ineffective == ["102a@t.example"] and ev.resolved == []


def test_reset_and_stopped_resolves_and_return_is_a_repeat_offender():
    s = st.empty()
    st.advance(s, [bad()], "t1")
    st.record_reset(s, D, "102a", "t2")
    assert st.advance(s, [], "t3").resolved == ["102a@t.example"]
    ev = st.advance(s, [bad()], "t4")
    assert ev.repeats == ["102a@t.example"] and ev.new_compromised == []
    rec = s["devices"]["102a@t.example"]
    assert rec["repeat"] and rec["repeat_count"] == 1 and rec["episodes"] == 2


def test_a_reset_from_a_previous_episode_does_not_count():
    s = st.empty()
    st.advance(s, [bad()], "t1")
    st.record_reset(s, D, "102a", "t2")
    st.advance(s, [], "t3")                   # resolved
    st.advance(s, [bad()], "t4")              # back: new episode starting t4
    ev = st.advance(s, [], "t5")              # stops again, but no reset since t4
    assert ev.open_not_registering == ["102a@t.example"]


def test_undone_reset_is_ignored_and_reset_by_user_matches():
    s = st.empty()
    st.advance(s, [bad()], "t1")
    st.record_reset(s, D, "102a", "t2")
    s["resets"][-1]["undone"] = True
    assert st.advance(s, [], "t3").resolved == []
    st.record_reset(s, D, "102", "t4", user="102")   # logged against the user, not the device
    assert st.advance(s, [], "t5").resolved == ["102a@t.example"]


def test_clean_verdicts_create_no_device_records(tmp_path):
    s = st.empty()
    st.advance(s, [clean()], "t1")
    assert s["devices"] == {}
    st.save(s, tmp_path / "s.json")
    assert st.load(tmp_path / "s.json")["ips"]["198.51.100.9"]["flagged"] is False
    assert st.load(tmp_path / "missing.json") == st.empty()
