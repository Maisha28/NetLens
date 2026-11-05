"""Tests for the per-device security score and the report endpoint."""

import json
import threading
import urllib.request

import pytest

from engine.engine import Engine
from security.score import DEDUCTIONS, assess_device, grade_for, methodology, summarise
from sim import frames as F
from sim.scenario import BULB, BULB_CLOUD, BULB_FW, GATEWAY, LAPTOP2, PHONE, SITES, Simulator


def device(**kw):
    base = dict(ip="10.0.0.5", mac="aa:bb:cc:00:00:05", vendor="", randomized_mac=False, packets=500, bytes_total=90_000,
                findings=[], tls_rows=[], alerts=[], posture_bytes={})
    base.update(kw)
    return assess_device(**base)


def tls_row(grade="A", version="TLS 1.3", sni="a.example"):
    return {"grade": grade, "offered_version": version, "sni": sni, "server": "1.2.3.4"}


# ---------------------------------------------------------------- scoring rules


def test_grade_bands():
    assert [grade_for(s) for s in (100, 90, 89, 75, 74, 60, 59, 40, 39, 0)] == list("AABBCCDDFF")


def test_clean_modern_device_is_an_a_with_good_signs():
    d = device(tls_rows=[tls_row("A"), tls_row("A")], randomized_mac=True)
    assert (d["grade"], d["score"]) == ("A", 100) and d["deductions"] == []
    assert any("TLS 1.3" in g for g in d["good"]) and any("randomised" in g for g in d["good"])


def test_legacy_tls_cleartext_and_weak_cipher_stack_up_to_an_f():
    findings = [
        {"title": "Server negotiated TLS 1.0 with RSA_RC4_128_SHA", "host": "10.0.0.5"},
        {"title": "Unencrypted HTTP traffic", "host": "10.0.0.5"},
    ]
    d = device(tls_rows=[tls_row("F", "TLS 1.0")], findings=findings)
    assert {x["key"] for x in d["deductions"]} == {"weak_tls_client", "weak_tls_negotiated", "cleartext"}
    assert d["score"] == 100 - 40 - 15 - 20 and d["grade"] == "F"
    assert all(x["advice"] for x in d["deductions"])   # every problem comes with what to do


def test_c_grade_handshake_only_costs_the_smaller_amount():
    d = device(tls_rows=[tls_row("C", "TLS 1.2")])
    assert [x["key"] for x in d["deductions"]] == ["weak_tls_ciphers"] and d["score"] == 85 and d["grade"] == "B"


def test_extra_cleartext_protocols_are_capped():
    findings = [{"title": f"Unencrypted {p} traffic", "host": "10.0.0.5"} for p in ("HTTP", "FTP", "Telnet", "SMTP", "POP3")]
    d = device(findings=findings)
    assert sum(x["points"] for x in d["deductions"]) == 20 + 10


def test_behaviour_alerts_are_attributed_to_the_right_device():
    scan = {"rule": "port_scan", "host": "10.0.0.5", "evidence": {"distinct_ports": 90}}
    hogs = [{"rule": "bandwidth_hog", "host": "10.0.0.5", "evidence": {}}] * 3
    arp = {"rule": "arp_spoof", "host": "10.0.0.1", "evidence": {"ip": "10.0.0.1", "new_mac": "AA:BB:CC:00:00:05", "old_mac": "x"}}
    d = device(alerts=[scan, arp, *hogs])
    keys = {x["key"]: x["points"] for x in d["deductions"]}
    assert keys == {"port_scan": 25, "bandwidth_hog": 20, "arp_spoof": 35}  # hog capped at 20; MAC match -> attacker
    victim = device(ip="10.0.0.1", mac="11:22:33:44:55:66", alerts=[arp])
    assert [x["key"] for x in victim["deductions"]] == ["arp_victim"] and victim["score"] == 90
    bystander = device(ip="10.0.0.9", mac="99:99:99:99:99:99", alerts=[scan, arp])
    assert bystander["deductions"] == []


def test_score_never_goes_below_zero():
    findings = [{"title": "Server negotiated x", "host": "h"}, {"title": "Unencrypted HTTP traffic", "host": "h"}, {"title": "Unencrypted FTP traffic", "host": "h"}]
    arp = {"rule": "arp_spoof", "host": "g", "evidence": {"new_mac": "aa:bb:cc:00:00:05"}}
    scan = {"rule": "port_scan", "host": "10.0.0.5", "evidence": {}}
    d = device(tls_rows=[tls_row("F", "TLS 1.0")], findings=findings, alerts=[arp, scan])
    assert d["score"] == 0 and d["grade"] == "F"


def test_monitoring_laptop_and_new_devices_are_not_graded():
    me = device(is_self=True)
    new = device(packets=5)
    assert me["assessed"] is False and me["grade"] == "-"
    assert new["assessed"] is False and new["grade"] == "?" and "too little" in new["note"]


def test_summary_and_methodology():
    devs = [device(), device(ip="10.0.0.6", tls_rows=[tls_row("F", "TLS 1.0")]), device(packets=1)]
    s = summarise(devs)
    assert s["assessed"] == 2 and s["weakest"]["ip"] == "10.0.0.6" and s["score"] == round((100 + 60) / 2)
    assert summarise([device(packets=1)])["grade"] == "?"
    m = methodology()
    assert {x["key"] for x in m} == set(DEDUCTIONS) and all(x["points"] > 0 and x["rule"] for x in m)


# ------------------------------------------------------------ engine integration


@pytest.fixture
def engine(tmp_path):
    eng = Engine(db_path=tmp_path / "t.db", window_seconds=4.0, time_source="packet", key_path=tmp_path / "k")
    yield eng
    eng.shutdown()


def _run_mixed_network(engine):
    from tests.test_engine_e2e import feed, warm_up

    sim = Simulator(seed=3)
    t = warm_up(engine, sim, windows=6)
    feed(engine, [(t + off, raw) for off, raw in sim._tls_session(BULB, BULB_CLOUD, 0, 12)])
    feed(engine, [(t + 8 + off, raw) for off, raw in sim._http_clear(BULB, BULB_FW, 0)])
    scan = [(t + 10 + i * 0.03, F.tcp_frame(LAPTOP2.mac, GATEWAY.mac, LAPTOP2.ip, GATEWAY.ip, 40001, 100 + i, 1, 0, F.TCP_SYN)) for i in range(120)]
    feed(engine, scan + [(t + 11, F.arp_frame(2, LAPTOP2.mac, GATEWAY.ip, PHONE.mac, PHONE.ip))])
    engine.tick(t + 20)


def test_engine_grades_a_mixed_network_sensibly(engine):
    _run_mixed_network(engine)
    rep = engine.security_report()
    by_ip = {d["ip"]: d for d in rep["devices"]}
    assert by_ip[GATEWAY.ip]["assessed"] is False                       # the monitoring laptop
    assert by_ip[PHONE.ip]["grade"] == "A"                              # modern TLS, no incidents
    assert by_ip[BULB.ip]["grade"] == "F"                               # legacy TLS + RC4 + cleartext HTTP
    assert {x["key"] for x in by_ip[BULB.ip]["deductions"]} >= {"weak_tls_client", "cleartext"}
    assert by_ip[LAPTOP2.ip]["grade"] in ("D", "F")                     # scanned ports and impersonated the gateway
    assert {x["key"] for x in by_ip[LAPTOP2.ip]["deductions"]} >= {"port_scan", "arp_spoof"}
    assert rep["overall"]["weakest"]["ip"] == BULB.ip and rep["overall"]["grade"] in ("C", "D", "F")
    assert rep["methodology"] and rep["limits"]
    json.dumps(rep)


def test_report_bundle_includes_the_security_section(engine):
    _run_mixed_network(engine)
    assert "security" in engine.report() and engine.report()["security"]["devices"]


def test_security_endpoint(tmp_path):
    from web.server import App, serve

    eng = Engine(db_path=tmp_path / "w.db", window_seconds=4.0, time_source="wall", key_path=tmp_path / "k")
    httpd, port = serve(App(eng, Simulator(seed=1)), "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/security", timeout=5) as r:
            body = json.loads(r.read())
        assert body["devices"] == [] and body["overall"]["grade"] == "?" and body["methodology"]
    finally:
        httpd.shutdown(); httpd.server_close(); eng.shutdown()
