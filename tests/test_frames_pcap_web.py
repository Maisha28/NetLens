"""
Decoder round-trips of the simulator's byte-level frames (the frames are real
and the checksums valid), packet-lab annotation, pcap recording/replay, and
the web API contract.
"""

import json
import threading
import urllib.error
import urllib.request

import pytest

from capture.pcap_io import PcapRecorder, replay_pcap
from decoder.decoder import decode
from decoder.explain import explain_frame
from engine.engine import Engine
from sim import frames as F
from sim.scenario import BULB, GATEWAY, LAPTOP2, PHONE, Simulator
from web.server import App, serve

A, B = PHONE, GATEWAY


# --- frames decode correctly ---------------------------------------------------------------------


def test_dns_query_and_response_round_trip():
    q = decode(F.udp_frame(A.mac, B.mac, A.ip, B.ip, 40000, 53, F.dns_query(7, "www.youtube.com")), 1.0)
    assert (q.protocol, q.dns_is_response, q.dns_query_name) == ("UDP", False, "www.youtube.com")
    r = decode(F.udp_frame(B.mac, A.mac, B.ip, A.ip, 53, 40000, F.dns_response(7, "www.youtube.com", ["142.250.1.1"], cname="edge.youtube.com")), 1.0)
    assert r.dns_is_response and any("142.250.1.1" in a for a in r.dns_answers)


def test_tcp_flags_ports_and_seq_round_trip():
    raw = F.tcp_frame(A.mac, B.mac, A.ip, "142.250.1.1", 51000, 443, 1234, 99, F.TCP_SYN | F.TCP_ACK)
    rec = decode(raw, 1.0)
    assert (rec.src_port, rec.dst_port, rec.tcp_seq, rec.tcp_ack, rec.tcp_flags) == (51000, 443, 1234, 99, "SYN,ACK")


def test_tls_hello_populates_sni_and_tls_info():
    raw = F.tcp_frame(A.mac, B.mac, A.ip, "142.250.1.1", 51000, 443, 1, 1, F.TCP_PSH | F.TCP_ACK, F.tls_client_hello("www.youtube.com"))
    rec = decode(raw, 1.0)
    assert rec.tls_sni == "www.youtube.com"
    assert rec.tls_info["grade"] == "A" and "ClientHello" in rec.summary


def test_cleartext_http_is_named_but_content_is_not_kept():
    raw = F.tcp_frame(BULB.mac, B.mac, BULB.ip, "52.58.77.202", 40000, 80, 1, 1, F.TCP_PSH | F.TCP_ACK, F.http_request("/fw/check", "fw.example"))
    rec = decode(raw, 1.0)
    assert rec.cleartext == "HTTP"
    assert "fw/check" not in (rec.summary or "")


def test_arp_round_trip():
    rec = decode(F.arp_frame(2, LAPTOP2.mac, GATEWAY.ip, PHONE.mac, PHONE.ip), 1.0)
    assert (rec.protocol, rec.src_ip, rec.arp_sender_mac, rec.arp_opcode) == ("ARP", GATEWAY.ip, LAPTOP2.mac, 2)


def test_explain_reports_verified_checksums_and_byte_offsets():
    raw = F.tcp_frame(A.mac, B.mac, A.ip, "142.250.1.1", 51000, 443, 1, 0, F.TCP_SYN)
    info = explain_frame(raw)
    assert [l["name"] for l in info["layers"]] == ["Ethernet II", "IPv4", "TCP"]
    fields = {f["name"]: f for l in info["layers"] for f in l["fields"]}
    assert fields["Header checksum"]["note"] == "verifies"
    assert fields["Checksum"]["note"].startswith("verifies")  # TCP checksum incl. pseudo-header
    assert fields["TTL"]["offset"] == 14 + 8 and fields["Protocol"]["offset"] == 14 + 9
    assert fields["Source IP"]["value"] == A.ip and fields["Destination port"]["value"] == "443"
    assert "SYN" in fields["Flags"]["value"]


def test_explain_covers_arp_dns_and_survives_garbage():
    assert explain_frame(F.arp_frame(1, A.mac, A.ip, "00:00:00:00:00:00", B.ip))["layers"][-1]["name"] == "ARP"
    dns = explain_frame(F.udp_frame(A.mac, B.mac, A.ip, B.ip, 40000, 53, F.dns_query(1, "a.example.com")))
    assert dns["layers"][-1]["name"] == "DNS" and dns["notes"]
    assert explain_frame(b"\x00\x01")["layers"] == []
    assert explain_frame(b"\xff" * 60)["length"] == 60  # nonsense never raises


# --- pcap ----------------------------------------------------------------------------------------------


def test_recorded_pcap_replays_identical_bytes_and_timestamps(tmp_path):
    frames = [
        (100.25, F.arp_frame(1, A.mac, A.ip, "00:00:00:00:00:00", B.ip)),
        (100.50, F.tcp_frame(A.mac, B.mac, A.ip, "1.2.3.4", 1, 2, 3, 4, F.TCP_SYN)),
        (101.00, F.udp_frame(A.mac, B.mac, A.ip, B.ip, 5, 53, F.dns_query(1, "x.example"))),
    ]
    rec = PcapRecorder(tmp_path)
    for ts, raw in frames:
        rec.write(raw, ts)
    rec.close()
    out = list(replay_pcap(rec.path, speed=0))
    assert [raw for raw, _ in out] == [raw for _, raw in frames]
    assert [round(ts, 3) for _, ts in out] == [100.25, 100.5, 101.0]


def test_replay_through_engine_reproduces_a_run(tmp_path):
    sim = Simulator(seed=11)
    items = []
    for k in range(6):
        for off, raw in sim._tls_session(PHONE, ("www.example.com", "142.250.1.1", "modern", 1, "api"), 0, 6):
            items.append((1000.0 + k * 4 + off, raw))
    rec = PcapRecorder(tmp_path)
    for ts, raw in sorted(items, key=lambda x: x[0]):
        rec.write(raw, ts)
    rec.close()

    eng = Engine(db_path=tmp_path / "r.db", window_seconds=4.0, time_source="packet", key_path=tmp_path / "k")
    for raw, ts in replay_pcap(rec.path, speed=0):
        eng.ingest_frame(raw, ts)
    assert eng.counters["frames_captured"] == len(items) and eng.counters["decode_errors"] == 0
    assert any(h.bytes for h in eng.hosts.values())
    eng.shutdown()


# --- web API -------------------------------------------------------------------------------------------


@pytest.fixture
def server(tmp_path):
    eng = Engine(db_path=tmp_path / "w.db", window_seconds=4.0, time_source="wall", key_path=tmp_path / "k")
    app = App(eng, Simulator(seed=1))
    httpd, port = serve(app, "127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", app
    httpd.shutdown()
    httpd.server_close()
    eng.shutdown()


def get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.read()


def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_landing_page_dashboard_and_static_assets_are_served(server):
    base, _ = server
    status, body = get(base + "/")
    assert status == 200 and b"See your network." in body and b"/dashboard" in body   # landing page
    status, body = get(base + "/dashboard")
    assert status == 200 and b'id="pageTitle"' in body                                  # the application
    assert get(base + "/dashboard/")[0] == 200
    for asset in ("css/style.css", "css/landing.css", "js/app.js", "js/charts.js", "js/landing-hero.js", "js/landing-story.js"):
        assert get(f"{base}/{asset}")[0] == 200


def test_static_path_traversal_is_refused(server):
    base, _ = server
    for path in ("/..%2f..%2fapp.py", "/%2e%2e/%2e%2e/app.py", "/js/../../../app.py"):
        try:
            status, body = get(base + path)
        except urllib.error.HTTPError as exc:
            status, body = exc.code, b""
        assert status in (403, 404) and b"python app.py" not in body


def test_state_starts_in_standby_with_no_mock_data(server):
    base, _ = server
    _, body = get(base + "/api/state")
    state = json.loads(body)
    assert state["mode"] == "idle" and state["totals"]["packets"] == 0 and state["hosts"] == [] and state["alerts"] == []


def test_scenarios_refused_outside_simulation(server):
    base, _ = server
    status, body = post(base + "/api/scenario", {"name": "port_scan"})
    assert status == 409 and "simulation" in body["error"].lower()


def test_source_validation_errors(server):
    base, _ = server
    assert post(base + "/api/source", {"mode": "teleport"})[0] == 400
    assert post(base + "/api/source", {"mode": "pcap", "file": "../../etc/passwd"})[0] == 400
    assert post(base + "/api/control", {"action": "explode"})[0] == 400


def test_switching_to_simulation_and_back_always_resets(server):
    base, app = server
    assert post(base + "/api/source", {"mode": "sim"})[0] == 200
    assert app.engine.mode == "sim"
    import time

    time.sleep(1.5)
    assert app.engine.snapshot()["totals"]["packets"] > 0
    assert post(base + "/api/source", {"mode": "stop"})[0] == 200
    snap = json.loads(get(base + "/api/state")[1])
    assert snap["mode"] == "idle" and snap["totals"]["packets"] == 0  # simulated data did not leak


def test_system_check_shape(server):
    base, _ = server
    info = json.loads(get(base + "/api/system")[1])
    for key in ("admin", "npcap", "interfaces", "recommended", "hotspot_on", "recordings", "self_ips"):
        assert key in info
    assert all({"name", "noise", "recommended"} <= set(i) for i in info["interfaces"])


def test_live_refuses_cleanly_without_admin_or_npcap(server, monkeypatch):
    base, app = server
    from web import system

    monkeypatch.setattr(system, "system_check", lambda: {"admin": False, "npcap": True, "recommended": "X", "self_ips": []})
    status, body = post(base + "/api/source", {"mode": "live", "iface": "X"})
    assert status == 409 and "Administrator" in body["error"]
    monkeypatch.setattr(system, "system_check", lambda: {"admin": True, "npcap": False, "recommended": "X", "self_ips": []})
    status, body = post(base + "/api/source", {"mode": "live", "iface": "X"})
    assert status == 409 and "Npcap" in body["error"]
    assert app.engine.mode == "idle"  # a failed start must not leave a half-switched engine


def test_packet_and_ledger_endpoints_in_simulation(server):
    base, app = server
    post(base + "/api/source", {"mode": "sim"})
    import time

    time.sleep(2)
    feed = json.loads(get(base + "/api/feed?since=0")[1])
    assert feed["packets"]
    detail = json.loads(get(f"{base}/api/packet/{feed['packets'][-1]['seq']}")[1])
    assert detail["layers"] and detail["hex"]
    ledger = json.loads(get(base + "/api/ledger")[1])
    assert ledger["verification"]["ok"]
    report = json.loads(get(base + "/api/report")[1])
    assert report["mode"] == "sim" and "Metadata only" in report["note"]
