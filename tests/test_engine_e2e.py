"""
End-to-end: raw frames -> real decoder -> engine -> baselines -> rules -> sealed ledger.

Runs in "packet" time so windows close from packet timestamps - deterministic
and independent of the wall clock. Frames are built with sim.frames (real
Ethernet/IPv4/TCP/UDP/ARP bytes with valid checksums).
"""

import json
import random

import pytest

from engine.engine import Engine, is_local, is_probe
from shared.packet_record import PacketRecord
from sim import frames as F
from sim.scenario import BULB, GATEWAY, LAPTOP2, PHONE, SITES, Simulator

T0 = 1_000_000.0
WINDOW = 4.0


@pytest.fixture
def engine(tmp_path):
    eng = Engine(db_path=tmp_path / "t.db", window_seconds=WINDOW, time_source="packet", key_path=tmp_path / "k")
    yield eng
    eng.shutdown()


def feed(engine, items):
    """items: iterable of (timestamp, raw_frame) - must be time-ordered."""
    for ts, raw in sorted(items, key=lambda x: x[0]):
        engine.ingest_frame(raw, ts)


def normal_window(sim, start):
    """One window of ordinary traffic: phone browsing + a light laptop + ARP."""
    items = []
    rng = random.Random(int(start))
    for k in range(3):
        site = SITES[rng.randrange(len(SITES))]
        for off, raw in sim._tls_session(PHONE, site, 0, 12):
            items.append((start + k * 1.2 + off, raw))
    for off, raw in sim._tls_session(LAPTOP2, SITES[4], 0, 6):
        items.append((start + 0.5 + off, raw))
    for off, raw in sim._arp_pair(PHONE, GATEWAY, 0.1):
        items.append((start + off, raw))
    return items


def warm_up(engine, sim, windows=5):
    t = T0
    for _ in range(windows):
        feed(engine, normal_window(sim, t))
        t += WINDOW
    engine.tick(t)  # close the last normal window so tests start on a clean boundary
    engine._window_end = t + WINDOW
    return t


def test_full_pipeline_fires_all_three_rules_and_seals_them(engine):
    sim = Simulator(seed=1)
    t = warm_up(engine, sim)

    # 1) port scan: LAPTOP2 probes 120 distinct ports on the gateway in one window
    scan = [
        (t + i * 0.03, F.tcp_frame(LAPTOP2.mac, GATEWAY.mac, LAPTOP2.ip, GATEWAY.ip, 40001, 100 + i, 1, 0, F.TCP_SYN))
        for i in range(120)
    ]
    # 2) ARP spoof: LAPTOP2 claims the gateway's IP
    spoof = [(t + 1.0, F.arp_frame(2, LAPTOP2.mac, GATEWAY.ip, PHONE.mac, PHONE.ip))]
    # 3) bandwidth hog: phone downloads ~1.8 MB in the same window
    ip = SITES[1][1]
    hog = [
        (t + 0.2 + i * 0.002, F.tcp_frame(GATEWAY.mac, PHONE.mac, ip, PHONE.ip, 443, 41000, i, 1, F.TCP_ACK, b"x" * 1400))
        for i in range(1300)
    ]
    feed(engine, scan + spoof + hog)
    engine.tick(t + WINDOW)  # flush the window

    rules = {(a["rule"], a["host"]) for a in engine.alerts}
    assert ("port_scan", LAPTOP2.ip) in rules
    assert ("arp_spoof", GATEWAY.ip) in rules
    assert ("bandwidth_hog", PHONE.ip) in rules
    # the scan's few small packets must not be called a bandwidth hog
    assert ("bandwidth_hog", LAPTOP2.ip) not in rules

    verdict = engine.ledger.verify()
    assert verdict["ok"] and verdict["count"] == len(engine.alerts) == 3

    # every alert carries its evidence and its seal
    for a in engine.alerts:
        assert a["evidence"] and a["seal"]["hash"] and a["seal"]["sig"]
    scan_alert = next(a for a in engine.alerts if a["rule"] == "port_scan")
    assert scan_alert["evidence"]["distinct_ports"] >= 120
    spoof_alert = next(a for a in engine.alerts if a["rule"] == "arp_spoof")
    assert spoof_alert["evidence"]["old_mac"] == GATEWAY.mac
    assert spoof_alert["evidence"]["new_mac"] == LAPTOP2.mac


def test_alerting_window_is_not_learned_from(engine):
    sim = Simulator(seed=2)
    t = warm_up(engine, sim)
    before = engine.tracker.get_baseline(PHONE.ip)
    samples, ewma = before.samples_seen, before.ewma_bytes
    ip = SITES[1][1]
    hog = [(t + i * 0.002, F.tcp_frame(GATEWAY.mac, PHONE.mac, ip, PHONE.ip, 443, 41000, i, 1, F.TCP_ACK, b"x" * 1400)) for i in range(1500)]
    feed(engine, hog)
    engine.tick(t + WINDOW)
    after = engine.tracker.get_baseline(PHONE.ip)
    assert any(a["rule"] == "bandwidth_hog" for a in engine.alerts)
    assert after.samples_seen == samples and after.ewma_bytes == ewma  # spike did not inflate its own baseline


def test_nothing_fires_before_baselines_are_ready(engine):
    sim = Simulator(seed=3)
    feed(engine, normal_window(sim, T0))
    scan = [(T0 + 1 + i * 0.01, F.tcp_frame(LAPTOP2.mac, GATEWAY.mac, LAPTOP2.ip, GATEWAY.ip, 40001, 100 + i, 1, 0, F.TCP_SYN)) for i in range(200)]
    feed(engine, scan)
    engine.tick(T0 + WINDOW)
    assert [a for a in engine.alerts if a["rule"] in ("port_scan", "bandwidth_hog")] == []  # REQ-29


def test_normal_traffic_raises_no_alerts(engine):
    sim = Simulator(seed=4)
    warm_up(engine, sim, windows=9)
    assert engine.alerts == []


def test_dns_server_replying_to_many_client_ports_is_not_a_scan(engine):
    """The false positive that motivated counting only connection-initiating packets."""
    sim = Simulator(seed=5)
    t = warm_up(engine, sim)
    replies = []
    for i in range(80):
        sport = 33000 + i * 7
        q = F.udp_frame(PHONE.mac, GATEWAY.mac, PHONE.ip, GATEWAY.ip, sport, 53, F.dns_query(i, f"h{i}.example.com"))
        r = F.udp_frame(GATEWAY.mac, PHONE.mac, GATEWAY.ip, PHONE.ip, 53, sport, F.dns_response(i, f"h{i}.example.com", ["93.184.216.34"]))
        replies += [(t + i * 0.04, q), (t + i * 0.04 + 0.01, r)]
    feed(engine, replies)
    engine.tick(t + WINDOW)
    assert [a for a in engine.alerts if a["rule"] == "port_scan"] == []


def test_arp_cooldown_collapses_a_sustained_spoof_into_one_alert(engine):
    sim = Simulator(seed=6)
    t = warm_up(engine, sim)
    feed(engine, [(t + i, F.arp_frame(2, LAPTOP2.mac, GATEWAY.ip, PHONE.mac, PHONE.ip)) for i in range(6)])
    arps = [a for a in engine.alerts if a["rule"] == "arp_spoof"]
    assert len(arps) == 1 and arps[0]["repeats"] >= 4


def test_tls_and_cleartext_findings(engine):
    sim = Simulator(seed=7)
    t = warm_up(engine, sim, windows=1)
    from sim.scenario import BULB_CLOUD, BULB_FW

    feed(engine, [(t + off, raw) for off, raw in sim._tls_session(BULB, BULB_CLOUD, 0, 2)])
    feed(engine, [(t + 5 + off, raw) for off, raw in sim._http_clear(BULB, BULB_FW, 0)])
    titles = " | ".join(f["title"] for f in engine.findings.values())
    assert "Weak TLS client" in titles and "TLS 1.0" in titles and "Unencrypted HTTP" in titles
    row = next(r for r in engine.tls_rows.values() if r["client"] == BULB.ip)
    assert row["grade"] == "F" and row["negotiated"] == "TLS 1.0" and row["cipher_weakness"]


def test_snapshot_is_json_serialisable_and_complete(engine):
    sim = Simulator(seed=8)
    warm_up(engine, sim, windows=4)
    snap = engine.snapshot()
    text = json.dumps(snap, default=str)
    assert len(text) > 1000
    for key in ("totals", "stages", "timeline", "hosts", "conversations", "posture", "tls", "ledger", "trace", "beacons"):
        assert key in snap
    assert snap["stages"]["captured"] == snap["stages"]["decoded"] > 0
    assert snap["stages"]["decode_errors"] == 0
    assert snap["totals"]["ready_hosts"] >= 2


def test_frame_detail_matches_buffered_frame(engine):
    sim = Simulator(seed=9)
    feed(engine, normal_window(sim, T0))
    seq = engine.seq
    detail = engine.frame_detail(seq)
    assert detail["length"] == len(bytes.fromhex(detail["hex"]))
    assert detail["layers"][0]["name"] == "Ethernet II"


def test_reset_clears_everything_but_keeps_running(engine):
    sim = Simulator(seed=10)
    warm_up(engine, sim, windows=3)
    engine.reset()
    snap = engine.snapshot()
    assert snap["totals"]["packets"] == 0 and snap["alerts"] == [] and engine.ledger.count == 0


# --- helpers ---------------------------------------------------------------------------------


def _rec(**kw):
    return PacketRecord(timestamp=0.0, length=60, src_mac="", dst_mac="", eth_type=0x0800, **kw)


def test_is_probe_counts_only_connection_initiating_packets():
    assert is_probe(_rec(protocol="TCP", dst_port=80, src_port=50000, tcp_flags="SYN"))
    assert not is_probe(_rec(protocol="TCP", dst_port=80, src_port=50000, tcp_flags="SYN,ACK"))
    assert not is_probe(_rec(protocol="TCP", dst_port=80, src_port=50000, tcp_flags="ACK"))
    assert is_probe(_rec(protocol="UDP", dst_port=53, src_port=50000))
    assert not is_probe(_rec(protocol="UDP", dst_port=50000, src_port=53))  # a reply
    assert not is_probe(_rec(protocol="ARP"))


def test_is_local():
    assert is_local("192.168.137.45") and is_local("10.1.2.3")
    assert not is_local("8.8.8.8") and not is_local("224.0.0.251") and not is_local("255.255.255.255")
    assert not is_local(None) and not is_local("not-an-ip")
