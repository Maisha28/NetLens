"""
A labelled benchmark capture for the Tuning Lab.

To say how good a detector is, you need to know the right answer. This builds a
deterministic ~4-minute hotspot capture in which every interesting event is
LABELLED with ground truth:

  attack events        should raise an alert   (port scans, bandwidth spikes, ARP spoofing)
  harmless events      look unusual but should NOT raise an alert
                       (printer discovery, a software update, a video call, a DNS burst)

Everything else is ordinary browsing. Event sizes are defined as multiples of each
device's own *measured* normal (not hard-coded byte counts), so the scenarios stay
meaningful whatever the background looks like.

It is synthetic and says so: it exists to measure the detector's trade-offs
reproducibly, not to claim accuracy on the real world. A real recording can be
scored the same way by placing a <name>.labels.json file next to it.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from capture.pcap_io import CAPTURE_DIR, PcapRecorder
from sim import frames as F
from sim.scenario import GATEWAY, LAPTOP2, PHONE, SITES, LAPTOP_SITES, Simulator

T0 = 1_700_000_000.0
WINDOW = 4.0
WINDOWS = 72
BENCHMARK_NAME = "benchmark"

Frame = Tuple[float, bytes]


def _background(sim: Simulator, rng: random.Random, end: float) -> List[Frame]:
    out: List[Frame] = []
    t = 0.0
    while t < end:  # phone: ordinary browsing, modest session sizes
        site = sim._pick_site(SITES)
        if rng.random() < 0.12:
            frames = sim._quic(PHONE, "142.250.77.14", 0, rng.randint(6, 14))
        else:
            pkts = rng.randint(14, 30) if site[4] == "video" else rng.randint(5, 14)
            frames = sim._tls_session(PHONE, site, 0, pkts, up_bytes=300)
        out += [(T0 + t + off, raw) for off, raw in frames]
        t += rng.expovariate(1 / 0.9)
    t = 0.0
    while t < end:  # second laptop: light background
        frames = sim._tls_session(LAPTOP2, sim._pick_site(LAPTOP_SITES), 0, rng.randint(5, 8))
        out += [(T0 + t + off, raw) for off, raw in frames]
        t += rng.expovariate(1 / 2.2)
    t = 1.0
    while t < end:  # ARP: devices re-announce themselves
        for off, raw in sim._arp_pair(PHONE, GATEWAY, 0) + sim._arp_pair(LAPTOP2, GATEWAY, 0.4):
            out.append((T0 + t + off, raw))
        t += 5.0
    return out


def _window_bytes(frames: List[Frame], ip: str) -> Dict[int, int]:
    """Bytes per window involving a host, counted both directions (as the engine does)."""
    out: Dict[int, int] = {}
    needle_src, needle_dst = F.ip_bytes(ip), F.ip_bytes(ip)
    for ts, raw in frames:
        if len(raw) >= 34 and raw[12:14] == b"\x08\x00" and (raw[26:30] == needle_src or raw[30:34] == needle_dst):
            w = int((ts - T0) // WINDOW)
            out[w] = out.get(w, 0) + len(raw)
    return out


def _scan(attacker, target, ports: List[int], start: float, seconds: float, sport: int, open_ports=(80, 135, 443, 445)) -> List[Frame]:
    out: List[Frame] = []
    for i, port in enumerate(ports):
        t = start + i * seconds / len(ports)
        out.append((t, F.tcp_frame(attacker.mac, target.mac, attacker.ip, target.ip, sport, port, 1000 + i, 0, F.TCP_SYN)))
        if port in open_ports:  # closed ports are silently dropped by a default firewall
            out.append((t + 0.0008, F.tcp_frame(target.mac, attacker.mac, target.ip, attacker.ip, port, sport, 0, 1001 + i, F.TCP_SYN | F.TCP_ACK, ttl=128)))
    return out


def _extra_traffic(ip_client, server_ip: str, start: float, seconds: float, extra_bytes: int, rng: random.Random) -> List[Frame]:
    """A download-like stream adding about `extra_bytes` to `ip_client`'s window."""
    out: List[Frame] = []
    sport = 45000 + rng.randrange(1000)
    sent, i = 0, 0
    per = 1400
    n = max(1, int(extra_bytes / (per + 54 + 27)))
    for i in range(n):
        t = start + i * seconds / n
        out.append((t, F.tcp_frame(GATEWAY.mac, ip_client.mac, server_ip, ip_client.ip, 443, sport, i * per, 1, F.TCP_ACK, rng.randbytes(per), ttl=57)))
        if i % 2:
            out.append((t + 0.0004, F.tcp_frame(ip_client.mac, GATEWAY.mac, ip_client.ip, server_ip, sport, 443, 1, i * per, F.TCP_ACK)))
    return out


def build_benchmark(seed: int = 7) -> Tuple[List[Frame], List[dict]]:
    rng = random.Random(seed)
    sim = Simulator(seed=seed)
    end = WINDOWS * WINDOW
    frames = _background(sim, rng, end)
    labels: List[dict] = []

    # per-device "normal": mean window bytes over the first (quiet, event-free) windows
    base = {}
    for dev in (PHONE, LAPTOP2):
        wb = _window_bytes(frames, dev.ip)
        base[dev.ip] = sum(wb.get(w, 0) for w in range(1, 8)) / 7.0

    def at(w: float) -> float:
        return T0 + w * WINDOW

    def lift(dev, w: int, multiple: float) -> int:
        """Extra bytes needed so window w totals about `multiple` x this device's normal."""
        have = _window_bytes(frames, dev.ip).get(w, 0)
        return max(0, int(multiple * base[dev.ip] - have))

    def add(kind, rule, host, title, why, start, stop, items):
        nonlocal frames
        frames += items
        labels.append({"id": f"{kind[:3]}-{len(labels) + 1}", "kind": kind, "rule": rule, "host": host,
                       "title": title, "why": why, "start": start, "end": stop})

    # ---------------------------------------------------------------- attacks
    ports = rng.sample(range(1, 1025), 296) + [22, 80, 135, 443]
    add("attack", "port_scan", LAPTOP2.ip, "Fast port scan (300 ports)",
        "Second laptop probes 300 ports on this laptop in 8 seconds.", at(8), at(10),
        _scan(LAPTOP2, GATEWAY, ports, at(8), 8.0, 41001))
    for w in (15, 16):
        frames_w = _extra_traffic(PHONE, SITES[1][1], at(w) + 0.2, 3.6, lift(PHONE, w, 10.0), rng)
        frames += frames_w
    labels.append({"id": "att-2", "kind": "attack", "rule": "bandwidth_hog", "host": PHONE.ip,
                   "title": "Heavy download (about 10x normal)", "why": "Phone moves ten times its normal data for two windows.",
                   "start": at(15), "end": at(17)})
    frames += _extra_traffic(PHONE, SITES[1][1], at(28) + 0.2, 3.6, lift(PHONE, 28, 5.5), rng)
    labels.append({"id": "att-3", "kind": "attack", "rule": "bandwidth_hog", "host": PHONE.ip,
                   "title": "Moderate spike (about 5x normal)", "why": "A smaller but still clearly abnormal burst.",
                   "start": at(28), "end": at(29)})
    add("attack", "arp_spoof", GATEWAY.ip, "ARP spoofing (gateway impersonated)",
        "Second laptop claims the gateway's IP with its own MAC.", at(36), at(37),
        [(at(36) + i, F.arp_frame(2, LAPTOP2.mac, GATEWAY.ip, PHONE.mac, PHONE.ip)) for i in range(5)])
    slow = rng.sample(range(400, 1000), 70)
    add("attack", "port_scan", LAPTOP2.ip, "Slow, quiet port scan (70 ports)",
        "A stealthier scan: about 35 ports per window.", at(42), at(44),
        _scan(LAPTOP2, GATEWAY, slow, at(42), 8.0, 41002))
    add("attack", "arp_spoof", GATEWAY.ip, "ARP spoofing again",
        "The same impersonation is repeated later.", at(66), at(67),
        [(at(66) + i, F.arp_frame(2, LAPTOP2.mac, GATEWAY.ip, PHONE.mac, PHONE.ip)) for i in range(5)])

    for w in range(44, 50):  # sustained: six windows at ~6x normal
        frames += _extra_traffic(PHONE, SITES[1][1], at(w) + 0.2, 3.6, lift(PHONE, w, 6.0), rng)
    labels.append({"id": "att-x", "kind": "attack", "rule": "bandwidth_hog", "host": PHONE.ip,
                   "title": "Sustained heavy use (6 windows at about 6x)",
                   "why": "A long, steady abnormal download - the kind that tries to become the new normal.",
                   "start": at(44), "end": at(50)})

    # ------------------------------------------------------ harmless but unusual
    disc = rng.sample([53, 67, 80, 443, 1900, 5353, 8080, 8443, 9100, 631, 515, 3702], 12)
    add("benign", "port_scan", LAPTOP2.ip, "Printer / device discovery (12 ports)",
        "Harmless: a laptop looking for printers and media devices touches a dozen ports.", at(12), at(13),
        _scan(LAPTOP2, GATEWAY, disc, at(12) + 0.3, 3.0, 41003))
    frames += _extra_traffic(LAPTOP2, LAPTOP_SITES[1][1], at(20) + 0.2, 3.5, lift(LAPTOP2, 20, 3.4), rng)
    labels.append({"id": "ben-6", "kind": "benign", "rule": "bandwidth_hog", "host": LAPTOP2.ip,
                   "title": "Small software update (about 3.4x a quiet laptop)", "why": "Harmless: a quiet device downloads a small update - a big ratio but a tiny volume.",
                   "start": at(20), "end": at(21)})
    frames += _extra_traffic(PHONE, SITES[0][1], at(24) + 0.2, 3.6, lift(PHONE, 24, 2.6), rng)
    labels.append({"id": "ben-7", "kind": "benign", "rule": "bandwidth_hog", "host": PHONE.ip,
                   "title": "App update (about 2.6x normal)", "why": "Harmless: noticeably busier than usual, but ordinary.",
                   "start": at(24), "end": at(25)})
    dns = []
    for i in range(44):
        sport = 33000 + i * 11
        t = at(33) + 0.1 + i * 0.08
        dns.append((t, F.udp_frame(PHONE.mac, GATEWAY.mac, PHONE.ip, GATEWAY.ip, sport, 53, F.dns_query(i, f"tracker{i}.example.com"))))
        dns.append((t + 0.015, F.udp_frame(GATEWAY.mac, PHONE.mac, GATEWAY.ip, PHONE.ip, 53, sport, F.dns_response(i, f"tracker{i}.example.com", ["93.184.216.34"]))))
    add("benign", "port_scan", GATEWAY.ip, "Web page with 44 DNS lookups",
        "Harmless: the gateway answers lots of DNS queries from many client ports - replies are not probes.", at(33), at(34), dns)
    for w in (58, 59, 60):
        frames += _extra_traffic(PHONE, SITES[2][1], at(w) + 0.2, 3.6, lift(PHONE, w, 2.3), rng)
    labels.append({"id": "ben-9", "kind": "benign", "rule": "bandwidth_hog", "host": PHONE.ip,
                   "title": "Video call (about 2.3x normal for 12 s)", "why": "Harmless: steady, higher-than-usual traffic.",
                   "start": at(58), "end": at(61)})

    frames.sort(key=lambda f: f[0])
    labels.sort(key=lambda l: l["start"])
    counters = {"attack": 0, "benign": 0}
    for l in labels:  # stable, unique ids in time order
        counters[l["kind"]] += 1
        l["id"] = f"{'att' if l['kind'] == 'attack' else 'ben'}-{counters[l['kind']]}"
    return frames, labels


def labels_path(capture_path: Path) -> Path:
    return capture_path.with_name(capture_path.stem + ".labels.json")


def write_benchmark(directory: Path = CAPTURE_DIR, seed: int = 7) -> Path:
    """Write benchmark.pcap and benchmark.labels.json (overwriting) and return the pcap path."""
    frames, labels = build_benchmark(seed)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{BENCHMARK_NAME}.pcap"
    rec = PcapRecorder(directory, filename=f"{BENCHMARK_NAME}.pcap")
    for ts, raw in frames:
        rec.write(raw, ts)
    rec.close()
    labels_path(path).write_text(json.dumps({"seed": seed, "window_seconds": WINDOW, "labels": labels}, indent=2))
    return path


def load_labels(capture_path: Path) -> Optional[List[dict]]:
    p = labels_path(capture_path)
    if not p.exists():
        return None
    return json.loads(p.read_text()).get("labels")
