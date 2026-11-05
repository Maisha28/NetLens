"""
Traffic simulator - a believable hotspot network that needs no Administrator
rights, no Npcap and no phone.

It emits RAW FRAMES (bytes + timestamp), the exact interface capture/capture.py
exposes, so everything downstream - decoder, flow tracker, baseline, detection,
ledger, UI - runs unmodified on simulated traffic. The UI labels this mode
"SIMULATION"; nothing is hidden.

Devices on the simulated 192.168.137.0/24 hotspot:
    laptop  .1   gateway / DNS (this machine)
    phone   .45  browses (YouTube, Instagram, news, Spotify, Apple services)
    laptop2 .60  light background traffic; the "attacker" in staged scenarios
    bulb    .80  legacy IoT bulb - joins on demand, speaks TLS 1.0 + RC4

Scenarios are staged against devices on the simulated network only, mirroring
the project's ethics rule (own devices, own network, to test our own detector).
"""

from __future__ import annotations

import heapq
import random
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Tuple, Union

from sim import frames as F


@dataclass(frozen=True)
class Device:
    key: str
    name: str
    ip: str
    mac: str


GATEWAY = Device("gateway", "This laptop (gateway)", "192.168.137.1", "00:0c:f1:5a:22:10")
PHONE = Device("phone", "Phone", "192.168.137.45", "da:4e:91:3c:70:b2")  # randomised MAC
LAPTOP2 = Device("laptop2", "Second laptop", "192.168.137.60", "00:1b:21:ab:cd:ef")
BULB = Device("bulb", "Smart bulb", "192.168.137.80", "24:0a:c4:19:5e:77")

DEVICES = [GATEWAY, PHONE, LAPTOP2, BULB]

# domain, server ip, TLS profile, weight, session kind
SITES = [
    ("www.youtube.com", "142.250.77.14", "modern", 18, "video"),
    ("rr2---sn-gvnuxaxjvh-gvnl.googlevideo.com", "172.217.14.206", "modern", 8, "video"),
    ("www.instagram.com", "157.240.1.174", "modern", 16, "api"),
    ("graph.facebook.com", "157.240.22.19", "modern", 5, "api"),
    ("www.nytimes.com", "151.101.65.164", "modern", 8, "api"),
    ("api.spotify.com", "35.186.224.53", "modern", 8, "api"),
    ("gsp-ssl.ls.apple.com", "17.253.144.10", "safari_like", 9, "api"),
    ("cdnjs.cloudflare.com", "104.16.133.229", "modern", 6, "api"),
    ("chatgpt.com", "104.18.32.47", "modern", 7, "api"),
    ("en.wikipedia.org", "208.80.154.224", "modern", 5, "api"),
    ("github.com", "140.82.113.3", "modern", 5, "api"),
    ("s3.amazonaws.com", "52.216.88.131", "tls12_only", 5, "api"),
]
LAPTOP_SITES = [
    ("teams.microsoft.com", "20.190.151.67", "tls12_only", 1, "api"),
    ("github.com", "140.82.113.3", "modern", 1, "api"),
    ("www.google.com", "142.250.183.100", "modern", 1, "api"),
]
APPLE = ("gsp-ssl.ls.apple.com", "17.253.144.10", "safari_like", 0, "beacon")
GOOGLE = ("mtalk.google.com", "142.250.4.188", "modern", 0, "beacon")
META = ("graph.instagram.com", "157.240.1.63", "modern", 0, "beacon")
BULB_CLOUD = ("cloud.lumio-bulbs.com", "52.58.77.201", "legacy_iot", 0, "beacon")
BULB_FW = ("fw.lumio-bulbs.com", "52.58.77.202", "legacy_iot", 0, "http")

Item = Union[bytes, Callable[[float], None]]

# (id, title, what it demonstrates) - shown by the UI's Scenario Lab.
SCENARIOS = {
    "smart_bulb": "A legacy smart bulb joins the network",
    "bandwidth_hog": "Phone suddenly downloads far more than its baseline",
    "port_scan": "Second laptop scans this laptop's ports",
    "arp_spoof": "Second laptop claims the gateway's IP address",
    "idle_phone": "Phone put face-down: only background beacons remain",
    "resume_browsing": "Phone back in use",
    "guided": "Scripted full run: bulb -> hog -> scan -> spoof",
}


class Simulator:
    def __init__(self, seed: Optional[int] = None, rate: float = 1.0) -> None:
        self.rng = random.Random(seed)
        self.rate = rate
        self._heap: List[Tuple[float, int, Item]] = []
        self._seq = 0
        self._lock = threading.RLock()
        self._stop = False
        self._paused = False
        self._idle = False
        self._bulb_on = False
        self._next: Dict[str, float] = {}
        self._active: Dict[str, float] = {}  # scenario -> monotonic end time
        self._log: List[dict] = []
        self._sport = {d.key: self.rng.randint(40000, 60000) for d in DEVICES}
        self._guided_steps: List[dict] = []

    # --- control (called from the web thread) -----------------------------

    def stop(self) -> None:
        self._stop = True

    def pause(self, paused: bool) -> None:
        self._paused = paused

    @property
    def paused(self) -> bool:
        return self._paused

    def reset(self) -> None:
        with self._lock:
            self._heap.clear()
            self._active.clear()
            self._next.clear()
            self._idle = False
            self._bulb_on = False
            self._guided_steps = []
            self._log = []

    def trigger(self, name: str) -> dict:
        """Start a scenario now. Returns what was scheduled (for the UI)."""
        if name not in SCENARIOS:
            raise KeyError(name)
        now = time.monotonic()
        with self._lock:
            handler = getattr(self, f"_scn_{name}")
            info = handler(now) or {}
            self._log.append({"t": time.time(), "scenario": name, "title": SCENARIOS[name]})
            self._log = self._log[-30:]
        return {"scenario": name, "title": SCENARIOS[name], **info}

    def status(self) -> dict:
        now = time.monotonic()
        with self._lock:
            active = {k: round(v - now, 1) for k, v in self._active.items() if v > now}
            return {
                "paused": self._paused,
                "idle_phone": self._idle,
                "bulb_online": self._bulb_on,
                "active": active,
                "guided": list(self._guided_steps),
                "log": list(self._log[-8:]),
                "scenarios": SCENARIOS,
            }

    # --- scheduling helpers -------------------------------------------------

    def _push(self, due: float, item: Item) -> None:
        self._seq += 1
        heapq.heappush(self._heap, (due, self._seq, item))

    def _push_all(self, base: float, items: List[Tuple[float, bytes]]) -> None:
        for offset, frame in items:
            self._push(base + offset, frame)

    def _eph(self, device: Device) -> int:
        self._sport[device.key] = 40000 + (self._sport[device.key] - 40000 + self.rng.randint(1, 97)) % 20000
        return self._sport[device.key]

    # --- session builders -----------------------------------------------------

    def _dns(self, client: Device, domain: str, ip: str, t: float, cname: Optional[str] = None) -> List[Tuple[float, bytes]]:
        txid = self.rng.getrandbits(16)
        sport = self._eph(client)
        q = F.udp_frame(client.mac, GATEWAY.mac, client.ip, GATEWAY.ip, sport, 53, F.dns_query(txid, domain))
        r = F.udp_frame(GATEWAY.mac, client.mac, GATEWAY.ip, client.ip, 53, sport, F.dns_response(txid, domain, [ip], cname=cname))
        return [(t, q), (t + 0.018, r)]

    def _tls_session(
        self, client: Device, site: tuple, t0: float, data_pkts: int, with_dns: bool = True, up_bytes: int = 0,
    ) -> List[Tuple[float, bytes]]:
        domain, ip, profile, _w, _k = site
        out: List[Tuple[float, bytes]] = []
        t = t0
        if with_dns:
            out += self._dns(client, domain, ip, t, cname=("edge." + domain) if self.rng.random() < 0.3 else None)
            t += 0.06
        sport = self._eph(client)
        cseq, sseq = self.rng.getrandbits(31), self.rng.getrandbits(31)
        ttl_s = self.rng.choice([52, 54, 57, 58, 60])
        mac_c, mac_s = client.mac, GATEWAY.mac  # next hop is always the gateway

        def c2s(flags, payload=b"", dt=0.0):
            nonlocal t, cseq
            t += dt
            out.append((t, F.tcp_frame(mac_c, mac_s, client.ip, ip, sport, 443, cseq, sseq + 1, flags, payload)))
            cseq += len(payload) + (1 if flags & (F.TCP_SYN | F.TCP_FIN) else 0)

        def s2c(flags, payload=b"", dt=0.0):
            nonlocal t, sseq
            t += dt
            out.append((t, F.tcp_frame(mac_s, mac_c, ip, client.ip, 443, sport, sseq, cseq, flags, payload, ttl=ttl_s)))
            sseq += len(payload) + (1 if flags & (F.TCP_SYN | F.TCP_FIN) else 0)

        c2s(F.TCP_SYN, dt=0.0)
        s2c(F.TCP_SYN | F.TCP_ACK, dt=0.022)
        c2s(F.TCP_ACK, dt=0.001)
        c2s(F.TCP_PSH | F.TCP_ACK, F.tls_client_hello(domain, profile, self.rng), dt=0.003)
        version, cipher = {
            "modern": (0x0304, 0x1301),
            "safari_like": (0x0304, 0x1302),
            "tls12_only": (0x0303, 0xC02F),
            "legacy_iot": (0x0301, 0x0005),
        }[profile]
        s2c(F.TCP_PSH | F.TCP_ACK, F.tls_server_hello(version, cipher, self.rng), dt=0.026)
        c2s(F.TCP_ACK, dt=0.002)
        for i in range(data_pkts):
            size = self.rng.choice([1380, 1400, 1400, 1400, 900, 512])
            s2c(F.TCP_PSH | F.TCP_ACK, F.tls_app_data(size - 5, self.rng), dt=self.rng.uniform(0.006, 0.035))
            if i % 2 == 1:
                c2s(F.TCP_ACK, dt=0.001)
            if up_bytes and i % 7 == 3:
                c2s(F.TCP_PSH | F.TCP_ACK, F.tls_app_data(up_bytes, self.rng), dt=0.002)
        c2s(F.TCP_FIN | F.TCP_ACK, dt=0.01)
        s2c(F.TCP_FIN | F.TCP_ACK, dt=0.02)
        c2s(F.TCP_ACK, dt=0.001)
        return out

    def _quic(self, client: Device, ip: str, t0: float, n: int) -> List[Tuple[float, bytes]]:
        sport, t, out = self._eph(client), t0, []
        for i in range(n):
            t += self.rng.uniform(0.004, 0.03)
            out.append((t, F.udp_frame(client.mac, GATEWAY.mac, client.ip, ip, sport, 443, self.rng.randbytes(1200 if i else 1250))))
            out.append((t + 0.02, F.udp_frame(GATEWAY.mac, client.mac, ip, client.ip, 443, sport, self.rng.randbytes(self.rng.choice([1200, 1350])), ttl=57)))
        return out

    def _http_clear(self, client: Device, site: tuple, t0: float) -> List[Tuple[float, bytes]]:
        domain, ip, _p, _w, _k = site
        out = self._dns(client, domain, ip, t0)
        t = t0 + 0.06
        sport = self._eph(client)
        cseq, sseq = self.rng.getrandbits(31), self.rng.getrandbits(31)
        out.append((t, F.tcp_frame(client.mac, GATEWAY.mac, client.ip, ip, sport, 80, cseq, 0, F.TCP_SYN)))
        out.append((t + 0.03, F.tcp_frame(GATEWAY.mac, client.mac, ip, client.ip, 80, sport, sseq, cseq + 1, F.TCP_SYN | F.TCP_ACK)))
        req = F.http_request("/fw/check?v=1.2.0", domain)
        out.append((t + 0.032, F.tcp_frame(client.mac, GATEWAY.mac, client.ip, ip, sport, 80, cseq + 1, sseq + 1, F.TCP_PSH | F.TCP_ACK, req)))
        out.append((t + 0.07, F.tcp_frame(GATEWAY.mac, client.mac, ip, client.ip, 80, sport, sseq + 1, cseq + 1 + len(req), F.TCP_PSH | F.TCP_ACK, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")))
        return out

    def _arp_pair(self, asker: Device, target: Device, t0: float) -> List[Tuple[float, bytes]]:
        return [
            (t0, F.arp_frame(1, asker.mac, asker.ip, "00:00:00:00:00:00", target.ip)),
            (t0 + 0.002, F.arp_frame(2, target.mac, target.ip, asker.mac, asker.ip)),
        ]

    # --- background traffic -----------------------------------------------------

    def _pick_site(self, pool: list) -> tuple:
        return self.rng.choices(pool, weights=[s[3] for s in pool])[0]

    def _background(self, now: float) -> None:
        def due(name: str, mean: float, jitter: float = 0.0) -> bool:
            nxt = self._next.get(name)
            if nxt is None:
                self._next[name] = now + self.rng.uniform(0.0, mean)
                return False
            if now < nxt:
                return False
            gap = self.rng.expovariate(1.0 / mean) if jitter == 0 else mean * (1 + self.rng.uniform(-jitter, jitter))
            self._next[name] = now + max(0.05, gap / self.rate)
            return True

        if not self._idle and due("phone", 0.75):
            site = self._pick_site(SITES)
            if self.rng.random() < 0.14:
                self._push_all(now, self._quic(PHONE, "142.250.77.14", 0, self.rng.randint(6, 18)))
            else:
                pkts = self.rng.randint(25, 55) if site[4] == "video" else self.rng.randint(5, 16)
                self._push_all(now, self._tls_session(PHONE, site, 0, pkts, up_bytes=300))
        if due("laptop2", 2.2, jitter=0.3):
            self._push_all(now, self._tls_session(LAPTOP2, self._pick_site(LAPTOP_SITES), 0, self.rng.randint(5, 8)))
        if due("arp", 5.0, jitter=0.1):
            self._push_all(now, self._arp_pair(PHONE, GATEWAY, 0))
            self._push_all(now, self._arp_pair(LAPTOP2, GATEWAY, 0.4))
        if self._idle:
            # Idle phone: only periodic, near-fixed-interval background check-ins.
            if due("beacon_apple", 10.0, jitter=0.03):
                self._push_all(now, self._tls_session(PHONE, APPLE, 0, 3))
            if due("beacon_google", 15.0, jitter=0.03):
                self._push_all(now, self._tls_session(PHONE, GOOGLE, 0, 3))
            if due("beacon_meta", 30.0, jitter=0.04):
                self._push_all(now, self._tls_session(PHONE, META, 0, 4))
        if self._bulb_on:
            if due("bulb", 10.0, jitter=0.04):
                self._push_all(now, self._tls_session(BULB, BULB_CLOUD, 0, 2))
            if due("bulb_fw", 22.0, jitter=0.05):
                self._push_all(now, self._http_clear(BULB, BULB_FW, 0))
            if due("bulb_arp", 6.0, jitter=0.1):
                self._push_all(now, self._arp_pair(BULB, GATEWAY, 0))

    # --- scenarios ------------------------------------------------------------------

    def _scn_smart_bulb(self, now: float) -> dict:
        self._bulb_on = True
        self._next.pop("bulb", None)
        self._push_all(now, self._arp_pair(BULB, GATEWAY, 0.0))
        self._push_all(now, self._tls_session(BULB, BULB_CLOUD, 0.3, 2))
        self._push_all(now, self._http_clear(BULB, BULB_FW, 1.2))
        return {"device": BULB.ip}

    def _scn_idle_phone(self, now: float) -> dict:
        self._idle = True
        for k in ("beacon_apple", "beacon_google", "beacon_meta"):
            self._next[k] = now + 1.0
        return {"device": PHONE.ip}

    def _scn_resume_browsing(self, now: float) -> dict:
        self._idle = False
        return {"device": PHONE.ip}

    def _scn_bandwidth_hog(self, now: float, seconds: float = 9.0, pps: int = 300) -> dict:
        # One long video-style download: a sustained stream of full-size frames.
        site = SITES[1]
        _d, ip, _p, _w, _k = site
        sport, seq, ack = self._eph(PHONE), self.rng.getrandbits(31), self.rng.getrandbits(31)
        frames: List[Tuple[float, bytes]] = []
        total = int(seconds * pps)
        for i in range(total):
            t = i / pps
            payload = self.rng.randbytes(1400)
            frames.append((t, F.tcp_frame(GATEWAY.mac, PHONE.mac, ip, PHONE.ip, 443, sport, seq + i * 1400, ack, F.TCP_ACK, payload, ttl=57)))
            if i % 2:
                frames.append((t + 0.0005, F.tcp_frame(PHONE.mac, GATEWAY.mac, PHONE.ip, ip, sport, 443, ack, seq + i * 1400, F.TCP_ACK)))
        self._push_all(now, frames)
        self._active["bandwidth_hog"] = now + seconds
        return {"device": PHONE.ip, "seconds": seconds}

    def _scn_port_scan(self, now: float, seconds: float = 8.0, pps: int = 45) -> dict:
        ports = self.rng.sample(range(1, 1025), int(seconds * pps) - 4) + [22, 80, 135, 443]
        self.rng.shuffle(ports)
        sport = self._eph(LAPTOP2)
        open_ports = {80, 135, 443, 445}
        frames: List[Tuple[float, bytes]] = []
        for i, port in enumerate(ports):
            t = i / pps
            seq = self.rng.getrandbits(31)
            frames.append((t, F.tcp_frame(LAPTOP2.mac, GATEWAY.mac, LAPTOP2.ip, GATEWAY.ip, sport, port, seq, 0, F.TCP_SYN)))
            # A default Windows firewall silently DROPS SYNs to closed ports (no RST),
            # so only the few open ports answer - exactly what a real scan looks like.
            if port in open_ports:
                frames.append((t + 0.0008, F.tcp_frame(GATEWAY.mac, LAPTOP2.mac, GATEWAY.ip, LAPTOP2.ip, port, sport, 0, seq + 1, F.TCP_SYN | F.TCP_ACK, ttl=128)))
        self._push_all(now, frames)
        self._active["port_scan"] = now + seconds
        return {"attacker": LAPTOP2.ip, "target": GATEWAY.ip, "ports": len(ports)}

    def _scn_arp_spoof(self, now: float, seconds: float = 7.0) -> dict:
        # "The gateway's IP is at MY MAC" - repeated, as real ARP poisoning is,
        # because the victim's cache entry times out and must be re-poisoned.
        frames = []
        for i in range(int(seconds)):
            frames.append((i * 1.0, F.arp_frame(2, LAPTOP2.mac, GATEWAY.ip, PHONE.mac, PHONE.ip)))
        self._push_all(now, frames)
        self._active["arp_spoof"] = now + seconds
        return {"attacker_mac": LAPTOP2.mac, "claims": GATEWAY.ip, "victim": PHONE.ip}

    def _scn_guided(self, now: float) -> dict:
        steps = [
            (0, "smart_bulb", "A legacy IoT bulb joins - watch Crypto"),
            (9, "bandwidth_hog", "Phone download spikes past its baseline"),
            (27, "port_scan", "Laptop scans this machine's ports"),
            (44, "arp_spoof", "Laptop impersonates the gateway"),
        ]
        self._guided_steps = []
        for offset, scenario, text in steps:
            entry = {"at": offset, "scenario": scenario, "text": text, "done": False}
            self._guided_steps.append(entry)

            def fire(_n, s=scenario, e=entry):
                e["done"] = True
                self.trigger(s)

            self._push(now + offset, fire)
        return {"steps": len(steps)}

    # --- the stream --------------------------------------------------------------------

    def stream(self) -> Iterator[Tuple[bytes, float]]:
        """Yield (raw_frame, wall_timestamp) in real time, forever, until stop()."""
        while not self._stop:
            if self._paused:
                time.sleep(0.1)
                continue
            now = time.monotonic()
            emitted = 0
            with self._lock:
                self._background(now)
                ready: List[bytes] = []
                while self._heap and self._heap[0][0] <= now and emitted < 500:
                    _due, _seq, item = heapq.heappop(self._heap)
                    if callable(item):
                        item(now)
                    else:
                        ready.append(item)
                        emitted += 1
            for frame in ready:
                yield frame, time.time()
            if not ready:
                time.sleep(0.004)
