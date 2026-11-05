"""
The NetLens pipeline as one object, shared by the terminal CLI and the web UI.

    frames -> decode -> hostnames/TLS/ARP -> flows + conversations -> SQLite
                                           -> per-host interval stats
    every window: baselines -> bandwidth_hog / port_scan rules -> alerts
                  -> signed ledger -> UI

main.py (terminal) and web/server.py (dashboard) both drive this class, so the
two interfaces can never disagree about what the detections are. All mutable
state sits behind one RLock; ingest() is called from the capture/simulator
thread, snapshot()/views from HTTP handler threads.

Time: time_source="wall" runs windows off a ticker thread (live capture and
the simulator); "packet" closes windows from packet timestamps, which makes
pcap replay and the tests deterministic and independent of the clock.
"""

from __future__ import annotations

import ipaddress
import statistics
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable, Deque, Dict, Iterable, List, Optional, Tuple

from baseline.baseline import BaselineTracker, IntervalStats
from crypto.ledger import Ledger, load_or_create_key
from decoder.decoder import decode
from decoder.explain import explain_frame
from detection.rules import Alert, ArpWatcher, check_bandwidth_hog, check_port_scan
from enrichment.enrichment import resolve_org
from enrichment.hostnames import HostnameMap
from enrichment.oui import is_randomized, vendor
from shared.packet_record import PacketRecord
from storage.db import get_connection, store_alert, store_flows, store_packet, upsert_baseline
from storage.flow_tracker import FlowKey, FlowStats, bump_flow

PACKET_RING = 1500
RAW_RING = 5000
MAX_CONVS = 3000
HISTORY_POINTS = 90
ALERT_COOLDOWN_SECONDS = 12.0

POSTURE_LABELS = {
    "tls13": "TLS 1.3",
    "tls12": "TLS 1.2",
    "tls_legacy": "Legacy TLS (<= 1.1)",
    "tls_unseen": "HTTPS (handshake not seen)",
    "quic": "QUIC (opaque)",
    "dns": "DNS (plaintext)",
    "cleartext": "Cleartext HTTP / other",
    "other": "Other / unclassified",
}


@lru_cache(maxsize=8192)
def is_local(ip: Optional[str]) -> bool:
    """A device on the local network (RFC 1918 etc.), excluding broadcast/multicast noise."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback or addr.is_link_local:
        return False
    return addr.is_private and str(addr) != "255.255.255.255"


def is_probe(record: PacketRecord) -> bool:
    """
    A packet that *initiates* contact with a destination port: a TCP SYN
    without ACK, or a UDP datagram from an ephemeral port to a service port.
    The port-scan rule counts these only. Counting every packet's destination
    port would make a DNS server replying to many clients look like a scanner -
    a measured false positive, which is why the rule is defined this way.
    """
    if record.dst_port is None:
        return False
    if record.protocol == "TCP":
        flags = (record.tcp_flags or "").split(",")
        return "SYN" in flags and "ACK" not in flags
    if record.protocol == "UDP":
        return (record.src_port or 0) >= 32768 > record.dst_port
    return False


@dataclass
class HostState:
    ip: str
    mac: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    bytes: int = 0
    packets: int = 0
    ttl: Optional[int] = None
    orgs: Counter = field(default_factory=Counter)
    sites: Counter = field(default_factory=Counter)
    history: Deque[dict] = field(default_factory=lambda: deque(maxlen=HISTORY_POINTS))
    last_alert_at: float = 0.0


@dataclass
class Conversation:
    initiator: Tuple[str, int]
    responder: Tuple[str, int]
    protocol: str
    first: float
    last: float
    packets: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    posture: str = "other"
    sni: str = ""
    state: str = "open"
    ja3: str = ""


class Engine:
    def __init__(
        self,
        db_path: Optional[Path] = None,
        window_seconds: float = 4.0,
        time_source: str = "wall",
        key_path: Optional[Path] = None,
        fresh: bool = True,
    ) -> None:
        self.window_seconds = window_seconds
        self.time_source = time_source
        self.lock = threading.RLock()
        self.conn = get_connection(db_path, shared=True) if db_path else get_connection(shared=True)
        if key_path is None:
            key_path = Path(__file__).resolve().parent.parent / "storage" / ".ledger_key"
        self.ledger = Ledger(self.conn, load_or_create_key(key_path), self.lock)
        self.on_packet: List[Callable[[PacketRecord], None]] = []
        self.on_alert: List[Callable[[dict], None]] = []
        self.mode = "idle"
        self.source_error: Optional[str] = None
        # Set by the web app: capture interface, pcap being recorded, this
        # machine's own addresses (so the UI can label "this laptop").
        self.meta: Dict[str, object] = {"iface": None, "record": None, "self_ips": [], "label": ""}
        self.paused = False
        self._run_id = 0
        self._ticker: Optional[threading.Thread] = None
        self._shutdown = threading.Event()
        self.simulator = None  # set by the web app when in simulation mode
        self._init_state()
        if fresh:
            self._truncate_tables()

    # ------------------------------------------------------------------ state

    def _init_state(self) -> None:
        self.started_at = time.time()
        self.hostnames = HostnameMap()
        self.tracker = BaselineTracker()
        self.arp = ArpWatcher()
        self.flows: Dict[FlowKey, FlowStats] = {}
        self.convs: Dict[tuple, Conversation] = {}
        self.hosts: Dict[str, HostState] = {}
        self.interval: Dict[str, IntervalStats] = {}
        self.window_bytes_total = 0
        self.window_start = time.time()
        self._window_end: Optional[float] = None
        self.packet_ring: Deque[dict] = deque(maxlen=PACKET_RING)
        self.raw_ring: Dict[int, bytes] = {}
        self.alerts: List[dict] = []
        self._cooldown: Dict[Tuple[str, str], dict] = {}
        self.timeline: Dict[int, List[int]] = {}
        self.proto_bytes: Counter = Counter()
        self.proto_packets: Counter = Counter()
        self.org_bytes: Counter = Counter()
        self.posture_bytes: Counter = Counter()
        self.tls_rows: Dict[tuple, dict] = {}
        self.ja3_groups: Dict[str, dict] = {}
        self.findings: Dict[tuple, dict] = {}
        self.dns_queries = 0
        self.dns_names: Counter = Counter()
        self.syn_times: Dict[Tuple[str, str], Deque[float]] = defaultdict(lambda: deque(maxlen=30))
        self.seq = 0
        self.counters = Counter()
        self.last_ts = time.time()
        self.last_raw: bytes = b""
        self.last_record: Optional[PacketRecord] = None
        self.last_flow_key: Optional[FlowKey] = None
        self.last_host: Optional[str] = None
        self.window_log: Deque[dict] = deque(maxlen=60)

    def _truncate_tables(self) -> None:
        with self.lock:
            for table in ("packets", "flows", "baselines", "alerts"):
                self.conn.execute(f"DELETE FROM {table}")
            self.conn.commit()
            self.ledger.reset()

    def reset(self) -> None:
        with self.lock:
            self._init_state()
            self._truncate_tables()
            if self.simulator is not None:
                self.simulator.reset()

    def set_time_source(self, source: str) -> None:
        """'wall' for live/simulated traffic, 'packet' for pcap replay (windows follow packet timestamps)."""
        with self.lock:
            self.time_source = source
            self._window_end = None

    def now(self) -> float:
        return time.time() if self.time_source == "wall" else self.last_ts

    # ------------------------------------------------------------- lifecycle

    def start_ticker(self) -> None:
        """Wall-clock window closing for live capture / simulation."""
        if self._ticker is not None:
            return

        def loop() -> None:
            while not self._shutdown.is_set():
                time.sleep(0.2)
                with self.lock:
                    if self.time_source != "wall":
                        continue
                    now = time.time()
                    if self._window_end is None:
                        self._window_end = now + self.window_seconds
                    elif now >= self._window_end:
                        self.tick(now)
                        self._window_end = now + self.window_seconds

        self._ticker = threading.Thread(target=loop, daemon=True, name="netlens-ticker")
        self._ticker.start()

    def run_source(self, frames: Iterable[Tuple[bytes, float]], mode: str) -> threading.Thread:
        """Consume (raw, ts) frames on a background thread until replaced or shut down."""
        with self.lock:
            self._run_id += 1
            run_id = self._run_id
            self.mode = mode
            self.source_error = None

        def loop() -> None:
            try:
                for raw, ts in frames:
                    if self._shutdown.is_set() or run_id != self._run_id:
                        break
                    if self.paused:
                        continue
                    self.ingest_frame(raw, ts)
            except PermissionError:
                self.source_error = (
                    "Permission denied opening the capture device. Run from an Administrator "
                    "terminal with Npcap installed (WinPcap-compatible mode)."
                )
            except OSError as exc:
                self.source_error = f"Capture failed to start ({exc}). Is Npcap installed and is the interface correct?"
            except Exception as exc:  # never let the thread die silently
                self.source_error = f"{type(exc).__name__}: {exc}"

        thread = threading.Thread(target=loop, daemon=True, name=f"netlens-source-{mode}")
        thread.start()
        return thread

    def shutdown(self) -> None:
        self._shutdown.set()
        self._run_id += 1
        with self.lock:
            self.conn.commit()

    # --------------------------------------------------------------- ingest

    def ingest_frame(self, raw: bytes, ts: float) -> Optional[PacketRecord]:
        """Decode one raw frame and run it through the pipeline. Never raises."""
        with self.lock:
            self.counters["frames_captured"] += 1
            try:
                record = decode(raw, ts)
            except Exception:
                self.counters["decode_errors"] += 1
                return None
            self.counters["decoded_ok"] += 1
            try:
                self.ingest(record, raw)
            except Exception:
                self.counters["pipeline_errors"] += 1
                return None
            return record

    def ingest(self, record: PacketRecord, raw: Optional[bytes] = None) -> None:
        with self.lock:
            self.last_ts = record.timestamp
            if self.time_source == "packet":
                if self._window_end is None:
                    self._window_end = record.timestamp + self.window_seconds
                elif record.timestamp >= self._window_end:
                    self.tick(record.timestamp)
                    self._window_end = record.timestamp + self.window_seconds

            self.seq += 1
            self.hostnames.learn(record)
            store_packet(record, self.conn, commit=False)
            self.counters["packets_stored"] += 1
            flow = bump_flow(self.flows, record)
            self.last_flow_key = flow.key
            self.last_record = record
            if raw is not None:
                self.last_raw = raw
                self.raw_ring[self.seq] = raw
                self.raw_ring.pop(self.seq - RAW_RING, None)

            self.last_host = record.src_ip if is_local(record.src_ip) else record.dst_ip
            self._account_traffic(record)
            self._track_conversation(record)
            self._track_hosts(record)
            self._track_tls(record)
            self._check_arp(record)
            self._append_feed(record)
            for callback in self.on_packet:
                callback(record)

    # --- per-packet accounting -------------------------------------------------

    def _account_traffic(self, record: PacketRecord) -> None:
        proto = record.protocol or "OTHER"
        self.proto_bytes[proto] += record.length
        self.proto_packets[proto] += 1
        self.window_bytes_total += record.length
        bucket = self.timeline.setdefault(int(record.timestamp), [0, 0, 0, 0, 0, 0])
        bucket[0] += record.length
        bucket[1] += 1
        bucket[{"TCP": 2, "UDP": 3, "ARP": 4}.get(proto, 5)] += record.length
        if len(self.timeline) > 700:
            for key in sorted(self.timeline)[:100]:
                del self.timeline[key]

        if record.dns_query_name and record.dns_is_response is False:
            self.dns_queries += 1
            self.dns_names[record.dns_query_name] += 1

        remote = record.dst_ip if is_local(record.src_ip) and not is_local(record.dst_ip) else (
            record.src_ip if is_local(record.dst_ip) and not is_local(record.src_ip) else None
        )
        if remote:
            self.org_bytes[resolve_org(remote)] += record.length

    def _track_conversation(self, record: PacketRecord) -> None:
        if not record.src_ip or not record.dst_ip or record.protocol not in ("TCP", "UDP"):
            return
        a = (record.src_ip, record.src_port or 0)
        b = (record.dst_ip, record.dst_port or 0)
        key = (min(a, b), max(a, b), record.protocol)
        conv = self.convs.get(key)
        if conv is None:
            conv = self.convs[key] = Conversation(
                initiator=a, responder=b, protocol=record.protocol, first=record.timestamp, last=record.timestamp
            )
            if len(self.convs) > MAX_CONVS:
                for old in sorted(self.convs, key=lambda k: self.convs[k].last)[:200]:
                    del self.convs[old]
        conv.packets += 1
        conv.last = record.timestamp
        if a == conv.initiator:
            conv.bytes_up += record.length
        else:
            conv.bytes_down += record.length

        flags = (record.tcp_flags or "").split(",")
        if "RST" in flags:
            conv.state = "reset"
        elif "FIN" in flags and conv.state != "reset":
            conv.state = "closed"

        ports = {record.src_port, record.dst_port}
        info = record.tls_info
        if info:
            if info["kind"] == "client_hello":
                conv.ja3 = info["ja3"]
                conv.sni = info.get("sni") or conv.sni
                if conv.posture in ("other", "tls_unseen", "tls13", "tls12", "tls_legacy"):
                    conv.posture = _tls_posture(info["version_code"])
            else:
                conv.posture = _tls_posture(info["version_code"])
        elif record.cleartext:
            conv.posture = "cleartext"
        elif record.protocol == "UDP":
            if 53 in ports:
                conv.posture = "dns"
            elif 443 in ports:
                conv.posture = "quic"
        elif conv.posture == "other" and 443 in ports:
            # Mid-stream capture: the handshake happened before we started
            # listening, so the version is unknown - but the port says TLS.
            conv.posture = "tls_unseen"
        self.posture_bytes[conv.posture] += record.length
        if record.tls_sni:
            conv.sni = record.tls_sni

        if record.cleartext:
            server = conv.responder
            self._finding(
                ("cleartext", conv.initiator[0], record.cleartext, server[0]),
                severity="high",
                title=f"Unencrypted {record.cleartext} traffic",
                detail=(
                    f"{conv.initiator[0]} -> {server[0]}:{server[1]} ({resolve_org(server[0])}) "
                    f"is sent without TLS; anyone on the path can read it."
                ),
                host=conv.initiator[0],
                ts=record.timestamp,
            )

    def _track_hosts(self, record: PacketRecord) -> None:
        mac_by_side = {record.src_ip: record.src_mac, record.dst_ip: record.dst_mac}
        if record.protocol == "ARP":
            mac_by_side = {record.src_ip: record.arp_sender_mac}
        for ip in (record.src_ip, record.dst_ip):
            if not ip or not is_local(ip):
                continue
            host = self.hosts.get(ip)
            if host is None:
                host = self.hosts[ip] = HostState(ip=ip, first_seen=record.timestamp)
            host.last_seen = record.timestamp
            host.bytes += record.length
            host.packets += 1
            # Only trust a frame's MAC for the sender side: a frame addressed to
            # a host carries the *next hop's* MAC, not necessarily the host's own.
            if ip == record.src_ip and mac_by_side.get(ip):
                host.mac = mac_by_side[ip]
            if ip == record.src_ip and record.ttl:
                host.ttl = record.ttl
            other = record.dst_ip if ip == record.src_ip else record.src_ip
            if other and not is_local(other):
                host.orgs[resolve_org(other)] += record.length
                site = self.hostnames.site(other)
                if site:
                    host.sites[site] += record.length

            stats = self.interval.setdefault(ip, IntervalStats())
            stats.byte_count += record.length
            stats.packet_count += 1
            if ip == record.src_ip and is_probe(record):
                stats.distinct_dst_ports.add(record.dst_port)
                if record.dst_ip:
                    stats.distinct_dst_ips.add(record.dst_ip)

        if record.protocol == "TCP" and record.src_ip and is_local(record.src_ip) and record.dst_ip and not is_local(record.dst_ip):
            flags = (record.tcp_flags or "").split(",")
            if "SYN" in flags and "ACK" not in flags:
                self.syn_times[(record.src_ip, record.dst_ip)].append(record.timestamp)

    def _track_tls(self, record: PacketRecord) -> None:
        info = record.tls_info
        if not info:
            return
        if info["kind"] == "client_hello":
            sni = info.get("sni") or ""
            key = (record.src_ip, record.dst_ip, sni)
            row = self.tls_rows.get(key)
            if row is None:
                row = self.tls_rows[key] = {
                    "client": record.src_ip, "server": record.dst_ip, "sni": sni,
                    "site": self.hostnames.site(record.dst_ip) or sni, "org": resolve_org(record.dst_ip),
                    "offered_version": info["version"], "ja3": info["ja3"], "client_grade": info["grade"],
                    "weak": info["weak_ciphers"], "reasons": info["reasons"], "ciphers": info["cipher_count"],
                    "alpn": info["alpn"], "pfs": info["forward_secrecy"],
                    "negotiated": None, "cipher": None, "cipher_weakness": None, "grade": info["grade"],
                    "first": record.timestamp, "count": 0,
                }
            row["count"] += 1
            row["last"] = record.timestamp
            group = self.ja3_groups.setdefault(
                info["ja3"],
                {"ja3": info["ja3"], "version": info["version"], "grade": info["grade"], "count": 0,
                 "clients": set(), "snis": Counter(), "ja3_string": info["ja3_string"]},
            )
            group["count"] += 1
            group["clients"].add(record.src_ip)
            if sni:
                group["snis"][sni] += 1
            if info["grade"] in ("F", "C"):
                self._finding(
                    ("weak_client", record.src_ip, info["ja3"]),
                    severity="critical" if info["grade"] == "F" else "medium",
                    title=f"Weak TLS client ({info['version']}, grade {info['grade']})",
                    detail=(
                        f"{record.src_ip} connecting to {sni or record.dst_ip}: "
                        + "; ".join(info["reasons"])
                        + (f". Example: {info['weak_ciphers'][0]['name']} - {info['weak_ciphers'][0]['why']}" if info["weak_ciphers"] else "")
                    ),
                    host=record.src_ip,
                    ts=record.timestamp,
                )
        else:
            # ServerHello: server -> client. Match the client's row by address.
            for key, row in self.tls_rows.items():
                if key[0] == record.dst_ip and key[1] == record.src_ip and row["negotiated"] is None:
                    row["negotiated"] = info["version"]
                    row["cipher"] = info["cipher"]
                    row["cipher_weakness"] = info["cipher_weakness"]
                    row["pfs"] = info["forward_secrecy"]
                    row["grade"] = max(row["client_grade"], info["grade"])  # 'F' > 'C' > 'B' > 'A'
                    if info["cipher_weakness"] or info["version_code"] <= 0x0302:
                        self._finding(
                            ("weak_negotiated", record.dst_ip, info["cipher"]),
                            severity="critical",
                            title=f"Server negotiated {info['version']} with {info['cipher']}",
                            detail=(
                                f"{record.src_ip} ({resolve_org(record.src_ip)}) agreed to a connection with "
                                f"{record.dst_ip} using {info['cipher']}"
                                + (f": {info['cipher_weakness']}." if info["cipher_weakness"] else ".")
                            ),
                            host=record.dst_ip,
                            ts=record.timestamp,
                        )
                    break

    def _finding(self, key: tuple, severity: str, title: str, detail: str, host: str, ts: float) -> None:
        existing = self.findings.get(key)
        if existing:
            existing["count"] += 1
            existing["last"] = ts
            return
        self.findings[key] = {
            "id": len(self.findings) + 1, "severity": severity, "title": title, "detail": detail,
            "host": host, "count": 1, "first": ts, "last": ts,
        }

    def _check_arp(self, record: PacketRecord) -> None:
        if record.protocol != "ARP":
            return
        alert = self.arp.observe(record.src_ip, record.arp_sender_mac, record.timestamp)
        if alert:
            self._emit(alert, record.timestamp)

    def _append_feed(self, record: PacketRecord) -> None:
        remote = None
        if record.dst_ip and not is_local(record.dst_ip):
            remote = record.dst_ip
        elif record.src_ip and not is_local(record.src_ip):
            remote = record.src_ip
        proto = record.protocol or "OTHER"
        src = f"{record.src_ip}:{record.src_port}" if record.src_port else (record.src_ip or record.src_mac)
        dst = f"{record.dst_ip}:{record.dst_port}" if record.dst_port else (record.dst_ip or record.dst_mac)
        tag = ""
        if record.tls_info:
            tag = "tls"
        elif record.cleartext:
            tag = "clear"
        elif record.dns_query_name:
            tag = "dns"
        self.packet_ring.append(
            {
                "seq": self.seq, "t": record.timestamp, "proto": proto, "src": src, "dst": dst,
                "len": record.length, "flags": record.tcp_flags or "", "info": record.summary or "",
                "org": resolve_org(remote) if remote else "", "site": self.hostnames.site(record.dst_ip, record.src_ip),
                "tag": tag,
            }
        )

    # ------------------------------------------------------------- windows

    def tick(self, now: float) -> List[dict]:
        """Close the current detection window: rules -> alerts -> baselines -> persist."""
        with self.lock:
            window = max(0.001, self.window_seconds)
            stats = self.interval
            self.counters["windows"] += 1

            fired: List[Alert] = []
            # The floor scales with the window so a quiet host (e.g. a gateway
            # that only answers DNS) doesn't trip the rule on a handful of packets.
            # Likewise it must move a meaningful amount (>= 15 KB/s): an idle phone's
            # background beacon is 3x its near-zero baseline but is not a hog.
            hogs = check_bandwidth_hog(
                stats, self.tracker, min_baseline_bytes=1000.0 * window, min_observed_bytes=15000.0 * window
            )
            for alert in hogs:
                share = (alert.observed_value / self.window_bytes_total * 100) if self.window_bytes_total else 0.0
                alert.severity = "high"
                alert.evidence = {
                    "bytes": int(alert.observed_value), "baseline_bytes": round(alert.baseline_value, 1),
                    "multiplier_threshold": alert.threshold_multiplier,
                    "multiplier_observed": round(alert.observed_value / alert.baseline_value, 2),
                    "share_of_window_total_pct": round(share, 1), "window_seconds": window,
                }
            fired += hogs
            fired += check_port_scan(stats, self.tracker, window_seconds=window)

            for alert in fired:
                alert.timestamp = now
            alerted_hosts = {a.host for a in fired}
            emitted = [e for e in (self._emit(a, now) for a in fired) if e]

            # Baselines AFTER the check (a spike must not inflate its own
            # baseline), and never from a window that raised an alert.
            for ip in set(stats) | set(self.hosts):
                host = self.hosts.get(ip)
                if host is None:
                    continue
                st = stats.get(ip, IntervalStats())
                base = self.tracker.get_baseline(ip)
                ready = self.tracker.is_baseline_ready(ip)
                host.history.append(
                    {
                        "t": now, "bytes": st.byte_count, "packets": st.packet_count,
                        "ports": len(st.distinct_dst_ports),
                        "base_bytes": round(base.ewma_bytes, 1) if base else None,
                        "base_ports": round(base.ewma_distinct_ports, 2) if base else None,
                        "ready": ready, "alert": ip in alerted_hosts,
                    }
                )
                if ip in stats and ip not in alerted_hosts:
                    self.tracker.update(ip, st, now)
                    upsert_baseline(self.tracker.get_baseline(ip), self.conn)

            self.window_log.append(
                {"t": now, "hosts": len(stats), "bytes": self.window_bytes_total, "alerts": len(emitted)}
            )
            self.interval = {}
            self.window_bytes_total = 0
            self.window_start = now
            store_flows(self.flows, self.conn)
            self.conn.commit()
            return emitted

    def _emit(self, alert: Alert, now: float) -> Optional[dict]:
        key = (alert.rule_name, alert.host)
        last = self._cooldown.get(key)
        if last and now - last["t"] < ALERT_COOLDOWN_SECONDS:
            last["alert"]["repeats"] = last["alert"].get("repeats", 0) + 1
            last["alert"]["last_seen"] = now
            return None

        store_alert(alert, self.conn)
        payload = {
            "rule": alert.rule_name, "host": alert.host, "observed": round(alert.observed_value, 3),
            "baseline": round(alert.baseline_value, 3), "threshold": round(alert.threshold_multiplier, 3),
            "message": alert.message, "severity": alert.severity, "evidence": alert.evidence, "ts": alert.timestamp,
        }
        seal = self.ledger.append(payload, alert.timestamp)
        self.counters["ledger_sealed"] += 1
        self.counters["alerts"] += 1
        host = self.hosts.get(alert.host)
        if host:
            host.last_alert_at = now
        record = {
            "id": self.counters["alerts"], "rule": alert.rule_name, "host": alert.host, "org": resolve_org(alert.host),
            "observed": alert.observed_value, "baseline": alert.baseline_value, "threshold": alert.threshold_multiplier,
            "message": alert.message, "severity": alert.severity, "evidence": alert.evidence, "ts": alert.timestamp,
            "repeats": 0, "last_seen": alert.timestamp,
            "seal": {"idx": seal["idx"], "hash": seal["entry_hash"], "sig": seal["signature"]},
            "window_seconds": self.window_seconds,
        }
        self.alerts.append(record)
        self.alerts = self.alerts[-500:]
        self._cooldown[key] = {"t": now, "alert": record}
        for callback in self.on_alert:
            callback(record)
        return record

    # ----------------------------------------------------------------- views

    def packets_since(self, seq: int, limit: int = 300) -> dict:
        with self.lock:
            fresh = [p for p in self.packet_ring if p["seq"] > seq]
            if len(fresh) > limit:
                fresh = fresh[-limit:]
            return {"seq": self.seq, "packets": fresh}

    def frame_detail(self, seq: int) -> Optional[dict]:
        with self.lock:
            raw = self.raw_ring.get(seq)
            summary = next((p for p in self.packet_ring if p["seq"] == seq), None)
        if raw is None:
            return None
        return {"seq": seq, "summary": summary, "hex": raw.hex(), **explain_frame(raw)}

    def alerts_since(self, after_id: int) -> List[dict]:
        with self.lock:
            return [a for a in self.alerts if a["id"] > after_id]

    def _beacons(self) -> dict:
        rows, raster = [], []
        for (host, dst), times in self.syn_times.items():
            if len(times) < 3:
                continue
            ts = list(times)
            gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.2]
            periodic = False
            period = cv = 0.0
            if len(gaps) >= 4:
                mean = statistics.fmean(gaps)
                cv = statistics.pstdev(gaps) / mean if mean else 9.0
                period = mean
                periodic = 3.0 <= mean <= 600.0 and cv < 0.25
            entry = {
                "host": host, "dst": dst, "org": resolve_org(dst),
                "site": self.hostnames.site(dst) or "", "events": ts[-24:], "count": len(ts),
                "period": round(period, 2), "cv": round(cv, 3), "periodic": periodic,
            }
            raster.append(entry)
            if periodic:
                rows.append(entry)
        rows.sort(key=lambda r: r["cv"])
        raster.sort(key=lambda r: (not r["periodic"], -r["count"]))
        return {"periodic": rows, "raster": raster[:14]}

    def snapshot(self) -> dict:
        with self.lock:
            now = self.now()
            uptime = max(0.0, time.time() - self.started_at)
            total_bytes = sum(self.proto_bytes.values())
            total_packets = sum(self.proto_packets.values())

            horizon = int(now) - 119
            series = []
            for t in range(horizon, int(now) + 1):
                b = self.timeline.get(t)
                series.append([t] + (b if b else [0, 0, 0, 0, 0, 0]))
            recent = [self.timeline.get(t, [0, 0]) for t in range(int(now) - 4, int(now))]
            bps = sum(r[0] for r in recent) / 4.0
            pps = sum(r[1] for r in recent) / 4.0

            hosts = []
            for ip, h in sorted(self.hosts.items(), key=lambda kv: tuple(int(p) for p in kv[0].split("."))):
                base = self.tracker.get_baseline(ip)
                st = self.interval.get(ip)
                hosts.append(
                    {
                        "ip": ip, "mac": h.mac, "vendor": vendor(h.mac), "randomized_mac": is_randomized(h.mac),
                        "ttl": h.ttl, "bytes": h.bytes, "packets": h.packets, "first_seen": h.first_seen,
                        "last_seen": h.last_seen, "window_bytes": st.byte_count if st else 0,
                        "window_ports": len(st.distinct_dst_ports) if st else 0,
                        "baseline": None if base is None else {
                            "bytes": round(base.ewma_bytes, 1), "packets": round(base.ewma_packets, 1),
                            "ports": round(base.ewma_distinct_ports, 2), "samples": base.samples_seen,
                            "ready": self.tracker.is_baseline_ready(ip),
                        },
                        "top_orgs": h.orgs.most_common(4), "top_sites": h.sites.most_common(5),
                        "history": list(h.history), "alerted_recently": now - h.last_alert_at < 20,
                    }
                )

            ready_hosts = sum(1 for h in hosts if h["baseline"] and h["baseline"]["ready"])
            convs = sorted(self.convs.values(), key=lambda c: c.last, reverse=True)[:120]
            conv_rows = []
            for c in convs:
                server = c.responder
                client = c.initiator
                conv_rows.append(
                    {
                        "proto": c.protocol, "client": f"{client[0]}:{client[1]}", "server": f"{server[0]}:{server[1]}",
                        "org": resolve_org(server[0] if not is_local(server[0]) else client[0]),
                        "site": c.sni and _friendly(c.sni) or self.hostnames.site(server[0], client[0]),
                        "sni": c.sni, "packets": c.packets, "up": c.bytes_up, "down": c.bytes_down,
                        "bytes": c.bytes_up + c.bytes_down, "first": c.first, "last": c.last,
                        "posture": c.posture, "state": c.state,
                    }
                )

            tls = sorted(self.tls_rows.values(), key=lambda r: ("FCBA".find(r["grade"]) if r["grade"] in "FCBA" else 9, -r.get("last", 0)))
            ja3 = sorted(self.ja3_groups.values(), key=lambda g: -g["count"])
            beacons = self._beacons()

            posture_total = sum(self.posture_bytes.values()) or 1
            return {
                "mode": self.mode, "paused": self.paused, "error": self.source_error, "meta": dict(self.meta),
                "window_seconds": self.window_seconds, "uptime": uptime, "now": now,
                "totals": {
                    "packets": total_packets, "bytes": total_bytes, "flows": len(self.flows),
                    "conversations": len(self.convs), "hosts": len(self.hosts), "alerts": self.counters["alerts"],
                    "dns_queries": self.dns_queries, "bps": bps, "pps": pps, "ready_hosts": ready_hosts,
                },
                "stages": {
                    "captured": self.counters["frames_captured"], "decoded": self.counters["decoded_ok"],
                    "decode_errors": self.counters["decode_errors"], "stored": self.counters["packets_stored"],
                    "flows": len(self.flows), "windows": self.counters["windows"], "baselines": ready_hosts,
                    "alerts": self.counters["alerts"], "sealed": self.counters["ledger_sealed"],
                },
                "timeline": series,
                "protocols": [[k, self.proto_bytes[k], self.proto_packets[k]] for k, _ in self.proto_bytes.most_common()],
                "orgs": self.org_bytes.most_common(8),
                "posture": [
                    {"key": k, "label": POSTURE_LABELS.get(k, k), "bytes": v, "pct": round(v * 100 / posture_total, 1)}
                    for k, v in self.posture_bytes.most_common()
                ],
                "dns_top": self.dns_names.most_common(6),
                "hosts": hosts, "conversations": conv_rows,
                "alerts": list(reversed(self.alerts[-60:])),
                "tls": tls[:60], "ja3": [
                    {**g, "clients": sorted(g["clients"]), "snis": g["snis"].most_common(4)} for g in ja3[:12]
                ],
                "findings": sorted(self.findings.values(), key=lambda f: ({"critical": 0, "high": 1, "medium": 2}.get(f["severity"], 3), -f["last"])),
                "beacons": beacons,
                "arp_table": self.arp.table(),
                "ledger": {"count": self.ledger.count, "head": self.ledger.head},
                "trace": self._trace(),
                "windows": list(self.window_log)[-20:],
            }

    def _trace(self) -> dict:
        rec = self.last_record
        if rec is None:
            return {}
        host = self.last_host or rec.src_ip
        base = self.tracker.get_baseline(host) if host else None
        raw = self.last_raw[:40]
        flow = self.flows.get(self.last_flow_key) if self.last_flow_key else None
        layers = ["Ethernet"]
        if rec.protocol == "ARP":
            layers.append("ARP")
        elif rec.src_ip:
            layers += ["IPv4", rec.protocol or "?"]
            if rec.dns_query_name:
                layers.append("DNS")
            elif rec.tls_info:
                layers.append("TLS")
        return {
            "raw_hex": " ".join(f"{b:02x}" for b in raw), "raw_len": len(self.last_raw) or rec.length,
            "summary": rec.summary, "layers": layers,
            "flow": None if flow is None else {
                "key": f"{flow.key[0]}:{flow.key[1]} -> {flow.key[2]}:{flow.key[3]} {flow.key[4]}",
                "packets": flow.packet_count, "bytes": flow.byte_count,
            },
            "host": host,
            "window_bytes": self.interval.get(host).byte_count if host in self.interval else 0,
            "baseline": None if base is None else {"bytes": round(base.ewma_bytes, 1), "samples": base.samples_seen},
        }

    def report(self) -> dict:
        """Evidence bundle for download: alerts, verified ledger, hosts, crypto findings."""
        snap = self.snapshot()
        return {
            "generated_at": time.time(), "mode": snap["mode"], "window_seconds": self.window_seconds,
            "totals": snap["totals"],
            "alerts": snap["alerts"],
            "ledger": {"verification": {k: v for k, v in self.ledger.verify().items() if k != "checks"},
                       "entries": self.ledger.entries(500)},
            "hosts": [{k: v for k, v in h.items() if k != "history"} for h in snap["hosts"]],
            "crypto_findings": snap["findings"],
            "note": "Metadata only: addresses, ports, timing, sizes and cleartext handshake fields. No payload content.",
        }


def _tls_posture(version_code: int) -> str:
    if version_code >= 0x0304:
        return "tls13"
    if version_code == 0x0303:
        return "tls12"
    return "tls_legacy"


def _friendly(hostname: str) -> str:
    from enrichment.hostnames import site_label

    return site_label(hostname)
