"""
Person C's part: persist PacketRecords and flow summaries to SQLite.

The `packets` table mirrors PacketRecord's fields 1:1 so store/retrieve
round-trips lose nothing. dns_answers (a list) is the one field that
doesn't map to a SQLite column type directly - it's stored as a
comma-joined string and split back out on read.

The `flows` table mirrors flow_tracker.FlowStats: one row per 5-tuple
(src_ip, src_port, dst_ip, dst_port, protocol), keyed on that tuple, with
running packet/byte counts and first/last-seen timestamps. It's a
snapshot, not an append-log - store_flows() re-derives flows from every
packet seen so far (see main.py) and upserts each key, so the table
always reflects the latest totals rather than growing per call.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

from baseline.baseline import HostBaseline
from detection.rules import Alert
from shared.packet_record import PacketRecord
from storage.flow_tracker import FlowKey, FlowStats

DEFAULT_DB_PATH = Path(__file__).parent / "netlens.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    length INTEGER NOT NULL,
    src_mac TEXT NOT NULL,
    dst_mac TEXT NOT NULL,
    eth_type INTEGER NOT NULL,
    protocol TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    ttl INTEGER,
    ip_total_length INTEGER,
    tcp_flags TEXT,
    tcp_seq INTEGER,
    tcp_ack INTEGER,
    arp_opcode INTEGER,
    arp_sender_mac TEXT,
    arp_target_mac TEXT,
    dns_is_response INTEGER,
    dns_query_name TEXT,
    dns_query_type TEXT,
    dns_answers TEXT,
    summary TEXT
)
"""

FLOWS_SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (src_ip, src_port, dst_ip, dst_port, protocol)
)
"""

BASELINES_SCHEMA = """
CREATE TABLE IF NOT EXISTS baselines (
    host TEXT PRIMARY KEY,
    ewma_bytes REAL NOT NULL,
    ewma_packets REAL NOT NULL,
    ewma_distinct_ports REAL NOT NULL,
    samples_seen INTEGER NOT NULL,
    last_updated REAL NOT NULL
)
"""

ALERTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    host TEXT NOT NULL,
    observed_value REAL NOT NULL,
    baseline_value REAL NOT NULL,
    threshold_multiplier REAL NOT NULL,
    timestamp REAL NOT NULL,
    message TEXT NOT NULL
)
"""

_COLUMNS = [
    "timestamp", "length", "src_mac", "dst_mac", "eth_type", "protocol",
    "src_ip", "dst_ip", "src_port", "dst_port", "ttl", "ip_total_length",
    "tcp_flags", "tcp_seq", "tcp_ack", "arp_opcode", "arp_sender_mac",
    "arp_target_mac", "dns_is_response", "dns_query_name", "dns_query_type",
    "dns_answers", "summary",
]

_FLOW_COLUMNS = [
    "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "packet_count", "byte_count", "first_seen", "last_seen",
]

_BASELINE_COLUMNS = [
    "host", "ewma_bytes", "ewma_packets", "ewma_distinct_ports",
    "samples_seen", "last_updated",
]

_ALERT_COLUMNS = [
    "rule_name", "host", "observed_value", "baseline_value",
    "threshold_multiplier", "timestamp", "message",
]


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(SCHEMA)
    conn.execute(FLOWS_SCHEMA)
    conn.execute(BASELINES_SCHEMA)
    conn.execute(ALERTS_SCHEMA)
    conn.commit()
    return conn


def store_packet(record: PacketRecord, conn: sqlite3.Connection) -> None:
    placeholders = ", ".join("?" for _ in _COLUMNS)
    column_list = ", ".join(_COLUMNS)

    # Build values in column order, handling the list->str conversion and
    # the bool->int conversion SQLite needs.
    values = []
    for col in _COLUMNS:
        value = getattr(record, col)
        if col == "dns_answers":
            value = ",".join(value) if value else None
        elif col == "dns_is_response" and value is not None:
            value = int(value)
        values.append(value)

    conn.execute(
        f"INSERT INTO packets ({column_list}) VALUES ({placeholders})", values
    )
    conn.commit()


def get_all_packets(conn: sqlite3.Connection) -> List[PacketRecord]:
    cursor = conn.execute(f"SELECT {', '.join(_COLUMNS)} FROM packets ORDER BY id")
    records = []
    for row in cursor.fetchall():
        kwargs = dict(zip(_COLUMNS, row))
        kwargs["dns_answers"] = kwargs["dns_answers"].split(",") if kwargs["dns_answers"] else []
        kwargs["dns_is_response"] = (
            bool(kwargs["dns_is_response"]) if kwargs["dns_is_response"] is not None else None
        )
        records.append(PacketRecord(**kwargs))
    return records


def store_flows(flows: Dict[FlowKey, FlowStats], conn: sqlite3.Connection) -> None:
    """
    Upsert the current flow snapshot. Callers (see main.py) recompute
    `flows` from every packet stored so far each time, so each key's row
    is replaced with the latest totals rather than accumulated further
    here - the accumulation already happened in group_into_flows().
    """
    placeholders = ", ".join("?" for _ in _FLOW_COLUMNS)
    column_list = ", ".join(_FLOW_COLUMNS)

    for (src_ip, src_port, dst_ip, dst_port, protocol), stats in flows.items():
        conn.execute(
            f"INSERT OR REPLACE INTO flows ({column_list}) VALUES ({placeholders})",
            [
                src_ip, src_port, dst_ip, dst_port, protocol,
                stats.packet_count, stats.byte_count,
                stats.first_seen, stats.last_seen,
            ],
        )
    conn.commit()


def get_all_flows(conn: sqlite3.Connection) -> Dict[FlowKey, FlowStats]:
    """
    Read the persisted flow snapshot back as FlowStats keyed by 5-tuple.
    The returned FlowStats have empty `records` - the flows table stores
    only aggregate counts, not the underlying packets (those live in the
    packets table and can be re-joined by 5-tuple if ever needed).
    """
    cursor = conn.execute(f"SELECT {', '.join(_FLOW_COLUMNS)} FROM flows")
    flows: Dict[FlowKey, FlowStats] = {}
    for src_ip, src_port, dst_ip, dst_port, protocol, packet_count, byte_count, first_seen, last_seen in cursor.fetchall():
        key: FlowKey = (src_ip, src_port, dst_ip, dst_port, protocol)
        flows[key] = FlowStats(
            key=key,
            packet_count=packet_count,
            byte_count=byte_count,
            first_seen=first_seen,
            last_seen=last_seen,
        )
    return flows


def upsert_baseline(baseline: HostBaseline, conn: sqlite3.Connection) -> None:
    """
    One current row per host, not an append-log - baseline is re-derived
    every interval (see baseline.BaselineTracker.update()), so replacing
    is correct and appending would just pile up duplicates.
    """
    placeholders = ", ".join("?" for _ in _BASELINE_COLUMNS)
    column_list = ", ".join(_BASELINE_COLUMNS)
    conn.execute(
        f"INSERT OR REPLACE INTO baselines ({column_list}) VALUES ({placeholders})",
        [getattr(baseline, col) for col in _BASELINE_COLUMNS],
    )
    conn.commit()


def get_all_baselines(conn: sqlite3.Connection) -> Dict[str, HostBaseline]:
    cursor = conn.execute(f"SELECT {', '.join(_BASELINE_COLUMNS)} FROM baselines")
    baselines: Dict[str, HostBaseline] = {}
    for row in cursor.fetchall():
        kwargs = dict(zip(_BASELINE_COLUMNS, row))
        baselines[kwargs["host"]] = HostBaseline(**kwargs)
    return baselines


def store_alert(alert: Alert, conn: sqlite3.Connection) -> None:
    """
    Append-only, unlike flows and baselines - an alert is a historical
    event, not a snapshot of current state, so every firing gets its own
    row.
    """
    placeholders = ", ".join("?" for _ in _ALERT_COLUMNS)
    column_list = ", ".join(_ALERT_COLUMNS)
    conn.execute(
        f"INSERT INTO alerts ({column_list}) VALUES ({placeholders})",
        [getattr(alert, col) for col in _ALERT_COLUMNS],
    )
    conn.commit()


def get_all_alerts(conn: sqlite3.Connection) -> List[Alert]:
    cursor = conn.execute(f"SELECT {', '.join(_ALERT_COLUMNS)} FROM alerts ORDER BY id")
    return [Alert(**dict(zip(_ALERT_COLUMNS, row))) for row in cursor.fetchall()]


if __name__ == "__main__":
    import tempfile

    from storage.sample_records import SAMPLE_RECORDS

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "netlens_test.db"
        conn = get_connection(db_path)

        for record in SAMPLE_RECORDS:
            store_packet(record, conn)

        fetched = get_all_packets(conn)
        conn.close()

        print(f"Stored {len(SAMPLE_RECORDS)} records, fetched {len(fetched)} back.\n")
        for record in fetched:
            print(f"  [{record.protocol:>5}] {record.summary}")
