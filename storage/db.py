"""
Person C's part: persist PacketRecords to SQLite.

The `packets` table mirrors PacketRecord's fields 1:1 so store/retrieve
round-trips lose nothing. dns_answers (a list) is the one field that
doesn't map to a SQLite column type directly - it's stored as a
comma-joined string and split back out on read.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import List, Optional

from shared.packet_record import PacketRecord

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

_COLUMNS = [
    "timestamp", "length", "src_mac", "dst_mac", "eth_type", "protocol",
    "src_ip", "dst_ip", "src_port", "dst_port", "ttl", "ip_total_length",
    "tcp_flags", "tcp_seq", "tcp_ack", "arp_opcode", "arp_sender_mac",
    "arp_target_mac", "dns_is_response", "dns_query_name", "dns_query_type",
    "dns_answers", "summary",
]


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(SCHEMA)
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
