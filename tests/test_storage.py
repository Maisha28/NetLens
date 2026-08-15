"""
Tests for storage.db: SQLite persistence for both packets and flows.
Each test gets its own throwaway on-disk DB via pytest's tmp_path so
tests never touch storage/netlens.db or each other.
"""

import pytest

from storage.db import get_all_flows, get_all_packets, get_connection, store_flows, store_packet
from storage.flow_tracker import group_into_flows
from storage.sample_records import SAMPLE_RECORDS


@pytest.fixture
def conn(tmp_path):
    connection = get_connection(tmp_path / "netlens_test.db")
    yield connection
    connection.close()


def test_creates_packets_and_flows_tables(conn):
    tables = {
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "packets" in tables
    assert "flows" in tables


def test_store_and_fetch_packets_round_trip(conn):
    for record in SAMPLE_RECORDS:
        store_packet(record, conn)

    fetched = get_all_packets(conn)
    assert len(fetched) == len(SAMPLE_RECORDS)

    original, restored = SAMPLE_RECORDS[0], fetched[0]
    assert restored.protocol == original.protocol
    assert restored.src_ip == original.src_ip
    assert restored.dst_ip == original.dst_ip
    assert restored.src_port == original.src_port
    assert restored.tcp_flags == original.tcp_flags
    assert restored.tcp_seq == original.tcp_seq


def test_dns_answers_list_round_trips(conn):
    dns_response = SAMPLE_RECORDS[4]  # UDP DNS response w/ one A answer
    store_packet(dns_response, conn)

    fetched = get_all_packets(conn)[0]
    assert fetched.dns_answers == dns_response.dns_answers
    assert fetched.dns_is_response is True


def test_arp_record_round_trips(conn):
    arp_record = SAMPLE_RECORDS[5]
    store_packet(arp_record, conn)

    fetched = get_all_packets(conn)[0]
    assert fetched.protocol == "ARP"
    assert fetched.arp_opcode == arp_record.arp_opcode
    assert fetched.arp_sender_mac == arp_record.arp_sender_mac
    assert fetched.src_port is None


def test_store_and_fetch_flows_round_trip(conn):
    flows = group_into_flows(SAMPLE_RECORDS)
    store_flows(flows, conn)

    fetched = get_all_flows(conn)
    assert set(fetched.keys()) == set(flows.keys())

    key = ("10.0.0.5", 51000, "93.184.216.34", 443, "TCP")
    assert fetched[key].packet_count == flows[key].packet_count
    assert fetched[key].byte_count == flows[key].byte_count
    assert fetched[key].first_seen == flows[key].first_seen
    assert fetched[key].last_seen == flows[key].last_seen


def test_store_flows_upserts_rather_than_duplicating(conn):
    flows = group_into_flows(SAMPLE_RECORDS)
    store_flows(flows, conn)
    store_flows(flows, conn)  # simulate main.py re-persisting every N packets

    row_count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    assert row_count == len(flows)
