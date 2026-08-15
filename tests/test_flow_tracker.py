"""
Tests for storage.flow_tracker.group_into_flows(): groups PacketRecords
into flows keyed by the 5-tuple (src_ip, src_port, dst_ip, dst_port,
protocol). Uses the hardcoded SAMPLE_RECORDS fixture (a TCP handshake +
data, a DNS query/response, and an ARP request) so expected groupings
and totals are known up front.
"""

from storage.flow_tracker import group_into_flows
from storage.sample_records import SAMPLE_RECORDS


def test_groups_by_five_tuple():
    flows = group_into_flows(SAMPLE_RECORDS)
    # 6 packets, 5 distinct 5-tuples: the TCP SYN and PSH,ACK share a key
    # (same direction), everything else (including the reverse-direction
    # SYN,ACK) is its own flow.
    assert len(flows) == 5


def test_same_direction_packets_accumulate_into_one_flow():
    flows = group_into_flows(SAMPLE_RECORDS)
    key = ("10.0.0.5", 51000, "93.184.216.34", 443, "TCP")
    stats = flows[key]
    assert stats.packet_count == 2
    assert stats.byte_count == 54 + 512
    assert stats.first_seen == 1000.000
    assert stats.last_seen == 1000.900


def test_reverse_direction_is_a_different_flow():
    flows = group_into_flows(SAMPLE_RECORDS)
    forward = ("10.0.0.5", 51000, "93.184.216.34", 443, "TCP")
    reverse = ("93.184.216.34", 443, "10.0.0.5", 51000, "TCP")
    assert forward in flows
    assert reverse in flows
    assert flows[reverse].packet_count == 1
    assert flows[reverse].byte_count == 60


def test_dns_query_and_response_are_separate_flows():
    flows = group_into_flows(SAMPLE_RECORDS)
    query_key = ("10.0.0.5", 51002, "8.8.8.8", 53, "UDP")
    response_key = ("8.8.8.8", 53, "10.0.0.5", 51002, "UDP")
    assert flows[query_key].packet_count == 1
    assert flows[response_key].packet_count == 1


def test_arp_records_group_without_ports():
    flows = group_into_flows(SAMPLE_RECORDS)
    key = ("10.0.0.9", 0, "10.0.0.1", 0, "ARP")
    assert key in flows
    assert flows[key].packet_count == 1
    assert flows[key].byte_count == 42


def test_empty_input_gives_no_flows():
    assert group_into_flows([]) == {}
