"""
Tests for decoder.decode(): loads the raw frame fixtures in
decoder/test_data/ (built by generate_samples.py) and checks decode()
pulls out the fields we know those frames contain by construction, since
they were built with fixed, known values. This is what backs the "point
at the raw bytes and manually derive each field" bar from the Phase 1
definition of done - if these pass, decode()'s byte-level parsing agrees
with the known contents of each frame.
"""

from pathlib import Path

import pytest

from decoder.decoder import decode

FIXTURES_DIR = Path(__file__).parent.parent / "decoder" / "test_data"


def _load(name: str) -> bytes:
    path = FIXTURES_DIR / name
    if not path.exists():
        pytest.skip(f"fixture {name} missing - run decoder/test_data/generate_samples.py")
    return path.read_bytes()


def test_tcp_packet():
    record = decode(_load("tcp_packet.bin"), timestamp=1234.5)
    assert record.src_mac == "aa:bb:cc:dd:ee:01"
    assert record.dst_mac == "aa:bb:cc:dd:ee:02"
    assert record.eth_type == 0x0800
    assert record.protocol == "TCP"
    assert record.src_ip == "10.0.0.5"
    assert record.dst_ip == "93.184.216.34"
    assert record.ttl == 64
    assert record.src_port == 51000
    assert record.dst_port == 443
    assert record.tcp_flags == "SYN"
    assert record.tcp_seq == 1000


def test_udp_packet():
    record = decode(_load("udp_packet.bin"), timestamp=1234.5)
    assert record.protocol == "UDP"
    assert record.src_ip == "10.0.0.5"
    assert record.dst_ip == "10.0.0.1"
    assert record.src_port == 51001
    assert record.dst_port == 5353


def test_arp_packet():
    record = decode(_load("arp_packet.bin"), timestamp=1234.5)
    assert record.eth_type == 0x0806
    assert record.protocol == "ARP"
    assert record.arp_opcode == 1
    assert record.src_ip == "10.0.0.5"  # ARP sender protocol address
    assert record.dst_ip == "10.0.0.1"  # ARP target protocol address
    assert record.arp_sender_mac == "aa:bb:cc:dd:ee:01"
    assert record.arp_target_mac == "00:00:00:00:00:00"


def test_dns_query():
    record = decode(_load("dns_query.bin"), timestamp=1234.5)
    assert record.protocol == "UDP"
    assert record.src_port == 51002
    assert record.dst_port == 53
    assert record.dns_is_response is False
    assert record.dns_query_name == "example.com"
    assert record.dns_query_type == "A"


def test_dns_response():
    record = decode(_load("dns_response.bin"), timestamp=1234.5)
    assert record.protocol == "UDP"
    assert record.dns_is_response is True
    assert record.dns_query_name == "example.com"
    assert record.dns_query_type == "A"
    assert record.dns_answers == ["example.com -> 93.184.216.34"]


def test_truncated_frame_falls_back_to_other():
    record = decode(b"\x00" * 5, timestamp=1234.5)
    assert record.protocol == "OTHER"
    assert "too short" in record.summary.lower()


def test_unknown_ethertype_falls_back_to_other():
    # 14-byte Ethernet header (dst mac, src mac, EtherType 0x9999) with
    # no recognised protocol behind it, plus arbitrary payload bytes.
    raw = bytes.fromhex("aabbccddee02" "aabbccddee01" "9999") + b"\x00" * 20
    record = decode(raw, timestamp=1234.5)
    assert record.protocol == "OTHER"
    assert "unhandled ethertype" in record.summary.lower()
