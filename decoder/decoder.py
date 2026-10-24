"""
Person B's part: turn raw frame bytes into a PacketRecord by hand.

Every header field below is pulled out with struct.unpack / manual byte
slicing at a known offset - no scapy dissection is used for the actual
parsing. Scapy is only used elsewhere in the project (capture, and to
build test fixtures here) to produce raw bytes; this file proves we
understand RFC 894 (Ethernet), RFC 791 (IPv4), RFC 793 (TCP), RFC 768
(UDP), RFC 826 (ARP) and RFC 1035 (DNS) header layouts ourselves.

All multi-byte integer fields in these protocols are big-endian
("network byte order"), so every struct format string below starts
with '!'.

decode() is called on real live traffic (see main.py), so every parser
below is defensive about length: a header that's too short to safely
read is reported as truncated/OTHER instead of raising, since a single
malformed or unusual frame must never take the parser down.
"""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple

from shared.packet_record import PacketRecord

# EtherType values (Ethernet II, bytes 12-13 of the frame)
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_ARP = 0x0806
ETH_TYPE_IPV6 = 0x86DD
ETH_TYPE_VLAN = 0x8100  # 802.1Q tag - real EtherType is 4 bytes further in

# IPv4 "protocol" field values (byte 9 of the IPv4 header)
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_ICMP = 1

TCP_FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
)

DNS_PORT = 53

ETHERNET_HEADER_LEN = 14
VLAN_TAG_LEN = 4
IPV4_MIN_HEADER_LEN = 20
IPV6_HEADER_LEN = 40
ARP_PACKET_LEN = 28
TCP_MIN_HEADER_LEN = 20
UDP_HEADER_LEN = 8
DNS_MIN_HEADER_LEN = 12


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _format_ipv4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _format_ipv6(raw: bytes) -> str:
    # 8 groups of 2 bytes each, printed as hex, colon-separated. Real
    # tooling would also apply the "::" zero-compression shorthand; we
    # skip that here since this is only used for OTHER-bucketed frames.
    groups = struct.unpack("!8H", raw)
    return ":".join(f"{g:x}" for g in groups)


def _parse_ethernet(raw: bytes) -> Optional[Tuple[str, str, int, int]]:
    """
    Ethernet II header - fixed 14 bytes at the start of every frame:
      bytes 0-5   : destination MAC
      bytes 6-11  : source MAC
      bytes 12-13 : EtherType (big-endian uint16)

    If EtherType is 0x8100 (802.1Q VLAN tag), the real EtherType is
    pushed back another 4 bytes: 2 bytes of tag control info we don't
    care about, then the actual EtherType:
      bytes 12-13 : 0x8100 (tag marker)
      bytes 14-15 : VLAN tag control info (priority/VLAN id, unused here)
      bytes 16-17 : real EtherType

    Returns (src_mac, dst_mac, eth_type, header_len) where header_len is
    where the next layer starts (14, or 18 if a VLAN tag was present).
    Returns None if raw is too short to even hold an Ethernet header.
    """
    if len(raw) < ETHERNET_HEADER_LEN:
        return None

    dst_mac = _format_mac(raw[0:6])
    src_mac = _format_mac(raw[6:12])
    (eth_type,) = struct.unpack("!H", raw[12:14])
    header_len = ETHERNET_HEADER_LEN

    if eth_type == ETH_TYPE_VLAN:
        if len(raw) < ETHERNET_HEADER_LEN + VLAN_TAG_LEN:
            return src_mac, dst_mac, eth_type, header_len
        (eth_type,) = struct.unpack("!H", raw[16:18])
        header_len = ETHERNET_HEADER_LEN + VLAN_TAG_LEN

    return src_mac, dst_mac, eth_type, header_len


def _parse_ipv4(raw: bytes, offset: int) -> Optional[dict]:
    """
    IPv4 header - starts right after the Ethernet (+ optional VLAN tag)
    header. Minimum 20 bytes; IHL (bottom nibble of byte 0) counts in
    32-bit words, so header length in bytes = IHL * 4 (there can be
    options after byte 20, which we skip over using that length).

      byte  0      : version (top nibble) + IHL (bottom nibble)
      byte  1      : DSCP/ECN (unused here)
      bytes 2-3    : total length (uint16)
      bytes 4-5    : identification (unused here)
      bytes 6-7    : flags (top 3 bits) + fragment offset (low 13 bits)
      byte  8      : TTL
      byte  9      : protocol (6=TCP, 17=UDP, 1=ICMP)
      bytes 10-11  : header checksum (unused here)
      bytes 12-15  : source IP
      bytes 16-19  : destination IP

    Non-zero fragment offset means this is a non-initial IP fragment:
    its payload is a raw continuation of the original datagram, NOT a
    fresh TCP/UDP header, so we deliberately don't hand it to the L4
    parsers (that would decode a random offset into the data as if it
    were a port/flags/etc and produce garbage).
    """
    ip = raw[offset:]
    if len(ip) < IPV4_MIN_HEADER_LEN:
        return None

    version_ihl = ip[0]
    ihl_words = version_ihl & 0x0F
    header_len = ihl_words * 4  # bytes, includes any IP options
    if header_len < IPV4_MIN_HEADER_LEN or len(ip) < header_len:
        return None  # malformed IHL / truncated before header even ends

    (total_length,) = struct.unpack("!H", ip[2:4])
    flags_and_frag = struct.unpack("!H", ip[6:8])[0]
    fragment_offset = flags_and_frag & 0x1FFF
    more_fragments = bool(flags_and_frag & 0x2000)
    ttl = ip[8]
    protocol_num = ip[9]
    src_ip = _format_ipv4(ip[12:16])
    dst_ip = _format_ipv4(ip[16:20])

    return {
        "total_length": total_length,
        "ttl": ttl,
        "protocol_num": protocol_num,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "is_fragment": fragment_offset != 0 or more_fragments,
        "is_initial_fragment": fragment_offset == 0,
        "payload": ip[header_len:],
    }


def _parse_tcp(segment: bytes) -> Optional[dict]:
    """
    TCP header - minimum 20 bytes.
      bytes 0-1  : source port (uint16)
      bytes 2-3  : destination port (uint16)
      bytes 4-7  : sequence number (uint32)
      bytes 8-11 : acknowledgment number (uint32)
      byte  12   : data offset (top nibble, in 32-bit words) + reserved
      byte  13   : flags (FIN,SYN,RST,PSH,ACK,URG in the low 6 bits)
      bytes 14-15: window size (unused here)
      bytes 16-17: checksum (unused here)
      bytes 18-19: urgent pointer (unused here)
    """
    if len(segment) < TCP_MIN_HEADER_LEN:
        return None

    src_port, dst_port, seq, ack, data_offset_reserved, flag_byte = struct.unpack(
        "!HHIIBB", segment[0:14]
    )
    data_offset = (data_offset_reserved >> 4) * 4  # header length in bytes
    if data_offset < TCP_MIN_HEADER_LEN or data_offset > len(segment):
        data_offset = TCP_MIN_HEADER_LEN if len(segment) >= TCP_MIN_HEADER_LEN else len(segment)

    flags = [name for bit, name in TCP_FLAG_BITS if flag_byte & bit]

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "flags": ",".join(flags) if flags else "",
        "payload": segment[data_offset:],
    }


def _parse_udp(segment: bytes) -> Optional[dict]:
    """
    UDP header - fixed 8 bytes.
      bytes 0-1 : source port (uint16)
      bytes 2-3 : destination port (uint16)
      bytes 4-5 : length (header + data, unused here)
      bytes 6-7 : checksum (unused here)
    """
    if len(segment) < UDP_HEADER_LEN:
        return None

    src_port, dst_port, _length, _checksum = struct.unpack("!HHHH", segment[0:8])
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "payload": segment[8:],
    }


def _parse_arp(raw: bytes, offset: int) -> Optional[dict]:
    """
    ARP packet - starts right after Ethernet (+ optional VLAN tag),
    fixed 28 bytes for IPv4-over-Ethernet ARP (the only kind we handle):
      bytes 0-1   : hardware type (unused here, always 1=Ethernet)
      bytes 2-3   : protocol type (unused here, always 0x0800=IPv4)
      byte  4     : hardware address length (unused here, always 6)
      byte  5     : protocol address length (unused here, always 4)
      bytes 6-7   : opcode (1=request, 2=reply)
      bytes 8-13  : sender hardware address (MAC)
      bytes 14-17 : sender protocol address (IP)
      bytes 18-23 : target hardware address (MAC)
      bytes 24-27 : target protocol address (IP)
    """
    arp = raw[offset : offset + ARP_PACKET_LEN]
    if len(arp) < ARP_PACKET_LEN:
        return None

    (opcode,) = struct.unpack("!H", arp[6:8])
    sender_mac = _format_mac(arp[8:14])
    sender_ip = _format_ipv4(arp[14:18])
    target_mac = _format_mac(arp[18:24])
    target_ip = _format_ipv4(arp[24:28])

    return {
        "opcode": opcode,
        "sender_mac": sender_mac,
        "sender_ip": sender_ip,
        "target_mac": target_mac,
        "target_ip": target_ip,
    }


DNS_MAX_POINTER_JUMPS = 20  # guards against a malicious/malformed pointer cycle


def _parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """
    DNS names are a sequence of length-prefixed labels ending in a zero
    byte, e.g. b'\\x07example\\x03com\\x00' -> "example.com".

    A label length byte with its top two bits set (>= 0xC0) is instead a
    *compression pointer*: the remaining 14 bits are an offset back into
    the message where the rest of the name continues (RFC 1035 4.1.4).
    Real-world DNS responses use these constantly, so we follow them.

    Returns (name, offset_after_this_name_in_the_original_buffer).
    Raises ValueError on out-of-range offsets or a pointer chain that
    doesn't terminate - callers treat DNS parsing as best-effort and
    catch this rather than letting it crash the whole packet.
    """
    labels: List[str] = []
    pos = offset
    end_pos: Optional[int] = None  # where reading resumes after pointer jump
    jumps = 0

    while True:
        if pos >= len(data):
            raise ValueError("DNS name ran past end of message")

        length_byte = data[pos]
        if length_byte == 0:
            pos += 1
            if end_pos is None:
                end_pos = pos
            break

        if length_byte & 0xC0 == 0xC0:
            if pos + 2 > len(data):
                raise ValueError("truncated DNS compression pointer")
            jumps += 1
            if jumps > DNS_MAX_POINTER_JUMPS:
                raise ValueError("too many DNS compression pointer jumps")
            (pointer_word,) = struct.unpack("!H", data[pos : pos + 2])
            pointer = pointer_word & 0x3FFF
            if end_pos is None:
                end_pos = pos + 2
            pos = pointer
            continue

        pos += 1
        if pos + length_byte > len(data):
            raise ValueError("DNS label ran past end of message")
        labels.append(data[pos : pos + length_byte].decode("ascii", errors="replace"))
        pos += length_byte

    return ".".join(labels), end_pos


DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}


def _parse_dns(payload: bytes) -> Optional[dict]:
    """
    DNS message header - fixed 12 bytes:
      bytes 0-1  : transaction ID (unused here)
      bytes 2-3  : flags - bit 15 (top bit of byte 2) is QR: 0=query, 1=response
      bytes 4-5  : QDCOUNT - number of questions
      bytes 6-7  : ANCOUNT - number of answer records
      bytes 8-9  : NSCOUNT (unused here)
      bytes 10-11: ARCOUNT (unused here)

    Followed by the question section: QNAME (variable), then QTYPE
    (uint16) and QCLASS (uint16). We parse the first question and, for
    responses, walk ANCOUNT answer records to collect their names.

    Raises ValueError/struct.error on malformed input; decode() treats
    DNS enrichment as best-effort on top of an already-valid UDP/TCP
    record, so callers catch those and just skip the DNS fields.
    """
    if len(payload) < DNS_MIN_HEADER_LEN:
        return None

    flags, qdcount, ancount = struct.unpack("!HHH", payload[2:8])
    is_response = bool(flags & 0x8000)

    pos = 12
    query_name = ""
    query_type = None
    if qdcount > 0:
        query_name, pos = _parse_dns_name(payload, pos)
        if pos + 4 <= len(payload):
            (qtype,) = struct.unpack("!H", payload[pos : pos + 2])
            query_type = DNS_QTYPES.get(qtype, str(qtype))
            pos += 4  # QTYPE + QCLASS

    answers: List[str] = []
    for _ in range(ancount):
        if pos >= len(payload):
            break
        name, pos = _parse_dns_name(payload, pos)
        if pos + 10 > len(payload):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", payload[pos : pos + 10])
        pos += 10
        if pos + rdlength > len(payload):
            break
        rdata = payload[pos : pos + rdlength]
        if rtype == 1 and len(rdata) == 4:  # A record
            answers.append(f"{name} -> {_format_ipv4(rdata)}")
        else:
            answers.append(f"{name} -> {DNS_QTYPES.get(rtype, rtype)} record")
        pos += rdlength

    return {
        "is_response": is_response,
        "query_name": query_name,
        "query_type": query_type,
        "answers": answers,
    }


def _parse_tls_sni(payload: bytes) -> Optional[str]:
    """
    Pull the server name out of a TLS ClientHello, or None if this payload
    isn't one (or the hello is split across segments / has no SNI).

      TLS record  : type 0x16 (handshake), version(2), length(2)
      Handshake   : type 0x01 (ClientHello), length(3)
      ClientHello : version(2), random(32), session_id(1+n),
                    cipher_suites(2+n), compression(1+n), extensions(2+n)
      Extension   : type(2), length(2); SNI is type 0:
                    list_len(2), name_type(1)=0, name_len(2), name
    """
    try:
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32
        pos += 1 + payload[pos]  # session id
        (n,) = struct.unpack("!H", payload[pos : pos + 2])
        pos += 2 + n  # cipher suites
        pos += 1 + payload[pos]  # compression methods
        (ext_total,) = struct.unpack("!H", payload[pos : pos + 2])
        pos += 2
        end = min(pos + ext_total, len(payload))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos : pos + 4])
            pos += 4
            if ext_type == 0:
                name_type = payload[pos + 2]
                (name_len,) = struct.unpack("!H", payload[pos + 3 : pos + 5])
                if name_type != 0:
                    return None
                return payload[pos + 5 : pos + 5 + name_len].decode("ascii")
            pos += ext_len
    except (IndexError, struct.error, UnicodeDecodeError):
        pass
    return None


def decode(raw_bytes: bytes, timestamp: float) -> PacketRecord:
    """Parse one raw frame into a PacketRecord. See module docstring."""
    eth = _parse_ethernet(raw_bytes)
    if eth is None:
        # Shorter than a minimum Ethernet header - nothing we can safely
        # read. Shouldn't happen from a real NIC, but a snaplen-truncated
        # or corrupt capture could produce this.
        return PacketRecord(
            timestamp=timestamp,
            length=len(raw_bytes),
            src_mac="",
            dst_mac="",
            eth_type=0,
            protocol="OTHER",
            summary=f"Frame too short to parse ({len(raw_bytes)} bytes)",
        )

    src_mac, dst_mac, eth_type, l3_offset = eth

    record = PacketRecord(
        timestamp=timestamp,
        length=len(raw_bytes),
        src_mac=src_mac,
        dst_mac=dst_mac,
        eth_type=eth_type,
    )

    if eth_type == ETH_TYPE_ARP:
        arp = _parse_arp(raw_bytes, l3_offset)
        if arp is None:
            record.protocol = "OTHER"
            record.summary = "Truncated ARP packet"
            return record
        record.protocol = "ARP"
        record.src_ip = arp["sender_ip"]
        record.dst_ip = arp["target_ip"]
        record.arp_opcode = arp["opcode"]
        record.arp_sender_mac = arp["sender_mac"]
        record.arp_target_mac = arp["target_mac"]
        record.summary = (
            f"ARP {'request' if arp['opcode'] == 1 else 'reply'}: "
            f"who has {arp['target_ip']}? tell {arp['sender_ip']}"
        )
        return record

    if eth_type == ETH_TYPE_IPV6:
        # Day 1's contract only covers IPv4 5-tuples; IPv6 is bucketed as
        # OTHER rather than decoded, but we still surface the addresses
        # in the summary since the fixed 40-byte header makes that easy
        # and it's far more useful than a bare "unhandled" note.
        record.protocol = "OTHER"
        v6 = raw_bytes[l3_offset : l3_offset + IPV6_HEADER_LEN]
        if len(v6) == IPV6_HEADER_LEN:
            record.summary = f"IPv6 {_format_ipv6(v6[8:24])} -> {_format_ipv6(v6[24:40])} (not decoded)"
        else:
            record.summary = "Truncated IPv6 header"
        return record

    if eth_type != ETH_TYPE_IPV4:
        record.protocol = "OTHER"
        record.summary = f"Unhandled EtherType 0x{eth_type:04x}"
        return record

    ip = _parse_ipv4(raw_bytes, l3_offset)
    if ip is None:
        record.protocol = "OTHER"
        record.summary = "Truncated or malformed IPv4 header"
        return record

    record.src_ip = ip["src_ip"]
    record.dst_ip = ip["dst_ip"]
    record.ttl = ip["ttl"]
    record.ip_total_length = ip["total_length"]

    if ip["is_fragment"] and not ip["is_initial_fragment"]:
        # Non-initial fragment: payload is a raw continuation of the
        # original datagram, not a fresh TCP/UDP header - parsing it as
        # one would read garbage ports/flags out of arbitrary data.
        record.protocol = "OTHER"
        record.summary = f"IP fragment (proto {ip['protocol_num']}) {record.src_ip} -> {record.dst_ip}"
        return record

    if ip["protocol_num"] == IP_PROTO_TCP:
        tcp = _parse_tcp(ip["payload"])
        if tcp is None:
            record.protocol = "OTHER"
            record.summary = f"Truncated TCP segment {record.src_ip} -> {record.dst_ip}"
            return record

        record.protocol = "TCP"
        record.src_port = tcp["src_port"]
        record.dst_port = tcp["dst_port"]
        record.tcp_flags = tcp["flags"]
        record.tcp_seq = tcp["seq"]
        record.tcp_ack = tcp["ack"]
        record.summary = f"TCP {record.src_ip}:{tcp['src_port']} -> {record.dst_ip}:{tcp['dst_port']} [{tcp['flags']}]"

        if DNS_PORT in (tcp["src_port"], tcp["dst_port"]) and len(tcp["payload"]) > 2:
            # DNS-over-TCP is prefixed with a 2-byte message length (RFC 1035
            # 4.2.2); skip it before handing off to the DNS parser.
            try:
                dns = _parse_dns(tcp["payload"][2:])
            except (ValueError, struct.error):
                dns = None  # not actually DNS, or malformed - keep the TCP record as-is
            _apply_dns(record, dns)

        sni = _parse_tls_sni(tcp["payload"])
        if sni:
            record.tls_sni = sni
            record.summary += f" TLS SNI {sni}"

    elif ip["protocol_num"] == IP_PROTO_UDP:
        udp = _parse_udp(ip["payload"])
        if udp is None:
            record.protocol = "OTHER"
            record.summary = f"Truncated UDP segment {record.src_ip} -> {record.dst_ip}"
            return record

        record.protocol = "UDP"
        record.src_port = udp["src_port"]
        record.dst_port = udp["dst_port"]
        record.summary = f"UDP {record.src_ip}:{udp['src_port']} -> {record.dst_ip}:{udp['dst_port']}"

        if DNS_PORT in (udp["src_port"], udp["dst_port"]):
            try:
                dns = _parse_dns(udp["payload"])
            except (ValueError, struct.error):
                dns = None
            _apply_dns(record, dns)

    elif ip["protocol_num"] == IP_PROTO_ICMP:
        record.protocol = "ICMP"
        record.summary = f"ICMP {record.src_ip} -> {record.dst_ip}"

    else:
        # Any other IP protocol number (IGMP, GRE, ESP, OSPF, ...) - the
        # contract only models TCP/UDP/ICMP/ARP, so this is OTHER rather
        # than a crash.
        record.protocol = "OTHER"
        record.summary = f"IP protocol {ip['protocol_num']} {record.src_ip} -> {record.dst_ip}"

    return record


def _apply_dns(record: PacketRecord, dns: Optional[dict]) -> None:
    if dns is None:
        return
    record.dns_is_response = dns["is_response"]
    record.dns_query_name = dns["query_name"]
    record.dns_query_type = dns["query_type"]
    record.dns_answers = dns["answers"]
    kind = "response" if dns["is_response"] else "query"
    record.summary = f"DNS {kind}: {dns['query_name']} ({dns['query_type']})"
    if dns["answers"]:
        record.summary += f" -> {'; '.join(dns['answers'])}"
