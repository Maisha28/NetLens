"""
Byte-level frame builders for the traffic simulator.

These construct real Ethernet / IPv4 / TCP / UDP / ARP / DNS / TLS frames with
correct lengths and checksums, using struct only - the same RFC layouts the
decoder reads. The simulator therefore feeds NetLens genuine raw bytes through
the genuine decoder: nothing in the pipeline knows (or is told) that the
traffic is synthetic.
"""

from __future__ import annotations

import random
import struct
from typing import Iterable, List, Optional, Sequence

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def mac_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def ip_bytes(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


def checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum (ones'-complement sum of 16-bit words)."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


# --- Layer 2 / 3 -----------------------------------------------------------


def ethernet(dst_mac: str, src_mac: str, eth_type: int, payload: bytes) -> bytes:
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack("!H", eth_type) + payload


_ip_ident = 0x1000


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    global _ip_ident
    _ip_ident = (_ip_ident + 1) & 0xFFFF
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version 4, header length 5 words
        0,
        20 + len(payload),
        _ip_ident,
        0x4000,  # don't-fragment
        ttl,
        proto,
        0,
        ip_bytes(src),
        ip_bytes(dst),
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def _pseudo_header(src: str, dst: str, proto: int, length: int) -> bytes:
    return ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, proto, length)


def tcp_segment(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    window: int = 65535,
) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, window, 0, 0
    )
    segment = header + payload
    csum = checksum(_pseudo_header(src, dst, 6, len(segment)) + segment)
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def udp_datagram(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    datagram = struct.pack("!HHHH", sport, dport, length, 0) + payload
    csum = checksum(_pseudo_header(src, dst, 17, length) + datagram) or 0xFFFF
    return datagram[:6] + struct.pack("!H", csum) + datagram[8:]


def arp_packet(opcode: int, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, opcode)
        + mac_bytes(sender_mac)
        + ip_bytes(sender_ip)
        + mac_bytes(target_mac)
        + ip_bytes(target_ip)
    )


# --- Convenience: whole frames --------------------------------------------


def tcp_frame(
    src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, sport: int, dport: int,
    seq: int, ack: int, flags: int, payload: bytes = b"", ttl: int = 64,
) -> bytes:
    seg = tcp_segment(src_ip, dst_ip, sport, dport, seq, ack, flags, payload)
    return ethernet(dst_mac, src_mac, 0x0800, ipv4(src_ip, dst_ip, 6, seg, ttl))


def udp_frame(
    src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, sport: int, dport: int,
    payload: bytes, ttl: int = 64,
) -> bytes:
    dg = udp_datagram(src_ip, dst_ip, sport, dport, payload)
    return ethernet(dst_mac, src_mac, 0x0800, ipv4(src_ip, dst_ip, 17, dg, ttl))


def arp_frame(opcode: int, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    # Requests are broadcast (target MAC unknown = zeros); replies are unicast.
    eth_dst = "ff:ff:ff:ff:ff:ff" if opcode == 1 else target_mac
    return ethernet(eth_dst, sender_mac, 0x0806, arp_packet(opcode, sender_mac, sender_ip, target_mac, target_ip))


# --- DNS -------------------------------------------------------------------


def _dns_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(txid: int, name: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + _dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(txid: int, name: str, ips: Sequence[str], cname: Optional[str] = None, ttl: int = 60) -> bytes:
    answers = b""
    count = 0
    owner = b"\xc0\x0c"  # compression pointer to the question name at offset 12
    if cname:
        target = _dns_name(cname)
        answers += owner + struct.pack("!HHIH", 5, 1, ttl, len(target)) + target
        count += 1
    for ip in ips:
        answers += owner + struct.pack("!HHIH", 1, 1, ttl, 4) + ip_bytes(ip)
        count += 1
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, count, 0, 0)
    return header + _dns_name(name) + struct.pack("!HH", 1, 1) + answers


# --- TLS -------------------------------------------------------------------

# Client profiles: what each kind of software offers in its ClientHello. The
# "legacy_iot" one is deliberately the sort of thing found in old embedded
# firmware - it exists so the Crypto page has something real to flag.
TLS_PROFILES = {
    "modern": {
        "client_version": 0x0303,
        "ciphers": [0x2A2A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035],
        "versions": [0x0A0A, 0x0304, 0x0303],
        "groups": [0x6A6A, 0x001D, 0x0017, 0x0018],
        "alpn": ["h2", "http/1.1"],
        "exts": [0x0A0A, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43],
    },
    "safari_like": {
        "client_version": 0x0303,
        "ciphers": [0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8, 0xC00A, 0xC009, 0xC014, 0xC013, 0x009D, 0x009C, 0x0035, 0x002F],
        "versions": [0x0304, 0x0303],
        "groups": [0x001D, 0x0017, 0x0018],
        "alpn": ["h2", "http/1.1"],
        "exts": [0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43],
    },
    "tls12_only": {
        "client_version": 0x0303,
        "ciphers": [0xC02F, 0xC030, 0xC02B, 0xC02C, 0x009E, 0x009F, 0xC013, 0xC014, 0x002F, 0x0035],
        "versions": [],
        "groups": [0x0017, 0x0018],
        "alpn": ["http/1.1"],
        "exts": [0, 10, 11, 13, 16, 23],
    },
    "legacy_iot": {
        "client_version": 0x0301,
        "ciphers": [0x0005, 0x000A, 0x002F, 0x0035, 0x0004],
        "versions": [],
        "groups": [0x0017, 0x0018],
        "alpn": [],
        "exts": [0, 10, 11],
    },
}


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def tls_client_hello(sni: str, profile: str = "modern", rng: Optional[random.Random] = None) -> bytes:
    rng = rng or random
    p = TLS_PROFILES[profile]
    cipher_bytes = b"".join(struct.pack("!H", c) for c in p["ciphers"])

    name = sni.encode()
    server_name = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    alpn = b"".join(bytes([len(a)]) + a.encode() for a in p["alpn"])
    group_bytes = b"".join(struct.pack("!H", g) for g in p["groups"])
    version_bytes = b"".join(struct.pack("!H", v) for v in p["versions"])

    ext_blobs: List[bytes] = []
    for ext_type in p["exts"]:
        if ext_type == 0:
            ext_blobs.append(_ext(0, server_name))
        elif ext_type == 10:
            ext_blobs.append(_ext(10, struct.pack("!H", len(group_bytes)) + group_bytes))
        elif ext_type == 11:
            ext_blobs.append(_ext(11, b"\x01\x00"))
        elif ext_type == 16 and alpn:
            ext_blobs.append(_ext(16, struct.pack("!H", len(alpn)) + alpn))
        elif ext_type == 43 and p["versions"]:
            ext_blobs.append(_ext(43, bytes([len(version_bytes)]) + version_bytes))
        elif ext_type == 0x0A0A:
            ext_blobs.append(_ext(0x0A0A, b""))
        else:
            ext_blobs.append(_ext(ext_type, b"\x00\x00"))
    extensions = b"".join(ext_blobs)

    body = (
        struct.pack("!H", p["client_version"])
        + rng.randbytes(32)
        + b"\x00"  # empty session id
        + struct.pack("!H", len(cipher_bytes))
        + cipher_bytes
        + b"\x01\x00"  # compression: null only
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tls_server_hello(version: int = 0x0304, cipher: int = 0x1301, rng: Optional[random.Random] = None) -> bytes:
    rng = rng or random
    extensions = b""
    legacy_version = version
    if version == 0x0304:
        legacy_version = 0x0303
        extensions = _ext(43, struct.pack("!H", 0x0304))
    body = (
        struct.pack("!H", legacy_version)
        + rng.randbytes(32)
        + b"\x00"
        + struct.pack("!H", cipher)
        + b"\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def tls_app_data(size: int, rng: Optional[random.Random] = None) -> bytes:
    """An 'application data' record: opaque ciphertext, exactly what a sniffer would see."""
    rng = rng or random
    return b"\x17\x03\x03" + struct.pack("!H", size) + rng.randbytes(size)


def http_request(path: str, host: str) -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: fw-updater/1.2\r\n\r\n".encode()
