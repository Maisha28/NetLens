"""
Field-by-field annotation of a raw frame, for the Packet Lab in the UI.

decoder.decode() answers "what is this packet?". explain_frame() answers the
viva question "show me WHERE in the bytes that came from": every header field
with its absolute byte offset, length, raw hex, decoded value and a one-line
note (what the field means, whether the checksum verifies, what TTL implies).

It re-reads the bytes with struct at the documented RFC offsets - it does not
share code with decode(), so the two act as a cross-check on each other.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional

from crypto.tls import parse_tls

PORT_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP server",
    68: "DHCP client", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 1900: "SSDP", 3389: "RDP", 5353: "mDNS", 8080: "HTTP-alt",
}
ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q VLAN"}
IP_PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IP", 47: "GRE", 50: "ESP"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _field(name: str, offset: int, length: int, raw: bytes, value, note: str = "") -> dict:
    return {
        "name": name,
        "offset": offset,
        "length": length,
        "hex": raw[offset : offset + length].hex(),
        "value": str(value),
        "note": note,
    }


def _port_note(port: int) -> str:
    return PORT_NAMES.get(port, "ephemeral / unassigned" if port >= 49152 else "")


def _ttl_note(ttl: int) -> str:
    for start in (32, 64, 128, 255):
        if ttl <= start:
            family = {
                32: "older devices",
                64: "Linux / Android / iOS / macOS",
                128: "Windows",
                255: "routers / network gear",
            }[start]
            return f"likely started at {start} ({family}), about {start - ttl} hop(s) away"
    return ""


def _checksum_ok(data: bytes) -> bool:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def _tcp_flags_text(flags: int) -> str:
    names = [(0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"), (0x20, "URG")]
    return ",".join(n for bit, n in names if flags & bit) or "none"


def _tcp_flag_meaning(flags: int) -> str:
    if flags & 0x02 and not flags & 0x10:
        return "connection request (step 1 of the 3-way handshake)"
    if flags & 0x02 and flags & 0x10:
        return "connection accepted (step 2 of the handshake)"
    if flags & 0x04:
        return "connection refused / reset - on a SYN this means the port is closed"
    if flags & 0x01:
        return "sender is closing its side of the connection"
    if flags & 0x08:
        return "data being pushed to the application"
    if flags & 0x10:
        return "acknowledging received data"
    return ""


def _dns_name(data: bytes, pos: int) -> str:
    labels, jumps = [], 0
    while pos < len(data) and jumps < 20:
        n = data[pos]
        if n == 0:
            break
        if n & 0xC0 == 0xC0:
            pos = ((n & 0x3F) << 8) | data[pos + 1]
            jumps += 1
            continue
        labels.append(data[pos + 1 : pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    return ".".join(labels)


def explain_frame(raw: bytes) -> dict:
    layers: List[dict] = []
    notes: List[str] = []

    def layer(name: str, kind: str, start: int, end: int, fields: List[dict]) -> None:
        layers.append({"name": name, "kind": kind, "start": start, "end": min(end, len(raw)), "fields": fields})

    if len(raw) < 14:
        return {"length": len(raw), "layers": [], "notes": ["Frame shorter than an Ethernet header (14 bytes)."]}

    eth_type = struct.unpack("!H", raw[12:14])[0]
    layer(
        "Ethernet II", "eth", 0, 14,
        [
            _field("Destination MAC", 0, 6, raw, _mac(raw[0:6]),
                   "broadcast - everyone on the LAN receives this" if raw[0:6] == b"\xff" * 6 else "next-hop hardware address"),
            _field("Source MAC", 6, 6, raw, _mac(raw[6:12]),
                   "locally-administered bit set: a randomised private MAC (typical of phones)" if raw[6] & 0x02 else ""),
            _field("EtherType", 12, 2, raw, f"0x{eth_type:04x}", ETHERTYPES.get(eth_type, "unrecognised")),
        ],
    )
    off = 14
    if eth_type == 0x8100 and len(raw) >= 18:
        inner = struct.unpack("!H", raw[16:18])[0]
        layer("802.1Q VLAN tag", "eth", 14, 18, [_field("Inner EtherType", 16, 2, raw, f"0x{inner:04x}", ETHERTYPES.get(inner, ""))])
        eth_type, off = inner, 18

    if eth_type == 0x0806 and len(raw) >= off + 28:
        a = raw[off : off + 28]
        opcode = struct.unpack("!H", a[6:8])[0]
        layer(
            "ARP", "arp", off, off + 28,
            [
                _field("Hardware type", off, 2, raw, struct.unpack("!H", a[0:2])[0], "1 = Ethernet"),
                _field("Protocol type", off + 2, 2, raw, f"0x{struct.unpack('!H', a[2:4])[0]:04x}", "IPv4"),
                _field("Address lengths", off + 4, 2, raw, f"{a[4]} / {a[5]}", "MAC 6 bytes / IP 4 bytes"),
                _field("Opcode", off + 6, 2, raw, opcode, "request - who has this IP?" if opcode == 1 else "reply - this IP is at this MAC"),
                _field("Sender MAC", off + 8, 6, raw, _mac(a[8:14]), "the claim: this hardware address..."),
                _field("Sender IP", off + 14, 4, raw, _ip(a[14:18]), "...owns this IP address"),
                _field("Target MAC", off + 18, 6, raw, _mac(a[18:24]), "zeros in a request = unknown yet"),
                _field("Target IP", off + 24, 4, raw, _ip(a[24:28])),
            ],
        )
        notes.append("ARP has no authentication: any host can claim any IP. That is why NetLens watches for one IP appearing with two MACs.")
        return {"length": len(raw), "layers": layers, "notes": notes}

    if eth_type != 0x0800 or len(raw) < off + 20:
        return {"length": len(raw), "layers": layers, "notes": notes or ["Not IPv4 - NetLens does not decode this EtherType."]}

    ip = raw[off:]
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    flags_frag = struct.unpack("!H", ip[6:8])[0]
    proto = ip[9]
    header = ip[:ihl]
    layer(
        "IPv4", "ip", off, off + ihl,
        [
            _field("Version", off, 1, raw, ip[0] >> 4, "high nibble of byte 0"),
            _field("Header length (IHL)", off, 1, raw, ip[0] & 0x0F, f"low nibble x 4 = {ihl} bytes"),
            _field("Type of service", off + 1, 1, raw, ip[1], "DSCP / ECN"),
            _field("Total length", off + 2, 2, raw, total, "header + payload"),
            _field("Identification", off + 4, 2, raw, struct.unpack("!H", ip[4:6])[0], "groups fragments of one datagram"),
            _field("Flags / fragment offset", off + 6, 2, raw, f"0x{flags_frag:04x}", "DF (don't fragment) set" if flags_frag & 0x4000 else ""),
            _field("TTL", off + 8, 1, raw, ip[8], _ttl_note(ip[8])),
            _field("Protocol", off + 9, 1, raw, proto, IP_PROTOCOLS.get(proto, "other")),
            _field("Header checksum", off + 10, 2, raw, f"0x{struct.unpack('!H', ip[10:12])[0]:04x}",
                   "verifies" if _checksum_ok(header) else "does NOT verify (offload or corruption)"),
            _field("Source IP", off + 12, 4, raw, _ip(ip[12:16])),
            _field("Destination IP", off + 16, 4, raw, _ip(ip[16:20])),
        ],
    )

    payload_off = off + ihl
    seg = raw[payload_off : off + total] if total >= ihl else raw[payload_off:]
    src_ip, dst_ip = ip[12:16], ip[16:20]

    if proto == 6 and len(seg) >= 20:
        sport, dport, seq, ack = struct.unpack("!HHII", seg[:12])
        doff = (seg[12] >> 4) * 4
        flags = seg[13]
        window = struct.unpack("!H", seg[14:16])[0]
        pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(seg))
        csum_ok = _checksum_ok(pseudo + seg)
        layer(
            "TCP", "tcp", payload_off, payload_off + doff,
            [
                _field("Source port", payload_off, 2, raw, sport, _port_note(sport)),
                _field("Destination port", payload_off + 2, 2, raw, dport, _port_note(dport)),
                _field("Sequence number", payload_off + 4, 4, raw, seq, "position of the first payload byte in the stream"),
                _field("Acknowledgement number", payload_off + 8, 4, raw, ack, "next byte the sender expects to receive"),
                _field("Data offset", payload_off + 12, 1, raw, seg[12] >> 4, f"x 4 = {doff} byte header"),
                _field("Flags", payload_off + 13, 1, raw, _tcp_flags_text(flags), _tcp_flag_meaning(flags)),
                _field("Window", payload_off + 14, 2, raw, window, "receive buffer the sender is advertising"),
                _field("Checksum", payload_off + 16, 2, raw, f"0x{struct.unpack('!H', seg[16:18])[0]:04x}",
                       "verifies (incl. pseudo-header)" if csum_ok else "does not verify (checksum offload?)"),
            ],
        )
        body = seg[doff:]
        body_off = payload_off + doff
        if body:
            tls = parse_tls(body)
            if tls and tls["kind"] == "client_hello":
                layer("TLS ClientHello", "tls", body_off, body_off + min(len(body), 5 + 4 + 2 + 32), [
                    _field("Record type", body_off, 1, raw, f"0x{body[0]:02x}", "22 = handshake"),
                    _field("Record version", body_off + 1, 2, raw, f"0x{struct.unpack('!H', body[1:3])[0]:04x}", "legacy field"),
                    _field("Record length", body_off + 3, 2, raw, struct.unpack("!H", body[3:5])[0]),
                    _field("Handshake type", body_off + 5, 1, raw, body[5], "1 = ClientHello"),
                    _field("Server name (SNI)", body_off, 0, raw, tls.get("sni") or "-", "sent in cleartext - this is how NetLens names HTTPS sites"),
                    _field("Highest version offered", body_off, 0, raw, tls["version"]),
                    _field("Cipher suites offered", body_off, 0, raw, tls["cipher_count"], "; ".join(tls["reasons"]) or "no weak suites"),
                    _field("JA3 fingerprint", body_off, 0, raw, tls["ja3"], "identifies the client software's TLS stack"),
                ])
                notes.append("Everything after the hello is encrypted. NetLens reads only this opening handshake - never the content.")
            elif tls and tls["kind"] == "server_hello":
                layer("TLS ServerHello", "tls", body_off, body_off + min(len(body), 9), [
                    _field("Record type", body_off, 1, raw, f"0x{body[0]:02x}", "22 = handshake"),
                    _field("Handshake type", body_off + 5, 1, raw, body[5], "2 = ServerHello"),
                    _field("Negotiated version", body_off, 0, raw, tls["version"]),
                    _field("Chosen cipher suite", body_off, 0, raw, tls["cipher"], tls["cipher_weakness"] or "acceptable"),
                ])
            elif body[0] == 0x17 and len(body) >= 5:
                layer("TLS Application Data", "tls", body_off, body_off + 5, [
                    _field("Record type", body_off, 1, raw, "0x17", "23 = application data"),
                    _field("Record length", body_off + 3, 2, raw, struct.unpack("!H", body[3:5])[0], "the rest is ciphertext"),
                ])
                notes.append("This payload is encrypted application data. A sniffer sees its size and timing, not its meaning.")
            elif body.startswith((b"GET ", b"POST ", b"HTTP/1.", b"PUT ", b"HEAD ")):
                notes.append("Cleartext HTTP: anyone on the path can read this. NetLens records only that the protocol is HTTP.")
            payload_start = layers[-1]["end"] if layers[-1]["kind"] == "tls" else body_off
            if payload_start < len(raw):
                layers.append({"name": "Payload", "kind": "data", "start": payload_start, "end": len(raw), "fields": []})
        if dport == 53 or sport == 53:
            notes.append("DNS over TCP.")
    elif proto == 17 and len(seg) >= 8:
        sport, dport, length = struct.unpack("!HHH", seg[:6])
        layer(
            "UDP", "udp", payload_off, payload_off + 8,
            [
                _field("Source port", payload_off, 2, raw, sport, _port_note(sport)),
                _field("Destination port", payload_off + 2, 2, raw, dport, _port_note(dport)),
                _field("Length", payload_off + 4, 2, raw, length, "header (8) + payload"),
                _field("Checksum", payload_off + 6, 2, raw, f"0x{struct.unpack('!H', seg[6:8])[0]:04x}"),
            ],
        )
        body, body_off = seg[8:], payload_off + 8
        if (dport == 53 or sport == 53) and len(body) >= 12:
            txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", body[:12])
            qname = _dns_name(body, 12)
            qtype = ""
            pos = 12
            while pos < len(body) and body[pos] != 0 and body[pos] & 0xC0 != 0xC0:
                pos += 1 + body[pos]
            if pos + 5 <= len(body):
                qtype = DNS_TYPES.get(struct.unpack("!H", body[pos + 1 : pos + 3])[0], "?")
            layer(
                "DNS", "dns", body_off, body_off + len(body),
                [
                    _field("Transaction ID", body_off, 2, raw, f"0x{txid:04x}", "matches a response to its query"),
                    _field("Flags", body_off + 2, 2, raw, f"0x{flags:04x}", "response" if flags & 0x8000 else "standard query"),
                    _field("Questions", body_off + 4, 2, raw, qd),
                    _field("Answers", body_off + 6, 2, raw, an),
                    _field("Question name", body_off + 12, 0, raw, qname, f"type {qtype}" if qtype else ""),
                ],
            )
            notes.append("DNS is plaintext: the name the phone is about to visit is visible to anyone on the path, even when the site itself uses HTTPS.")
        elif dport == 443 or sport == 443:
            notes.append("UDP/443 is QUIC (HTTP/3): encrypted from the first packet, so no SNI or cipher metadata is visible.")
    elif proto == 1 and len(seg) >= 8:
        layer("ICMP", "icmp", payload_off, payload_off + 8, [
            _field("Type", payload_off, 1, raw, seg[0], {8: "echo request (ping)", 0: "echo reply", 3: "destination unreachable"}.get(seg[0], "")),
            _field("Code", payload_off + 1, 1, raw, seg[1]),
            _field("Checksum", payload_off + 2, 2, raw, f"0x{struct.unpack('!H', seg[2:4])[0]:04x}"),
        ])

    return {"length": len(raw), "layers": layers, "notes": notes}
