"""
Shared data contract for NetLens.

Every decoded packet, from any source (live capture, pcap replay, test
fixtures), must be represented as a PacketRecord. capture/ produces raw
bytes, decoder/ turns those bytes into a PacketRecord, and storage/
consumes PacketRecords. No module should invent its own packet shape.

Do not edit without agreement from the whole team - all three modules
depend on this shape matching exactly.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PacketRecord:
    # --- Capture metadata ---
    timestamp: float  # epoch seconds, from the capture layer
    length: int        # total frame length in bytes, as seen on the wire

    # --- Ethernet (layer 2) - present on every frame ---
    src_mac: str        # e.g. "aa:bb:cc:dd:ee:ff"
    dst_mac: str
    eth_type: int        # EtherType, e.g. 0x0800 = IPv4, 0x0806 = ARP

    # --- Network / transport 5-tuple ---
    # Populated for IPv4 and ARP frames. For ARP, src_ip/dst_ip hold the
    # sender/target protocol addresses so ARP traffic can still be grouped
    # into flows alongside IP traffic. None for anything else (e.g. IPv6,
    # unrecognised EtherTypes) that Day 1 doesn't decode.
    protocol: Optional[str] = None   # "TCP" | "UDP" | "ICMP" | "ARP" | "OTHER"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None   # TCP/UDP only
    dst_port: Optional[int] = None   # TCP/UDP only

    # --- IPv4 header extras ---
    ttl: Optional[int] = None
    ip_total_length: Optional[int] = None

    # --- TCP extras ---
    tcp_flags: Optional[str] = None   # e.g. "SYN,ACK"
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None

    # --- ARP extras ---
    arp_opcode: Optional[int] = None       # 1 = request, 2 = reply
    arp_sender_mac: Optional[str] = None
    arp_target_mac: Optional[str] = None

    # --- DNS extras (application layer, riding on UDP/TCP port 53) ---
    dns_is_response: Optional[bool] = None
    dns_query_name: Optional[str] = None
    dns_query_type: Optional[str] = None
    dns_answers: List[str] = field(default_factory=list)

    # --- Fallback / debugging ---
    summary: Optional[str] = None   # short human-readable one-liner
