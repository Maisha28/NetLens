"""
Hardcoded fake PacketRecords for exercising db.py / flow_tracker.py /
display.py before live decoding is wired in. Not real captured traffic -
just enough of a mix (TCP handshake + data, UDP, ARP) to sanity-check
storage and flow grouping.
"""

from shared.packet_record import PacketRecord

SAMPLE_RECORDS = [
    PacketRecord(
        timestamp=1000.000, length=54,
        src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02", eth_type=0x0800,
        protocol="TCP", src_ip="10.0.0.5", dst_ip="93.184.216.34",
        src_port=51000, dst_port=443, ttl=64, ip_total_length=40,
        tcp_flags="SYN", tcp_seq=1000, tcp_ack=0,
        summary="TCP 10.0.0.5:51000 -> 93.184.216.34:443 [SYN]",
    ),
    PacketRecord(
        timestamp=1000.020, length=60,
        src_mac="aa:bb:cc:dd:ee:02", dst_mac="aa:bb:cc:dd:ee:01", eth_type=0x0800,
        protocol="TCP", src_ip="93.184.216.34", dst_ip="10.0.0.5",
        src_port=443, dst_port=51000, ttl=55, ip_total_length=44,
        tcp_flags="SYN,ACK", tcp_seq=5000, tcp_ack=1001,
        summary="TCP 93.184.216.34:443 -> 10.0.0.5:51000 [SYN,ACK]",
    ),
    PacketRecord(
        timestamp=1000.900, length=512,
        src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02", eth_type=0x0800,
        protocol="TCP", src_ip="10.0.0.5", dst_ip="93.184.216.34",
        src_port=51000, dst_port=443, ttl=64, ip_total_length=498,
        tcp_flags="PSH,ACK", tcp_seq=1001, tcp_ack=5001,
        summary="TCP 10.0.0.5:51000 -> 93.184.216.34:443 [PSH,ACK]",
    ),
    PacketRecord(
        timestamp=1001.100, length=71,
        src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02", eth_type=0x0800,
        protocol="UDP", src_ip="10.0.0.5", dst_ip="8.8.8.8",
        src_port=51002, dst_port=53, ttl=64, ip_total_length=57,
        dns_is_response=False, dns_query_name="example.com", dns_query_type="A",
        summary="DNS query: example.com (A)",
    ),
    PacketRecord(
        timestamp=1001.140, length=98,
        src_mac="aa:bb:cc:dd:ee:02", dst_mac="aa:bb:cc:dd:ee:01", eth_type=0x0800,
        protocol="UDP", src_ip="8.8.8.8", dst_ip="10.0.0.5",
        src_port=53, dst_port=51002, ttl=64, ip_total_length=84,
        dns_is_response=True, dns_query_name="example.com", dns_query_type="A",
        dns_answers=["example.com -> 93.184.216.34"],
        summary="DNS response: example.com (A) -> example.com -> 93.184.216.34",
    ),
    PacketRecord(
        timestamp=1002.000, length=42,
        src_mac="aa:bb:cc:dd:ee:03", dst_mac="ff:ff:ff:ff:ff:ff", eth_type=0x0806,
        protocol="ARP", src_ip="10.0.0.9", dst_ip="10.0.0.1",
        arp_opcode=1, arp_sender_mac="aa:bb:cc:dd:ee:03", arp_target_mac="00:00:00:00:00:00",
        summary="ARP request: who has 10.0.0.1? tell 10.0.0.9",
    ),
]
