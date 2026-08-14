"""
Builds sample raw frames for decoder testing.

Scapy IS used here, but only as a convenient frame builder (it computes
checksums/lengths for us) - not to parse anything. decode() never sees
a scapy object, only the raw bytes these frames serialise to, exactly as
capture.py would hand them over.

Run once to (re)generate the .bin fixtures:
    python decoder/test_data/generate_samples.py
"""

from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether

OUT_DIR = Path(__file__).parent


def _write(name: str, pkt) -> None:
    raw = bytes(pkt)
    (OUT_DIR / name).write_bytes(raw)
    print(f"wrote {name} ({len(raw)} bytes)")


def main() -> None:
    tcp_pkt = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src="10.0.0.5", dst="93.184.216.34", ttl=64)
        / TCP(sport=51000, dport=443, flags="S", seq=1000)
    )
    _write("tcp_packet.bin", tcp_pkt)

    udp_pkt = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src="10.0.0.5", dst="10.0.0.1", ttl=64)
        / UDP(sport=51001, dport=5353)
        / b"hello-netlens"
    )
    _write("udp_packet.bin", udp_pkt)

    arp_pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc="aa:bb:cc:dd:ee:01",
        psrc="10.0.0.5",
        hwdst="00:00:00:00:00:00",
        pdst="10.0.0.1",
    )
    _write("arp_packet.bin", arp_pkt)

    dns_query = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src="10.0.0.5", dst="8.8.8.8", ttl=64)
        / UDP(sport=51002, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    _write("dns_query.bin", dns_query)

    dns_response = (
        Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01")
        / IP(src="8.8.8.8", dst="10.0.0.5", ttl=64)
        / UDP(sport=53, dport=51002)
        / DNS(
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"),
        )
    )
    _write("dns_response.bin", dns_response)


if __name__ == "__main__":
    main()
