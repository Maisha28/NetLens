import struct

from decoder.decoder import _parse_tls_sni
from enrichment.hostnames import HostnameMap, site_label
from shared.packet_record import PacketRecord


def _client_hello(host: str) -> bytes:
    name = host.encode()
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    exts = struct.pack("!HH", 0, len(sni)) + sni
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _rec(**kw):
    return PacketRecord(timestamp=0.0, length=60, src_mac="", dst_mac="", eth_type=0x0800, **kw)


def test_parse_sni():
    assert _parse_tls_sni(_client_hello("www.nytimes.com")) == "www.nytimes.com"


def test_parse_sni_rejects_garbage():
    assert _parse_tls_sni(b"GET / HTTP/1.1\r\n" + b"x" * 60) is None
    assert _parse_tls_sni(_client_hello("a.com")[:20]) is None


def test_learn_from_dns_and_sni():
    m = HostnameMap()
    m.learn(_rec(dns_is_response=True, dns_query_name="www.youtube.com",
                 dns_answers=["www.youtube.com -> CNAME record", "youtube-ui.l.google.com -> 142.250.1.1"]))
    assert m.site("142.250.1.1") == "YouTube"
    m.learn(_rec(dst_ip="9.9.9.9", tls_sni="www.nytimes.com"))
    assert m.site("1.2.3.4", "9.9.9.9") == "NYTimes (Wordle)"
    assert m.site("1.2.3.4") == ""


def test_site_label():
    assert site_label("rr3---sn-abc.googlevideo.com") == "YouTube"
    assert site_label("news.bbc.co.uk") == "bbc.co.uk"
    assert site_label("foo.example.com") == "example.com"
