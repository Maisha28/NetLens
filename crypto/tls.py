"""
Passive TLS handshake analysis - cryptography posture from cleartext metadata.

A TLS handshake begins in the clear: the ClientHello announces the protocol
versions, cipher suites and extensions the client supports, and the
ServerHello announces what was actually chosen. Everything after that is
encrypted and NetLens never touches it - this module reads only the opening
bytes, by hand, at their RFC 8446 / RFC 5246 offsets:

  TLS record  : type 0x16 (handshake), legacy_version(2), length(2)
  Handshake   : type(1) 1=ClientHello 2=ServerHello, length(3)
  ClientHello : client_version(2), random(32), session_id(1+n),
                cipher_suites(2+n, 2 bytes each), compression(1+n),
                extensions(2+n)
  ServerHello : server_version(2), random(32), session_id(1+n),
                cipher_suite(2), compression(1), extensions(2+n)
  Extension   : type(2), length(2), data

Outputs per hello: negotiated/offered version, a JA3 fingerprint (an MD5 of
the hello's version/ciphers/extensions/curves/point-formats - the published
JA3 recipe, GREASE values stripped), ALPN, and a grade for the cipher list.

Limits, stated plainly: a hello split across TCP segments is not reassembled,
TLS 1.3 encrypts the certificate so it is never visible, and QUIC (HTTP/3)
hides the hello inside encrypted UDP. Those flows are simply "not inspected".
"""

from __future__ import annotations

import hashlib
import struct
from typing import Dict, List, Optional

VERSION_NAMES = {
    0x0200: "SSL 2.0",
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Cipher-suite registry (IANA) - the suites that matter for grading.
CIPHER_NAMES: Dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE_ECDSA_AES_128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_AES_256_GCM_SHA384",
    0xC02F: "ECDHE_RSA_AES_128_GCM_SHA256",
    0xC030: "ECDHE_RSA_AES_256_GCM_SHA384",
    0xCCA8: "ECDHE_RSA_CHACHA20_POLY1305",
    0xCCA9: "ECDHE_ECDSA_CHACHA20_POLY1305",
    0x009E: "DHE_RSA_AES_128_GCM_SHA256",
    0x009F: "DHE_RSA_AES_256_GCM_SHA384",
    0xC013: "ECDHE_RSA_AES_128_CBC_SHA",
    0xC014: "ECDHE_RSA_AES_256_CBC_SHA",
    0xC009: "ECDHE_ECDSA_AES_128_CBC_SHA",
    0xC00A: "ECDHE_ECDSA_AES_256_CBC_SHA",
    0x009C: "RSA_AES_128_GCM_SHA256",
    0x009D: "RSA_AES_256_GCM_SHA384",
    0x002F: "RSA_AES_128_CBC_SHA",
    0x0035: "RSA_AES_256_CBC_SHA",
    0x000A: "RSA_3DES_EDE_CBC_SHA",
    0x0005: "RSA_RC4_128_SHA",
    0x0004: "RSA_RC4_128_MD5",
    0x0009: "RSA_DES_CBC_SHA",
    0x0003: "RSA_EXPORT_RC4_40_MD5",
    0x0006: "RSA_EXPORT_RC2_CBC_40_MD5",
    0x0001: "RSA_NULL_MD5",
    0x0002: "RSA_NULL_SHA",
    0x0018: "DH_ANON_RC4_128_MD5",
    0x00FF: "EMPTY_RENEGOTIATION_INFO_SCSV",
}

# Substrings that make a suite unacceptable today, with the reason shown in
# the UI. Order matters only for the reported reason.
_WEAK_MARKERS = (
    ("NULL", "no encryption at all"),
    ("EXPORT", "40-bit export-grade key (FREAK/Logjam class)"),
    ("ANON", "unauthenticated key exchange (man-in-the-middle trivial)"),
    ("RC4", "RC4 stream cipher is broken (RFC 7465 prohibits it)"),
    ("3DES", "64-bit block cipher (Sweet32 birthday attack)"),
    ("DES_CBC", "56-bit DES key is brute-forceable"),
    ("MD5", "MD5 MAC is collision-broken"),
)


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE values: 0x0a0a, 0x1a1a ... 0xfafa (both bytes equal, low nibble 0xa)."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def cipher_name(code: int) -> str:
    return CIPHER_NAMES.get(code, f"0x{code:04X}")


def weakness(code: int) -> Optional[str]:
    name = CIPHER_NAMES.get(code)
    if name is None:
        return None
    for marker, reason in _WEAK_MARKERS:
        if marker in name:
            return reason
    return None


def _forward_secrecy(code: int) -> bool:
    name = CIPHER_NAMES.get(code, "")
    return code in (0x1301, 0x1302, 0x1303) or name.startswith(("ECDHE", "DHE"))


def version_name(code: Optional[int]) -> str:
    if code is None:
        return "unknown"
    return VERSION_NAMES.get(code, f"0x{code:04X}")


def _u16_list(data: bytes) -> List[int]:
    return [v for (v,) in struct.iter_unpack("!H", data[: len(data) // 2 * 2])]


def _record_body(payload: bytes, handshake_type: int) -> Optional[bytes]:
    """Return the handshake body (after the 4-byte handshake header) or None."""
    if len(payload) < 9 or payload[0] != 0x16 or payload[1] != 0x03:
        return None
    if payload[5] != handshake_type:
        return None
    hs_len = int.from_bytes(payload[6:9], "big")
    body = payload[9 : 9 + hs_len]
    return body if len(body) >= 34 else None


def _extensions(body: bytes, pos: int) -> List[tuple]:
    out = []
    if pos + 2 > len(body):
        return out
    (total,) = struct.unpack("!H", body[pos : pos + 2])
    pos += 2
    end = min(pos + total, len(body))
    while pos + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", body[pos : pos + 4])
        pos += 4
        out.append((ext_type, body[pos : pos + ext_len]))
        pos += ext_len
    return out


def grade_client(max_version: Optional[int], ciphers: List[int]) -> tuple:
    """Return (grade, reasons). A is best, F is worst."""
    weak = [c for c in ciphers if weakness(c)]
    reasons: List[str] = []
    if max_version is not None and max_version <= 0x0302:
        reasons.append(
            f"best version offered is {version_name(max_version)} (deprecated by RFC 8996)"
        )
        return "F", reasons
    if weak:
        reasons.append(f"offers {len(weak)} broken suite(s), e.g. {cipher_name(weak[0])}")
        return "C", reasons
    if max_version == 0x0304:
        return "A", reasons
    if any(_forward_secrecy(c) for c in ciphers):
        reasons.append("no TLS 1.3 offered")
        return "B", reasons
    reasons.append("no forward-secret suites offered")
    return "C", reasons


def parse_client_hello(payload: bytes) -> Optional[dict]:
    """Parse a TLS ClientHello from the start of a TCP payload, or None."""
    try:
        body = _record_body(payload, 0x01)
        if body is None:
            return None
        client_version = struct.unpack("!H", body[0:2])[0]
        pos = 2 + 32
        pos += 1 + body[pos]  # session id
        (cs_len,) = struct.unpack("!H", body[pos : pos + 2])
        pos += 2
        ciphers = _u16_list(body[pos : pos + cs_len])
        pos += cs_len
        pos += 1 + body[pos]  # compression methods

        sni = None
        alpn: List[str] = []
        groups: List[int] = []
        point_formats: List[int] = []
        supported_versions: List[int] = []
        ext_types: List[int] = []
        for ext_type, data in _extensions(body, pos):
            ext_types.append(ext_type)
            if ext_type == 0 and len(data) >= 5 and data[2] == 0:
                (name_len,) = struct.unpack("!H", data[3:5])
                sni = data[5 : 5 + name_len].decode("ascii", "replace")
            elif ext_type == 10 and len(data) >= 2:
                groups = _u16_list(data[2:])
            elif ext_type == 11 and len(data) >= 1:
                point_formats = list(data[1 : 1 + data[0]])
            elif ext_type == 16 and len(data) >= 2:
                p, end = 2, len(data)
                while p < end:
                    n = data[p]
                    alpn.append(data[p + 1 : p + 1 + n].decode("ascii", "replace"))
                    p += 1 + n
            elif ext_type == 43 and len(data) >= 1:
                supported_versions = _u16_list(data[1 : 1 + data[0]])

        real_versions = [v for v in supported_versions if not is_grease(v)]
        max_version = max(real_versions) if real_versions else client_version

        ja3_ciphers = [c for c in ciphers if not is_grease(c)]
        ja3_exts = [e for e in ext_types if not is_grease(e)]
        ja3_groups = [g for g in groups if not is_grease(g)]
        ja3_string = ",".join(
            [
                str(client_version),
                "-".join(map(str, ja3_ciphers)),
                "-".join(map(str, ja3_exts)),
                "-".join(map(str, ja3_groups)),
                "-".join(map(str, point_formats)),
            ]
        )
        # MD5 here is the JA3 *fingerprint* convention (an identifier, not a
        # security control) - the evidence ledger uses SHA-256/HMAC instead.
        ja3 = hashlib.md5(ja3_string.encode(), usedforsecurity=False).hexdigest()

        grade, reasons = grade_client(max_version, ja3_ciphers)
        weak = [
            {"code": f"0x{c:04X}", "name": cipher_name(c), "why": weakness(c)}
            for c in ja3_ciphers
            if weakness(c)
        ]
        return {
            "kind": "client_hello",
            "sni": sni,
            "version": version_name(max_version),
            "version_code": max_version,
            "ja3": ja3,
            "ja3_string": ja3_string,
            "cipher_count": len(ja3_ciphers),
            "ciphers": [cipher_name(c) for c in ja3_ciphers[:24]],
            "weak_ciphers": weak,
            "alpn": alpn,
            "forward_secrecy": any(_forward_secrecy(c) for c in ja3_ciphers),
            "grade": grade,
            "reasons": reasons,
        }
    except (IndexError, struct.error):
        return None


def parse_server_hello(payload: bytes) -> Optional[dict]:
    """Parse a TLS ServerHello - the suite the server actually chose."""
    try:
        body = _record_body(payload, 0x02)
        if body is None:
            return None
        version = struct.unpack("!H", body[0:2])[0]
        pos = 2 + 32
        pos += 1 + body[pos]  # session id
        (cipher,) = struct.unpack("!H", body[pos : pos + 2])
        pos += 3  # cipher(2) + compression(1)
        for ext_type, data in _extensions(body, pos):
            if ext_type == 43 and len(data) == 2:  # supported_versions: selected version
                version = struct.unpack("!H", data)[0]

        why = weakness(cipher)
        if version <= 0x0302:
            grade = "F"
        elif why:
            grade = "C"
        elif version == 0x0304:
            grade = "A"
        else:
            grade = "B" if _forward_secrecy(cipher) else "C"
        return {
            "kind": "server_hello",
            "version": version_name(version),
            "version_code": version,
            "cipher": cipher_name(cipher),
            "cipher_weakness": why,
            "forward_secrecy": _forward_secrecy(cipher),
            "grade": grade,
        }
    except (IndexError, struct.error):
        return None


def parse_tls(payload: bytes) -> Optional[dict]:
    """ClientHello or ServerHello, whichever this payload starts with."""
    if len(payload) < 9 or payload[0] != 0x16:
        return None
    return parse_client_hello(payload) if payload[5] == 0x01 else parse_server_hello(payload)
