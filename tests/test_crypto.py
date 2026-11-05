"""Tests for the cryptography layer: passive TLS analysis and the tamper-evident ledger."""

import sqlite3

import pytest

from crypto.ledger import Ledger
from crypto.tls import is_grease, parse_client_hello, parse_server_hello, parse_tls, weakness
from sim import frames as F


# --- TLS ---------------------------------------------------------------------------


def test_modern_client_hello_is_grade_a_with_tls13_and_alpn():
    info = parse_client_hello(F.tls_client_hello("www.example.com", "modern"))
    assert info["sni"] == "www.example.com"
    assert info["version"] == "TLS 1.3"
    assert info["grade"] == "A"
    assert info["alpn"] == ["h2", "http/1.1"]
    assert info["forward_secrecy"] is True
    assert info["weak_ciphers"] == []


def test_tls12_only_client_is_grade_b():
    info = parse_client_hello(F.tls_client_hello("a.example", "tls12_only"))
    assert (info["version"], info["grade"]) == ("TLS 1.2", "B")


def test_legacy_client_is_grade_f_and_lists_why():
    info = parse_client_hello(F.tls_client_hello("old.example", "legacy_iot"))
    assert info["version"] == "TLS 1.0"
    assert info["grade"] == "F"
    names = {w["name"] for w in info["weak_ciphers"]}
    assert {"RSA_RC4_128_SHA", "RSA_3DES_EDE_CBC_SHA"} <= names
    assert any("RC4" in w["why"] for w in info["weak_ciphers"])


def test_ja3_is_stable_ignores_grease_and_differs_between_stacks():
    a = parse_client_hello(F.tls_client_hello("x.example", "modern"))
    b = parse_client_hello(F.tls_client_hello("y.example", "modern"))
    c = parse_client_hello(F.tls_client_hello("x.example", "safari_like"))
    assert a["ja3"] == b["ja3"]  # random bytes and SNI do not change the fingerprint
    assert a["ja3"] != c["ja3"]
    assert len(a["ja3"]) == 32 and "2570" not in a["ja3_string"].split(",")[1]  # 0x0a0a GREASE stripped


def test_grease_detection():
    assert is_grease(0x0A0A) and is_grease(0xFAFA) and is_grease(0x2A2A)
    assert not is_grease(0x1301) and not is_grease(0x0A0B)


def test_server_hello_negotiated_values_and_grades():
    good = parse_server_hello(F.tls_server_hello(0x0304, 0x1301))
    assert (good["version"], good["cipher"], good["grade"]) == ("TLS 1.3", "TLS_AES_128_GCM_SHA256", "A")
    bad = parse_server_hello(F.tls_server_hello(0x0301, 0x0005))
    assert bad["grade"] == "F" and "RC4" in bad["cipher_weakness"]


def test_parse_tls_dispatches_and_rejects_garbage():
    assert parse_tls(F.tls_client_hello("a.example"))["kind"] == "client_hello"
    assert parse_tls(F.tls_server_hello())["kind"] == "server_hello"
    assert parse_tls(b"GET / HTTP/1.1\r\n\r\n") is None
    assert parse_tls(F.tls_client_hello("a.example")[:30]) is None
    assert parse_tls(b"") is None


def test_weakness_table():
    assert weakness(0x0005) and weakness(0x000A) and weakness(0x0001)
    assert weakness(0x1301) is None and weakness(0xC02F) is None


# --- ledger ----------------------------------------------------------------------------


def _ledger(n=4):
    ledger = Ledger(sqlite3.connect(":memory:", check_same_thread=False), b"k" * 32)
    for i in range(n):
        ledger.append({"rule": "port_scan", "host": f"10.0.0.{i}", "n": i}, float(i))
    return ledger


def test_intact_chain_verifies():
    v = _ledger().verify()
    assert v["ok"] and v["count"] == 4 and v["broken_at"] is None


def test_editing_a_payload_is_detected_and_located():
    ledger = _ledger()
    ledger.tamper(1)
    v = ledger.verify()
    assert not v["ok"] and v["broken_at"] == 1
    assert "hash" in v["reason"]


def test_restore_makes_it_verify_again():
    ledger = _ledger()
    ledger.tamper(2)
    assert not ledger.verify()["ok"]
    assert ledger.restore() == 1
    assert ledger.verify()["ok"]


def test_deleting_a_middle_row_breaks_the_chain():
    ledger = _ledger()
    ledger._conn.execute("DELETE FROM alert_ledger WHERE idx = 1")
    v = ledger.verify()
    assert not v["ok"] and v["broken_at"] == 2


def test_truncating_the_tail_is_caught_by_the_anchor():
    ledger = _ledger()
    ledger._conn.execute("DELETE FROM alert_ledger WHERE idx = 3")
    v = ledger.verify()
    assert not v["ok"] and "truncated" in v["reason"]


def test_recomputing_hashes_without_the_key_still_fails_the_signature():
    ledger = _ledger()
    # Attacker edits idx 1 AND recomputes its hash and the chain after it, but has no key.
    import json

    rows = ledger._conn.execute("SELECT idx, payload, prev_hash FROM alert_ledger ORDER BY idx").fetchall()
    prev = rows[0][2]
    forged_prev = None
    for idx, payload, _ in rows:
        data = json.loads(payload)
        if idx == 1:
            data["host"] = "6.6.6.6"
        pj = json.dumps(data, sort_keys=True, separators=(",", ":"))
        if forged_prev is None:
            forged_prev = ledger._conn.execute("SELECT prev_hash FROM alert_ledger WHERE idx = 0").fetchone()[0]
        h = ledger._entry_hash(forged_prev, pj)
        ledger._conn.execute(
            "UPDATE alert_ledger SET payload=?, prev_hash=?, entry_hash=? WHERE idx=?", (pj, forged_prev, h, idx)
        )
        forged_prev = h
    v = ledger.verify()
    assert not v["ok"]
    assert "signature" in v["reason"]  # hashes were made consistent; only the HMAC gives it away


def test_a_different_key_cannot_validate_the_chain():
    ledger = _ledger()
    other = Ledger(ledger._conn, b"x" * 32)
    assert not other.verify()["ok"]


@pytest.mark.parametrize("n", [0, 1])
def test_small_ledgers(n):
    ledger = _ledger(n)
    assert ledger.verify()["ok"]
    if n == 0:
        assert ledger.tamper() is None
