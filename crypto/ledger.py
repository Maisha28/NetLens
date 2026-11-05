"""
Tamper-evident alert ledger: a SHA-256 hash chain, sealed with HMAC-SHA256.

Why: an alert is evidence. If someone with access to netlens.db could quietly
edit or delete an alert afterwards, the alert history would be worthless. The
ledger makes any such edit detectable:

  entry_hash[i] = SHA256( entry_hash[i-1] || canonical_json(payload[i]) )
  signature[i]  = HMAC-SHA256( secret_key, entry_hash[i] )

  * Changing any stored payload changes its hash, which breaks every later link.
  * Deleting or re-ordering rows breaks the chain.
  * Recomputing the hashes after an edit is possible for anyone - but producing
    the matching HMAC needs the secret key, which lives in a separate file.
  * The in-memory anchor (count + head hash) catches deletion of the newest
    rows, which a bare chain cannot see.

What it is not: encryption (alerts are not secret) and not protection against
someone who has both the database and the key file. It proves integrity, not
confidentiality. Stdlib only (hashlib, hmac, secrets) - no third-party crypto.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_ledger (
    idx INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    signature TEXT NOT NULL
)
"""


def canonical(payload: Dict[str, Any]) -> str:
    """Deterministic JSON so the same data always hashes identically."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def load_or_create_key(path: Path) -> bytes:
    if path.exists():
        return bytes.fromhex(path.read_text().strip())
    key = secrets.token_bytes(32)
    path.write_text(key.hex())
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


class Ledger:
    def __init__(
        self,
        conn: sqlite3.Connection,
        key: bytes,
        lock: Optional[threading.RLock] = None,
    ) -> None:
        self._conn = conn
        self._key = key
        self._lock = lock or threading.RLock()
        with self._lock:
            conn.execute(SCHEMA)
            conn.commit()
            row = conn.execute(
                "SELECT idx, entry_hash FROM alert_ledger ORDER BY idx DESC LIMIT 1"
            ).fetchone()
        self._count = (row[0] + 1) if row else 0
        self._head = row[1] if row else GENESIS
        self._tampered: Dict[int, str] = {}

    # --- hashing --------------------------------------------------------

    def _entry_hash(self, prev_hash: str, payload_json: str) -> str:
        return hashlib.sha256((prev_hash + payload_json).encode()).hexdigest()

    def _sign(self, entry_hash: str) -> str:
        return hmac.new(self._key, entry_hash.encode(), hashlib.sha256).hexdigest()

    # --- write ----------------------------------------------------------

    def append(self, payload: Dict[str, Any], ts: float) -> dict:
        payload_json = canonical(payload)
        with self._lock:
            idx = self._count
            entry_hash = self._entry_hash(self._head, payload_json)
            signature = self._sign(entry_hash)
            self._conn.execute(
                "INSERT INTO alert_ledger (idx, ts, payload, prev_hash, entry_hash, signature) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (idx, ts, payload_json, self._head, entry_hash, signature),
            )
            self._conn.commit()
            entry = {
                "idx": idx,
                "ts": ts,
                "prev_hash": self._head,
                "entry_hash": entry_hash,
                "signature": signature,
            }
            self._head = entry_hash
            self._count += 1
        return entry

    def reset(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM alert_ledger")
            self._conn.commit()
            self._count, self._head, self._tampered = 0, GENESIS, {}

    # --- read -----------------------------------------------------------

    def entries(self, limit: int = 200) -> List[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT idx, ts, payload, prev_hash, entry_hash, signature "
                "FROM alert_ledger ORDER BY idx DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for idx, ts, payload, prev_hash, entry_hash, signature in reversed(rows):
            out.append(
                {
                    "idx": idx,
                    "ts": ts,
                    "payload": json.loads(payload),
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                    "signature": signature,
                }
            )
        return out

    def verify(self) -> dict:
        """
        Re-derive the whole chain from the stored rows. Returns
        {ok, count, broken_at, reason, checks} - `checks` lists each entry's
        three tests (payload hash, chain link, HMAC) so the UI can show
        exactly which one failed.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT idx, payload, prev_hash, entry_hash, signature "
                "FROM alert_ledger ORDER BY idx"
            ).fetchall()
            expected_count, expected_head = self._count, self._head

        checks = []
        prev = GENESIS
        broken_at: Optional[int] = None
        reason: Optional[str] = None
        for pos, (idx, payload, prev_hash, entry_hash, signature) in enumerate(rows):
            link_ok = prev_hash == prev and idx == pos
            hash_ok = self._entry_hash(prev_hash, payload) == entry_hash
            sig_ok = hmac.compare_digest(self._sign(entry_hash), signature)
            checks.append({"idx": idx, "link": link_ok, "hash": hash_ok, "signature": sig_ok})
            if broken_at is None and not (link_ok and hash_ok and sig_ok):
                broken_at = idx
                reason = (
                    "stored data no longer matches its hash"
                    if not hash_ok
                    else "chain link broken (a row was removed or reordered)"
                    if not link_ok
                    else "signature invalid (hash was recomputed without the key)"
                )
            prev = entry_hash

        if broken_at is None and (len(rows) != expected_count or (rows and prev != expected_head)):
            broken_at = len(rows)
            reason = f"ledger truncated: {expected_count} entries were sealed, {len(rows)} remain"

        return {
            "ok": broken_at is None,
            "count": len(rows),
            "broken_at": broken_at,
            "reason": reason,
            "head": prev,
            "checks": checks[-200:],
        }

    # --- demo helpers ---------------------------------------------------

    def tamper(self, idx: Optional[int] = None) -> Optional[dict]:
        """
        DEMO ONLY: simulate an attacker editing a stored alert (rewriting its
        host and message) WITHOUT access to the signing key, so verify() can
        be shown catching it. Reversible via restore().
        """
        with self._lock:
            if self._count == 0:
                return None
            if idx is None:
                idx = max(0, self._count - 1)
            row = self._conn.execute(
                "SELECT payload FROM alert_ledger WHERE idx = ?", (idx,)
            ).fetchone()
            if row is None:
                return None
            original = row[0]
            data = json.loads(original)
            data["host"] = "10.0.0.99"
            data["message"] = "(edited) nothing to see here"
            data["severity"] = "low"
            self._tampered.setdefault(idx, original)
            self._conn.execute(
                "UPDATE alert_ledger SET payload = ? WHERE idx = ?", (canonical(data), idx)
            )
            self._conn.commit()
        return {"idx": idx}

    def restore(self) -> int:
        with self._lock:
            n = len(self._tampered)
            for idx, original in self._tampered.items():
                self._conn.execute(
                    "UPDATE alert_ledger SET payload = ? WHERE idx = ?", (original, idx)
                )
            self._conn.commit()
            self._tampered = {}
        return n

    @property
    def count(self) -> int:
        return self._count

    @property
    def head(self) -> str:
        return self._head
