"""Bounded, secret-safe content-addressed evidence stored with the scan database."""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3

from core.redact import redact_data

MAX_EVIDENCE_BYTES = 256_000
MAX_STORE_BYTES = 64_000_000


class EvidenceError(ValueError):
    pass


def serialize(value, limit=MAX_EVIDENCE_BYTES) -> bytes:
    """Reject executable/custom objects, cycles, deep structures and oversized input."""
    seen, used = set(), 0

    def clean(item, depth=0):
        nonlocal used
        if depth > 20:
            raise EvidenceError("evidence nesting exceeds 20 levels")
        if item is None or isinstance(item, (bool, int)):
            used += 24
            result = item
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise EvidenceError("non-finite evidence number")
            used += 24
            result = item
        elif isinstance(item, (str, bytes)):
            if len(item) > limit:
                raise EvidenceError("evidence exceeds size limit")
            result = item.decode("utf-8", errors="replace") if isinstance(item, bytes) else item
            used += len(result.encode("utf-8"))
        elif isinstance(item, (dict, list, tuple)):
            if id(item) in seen:
                raise EvidenceError("cyclic evidence")
            seen.add(id(item))
            if isinstance(item, dict):
                if any(not isinstance(key, str) for key in item):
                    raise EvidenceError("evidence keys must be strings")
                result = {clean(key, depth + 1): clean(val, depth + 1)
                          for key, val in item.items()}
            else:
                result = [clean(val, depth + 1) for val in item]
            seen.remove(id(item))
        else:
            raise EvidenceError(f"unsupported evidence type: {type(item).__name__}")
        if used > limit:
            raise EvidenceError("evidence exceeds size limit")
        return result

    safe = redact_data(clean(value))
    encoded = json.dumps(safe, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > limit:
        raise EvidenceError("serialized evidence exceeds size limit")
    return encoded


class EvidenceStore:
    """Shares ScanStore's connection/transaction; hashes sanitized bytes only."""
    def __init__(self, connection: sqlite3.Connection, limit=MAX_EVIDENCE_BYTES,
                 total_limit=MAX_STORE_BYTES):
        self.conn, self.limit, self.total_limit = connection, limit, total_limit
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS evidence (
                sha256 TEXT PRIMARY KEY, content BLOB NOT NULL, size INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS finding_evidence (
                scan_id TEXT NOT NULL, fingerprint TEXT NOT NULL, sha256 TEXT NOT NULL,
                PRIMARY KEY(scan_id, fingerprint, sha256),
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY(sha256) REFERENCES evidence(sha256));
        """)

    def put(self, scan_id, fingerprint, value) -> dict:
        content = serialize(value, self.limit)
        digest = hashlib.sha256(content).hexdigest()
        existing = self.conn.execute("SELECT size FROM evidence WHERE sha256=?", (digest,)).fetchone()
        if not existing:
            total = self.conn.execute("SELECT COALESCE(SUM(size),0) FROM evidence").fetchone()[0]
            if total + len(content) > self.total_limit:
                raise EvidenceError("central evidence store capacity reached")
            self.conn.execute("INSERT INTO evidence VALUES(?,?,?)", (digest, content, len(content)))
        self.conn.execute("INSERT OR IGNORE INTO finding_evidence VALUES(?,?,?)",
                          (scan_id, fingerprint, digest))
        return {"sha256": digest, "size": len(content), "redacted": True}

    def get(self, digest) -> dict:
        size = self.conn.execute("SELECT length(content) FROM evidence WHERE sha256=?", (digest,)).fetchone()
        if size and size[0] > self.limit:
            raise EvidenceError("evidence integrity size limit exceeded")
        row = self.conn.execute("SELECT content,size FROM evidence WHERE sha256=?", (digest,)).fetchone()
        if row is None:
            raise EvidenceError("evidence not found")
        content = bytes(row[0])
        if len(content) != row[1] or hashlib.sha256(content).hexdigest() != digest:
            raise EvidenceError("evidence integrity verification failed")
        return json.loads(content)

    def references(self, scan_id, fingerprint) -> list:
        rows = self.conn.execute("SELECT e.sha256,e.size FROM evidence e JOIN finding_evidence f "
                                 "ON e.sha256=f.sha256 WHERE f.scan_id=? AND f.fingerprint=?",
                                 (scan_id, fingerprint)).fetchall()
        return [{"sha256": row[0], "size": row[1], "redacted": True} for row in rows]
