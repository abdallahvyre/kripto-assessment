"""Local scan persistence: history, resume state and baseline comparison.

Everything lives in one SQLite file so an engagement keeps a verifiable record
between runs without a server.  Two rules are enforced here rather than trusted
to callers:

* no credential material is written - the caller's settings are redacted before
  they are stored, and the redaction is applied again on read;
* a stored scan is only ever resumed against the same target and mode, so a
  resumed run cannot silently change what was being assessed.
"""

from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import time
import uuid
import threading
from functools import wraps

from core import findings as finding_model
from core.redact import redact_data
from core.fingerprint import fingerprint as make_fingerprint
from core.lifecycle import FindingRecord, initial_status, require_status
from core.evidence import EvidenceStore

SCHEMA_VERSION = 3
DEFAULT_FILENAME = "kripto.db"


RUNNING = "running"
COMPLETE = "complete"
INTERRUPTED = "interrupted"
FAILED = "failed"

_COMPATIBLE_FIELDS = ("target", "mode")


class StoreError(RuntimeError):
    """Raised when the local scan store cannot be used."""


def synchronized(function):
    @wraps(function)
    def call(self, *args, **kwargs):
        with self._lock:
            return function(self, *args, **kwargs)
    return call


def default_path(output_dir: str) -> str:
    return os.path.join(output_dir or "output", DEFAULT_FILENAME)


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _loads(value, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def new_scan_id() -> str:
    """Time-ordered, human-sortable identifier."""
    return time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


def target_key(target):
    return hashlib.sha256(str(target).encode("utf-8")).hexdigest()


class ScanStore:
    """Thin, explicit SQLite wrapper - no ORM, no hidden state."""

    def __init__(self, path: str = None, output_dir: str = "output"):
        self.path = path or default_path(output_dir)
        self._conn = None
        self._lock = threading.RLock()

    

    @synchronized
    def connect(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        directory = os.path.dirname(os.path.abspath(self.path))
        try:
            os.makedirs(directory, exist_ok=True)
            self._conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
        except (OSError, sqlite3.Error) as exc:
            self._discard_connection()
            raise StoreError(f"{self.path} is not a usable scan store: {exc}") from exc
        try:
            self._init_schema()
        except sqlite3.Error as exc:
            
            
            self._discard_connection()
            raise StoreError(
                f"{self.path} is not a usable scan store: {exc}"
            ) from exc
        return self._conn

    def _discard_connection(self) -> None:
        """Close and forget a half-open connection.

        On Windows an unclosed handle keeps the file locked, so a failed open
        must release it here rather than leaving it to the garbage collector.
        """
        if self._conn is None:
            return
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
        finally:
            self._conn = None

    def _init_schema(self) -> None:
        conn = self._conn
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise sqlite3.DatabaseError("scan schema is newer than this Kripto version")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                profile TEXT,
                status TEXT NOT NULL,
                started_at REAL NOT NULL,
                finished_at REAL,
                schema_version INTEGER NOT NULL,
                settings TEXT
            );
            CREATE TABLE IF NOT EXISTS stages (
                scan_id TEXT NOT NULL,
                name TEXT NOT NULL,
                state TEXT NOT NULL,
                note TEXT,
                elapsed REAL,
                PRIMARY KEY (scan_id, name),
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS endpoints (
                scan_id TEXT NOT NULL,
                url TEXT NOT NULL,
                source TEXT,
                PRIMARY KEY (scan_id, url),
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS findings (
                scan_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT,
                cvss REAL,
                verification TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                payload TEXT,
                PRIMARY KEY (scan_id, fingerprint),
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS lifecycle (
                target TEXT NOT NULL, fingerprint TEXT NOT NULL, payload TEXT NOT NULL,
                PRIMARY KEY(target, fingerprint));
            """
        )
        self.evidence = EvidenceStore(conn)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        if "target_key" not in columns:
            conn.execute("ALTER TABLE scans ADD COLUMN target_key TEXT")
            conn.execute("PRAGMA secure_delete = ON")
            for row in conn.execute("SELECT id,target FROM scans").fetchall():
                key = target_key(row["target"])
                conn.execute("UPDATE scans SET target=?,target_key=? WHERE id=?",
                             (redact_data(row["target"]), key, row["id"]))
                conn.execute("UPDATE lifecycle SET target=? WHERE target=?", (key, row["target"]))
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()

    @synchronized
    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self._conn.commit()
        finally:
            self.close()
        return False

    def schema_version(self) -> int:
        conn = self.connect()
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        try:
            return int(row["value"]) if row else 0
        except (TypeError, ValueError):
            return 0

    

    @synchronized
    def start_scan(self, target: str, mode: str, profile=None,
                   settings: dict = None) -> str:
        conn = self.connect()
        scan_id = new_scan_id()
        safe_settings = redact_data(settings or {})
        conn.execute(
            "INSERT INTO scans(id, target, mode, profile, status, started_at,"
            " schema_version, settings, target_key) VALUES(?,?,?,?,?,?,?,?,?)",
            (scan_id, redact_data(target), mode, profile or "", RUNNING, time.time(),
             SCHEMA_VERSION, _json(safe_settings), target_key(target)),
        )
        conn.commit()
        return scan_id

    @synchronized
    def record_stage(self, scan_id: str, name: str, state: str,
                     note: str = "", elapsed: float = None) -> None:
        conn = self.connect()
        conn.execute(
            "INSERT OR REPLACE INTO stages(scan_id, name, state, note, elapsed)"
            " VALUES(?,?,?,?,?)",
            (scan_id, name, state, str(redact_data(note or ""))[:400], elapsed),
        )
        conn.commit()

    @synchronized
    def record_endpoints(self, scan_id: str, endpoints) -> int:
        """Persist discovered endpoints. Accepts URLs or surface entries."""
        conn = self.connect()
        rows = []
        for entry in endpoints or []:
            if isinstance(entry, dict):
                url = entry.get("url") or ""
                source = entry.get("source") or ",".join(entry.get("sources") or [])
            else:
                url, source = str(entry or ""), ""
            if not url:
                continue
            rows.append((scan_id, redact_data(url), str(redact_data(source or ""))[:80]))
        if not rows:
            return 0
        conn.executemany(
            "INSERT OR IGNORE INTO endpoints(scan_id, url, source) VALUES(?,?,?)",
            rows,
        )
        conn.commit()
        return len(rows)

    @synchronized
    def record_findings(self, scan_id: str, findings) -> int:
        """Persist findings keyed by a stable fingerprint.

        The fingerprint is the same identity the report uses, so resuming a scan
        cannot duplicate a finding it has already recorded.
        """
        conn = self.connect()
        rows = []
        for entry in findings or []:
            if not isinstance(entry, dict):
                continue
            fingerprint = str(entry.get("fingerprint") or make_fingerprint(entry))
            entry["fingerprint"] = fingerprint
            lifecycle = self.lifecycle_record(scan_id, entry)
            entry["status"] = lifecycle.status.value
            entry["status_history"] = lifecycle.history
            entry["reproducibility"] = lifecycle.reproducibility
            self.save_lifecycle(scan_id, lifecycle)
            try:
                reference = self.evidence.put(scan_id, fingerprint, {
                    "kind": entry.get("kind"),
                    "target": entry.get("target"), "method": entry.get("method", "GET"),
                    "evidence": entry.get("evidence"), "payload": entry.get("payload"),
                    "reproduce": entry.get("reproduction") or entry.get("reproduce") or entry.get("reproduction_steps"),
                })
                entry["evidence_refs"] = [reference]
            except ValueError as exc:
                entry["evidence_error"] = str(exc)
            safe = redact_data(entry)
            rows.append((
                scan_id,
                fingerprint,
                str(entry.get("kind") or "unknown"),
                str(safe.get("title") or "")[:300],
                str(entry.get("severity") or ""),
                float(entry.get("cvss_score") or 0.0),
                str(entry.get("verification") or ""),
                lifecycle.status.value,
                _json(safe),
            ))
        if not rows:
            return 0
        conn.executemany(
            "INSERT OR REPLACE INTO findings(scan_id, fingerprint, kind, title,"
            " severity, cvss, verification, status, payload) VALUES(?,?,?,?,?,?,?,?,?)",
            rows,
        )
        conn.commit()
        return len(rows)

    def lifecycle_record(self, scan_id, entry) -> FindingRecord:
        target = self._scan_target(scan_id)
        key = entry["fingerprint"]
        row = self.connect().execute("SELECT payload FROM lifecycle WHERE target=? AND fingerprint=?",
                                     (target, key)).fetchone()
        if row:
            saved = json.loads(row[0])
            counts = saved.get("reproducibility") or {}
            record = FindingRecord(key, saved.get("kind", ""), saved.get("title", ""),
                                 require_status(saved["status"]), saved.get("verification", ""),
                                 counts.get("attempts", 0), counts.get("reproduced", 0),
                                 saved.get("history", []))
            if not any(event.get("scan_id") == scan_id for event in record.history):
                from core.lifecycle import _now
                record.history.append({"from": record.status.value, "to": record.status.value,
                                       "at": _now(), "scan_id": scan_id,
                                       "reason": "observed again; workflow decision retained"})
            return record
        from core.lifecycle import LifecycleRegistry
        record = LifecycleRegistry().register(entry)
        record.history[-1]["scan_id"] = scan_id
        return record

    def _scan_target(self, scan_id):
        row = self.connect().execute("SELECT target_key FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            raise StoreError("scan not found")
        return row[0]

    def save_lifecycle(self, scan_id, record):
        target = self._scan_target(scan_id)
        self.connect().execute("INSERT OR REPLACE INTO lifecycle VALUES(?,?,?)",
                               (target, record.fingerprint, _json(redact_data(record.as_dict()))))

    @synchronized
    def transition_finding(self, scan_id, fingerprint, status, reason):
        entry = self.finding_payload(scan_id, fingerprint)
        record = self.lifecycle_record(scan_id, entry)
        record.transition(status, reason)
        self._update_lifecycle(scan_id, entry, record)
        return record.as_dict()

    @synchronized
    def retest_finding(self, scan_id, fingerprint, outcome):
        entry = self.finding_payload(scan_id, fingerprint)
        record = self.lifecycle_record(scan_id, entry)
        record.retest(outcome.get("reproduced", 0), outcome.get("attempts", 0),
                      outcome.get("reason", ""), conclusive=outcome.get("conclusive", False))
        self._update_lifecycle(scan_id, entry, record)
        return record.as_dict()

    def _update_lifecycle(self, scan_id, entry, record):
        self.save_lifecycle(scan_id, record)
        entry.update(status=record.status.value, status_history=record.history,
                     reproducibility=record.reproducibility)
        self.connect().execute("UPDATE findings SET status=?,payload=? WHERE scan_id=? AND fingerprint=?",
                               (record.status.value, _json(redact_data(entry)), scan_id, record.fingerprint))
        self.connect().commit()

    @synchronized
    def finding_payload(self, scan_id, fingerprint):
        row = self.connect().execute("SELECT payload FROM findings WHERE scan_id=? AND fingerprint=?",
                                     (scan_id, fingerprint)).fetchone()
        if row is None:
            raise StoreError("finding not found in selected scan")
        return json.loads(row[0])

    @synchronized
    def finish_scan(self, scan_id: str, status: str = COMPLETE) -> None:
        conn = self.connect()
        conn.execute(
            "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
            (status, time.time(), scan_id),
        )
        conn.commit()

    

    @synchronized
    def list_scans(self, limit: int = 20) -> list:
        conn = self.connect()
        rows = conn.execute(
            "SELECT s.id, s.target, s.mode, s.profile, s.status, s.started_at,"
            " s.finished_at,"
            " (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS findings,"
            " (SELECT COUNT(*) FROM endpoints e WHERE e.scan_id = s.id) AS endpoints"
            " FROM scans s ORDER BY s.started_at DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
        return [dict(row) for row in rows]

    @synchronized
    def get_scan(self, scan_id: str) -> dict:
        conn = self.connect()
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise StoreError(f"no stored scan with id {scan_id!r}")
        record = dict(row)
        record["target"] = redact_data(record["target"])
        record["settings"] = redact_data(_loads(record.get("settings"), {}))
        record["stages"] = [
            dict(item) for item in conn.execute(
                "SELECT name, state, note, elapsed FROM stages WHERE scan_id = ?"
                " ORDER BY name", (scan_id,)
            ).fetchall()
        ]
        record["findings"] = [
            dict(item) for item in conn.execute(
                "SELECT fingerprint, kind, title, severity, cvss, verification, status"
                " FROM findings WHERE scan_id = ? ORDER BY severity, title",
                (scan_id,)
            ).fetchall()
        ]
        record["endpoints"] = [
            item["url"] for item in conn.execute(
                "SELECT url FROM endpoints WHERE scan_id = ? ORDER BY url", (scan_id,)
            ).fetchall()
        ]
        return record

    @synchronized
    def resume_state(self, scan_id: str, target: str, mode: str) -> dict:
        """Load what a resumed run may safely skip or reuse.

        A scan recorded against a different target or mode is refused: resuming
        it would claim coverage that was never measured.
        """
        record = self.get_scan(scan_id)
        for field in _COMPATIBLE_FIELDS:
            expected = target_key(target) if field == "target" else mode
            actual = record.get("target_key") if field == "target" else record.get(field)
            if str(actual or "") != str(expected or ""):
                raise StoreError(
                    f"scan {scan_id} was recorded for {field} "
                    f"{record.get(field)!r}, not {expected!r}; refusing to resume it"
                )
        completed = {item["name"] for item in record["stages"]
                     if item["state"] == "OK"}
        return {
            "scan_id": scan_id,
            "completed_stages": sorted(completed),
            "endpoints": record["endpoints"],
            "findings": record["findings"],
            "target": record["target"],
            "mode": record["mode"],
        }

    @synchronized
    def export_scan(self, scan_id: str) -> dict:
        """A single JSON-ready document for archiving or diffing."""
        record = self.get_scan(scan_id)
        return {
            "scan": {key: value for key, value in record.items()
                     if key not in ("findings", "endpoints", "stages")},
            "stages": record["stages"],
            "endpoints": record["endpoints"],
            "findings": [self.finding_payload(scan_id, item["fingerprint"])
                         for item in record["findings"]],
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

    

    @synchronized
    def compare(self, previous_id: str, current_id: str) -> dict:
        """Classify every finding between two scans of the same engagement."""
        if self._scan_target(previous_id) != self._scan_target(current_id):
            raise StoreError("cannot compare scans of different targets")
        previous = {item["fingerprint"]: item
                    for item in self.get_scan(previous_id)["findings"]}
        current = {item["fingerprint"]: item
                   for item in self.get_scan(current_id)["findings"]}

        new, resolved, persistent, changed = [], [], [], []
        for fingerprint, item in current.items():
            if fingerprint not in previous:
                new.append(item)
                continue
            before = previous[fingerprint]
            persistent.append(item)
            if (str(before.get("severity") or "") != str(item.get("severity") or "")
                    or float(before.get("cvss") or 0) != float(item.get("cvss") or 0)):
                changed.append({
                    "fingerprint": fingerprint,
                    "title": item["title"],
                    "previous_severity": before.get("severity"),
                    "current_severity": item.get("severity"),
                    "previous_cvss": before.get("cvss"),
                    "current_cvss": item.get("cvss"),
                })
        for fingerprint, item in previous.items():
            if fingerprint not in current:
                resolved.append(item)

        return {
            "previous": previous_id,
            "current": current_id,
            "counts": {
                "new": len(new),
                "resolved": len(resolved),
                "persistent": len(persistent),
                "severity_changed": len(changed),
            },
            "new": new,
            "resolved": resolved,
            "persistent": persistent,
            "severity_changed": changed,
            "resolution_verified": False,
            "comparison_note": "Missing findings are not observed; a conclusive retest is required to establish a fix.",
        }

    @synchronized
    def mark_resolved(self, scan_id: str, fingerprints) -> int:
        """Record that findings were verified as no longer present."""
        conn = self.connect()
        names = [(scan_id, str(item)) for item in (fingerprints or [])]
        if not names:
            return 0
        for _, key in names:
            self.transition_finding(scan_id, key, "RETESTED_FIXED",
                                    "operator records a conclusive retest as fixed")
        conn.commit()
        return len(names)
    
