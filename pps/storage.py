"""StorageModule: SQLite metadata, PCAP files, rotation, audit log (PPS-F-030..034, PPS-SR-005)."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import shutil
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .settings import DEFAULT_CONFIG

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, source TEXT, bpf TEXT, started REAL, ended REAL,
    packets INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0, status TEXT, file TEXT,
    created_by TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, type TEXT, severity TEXT,
    ts REAL, message TEXT, details TEXT, acked INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS presets (
    name TEXT PRIMARY KEY, expression TEXT, created_by TEXT, updated REAL
);
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, pw_hash TEXT, role TEXT, active INTEGER DEFAULT 1, created REAL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, details TEXT,
    prev_hash TEXT, hash TEXT
);
CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT);
"""

GENESIS = "0" * 64

# Session IDs become file names, so restrict them to a safe character set
# (no path separators, no "..").
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

INTERRUPTED_ERROR = "interrupted: process stopped before the capture finished"


def _entry_hash(
    prev: str, ts: float, actor: str, action: str, details: str, key: bytes | None = None
) -> str:
    payload = json.dumps([prev, round(ts, 6), actor, action, details], separators=(",", ":"))
    if key:
        return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    return hashlib.sha256(payload.encode()).hexdigest()


class Storage:
    def __init__(
        self,
        db_path: Path,
        captures_dir: Path,
        defaults: dict[str, Any] | None = None,
        *,
        audit_key: bytes | None = None,
        recover_interrupted: bool = True,
    ):
        """Open (or create) the metadata database and captures directory.

        defaults: runtime config defaults (see settings.runtime_defaults); values
            saved with set_config() override them.
        audit_key: optional secret for HMAC-SHA256 audit entries. Without it the
            chain uses plain SHA-256, which detects edits but can be recomputed
            by anyone with write access to the database.
        recover_interrupted: mark sessions left ACTIVE by a previous run as
            INTERRUPTED. Disable only if several processes share one database.
        """
        self.defaults = dict(DEFAULT_CONFIG if defaults is None else defaults)
        self.captures_dir = Path(captures_dir)
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self._audit_key = audit_key
        self._lock = threading.RLock()
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self._lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript(SCHEMA)
            self.db.commit()
        if recover_interrupted:
            self.recover_interrupted_sessions()

    # ------------------------------------------------------------------ helpers
    def _exec(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur

    def _all(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def _one(self, sql: str, args: tuple = ()) -> dict[str, Any] | None:
        with self._lock:
            r = self.db.execute(sql, args).fetchone()
            return dict(r) if r else None

    def close(self) -> None:
        with self._lock:
            self.db.close()

    def __enter__(self) -> Storage:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ config (PPS-F-060)
    def get_config(self) -> dict[str, Any]:
        cfg = dict(self.defaults)
        for row in self._all("SELECT key, value FROM config"):
            cfg[row["key"]] = json.loads(row["value"])
        return cfg

    def set_config(self, updates: dict[str, Any]) -> dict[str, Any]:
        unknown = [k for k in updates if k not in self.defaults]
        if unknown:
            raise KeyError(unknown[0])
        for k, v in updates.items():
            self._exec(
                "INSERT OR REPLACE INTO config(key, value) VALUES (?, ?)", (k, json.dumps(v))
            )
        return self.get_config()

    # ------------------------------------------------------------------ sessions (PPS-F-030)
    @staticmethod
    def validate_session_id(session_id: str) -> str:
        if not isinstance(session_id, str) or not SESSION_ID_RE.fullmatch(session_id):
            raise ValueError(f"invalid session id: {session_id!r}")
        return session_id

    def pcap_path(self, session_id: str) -> Path:
        return self.captures_dir / f"{self.validate_session_id(session_id)}.pcap"

    def create_session(self, session_id: str, source: str, bpf: str, user: str) -> dict[str, Any]:
        self._exec(
            "INSERT INTO sessions(id, source, bpf, started, status, file, created_by) "
            "VALUES (?,?,?,?,?,?,?)",
            (session_id, source, bpf, time.time(), "ACTIVE", self.pcap_path(session_id).name, user),
        )
        return self.get_session(session_id)  # type: ignore[return-value]

    def finish_session(
        self,
        session_id: str,
        packets: int,
        nbytes: int,
        status: str = "DONE",
        error: str | None = None,
    ) -> None:
        self._exec(
            "UPDATE sessions SET ended=?, packets=?, bytes=?, status=?, error=? WHERE id=?",
            (time.time(), packets, nbytes, status, error, session_id),
        )

    def recover_interrupted_sessions(self) -> list[str]:
        """Mark sessions still ACTIVE from a previous run as INTERRUPTED.

        A crash or power loss mid-capture would otherwise leave the session
        ACTIVE forever, so rotation would never reclaim its file.
        """
        with self._lock:
            ids = [
                r["id"]
                for r in self.db.execute("SELECT id FROM sessions WHERE status='ACTIVE'")
            ]
            if ids:
                self.db.execute(
                    "UPDATE sessions SET status='INTERRUPTED', ended=COALESCE(ended, ?), "
                    "error=COALESCE(error, ?) WHERE status='ACTIVE'",
                    (time.time(), INTERRUPTED_ERROR),
                )
                self.db.commit()
        return ids

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM sessions WHERE id=?", (session_id,))

    def list_sessions(self) -> list[dict[str, Any]]:
        rows = self._all("SELECT * FROM sessions ORDER BY started DESC")
        for r in rows:
            p = self.captures_dir / (r["file"] or "")
            r["file_size"] = p.stat().st_size if p.is_file() else 0
        return rows

    def delete_session(self, session_id: str) -> None:
        p = self.pcap_path(session_id)
        if p.exists():
            p.unlink()
        self._exec("DELETE FROM sessions WHERE id=?", (session_id,))

    # ------------------------------------------------------------------ rotation (PPS-F-032, F-034)
    def storage_used_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.captures_dir.glob("*.pcap") if p.is_file())

    def disk_free_pct(self) -> float:
        du = shutil.disk_usage(self.captures_dir)
        return 100.0 * du.free / du.total

    def rotate(self, max_bytes: int, keep: set[str] | None = None) -> list[str]:
        """Delete oldest finished sessions until total capture size <= max_bytes.

        Only sessions whose PCAP file frees space are candidates; ACTIVE sessions,
        sessions in ``keep`` and sessions with no file on disk are never removed.
        If deleting every candidate still could not bring usage under the limit
        (for example a live capture or untracked .pcap files take up the space),
        nothing is deleted: removing history would not solve the problem.
        """
        keep = keep or set()
        used = self.storage_used_bytes()
        if used <= max_bytes:
            return []
        candidates = [
            s
            for s in sorted(self.list_sessions(), key=lambda r: r["started"] or 0)
            if s["id"] not in keep and s["status"] != "ACTIVE" and s["file_size"] > 0
        ]
        if used - sum(s["file_size"] for s in candidates) > max_bytes:
            return []
        removed: list[str] = []
        for s in candidates:
            if used <= max_bytes:
                break
            used -= s["file_size"]
            self.delete_session(s["id"])
            removed.append(s["id"])
        return removed

    def storage_status(self, cfg: dict[str, Any]) -> dict[str, Any]:
        used = self.storage_used_bytes()
        quota = int(cfg["max_storage_mb"]) * 1024 * 1024
        free_pct = self.disk_free_pct()
        quota_left_pct = 100.0 * max(quota - used, 0) / quota if quota else 100.0
        warn_pct = float(cfg["low_space_warn_pct"])
        return {
            "used_bytes": used,
            "quota_bytes": quota,
            "quota_left_pct": round(quota_left_pct, 1),
            "disk_free_pct": round(free_pct, 1),
            "warning": quota_left_pct < warn_pct or free_pct < warn_pct,
        }

    # ------------------------------------------------------------------ alerts (PPS-F-043)
    def save_alert(self, session_id: str | None, alert: dict[str, Any]) -> int:
        cur = self._exec(
            "INSERT INTO alerts(session_id, type, severity, ts, message, details) "
            "VALUES (?,?,?,?,?,?)",
            (
                session_id,
                alert["type"],
                alert["severity"],
                alert["ts"],
                alert["message"],
                json.dumps(alert.get("details", {})),
            ),
        )
        return int(cur.lastrowid or 0)

    def list_alerts(
        self,
        since: float | None = None,
        type_: str | None = None,
        session_id: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM alerts WHERE 1=1", []
        if since is not None:
            sql += " AND ts >= ?"
            args.append(since)
        if type_:
            sql += " AND type = ?"
            args.append(type_)
        if session_id:
            sql += " AND session_id = ?"
            args.append(session_id)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        rows = self._all(sql, tuple(args))
        for r in rows:
            r["details"] = json.loads(r["details"] or "{}")
            r["acked"] = bool(r["acked"])
        return rows

    def ack_alert(self, alert_id: int) -> bool:
        return self._exec("UPDATE alerts SET acked=1 WHERE id=?", (alert_id,)).rowcount > 0

    # ------------------------------------------------------------------ presets (PPS-F-023)
    def list_presets(self) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM presets ORDER BY name")

    def save_preset(self, name: str, expression: str, user: str) -> None:
        self._exec(
            "INSERT OR REPLACE INTO presets(name, expression, created_by, updated) "
            "VALUES (?,?,?,?)",
            (name, expression, user, time.time()),
        )

    def delete_preset(self, name: str) -> bool:
        return self._exec("DELETE FROM presets WHERE name=?", (name,)).rowcount > 0

    # ------------------------------------------------------------------ users (PPS-F-061)
    def get_user(self, username: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM users WHERE username=?", (username,))

    def list_users(self) -> list[dict[str, Any]]:
        return self._all("SELECT username, role, active, created FROM users ORDER BY username")

    def upsert_user(
        self, username: str, pw_hash: str | None, role: str, active: bool = True
    ) -> None:
        """Create or update a user. pw_hash=None keeps the existing hash on update.

        The caller hashes passwords; this layer never sees plaintext.
        """
        existing = self.get_user(username)
        if existing:
            self._exec(
                "UPDATE users SET pw_hash=COALESCE(?, pw_hash), role=?, active=? "
                "WHERE username=?",
                (pw_hash, role, int(active), username),
            )
        else:
            self._exec(
                "INSERT INTO users(username, pw_hash, role, active, created) VALUES (?,?,?,?,?)",
                (username, pw_hash, role, int(active), time.time()),
            )

    def user_count(self) -> int:
        row = self._one("SELECT COUNT(*) AS n FROM users")
        return int(row["n"]) if row else 0

    # ------------------------------------------------------------------ audit log (PPS-SR-005)
    def audit(self, actor: str, action: str, details: dict[str, Any] | None = None) -> str:
        """Append an audit entry and return its hash (the new head of the chain)."""
        det = json.dumps(details or {}, sort_keys=True)
        with self._lock:
            row = self.db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            ts = time.time()
            h = _entry_hash(prev, ts, actor, action, det, self._audit_key)
            self.db.execute(
                "INSERT INTO audit_log(ts, actor, action, details, prev_hash, hash) "
                "VALUES (?,?,?,?,?,?)",
                (ts, actor, action, det, prev, h),
            )
            self.db.commit()
        return h

    def list_audit(self, limit: int = 500) -> list[dict[str, Any]]:
        rows = self._all("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        for r in rows:
            r["details"] = json.loads(r["details"] or "{}")
        return rows

    def verify_audit(self, expected_head: str | None = None) -> dict[str, Any]:
        """Check the hash chain.

        Detects edited or deleted entries anywhere except at the end. Deleting
        the newest entries leaves a valid shorter chain, so to detect that, keep
        the head returned by audit() somewhere outside this database and pass it
        as expected_head.
        """
        prev = GENESIS
        rows = self._all("SELECT * FROM audit_log ORDER BY id ASC")
        for r in rows:
            expect = _entry_hash(
                prev, r["ts"], r["actor"], r["action"], r["details"], self._audit_key
            )
            if r["prev_hash"] != prev or r["hash"] != expect:
                return {"ok": False, "entries": len(rows), "broken_at": r["id"], "head": None}
            prev = r["hash"]
        head = prev if rows else None
        if expected_head is not None and head != expected_head:
            return {"ok": False, "entries": len(rows), "broken_at": "head", "head": head}
        return {"ok": True, "entries": len(rows), "broken_at": None, "head": head}
