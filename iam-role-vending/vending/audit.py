"""
audit.py — append-only SQLite audit log for every vending event.

Events recorded:
  credential_issued   — a new short-lived credential was issued
  credential_expired  — credential TTL elapsed (detected by janitor)
  credential_revoked  — operator manually revoked a credential
  vending_denied      — request was rejected (validation failure)

In production, replace SQLite with DynamoDB (for scalability)
or an S3-backed WORM store (for tamper-resistance).
"""
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("audit")

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                   REAL    NOT NULL,
    event                TEXT    NOT NULL,
    credential_id        TEXT,
    agent_id             TEXT,
    task_type            TEXT,
    role_arn             TEXT,
    duration_seconds     INTEGER,
    issued_at            REAL,
    expires_at           REAL,
    resource_constraints TEXT,
    context              TEXT,
    details              TEXT
)
"""


class AuditLogger:
    def __init__(self, db_path: str = "audit.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._lock = threading.Lock()
        with self._conn() as conn:
            conn.execute(CREATE_TABLE)

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def _write(self, event: str, **kwargs) -> None:
        row = {
            "ts":    time.time(),
            "event": event,
            **{k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
               for k, v in kwargs.items()},
        }
        cols = ", ".join(row.keys())
        placeholders = ", ".join("?" * len(row))
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    f"INSERT INTO audit_log ({cols}) VALUES ({placeholders})",
                    list(row.values()),
                )
        logger.info(json.dumps({"event": event, **{k: v for k, v in kwargs.items()
                                                    if k not in ("resource_constraints", "context")}}))

    # ── Public event methods ──────────────────────────────────────────────────

    def log_issued(
        self,
        credential_id: str,
        agent_id: str,
        task_type: str,
        role_arn: str,
        duration_seconds: int,
        issued_at: float,
        expires_at: float,
        resource_constraints: dict,
        context: dict,
    ) -> None:
        self._write(
            "credential_issued",
            credential_id=credential_id,
            agent_id=agent_id,
            task_type=task_type,
            role_arn=role_arn,
            duration_seconds=duration_seconds,
            issued_at=issued_at,
            expires_at=expires_at,
            resource_constraints=resource_constraints,
            context=context,
        )

    def log_expired(self, credential_id: str, agent_id: str, task_type: str) -> None:
        self._write(
            "credential_expired",
            credential_id=credential_id,
            agent_id=agent_id,
            task_type=task_type,
        )

    def log_revoked(
        self,
        credential_id: str,
        agent_id: str,
        task_type: str,
        reason: str,
    ) -> None:
        self._write(
            "credential_revoked",
            credential_id=credential_id,
            agent_id=agent_id,
            task_type=task_type,
            details=reason,
        )

    def log_denied(
        self,
        agent_id: str,
        task_type: str,
        reason: str,
    ) -> None:
        self._write(
            "vending_denied",
            agent_id=agent_id,
            task_type=task_type,
            details=reason,
        )

    # ── Query methods ─────────────────────────────────────────────────────────

    def recent(self, limit: int = 50, agent_id: Optional[str] = None) -> list[dict]:
        query = "SELECT * FROM audit_log"
        params = []
        if agent_id:
            query += " WHERE agent_id = ?"
            params.append(agent_id)
        query += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()

        result = []
        for row in rows:
            d = dict(row)
            for field in ("resource_constraints", "context"):
                if d.get(field):
                    try:
                        d[field] = json.loads(d[field])
                    except (json.JSONDecodeError, TypeError):
                        pass
            result.append(d)
        return result

    def stats(self) -> dict:
        with self._conn() as conn:
            total    = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            issued   = conn.execute("SELECT COUNT(*) FROM audit_log WHERE event='credential_issued'").fetchone()[0]
            expired  = conn.execute("SELECT COUNT(*) FROM audit_log WHERE event='credential_expired'").fetchone()[0]
            revoked  = conn.execute("SELECT COUNT(*) FROM audit_log WHERE event='credential_revoked'").fetchone()[0]
            denied   = conn.execute("SELECT COUNT(*) FROM audit_log WHERE event='vending_denied'").fetchone()[0]
        return {
            "total_events": total,
            "credentials_issued": issued,
            "credentials_expired": expired,
            "credentials_revoked": revoked,
            "requests_denied": denied,
        }
