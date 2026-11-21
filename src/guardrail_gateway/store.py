"""SQLite-backed change request store with explicit state transitions."""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

STATUSES = (
    "pending",  # waiting for approvals
    "approved",  # enough approvals, ready to execute
    "rejected",
    "expired",
    "executing",
    "succeeded",
    "failed",  # upstream error, nothing to roll back or rollback not configured
    "rolled_back",  # verification failed and rollback succeeded
    "rollback_failed",  # verification failed and rollback failed -> needs a human now
    "blocked",  # pre-execution check failed (drift, window), can be retried
)
TERMINAL = {"rejected", "expired", "succeeded", "failed", "rolled_back", "rollback_failed"}
_TRANSITIONS: dict[str, set[str]] = {
    "pending": {"approved", "rejected", "expired"},
    "approved": {"executing", "rejected", "expired", "blocked"},
    "blocked": {"executing", "rejected", "expired", "blocked"},
    "executing": {"succeeded", "failed", "rolled_back", "rollback_failed"},
}
_EXPIRABLE = {s for s, targets in _TRANSITIONS.items() if "expired" in targets}


class TransitionError(RuntimeError):
    pass


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


@dataclass
class Change:
    id: str
    created_at: str
    expires_at: str
    requester: str
    tool: str
    args: dict[str, Any]
    args_sha256: str
    tool_class: str
    risk: str
    risk_score: int
    required_approvals: int
    justification: str
    status: str = "pending"
    approvals: list[dict[str, Any]] = field(default_factory=list)
    preview_before: Any = None
    snapshot: Any = None
    result: Any = None
    verify_result: Any = None
    rollback_result: Any = None
    status_reason: str = ""
    updated_at: str = ""

    @property
    def is_expired(self) -> bool:
        # 'executing' is never expired: an in-flight change must reach a real outcome.
        return self.status in _EXPIRABLE and utcnow() > datetime.fromisoformat(self.expires_at)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "tool": self.tool,
            "risk": self.risk,
            "requester": self.requester,
            "approvals": f"{len(self.approvals)}/{self.required_approvals}",
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "justification": self.justification,
            "status_reason": self.status_reason,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_JSON_FIELDS = ("args", "approvals", "preview_before", "snapshot", "result", "verify_result", "rollback_result")
_COLUMNS = [f for f in Change.__dataclass_fields__]


class ChangeStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        if self.path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        cols = ", ".join(f"{c} TEXT" if c != "id" else "id TEXT PRIMARY KEY" for c in _COLUMNS)
        self._db.execute(f"CREATE TABLE IF NOT EXISTS changes ({cols})")
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_changes_status ON changes(status)")

    @staticmethod
    def new_id() -> str:
        return f"CHG-{utcnow():%Y%m%d}-{secrets.token_hex(3).upper()}"

    def create(self, *, ttl_minutes: int, **kwargs: Any) -> Change:
        now = utcnow()
        change = Change(
            id=self.new_id(),
            created_at=now.isoformat(timespec="seconds"),
            expires_at=(now + timedelta(minutes=ttl_minutes)).isoformat(timespec="seconds"),
            updated_at=now.isoformat(timespec="seconds"),
            **kwargs,
        )
        self._write(change, insert=True)
        return change

    def _write(self, change: Change, insert: bool = False, expected_status: str | None = None) -> None:
        """Insert, or update with compare-and-set on the status the caller last read.

        The CAS makes a stale in-memory copy (e.g. one held across an `await` while a
        human rejects the change via REST/CLI) unable to overwrite a newer status.
        """
        row = {}
        for c in _COLUMNS:
            v = getattr(change, c)
            row[c] = json.dumps(v, default=str) if c in _JSON_FIELDS else (None if v is None else str(v))
        with self._lock:
            if insert:
                ph = ", ".join("?" for _ in _COLUMNS)
                self._db.execute(f"INSERT INTO changes ({', '.join(_COLUMNS)}) VALUES ({ph})", [row[c] for c in _COLUMNS])  # noqa: S608 - column names are constants
                return
            sets = ", ".join(f"{c}=?" for c in _COLUMNS if c != "id")
            cur = self._db.execute(
                f"UPDATE changes SET {sets} WHERE id=? AND status=?",  # noqa: S608 - column names are constants
                [row[c] for c in _COLUMNS if c != "id"] + [change.id, expected_status or change.status],
            )
            if cur.rowcount != 1:
                now = self._db.execute("SELECT status FROM changes WHERE id=?", (change.id,)).fetchone()
                actual = now["status"] if now else "missing"
                raise TransitionError(f"{change.id} changed concurrently (now {actual}); refusing to overwrite")

    def _from_row(self, row: sqlite3.Row) -> Change:
        data: dict[str, Any] = {}
        for c in _COLUMNS:
            v = row[c]
            if c in _JSON_FIELDS:
                data[c] = json.loads(v) if v is not None else None
            elif c in ("risk_score", "required_approvals"):
                data[c] = int(v)
            else:
                data[c] = v if v is not None else ""
        return Change(**data)

    def get(self, change_id: str) -> Change | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM changes WHERE id=?", (change_id,)).fetchone()
        if row is None:
            return None
        return self._expire_if_due(self._from_row(row))

    def _expire_if_due(self, change: Change) -> Change:
        if change.is_expired:
            try:
                self.transition(change, "expired", "approval window elapsed")
            except TransitionError:  # someone else moved it first; report what the DB holds
                with self._lock:
                    row = self._db.execute("SELECT * FROM changes WHERE id=?", (change.id,)).fetchone()
                return self._from_row(row) if row is not None else change
        return change

    def list(self, status: str | None = None, limit: int = 50, requester: str | None = None) -> list[Change]:
        where, params = [], []
        if status:
            where.append("status=?")
            params.append(status)
        if requester is not None:
            where.append("requester=?")
            params.append(requester)
        clause = f"WHERE {' AND '.join(where)} " if where else ""
        with self._lock:
            rows = self._db.execute(
                f"SELECT * FROM changes {clause}ORDER BY created_at DESC LIMIT ?",  # noqa: S608 - fixed fragments, values bound
                [*params, limit],
            ).fetchall()
        return [self._expire_if_due(self._from_row(r)) for r in rows]

    def transition(self, change: Change, new_status: str, reason: str = "") -> Change:
        if new_status not in STATUSES:
            raise TransitionError(f"unknown status {new_status}")
        allowed = _TRANSITIONS.get(change.status, set())
        if new_status not in allowed:
            raise TransitionError(f"cannot move {change.id} from {change.status} to {new_status}")
        old = (change.status, change.status_reason, change.updated_at)
        change.status = new_status
        change.status_reason = reason
        change.updated_at = utcnow().isoformat(timespec="seconds")
        try:
            self._write(change, expected_status=old[0])
        except TransitionError:
            change.status, change.status_reason, change.updated_at = old
            raise
        return change

    def save(self, change: Change) -> None:
        change.updated_at = utcnow().isoformat(timespec="seconds")
        self._write(change)

    def claim_for_execution(self, change_id: str) -> Change | None:
        """Atomically move an approved/blocked change to executing (prevents double execution)."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE changes SET status='executing', updated_at=? WHERE id=? AND status IN ('approved','blocked')",
                (utcnow().isoformat(timespec="seconds"), change_id),
            )
            if cur.rowcount != 1:
                return None
            row = self._db.execute("SELECT * FROM changes WHERE id=?", (change_id,)).fetchone()
        return self._from_row(row)

    def close(self) -> None:
        self._db.close()
