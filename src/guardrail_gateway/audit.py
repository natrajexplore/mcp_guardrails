"""Tamper-evident audit log.

Every event is one JSON line. Each record carries the hash of the previous
record and its own hash (HMAC-SHA256 when a key is configured, plain SHA-256
otherwise), so deleting, reordering or editing any line breaks the chain and
`guardrail audit verify` reports the first bad sequence number.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from .redact import canonical_json

# Inter-process lock: the CLI and the server may append to the same log concurrently.
# Every append holds an exclusive lock while it re-reads the chain tail and writes.
_LOCK_TIMEOUT_SECONDS = 30.0

if os.name == "nt":  # pragma: no cover - exercised by the Windows CI job
    import errno
    import msvcrt
    import time

    class _FileLock:
        """Exclusive lock on a sidecar '<log>.lock' file.

        Windows byte-range locks are mandatory, so locking the log itself would
        make concurrent readers (verify, tail) fail; a sidecar avoids that.
        """

        def __init__(self, log_path: Path) -> None:
            self.path = log_path.with_name(log_path.name + ".lock")
            self._fh: IO[bytes] | None = None

        def __enter__(self) -> None:
            fh = self.path.open("a+b")
            deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
            try:
                while True:
                    try:
                        fh.seek(0)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as exc:
                        # only "held by someone else" is retried; anything else is a real failure
                        if exc.errno not in (errno.EACCES, errno.EDEADLOCK) or time.monotonic() > deadline:
                            raise TimeoutError(f"could not lock {self.path}: {exc}") from exc
                        time.sleep(0.005)
            except BaseException:
                fh.close()
                raise
            self._fh = fh

        def __exit__(self, *exc: Any) -> None:
            fh, self._fh = self._fh, None
            if fh is not None:
                try:
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                finally:
                    fh.close()

else:
    import fcntl

    class _FileLock:
        """`flock` on the log file itself (advisory, per open file description)."""

        def __init__(self, log_path: Path) -> None:
            self.path = log_path
            self._fh: IO[bytes] | None = None

        def __enter__(self) -> None:
            self._fh = self.path.open("a+b")
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)

        def __exit__(self, *exc: Any) -> None:
            fh, self._fh = self._fh, None
            if fh is not None:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                finally:
                    fh.close()


GENESIS = "0" * 64


def _digest(record: dict[str, Any], key: bytes | None) -> str:
    body = canonical_json({k: v for k, v in record.items() if k != "hash"}).encode()
    if key:
        return hmac.new(key, body, hashlib.sha256).hexdigest()
    return hashlib.sha256(body).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    records: int
    first_bad_seq: int | None = None
    message: str = ""


class AuditLog:
    def __init__(self, path: str | Path, hmac_key: bytes | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.key = hmac_key
        self._lock = threading.Lock()
        self._sinks: list[Callable[[dict[str, Any]], None]] = []

    @classmethod
    def from_env(cls, path: str | Path, key_env: str | None) -> AuditLog:
        raw = os.environ.get(key_env) if key_env else None
        return cls(path, raw.encode() if raw else None)

    def add_sink(self, sink: Callable[[dict[str, Any]], None]) -> None:
        self._sinks.append(sink)

    @staticmethod
    def _last_record(fh: IO[bytes]) -> tuple[int, str]:
        """Read the last JSON line by scanning backwards from EOF.

        Linear in the length of the last line (chunks are collected, never re-split), so one oversized
        record cannot make every later append slow while the lock is held.
        """
        fh.seek(0, os.SEEK_END)
        pos = fh.tell()
        chunks: list[bytes] = []
        found_content = False
        while pos > 0:
            step = min(8192, pos)
            pos -= step
            fh.seek(pos)
            data = fh.read(step)
            if not found_content:
                data = data.rstrip()
                if not data:
                    continue
                found_content = True
            nl = data.rfind(b"\n")
            if nl != -1:
                chunks.append(data[nl + 1 :])
                break
            chunks.append(data)
        if not found_content:
            return 0, GENESIS
        rec = json.loads(b"".join(reversed(chunks)))
        return int(rec["seq"]), str(rec["hash"])

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock, _FileLock(self.path), self.path.open("a+b") as fh:
            seq, prev = self._last_record(fh)
            record: dict[str, Any] = {
                "seq": seq + 1,
                "ts": datetime.now(tz=UTC).isoformat(timespec="milliseconds"),
                "event": event,
                **fields,
                "prev_hash": prev,
            }
            record["hash"] = _digest(record, self.key)
            fh.seek(0, os.SEEK_END)
            fh.write((canonical_json(record) + "\n").encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        for sink in self._sinks:
            try:
                sink(record)
            except Exception as exc:  # sinks are best-effort and must never break the call path
                logging.getLogger("guardrail.audit").warning("audit sink failed: %s", exc)
        return record

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        return [json.loads(ln) for ln in lines[-limit:]]


def verify_chain(path: str | Path, hmac_key: bytes | None = None) -> VerifyResult:
    p = Path(path)
    if not p.exists():
        return VerifyResult(True, 0, message="audit log does not exist yet")
    prev, expected_seq, count = GENESIS, 1, 0
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return VerifyResult(False, count, expected_seq, f"line {lineno}: not valid JSON")
            seq = rec.get("seq")
            if seq != expected_seq:
                return VerifyResult(False, count, expected_seq, f"line {lineno}: expected seq {expected_seq}, got {seq}")
            if rec.get("prev_hash") != prev:
                return VerifyResult(False, count, seq, f"seq {seq}: prev_hash does not match previous record")
            if not hmac.compare_digest(str(rec.get("hash")), _digest(rec, hmac_key)):
                return VerifyResult(False, count, seq, f"seq {seq}: hash mismatch (record modified or wrong key)")
            prev, expected_seq, count = rec["hash"], expected_seq + 1, count + 1
    return VerifyResult(True, count, message=f"{count} records verified, chain intact")
