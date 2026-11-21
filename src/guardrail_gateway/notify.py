"""Out-of-band notifications: Webex room messages, Splunk HEC audit forwarding, generic webhooks.

All delivery is best-effort with a short timeout; a notification failure is
logged and never blocks or fails a tool call.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

import httpx2

from .config import NotificationConfig
from .store import Change

log = logging.getLogger("guardrail.notify")

_EMOJI = {
    "change.pending": "🟡",
    "change.approved": "🟢",
    "change.rejected": "⛔",
    "change.succeeded": "✅",
    "change.failed": "❌",
    "change.rolled_back": "↩️",
    "change.rollback_failed": "🚨",
    "change.blocked": "⏸️",
}


def _literal(text: str, limit: int = 500) -> str:
    """Render untrusted (agent- or upstream-controlled) text as one inert inline-code span.

    Newlines are flattened and backticks removed so the text cannot break out of
    the span to forge headings, approval banners or links in the approvers' room.
    """
    flat = " ".join(str(text).replace("`", "'").split())
    if len(flat) > limit:
        flat = flat[: limit - 3] + "..."
    return f"`{flat}`"


def webex_markdown(event: str, change: Change, public_url: str | None) -> str:
    lines = [
        f"{_EMOJI.get(event, '•')} **{event.replace('change.', '').replace('_', ' ').upper()}** `{change.id}`",
        f"- **Tool:** `{change.tool}`  **Risk:** {change.risk} ({change.risk_score})",
        f"- **Requested by:** {change.requester}  **Approvals:** {len(change.approvals)}/{change.required_approvals}",
    ]
    if change.justification:
        lines.append(f"- **Justification:** {_literal(change.justification)}")
    if change.status_reason:
        lines.append(f"- **Detail:** {_literal(change.status_reason)}")
    if event == "change.pending":
        lines.append(f"- Approve: `guardrail changes approve {change.id}`")
        if public_url:
            lines.append(f"- Review: {public_url.rstrip('/')}/guardrail/changes/{change.id}")
    return "\n".join(lines)


class Notifier:
    def __init__(self, config: NotificationConfig) -> None:
        self.config = config
        self._queue: asyncio.Queue[tuple[str, Any]] | None = None
        self._worker: asyncio.Task[None] | None = None
        self._client: httpx2.AsyncClient | None = None

    @property
    def enabled(self) -> bool:
        c = self.config
        return bool(c.webex or c.splunk_hec or c.webhooks)

    async def start(self) -> None:
        if not self.enabled or self._worker:
            return
        verify = self.config.splunk_hec.verify_tls if self.config.splunk_hec else True
        self._client = httpx2.AsyncClient(timeout=5.0, verify=verify)
        self._queue = asyncio.Queue(maxsize=10_000)
        self._worker = asyncio.create_task(self._run(), name="guardrail-notifier")

    async def stop(self) -> None:
        if self._worker and self._queue is not None:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._queue.join(), timeout=5)
            self._worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._worker
        if self._client:
            await self._client.aclose()
        self._worker = self._client = self._queue = None

    def _enqueue(self, kind: str, payload: Any) -> None:
        if self._queue is None:
            return
        try:
            self._queue.put_nowait((kind, payload))
        except asyncio.QueueFull:
            log.warning("notification queue full, dropping %s", kind)

    # sync hook used as an AuditLog sink
    def audit_sink(self, record: dict[str, Any]) -> None:
        if self.config.splunk_hec:
            self._enqueue("splunk", record)

    def change_event(self, event: str, change: Change) -> None:
        if self.config.webex:
            self._enqueue("webex", webex_markdown(event, change, self.config.public_url))
        for hook in self.config.webhooks:
            self._enqueue("webhook", (hook, {"event": event, "change": change.summary()}))

    async def _run(self) -> None:
        assert self._queue is not None
        while True:
            kind, payload = await self._queue.get()
            try:
                await self._deliver(kind, payload)
            except Exception as exc:
                log.warning("notification %s failed: %s", kind, exc)
            finally:
                self._queue.task_done()

    async def _deliver(self, kind: str, payload: Any) -> None:
        assert self._client is not None
        c = self.config
        if kind == "webex" and c.webex:
            r = await self._client.post(
                c.webex.api_url,
                headers={"Authorization": f"Bearer {c.webex.bot_token}"},
                json={"roomId": c.webex.room_id, "markdown": payload},
            )
            r.raise_for_status()
        elif kind == "splunk" and c.splunk_hec:
            event: dict[str, Any] = {"event": payload, "sourcetype": c.splunk_hec.sourcetype, "source": "mcp-guardrail-gateway"}
            if c.splunk_hec.index:
                event["index"] = c.splunk_hec.index
            r = await self._client.post(c.splunk_hec.url, headers={"Authorization": f"Splunk {c.splunk_hec.token}"}, json=event)
            r.raise_for_status()
        elif kind == "webhook":
            hook, body = payload
            r = await self._client.post(hook.url, headers=hook.headers, json=body)
            r.raise_for_status()
