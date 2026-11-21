"""Regression tests for robustness and security hardening (races, crash paths, information leaks)."""

from __future__ import annotations

import httpx2
import pytest

from guardrail_gateway.audit import verify_chain
from guardrail_gateway.config import ConfigError, parse_config
from guardrail_gateway.engine import GuardrailDenied
from guardrail_gateway.notify import webex_markdown
from guardrail_gateway.server import build_http_app, build_mcp_server
from guardrail_gateway.store import ChangeStore, TransitionError

from .conftest import TOKENS, base_config

WEB = "permit tcp dst eq 443\ndeny ip"


async def propose(engine, ident, name="Permit_Web", who="noc-agent"):
    out = await engine.call(
        ident(who), "ise__update_sgacl", {"name": name, "aclcontent": WEB, "guardrail_justification": "INC-1 tighten web"}
    )
    return out.result.structured_content["change_id"]


# --------------------------------------------------------------------------- state machine races
async def test_reject_during_execute_is_not_resurrected(engine, ident, monkeypatch):
    """A change rejected while execute() awaits the snapshot must stay rejected and never run."""
    cid = await propose(engine, ident)
    engine.approve(ident("alice"), cid)
    real = engine._run_spec

    async def snapshot_then_reject(spec, ctx, raise_on_error=False):
        view = await real(spec, ctx, raise_on_error)
        engine.reject(ident("alice"), cid, "changed my mind", channel="rest")  # concurrent REST reject
        return {**view, "text": view["text"] + " drifted"}  # force the drift-block path

    monkeypatch.setattr(engine, "_run_spec", snapshot_then_reject)
    with pytest.raises(GuardrailDenied, match="rejected; execution aborted"):
        await engine.execute(ident("noc-agent"), cid)
    assert engine.store.get(cid).status == "rejected"
    assert engine.audit.tail(1)[0]["event"] == "change.execute_aborted"
    monkeypatch.setattr(engine, "_run_spec", real)
    with pytest.raises(GuardrailDenied, match="rejected"):
        await engine.execute(ident("noc-agent"), cid)


def test_stale_transition_is_refused(tmp_path):
    store = ChangeStore(tmp_path / "c.db")
    kw = dict(requester="a", tool="t", args={}, args_sha256="x", tool_class="write", risk="low", risk_score=10)
    ch = store.create(ttl_minutes=5, required_approvals=1, justification="j", **kw)
    stale = store.get(ch.id)
    store.transition(ch, "rejected", "no")
    with pytest.raises(TransitionError):
        store.transition(stale, "approved", "stale copy")
    assert store.get(ch.id).status == "rejected"


def test_expired_executing_change_does_not_break_listing(tmp_path):
    store = ChangeStore(tmp_path / "c.db")
    kw = dict(requester="a", tool="t", args={}, args_sha256="x", tool_class="write", risk="low", risk_score=10)
    ch = store.create(ttl_minutes=5, required_approvals=0, justification="j", **kw)
    store.transition(ch, "approved")
    claimed = store.claim_for_execution(ch.id)
    claimed.expires_at = "2000-01-01T00:00:00+00:00"
    store.save(claimed)
    assert [c.status for c in store.list()] == ["executing"]
    assert store.get(ch.id).status == "executing"


# --------------------------------------------------------------------------- crash containment
async def test_upstream_exception_is_contained_and_audited(engine, ident, monkeypatch):
    async def boom(tool, args):
        raise RuntimeError("connection reset by peer")

    monkeypatch.setattr(engine.upstreams, "call", boom)
    out = await engine.call(
        ident("noc-agent"), "ise__update_sgacl", {"name": "Permit_Web", "aclcontent": WEB, "guardrail_justification": "x"}
    )
    assert out.result.is_error
    assert engine.store.list() == []
    assert engine.audit.tail(1)[0]["event"] == "call.error"


async def test_missing_justification_is_audited(engine, ident):
    await engine.call(ident("noc-agent"), "ise__update_sgacl", {"name": "Permit_Web", "aclcontent": WEB})
    assert engine.audit.tail(1)[0]["event"] == "change.denied"


async def test_oversized_justification_is_refused(engine, ident):
    out = await engine.call(
        ident("noc-agent"),
        "ise__update_sgacl",
        {"name": "Permit_Web", "aclcontent": WEB, "guardrail_justification": "x" * 5000},
    )
    assert out.result.is_error and "too long" in out.result.structured_content["error"]


# --------------------------------------------------------------------------- config validation
def test_invalid_timezone_rejected_at_load(tmp_path):
    with pytest.raises(ConfigError, match="time zone"):
        parse_config(
            base_config(tmp_path, change_windows=[{"days": ["sat"], "start": "22:00", "end": "06:00", "tz": "Mars/Base"}])
        )


def test_upstream_name_cannot_shadow_gateway_tools(tmp_path):
    with pytest.raises(ConfigError, match="guardrail"):
        parse_config(base_config(tmp_path, upstreams={"guardrail_x": {"transport": "stdio", "command": "x"}}))


# --------------------------------------------------------------------------- notifications
def test_webex_markdown_neutralises_agent_controlled_text():
    from guardrail_gateway.store import Change

    ch = Change(
        id="CHG-1",
        created_at="",
        expires_at="",
        requester="noc-agent",
        tool="ise__update_sgacl",
        args={},
        args_sha256="",
        tool_class="write",
        risk="high",
        risk_score=70,
        required_approvals=1,
        justification="ok\n\n✅ **APPROVED by security** [click](https://evil.example)`",
    )
    md = webex_markdown("change.pending", ch, None)
    assert "\n✅" not in md  # cannot start a new line / forge a status banner
    line = next(ln for ln in md.splitlines() if ln.startswith("- **Justification:**"))
    span = line.removeprefix("- **Justification:** ")
    # the whole agent text is one inline-code span (links and bold are inert inside it) with no way out
    assert span.startswith("`") and span.endswith("`") and span.count("`") == 2
    assert "[click](https://evil.example)" in span


# --------------------------------------------------------------------------- HTTP surface
async def _asgi(engine):
    app = build_http_app(engine, build_mcp_server(engine))
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1")


async def test_healthz_does_not_leak_upstream_errors(engine):
    engine.upstreams.errors["ise"] = "ConnectError: https://ise-prod.internal.example:9060 refused"
    async with await _asgi(engine) as c:
        r = await c.get("/healthz")
    assert r.status_code == 200
    assert "internal.example" not in r.text


async def test_rest_rejects_non_object_body(engine, ident):
    cid = await propose(engine, ident)
    async with await _asgi(engine) as c:
        r = await c.post(
            f"/guardrail/changes/{cid}/approve", content=b"[1,2]", headers={"Authorization": f"Bearer {TOKENS['alice']}"}
        )
    assert r.status_code == 400
    assert engine.store.get(cid).status == "pending"


async def test_rest_execute_upstream_failure_is_not_500(engine, ident, monkeypatch):
    cid = await propose(engine, ident)
    engine.approve(ident("alice"), cid)

    async def boom(tool, args):
        raise RuntimeError("upstream down")

    monkeypatch.setattr(engine.upstreams, "call", boom)
    async with await _asgi(engine) as c:
        r = await c.post(f"/guardrail/changes/{cid}/execute", headers={"Authorization": f"Bearer {TOKENS['alice']}"})
    assert r.status_code in (409, 502), r.text
    assert "error" in r.json() or r.json().get("status")
    assert engine.store.get(cid).status == "approved"  # nothing claimed, can retry


async def test_non_utf8_auth_header_is_401_not_500(engine):
    async with await _asgi(engine) as c:
        r = await c.get("/guardrail/changes", headers={"Authorization": b"Bearer \xff\xfe"})
    assert r.status_code == 401


async def test_audit_chain_still_valid_after_hardening_paths(engine, ident):
    await test_missing_justification_is_audited(engine, ident)
    assert verify_chain(engine.audit.path).ok


# --------------------------------------------------------------------------- MCP protocol conformance
async def test_write_tools_do_not_advertise_upstream_output_schema(engine):
    """Writes return the gateway's change payload, so the upstream outputSchema must not be advertised:
    spec-compliant clients validate structuredContent against it and would reject every write."""
    from mcp import Client

    async with Client(build_mcp_server(engine, "noc-agent")) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        assert tools["ise__set_fault"].output_schema is None
        assert tools["ise__get_sgacl"].output_schema is not None  # reads pass upstream results through unchanged
        r = await c.call_tool("ise__set_fault", {"fault": "", "guardrail_justification": "lab"})
        assert r.structured_content["status"] == "succeeded"
        r = await c.call_tool("ise__get_sgacl", {"name": "Deny_All"})
        assert not r.is_error


# --------------------------------------------------------------------------- execution must always reach an outcome
async def test_cancel_after_apply_still_verifies_and_records_outcome(engine, ident, monkeypatch):
    """A client disconnect / notifications/cancelled after the upstream write must not skip verify/rollback."""
    import anyio
    import anyio.lowlevel

    cid = await propose(engine, ident)
    engine.approve(ident("alice"), cid)
    real = engine.upstreams.call
    scope = anyio.CancelScope()

    async def apply_then_cancel(tool, args):
        result = await real(tool, args)
        if tool == "ise__update_sgacl":
            scope.cancel()  # the client goes away right after the write landed
        await anyio.lowlevel.checkpoint()  # cancellation is delivered here unless shielded
        return result

    monkeypatch.setattr(engine.upstreams, "call", apply_then_cancel)
    with scope:
        await engine.execute(ident("noc-agent"), cid)
    ch = engine.store.get(cid)
    assert ch.status == "succeeded", ch.status
    assert ch.verify_result["ok"]
    assert engine.audit.tail(1)[0]["event"] == "change.succeeded"


async def test_crash_after_apply_is_recorded_for_a_human(engine, ident, monkeypatch):
    cid = await propose(engine, ident)
    engine.approve(ident("alice"), cid)

    async def bad_verify(spec, ctx):
        raise RuntimeError("bug in verify")

    monkeypatch.setattr(engine, "_verify", bad_verify)
    out = await engine.call(ident("noc-agent"), "guardrail_execute_change", {"change_id": cid})
    assert out.result.is_error
    ch = engine.store.get(cid)
    assert ch.status == "rollback_failed" and "manual verification required" in ch.status_reason
    events = [r["event"] for r in engine.audit.tail(3)]
    assert "change.execute_crashed" in events


async def test_refused_control_actions_are_audited(engine, ident):
    cid = await propose(engine, ident)
    with pytest.raises(GuardrailDenied):
        engine.approve(ident("noc-agent"), cid)  # agent may not approve
    assert engine.audit.tail(1)[0]["event"] == "change.approve_denied"
    with pytest.raises(GuardrailDenied):
        await engine.execute(ident("noc-agent"), cid)  # not approved yet
    assert engine.audit.tail(1)[0]["event"] == "change.execute_denied"
    with pytest.raises(GuardrailDenied):
        engine.reject(ident("viewer-bot"), cid, "nope")
    assert engine.audit.tail(1)[0]["event"] == "change.reject_denied"


async def test_approve_racing_reject_is_denied_not_crash(engine, ident, monkeypatch):
    cid = await propose(engine, ident)
    real_get = engine.store.get

    def get_then_reject_elsewhere(change_id):
        ch = real_get(change_id)
        other = real_get(change_id)
        engine.store.transition(other, "rejected", "rejected by another process")
        return ch

    monkeypatch.setattr(engine.store, "get", get_then_reject_elsewhere)
    with pytest.raises(GuardrailDenied, match="concurrently"):
        engine.approve(ident("alice"), cid)


async def test_args_rechecked_on_claimed_row(engine, ident, monkeypatch):
    cid = await propose(engine, ident)
    engine.approve(ident("alice"), cid)
    real_claim = engine.store.claim_for_execution

    def claim_tampered(change_id):
        ch = real_claim(change_id)
        ch.args["aclcontent"] = "permit ip"  # row edited between the pre-check and the claim
        return ch

    monkeypatch.setattr(engine.store, "claim_for_execution", claim_tampered)
    out = await engine.execute(ident("noc-agent"), cid)
    assert out.result.structured_content["status"] == "failed"
    assert "modified" in out.result.structured_content["reason"]


async def test_oversized_reason_refused(engine, ident):
    cid = await propose(engine, ident)
    with pytest.raises(GuardrailDenied, match="too long"):
        engine.reject(ident("noc-agent"), cid, "r" * 5000)


def test_audit_tail_scan_is_linear(tmp_path):
    import time

    from guardrail_gateway.audit import AuditLog

    log = AuditLog(tmp_path / "a.jsonl")
    log.write("big", blob="x" * 8_000_000)
    t = time.perf_counter()
    log.write("next")
    assert time.perf_counter() - t < 1.0
    assert verify_chain(tmp_path / "a.jsonl").ok


def test_ttl_must_be_positive(tmp_path):
    with pytest.raises(ConfigError):
        parse_config(base_config(tmp_path, approvals={"change_ttl_minutes": 0}))


async def test_websocket_scope_refused(engine):
    app = build_http_app(engine, build_mcp_server(engine))
    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "websocket.connect"}

    await app({"type": "websocket", "path": "/mcp", "headers": []}, receive, send)
    assert sent == [{"type": "websocket.close", "code": 1008}]


async def test_hung_upstream_hits_execution_deadline(engine, ident, monkeypatch):
    import anyio

    cid = await propose(engine, ident)
    engine.approve(ident("alice"), cid)
    real = engine.upstreams.call

    async def hang_on_apply(tool, args):
        if tool == "ise__update_sgacl":
            await anyio.sleep_forever()
        return await real(tool, args)

    monkeypatch.setattr(engine.upstreams, "call", hang_on_apply)
    monkeypatch.setattr(engine, "_execution_deadline", lambda tool: 0.3)
    with anyio.fail_after(5):
        out = await engine.execute(ident("noc-agent"), cid)
    assert out.result.is_error
    ch = engine.store.get(cid)
    assert ch.status == "rollback_failed", ch.status  # device state unknown: a human must look
    assert any(r["event"] == "change.execute_crashed" for r in engine.audit.tail(3))


async def test_native_asyncio_cancel_after_apply_is_recorded(engine, ident, monkeypatch):
    """Ctrl-C under anyio.run cancels the main task with task.cancel(), which bypasses anyio shields."""
    import asyncio

    cid = await propose(engine, ident)
    engine.approve(ident("alice"), cid)
    real = engine.upstreams.call

    async def apply_then_ctrl_c(tool, args):
        result = await real(tool, args)
        if tool == "ise__update_sgacl":
            asyncio.current_task().cancel()
            await asyncio.sleep(0)
        return result

    monkeypatch.setattr(engine.upstreams, "call", apply_then_ctrl_c)
    task = asyncio.ensure_future(engine.execute(ident("noc-agent"), cid))
    with pytest.raises(asyncio.CancelledError):
        await task
    ch = engine.store.get(cid)
    assert ch.status == "rollback_failed", ch.status  # the write landed but was never verified
    assert "device state unknown" in ch.status_reason
    assert any(r["event"] == "change.execute_crashed" for r in engine.audit.tail(3))


async def test_denied_change_id_is_truncated_in_audit(engine, ident):
    with pytest.raises(GuardrailDenied):
        engine.approve(ident("noc-agent"), "X" * 100_000)
    rec = engine.audit.tail(1)[0]
    assert rec["event"] == "change.approve_denied" and len(rec["change_id"]) <= 64


# --------------------------------------------------------------------------- hidden tools, approver separation, recovery
async def test_hidden_tool_is_indistinguishable_from_missing(engine, ident):
    hidden = await engine.call(ident("viewer-bot"), "ise__delete_sgacl", {"name": "X", "guardrail_justification": "x"})
    missing = await engine.call(ident("viewer-bot"), "ise__does_not_exist", {})
    assert hidden.result.structured_content["error"] == "unknown tool 'ise__delete_sgacl'"
    assert missing.result.structured_content["error"] == "unknown tool 'ise__does_not_exist'"


def test_identity_cannot_both_write_and_approve(tmp_path):
    raw = base_config(tmp_path)
    raw["identities"].append({"id": "both", "roles": ["agent", "approver"]})
    with pytest.raises(ConfigError, match="propose write changes and approve"):
        parse_config(raw)
    raw["approvals"] = {"allow_writer_approvers": True}
    assert parse_config(raw).identity("both") is not None


async def _stuck_change(engine, ident, age_seconds):
    from datetime import timedelta

    from guardrail_gateway.store import utcnow

    cid = await propose(engine, ident)
    engine.approve(ident("alice"), cid)
    ch = engine.store.claim_for_execution(cid)  # simulate a gateway killed right after the claim
    ch.updated_at = (utcnow() - timedelta(seconds=age_seconds)).isoformat(timespec="seconds")
    engine.store._write(ch)  # bypass save() so updated_at keeps the simulated age
    return cid


async def test_recover_stale_executing_change(engine, ident):
    cid = await _stuck_change(engine, ident, age_seconds=10_000)
    with pytest.raises(GuardrailDenied, match="cannot recover"):
        engine.recover(ident("noc-agent"), cid, "agent tries")
    ch = engine.recover(ident("alice"), cid, "gateway host rebooted")
    assert ch.status == "rollback_failed" and "verify the device" in ch.status_reason
    assert engine.audit.tail(1)[0]["event"] == "change.recovered"
    with pytest.raises(GuardrailDenied, match="only 'executing'"):
        engine.recover(ident("alice"), cid, "again")


async def test_recover_refuses_possibly_running_change(engine, ident):
    cid = await _stuck_change(engine, ident, age_seconds=5)
    with pytest.raises(GuardrailDenied, match="may still be running"):
        engine.recover(ident("alice"), cid, "too eager")
    assert engine.store.get(cid).status == "executing"


# --------------------------------------------------------------------------- round 4: cross-process deadline, leaks, tokens
def test_execution_deadline_is_config_only_and_covers_rule_tools(tmp_path):
    """The CLI's offline engine (no upstream catalog) must compute the same deadline as the server."""
    from guardrail_gateway.cli import _offline_engine

    raw = base_config(tmp_path)
    raw["upstreams"] = {
        "ise": {"transport": "stdio", "command": "x", "timeout_seconds": 300},
        "verifier": {"transport": "stdio", "command": "x", "timeout_seconds": 500},
    }
    raw["rules"][0]["verify"]["tool"] = "verifier__get_sgacl"
    offline = _offline_engine(parse_config(raw))
    assert offline._execution_deadline("ise__update_sgacl") == 4 * 500 + 30


async def test_hidden_and_missing_tools_leave_the_same_audit_trace(engine, ident):
    seq0 = engine.audit.tail(1)[0]["seq"]
    await engine.call(ident("viewer-bot"), "ise__delete_sgacl", {"name": "X"})
    hidden = engine.audit.tail(1)[0]
    await engine.call(ident("viewer-bot"), "ise__nope", {})
    missing = engine.audit.tail(1)[0]
    assert (hidden["seq"], missing["seq"]) == (seq0 + 1, seq0 + 2)  # each call leaves exactly one record
    assert hidden["event"] == missing["event"] == "call.denied"
    assert set(hidden) == set(missing)


async def test_change_records_scoped_to_requester_unless_approver(engine, ident):
    cid = await propose(engine, ident)
    viewer = await engine.call(ident("viewer-bot"), "guardrail_list_changes", {})
    assert viewer.result.structured_content["changes"] == []
    detail = await engine.call(ident("viewer-bot"), "guardrail_get_change", {"change_id": cid})
    assert detail.result.is_error and "not found" in detail.result.structured_content["error"]
    mine = await engine.call(ident("noc-agent"), "guardrail_list_changes", {})
    assert [c["id"] for c in mine.result.structured_content["changes"]] == [cid]
    approver = await engine.call(ident("alice"), "guardrail_get_change", {"change_id": cid})
    assert approver.result.structured_content["id"] == cid
    status = await engine.call(ident("viewer-bot"), "guardrail_status", {})
    assert "tools" not in status.result.structured_content["upstreams"]["ise"]


async def test_approver_may_explain_tools_it_reviews(engine, ident):
    out = await engine.call(ident("alice"), "guardrail_explain_tool", {"tool": "ise__update_sgacl", "arguments": {}})
    assert not out.result.is_error and out.result.structured_content["class"] == "write"


def test_duplicate_tokens_rejected(tmp_path):
    raw = base_config(tmp_path)
    raw["identities"][2]["token_sha256"] = raw["identities"][0]["token_sha256"]  # alice shares the agent's token
    with pytest.raises(ConfigError, match="share a token"):
        parse_config(raw)


async def test_apply_that_raises_is_verified_not_assumed_failed(engine, ident, monkeypatch):
    """A write that times out may still have landed: verify decides, never a blind 'failed'."""
    cid = await propose(engine, ident)
    engine.approve(ident("alice"), cid)
    real = engine.upstreams.call

    async def commit_then_timeout(tool, args):
        result = await real(tool, args)
        if tool == "ise__update_sgacl" and args.get("aclcontent") == WEB:
            raise TimeoutError("read timed out after commit")
        return result

    monkeypatch.setattr(engine.upstreams, "call", commit_then_timeout)
    out = await engine.execute(ident("noc-agent"), cid)
    data = out.result.structured_content
    assert data["status"] == "succeeded", data
    assert "raised" in data["reason"]


def test_rollback_requires_snapshot_and_verify_requires_expectations(tmp_path):
    raw = base_config(tmp_path)
    del raw["rules"][0]["snapshot"]
    with pytest.raises(ConfigError, match="rollback needs a snapshot"):
        parse_config(raw)
    raw = base_config(tmp_path)
    raw["rules"][0]["verify"]["expect_json"] = {}
    with pytest.raises(ConfigError, match="at least one expectation"):
        parse_config(raw)


async def test_foreign_change_ids_cannot_be_probed(engine, ident):
    cid = await propose(engine, ident)
    for tool, extra in (("guardrail_execute_change", {}), ("guardrail_cancel_change", {"reason": "x"})):
        real = await engine.call(ident("viewer-bot"), tool, {"change_id": cid, **extra})
        fake = await engine.call(ident("viewer-bot"), tool, {"change_id": "CHG-20000101-000000", **extra})
        assert real.result.structured_content["error"].replace(cid, "ID") == fake.result.structured_content["error"].replace(
            "CHG-20000101-000000", "ID"
        )
    status = await engine.call(ident("viewer-bot"), "guardrail_status", {})
    assert status.result.structured_content["pending_changes"] == 0
