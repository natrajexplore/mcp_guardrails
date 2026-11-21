from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from guardrail_gateway.audit import verify_chain
from guardrail_gateway.config import parse_config
from guardrail_gateway.engine import GuardrailDenied
from guardrail_gateway.server import running_engine

from .conftest import base_config

WEB = "permit tcp dst eq 443\ndeny ip"


async def current(engine, name="Permit_Web"):
    r = await engine.upstreams.call("ise__get_sgacl", {"name": name})
    return json.loads(r.content[0].text)["aclcontent"]


async def propose(engine, ident, content=WEB, name="Permit_Web", who="noc-agent"):
    out = await engine.call(
        ident(who), "ise__update_sgacl", {"name": name, "aclcontent": content, "guardrail_justification": "INC-1234 tighten web"}
    )
    return out.result


async def test_read_passes_through_and_is_audited(engine, ident):
    out = await engine.call(ident("noc-agent"), "ise__get_sgacl", {"name": "Deny_All"})
    assert not out.result.is_error
    assert "deny ip log" in out.result.content[0].text
    assert engine.audit.tail(1)[0]["event"] == "call.read"


async def test_viewer_cannot_see_or_call_writes(engine, ident):
    names = {t.name for t in engine.visible_tools(ident("viewer-bot"))}
    assert "ise__get_sgacl" in names
    assert "ise__update_sgacl" not in names
    res = await propose(engine, ident, who="viewer-bot")
    assert res.is_error and "unknown tool" in res.structured_content["error"]  # hidden == nonexistent
    rec = engine.audit.tail(1)[0]
    assert rec["event"] == "call.denied" and "does not allow write" in rec["reason"]  # real reason is audited


async def test_write_tools_advertise_justification_and_approval(engine, ident):
    tool = next(t for t in engine.visible_tools(ident("noc-agent")) if t.name == "ise__update_sgacl")
    assert "guardrail_justification" in tool.input_schema["required"]
    assert "human approval" in tool.description


async def test_write_is_held_not_applied(engine, ident):
    before = await current(engine)
    res = await propose(engine, ident)
    data = res.structured_content
    assert data["status"] == "approval_required"
    assert data["assessment"]["risk"] == "high"
    assert data["current_state_preview"]["json"]["aclcontent"] == before
    assert await current(engine) == before  # nothing applied


async def test_justification_required(engine, ident):
    out = await engine.call(ident("noc-agent"), "ise__update_sgacl", {"name": "Permit_Web", "aclcontent": WEB})
    assert out.result.is_error and "guardrail_justification" in out.result.structured_content["error"]


async def test_constraint_blocks_permit_ip(engine, ident):
    res = await propose(engine, ident, content="permit ip")
    assert res.is_error and "permit ip" in res.structured_content["error"]
    assert engine.store.list() == []


async def test_escalation_raises_risk(engine, ident):
    res = await propose(engine, ident, name="bad-name!")
    assert res.structured_content["assessment"]["risk"] == "critical"
    assert res.structured_content["assessment"]["required_approvals"] == 2


async def test_full_approve_execute_verify(engine, ident):
    cid = (await propose(engine, ident)).structured_content["change_id"]
    with pytest.raises(GuardrailDenied, match="disabled"):
        engine.approve(ident("alice"), cid, channel="mcp")
    with pytest.raises(GuardrailDenied, match="cannot approve"):
        engine.approve(ident("noc-agent"), cid)
    ch = engine.approve(ident("alice"), cid, "looks right")
    assert ch.status == "approved"
    out = await engine.call(ident("noc-agent"), "guardrail_execute_change", {"change_id": cid})
    assert out.result.structured_content["status"] == "succeeded", out.result.structured_content
    assert await current(engine) == WEB
    stored = engine.store.get(cid)
    assert stored.verify_result["ok"] and stored.snapshot["json"]["aclcontent"].startswith("permit tcp dst eq 443\npermit")
    # cannot run twice
    again = await engine.call(ident("noc-agent"), "guardrail_execute_change", {"change_id": cid})
    assert again.result.is_error


async def test_failed_verification_rolls_back(engine, ident):
    before = await current(engine)
    cid = (await propose(engine, ident)).structured_content["change_id"]
    engine.approve(ident("alice"), cid)
    await engine.upstreams.call("ise__set_fault", {"fault": "corrupt_once"})
    out = await engine.execute(ident("noc-agent"), cid)
    data = out.result.structured_content
    assert data["status"] == "rolled_back", data
    assert "verification failed" in data["reason"]
    assert data["rollback"]["restored_state_matches_snapshot"] is True
    assert await current(engine) == before


async def test_rollback_that_does_not_restore_is_flagged(engine, ident):
    cid = (await propose(engine, ident)).structured_content["change_id"]
    engine.approve(ident("alice"), cid)
    await engine.upstreams.call("ise__set_fault", {"fault": "corrupt"})
    out = await engine.execute(ident("noc-agent"), cid)
    data = out.result.structured_content
    assert data["status"] == "rollback_failed", data
    assert "manual intervention" in data["reason"]
    assert data["rollback"]["restored_state_matches_snapshot"] is False


async def test_state_drift_blocks_execution(engine, ident):
    cid = (await propose(engine, ident)).structured_content["change_id"]
    engine.approve(ident("alice"), cid)
    await engine.upstreams.call("ise__update_sgacl", {"name": "Permit_Web", "aclcontent": "deny ip"})  # out-of-band edit
    out = await engine.execute(ident("noc-agent"), cid)
    assert out.result.structured_content["status"] == "blocked"
    assert "drifted" in out.result.structured_content["reason"]
    assert await current(engine) == "deny ip"


async def test_change_window_blocks(tmp_path, lab, ident):
    cfg = parse_config(
        base_config(tmp_path, change_windows=[{"days": ["sat"], "start": "22:00", "end": "06:00", "tz": "Asia/Kolkata"}])
    )
    async with running_engine(cfg, targets={"ise": lab}) as eng:
        res = await eng.call(
            eng.identity("noc-agent"),
            "ise__update_sgacl",
            {"name": "Permit_Web", "aclcontent": WEB, "guardrail_justification": "x"},
        )
        cid = res.result.structured_content["change_id"]
        eng.approve(eng.identity("alice"), cid)
        eng._now = datetime(2026, 11, 18, 6, 0, tzinfo=UTC)  # Wednesday
        out = await eng.execute(eng.identity("noc-agent"), cid)
        assert out.result.structured_content["status"] == "blocked"
        eng._now = datetime(2026, 11, 21, 18, 0, tzinfo=UTC)  # Sat 23:30 IST
        out = await eng.execute(eng.identity("noc-agent"), cid)
        assert out.result.structured_content["status"] == "succeeded"


async def test_critical_needs_two_distinct_approvers(engine, ident):
    out = await engine.call(
        ident("noc-agent"), "ise__delete_sgacl", {"name": "Deny_All", "guardrail_justification": "decommission"}
    )
    cid = out.result.structured_content["change_id"]
    assert out.result.structured_content["assessment"]["required_approvals"] == 2
    assert engine.approve(ident("alice"), cid).status == "pending"
    with pytest.raises(GuardrailDenied, match="already approved"):
        engine.approve(ident("alice"), cid)
    assert engine.approve(ident("bob"), cid).status == "approved"
    res = await engine.execute(ident("noc-agent"), cid)
    assert res.result.structured_content["status"] == "succeeded"


async def test_low_risk_auto_approved_and_executed(engine, ident):
    out = await engine.call(ident("noc-agent"), "ise__set_fault", {"fault": "", "guardrail_justification": "lab"})
    assert out.result.structured_content["status"] == "succeeded"
    ch = engine.store.list()[0]
    assert ch.approvals[0]["by"] == "policy:auto"


async def test_cancel_by_requester(engine, ident):
    cid = (await propose(engine, ident)).structured_content["change_id"]
    out = await engine.call(ident("noc-agent"), "guardrail_cancel_change", {"change_id": cid, "reason": "wrong SGACL"})
    assert out.result.structured_content["status"] == "rejected"
    with pytest.raises(GuardrailDenied):
        engine.approve(ident("alice"), cid)


async def test_explain_tool(engine, ident):
    out = await engine.call(
        ident("noc-agent"),
        "guardrail_explain_tool",
        {"tool": "ise__update_sgacl", "arguments": {"name": "X", "aclcontent": "permit ip"}},
    )
    d = out.result.structured_content
    assert d["class"] == "write" and d["authorized"] is True and d["violations"]
    hidden = await engine.call(ident("viewer-bot"), "guardrail_explain_tool", {"tool": "ise__update_sgacl"})
    assert hidden.result.is_error and "unknown tool" in hidden.result.structured_content["error"]


async def test_unknown_tool(engine, ident):
    out = await engine.call(ident("noc-agent"), "ise__nope", {})
    assert out.result.is_error and "unknown tool" in out.result.structured_content["error"]


async def test_expired_change(engine, ident):
    cid = (await propose(engine, ident)).structured_content["change_id"]
    ch = engine.store.get(cid)
    ch.expires_at = "2000-01-01T00:00:00+00:00"
    engine.store.save(ch)
    assert engine.store.get(cid).status == "expired"


async def test_audit_chain_and_tamper_detection(engine, ident):
    cid = (await propose(engine, ident)).structured_content["change_id"]
    engine.approve(ident("alice"), cid)
    await engine.execute(ident("noc-agent"), cid)
    res = verify_chain(engine.audit.path)
    assert res.ok and res.records >= 5
    lines = engine.audit.path.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["identity"] = "mallory"
    lines[2] = json.dumps(rec)
    engine.audit.path.write_text("\n".join(lines) + "\n")
    bad = verify_chain(engine.audit.path)
    assert not bad.ok and bad.first_bad_seq == 3


async def test_secrets_redacted_in_audit(engine, ident):
    await engine.call(ident("noc-agent"), "ise__get_sgacl", {"name": "Deny_All", "api_token": "s3cr3t-value"})
    text = engine.audit.path.read_text()
    assert "s3cr3t-value" not in text
    assert "REDACTED" in text
