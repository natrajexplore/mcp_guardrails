"""Gateway in front of trustsec-policy-agent (https://github.com/natrajexplore/trustsec-policy-agent).

Skipped when trustsec-policy-agent is not installed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

tsa = pytest.importorskip("trustsec_agent")

from trustsec_agent.ise import FileBackend  # noqa: E402
from trustsec_agent.mcp_server import PolicyContext, build_server  # noqa: E402
from trustsec_agent.models import Matrix  # noqa: E402
from trustsec_agent.sample import enterprise_demo  # noqa: E402

from guardrail_gateway.config import parse_config  # noqa: E402
from guardrail_gateway.server import running_engine  # noqa: E402

from .conftest import base_config  # noqa: E402

EXAMPLE = Path(__file__).parent.parent / "examples" / "gateway-trustsec.yaml"


def tsa_rules() -> list[dict]:
    raw = yaml.safe_load(EXAMPLE.read_text())
    return raw["rules"]


@pytest.fixture
def snapshot(tmp_path):
    p = tmp_path / "matrix.json"
    enterprise_demo().save(p)
    return p


async def test_guarded_trustsec_cell_change(tmp_path, snapshot):
    raw = base_config(tmp_path)
    raw["roles"]["agent"]["allow_tools"] = ["tsa__*"]
    raw["rules"] = tsa_rules()
    cfg = parse_config(raw)
    server = build_server(PolicyContext(FileBackend(snapshot), ttl_seconds=0), enable_writes=True)
    async with running_engine(cfg, targets={"tsa": server}) as eng:
        agent, alice = eng.identity("noc-agent"), eng.identity("alice")

        # reads flow straight through
        r = await eng.call(agent, "tsa__what_if_flow", {"src": "Guests", "dst": "PCI_Servers", "service": "tcp/443"})
        assert json.loads(r.result.content[0].text)["action"] == "permit"

        # a dangerous write is refused outright by policy
        bad = await eng.call(
            agent,
            "tsa__update_matrix_cell",
            {
                "src": "Guests",
                "dst": "PCI_Servers",
                "sgacls": ["Permit_IP"],
                "default_rule": "DENY_IP",
                "guardrail_justification": "test",
            },
        )
        assert bad.result.is_error and "Permit_IP" in bad.result.structured_content["error"]

        # the real fix is held for approval with a preview of the current cell
        res = await eng.call(
            agent,
            "tsa__update_matrix_cell",
            {
                "src": "Guests",
                "dst": "PCI_Servers",
                "sgacls": ["Deny_IP_Log"],
                "default_rule": "DENY_IP",
                "guardrail_justification": "ZT-01: guests must not reach the CDE",
            },
        )
        data = res.result.structured_content
        assert data["status"] == "approval_required"
        assert data["current_state_preview"]["json"]["cell"]["exists"] is False
        assert Matrix.load(snapshot).cell(Matrix.load(snapshot).sgt("Guests"), Matrix.load(snapshot).sgt("PCI_Servers")) is None

        eng.approve(alice, data["change_id"], "matches intent ZT-01")
        done = await eng.execute(agent, data["change_id"])
        assert done.result.structured_content["status"] == "succeeded", done.result.structured_content

        r = await eng.call(agent, "tsa__what_if_flow", {"src": "Guests", "dst": "PCI_Servers", "service": "tcp/443"})
        assert json.loads(r.result.content[0].text)["action"] == "deny"


async def test_rollback_restores_previous_cell(tmp_path, snapshot, monkeypatch):
    raw = base_config(tmp_path)
    raw["roles"]["agent"]["allow_tools"] = ["tsa__*"]
    raw["rules"] = tsa_rules()
    cfg = parse_config(raw)
    backend = FileBackend(snapshot)
    server = build_server(PolicyContext(backend, ttl_seconds=0), enable_writes=True)

    real_set_cell = backend.set_cell
    calls = {"n": 0}

    async def flaky_set_cell(src, dst, sgacls, default_rule, status):
        calls["n"] += 1
        if calls["n"] == 1:  # first write silently applies the wrong SGACL (simulates a bad device/API write)
            return await real_set_cell(src, dst, ["Permit_IP"], default_rule, status)
        return await real_set_cell(src, dst, sgacls, default_rule, status)

    monkeypatch.setattr(backend, "set_cell", flaky_set_cell)
    async with running_engine(cfg, targets={"tsa": server}) as eng:
        agent, alice = eng.identity("noc-agent"), eng.identity("alice")
        res = await eng.call(
            agent,
            "tsa__update_matrix_cell",
            {
                "src": "Employees",
                "dst": "PCI_Servers",
                "sgacls": ["Web_Only"],
                "default_rule": "DENY_IP",
                "guardrail_justification": "tighten",
            },
        )
        cid = res.result.structured_content["change_id"]
        eng.approve(alice, cid)
        out = await eng.execute(agent, cid)
        data = out.result.structured_content
        assert data["status"] == "rolled_back", data
        m = Matrix.load(snapshot)
        cell = m.cell(m.sgt("Employees"), m.sgt("PCI_Servers"))
        assert [m.sgacl_by_id[i].name for i in cell.sgacl_ids] == ["PCI_Allowed"]
