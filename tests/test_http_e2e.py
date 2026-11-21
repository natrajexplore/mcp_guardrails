"""End-to-end over real transports: Streamable HTTP with bearer auth + REST approvals, and stdio subprocesses."""

from __future__ import annotations

import socket
import sys

import anyio
import httpx2
import uvicorn
import yaml
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from guardrail_gateway.config import parse_config
from guardrail_gateway.demo_upstream import build_lab_server
from guardrail_gateway.server import build_http_app, build_mcp_server, running_engine

from .conftest import TOKENS, base_config


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def test_http_auth_rest_approval_and_execute(tmp_path):
    port = free_port()
    cfg = parse_config(base_config(tmp_path))
    async with running_engine(cfg, targets={"ise": build_lab_server(fault="")}) as engine:
        app = build_http_app(engine, build_mcp_server(engine))
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        base = f"http://127.0.0.1:{port}"
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.serve)
            for _ in range(50):
                if server.started:
                    break
                await anyio.sleep(0.05)
            async with httpx2.AsyncClient() as raw:
                assert (await raw.get(f"{base}/healthz")).status_code == 200
                assert (await raw.post(f"{base}/mcp", json={})).status_code == 401
                assert (await raw.get(f"{base}/guardrail/changes", headers={"Authorization": "Bearer wrong"})).status_code == 401

            async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {TOKENS['noc-agent']}"}) as hc:
                async with Client(streamable_http_client(f"{base}/mcp", http_client=hc)) as agent:
                    names = {t.name for t in (await agent.list_tools()).tools}
                    assert {"ise__get_sgacl", "ise__update_sgacl", "guardrail_execute_change"} <= names
                    assert "guardrail_approve_change" not in names
                    who = await agent.call_tool("guardrail_whoami", {})
                    assert who.structured_content["identity"] == "noc-agent"
                    res = await agent.call_tool(
                        "ise__update_sgacl",
                        {
                            "name": "Permit_Web",
                            "aclcontent": "permit tcp dst eq 443\ndeny ip",
                            "guardrail_justification": "CHG ticket 42",
                        },
                    )
                    cid = res.structured_content["change_id"]

                    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {TOKENS['alice']}"}) as human:
                        detail = (await human.get(f"{base}/guardrail/changes/{cid}")).json()
                        assert detail["status"] == "pending" and detail["justification"] == "CHG ticket 42"
                        r = await human.post(f"{base}/guardrail/changes/{cid}/approve", json={"comment": "ok"})
                        assert r.status_code == 200 and r.json()["status"] == "approved", r.text

                    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {TOKENS['noc-agent']}"}) as self_ap:
                        r = await self_ap.post(f"{base}/guardrail/changes/{cid}/approve", json={})
                        assert r.status_code == 403

                    done = await agent.call_tool("guardrail_execute_change", {"change_id": cid})
                    assert done.structured_content["status"] == "succeeded", done.structured_content

            async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {TOKENS['viewer-bot']}"}) as hc:
                async with Client(streamable_http_client(f"{base}/mcp", http_client=hc)) as viewer:
                    names = {t.name for t in (await viewer.list_tools()).tools}
                    assert "ise__update_sgacl" not in names and "ise__get_sgacl" in names
                r = await hc.get(f"{base}/guardrail/audit/verify")
                assert r.status_code == 200 and r.json()["ok"]
            server.should_exit = True


async def test_stdio_gateway_with_stdio_upstream(tmp_path):
    raw = base_config(tmp_path)
    raw["upstreams"] = {
        "ise": {
            "transport": "stdio",
            "command": sys.executable,
            "args": ["-m", "guardrail_gateway.demo_upstream"],
            "env": {"LAB_FAULT": ""},
        }
    }
    cfg_path = tmp_path / "gw.yaml"
    cfg_path.write_text(yaml.safe_dump(raw))
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "guardrail_gateway.cli", "serve", "-c", str(cfg_path), "-t", "stdio"]
    )
    async with Client(params) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        assert "ise__delete_sgacl" in tools
        r = await c.call_tool("ise__list_sgacls", {})
        assert "Permit_Web" in " ".join(b.text for b in r.content)
        r = await c.call_tool("ise__delete_sgacl", {"name": "Deny_All", "guardrail_justification": "cleanup"})
        assert r.structured_content["status"] == "approval_required"
        assert r.structured_content["assessment"]["required_approvals"] == 2
