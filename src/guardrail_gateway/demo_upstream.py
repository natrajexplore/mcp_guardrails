"""A small in-memory 'lab ISE' MCP server used by the quick-start demo and the test suite.

It models TrustSec SGACLs so the full guardrail flow (preview, approval,
snapshot, verify, rollback) can be exercised without a real ISE node.
Set LAB_FAULT=corrupt_once (next update only) or corrupt (every update) to make
updates store the wrong content, which makes verification fail and demonstrates
automatic rollback (and, with 'corrupt', a failed rollback that needs a human).
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

READ = ToolAnnotations(read_only_hint=True)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True)
DESTROY = ToolAnnotations(read_only_hint=False, destructive_hint=True)


def build_lab_server(fault: str | None = None) -> MCPServer:
    state: dict[str, dict[str, Any]] = {
        "Permit_Web": {"name": "Permit_Web", "aclcontent": "permit tcp dst eq 443\npermit tcp dst eq 80\ndeny ip"},
        "Deny_All": {"name": "Deny_All", "aclcontent": "deny ip log"},
    }
    mode = {"fault": fault if fault is not None else os.environ.get("LAB_FAULT", "")}
    server = MCPServer("lab-ise", instructions="Simulated Cisco ISE TrustSec SGACL API for demos and tests.")

    @server.tool(annotations=READ)
    def list_sgacls() -> list[str]:
        """List SGACL names."""
        return sorted(state)

    @server.tool(annotations=READ)
    def get_sgacl(name: str) -> dict[str, Any]:
        """Get one SGACL by name, including its ACE content."""
        if name not in state:
            raise ValueError(f"SGACL {name} not found")
        return dict(state[name])

    @server.tool(annotations=WRITE)
    def update_sgacl(name: str, aclcontent: str) -> dict[str, Any]:
        """Create or replace the ACE content of an SGACL."""
        stored = aclcontent
        if mode["fault"] in ("corrupt", "corrupt_once"):
            stored = aclcontent + "\npermit ip"
            if mode["fault"] == "corrupt_once":
                mode["fault"] = ""
        state[name] = {"name": name, "aclcontent": stored}
        return {"updated": name}

    @server.tool(annotations=DESTROY)
    def delete_sgacl(name: str) -> dict[str, Any]:
        """Delete an SGACL."""
        state.pop(name, None)
        return {"deleted": name}

    @server.tool(annotations=WRITE)
    def set_fault(fault: str) -> str:
        """Lab only: set fault injection mode: '', 'corrupt_once' or 'corrupt'."""
        mode["fault"] = fault
        return f"fault={fault!r}"

    return server


def main() -> None:  # pragma: no cover
    build_lab_server().run("stdio")


if __name__ == "__main__":  # pragma: no cover
    main()
