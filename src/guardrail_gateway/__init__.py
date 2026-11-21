"""MCP Guardrail Gateway.

A policy-enforcing MCP proxy that sits between AI agents and Cisco MCP servers
(ISE, Secure Firewall/FMC, Catalyst Center, Meraki, ...). Read calls pass
through with RBAC and audit; write calls become change requests that need
human approval, run inside change windows, are snapshotted before execution,
verified afterwards and rolled back automatically when verification fails.
"""

__version__ = "1.0.0"
