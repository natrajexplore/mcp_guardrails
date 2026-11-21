# Connecting MCP clients to the gateway

Each agent gets its own identity and token (`guardrail token new`). Only the SHA-256 goes into the gateway config.

## VS Code (GitHub Copilot agent mode): `.vscode/mcp.json`
```json
{
  "inputs": [{ "id": "guardrail-token", "type": "promptString", "description": "Guardrail token", "password": true }],
  "servers": {
    "guardrail": {
      "type": "http",
      "url": "https://guardrail.example.com/mcp",
      "headers": { "Authorization": "Bearer ${input:guardrail-token}" }
    }
  }
}
```

## Claude Desktop / any stdio client
Run the gateway itself as the stdio server. It launches the upstreams and acts as `server.stdio_identity`:
```json
{
  "mcpServers": {
    "cisco-guarded": {
      "command": "guardrail",
      "args": ["serve", "-t", "stdio", "-c", "/etc/guardrail/gateway.yaml"],
      "env": { "GUARDRAIL_AUDIT_HMAC_KEY": "<from your secret manager>" }
    }
  }
}
```

## Python (MCP SDK 2.x)
```python
import anyio, httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

async def main():
    async with httpx2.AsyncClient(headers={"Authorization": "Bearer <token>"}) as http:
        async with Client(streamable_http_client("http://127.0.0.1:8080/mcp", http_client=http)) as c:
            print(await c.call_tool("guardrail_explain_tool", {"tool": "ise__update_sgacl",
                                                               "arguments": {"name": "Permit_Web", "aclcontent": "deny ip"}}))
anyio.run(main)
```
