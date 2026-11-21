"""Connections to the downstream MCP servers and the namespaced tool catalog."""

from __future__ import annotations

import logging
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any

import httpx2
from mcp import Client, types
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from .config import UpstreamConfig

log = logging.getLogger("guardrail.upstreams")
SEP = "__"
DEFAULT_UPSTREAM_TIMEOUT = 60.0  # seconds; in-process targets have no config of their own


@dataclass
class UpstreamTool:
    upstream: str
    name: str  # name on the upstream server
    tool: types.Tool  # original definition

    @property
    def qualified(self) -> str:
        return f"{self.upstream}{SEP}{self.name}"


class UpstreamError(RuntimeError):
    pass


class UpstreamManager:
    """Owns one MCP client session per upstream for the lifetime of the gateway.

    `targets` lets tests (or embedders) pass in-process servers instead of config.
    """

    def __init__(self, configs: dict[str, UpstreamConfig], targets: dict[str, Any] | None = None) -> None:
        self.configs = {k: v for k, v in configs.items() if v.enabled}
        self.targets = targets or {}
        self._stack = AsyncExitStack()
        self._clients: dict[str, Client] = {}
        self.tools: dict[str, UpstreamTool] = {}
        self.errors: dict[str, str] = {}

    async def __aenter__(self) -> UpstreamManager:
        await self._stack.__aenter__()
        names = set(self.configs) | set(self.targets)
        for name in sorted(names):
            await self._connect(name)
        await self.refresh()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._stack.__aexit__(*exc)
        self._clients.clear()

    def _client_for(self, name: str) -> Client:
        if name in self.targets:
            return Client(self.targets[name], read_timeout_seconds=DEFAULT_UPSTREAM_TIMEOUT)
        cfg = self.configs[name]
        if cfg.transport == "stdio":
            params = StdioServerParameters(command=cfg.command or "", args=cfg.args, env=cfg.env or None, cwd=cfg.cwd)
            return Client(params, read_timeout_seconds=cfg.timeout_seconds)
        http = httpx2.AsyncClient(headers=cfg.headers, verify=cfg.verify_tls, timeout=cfg.timeout_seconds)
        self._stack.push_async_callback(http.aclose)
        return Client(streamable_http_client(cfg.url or "", http_client=http), read_timeout_seconds=cfg.timeout_seconds)

    async def _connect(self, name: str) -> None:
        try:
            client = await self._stack.enter_async_context(self._client_for(name))
            self._clients[name] = client
            self.errors.pop(name, None)
            log.info("connected to upstream %s", name)
        except Exception as exc:  # an unreachable upstream must not take the gateway down
            self.errors[name] = f"{type(exc).__name__}: {exc}"
            log.error("upstream %s unavailable: %s", name, exc)

    async def refresh(self) -> dict[str, int]:
        catalog: dict[str, UpstreamTool] = {}
        counts: dict[str, int] = {}
        for name, client in self._clients.items():
            try:
                cursor: str | None = None
                n = 0
                while True:
                    page = await client.list_tools(cursor=cursor, cache_mode="bypass")
                    for t in page.tools:
                        ut = UpstreamTool(name, t.name, t)
                        catalog[ut.qualified] = ut
                        n += 1
                    cursor = page.next_cursor
                    if not cursor:
                        break
                counts[name] = n
            except Exception as exc:
                self.errors[name] = f"list_tools failed: {exc}"
                log.error("listing tools on %s failed: %s", name, exc)
        self.tools = catalog
        return counts

    def resolve(self, qualified: str) -> UpstreamTool:
        tool = self.tools.get(qualified)
        if tool is None:
            raise UpstreamError(f"unknown tool '{qualified}'")
        return tool

    async def call(self, qualified: str, arguments: dict[str, Any]) -> types.CallToolResult:
        tool = self.resolve(qualified)
        client = self._clients.get(tool.upstream)
        if client is None:
            raise UpstreamError(f"upstream '{tool.upstream}' is not connected: {self.errors.get(tool.upstream, '')}")
        return await client.call_tool(tool.name, arguments)

    def status(self) -> dict[str, Any]:
        out = {}
        for name in sorted(set(self.configs) | set(self.targets)):
            out[name] = {
                "connected": name in self._clients,
                "tools": sum(1 for t in self.tools.values() if t.upstream == name),
                "error": self.errors.get(name),
            }
        return out


def result_text(result: types.CallToolResult) -> str:
    parts = []
    for block in result.content:
        text = getattr(block, "text", None)
        if text is not None:
            parts.append(text)
    return "\n".join(parts)


def result_json(result: types.CallToolResult) -> Any:
    """Best-effort structured view of a tool result for templating and verification."""
    import json

    if result.structured_content is not None:
        sc = result.structured_content
        # MCPServer wraps non-object returns as {"result": ...}
        return sc.get("result", sc) if isinstance(sc, dict) and set(sc) == {"result"} else sc
    text = result_text(result)
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None
