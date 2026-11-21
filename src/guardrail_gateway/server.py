"""MCP server front-end (stdio and Streamable HTTP) plus the human approval REST API."""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import __version__
from .audit import AuditLog, verify_chain
from .config import GatewayConfig, IdentityConfig
from .engine import CallOutcome, GuardrailDenied, GuardrailEngine
from .notify import Notifier
from .store import ChangeStore, TransitionError
from .upstreams import UpstreamError, UpstreamManager

log = logging.getLogger("guardrail.server")
IDENTITY_KEY = "guardrail_identity"
PUBLIC_PATHS = {"/healthz"}

INSTRUCTIONS = """\
This is an MCP Guardrail Gateway in front of Cisco network/security MCP servers.
Tools are namespaced as <upstream>__<tool>. Read-only tools run immediately.
Write and destructive tools DO NOT run immediately: they return a change_id and
wait for human approval. Always pass guardrail_justification on writes. Use
guardrail_explain_tool to check risk and approvals before proposing a change,
and guardrail_execute_change once a change is approved. Never retry a denied
change with altered arguments to get around a policy constraint."""


def build_engine(config: GatewayConfig, upstreams: UpstreamManager) -> GuardrailEngine:
    store = ChangeStore(config.storage.database)
    audit = AuditLog.from_env(config.storage.audit_log, config.storage.audit_hmac_key_env)
    notifier = Notifier(config.notifications)
    audit.add_sink(notifier.audit_sink)
    return GuardrailEngine(config, upstreams, store, audit, notifier)


def build_mcp_server(engine: GuardrailEngine, stdio_identity: str | None = None) -> Server[Any]:
    def caller(ctx: Any) -> IdentityConfig:
        ident_id = None
        request = getattr(ctx, "request", None)
        if request is not None:
            ident_id = request.scope.get("state", {}).get(IDENTITY_KEY)
        else:
            ident_id = stdio_identity
        ident = engine.identity(ident_id)
        if ident is None:
            raise GuardrailDenied("caller is not authenticated")
        return ident

    async def on_list_tools(ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
        try:
            ident = caller(ctx)
        except GuardrailDenied:
            return types.ListToolsResult(tools=[])
        return types.ListToolsResult(tools=engine.visible_tools(ident))

    async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        try:
            ident = caller(ctx)
        except GuardrailDenied as exc:
            return CallOutcome.error(str(exc)).result
        outcome = await engine.call(ident, params.name, params.arguments)
        return outcome.result

    return Server(
        engine.config.server.name,
        version=__version__,
        instructions=INSTRUCTIONS,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


# ----------------------------------------------------------------------------- HTTP


class BearerAuthMiddleware:
    """Authenticates every non-public request with a bearer token mapped to a configured identity."""

    def __init__(self, app: Any, engine: GuardrailEngine) -> None:
        self.app = app
        self.engine = engine

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan" or (scope["type"] == "http" and scope.get("path") in PUBLIC_PATHS):
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":  # no websocket (or unknown) surface: refuse before routing
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        # latin-1 decodes any byte sequence, so malformed headers yield 401 instead of a 500
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        ident = None
        if auth.lower().startswith("bearer "):
            ident = self.engine.authenticate_token(auth[7:].strip())
        if ident is None:
            resp = JSONResponse(
                {"error": "invalid or missing bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="mcp-guardrail-gateway"'},
            )
            await resp(scope, receive, send)
            return
        scope.setdefault("state", {})[IDENTITY_KEY] = ident.id
        await self.app(scope, receive, send)


class _BadBody(ValueError):
    """The REST body parsed as JSON but is not an object."""


def _ident(request: Request, engine: GuardrailEngine) -> IdentityConfig:
    ident = engine.identity(request.scope.get("state", {}).get(IDENTITY_KEY))
    if ident is None:
        raise GuardrailDenied("not authenticated")
    return ident


def rest_routes(engine: GuardrailEngine) -> list[Route]:
    def guarded(fn: Any) -> Any:
        async def handler(request: Request) -> JSONResponse:
            try:
                return await fn(request, _ident(request, engine))
            except GuardrailDenied as exc:
                return JSONResponse({"error": str(exc)}, status_code=403)
            except (json.JSONDecodeError, UnicodeDecodeError, _BadBody):
                return JSONResponse({"error": "body must be a JSON object"}, status_code=400)
            except TransitionError as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            except UpstreamError as exc:
                _audit_rest_error(request, str(exc)[:500])
                return JSONResponse({"error": f"upstream error: {exc}"}, status_code=502)
            except Exception as exc:
                log.exception("REST %s failed", request.url.path)
                _audit_rest_error(request, type(exc).__name__)
                return JSONResponse({"error": "internal gateway error; the event was logged"}, status_code=500)

        return handler

    def _audit_rest_error(request: Request, error: str) -> None:
        try:
            ident_id = request.scope.get("state", {}).get(IDENTITY_KEY)
            engine.audit.write("rest.error", identity=ident_id, path=request.url.path[:200], error=error)
        except Exception:
            log.exception("could not audit REST error")

    async def body(request: Request) -> dict[str, Any]:
        raw = await request.body()
        data = json.loads(raw) if raw else {}
        if not isinstance(data, dict):
            raise _BadBody
        return data

    async def healthz(request: Request) -> JSONResponse:
        # Unauthenticated: liveness only. Upstream error strings can carry internal hostnames/URLs;
        # authenticated callers get the full detail from guardrail_status.
        ups = {name: {"connected": s["connected"]} for name, s in engine.upstreams.status().items()}
        return JSONResponse({"status": "ok", "version": __version__, "upstreams": ups})

    async def list_changes(request: Request, ident: IdentityConfig) -> JSONResponse:
        status = request.query_params.get("status")
        return JSONResponse({"changes": [c.summary() for c in engine.changes_for(ident, status)]})

    async def get_change(request: Request, ident: IdentityConfig) -> JSONResponse:
        try:
            return JSONResponse(engine.change_detail(ident, request.path_params["change_id"]))
        except GuardrailDenied as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)

    async def approve(request: Request, ident: IdentityConfig) -> JSONResponse:
        b = await body(request)
        ch = engine.approve(ident, request.path_params["change_id"], str(b.get("comment", "")), channel="rest")
        return JSONResponse(ch.summary())

    async def reject(request: Request, ident: IdentityConfig) -> JSONResponse:
        b = await body(request)
        ch = engine.reject(ident, request.path_params["change_id"], str(b.get("reason", "rejected via REST")), "rest")
        return JSONResponse(ch.summary())

    async def execute(request: Request, ident: IdentityConfig) -> JSONResponse:
        outcome = await engine.execute(ident, request.path_params["change_id"])
        status = 200 if not outcome.result.is_error else 409
        return JSONResponse(outcome.result.structured_content, status_code=status)

    async def audit_verify(request: Request, ident: IdentityConfig) -> JSONResponse:
        res = verify_chain(engine.audit.path, engine.audit.key)
        return JSONResponse(res.__dict__, status_code=200 if res.ok else 500)

    return [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/guardrail/changes", guarded(list_changes), methods=["GET"]),
        Route("/guardrail/changes/{change_id}", guarded(get_change), methods=["GET"]),
        Route("/guardrail/changes/{change_id}/approve", guarded(approve), methods=["POST"]),
        Route("/guardrail/changes/{change_id}/reject", guarded(reject), methods=["POST"]),
        Route("/guardrail/changes/{change_id}/execute", guarded(execute), methods=["POST"]),
        Route("/guardrail/audit/verify", guarded(audit_verify), methods=["GET"]),
    ]


def build_http_app(engine: GuardrailEngine, server: Server[Any]) -> Any:
    cfg = engine.config.server
    security = None
    if cfg.allowed_hosts:
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=cfg.allowed_hosts,
            allowed_origins=[f"http://{h}" for h in cfg.allowed_hosts] + [f"https://{h}" for h in cfg.allowed_hosts],
        )
    app = server.streamable_http_app(
        streamable_http_path=cfg.path,
        host=cfg.host,
        transport_security=security,
        custom_starlette_routes=rest_routes(engine),
    )
    return BearerAuthMiddleware(app, engine)


@contextlib.asynccontextmanager
async def running_engine(config: GatewayConfig, targets: dict[str, Any] | None = None) -> AsyncIterator[GuardrailEngine]:
    async with UpstreamManager(config.upstreams, targets) as upstreams:
        engine = build_engine(config, upstreams)
        await engine.notifier.start()
        engine.audit.write("gateway.start", version=__version__, upstreams=upstreams.status())
        try:
            yield engine
        finally:
            engine.audit.write("gateway.stop")
            await engine.notifier.stop()
            engine.store.close()


async def serve_stdio(config: GatewayConfig) -> None:
    if not config.server.stdio_identity:
        raise SystemExit("stdio mode needs server.stdio_identity in the config")
    async with running_engine(config) as engine:
        server = build_mcp_server(engine, config.server.stdio_identity)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())


async def serve_http(config: GatewayConfig) -> None:
    import uvicorn

    async with running_engine(config) as engine:
        server = build_mcp_server(engine)
        app = build_http_app(engine, server)
        uv = uvicorn.Server(uvicorn.Config(app, host=config.server.host, port=config.server.port, log_level="info"))
        await uv.serve()


def run(config: GatewayConfig, transport: str) -> None:
    anyio.run(serve_stdio if transport == "stdio" else serve_http, config)
