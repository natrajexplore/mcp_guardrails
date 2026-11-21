"""`guardrail` command line: run the gateway, approve changes, verify the audit chain."""

from __future__ import annotations

import getpass
import hashlib
import json
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Annotated, Any

import anyio
import typer

from . import __version__
from .audit import AuditLog, verify_chain
from .config import ConfigError, GatewayConfig, IdentityConfig, load_config
from .engine import GuardrailDenied, GuardrailEngine
from .notify import Notifier
from .store import ChangeStore
from .upstreams import UpstreamManager

app = typer.Typer(
    help="MCP Guardrail Gateway: human-approved, audited write actions for Cisco MCP servers.",
    no_args_is_help=True,
    add_completion=False,
)
changes_app = typer.Typer(help="Review, approve, reject and execute change requests.", no_args_is_help=True)
audit_app = typer.Typer(help="Inspect and verify the tamper-evident audit log.", no_args_is_help=True)
token_app = typer.Typer(help="Create and hash identity bearer tokens.", no_args_is_help=True)
config_app = typer.Typer(help="Validate configuration.", no_args_is_help=True)
for sub, name in ((changes_app, "changes"), (audit_app, "audit"), (token_app, "token"), (config_app, "config")):
    app.add_typer(sub, name=name)

ConfigOpt = Annotated[Path, typer.Option("--config", "-c", envvar="GUARDRAIL_CONFIG", help="Gateway YAML config")]
AsOpt = Annotated[str, typer.Option("--as", help="Your identity id from the config")]


def _load(path: Path) -> GatewayConfig:
    try:
        return load_config(path)
    except ConfigError as exc:
        typer.secho(f"config error: {exc}", fg="red", err=True)
        raise typer.Exit(2) from exc


def _offline_engine(cfg: GatewayConfig) -> GuardrailEngine:
    """Engine bound to the change DB and audit log only (no upstream connections)."""
    store = ChangeStore(cfg.storage.database)
    audit = AuditLog.from_env(cfg.storage.audit_log, cfg.storage.audit_hmac_key_env)
    return GuardrailEngine(cfg, UpstreamManager({}), store, audit, Notifier(cfg.notifications))


def _authenticate(engine: GuardrailEngine, identity_id: str) -> IdentityConfig:
    ident = engine.identity(identity_id)
    if ident is None:
        typer.secho(f"unknown identity '{identity_id}'", fg="red", err=True)
        raise typer.Exit(2)
    token = os.environ.get("GUARDRAIL_TOKEN") or getpass.getpass(f"bearer token for {identity_id}: ")
    match = engine.authenticate_token(token)
    if match is None or match.id != ident.id:
        engine.audit.write("cli.auth_failed", identity=identity_id)
        typer.secho("authentication failed", fg="red", err=True)
        raise typer.Exit(3)
    return ident


def _print(data: Any) -> None:
    typer.echo(json.dumps(data, indent=2, default=str))


@app.callback()
def main(verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


@app.command()
def serve(
    config: ConfigOpt,
    transport: Annotated[str, typer.Option("--transport", "-t", help="http or stdio")] = "http",
) -> None:
    """Run the gateway as an MCP server."""
    from .server import run

    if transport not in ("http", "stdio"):
        raise typer.BadParameter("transport must be http or stdio")
    run(_load(config), transport)


@app.command()
def tools(config: ConfigOpt, as_: AsOpt) -> None:
    """Connect to upstreams and show every tool with its class, risk and approval requirement for an identity."""
    cfg = _load(config)

    async def go() -> None:
        async with UpstreamManager(cfg.upstreams) as ups:
            engine = GuardrailEngine(cfg, ups, ChangeStore(":memory:"), AuditLog(os.devnull), Notifier(cfg.notifications))
            ident = engine.identity(as_)
            if ident is None:
                raise typer.BadParameter(f"unknown identity {as_}")
            rows = []
            for name, ut in sorted(ups.tools.items()):
                a = engine.policy.assess(name, {}, ut.tool.annotations)
                d = engine.policy.authorize(ident, name, a.tool_class, a.risk)
                rows.append(
                    {
                        "tool": name,
                        "class": a.tool_class,
                        "risk": a.risk,
                        "approvals": a.required_approvals,
                        "visible": d.allowed,
                        "rollback": bool(a.rule and a.rule.rollback),
                    }
                )
            _print({"upstreams": ups.status(), "tools": rows})

    anyio.run(go)


# ---------------------------------------------------------------- changes
@changes_app.command("list")
def changes_list(config: ConfigOpt, status: Annotated[str | None, typer.Option()] = None, limit: int = 50) -> None:
    """List change requests."""
    engine = _offline_engine(_load(config))
    rows = [c.summary() for c in engine.store.list(status, limit)]
    if not rows:
        typer.echo("no changes")
    for r in rows:
        typer.echo(f"{r['id']}  {r['status']:<15} {r['risk']:<8} {r['approvals']:<5} {r['tool']}  ({r['requester']})")


@changes_app.command("show")
def changes_show(config: ConfigOpt, change_id: str) -> None:
    """Show full detail for a change."""
    engine = _offline_engine(_load(config))
    ch = engine.store.get(change_id)
    if ch is None:
        typer.secho("not found", fg="red", err=True)
        raise typer.Exit(1)
    from .redact import redact

    data = ch.to_dict()
    data["args"] = redact(data["args"], engine.config.redact_keys)
    _print(data)


@changes_app.command("approve")
def changes_approve(config: ConfigOpt, change_id: str, as_: AsOpt, comment: Annotated[str, typer.Option()] = "") -> None:
    """Approve a pending change (token is read from GUARDRAIL_TOKEN or prompted)."""
    engine = _offline_engine(_load(config))
    ident = _authenticate(engine, as_)
    ch = engine.store.get(change_id)
    if ch is not None:
        from .redact import redact

        typer.echo(f"{ch.id}: {ch.tool} risk={ch.risk} requested by {ch.requester}")
        # json.dumps escapes control characters, so agent text cannot rewrite the terminal (ANSI injection)
        typer.echo(f"justification: {json.dumps(ch.justification, ensure_ascii=True)}")
        typer.echo("arguments: " + json.dumps(redact(ch.args, engine.config.redact_keys), indent=2))
        if os.environ.get("GUARDRAIL_ASSUME_YES") != "1" and sys.stdin.isatty():
            typer.confirm("Approve this change?", abort=True)
    try:
        ch = engine.approve(ident, change_id, comment, channel="cli")
    except GuardrailDenied as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1) from exc
    _print(ch.summary())


@changes_app.command("reject")
def changes_reject(config: ConfigOpt, change_id: str, as_: AsOpt, reason: Annotated[str, typer.Option()] = "rejected") -> None:
    """Reject a change."""
    engine = _offline_engine(_load(config))
    ident = _authenticate(engine, as_)
    try:
        _print(engine.reject(ident, change_id, reason, channel="cli").summary())
    except GuardrailDenied as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1) from exc


@changes_app.command("recover")
def changes_recover(config: ConfigOpt, change_id: str, as_: AsOpt, reason: Annotated[str, typer.Option()]) -> None:
    """Mark a change stuck in 'executing' (gateway killed mid-change) as rollback_failed so a human checks the device."""
    engine = _offline_engine(_load(config))
    ident = _authenticate(engine, as_)
    try:
        _print(engine.recover(ident, change_id, reason).summary())
    except GuardrailDenied as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1) from exc


@changes_app.command("execute")
def changes_execute(config: ConfigOpt, change_id: str, as_: AsOpt) -> None:
    """Execute an approved change from the CLI (connects to upstreams)."""
    cfg = _load(config)
    from .server import running_engine

    async def go() -> None:
        async with running_engine(cfg) as engine:
            ident = _authenticate(engine, as_)
            try:
                outcome = await engine.execute(ident, change_id)
            except GuardrailDenied as exc:
                typer.secho(str(exc), fg="red", err=True)
                raise typer.Exit(1) from exc
            _print(outcome.result.structured_content)
            if outcome.result.is_error:
                raise typer.Exit(1)

    anyio.run(go)


# ---------------------------------------------------------------- audit
@audit_app.command("verify")
def audit_verify(config: ConfigOpt) -> None:
    """Verify the hash chain of the audit log."""
    cfg = _load(config)
    key_env = cfg.storage.audit_hmac_key_env
    key = os.environ.get(key_env).encode() if key_env and os.environ.get(key_env) else None
    res = verify_chain(cfg.storage.audit_log, key)
    typer.secho(res.message, fg="green" if res.ok else "red")
    if not res.ok:
        raise typer.Exit(1)


@audit_app.command("tail")
def audit_tail(config: ConfigOpt, limit: int = 20) -> None:
    """Show the most recent audit records."""
    cfg = _load(config)
    for rec in AuditLog(cfg.storage.audit_log).tail(limit):
        typer.echo(json.dumps(rec, default=str))


# ---------------------------------------------------------------- tokens & config
@token_app.command("new")
def token_new() -> None:
    """Generate a random bearer token and the SHA-256 digest to put in the config."""
    tok = "grg_" + secrets.token_urlsafe(32)
    typer.echo(f"token:        {tok}")
    typer.echo(f"token_sha256: {hashlib.sha256(tok.encode()).hexdigest()}")
    typer.secho("Store the token in a secret manager; only the digest belongs in the config.", fg="yellow")


@token_app.command("hash")
def token_hash(token: Annotated[str, typer.Argument(help="Token to hash ('-' reads stdin)")]) -> None:
    """Print the SHA-256 digest of an existing token."""
    if token == "-":
        token = sys.stdin.readline().strip()
    typer.echo(hashlib.sha256(token.encode()).hexdigest())


@config_app.command("validate")
def config_validate(config: ConfigOpt) -> None:
    """Validate the config and print a policy summary."""
    cfg = _load(config)
    missing = [i.id for i in cfg.identities if not i.token_digest()]
    _print(
        {
            "valid": True,
            "upstreams": {k: v.transport for k, v in cfg.upstreams.items()},
            "roles": list(cfg.roles),
            "identities": [i.id for i in cfg.identities],
            "identities_without_token": missing,
            "rules": [r.match for r in cfg.rules],
            "approval_policy": cfg.approvals.model_dump(),
        }
    )


if __name__ == "__main__":  # pragma: no cover
    app()
