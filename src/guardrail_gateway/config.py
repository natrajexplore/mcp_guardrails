"""Gateway configuration: YAML file with ${ENV} interpolation, validated by pydantic."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt, field_validator, model_validator

ToolClass = Literal["read", "write", "destructive"]
RiskLevel = Literal["low", "medium", "high", "critical"]

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(ValueError):
    """Raised when the configuration file is invalid."""


def interpolate_env(value: Any) -> Any:
    """Replace ${VAR} and ${VAR:-default} in every string of a nested structure.

    A reference to an unset variable without a default is an error, so a
    missing secret fails loudly at startup instead of silently becoming "".
    """
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            if name in os.environ:
                return os.environ[name]
            if default is not None:
                return default
            raise ConfigError(f"environment variable {name} is not set (referenced in config)")

        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, list):
        return [interpolate_env(v) for v in value]
    if isinstance(value, dict):
        return {k: interpolate_env(v) for k, v in value.items()}
    return value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UpstreamConfig(_Strict):
    """One downstream MCP server the gateway fronts."""

    transport: Literal["stdio", "http"]
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = True
    timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    enabled: bool = True

    @model_validator(mode="after")
    def _check_transport(self) -> UpstreamConfig:
        if self.transport == "stdio" and not self.command:
            raise ValueError("stdio upstream requires 'command'")
        if self.transport == "http" and not self.url:
            raise ValueError("http upstream requires 'url'")
        return self


class RoleConfig(_Strict):
    """What an identity holding this role may do."""

    allow_tools: list[str] = Field(default_factory=lambda: ["*"])
    deny_tools: list[str] = Field(default_factory=list)
    classes: list[ToolClass] = Field(default_factory=lambda: ["read"])
    can_approve: bool = False
    can_execute: bool = True
    max_risk: RiskLevel = "critical"


class IdentityConfig(_Strict):
    """A caller of the gateway, authenticated by a bearer token over HTTP."""

    id: str
    roles: list[str]
    token_sha256: str | None = None
    token_env: str | None = None
    description: str = ""

    @field_validator("token_sha256")
    @classmethod
    def _hex64(cls, v: str | None) -> str | None:
        if v is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", v):
            raise ValueError("token_sha256 must be a 64-char hex SHA-256 digest")
        return v.lower() if v else v

    def token_digest(self) -> str | None:
        if self.token_sha256:
            return self.token_sha256
        if self.token_env:
            raw = os.environ.get(self.token_env)
            if raw:
                return hashlib.sha256(raw.encode()).hexdigest()
        return None


class CallSpec(_Strict):
    """A templated call to an upstream tool (snapshot / verify / rollback)."""

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class VerifySpec(CallSpec):
    expect_contains: list[str] = Field(default_factory=list)
    expect_not_contains: list[str] = Field(default_factory=list)
    expect_json: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _has_expectation(self) -> VerifySpec:
        if not (self.expect_contains or self.expect_not_contains or self.expect_json):
            raise ValueError("verify needs at least one expectation (expect_contains, expect_not_contains or expect_json)")
        return self


class ConstraintConfig(_Strict):
    """Argument-level guardrail evaluated before a change is accepted."""

    arg: str
    deny_regex: str | None = None
    allow_regex: str | None = None
    allowed_values: list[Any] | None = None
    max_length: int | None = None
    message: str = ""
    effect: Literal["deny", "escalate"] = "deny"

    @field_validator("deny_regex", "allow_regex")
    @classmethod
    def _compiles(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                re.compile(v)
            except re.error as exc:
                raise ValueError(f"invalid regex {v!r}: {exc}") from exc
        return v


class ChangeWindow(_Strict):
    """Execution window, e.g. Sat-Sun 22:00-06:00 in Asia/Kolkata."""

    days: list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]]
    start: str
    end: str
    tz: str = "UTC"

    @field_validator("start", "end")
    @classmethod
    def _hhmm(cls, v: str) -> str:
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
            raise ValueError("time must be HH:MM (24h)")
        return v

    @field_validator("tz")
    @classmethod
    def _tz(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown time zone {v!r} (use an IANA name such as 'Asia/Kolkata')") from exc
        return v


class RuleConfig(_Strict):
    """Per-tool policy. 'match' is a glob over the namespaced tool name."""

    match: str
    tool_class: ToolClass | None = Field(default=None, alias="class")
    risk: RiskLevel | None = None
    require_approvals: int | None = Field(default=None, ge=0)
    snapshot: CallSpec | None = None
    verify: VerifySpec | None = None
    rollback: CallSpec | None = None
    constraints: list[ConstraintConfig] = Field(default_factory=list)
    change_windows: list[ChangeWindow] | None = None
    description: str = ""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @model_validator(mode="after")
    def _rollback_needs_snapshot(self) -> RuleConfig:
        if self.rollback and not self.snapshot:
            raise ValueError(f"rule {self.match!r}: rollback needs a snapshot (to restore from and to confirm the restore)")
        return self


class ApprovalPolicy(_Strict):
    by_risk: dict[RiskLevel, NonNegativeInt] = Field(default_factory=lambda: {"low": 0, "medium": 1, "high": 1, "critical": 2})
    allow_self_approval: bool = False
    allow_mcp_approval: bool = False
    allow_writer_approvers: bool = False
    change_ttl_minutes: int = Field(default=240, ge=1)
    require_justification: bool = True
    block_on_state_drift: bool = True


class RateLimitConfig(_Strict):
    writes_per_minute: int = Field(default=10, ge=0)
    reads_per_minute: int = Field(default=300, ge=0)


class WebexConfig(_Strict):
    bot_token: str
    room_id: str
    api_url: str = "https://webexapis.com/v1/messages"


class SplunkHecConfig(_Strict):
    url: str
    token: str
    index: str | None = None
    sourcetype: str = "mcp:guardrail:audit"
    verify_tls: bool = True


class WebhookConfig(_Strict):
    url: str
    headers: dict[str, str] = Field(default_factory=dict)


class NotificationConfig(_Strict):
    webex: WebexConfig | None = None
    splunk_hec: SplunkHecConfig | None = None
    webhooks: list[WebhookConfig] = Field(default_factory=list)
    public_url: str | None = None


class ServerConfig(_Strict):
    name: str = "mcp-guardrail-gateway"
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    path: str = "/mcp"
    stdio_identity: str | None = None
    allowed_hosts: list[str] = Field(default_factory=list)


class StorageConfig(_Strict):
    database: str = "./guardrail-data/changes.db"
    audit_log: str = "./guardrail-data/audit.jsonl"
    audit_hmac_key_env: str | None = "GUARDRAIL_AUDIT_HMAC_KEY"


class GatewayConfig(_Strict):
    server: ServerConfig = Field(default_factory=ServerConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    upstreams: dict[str, UpstreamConfig] = Field(default_factory=dict)
    roles: dict[str, RoleConfig] = Field(default_factory=dict)
    identities: list[IdentityConfig] = Field(default_factory=list)
    rules: list[RuleConfig] = Field(default_factory=list)
    approvals: ApprovalPolicy = Field(default_factory=ApprovalPolicy)
    rate_limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    change_windows: list[ChangeWindow] = Field(default_factory=list)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    redact_keys: list[str] = Field(
        default_factory=lambda: ["password", "secret", "token", "apikey", "api_key", "psk", "community", "private_key"]
    )

    @field_validator("upstreams")
    @classmethod
    def _names(cls, v: dict[str, UpstreamConfig]) -> dict[str, UpstreamConfig]:
        for name in v:
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) or "__" in name:
                raise ValueError(f"upstream name {name!r} must match [a-z][a-z0-9_-]* without '__'")
            if name.startswith("guardrail"):
                raise ValueError(f"upstream name {name!r} is reserved: the 'guardrail' prefix belongs to gateway tools")
        return v

    @model_validator(mode="after")
    def _cross_refs(self) -> GatewayConfig:
        seen: set[str] = set()
        for ident in self.identities:
            if ident.id in seen:
                raise ValueError(f"duplicate identity id {ident.id!r}")
            seen.add(ident.id)
            for role in ident.roles:
                if role not in self.roles:
                    raise ValueError(f"identity {ident.id!r} references unknown role {role!r}")
            if not self.approvals.allow_writer_approvers:
                roles = [self.roles[r] for r in ident.roles]
                if any(r.can_approve for r in roles) and any(set(r.classes) & {"write", "destructive"} for r in roles):
                    raise ValueError(
                        f"identity {ident.id!r} can both propose write changes and approve them; separate the agent and "
                        "approver identities (or set approvals.allow_writer_approvers: true)"
                    )
        owners: dict[str, str] = {}
        for ident in self.identities:
            key = (
                f"sha256:{ident.token_sha256}" if ident.token_sha256 else (f"env:{ident.token_env}" if ident.token_env else None)
            )
            digest = ident.token_digest()
            for k in filter(None, (key, f"sha256:{digest}" if digest else None)):
                if k in owners and owners[k] != ident.id:
                    raise ValueError(f"identities {owners[k]!r} and {ident.id!r} share a token; every identity needs its own")
                owners[k] = ident.id
        if self.server.stdio_identity and self.server.stdio_identity not in seen:
            raise ValueError(f"server.stdio_identity {self.server.stdio_identity!r} is not a defined identity")
        return self

    def identity(self, identity_id: str) -> IdentityConfig | None:
        return next((i for i in self.identities if i.id == identity_id), None)


def load_config(path: str | Path) -> GatewayConfig:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {p}: {exc}") from exc
    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> GatewayConfig:
    try:
        return GatewayConfig.model_validate(interpolate_env(raw))
    except ConfigError:
        raise
    except Exception as exc:  # pydantic.ValidationError and friends
        raise ConfigError(str(exc)) from exc
