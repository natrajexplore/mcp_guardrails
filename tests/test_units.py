from __future__ import annotations

from datetime import UTC, datetime

import pytest
from mcp.types import ToolAnnotations

from guardrail_gateway.classify import classify
from guardrail_gateway.config import ChangeWindow, ConfigError, parse_config
from guardrail_gateway.policy import PolicyEngine, RateLimiter
from guardrail_gateway.redact import REDACTED, redact
from guardrail_gateway.templating import TemplateError, render


@pytest.mark.parametrize(
    "name,expected",
    [
        ("ise__get_sgt", "read"),
        ("fmc__listAccessPolicies", "read"),
        ("catc__deleteDevice", "destructive"),
        ("ise__quarantine_endpoint", "destructive"),
        ("fmc__deploy_policy", "write"),
        ("meraki__updateNetwork", "write"),
        ("x__frobnicate", "write"),
    ],
)
def test_classify_by_name(name, expected):
    assert classify(name) == expected


def test_annotations_win():
    assert classify("x__delete_all", ToolAnnotations(read_only_hint=True)) == "read"
    assert classify("x__get_thing", ToolAnnotations(destructive_hint=True)) == "destructive"


def test_render_preserves_types_and_interpolates():
    ctx = {"args": {"name": "A", "ids": [1, 2]}, "snapshot": {"json": {"x": {"y": 3}}}}
    assert render("{{args.ids}}", ctx) == [1, 2]
    assert render({"n": "SGACL {{args.name}} v{{snapshot.json.x.y}}"}, ctx) == {"n": "SGACL A v3"}
    assert render("{{ args.ids[1] }}", ctx) == 2
    with pytest.raises(TemplateError):
        render("{{args.missing}}", ctx)


def test_redact_nested():
    out = redact({"user": "u", "Password": "p", "nested": [{"api-key": "k", "ok": 1}]}, ["password", "api_key"])
    assert out == {"user": "u", "Password": REDACTED, "nested": [{"api-key": REDACTED, "ok": 1}]}


def test_window_crossing_midnight():
    w = [ChangeWindow(days=["sat"], start="22:00", end="06:00", tz="UTC")]
    assert PolicyEngine.in_window(w, datetime(2026, 11, 21, 23, 0, tzinfo=UTC))  # Sat 23:00
    assert PolicyEngine.in_window(w, datetime(2026, 11, 22, 5, 59, tzinfo=UTC))  # Sun 05:59
    assert not PolicyEngine.in_window(w, datetime(2026, 11, 22, 6, 0, tzinfo=UTC))
    assert not PolicyEngine.in_window(w, datetime(2026, 11, 21, 21, 0, tzinfo=UTC))
    assert PolicyEngine.in_window([], None)


def test_rate_limiter():
    rl = RateLimiter(writes_per_minute=2, reads_per_minute=5)
    assert rl.check("a", "write", 0) and rl.check("a", "write", 1)
    assert not rl.check("a", "write", 2)
    assert rl.check("a", "destructive", 61)  # destructive counts as write, window slid
    assert rl.check("b", "write", 2)


def test_env_interpolation(monkeypatch, tmp_path):
    monkeypatch.setenv("FMC_URL", "https://fmc.lab/mcp")
    cfg = parse_config(
        {"upstreams": {"fmc": {"transport": "http", "url": "${FMC_URL}", "headers": {"X-Env": "${MISSING:-dflt}"}}}}
    )
    assert cfg.upstreams["fmc"].url == "https://fmc.lab/mcp"
    assert cfg.upstreams["fmc"].headers["X-Env"] == "dflt"
    with pytest.raises(ConfigError, match="NOPE"):
        parse_config({"upstreams": {"x": {"transport": "http", "url": "${NOPE}"}}})


def test_config_cross_reference_errors():
    with pytest.raises(ConfigError, match="unknown role"):
        parse_config({"identities": [{"id": "a", "roles": ["ghost"]}]})
    with pytest.raises(ConfigError, match="upstream name"):
        parse_config({"upstreams": {"Bad__Name": {"transport": "http", "url": "http://x"}}})
    with pytest.raises(ConfigError, match="requires 'command'"):
        parse_config({"upstreams": {"a": {"transport": "stdio"}}})


def test_deny_wins_across_roles():
    cfg = parse_config(
        {
            "roles": {
                "broad": {"allow_tools": ["*"], "classes": ["read", "write"]},
                "fence": {"allow_tools": [], "deny_tools": ["fmc__deploy*"]},
            },
            "identities": [{"id": "x", "roles": ["broad", "fence"]}],
        }
    )
    p = PolicyEngine(cfg)
    ident = cfg.identity("x")
    assert p.authorize(ident, "ise__update_sgacl", "write", "medium").allowed
    assert not p.authorize(ident, "fmc__deploy_policy", "write", "medium").allowed


def test_max_risk_enforced():
    cfg = parse_config(
        {"roles": {"jr": {"classes": ["write"], "max_risk": "medium"}}, "identities": [{"id": "j", "roles": ["jr"]}]}
    )
    p = PolicyEngine(cfg)
    assert not p.authorize(cfg.identity("j"), "a__b", "write", "high").allowed


def test_audit_chain_with_concurrent_writers(tmp_path):
    """The server and the CLI append to the same log from different processes."""
    import multiprocessing as mp

    from guardrail_gateway.audit import AuditLog, verify_chain

    path = tmp_path / "audit.jsonl"
    a, b = AuditLog(path, b"k"), AuditLog(path, b"k")
    for i in range(5):
        a.write("server.event", i=i)
        b.write("cli.event", i=i)
    procs = [mp.get_context("spawn").Process(target=_writer, args=(str(path), n)) for n in range(3)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    res = verify_chain(path, b"k")
    assert res.ok, res.message
    assert res.records == 10 + 3 * 20
    assert not verify_chain(path, b"wrong-key").ok


def _writer(path: str, n: int) -> None:
    from guardrail_gateway.audit import AuditLog

    log = AuditLog(path, b"k")
    for i in range(20):
        log.write("proc.event", proc=n, i=i)
