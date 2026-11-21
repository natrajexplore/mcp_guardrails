from __future__ import annotations

import hashlib
from typing import Any

import pytest

from guardrail_gateway.config import parse_config
from guardrail_gateway.demo_upstream import build_lab_server
from guardrail_gateway.server import running_engine

TOKENS = {
    "noc-agent": "tok-agent",
    "viewer-bot": "tok-viewer",
    "alice": "tok-alice",
    "bob": "tok-bob",
}


def sha(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def base_config(tmp_path, **overrides: Any) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "server": {"stdio_identity": "noc-agent"},
        "storage": {
            "database": str(tmp_path / "changes.db"),
            "audit_log": str(tmp_path / "audit.jsonl"),
            "audit_hmac_key_env": None,
        },
        "roles": {
            "agent": {"allow_tools": ["ise__*"], "classes": ["read", "write", "destructive"]},
            "viewer": {"allow_tools": ["*"], "classes": ["read"]},
            "approver": {"allow_tools": ["*"], "classes": ["read"], "can_approve": True},
        },
        "identities": [
            {"id": "noc-agent", "roles": ["agent"], "token_sha256": sha(TOKENS["noc-agent"])},
            {"id": "viewer-bot", "roles": ["viewer"], "token_sha256": sha(TOKENS["viewer-bot"])},
            {"id": "alice", "roles": ["approver"], "token_sha256": sha(TOKENS["alice"])},
            {"id": "bob", "roles": ["approver"], "token_sha256": sha(TOKENS["bob"])},
        ],
        "rules": [
            {
                "match": "ise__update_sgacl",
                "risk": "high",
                "snapshot": {"tool": "ise__get_sgacl", "args": {"name": "{{args.name}}"}},
                "verify": {
                    "tool": "ise__get_sgacl",
                    "args": {"name": "{{args.name}}"},
                    "expect_json": {"aclcontent": "{{args.aclcontent}}"},
                },
                "rollback": {
                    "tool": "ise__update_sgacl",
                    "args": {"name": "{{args.name}}", "aclcontent": "{{snapshot.json.aclcontent}}"},
                },
                "constraints": [
                    {
                        "arg": "aclcontent",
                        "deny_regex": r"(?m)^\s*permit\s+ip\s*$",
                        "message": "blanket 'permit ip' is not allowed",
                    },
                    {"arg": "name", "allow_regex": r"[A-Za-z0-9_]{1,32}", "effect": "escalate", "message": "unusual SGACL name"},
                ],
            },
            {"match": "ise__delete_*", "risk": "critical"},
            {"match": "ise__set_fault", "class": "write", "risk": "low"},
        ],
    }
    for k, v in overrides.items():
        cfg[k] = v
    return cfg


@pytest.fixture
def anyio_backend():
    return "asyncio"


def pytest_collection_modifyitems(items):
    import inspect

    for item in items:
        if inspect.iscoroutinefunction(getattr(item, "function", None)):
            item.add_marker(pytest.mark.anyio)


@pytest.fixture
def lab():
    return build_lab_server(fault="")


@pytest.fixture
async def engine(tmp_path, lab):
    cfg = parse_config(base_config(tmp_path))
    async with running_engine(cfg, targets={"ise": lab}) as eng:
        yield eng


@pytest.fixture
def ident(engine):
    return lambda name: engine.identity(name)
