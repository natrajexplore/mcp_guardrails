# AGENTS.md: MCP Guardrail Gateway

Instructions for AI coding agents (Claude Code, Codex, Copilot, Cursor, ...) working in this repository.
Humans should read [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md) first.

## What this repo is
A policy-enforcing MCP proxy. It sits between AI agents and Cisco MCP servers and turns write tool calls into
human-approved, snapshotted, verified, auto-rollback change requests, with a hash-chained audit log. **This code is a
security control.** A bug here can let an AI agent change production network policy unapproved. Treat every change
accordingly.

## Setup
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pip install -e ../trustsec-policy-agent   # optional: enables tests/test_trustsec_integration.py
```
Python 3.11+. Runtime deps: `mcp>=2.3,<3` (MCP Python SDK **2.x**), `httpx2`, `pydantic` v2, `pyyaml`, `typer`,
`uvicorn`, `starlette`, `anyio`.

## Commands (run before declaring any task done)
| Purpose | Command |
|---|---|
| Tests (all) | `pytest -q -p no:asyncio` |
| One test | `pytest -q -p no:asyncio tests/test_engine.py::test_full_approve_execute_verify` |
| Lint | `ruff check src tests` |
| Format | `ruff format src tests` (CI runs `ruff format --check`) |
| Build | `python -m build` |
| Lab run | `GUARDRAIL_AUDIT_HMAC_KEY=dev guardrail serve -c examples/lab-quickstart.yaml` |
| Validate a config | `guardrail config validate -c <file>` |

Expected: all tests pass (≥ 78, ~12 s), ruff clean. Never mark work complete with failing or skipped-by-you tests.

## Code map
| File | Responsibility |
|---|---|
| `config.py` | YAML schema (pydantic, `extra="forbid"`), `${ENV}` interpolation, cross-ref validation |
| `classify.py` | read/write/destructive classification (**fail-safe: unknown means write**) |
| `policy.py` | RBAC, constraints, risk, change windows, rate limiter |
| `engine.py` | Change lifecycle. The security core |
| `store.py` | SQLite state machine + atomic `claim_for_execution` |
| `audit.py` | Hash-chained HMAC JSONL, `fcntl` inter-process lock, `verify_chain` |
| `server.py` | lowlevel MCP `Server`, bearer auth middleware, REST approval API |
| `upstreams.py` | MCP client sessions to upstreams, namespaced catalog |
| `notify.py` | Webex / Splunk HEC / webhooks (best-effort, never blocking) |
| `templating.py` | Sandboxed `{{path}}` rendering, no expressions |
| `demo_upstream.py` | Simulated ISE MCP server with fault injection |

## Security invariants: never break these
1. A write/destructive upstream call **never** executes on `tools/call`. It only executes from `GuardrailEngine.execute`
   after the approval quorum (or `required_approvals == 0` by explicit policy).
2. Unknown tools classify as **write**. Never default to read.
3. Deny wins across roles. Hidden tools stay hidden from `tools/list`.
4. No self-approval unless `allow_self_approval: true`. No MCP approval unless `allow_mcp_approval: true`. One approval per approver.
5. Execution re-checks: status, actor rights, `args_sha256`, requester authorization, change window, state drift, atomic claim.
6. After a failed verify, rollback must be followed by restore confirmation. If that fails, the status is `rollback_failed`.
7. Every decision path writes an audit record. Audit appends hold the inter-process lock and re-read the chain tail.
8. Secrets: tokens are stored only as SHA-256 and compared with `hmac.compare_digest`. Argument keys in `redact_keys`
   never reach audit logs or `get_change` output in clear text.
9. Notification or sink failures must never fail or block a tool call.
10. Templates are dotted lookups only. Never add `eval`, Jinja or expression support.

If a task seems to require relaxing an invariant, **stop and ask the human**. Do not implement it.

## Coding conventions
- Type hints everywhere. `from __future__ import annotations`. Line length 130 (ruff).
- Pydantic models use `_Strict` (`extra="forbid"`). New config keys go in `config.py` **and** `docs/configuration.md`.
- Errors safe to show the agent: raise `GuardrailDenied("<actionable message>")`. Never leak stack traces or secrets.
- Policy-visible behaviour changes need a test in `tests/test_engine.py` (lifecycle) or `tests/test_units.py` (pure logic).
- Async tests: the repo uses the **anyio** pytest plugin (auto-marked in `conftest.py`), not pytest-asyncio. Keep `-p no:asyncio`.
- MCP SDK 2.x: `from mcp.server.mcpserver import MCPServer` (FastMCP no longer exists), `from mcp import Client`.
  `Client(server_obj)` connects in-process, which is ideal for tests. Tool results expose `structured_content` and `is_error`.
- HTTP: use `httpx2` (the SDK's client), not `httpx`. Mock with `httpx2.MockTransport`.

## Boundaries
- ✅ Always: run tests and ruff, update docs/CHANGELOG for user-visible changes, add tests for bug fixes.
- ⚠️ Ask first: dependency changes, config schema changes, state-machine changes (`store.py` `_TRANSITIONS`), audit
  record format changes, anything touching `engine.execute`, `approve`, `authenticate_token`, `BearerAuthMiddleware`.
- 🚫 Never: commit secrets or real device data, read `.env`/keys, disable TLS verification by default, weaken an
  invariant, `git push` or publish without explicit human instruction, edit `LICENSE`/`NOTICE` text.

## Commits and PRs
Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `security:`). One logical change per
commit. The PR description states the problem, the change, the tests run, and which invariants were touched (normally none).
