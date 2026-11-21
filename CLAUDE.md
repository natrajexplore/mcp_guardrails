# CLAUDE.md: project memory for Claude Code

@AGENTS.md
@PROJECT.md

The two imports above are the source of truth for commands, code map, security invariants and the project charter.
This file adds what Claude Code specifically needs: how to work here, and what was learned the hard way.

## How to work in this repo
1. **Understand first.** For any non-trivial task, read the relevant module and its tests before editing. For
   anything touching `engine.py`, `store.py`, `audit.py`, `server.py` (auth) or `policy.py`, start in **plan mode**
   and present the plan, naming any invariant from AGENTS.md that is involved.
2. **Test-first for bugs.** Reproduce with a failing test, then fix, then run the full suite.
3. **Use the procedures** in `.claude/commands/` rather than improvising:
   `/test` · `/security-review` · `/add-policy-rule` · `/lab-demo` · `/release-check` · `/code-exchange-check`.
4. **Delegate to subagents** in `.claude/agents/` when the task matches:
   - `security-reviewer`: after any change to auth, approvals, execution, audit or redaction. Mandatory before a release.
   - `test-engineer`: write or extend tests, chase flaky async or transport tests.
   - `policy-author`: write gateway YAML policy (rules, snapshot/verify/rollback) for a new upstream MCP server.
   - `docs-writer`: keep README/docs/CHANGELOG aligned with behaviour.
5. **Finish properly.** All tests pass, `ruff check` and `ruff format --check` pass, docs and CHANGELOG are updated.
   Then summarize what changed and which invariants were touched (normally "none").

## Gotchas already learned (do not rediscover)
- **MCP SDK is 2.x.** `mcp.server.fastmcp` raises ModuleNotFoundError. Use `mcp.server.mcpserver.MCPServer` for
  static servers and `mcp.server.lowlevel.Server(on_list_tools=..., on_call_tool=...)` for the dynamic gateway catalog.
- In the lowlevel handlers, `ctx.request` is the Starlette `Request` over HTTP and `None` over stdio. The
  authenticated identity is read from `request.scope["state"]["guardrail_identity"]`, set by `BearerAuthMiddleware`.
- `Client.list_tools(cache_mode="bypass")`: the SDK client caches tool lists by default (`use`/`refresh`/`bypass`).
- **Tests:** async generator fixtures under pytest-asyncio crash with "cancel scope in a different task". The repo
  uses the anyio plugin (auto-marking in `tests/conftest.py`). Always run `pytest -p no:asyncio`.
- A tool returning a Python list yields **one TextContent per item**. Join block texts in tests; never `content[0]`.
- **Audit log:** the server and the CLI append concurrently. Each write takes `fcntl.flock` and re-reads the tail
  (`_last_record`). Never cache seq/prev_hash in memory again: that broke the chain in live testing.
- Rollback must be re-verified against the snapshot (`restored_state_matches_snapshot`). The lab fault mode `corrupt`
  proves the `rollback_failed` path; `corrupt_once` proves `rolled_back`.
- `examples/gateway-trustsec.yaml` needs `ISE_HOST/ISE_USERNAME/ISE_PASSWORD` set to validate (strict env
  interpolation). Tests only read its `rules` section.
- Docker isn't available in every dev sandbox. `python -m build` validates the build stage of the Dockerfile.

## Memory hygiene
- Durable, repo-wide facts belong here (gotchas) or in PROJECT.md (decisions, roadmap). Keep both short and current.
  Delete anything that stops being true.
- Personal or machine-specific notes go in `CLAUDE.local.md` (gitignored). Never put secrets, tokens, hostnames of
  real devices, or customer data in any memory file.
- When a decision is made with the human (e.g. "allow MCP approval for ITSM bots"), add a one-line entry to the
  Decision log in PROJECT.md with the date.
