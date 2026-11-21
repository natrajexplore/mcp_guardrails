# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]
### Security
- Hidden tools can't be enumerated. Calling or explaining a tool the caller can't see returns the same
  `unknown tool` error as a nonexistent tool, and both leave the same `call.denied` audit record. Approvers may still
  dry-run any tool with `guardrail_explain_tool`.
- Change records are scoped. Non-approvers see only the changes they requested (MCP `list_changes`/`get_change`, and
  REST, which answers 404 for others), and `guardrail_status` shows them only tool counts for tools they can see.
- Two identities may not share a token (startup error); an ambiguous token is refused at authentication.
- Execute/cancel of a change the caller may not view answers "not found", like a missing ID, so change IDs and
  statuses can't be probed. `pending_changes` in `guardrail_status` is scoped the same way.
- Config: a rule's `rollback` requires a `snapshot`, and `verify` needs at least one expectation (an empty verify
  always passed).
- An apply that raises (for example a timeout after the device committed) is no longer recorded as a plain `failed`.
  Verify decides: success, rollback, or `rollback_failed` when there is no verify spec.
- The execution deadline is derived from config only (the max `timeout_seconds` across the change tool and its rule's
  snapshot/verify/rollback upstreams), so `changes recover` run from the CLI uses the same deadline as the server.
- Separation of duties is enforced in config: an identity that can propose write/destructive changes may not also
  approve them, on any channel including REST (opt out with `approvals.allow_writer_approvers: true`).
- Execution can no longer be cut short after the upstream write. Previously, a client disconnect or
  `notifications/cancelled` after the apply skipped verify and rollback, and the change stayed `executing` with no
  recorded outcome. Everything after the claim now runs shielded from cancellation, under an overall deadline
  (4 × upstream `timeout_seconds` + 30 s). A timeout, a native cancel (Ctrl-C) or an unexpected error after the apply
  ends in `rollback_failed` (device state unknown, a human must check) with a `change.execute_crashed` audit record.
  `timeout_seconds` is capped at 600.
- `args_sha256` is re-checked on the claimed row immediately before the apply, which closes a TOCTOU window during
  the snapshot call.
- Every refused control action is audited: `change.approve_denied`, `change.reject_denied`, `change.execute_denied`
  (self-approval, MCP approval while disabled, unauthorized execute, tampered arguments, ...). REST failures are
  audited as `rest.error`.
- Audit appends stay linear in the size of the last record, so one huge record can no longer stall the gateway.
  Approval comments and reject reasons are capped at 2000 characters.
- The CLI approval prompt escapes the agent-controlled justification, so it cannot inject ANSI sequences.
- Change status updates are now compare-and-set. Previously a change rejected (REST/CLI) while `execute` awaited the
  snapshot could be overwritten to `blocked` and then executed. Execution now aborts with `change.execute_aborted`.
- `/healthz` no longer exposes upstream error strings (possible internal hostnames/URLs) to unauthenticated callers.
- Agent-controlled justification/status text is neutralised in Webex markdown (no forged banners or links).
  Justifications are capped at 2000 characters.
- The HTTP middleware only lets `lifespan` scopes through without auth; websocket connections are closed.
- Upstream names may not start with `guardrail` (would shadow gateway tools).

### Fixed
- Windows: the audit log now takes a real inter-process lock (sidecar `<audit_log>.lock`, `msvcrt`); concurrent CLI and
  server appends previously broke the hash chain.
- Windows: change windows crashed without an IANA zone database; `tzdata` is now a Windows-only dependency, and an
  invalid `tz` is rejected at config load instead of failing at execution time.
- Write tools no longer advertise the upstream `outputSchema`. Spec-compliant MCP clients (including the MCP Python SDK)
  rejected every write response, because writes return the gateway's change payload.
- A change still `executing` past its TTL made `list`/`get` raise; `executing` changes no longer expire.
- Unexpected upstream exceptions (snapshot, preview, verify setup) are contained: the agent gets a safe error, a
  `call.error` audit record is written, and REST returns 502 instead of 500.
- A missing justification is now audited (`change.denied`).
- Config bounds: `change_ttl_minutes >= 1`, non-negative approval counts and rate limits, a valid port range, and
  `timeout_seconds > 0`. `guardrail_list_changes` clamps `limit` to 1..200.
- Concurrent approve/reject races return a denial (MCP/CLI) or 409 (REST) instead of an internal error.
- REST: a JSON body that is not an object returns 400; a non-UTF-8 `Authorization` header returns 401 (both were 500).

### Added
- `guardrail changes recover <id> --as <approver> --reason ...`: operator recovery for a change stuck in `executing`
  after the gateway was killed mid-change. It is allowed only after the execution deadline and results in
  `rollback_failed` with a `change.recovered` audit record. The Claude Code guard hook treats it as a human-only action.

### Changed
- Removed `sample-report.md` (output of trustsec-policy-agent, not part of this project) from the repository root.
- CI runs on Ubuntu and Windows, with `pytest -p no:asyncio` as documented.

## [1.0.0] - 2026-11-20
### Added
- First public release of MCP Guardrail Gateway.
- AI-assisted development setup: AGENTS.md, CLAUDE.md, PROJECT.md, Claude Code subagents, slash-command procedures, least-privilege settings and guard hooks.
