# PROJECT.md: charter, status and decisions

## Mission
Let AI agents propose and carry out network changes on Cisco platforms **with the same controls as a human change
board**: least privilege, approval, a maintenance window, pre/post checks, rollback and audit.

## Users
| Persona | Needs |
|---|---|
| NOC/SecOps engineer running an AI agent | The agent can fix things, not just explain them |
| Security approver / CAB | Context (before vs proposed, risk, justification) and a fast approve/reject path |
| Platform owner | One choke point to enforce policy across many MCP servers |
| Auditor | A complete, verifiable record of who asked, who approved and what changed |

## Scope
**In:** MCP proxy (stdio + Streamable HTTP), RBAC, constraints, risk, approvals (CLI/REST), change windows, drift
check, snapshot/verify/rollback, hash-chained audit, Webex/Splunk/webhooks, simulated ISE upstream.

**Out (non-goals):** writing device-specific automation (that belongs to the upstream MCP servers), a full ITSM,
replacing ISE/FMC native change control, an LLM inside the gateway (decisions must be deterministic).

## Architecture (one paragraph)
Clients talk MCP to a lowlevel `Server` whose catalog is built from upstream MCP sessions and filtered per identity.
`GuardrailEngine` handles every call: reads are forwarded; writes become `Change` rows (SQLite state machine) and
execute later through drift check, atomic claim, apply, verify and rollback. Every step is written to the audit log.
Details: [docs/architecture.md](docs/architecture.md). Threat model: [docs/security-model.md](docs/security-model.md).

## Status
- **v1.0.0 (2026-11-20).** Feature-complete for the first Code Exchange submission. 41 tests (unit, lifecycle,
  HTTP+REST e2e, stdio e2e, multi-process audit, TrustSec integration). Validated live: lab flow and the full chain
  agent → gateway → trustsec-policy-agent.
- **Unreleased (2026-11-21).** Hardening pass before submission: concurrency (CAS status updates), cancellation-safe
  execution, full refusal auditing, Windows support. 79 tests, green on Windows; live lab re-validated.
- Not yet validated: against a real ISE (DevNet sandbox), a Docker image build, or a published GitHub repo.

## Roadmap
| Priority | Item |
|---|---|
| P1 | Validate on DevNet ISE sandbox with trustsec-policy-agent. Record the demo video |
| P1 | Publish to GitHub, CI green, submit to Code Exchange |
| P2 | Policy packs (rules + snapshot/verify) for the FMC, Catalyst Center and Meraki MCP servers, from `guardrail tools` output |
| P2 | Webex adaptive card with Approve/Reject buttons (webhook back to REST) |
| P3 | Minimal approval web UI. ServiceNow change connector |
| P3 | OpenTelemetry spans for each lifecycle step |
| P3 | Postgres store option for HA deployments |

## Definition of Done (every change)
- [ ] Tests added or updated. `pytest -q -p no:asyncio` is green.
- [ ] `ruff check src tests` and `ruff format --check src tests` are clean.
- [ ] No security invariant (AGENTS.md) weakened. The `security-reviewer` subagent was run if auth, approval, execute,
      audit or redaction code changed.
- [ ] Docs (`README.md`, `docs/*.md`) and `CHANGELOG.md` updated for user-visible behaviour.
- [ ] Config schema changes are reflected in `docs/configuration.md` and in the example configs.

## Release procedure
Run `/release-check`. In short: green CI, bump `__version__` and `pyproject.toml`, move the CHANGELOG
*Unreleased* section, `python -m build`, check the wheel in a clean venv, run the security review, tag `vX.Y.Z`.
A human pushes.

## Code Exchange submission checklist
See `/code-exchange-check`. Public repo, Apache-2.0 LICENSE plus NOTICE, README sections (Use Case, Related Sandbox,
Installation, Usage, How to test, Known issues, Getting help/involved, Credits, Licensing), CONTRIBUTING,
CODE_OF_CONDUCT, SECURITY, CI badge, repo topics (`cisco`, `mcp`, `ise`, `ai-agents`, `guardrails`).

## Decision log
| Date | Decision | Why |
|---|---|---|
| 2026-11-20 | MCP Python SDK 2.x, lowlevel `Server` | Dynamic, per-identity tool catalog; current SDK |
| 2026-11-20 | Unknown tools classify as write | Fail-safe default for a security control |
| 2026-11-20 | MCP approval disabled by default | An agent must not approve its own change |
| 2026-11-20 | Drift check compares the snapshot byte-for-byte | Simple and strict TOCTOU protection; requires deterministic snapshot tools |
| 2026-11-20 | Rollback is re-verified against the snapshot | A rollback that "succeeds" but doesn't restore state is worse than a visible failure |
| 2026-11-20 | Audit appends take `fcntl` lock and re-read the tail | CLI and server write concurrently (bug found in live test) |
| 2026-11-20 | Apache-2.0 + NOTICE | Code Exchange accepts OSI licenses; NOTICE is expected with Apache-2.0 |
| 2026-11-21 | Change status updates are compare-and-set on the last-read status | A REST reject during an in-flight execute was overwritten to `blocked` and became executable |
| 2026-11-21 | Windows supported: sidecar-file audit lock (`msvcrt`), `tzdata` dependency on win32 only, Windows CI job | Audit chain broke and change windows crashed on Windows |
| 2026-11-21 | Write tools do not advertise the upstream `outputSchema` | Writes return the gateway change payload; strict MCP clients rejected it |
| 2026-11-21 | Hidden tools answer `unknown tool` on call and explain | Invariant 3 intent: no enumeration of tools a caller can't see |
| 2026-11-21 | Identities may not both write and approve (`allow_writer_approvers` opt-out) | REST approval accepted any approver token, including an agent's |
| 2026-11-21 | Operator `changes recover` for stale `executing` rows, ending in `rollback_failed` | Reuses an existing transition; only after the execution deadline, so in-flight work is never pre-empted |
