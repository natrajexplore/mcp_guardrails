# Security model

The gateway assumes the **AI agent is helpful but not trustworthy**. It can be wrong, it can be prompt-injected by
content it reads (tickets, logs, web pages), and it will retry creatively. Every control below holds even when the
agent actively tries to get around it.

## Threats and controls

| Threat | Control |
|---|---|
| Agent performs a write directly | Writes never execute on the call. They become change requests that need N human approvals (`approvals.by_risk`, per-rule `require_approvals`). |
| Agent approves its own change | `allow_mcp_approval: false` (default) means there is no approve tool over MCP. Approval happens only over CLI or REST, with an approver token. Self-approval is refused (`allow_self_approval: false`). Each approver counts once. |
| Prompt-injected agent escalates scope | RBAC per identity: tool globs, classes, `max_risk`. Deny wins across roles. Tools a caller can't use are hidden from `tools/list`, so they never enter the model's context. Calling or explaining a hidden tool returns the same `unknown tool` error, and leaves the same audit record, as a nonexistent one (the real reason is audited). Non-approvers see only their own change records, and status counts cover only visible tools, so hidden tools can't be enumerated. |
| An agent identity is also an approver | Startup fails if an identity can both propose writes (`write`/`destructive` classes) and approve (`can_approve`), unless `approvals.allow_writer_approvers: true`. This holds for every approval channel, including REST. |
| Gateway killed mid-change | The change stays `executing`. After the execution deadline, an approver runs `guardrail changes recover <id> --reason ...`. It becomes `rollback_failed` (outcome unknown, check the device) and `change.recovered` is audited. Nothing is applied or rolled back automatically. |
| Dangerous arguments (e.g. `permit ip`, Permit_IP SGACL, editing ANY→ANY) | `constraints` deny the change or escalate its risk. Violations are audited (`change.denied`). |
| Agent tweaks arguments to slip past a denial | Every attempt is audited. Constraints are evaluated on the exact arguments that would execute. `args_sha256` is pinned at creation, and execution refuses if the stored arguments changed. |
| Unknown or new upstream tool | Fail-safe classification: anything not provably read-only is a write. `readOnlyHint` is honoured only when the upstream sets it. Rules can pin `class:` explicitly. |
| Approved change runs against a different state (TOCTOU) | The snapshot is taken at proposal (shown to approvers) and again at execution. Any difference means `blocked`, and the change must be resubmitted. |
| Change runs at the wrong time | `change_windows` (global or per rule, timezone-aware, crossing midnight) are checked at execution. |
| Double execution / races | Atomic `approved → executing` claim in SQLite. A second execute is refused. Every status update is a compare-and-set on the status last read, so a change rejected or expired while an execution is in flight (e.g. a REST reject during the snapshot call) can never be overwritten back to an executable state. |
| Client disconnects or cancels mid-execution | Everything after the atomic claim (apply, verify, rollback, restore check) is shielded from cancellation and bounded by an overall deadline, so it always ends in a recorded terminal status. A timeout, Ctrl-C or unexpected error ends in `rollback_failed` (`failed` if nothing was applied) with `change.execute_crashed`. Arguments are re-hashed on the claimed row just before the apply. |
| Agent probes the approval controls | Every refusal (self-approval, MCP approval while disabled, an unauthorized or premature execute, tampered arguments) writes `change.approve_denied`, `change.reject_denied` or `change.execute_denied`. |
| Partial or incorrect apply | `verify` after apply, then automatic `rollback` to the snapshot, then a re-verify that the restore matches the snapshot. If that fails: `rollback_failed`, plus Webex/webhook alerts. |
| Stale approvals | `change_ttl_minutes`. Expired changes cannot be executed. A change already `executing` is never expired, so it always reaches a recorded outcome. |
| Requester loses rights after approval | Requester authorization is re-checked at execution. |
| One token, two identities | Identities must not share a token digest or `token_env` (startup error), and an ambiguous token is refused, so the writer/approver separation can't be bypassed with a reused token. |
| Token theft from config | Only SHA-256 digests are stored (`token_sha256`), or the token comes from env (`token_env`). Comparison is constant-time. |
| Secrets in arguments leak into logs | Keys matching `redact_keys` (password, token, secret, psk, community, ...) are redacted in audit records and in `get_change` output. |
| Audit tampering | Hash chain with `prev_hash`, plus HMAC-SHA256 when `GUARDRAIL_AUDIT_HMAC_KEY` is set. `guardrail audit verify` reports the first bad record. Appends are fsync'ed and use an inter-process lock. Forward a copy to Splunk HEC for off-box retention. |
| Runaway agent loops | Per-identity sliding-window rate limits for reads and writes. |
| Unexpected errors leak internals or skip the audit | Any exception on the call path becomes a generic error for the agent (no stack trace) plus a `call.error` audit record. Upstream failures on REST return 502, malformed bodies 400. |
| Reconnaissance via the public health check | `/healthz` reports only liveness and per-upstream `connected`; upstream error strings (which can contain internal URLs) need an authenticated `guardrail_status` call. |
| Agent forges content in the approvers' Webex room | Agent-controlled text (justification, status detail) is flattened and rendered as a single inline-code span, capped at 500 characters (justifications at 2000), so it cannot inject banners or links. |
| DNS-rebinding against a local gateway | MCP transport security: DNS rebinding protection is on for localhost binds. Set `server.allowed_hosts` when binding elsewhere. |

## What the gateway does not do

- Keep the audit log on a filesystem used by a single OS. Linux locks the log file itself; Windows locks a sidecar
  `.lock` file, so the two don't exclude each other on a shared mount.
- It does not make an upstream MCP server safe on its own. If an agent can reach the upstream directly, it bypasses
  the gateway. Run upstreams over stdio as children of the gateway, or restrict their HTTP listeners to the gateway.
- It does not judge whether a change is a good idea. That is the approver's job. The gateway gives approvers the
  context to judge: preview, risk, justification, and (with trustsec-policy-agent) an effective-access simulation.
- HMAC protects integrity, not confidentiality. Treat the audit log as sensitive.

## Recommended production posture

1. One identity per agent and per human. Approvers hold no write classes.
2. `allow_mcp_approval: false`, `allow_self_approval: false`, `require_justification: true`, `block_on_state_drift: true`.
3. Every write tool has a rule with `snapshot` + `verify` (+ `rollback` where an inverse exists).
4. `critical` for anything with wide blast radius (deploys, SGACL content, default policies): two approvers plus a change window.
5. Set `GUARDRAIL_AUDIT_HMAC_KEY` from a secret manager. Forward the audit to Splunk. Run `guardrail audit verify` daily.
6. Terminate TLS in front of the HTTP listener (reverse proxy or service mesh).
