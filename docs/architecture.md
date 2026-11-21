# Architecture

```
src/guardrail_gateway/
  config.py         YAML + ${ENV} interpolation, strict pydantic models, cross-reference validation
  classify.py       read / write / destructive from MCP annotations, rules and verb heuristics (fail-safe)
  policy.py         RBAC, argument constraints, risk scoring, change windows, rate limits
  templating.py     sandboxed {{path}} rendering for snapshot / verify / rollback specs
  upstreams.py      one MCP client session per upstream (stdio or Streamable HTTP), namespaced tool catalog
  engine.py         the change lifecycle: propose -> approve -> execute (drift, claim, apply, verify, rollback)
  store.py          SQLite change store with an explicit state machine and atomic execution claim
  audit.py          hash-chained, HMAC-signed JSONL audit log with inter-process locking and verification
  notify.py         async best-effort Webex / Splunk HEC / webhook delivery
  server.py         MCP front-end (lowlevel Server, stdio + Streamable HTTP), bearer auth, REST approval API
  cli.py            `guardrail` command line
  demo_upstream.py  simulated ISE SGACL MCP server with fault injection (lab + tests)
```

## Request path

1. **Transport and identity.** Over HTTP, `BearerAuthMiddleware` maps the token's SHA-256 to an identity and stores it
   in the ASGI scope. Over stdio, the configured `stdio_identity` is used. Unauthenticated HTTP requests get 401
   before reaching MCP.
2. **`tools/list`.** For each upstream tool the engine computes class and base risk, drops tools the identity may not
   use, and rewrites the rest. The namespaced name, a `[guardrail: ...]` prefix in the description, and for writes a
   `guardrail_justification` argument in the schema. The gateway's own `guardrail_*` tools are appended.
3. **`tools/call`.**
   - Read: authorize, rate-limit, forward, audit `call.read`. The result is passed back unchanged.
   - Write: authorize, rate-limit, constraints, justification, snapshot preview, create change, audit `change.created`.
     If 0 approvals are required it executes immediately. Otherwise it returns `approval_required` and notifies.
4. **Approval** (CLI/REST): role check, separation of duties, risk ceiling, one approval per approver. The change
   moves to `approved` when the quorum is reached.
5. **Execution** (MCP `guardrail_execute_change`, REST or CLI):
   status, actor and argument-hash checks, then requester re-authorization, then change window, then snapshot and drift
   check, then atomic claim, then apply, then verify, then (on failure) rollback and restore confirmation, then final
   state and audit.

## Change state machine

```
pending ──approve(quorum)──> approved ──execute──> executing ──> succeeded
   │                           │   ▲                     ├──────> failed
   │                           ▼   │                     ├──────> rolled_back
   │                         blocked (window / drift)    └──────> rollback_failed
   ├──reject/cancel──> rejected
   └──ttl──────────> expired
```

## Why a lowlevel MCP server

The gateway's tool catalog is dynamic. It is discovered from upstreams at startup and filtered per caller, so it uses
the SDK's lowlevel `Server` with `on_list_tools` / `on_call_tool` handlers rather than decorator-registered tools.
Upstream schemas pass through untouched, apart from the added justification argument.
