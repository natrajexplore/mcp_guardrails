# Configuration reference

The gateway reads a single YAML file (`-c` / `GUARDRAIL_CONFIG`). Strings may reference environment variables as
`${NAME}` or `${NAME:-default}`. An unset variable without a default is a startup error. Unknown keys are rejected.

## `server`
| Key | Default | Meaning |
|---|---|---|
| `name` | `mcp-guardrail-gateway` | MCP server name shown to clients |
| `host` / `port` / `path` | `127.0.0.1` / `8080` / `/mcp` | Streamable HTTP listener |
| `stdio_identity` | – | Identity used when the gateway runs over stdio (required for `-t stdio`) |
| `allowed_hosts` | `[]` | Host header allow-list (DNS rebinding protection) when not bound to localhost |

## `storage`
| Key | Default | Meaning |
|---|---|---|
| `database` | `./guardrail-data/changes.db` | SQLite change store (WAL mode) |
| `audit_log` | `./guardrail-data/audit.jsonl` | Hash-chained audit log |
| `audit_hmac_key_env` | `GUARDRAIL_AUDIT_HMAC_KEY` | Env var with the HMAC key. If unset, plain SHA-256 chaining is used |

## `upstreams.<name>`
Name: lowercase, `[a-z][a-z0-9_-]*`, no `__`, and not starting with `guardrail` (reserved for gateway tools).
Tools are exposed as `<name>__<tool>`.

| Key | Applies to | Meaning |
|---|---|---|
| `transport` | all | `stdio` or `http` |
| `command`, `args`, `env`, `cwd` | stdio | Child process to launch |
| `url`, `headers`, `verify_tls` | http | Streamable HTTP endpoint |
| `timeout_seconds` | all | Per-request read timeout (default 60) |
| `enabled` | all | Set `false` to skip |

## `roles.<name>`
| Key | Default | Meaning |
|---|---|---|
| `allow_tools` | `["*"]` | Globs over namespaced tool names |
| `deny_tools` | `[]` | Globs that always deny (wins over every role) |
| `classes` | `[read]` | Any of `read`, `write`, `destructive` |
| `can_approve` | `false` | May approve/reject changes (CLI/REST, and MCP if enabled) |
| `can_execute` | `true` | May execute approved changes |
| `max_risk` | `critical` | Highest risk this role may request (or approve, for approver roles) |

## `identities[]`
| Key | Meaning |
|---|---|
| `id` | Unique identity name (shown in audit) |
| `roles` | List of role names |
| `token_sha256` | SHA-256 hex of the bearer token (`guardrail token new`) |
| `token_env` | Alternatively, env var holding the raw token |

## `rules[]`
The first rule whose `match` glob fits the tool applies.

| Key | Meaning |
|---|---|
| `match` | Glob, e.g. `ise__update_*`, `fmc__deploy*` |
| `class` | Force `read` / `write` / `destructive` |
| `risk` | `low` / `medium` / `high` / `critical` (defaults: read=low, write=medium, destructive=high) |
| `require_approvals` | Override the approvals required by risk |
| `snapshot` | `{tool, args}` read call. Shown as the preview, re-taken for the drift check, used for rollback |
| `verify` | `{tool, args, expect_json: {path: value}, expect_contains: [...], expect_not_contains: [...]}`. At least one expectation is required |
| `rollback` | `{tool, args}` call that restores the snapshot. Requires `snapshot` on the same rule |
| `constraints` | List of `{arg, deny_regex?, allow_regex?, allowed_values?, max_length?, effect: deny\|escalate, message}` |
| `change_windows` | Per-rule windows (overrides the global list; `[]` means any time) |

### Templates
`args`, `expect_*` values support `{{path}}` lookups in a sandboxed context. There are no expressions or code.

| Path | Value |
|---|---|
| `args.<name>` | Arguments of the change |
| `change.id`, `change.requester` | Change metadata |
| `snapshot.json.<path>` / `snapshot.text` | Snapshot result (JSON parsed when possible) |
| `result.json.<path>` / `result.text` | Result of the write (verify/rollback only) |

A string that is exactly one placeholder keeps the original type (lists stay lists). Index lists with `[n]`.

## `approvals`
| Key | Default |
|---|---|
| `by_risk` | `{low: 0, medium: 1, high: 1, critical: 2}`. 0 means auto-approve (still snapshotted and verified) |
| `allow_self_approval` | `false` |
| `allow_mcp_approval` | `false`. When `true`, a `guardrail_approve_change` tool is exposed to approver identities |
| `allow_writer_approvers` | `false`. By default an identity whose roles allow `write`/`destructive` tools may not also hold a `can_approve` role (startup error). This separates agents from approvers on every channel, including REST |
| `change_ttl_minutes` | `240` |
| `require_justification` | `true`. Adds a required `guardrail_justification` argument to every write tool |
| `block_on_state_drift` | `true` |

## `change_windows[]`
`{days: [mon..sun], start: "HH:MM", end: "HH:MM", tz: "Area/City"}`. A window may cross midnight. It belongs to the
day it starts on. `tz` must be a valid IANA zone name; an unknown zone is a startup error (on Windows the `tzdata`
package, installed automatically, provides the zone database).

## `rate_limits`
`writes_per_minute` (default 10), `reads_per_minute` (default 300), per identity.

## `notifications`
| Key | Meaning |
|---|---|
| `webex` | `{bot_token, room_id}`. Posts a markdown card for pending/approved/succeeded/failed/rolled_back/rollback_failed |
| `splunk_hec` | `{url, token, index?, sourcetype?, verify_tls?}`. Streams every audit record |
| `webhooks` | `[{url, headers}]`. JSON `{event, change}` for ITSM/ChatOps |
| `public_url` | Base URL used in links inside notifications |

## `redact_keys`
Substrings matched case-insensitively against argument keys. Matching values are replaced with `***REDACTED***` in
audit records and `get_change` output.
