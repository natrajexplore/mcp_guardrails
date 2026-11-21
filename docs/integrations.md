# Integrations

## Cisco MCP servers

The gateway works with any MCP server. Tool names differ per server and version, so always start with:

```bash
guardrail tools -c gateway.yaml --as noc-agent
```

This connects to every upstream and prints, for each tool, its class, risk, approvals, whether the identity can see
it, and whether a rollback is configured. Then add rules for the write tools you want to allow.

### trustsec-policy-agent (Cisco ISE TrustSec)
Fully worked policy with snapshot, verify and rollback: [examples/gateway-trustsec.yaml](../examples/gateway-trustsec.yaml).

### Cisco ISE, Secure Firewall (FMC), Catalyst Center, Meraki MCP servers
Starting-point rules using globs. Tighten them once you have seen the real tool list:

```yaml
rules:
  # Secure Firewall: deployments push policy to every managed FTD -> two approvers, maintenance window only
  - match: "fmc__*deploy*"
    risk: critical
    change_windows: [{days: [sat], start: "22:00", end: "04:00", tz: Asia/Kolkata}]
  - match: "fmc__*delete*"
    risk: critical

  # ISE: endpoint quarantine / ANC actions affect users immediately
  - match: "ise__*anc*"
    class: destructive
    risk: high

  # Catalyst Center: template deploys and device changes
  - match: "catc__*deploy*"
    risk: critical
  - match: "catc__*"
    risk: medium

  # Meraki: org/network updates
  - match: "meraki__update*"
    risk: high
  - match: "meraki__*"
    risk: medium
```

Where the server has a matching *get* tool, add `snapshot`/`verify` (and `rollback` when an inverse exists) as in the
ISE example. For one-way operations (deploys), rely on approvals plus change windows plus `verify`.

## Webex

Create a bot at developer.webex.com, add it to a space, and configure:

```yaml
notifications:
  public_url: https://guardrail.example.com
  webex: {bot_token: "${WEBEX_BOT_TOKEN}", room_id: "${WEBEX_ROOM_ID}"}
```

The space receives a card for every pending change (with the CLI approve command) and for each outcome. Outcomes
include **🚨 rollback_failed**, which needs immediate human attention.

## Splunk

```yaml
notifications:
  splunk_hec:
    url: https://splunk.example.com:8088/services/collector/event
    token: ${SPLUNK_HEC_TOKEN}
    index: netsec
    sourcetype: mcp:guardrail:audit
```

Every audit record is forwarded (best-effort, async). Example searches:

```
sourcetype=mcp:guardrail:audit event=call.denied | stats count by identity, tool, reason
sourcetype=mcp:guardrail:audit event IN (change.rolled_back, change.rollback_failed)
```

## ITSM / ChatOps webhooks

```yaml
notifications:
  webhooks:
    - url: https://itsm.example.com/api/guardrail
      headers: {Authorization: "Bearer ${ITSM_TOKEN}"}
```

Body: `{"event": "change.pending", "change": {...summary...}}`. An ITSM can approve back through
`POST /guardrail/changes/{id}/approve` using an approver identity token.
