---
description: Add or change a gateway policy rule for an upstream MCP tool, with tests and docs
argument-hint: "<upstream>__<tool> <intent, e.g. 'require 2 approvals, rollback via get_x'>"
---

Request: $ARGUMENTS

1. Delegate the design to the **policy-author** subagent, giving it the request and the target config file
   (`examples/*.yaml` or the one the user names).
2. Show the proposed rule and the tool → class/risk/approvals table, and wait for the user's OK.
3. Apply it, then run `guardrail config validate -c <file>`.
4. Add or extend a test in `tests/test_engine.py` proving the rule (approval count, constraint denial, verify and rollback).
5. Run `/test`. Update `docs/integrations.md` and the CHANGELOG.
