---
description: Audit the repo against Cisco DevNet Code Exchange submission requirements and report gaps
---

Check each item, mark ✅/❌ with evidence (file and line), and propose concrete fixes for ❌ items:

1. **Relevant to Cisco technology**: README states the Cisco platforms (ISE, Secure Firewall/FMC, Catalyst Center, Meraki via MCP).
2. **Public GitHub repo** with a description and topics (`cisco`, `mcp`, `ise`, `ai-agents`, `guardrails`, `zero-trust`). Remind the human to set these in GitHub.
3. **OSI license**: `LICENSE` is Apache-2.0 with the copyright line filled in; `NOTICE` is present.
4. **README sections**: Use Case, Related Sandbox, Installation, Usage/Quick start, How to test, Known issues,
   Getting help, Getting involved, Credits, Licensing info. Badges at the top.
5. `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md` are present and accurate.
6. Every Quick start command in the README actually works. Run the offline ones
   (lab-quickstart config validate).
7. CI workflow exists and the badge URL matches the repo path.
8. No secrets, internal hostnames or customer data in the repo or git history (`git log -p | grep -iE "password|token"` spot check).
9. Remind the human of the steps only they can do: submit the repo URL at developer.cisco.com/codeexchange
   (*Submit project*), then add the Code Exchange badge to the README once it is approved.
