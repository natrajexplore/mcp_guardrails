---
description: Run the end-to-end lab demo (propose → human approve → execute → verify → rollback) and capture output for docs or a video script
---

1. Validate: `guardrail config validate -c examples/lab-quickstart.yaml`.
2. Tell the user to start the gateway in their own terminal (long-running; do not start it yourself):
   `GUARDRAIL_AUDIT_HMAC_KEY=$(python -c "import secrets;print(secrets.token_hex(32))") guardrail serve -c examples/lab-quickstart.yaml`
3. Write a short Python MCP client script under `/tmp` (never in the repo) that uses the **demo agent token** to:
   call `ise__update_sgacl` with a justification and print the `change_id` and preview.
4. **Stop.** Ask the user to approve as a human:
   `guardrail changes approve <id> -c examples/lab-quickstart.yaml --as alice`. You must not run approve yourself.
5. After the user confirms, call `guardrail_execute_change` and show `succeeded` with the verification result.
6. Rollback demo: call `ise__set_fault` with `corrupt_once` (auto-approved, low risk), repeat steps 3-5, and show
   `rolled_back` with `restored_state_matches_snapshot: true`.
7. Run `guardrail audit verify -c examples/lab-quickstart.yaml` and show the result.
8. Summarize as a numbered demo script with the exact outputs (useful for the Code Exchange video).
