---
description: Run lint, format check and the full test suite; fix failures caused by the current change
allowed-tools: Bash(pytest:*), Bash(python -m pytest:*), Bash(ruff check:*), Bash(ruff format:*), Read, Grep, Edit
argument-hint: "[optional pytest selector]"
---

1. `ruff format src tests` then `ruff check src tests`. Fix any remaining lint issues properly (no blanket `noqa`).
2. Run `pytest -q -p no:asyncio $ARGUMENTS` (the whole suite if no selector was given).
3. For each failure: decide whether the **test** or the **code** is wrong, by reading AGENTS.md invariants and
   docs/security-model.md. Never weaken an assertion just to pass.
4. Re-run until green, then run the full suite once more if you used a selector.
5. Report: the pytest summary line, files changed, and the root cause of each failure fixed.
