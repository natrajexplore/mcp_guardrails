---
description: Pre-release checklist. Verifies everything needed to tag a release; never pushes or publishes
argument-hint: "<new version, e.g. 1.1.0>"
---

Target version: **$ARGUMENTS**. Work through each step, report pass/fail, and stop at the first hard failure.

1. Working tree clean (`git status`). Branch up to date with main.
2. `/test` is green. `ruff format --check src tests` passes.
3. Version bumped to $ARGUMENTS in **both** `pyproject.toml` and `src/guardrail_gateway/__init__.py`.
4. `CHANGELOG.md`: *Unreleased* content moved under `## [$ARGUMENTS] - <today>`. Entries are accurate against `git log`.
5. `python -m build` succeeds. Install the wheel into a fresh venv in a temp dir and run
   `guardrail version` and `guardrail config validate -c examples/lab-quickstart.yaml`.
6. Docs in sync: delegate to **docs-writer** for a verification pass (report-only).
7. Delegate to **security-reviewer** on `git diff <last tag>...HEAD`. The verdict must not be BLOCK.
8. Confirm no secrets: `git grep -nE "BEGIN .*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}"` returns nothing.
9. Print the exact commands for the **human** to run: `git tag -s v$ARGUMENTS -m "v$ARGUMENTS"` and `git push origin v$ARGUMENTS`.
   Do not run them yourself.
