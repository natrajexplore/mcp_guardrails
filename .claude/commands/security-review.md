---
description: Run the independent security review on the current changes and act on the verdict
argument-hint: "[base branch, default main]"
---

1. Base branch: `$ARGUMENTS` (use `main` if empty). Determine the change set with `git diff <base>...HEAD --stat`
   plus uncommitted `git diff --stat`.
2. Delegate to the **security-reviewer** subagent with the list of changed files and a one-paragraph description of
   the intent of the change.
3. Present its findings table and verdict to the user unchanged.
4. If the verdict is BLOCK or APPROVE WITH FIXES: propose fixes for each finding (tests first), and wait for the
   user to confirm before editing security-critical files.
5. After fixes, run `/test` and re-run the review on the fix diff.
