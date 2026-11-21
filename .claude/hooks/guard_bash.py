#!/usr/bin/env python3
"""PreToolUse hook for Bash: stop commands an AI agent must never run in this repo.

Defense in depth on top of the permission rules in .claude/settings.json.
"""

from __future__ import annotations

import json
import re
import sys

RULES = [
    (
        r"guardrail\s+changes\s+(approve|reject|execute|recover)",
        "Approving, rejecting, executing or recovering changes is a HUMAN action. Ask the user to run it.",
    ),
    (r"/guardrail/changes/[^/\s]+/(approve|reject|execute)", "Calling the approval REST API is a HUMAN action."),
    (r"git\s+push\b.*(--force|-f\b)", "Force-pushing is not allowed."),
    (
        r"\b(ISE_PASSWORD|GUARDRAIL_TOKEN\w*|WEBEX_BOT_TOKEN|SPLUNK_HEC_TOKEN)=\S",
        "Do not put secrets on the command line; they end up in shell history and logs.",
    ),
    (
        r"(?:^|[;&|]\s*)(?:sudo\s+)?rm\s+-[a-z]*r[a-z]*f?\s+(/|~|\$HOME|\.\.?)(\s|$)",
        "Recursive delete of a root/home/repo directory is blocked.",
    ),
    (r"\b(verify\s*=\s*False|ISE_VERIFY_TLS=false)\b", "Disabling TLS verification needs explicit human approval; ask first."),
]


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    cmd = str((event.get("tool_input") or {}).get("command") or "")
    for pattern, reason in RULES:
        if re.search(pattern, cmd, re.I):
            print(f"Blocked by repo policy: {reason} Command: {cmd[:200]}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
