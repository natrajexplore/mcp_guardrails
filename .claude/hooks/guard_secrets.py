#!/usr/bin/env python3
"""PreToolUse hook: block writes that would put secrets or key material into the repo.

Claude Code passes the tool call as JSON on stdin. Exit code 2 blocks the call and
feeds stderr back to Claude so it can correct course. Exit 0 allows it.
"""

from __future__ import annotations

import json
import re
import sys

BLOCKED_PATHS = re.compile(
    r"(^|/)(\.env(\..*)?|.*\.pem|.*\.key|.*\.p12|.*\.pfx|id_rsa.*|credentials\.json|secrets?\.(ya?ml|json))$", re.I
)
ALLOWED_PATHS = re.compile(r"(^|/)\.env\.example$", re.I)
PATTERNS = {
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\b(ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{20,}\b"),
    "Guardrail bearer token": re.compile(r"\bgrg_[A-Za-z0-9_\-]{30,}\b"),
    "Splunk HEC token": re.compile(r"Splunk [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I),
    "hard-coded password": re.compile(
        r"""(?i)\b(password|passwd|secret|api[_-]?key|bot_token|token)\b["']?\s*[:=]\s*["'](?![$<{*])[^"'\s]{12,}["']"""
    ),
}


def texts(tool_input: dict) -> list[str]:
    out = []
    for key in ("content", "new_string"):
        if isinstance(tool_input.get(key), str):
            out.append(tool_input[key])
    for edit in tool_input.get("edits") or []:
        if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
            out.append(edit["new_string"])
    return out


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    tool_input = event.get("tool_input") or {}
    path = str(tool_input.get("file_path") or "")
    if path and BLOCKED_PATHS.search(path) and not ALLOWED_PATHS.search(path):
        print(
            f"Blocked: '{path}' is a secrets/key file. Keep secrets in environment variables or a secret manager; "
            "commit only *.example templates.",
            file=sys.stderr,
        )
        return 2
    for text in texts(tool_input):
        for label, rx in PATTERNS.items():
            if rx.search(text):
                print(
                    f"Blocked: the content looks like it contains a {label}. Use an environment variable reference "
                    "(e.g. ${VAR}) or a placeholder like <token> instead. Lab demo tokens must stay obviously fake.",
                    file=sys.stderr,
                )
                return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
