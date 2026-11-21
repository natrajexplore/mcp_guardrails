#!/usr/bin/env python3
"""PostToolUse hook: auto-format and lint-fix Python files Claude just edited (never blocks)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    path = str((event.get("tool_input") or {}).get("file_path") or "")
    if not path.endswith(".py") or not shutil.which("ruff"):
        return 0
    subprocess.run(["ruff", "format", "--quiet", path], check=False)
    subprocess.run(["ruff", "check", "--fix", "--quiet", path], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
