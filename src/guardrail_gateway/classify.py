"""Decide whether an upstream tool reads, writes or destroys state.

Order of precedence:
1. an explicit `class:` on the first matching policy rule;
2. MCP tool annotations (readOnlyHint / destructiveHint) published by the upstream;
3. verb heuristics on the tool name;
4. anything still unknown is treated as a write (fail-safe).
"""

from __future__ import annotations

import re
from typing import Any

from .config import ToolClass

_READ_VERBS = {
    "get",
    "list",
    "show",
    "search",
    "describe",
    "read",
    "fetch",
    "find",
    "query",
    "lookup",
    "count",
    "check",
    "validate",
    "inspect",
    "export",
    "audit",
    "analyze",
    "analyse",
    "explain",
    "simulate",
    "whatif",
    "compare",
    "diff",
    "status",
    "health",
    "ping",
}
_DESTRUCTIVE_VERBS = {
    "delete",
    "remove",
    "purge",
    "clear",
    "reset",
    "reload",
    "reboot",
    "restart",
    "shutdown",
    "erase",
    "wipe",
    "revoke",
    "quarantine",
    "disconnect",
    "terminate",
    "factory",
}


def _first_verb(tool_name: str) -> str:
    # strip namespace "ise__get_sgt" -> "get_sgt", then split snake/kebab/camel case
    bare = tool_name.split("__", 1)[-1]
    words = re.split(r"[_\-\s]+|(?<=[a-z0-9])(?=[A-Z])", bare)
    return next((w.lower() for w in words if w), "")


def classify(tool_name: str, annotations: Any | None = None) -> ToolClass:
    """Classify an upstream tool from its annotations and name."""
    if annotations is not None:
        read_only = getattr(annotations, "read_only_hint", None)
        destructive = getattr(annotations, "destructive_hint", None)
        if read_only is True:
            return "read"
        if destructive is True:
            return "destructive"
        if read_only is False and destructive is False:
            return "write"
    verb = _first_verb(tool_name)
    if verb in _READ_VERBS:
        return "read"
    if verb in _DESTRUCTIVE_VERBS:
        return "destructive"
    return "write"
