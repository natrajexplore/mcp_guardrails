"""Minimal, sandboxed {{path.to.value}} templating for snapshot/verify/rollback specs.

No expressions, filters or code execution: only dotted lookups into a context
dict (args, snapshot, change). If a string is exactly one placeholder the raw
value is returned, so lists/dicts/ints survive the round trip.
"""

from __future__ import annotations

import json
import re
from typing import Any

_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_\.\-\[\]]*)\s*\}\}")


class TemplateError(KeyError):
    pass


def lookup(context: dict[str, Any], path: str) -> Any:
    cur: Any = context
    for part in re.split(r"\.|\[|\]", path):
        if part == "":
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            raise TemplateError(f"template path '{path}' not found (failed at '{part}')")
    return cur


def render(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        whole = _PLACEHOLDER.fullmatch(value.strip())
        if whole:
            return lookup(context, whole.group(1))

        def repl(m: re.Match[str]) -> str:
            v = lookup(context, m.group(1))
            return v if isinstance(v, str) else json.dumps(v, sort_keys=True)

        return _PLACEHOLDER.sub(repl, value)
    if isinstance(value, list):
        return [render(v, context) for v in value]
    if isinstance(value, dict):
        return {k: render(v, context) for k, v in value.items()}
    return value
