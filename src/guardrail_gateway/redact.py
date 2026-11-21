"""Secret redaction and stable hashing of tool arguments."""

from __future__ import annotations

import hashlib
import json
from typing import Any

REDACTED = "***REDACTED***"


def redact(value: Any, keys: list[str]) -> Any:
    lowered = [k.lower() for k in keys]

    def walk(v: Any) -> Any:
        if isinstance(v, dict):
            out = {}
            for k, item in v.items():
                if any(s in str(k).lower().replace("-", "_") for s in lowered):
                    out[k] = REDACTED
                else:
                    out[k] = walk(item)
            return out
        if isinstance(v, list):
            return [walk(i) for i in v]
        return v

    return walk(value)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_of(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()
