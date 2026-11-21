"""Authorization, argument constraints, risk scoring, change windows and rate limits."""

from __future__ import annotations

import fnmatch
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from .classify import classify
from .config import ChangeWindow, GatewayConfig, IdentityConfig, RiskLevel, RuleConfig, ToolClass

RISK_ORDER: list[RiskLevel] = ["low", "medium", "high", "critical"]
RISK_SCORE: dict[RiskLevel, int] = {"low": 10, "medium": 40, "high": 70, "critical": 90}
_CLASS_BASE_RISK: dict[ToolClass, RiskLevel] = {"read": "low", "write": "medium", "destructive": "high"}
_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


@dataclass
class Decision:
    allowed: bool
    reason: str = ""


@dataclass
class ConstraintResult:
    violations: list[str] = field(default_factory=list)
    escalations: list[str] = field(default_factory=list)


@dataclass
class Assessment:
    tool: str
    tool_class: ToolClass
    risk: RiskLevel
    risk_score: int
    required_approvals: int
    rule: RuleConfig | None
    constraints: ConstraintResult

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "class": self.tool_class,
            "risk": self.risk,
            "risk_score": self.risk_score,
            "required_approvals": self.required_approvals,
            "rule": self.rule.match if self.rule else None,
            "violations": self.constraints.violations,
            "escalations": self.constraints.escalations,
            "has_snapshot": bool(self.rule and self.rule.snapshot),
            "has_verify": bool(self.rule and self.rule.verify),
            "has_rollback": bool(self.rule and self.rule.rollback),
        }


def bump(level: RiskLevel, steps: int = 1) -> RiskLevel:
    return RISK_ORDER[min(len(RISK_ORDER) - 1, RISK_ORDER.index(level) + steps)]


class PolicyEngine:
    def __init__(self, config: GatewayConfig) -> None:
        self.config = config

    # ---- rules & classification -------------------------------------------------
    def rule_for(self, tool: str) -> RuleConfig | None:
        return next((r for r in self.config.rules if fnmatch.fnmatchcase(tool, r.match)), None)

    def tool_class(self, tool: str, annotations: Any | None = None) -> ToolClass:
        rule = self.rule_for(tool)
        if rule and rule.tool_class:
            return rule.tool_class
        return classify(tool, annotations)

    # ---- authorization ----------------------------------------------------------
    def authorize(self, identity: IdentityConfig, tool: str, tool_class: ToolClass, risk: RiskLevel) -> Decision:
        roles = [self.config.roles[r] for r in identity.roles]
        for role in roles:
            if any(fnmatch.fnmatchcase(tool, pat) for pat in role.deny_tools):
                return Decision(False, f"tool '{tool}' is explicitly denied for identity '{identity.id}'")
        reasons = []
        for name, role in zip(identity.roles, roles, strict=True):
            if not any(fnmatch.fnmatchcase(tool, pat) for pat in role.allow_tools):
                reasons.append(f"role '{name}' does not allow '{tool}'")
                continue
            if tool_class not in role.classes:
                reasons.append(f"role '{name}' does not allow {tool_class} tools")
                continue
            if RISK_ORDER.index(risk) > RISK_ORDER.index(role.max_risk):
                reasons.append(f"role '{name}' max risk is {role.max_risk}, change is {risk}")
                continue
            return Decision(True, f"allowed by role '{name}'")
        return Decision(False, "; ".join(reasons) or "no role grants access")

    def can_approve(self, identity: IdentityConfig) -> bool:
        return any(self.config.roles[r].can_approve for r in identity.roles)

    def can_execute(self, identity: IdentityConfig) -> bool:
        return any(self.config.roles[r].can_execute for r in identity.roles)

    # ---- constraints & risk -----------------------------------------------------
    @staticmethod
    def evaluate_constraints(rule: RuleConfig | None, args: dict[str, Any]) -> ConstraintResult:
        result = ConstraintResult()
        if not rule:
            return result
        for c in rule.constraints:
            if c.arg not in args:
                continue
            value = args[c.arg]
            text = value if isinstance(value, str) else repr(value)
            problems = []
            if c.deny_regex and re.search(c.deny_regex, text):
                problems.append(f"'{c.arg}' matches forbidden pattern")
            if c.allow_regex and not re.fullmatch(c.allow_regex, text):
                problems.append(f"'{c.arg}' does not match required pattern")
            if c.allowed_values is not None and value not in c.allowed_values:
                problems.append(f"'{c.arg}'={value!r} is not one of {c.allowed_values}")
            if c.max_length is not None and len(text) > c.max_length:
                problems.append(f"'{c.arg}' longer than {c.max_length}")
            if problems:
                msg = c.message or "; ".join(problems)
                (result.violations if c.effect == "deny" else result.escalations).append(msg)
        return result

    def assess(self, tool: str, args: dict[str, Any], annotations: Any | None = None) -> Assessment:
        rule = self.rule_for(tool)
        tclass = self.tool_class(tool, annotations)
        risk: RiskLevel = rule.risk if rule and rule.risk else _CLASS_BASE_RISK[tclass]
        constraints = self.evaluate_constraints(rule, args)
        if constraints.escalations:
            risk = bump(risk, len(constraints.escalations))
        if tclass == "read":
            approvals = 0
        elif rule and rule.require_approvals is not None:
            approvals = rule.require_approvals
        else:
            approvals = self.config.approvals.by_risk.get(risk, 1)
        return Assessment(tool, tclass, risk, RISK_SCORE[risk], approvals, rule, constraints)

    # ---- change windows ---------------------------------------------------------
    def windows_for(self, rule: RuleConfig | None) -> list[ChangeWindow]:
        if rule and rule.change_windows is not None:
            return rule.change_windows
        return self.config.change_windows

    @staticmethod
    def in_window(windows: list[ChangeWindow], now: datetime | None = None) -> bool:
        if not windows:
            return True
        for w in windows:
            local = (now or datetime.now(tz=UTC)).astimezone(ZoneInfo(w.tz))
            start = datetime.strptime(w.start, "%H:%M").time()
            end = datetime.strptime(w.end, "%H:%M").time()
            today = _DAYS[local.weekday()]
            yesterday = _DAYS[(local - timedelta(days=1)).weekday()]
            t = local.time()
            if start <= end:
                if today in w.days and start <= t < end:
                    return True
            else:  # crosses midnight: window belongs to the day it starts on
                if today in w.days and t >= start:
                    return True
                if yesterday in w.days and t < end:
                    return True
        return False


class RateLimiter:
    """Sliding one-minute window per (identity, kind)."""

    def __init__(self, writes_per_minute: int, reads_per_minute: int) -> None:
        self.limits = {"write": writes_per_minute, "read": reads_per_minute}
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, identity: str, kind: str, now: float | None = None) -> bool:
        kind = "read" if kind == "read" else "write"
        now = time.monotonic() if now is None else now
        q = self._events[(identity, kind)]
        while q and now - q[0] >= 60:
            q.popleft()
        if len(q) >= self.limits[kind]:
            return False
        q.append(now)
        return True
