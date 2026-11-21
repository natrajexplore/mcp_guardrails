"""The guardrail engine: every tool call from an agent goes through `GuardrailEngine.call`.

Reads are authorized, rate-limited, audited and forwarded. Writes become change
requests: they are assessed (class, risk, constraints), previewed with the
rule's snapshot call, and held until enough humans approve. Execution re-checks
the change window and state drift, snapshots, calls the upstream, verifies the
outcome and rolls back automatically if verification fails.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import anyio
from mcp import types

from .audit import AuditLog
from .config import GatewayConfig, IdentityConfig, VerifySpec
from .notify import Notifier
from .policy import RISK_ORDER, Decision, PolicyEngine, RateLimiter
from .redact import redact, sha256_of
from .store import Change, ChangeStore, TransitionError, utcnow
from .templating import TemplateError, lookup, render
from .upstreams import DEFAULT_UPSTREAM_TIMEOUT, SEP, UpstreamError, UpstreamManager, UpstreamTool, result_json, result_text

log = logging.getLogger("guardrail.engine")

JUSTIFICATION_ARG = "guardrail_justification"
MAX_JUSTIFICATION = 2000
MAX_COMMENT = 2000  # approval comments and reject/cancel reasons
GATEWAY_PREFIX = "guardrail_"


class GuardrailDenied(Exception):
    """A call refused by policy. The message is safe to show to the agent."""


@dataclass
class CallOutcome:
    """Result returned to the MCP layer."""

    result: types.CallToolResult

    @classmethod
    def data(cls, payload: dict[str, Any], is_error: bool = False) -> CallOutcome:
        text = json.dumps(payload, indent=2, default=str)
        return cls(
            types.CallToolResult(
                content=[types.TextContent(type="text", text=text)],
                structured_content=payload,
                is_error=is_error,
            )
        )

    @classmethod
    def error(cls, message: str, **extra: Any) -> CallOutcome:
        return cls.data({"status": "denied", "error": message, **extra}, is_error=True)


def _snapshot_view(result: types.CallToolResult) -> dict[str, Any]:
    return {"text": result_text(result), "json": result_json(result), "is_error": bool(result.is_error)}


class GuardrailEngine:
    def __init__(
        self,
        config: GatewayConfig,
        upstreams: UpstreamManager,
        store: ChangeStore,
        audit: AuditLog,
        notifier: Notifier | None = None,
    ) -> None:
        self.config = config
        self.policy = PolicyEngine(config)
        self.upstreams = upstreams
        self.store = store
        self.audit = audit
        self.notifier = notifier or Notifier(config.notifications)
        self.rate = RateLimiter(config.rate_limits.writes_per_minute, config.rate_limits.reads_per_minute)
        self._now: datetime | None = None  # test hook for change windows

    # ------------------------------------------------------------------ identity
    def identity(self, identity_id: str | None) -> IdentityConfig | None:
        return self.config.identity(identity_id) if identity_id else None

    def authenticate_token(self, token: str) -> IdentityConfig | None:
        digest = hashlib.sha256(token.encode()).hexdigest()
        matches = []
        for ident in self.config.identities:
            expected = ident.token_digest()
            if expected and hmac.compare_digest(expected, digest):
                matches.append(ident)
        # A token shared by two identities is ambiguous (e.g. an agent token reused for an approver): refuse it.
        return matches[0] if len(matches) == 1 else None

    # ------------------------------------------------------------------ catalog
    def _visibility(self, identity: IdentityConfig, qualified: str, annotations: Any) -> Decision:
        """Whether a tool appears in this identity's tools/list (authorized at its argument-free base risk)."""
        tclass = self.policy.tool_class(qualified, annotations)
        rule = self.policy.rule_for(qualified)
        base_risk = rule.risk if rule and rule.risk else {"read": "low", "write": "medium", "destructive": "high"}[tclass]
        return self.policy.authorize(identity, qualified, tclass, base_risk)

    def _resolve_visible(self, identity: IdentityConfig, qualified: str, audit_event: str | None = None) -> UpstreamTool:
        """Resolve a tool, treating tools hidden from this identity exactly like tools that do not exist.

        The agent cannot tell a hidden tool from a missing one (invariant 3); the real reason is audited.
        """
        try:
            ut = self.upstreams.resolve(qualified)
        except UpstreamError:
            if audit_event:  # same event and shape as a hidden tool, so the audit log can't be used to tell them apart
                self.audit.write(audit_event, identity=identity.id, tool=qualified, reason="unknown tool")
            raise GuardrailDenied(f"unknown tool '{qualified}'") from None
        visible = self._visibility(identity, qualified, ut.tool.annotations)
        if not visible.allowed:
            if audit_event:
                self.audit.write(audit_event, identity=identity.id, tool=qualified, reason=f"hidden tool: {visible.reason}")
            raise GuardrailDenied(f"unknown tool '{qualified}'")
        return ut

    def visible_tools(self, identity: IdentityConfig) -> list[types.Tool]:
        tools: list[types.Tool] = []
        for qualified, ut in sorted(self.upstreams.tools.items()):
            if not self._visibility(identity, qualified, ut.tool.annotations).allowed:
                continue
            tools.append(self._decorate(qualified, ut.tool, self.policy.tool_class(qualified, ut.tool.annotations)))
        tools.extend(self._gateway_tools())
        return tools

    def _decorate(self, qualified: str, tool: types.Tool, tclass: str) -> types.Tool:
        schema = copy.deepcopy(tool.input_schema or {"type": "object", "properties": {}})
        desc = tool.description or ""
        update: dict[str, Any] = {}
        if tclass == "read":
            tag = "[guardrail: read-only, audited]"
        else:
            assessment = self.policy.assess(qualified, {}, tool.annotations)
            need = assessment.required_approvals
            tag = (
                f"[guardrail: {tclass}, risk {assessment.risk}, "
                + (f"needs {need} human approval(s); returns a change ID" if need else "auto-approved, verified")
                + "]"
            )
            schema.setdefault("properties", {})[JUSTIFICATION_ARG] = {
                "type": "string",
                "description": "Why this change is needed (ticket number, incident, intent). Shown to approvers.",
            }
            if self.config.approvals.require_justification:
                req = list(schema.get("required", []))
                if JUSTIFICATION_ARG not in req:
                    req.append(JUSTIFICATION_ARG)
                schema["required"] = req
            # A write returns the gateway's change payload (status, change_id, ...), not the upstream result,
            # so the upstream outputSchema would make spec-compliant clients reject every write response.
            update["output_schema"] = None
        update |= {"name": qualified, "description": f"{tag} {desc}".strip(), "input_schema": schema}
        return tool.model_copy(update=update)

    def _gateway_tools(self) -> list[types.Tool]:
        def t(
            name: str, desc: str, props: dict[str, Any] | None = None, required: list[str] | None = None, read_only: bool = True
        ) -> types.Tool:
            return types.Tool(
                name=GATEWAY_PREFIX + name,
                description=desc,
                input_schema={"type": "object", "properties": props or {}, "required": required or []},
                annotations=types.ToolAnnotations(read_only_hint=read_only, destructive_hint=False),
            )

        cid = {"change_id": {"type": "string", "description": "Change ID, e.g. CHG-20261120-A1B2C3"}}
        tools = [
            t("whoami", "Show the caller identity, roles and what classes of tools it may use."),
            t("status", "Gateway health: upstream connections, tool counts, approval policy."),
            t(
                "explain_tool",
                "Dry-run policy assessment of a tool call without creating a change: class, risk, "
                "required approvals, constraint results and whether you are authorized.",
                {"tool": {"type": "string"}, "arguments": {"type": "object"}},
                ["tool"],
            ),
            t(
                "list_changes",
                "List change requests, newest first.",
                {
                    "status": {
                        "type": "string",
                        "enum": [
                            "pending",
                            "approved",
                            "blocked",
                            "executing",
                            "succeeded",
                            "failed",
                            "rolled_back",
                            "rollback_failed",
                            "rejected",
                            "expired",
                        ],
                    },
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                },
            ),
            t(
                "get_change",
                "Full detail of one change: arguments, approvals, preview, snapshot, verification.",
                cid,
                ["change_id"],
            ),
            t(
                "execute_change",
                "Execute an APPROVED change: checks change window and state drift, snapshots, "
                "applies, verifies, and rolls back automatically on failed verification.",
                cid,
                ["change_id"],
                read_only=False,
            ),
            t(
                "cancel_change",
                "Withdraw a change you requested (or reject it, if you are an approver).",
                {**cid, "reason": {"type": "string"}},
                ["change_id", "reason"],
                read_only=False,
            ),
        ]
        if self.config.approvals.allow_mcp_approval:
            tools.append(
                t(
                    "approve_change",
                    "Approve a pending change (approver role only; not your own change).",
                    {**cid, "comment": {"type": "string"}},
                    ["change_id"],
                    read_only=False,
                )
            )
        return tools

    # ------------------------------------------------------------------ dispatch
    async def call(self, identity: IdentityConfig, tool: str, arguments: dict[str, Any] | None) -> CallOutcome:
        args = dict(arguments or {})
        try:
            if tool.startswith(GATEWAY_PREFIX):
                return await self._gateway_call(identity, tool[len(GATEWAY_PREFIX) :], args)
            return await self._proxied_call(identity, tool, args)
        except GuardrailDenied as exc:
            return CallOutcome.error(str(exc))
        except UpstreamError as exc:
            self.audit.write("call.error", identity=identity.id, tool=tool, error=str(exc)[:500])
            return CallOutcome.error(str(exc))
        except Exception as exc:  # last resort: never leak a stack trace to the agent, always leave an audit trail
            log.exception("unexpected error handling %s for %s", tool, identity.id)
            try:
                self.audit.write("call.error", identity=identity.id, tool=tool, error=type(exc).__name__)
            except Exception:  # the audit log itself may be what failed; the log line above still records it
                log.exception("could not audit the error above")
            return CallOutcome.error(f"internal gateway error ({type(exc).__name__}); the event was logged")

    async def _proxied_call(self, identity: IdentityConfig, tool: str, args: dict[str, Any]) -> CallOutcome:
        ut = self._resolve_visible(identity, tool, audit_event="call.denied")
        justification = str(args.pop(JUSTIFICATION_ARG, "") or "").strip()
        assessment = self.policy.assess(tool, args, ut.tool.annotations)
        safe_args = redact(args, self.config.redact_keys)

        decision = self.policy.authorize(identity, tool, assessment.tool_class, assessment.risk)
        if not decision.allowed:
            self.audit.write("call.denied", identity=identity.id, tool=tool, args=safe_args, reason=decision.reason)
            raise GuardrailDenied(decision.reason)
        if not self.rate.check(identity.id, assessment.tool_class):
            self.audit.write("call.rate_limited", identity=identity.id, tool=tool)
            raise GuardrailDenied(f"rate limit exceeded for {assessment.tool_class} calls; retry in a minute")

        if assessment.tool_class == "read":
            try:
                result = await self.upstreams.call(tool, args)
            except Exception as exc:
                self.audit.write(
                    "call.read", identity=identity.id, tool=tool, args=safe_args, outcome="error", error=str(exc)[:500]
                )
                raise UpstreamError(f"upstream call failed: {type(exc).__name__}: {str(exc)[:300]}") from exc
            self.audit.write(
                "call.read", identity=identity.id, tool=tool, args=safe_args, outcome="error" if result.is_error else "ok"
            )
            return CallOutcome(result)

        # ---- write / destructive: becomes a change request
        if assessment.constraints.violations:
            self.audit.write(
                "change.denied", identity=identity.id, tool=tool, args=safe_args, violations=assessment.constraints.violations
            )
            raise GuardrailDenied("policy constraint violated: " + "; ".join(assessment.constraints.violations))
        if self.config.approvals.require_justification and not justification:
            self.audit.write("change.denied", identity=identity.id, tool=tool, args=safe_args, reason="missing justification")
            raise GuardrailDenied(f"write calls require '{JUSTIFICATION_ARG}' (ticket, incident or intent)")
        if len(justification) > MAX_JUSTIFICATION:
            self.audit.write("change.denied", identity=identity.id, tool=tool, args=safe_args, reason="justification too long")
            raise GuardrailDenied(f"'{JUSTIFICATION_ARG}' is too long (max {MAX_JUSTIFICATION} characters)")

        preview = None
        if assessment.rule and assessment.rule.snapshot:
            preview = await self._run_spec(assessment.rule.snapshot, {"args": args})

        change = self.store.create(
            ttl_minutes=self.config.approvals.change_ttl_minutes,
            requester=identity.id,
            tool=tool,
            args=args,
            args_sha256=sha256_of(args),
            tool_class=assessment.tool_class,
            risk=assessment.risk,
            risk_score=assessment.risk_score,
            required_approvals=assessment.required_approvals,
            justification=justification,
            preview_before=preview,
        )
        self.audit.write(
            "change.created",
            identity=identity.id,
            tool=tool,
            change_id=change.id,
            args=safe_args,
            args_sha256=change.args_sha256,
            risk=change.risk,
            required_approvals=change.required_approvals,
            justification=justification,
            escalations=assessment.constraints.escalations,
        )

        if change.required_approvals == 0:
            change.approvals.append(
                {
                    "by": "policy:auto",
                    "at": utcnow().isoformat(timespec="seconds"),
                    "comment": f"risk {change.risk} needs no human approval",
                    "channel": "policy",
                }
            )
            try:
                self.store.transition(change, "approved", "auto-approved by policy")
            except TransitionError as exc:
                raise self._deny("change.approve_denied", identity, change.id, str(exc)) from exc
            self.audit.write("change.approved", identity="policy:auto", change_id=change.id)
            return await self.execute(identity, change.id)

        self.notifier.change_event("change.pending", change)
        return CallOutcome.data(
            {
                "status": "approval_required",
                "change_id": change.id,
                "message": (
                    f"Change held for human approval ({change.required_approvals} needed). Nothing was applied. "
                    f"After approval, call guardrail_execute_change with change_id={change.id}."
                ),
                "assessment": assessment.as_dict(),
                "current_state_preview": preview,
                "expires_at": change.expires_at,
            }
        )

    # ------------------------------------------------------------------ lifecycle
    def approve(self, approver: IdentityConfig, change_id: str, comment: str = "", channel: str = "cli") -> Change:
        deny = "change.approve_denied"
        if channel == "mcp" and not self.config.approvals.allow_mcp_approval:
            raise self._deny(deny, approver, change_id, "approval over MCP is disabled; approve with the CLI or REST API")
        if not self.policy.can_approve(approver):
            raise self._deny(deny, approver, change_id, f"identity '{approver.id}' cannot approve changes")
        if len(comment) > MAX_COMMENT:
            raise self._deny(deny, approver, change_id, f"comment is too long (max {MAX_COMMENT} characters)")
        change = self._get(change_id)
        if change.status != "pending":
            raise self._deny(deny, approver, change.id, f"{change.id} is {change.status}, only pending changes can be approved")
        if approver.id == change.requester and not self.config.approvals.allow_self_approval:
            raise self._deny(deny, approver, change.id, "separation of duties: you cannot approve your own change")
        if any(a["by"] == approver.id for a in change.approvals):
            raise self._deny(deny, approver, change.id, f"'{approver.id}' already approved {change.id}")
        approver_roles = [self.config.roles[r] for r in approver.roles if self.config.roles[r].can_approve]
        if all(RISK_ORDER.index(change.risk) > RISK_ORDER.index(r.max_risk) for r in approver_roles):  # type: ignore[arg-type]
            raise self._deny(deny, approver, change.id, f"'{approver.id}' may not approve {change.risk}-risk changes")
        change.approvals.append(
            {"by": approver.id, "at": utcnow().isoformat(timespec="seconds"), "comment": comment, "channel": channel}
        )
        try:
            self.store.save(change)
        except TransitionError as exc:  # rejected/expired concurrently (e.g. by another process)
            raise self._deny(deny, approver, change.id, str(exc)) from exc
        self.audit.write(
            "change.approval",
            identity=approver.id,
            change_id=change.id,
            channel=channel,
            comment=comment,
            approvals=len(change.approvals),
            required=change.required_approvals,
        )
        if len(change.approvals) >= change.required_approvals:
            try:
                self.store.transition(change, "approved", f"approved by {', '.join(a['by'] for a in change.approvals)}")
            except TransitionError as exc:
                raise self._deny(deny, approver, change.id, str(exc)) from exc
            self.audit.write("change.approved", identity=approver.id, change_id=change.id)
            self.notifier.change_event("change.approved", change)
        return change

    def reject(self, actor: IdentityConfig, change_id: str, reason: str, channel: str = "cli") -> Change:
        deny = "change.reject_denied"
        if len(reason) > MAX_COMMENT:
            raise self._deny(deny, actor, change_id, f"reason is too long (max {MAX_COMMENT} characters)")
        change = self._get_visible(actor, change_id, deny)
        if actor.id != change.requester and not self.policy.can_approve(actor):
            raise self._deny(deny, actor, change.id, "only the requester or an approver can reject/cancel a change")
        try:
            self.store.transition(change, "rejected", f"{actor.id}: {reason}")
        except TransitionError as exc:
            raise self._deny(deny, actor, change.id, str(exc)) from exc
        self.audit.write("change.rejected", identity=actor.id, change_id=change.id, reason=reason, channel=channel)
        self.notifier.change_event("change.rejected", change)
        return change

    async def execute(self, actor: IdentityConfig, change_id: str) -> CallOutcome:
        deny = "change.execute_denied"
        change = self._get_visible(actor, change_id, deny)
        if change.status not in ("approved", "blocked"):
            raise self._deny(deny, actor, change.id, f"{change.id} is {change.status}; only approved changes can be executed")
        if not self.policy.can_execute(actor):
            raise self._deny(deny, actor, change.id, f"identity '{actor.id}' cannot execute changes")
        if actor.id != change.requester and not self.policy.can_approve(actor):
            raise self._deny(deny, actor, change.id, "only the requester or an approver can execute this change")
        if sha256_of(change.args) != change.args_sha256:
            raise self._deny(deny, actor, change.id, "change arguments were modified after approval; refusing to execute")
        requester = self.identity(change.requester)
        if requester is None and change.requester != "policy:auto":
            raise self._deny(deny, actor, change.id, f"requester '{change.requester}' no longer exists")
        if requester is not None:
            decision = self.policy.authorize(requester, change.tool, change.tool_class, change.risk)  # type: ignore[arg-type]
            if not decision.allowed:
                raise self._deny(deny, actor, change.id, f"requester is no longer authorized: {decision.reason}")

        rule = self.policy.rule_for(change.tool)
        windows = self.policy.windows_for(rule)
        if not self.policy.in_window(windows, self._now):
            return self._block(change, actor, "outside the allowed change window")

        ctx: dict[str, Any] = {"args": change.args, "change": {"id": change.id, "requester": change.requester}}
        snapshot = None
        if rule and rule.snapshot:
            snapshot = await self._run_spec(rule.snapshot, ctx)
            if (
                self.config.approvals.block_on_state_drift
                and change.preview_before is not None
                and snapshot is not None
                and snapshot != change.preview_before
            ):
                return self._block(
                    change, actor, "state drifted since the change was reviewed; re-submit so approvers see the current state"
                )
            ctx["snapshot"] = snapshot

        claimed = self.store.claim_for_execution(change.id)
        if claimed is None:
            raise self._deny(deny, actor, change.id, f"{change.id} is already being executed or changed state")
        # From here on the change is 'executing' and its only way out is a recorded outcome. The rest is shielded
        # from anyio cancellation (client disconnect, notifications/cancelled) so an apply is always followed by
        # verify/rollback, and bounded by an overall deadline so a hung upstream cannot pin it forever. A native
        # asyncio cancel (Ctrl-C under anyio.run) bypasses the shield: it is recorded synchronously, then re-raised.
        try:
            with anyio.fail_after(self._execution_deadline(claimed.tool), shield=True):
                return await self._execute_claimed(claimed, actor, rule, ctx, snapshot)
        except Exception as exc:  # includes TimeoutError from the deadline
            return self._execute_crashed(claimed, actor, exc)
        except BaseException as exc:
            self._execute_crashed(claimed, actor, exc)
            raise

    def recover(self, actor: IdentityConfig, change_id: str, reason: str) -> Change:
        """Operator recovery for a change stuck in 'executing' (e.g. the gateway process was killed mid-change).

        Only an approver may do it, and only after the execution deadline has passed, so an in-flight execution is
        never pre-empted. The change becomes 'rollback_failed' (outcome unknown: a human must check the device);
        nothing is applied or rolled back by this call.
        """
        deny = "change.recover_denied"
        if not self.policy.can_approve(actor):
            raise self._deny(deny, actor, change_id, f"identity '{actor.id}' cannot recover changes")
        if not reason.strip() or len(reason) > MAX_COMMENT:
            raise self._deny(deny, actor, change_id, f"a reason of 1-{MAX_COMMENT} characters is required")
        change = self._get(change_id)
        if change.status != "executing":
            raise self._deny(deny, actor, change.id, f"{change.id} is {change.status}; only 'executing' changes can be recovered")
        deadline = self._execution_deadline(change.tool)
        age = (utcnow() - datetime.fromisoformat(change.updated_at)).total_seconds()
        if age < deadline:
            raise self._deny(
                deny,
                actor,
                change.id,
                f"{change.id} may still be running ({int(age)}s of a {int(deadline)}s deadline); retry later",
            )
        try:
            self.store.transition(
                change,
                "rollback_failed",
                f"recovered by {actor.id} after {int(age)}s: {reason}; outcome unknown, verify the device",
            )
        except TransitionError as exc:
            raise self._deny(deny, actor, change.id, str(exc)) from exc
        self.audit.write("change.recovered", identity=actor.id, change_id=change.id, reason=reason, stale_seconds=int(age))
        self.notifier.change_event("change.rollback_failed", change)
        return change

    def _execution_deadline(self, tool: str) -> float:
        """Upper bound for apply + verify + rollback + restore check (four upstream calls) plus slack."""
        # Derived from config only, so the CLI's offline engine (no upstream catalog) and the server agree;
        # `changes recover` relies on that to never pre-empt a live execution.
        rule = self.policy.rule_for(tool)
        tools = [tool] + [spec.tool for spec in (rule.snapshot, rule.verify, rule.rollback) if spec] if rule else [tool]
        per_call = max(self._upstream_timeout(t.split(SEP, 1)[0]) for t in tools)
        return 4 * per_call + 30

    def _upstream_timeout(self, upstream: str) -> float:
        cfg = self.config.upstreams.get(upstream)
        if cfg is not None:
            return cfg.timeout_seconds
        # in-process target or unknown prefix: assume the longest configured timeout (never shorter than the default)
        return max([DEFAULT_UPSTREAM_TIMEOUT] + [c.timeout_seconds for c in self.config.upstreams.values()])

    async def _execute_claimed(
        self, change: Change, actor: IdentityConfig, rule: Any, ctx: dict[str, Any], snapshot: dict[str, Any] | None
    ) -> CallOutcome:
        change.snapshot = snapshot
        self.store.save(change)
        self.audit.write("change.executing", identity=actor.id, change_id=change.id, tool=change.tool)
        if sha256_of(change.args) != change.args_sha256:  # re-check on the row that is actually executed
            return self._finish(change, actor, "failed", "change arguments were modified after approval; nothing was applied")

        # ---- apply
        apply_raised: str | None = None
        try:
            result = await self.upstreams.call(change.tool, change.args)
            view = _snapshot_view(result)
        except Exception as exc:
            # A timeout or dropped connection does not mean nothing happened: the write may have committed.
            apply_raised = f"{type(exc).__name__}: {str(exc)[:300]}"
            view = {"text": apply_raised, "json": None, "is_error": True}
        change.result = view
        ctx["result"] = view
        if apply_raised is not None and not (rule and rule.verify):
            return self._finish(
                change, actor, "rollback_failed", f"apply raised ({apply_raised}); outcome unknown, verify the device"
            )
        if view["is_error"] and apply_raised is None:
            return self._finish(change, actor, "failed", f"upstream returned an error: {view['text'][:500]}")

        # ---- verify
        if rule and rule.verify:
            ok, detail = await self._verify(rule.verify, ctx)
            change.verify_result = {"ok": ok, "detail": detail}
            if not ok:
                if rule.rollback and snapshot is not None:
                    try:
                        rb = await self._run_spec(rule.rollback, ctx, raise_on_error=True)
                        change.rollback_result = rb
                        if rule.snapshot:
                            after = await self._run_spec(rule.snapshot, ctx)
                            restored = after.get("json") == snapshot.get("json") and after.get("text") == snapshot.get("text")
                            change.rollback_result = {**rb, "restored_state_matches_snapshot": restored}
                            if not restored:
                                raise UpstreamError("rollback ran but the device state does not match the pre-change snapshot")
                        return self._finish(
                            change, actor, "rolled_back", f"verification failed ({detail}); previous state restored and confirmed"
                        )
                    except Exception as exc:
                        change.rollback_result = {**(change.rollback_result or {}), "error": str(exc)}
                        return self._finish(
                            change,
                            actor,
                            "rollback_failed",
                            f"verification failed ({detail}) AND rollback failed ({exc}); manual intervention required",
                        )
                return self._finish(change, actor, "failed", f"verification failed ({detail}); no rollback configured")
        if apply_raised is not None:
            return self._finish(
                change, actor, "succeeded", f"apply raised ({apply_raised}) but verification confirmed the change"
            )
        return self._finish(change, actor, "succeeded", "applied" + (" and verified" if rule and rule.verify else ""))

    def _execute_crashed(self, change: Change, actor: IdentityConfig, exc: BaseException) -> CallOutcome:
        """Record an unexpected stop after the claim so a change never stays 'executing' silently.

        Synchronous on purpose: it must also run while a cancellation is propagating.
        """
        log.error("execution of %s stopped after claim: %r", change.id, exc, exc_info=isinstance(exc, Exception))
        applied = change.result is not None
        # Nothing was applied only if we never reached the apply and the stop was an ordinary error before it.
        # Anything else (applied, timed out or cancelled mid-flight) leaves the device state unknown: a human must look.
        unknown = applied or not isinstance(exc, Exception) or isinstance(exc, TimeoutError)
        status = "rollback_failed" if unknown else "failed"
        reason = f"execution stopped unexpectedly ({type(exc).__name__}); " + (
            "device state unknown, manual verification required" if unknown else "nothing was applied"
        )
        try:
            self.audit.write(
                "change.execute_crashed", identity=actor.id, change_id=change.id, applied=applied, error=type(exc).__name__
            )
        except Exception:
            log.exception("could not audit the crash of %s", change.id)
        try:
            current = self.store.get(change.id)
            if current is not None and current.status == "executing":
                current.result, current.verify_result = change.result, change.verify_result
                current.rollback_result = change.rollback_result
                self.store.transition(current, status, reason)
                self.notifier.change_event(f"change.{status}", current)
            elif current is not None:  # the outcome was already recorded before the stop; report what the DB holds
                status, reason = current.status, current.status_reason
        except Exception:
            log.exception("could not record the outcome of %s; it stays 'executing' and needs an operator", change.id)
        return CallOutcome.data({"status": status, "change_id": change.id, "reason": reason}, is_error=status != "succeeded")

    # ------------------------------------------------------------------ helpers
    # ------------------------------------------------------------------ scoped read access
    def _may_view(self, identity: IdentityConfig, change: Change) -> bool:
        """Approvers see every change; anyone else only the changes they requested."""
        return change.requester == identity.id or self.policy.can_approve(identity)

    def changes_for(self, identity: IdentityConfig, status: str | None = None, limit: int = 50) -> list[Change]:
        if self.policy.can_approve(identity):
            return self.store.list(status, limit=limit)
        return self.store.list(status, limit=limit, requester=identity.id)

    def change_detail(self, identity: IdentityConfig, change_id: str) -> dict[str, Any]:
        change = self.store.get(change_id)
        if change is None or not self._may_view(identity, change):
            raise GuardrailDenied(f"change '{change_id[:64]}' not found")  # same answer: no probing of other changes
        data = change.to_dict()
        data["args"] = redact(data["args"], self.config.redact_keys)
        return data

    def _status_for(self, identity: IdentityConfig) -> dict[str, Any]:
        full = self.upstreams.status()
        if self.policy.can_approve(identity):
            return full
        # non-approvers learn only about tools they can already see (no counts that reveal hidden tools)
        counts = Counter(t.name.split(SEP, 1)[0] for t in self.visible_tools(identity) if SEP in t.name)
        return {u: {"connected": s["connected"], "visible_tools": counts.get(u, 0)} for u, s in full.items()}

    def _deny(self, event: str, actor: IdentityConfig, change_id: str, message: str) -> GuardrailDenied:
        """Audit a refused control action (invariant 7) and return the exception to raise."""
        self.audit.write(event, identity=actor.id, change_id=str(change_id)[:64], reason=message[:500])
        return GuardrailDenied(message[:500])

    def _get_visible(self, actor: IdentityConfig, change_id: str, deny_event: str) -> Change:
        """Like _get, but a change the actor may not view is indistinguishable from a missing one."""
        change = self.store.get(change_id)
        if change is None or not self._may_view(actor, change):
            raise self._deny(deny_event, actor, change_id, f"change '{change_id[:64]}' not found")
        return change

    def _get(self, change_id: str) -> Change:
        change = self.store.get(change_id)
        if change is None:
            raise GuardrailDenied(f"change '{change_id}' not found")
        return change

    def _block(self, change: Change, actor: IdentityConfig, reason: str) -> CallOutcome:
        try:
            self.store.transition(change, "blocked", reason)
        except TransitionError as exc:
            # The change moved while we were checking it (e.g. rejected by a human). Never overwrite that.
            current = self.store.get(change.id)
            status = current.status if current else "missing"
            self.audit.write("change.execute_aborted", identity=actor.id, change_id=change.id, reason=str(exc))
            raise GuardrailDenied(f"{change.id} is {status}; execution aborted") from exc
        self.audit.write("change.blocked", identity=actor.id, change_id=change.id, reason=reason)
        self.notifier.change_event("change.blocked", change)
        return CallOutcome.data({"status": "blocked", "change_id": change.id, "reason": reason}, is_error=True)

    def _finish(self, change: Change, actor: IdentityConfig, status: str, reason: str) -> CallOutcome:
        self.store.save(change)
        self.store.transition(change, status, reason)
        self.audit.write(
            f"change.{status}",
            identity=actor.id,
            change_id=change.id,
            tool=change.tool,
            reason=reason,
            verify=change.verify_result,
        )
        self.notifier.change_event(f"change.{status}", change)
        payload = {
            "status": status,
            "change_id": change.id,
            "reason": reason,
            "result": change.result,
            "verification": change.verify_result,
            "rollback": change.rollback_result,
        }
        return CallOutcome.data(payload, is_error=status != "succeeded")

    async def _run_spec(self, spec: Any, ctx: dict[str, Any], raise_on_error: bool = False) -> dict[str, Any]:
        try:
            args = render(spec.args, ctx)
        except TemplateError as exc:
            raise GuardrailDenied(f"policy template error in {spec.tool}: {exc}") from exc
        try:
            result = await self.upstreams.call(spec.tool, args)
        except (GuardrailDenied, UpstreamError):
            raise
        except Exception as exc:
            raise UpstreamError(f"{spec.tool} failed: {type(exc).__name__}: {str(exc)[:300]}") from exc
        view = _snapshot_view(result)
        if raise_on_error and view["is_error"]:
            raise UpstreamError(view["text"][:500])
        return view

    async def _verify(self, spec: VerifySpec, ctx: dict[str, Any]) -> tuple[bool, str]:
        try:
            view = await self._run_spec(spec, ctx)
        except Exception as exc:
            return False, f"verify call failed: {exc}"
        ctx["verify"] = view
        if view["is_error"]:
            return False, "verify tool returned an error"
        text = view["text"]
        try:
            for needle in spec.expect_contains:
                n = str(render(needle, ctx))
                if n not in text:
                    return False, f"expected text not found: {n[:120]!r}"
            for needle in spec.expect_not_contains:
                n = str(render(needle, ctx))
                if n in text:
                    return False, f"forbidden text present: {n[:120]!r}"
            for path, expected in spec.expect_json.items():
                want = render(expected, ctx)
                try:
                    got = lookup({"json": view["json"]}, f"json.{path}")
                except TemplateError:
                    return False, f"json path '{path}' missing in verify result"
                if got != want:
                    return False, f"json '{path}' is {got!r}, expected {want!r}"
        except TemplateError as exc:
            return False, f"verify template error: {exc}"
        return True, "all expectations met"

    # ------------------------------------------------------------------ gateway tools
    async def _gateway_call(self, identity: IdentityConfig, name: str, args: dict[str, Any]) -> CallOutcome:
        if name == "whoami":
            roles = {r: self.config.roles[r].model_dump() for r in identity.roles}
            return CallOutcome.data({"identity": identity.id, "roles": roles})
        if name == "status":
            return CallOutcome.data(
                {
                    "upstreams": self._status_for(identity),
                    "approval_policy": self.config.approvals.model_dump(),
                    "change_windows": [w.model_dump() for w in self.config.change_windows],
                    "pending_changes": len(self.changes_for(identity, "pending", limit=500)),
                }
            )
        if name == "explain_tool":
            tool = str(args.get("tool", ""))
            # approvers may dry-run any tool they could be asked to approve; everyone else only what they can see
            ut = self.upstreams.resolve(tool) if self.policy.can_approve(identity) else self._resolve_visible(identity, tool)
            call_args = dict(args.get("arguments") or {})
            call_args.pop(JUSTIFICATION_ARG, None)
            a = self.policy.assess(tool, call_args, ut.tool.annotations)
            d = self.policy.authorize(identity, tool, a.tool_class, a.risk)
            return CallOutcome.data(
                {
                    **a.as_dict(),
                    "authorized": d.allowed,
                    "authorization": d.reason,
                    "in_change_window_now": self.policy.in_window(self.policy.windows_for(a.rule), self._now),
                }
            )
        if name == "list_changes":
            try:
                limit = min(max(int(args.get("limit") or 50), 1), 200)
            except (TypeError, ValueError) as exc:
                raise GuardrailDenied("'limit' must be an integer between 1 and 200") from exc
            changes = self.changes_for(identity, args.get("status"), limit=limit)
            return CallOutcome.data({"changes": [c.summary() for c in changes]})
        if name == "get_change":
            return CallOutcome.data(self.change_detail(identity, str(args.get("change_id", ""))))
        if name == "execute_change":
            return await self.execute(identity, str(args.get("change_id", "")))
        if name == "cancel_change":
            ch = self.reject(identity, str(args.get("change_id", "")), str(args.get("reason", "")), channel="mcp")
            return CallOutcome.data({"status": ch.status, "change_id": ch.id})
        if name == "approve_change":
            ch = self.approve(identity, str(args.get("change_id", "")), str(args.get("comment", "")), channel="mcp")
            return CallOutcome.data(ch.summary())
        raise GuardrailDenied(f"unknown gateway tool '{GATEWAY_PREFIX}{name}'")
