"""B2B execution policy extracted from the generic run/construction path.

Every B2B decision ``_create_agent`` and ``api_server_runs._execute_run`` used to
make inline lives here. The generic code calls the helpers below and branches on
their RETURN values — never on B2B state, the ``b2b_execution`` carrier, or the
sink directly.

Lane contract on every helper: ``_state_for`` first. An absent/disabled lane
returns before any execution-context, home, sink or store work — ordinary runs
pay zero B2B cost. The cheap reserved ``b2b_`` namespace refusal stays even
disabled (an admitted cap can only exist on an enabled lane).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
from contextlib import suppress
from typing import Any, Callable, Dict, Optional

from agent.b2b_execution import (
    B2BTerminalRefusal, is_b2b_session_id,
)
from gateway.platforms.api_server_b2b import _state_for


def guard_agent_construction(
    adapter: Any, *, session_id: Optional[str],
    ephemeral_system_prompt: Optional[str], gateway_session_key: Optional[str],
    room_dispatch: Optional[Dict[str, Any]], room_execution_policy: Optional[Dict[str, Any]],
    session_model: Optional[str], model_options: Optional[Dict[str, Any]],
    route: Optional[Dict[str, Any]], requested_model: Optional[str],
    requested_provider: Optional[str],
) -> None:
    """Pre-construction B2B gate for ``_create_agent`` (the moved guard block).

    Absent/disabled state: ordinary ids return immediately — no
    ``current_execution``, home resolve, or sink/policy checks. A reserved id
    still refuses ``b2b_capability_mismatch`` cheaply: no admission can exist
    on a disabled lane (and ``assert_current_policy`` would deny any stale cap
    the same way).

    Enabled: an ordinary id refuses only while a foreign cap is bound to this
    context. A reserved id requires a matching admitted cap whose policy_home
    and still-current operator policy verify — then rejects any caller-side
    override — before the WITHDRAWN runtime refuses durably at the sink
    (``context_unavailable``), ahead of every construction seam.
    """
    state = _state_for(adapter)
    sid = str(session_id or "")
    if not is_b2b_session_id(sid):
        if state is None or not state.config.enabled:
            return  # disabled ordinary: zero B2B work
        from agent.b2b_execution import current_execution
        if current_execution() is not None:
            raise B2BTerminalRefusal("b2b_capability_mismatch")
        return
    if state is None or not state.config.enabled:
        # Reserved namespace safety stays cheap: no admission exists here.
        raise B2BTerminalRefusal("b2b_capability_mismatch")

    # A B2B-session turn is ONLY legal inside an admitted binding whose cap is
    # bound to this context — anything else (foreign lane, stale scope, caller
    # that reached _create_agent without admission) fails closed BEFORE runtime
    # config resolution, credential reads or memory checkout.
    from agent.b2b_execution import current_execution
    from gateway.platforms.api_server import _api_request_profile
    from hermes_constants import get_hermes_home
    cap = current_execution(profile=_api_request_profile.get() or "default",
                            session_id=sid)
    if (cap is None or str(get_hermes_home().resolve()) != cap.policy_get("profile_home") or
            not cap.sink.assert_current_policy()):
        raise B2BTerminalRefusal("b2b_capability_mismatch")
    project = cap.policy_get("project")
    if (ephemeral_system_prompt is not None or gateway_session_key is not None or
            room_dispatch is not None or room_execution_policy is not None or
            session_model is not None or model_options is not None or route is not None or
            requested_model not in (None, project["model"]) or
            requested_provider not in (None, project["provider"])):
        raise B2BTerminalRefusal("b2b_policy_override")
    # H1: B2B runtime construction is WITHDRAWN. AIAgent.__init__ can reach
    # the provider before any bounded policy could be installed (lazy
    # context_length metadata probes), so the admitted attempt refuses
    # durably here — before run_agent import, runtime/credential/tool
    # resolution or memory checkout. A governed construction path returns
    # with C1's context producer.
    cap.sink.block("context_unavailable")
    raise B2BTerminalRefusal("context_unavailable")


async def construct_run_agent(adapter: Any, run: Any, construct_agent: Callable[[], Any],
                              loop) -> Any:
    """Build the run's agent: native call on ordinary lanes; B2B lanes bind the
    admitted execution, copy the context into a counted off-loop worker, and
    always reset — the original ``_execute_run`` construction block, intact."""
    state = _state_for(adapter)
    cap = getattr(run, "b2b_execution", None) if (
        state is not None and state.config.enabled) else None
    if cap is None:
        return construct_agent()
    from agent.b2b_execution import bind_execution, reset_execution
    cap_token = bind_execution(cap)  # agent construction reads it through current_execution
    try:
        # B2B: cold AIAgent.__init__ (httpx import, client build) must not
        # block the serving event loop — typed reads + control stay live.
        # copy_context carries the bound execution across the worker;
        # _submit_api_worker holds the worker's lifetime count.
        from contextvars import copy_context
        from gateway.platforms.api_server_runs import _submit_api_worker
        ctor_context = copy_context()
        return await _submit_api_worker(loop, lambda: ctor_context.run(construct_agent))
    finally:
        reset_execution(cap_token)


def run_execution_resets(adapter: Any, run: Any) -> list:
    """``(token, reset)`` pairs the worker body must unwind — ``[]`` on every
    ordinary lane (disabled state or no cap), the bound-execution pair only
    when an admitted cap actually rides the run."""
    state = _state_for(adapter)
    if state is None or not state.config.enabled:
        return []
    cap = getattr(run, "b2b_execution", None)
    if cap is None:
        return []
    from agent.b2b_execution import bind_execution, reset_execution
    return [(bind_execution(cap), reset_execution)]


async def finalize_run(adapter: Any, run: Any, result: Dict[str, Any],
                       status: str, fields: Dict[str, Any]):
    """Terminal classification hook: ``None`` on ordinary lanes (caller keeps
    its native finish), else ``(status, fields, extra)`` from the B2B seal
    path — the caller branches on the return, never on the cap."""
    state = _state_for(adapter)
    cap = getattr(run, "b2b_execution", None) if (
        state is not None and state.config.enabled) else None
    if cap is None:
        return None
    return await _b2b_finalize(cap, result, status, fields)


def _cap_or_none(adapter: Any, run: Any):
    state = _state_for(adapter)
    if state is None or not state.config.enabled:
        return None
    return getattr(run, "b2b_execution", None)


def block_interrupted_run(adapter: Any, run: Any) -> None:
    """Best-effort durable block when the run task is cancelled — never
    replaces the CancelledError or the terminal finish."""
    cap = _cap_or_none(adapter, run)
    if cap is not None:
        with suppress(Exception):
            cap.sink.block("native_run_interrupted")


def block_provider_unavailable_run(adapter: Any, run: Any) -> None:
    """Best-effort durable block on the controlled provider-auth error."""
    cap = _cap_or_none(adapter, run)
    if cap is not None:
        with suppress(Exception):
            cap.sink.block("policy_provider_unavailable")


def block_failed_run(adapter: Any, run: Any, exc: BaseException) -> None:
    """Best-effort durable block on an untyped run failure — the reason string
    rides along exactly as the inline block did."""
    cap = _cap_or_none(adapter, run)
    if cap is not None:
        with suppress(Exception):
            cap.sink.block(str(exc))


async def generic_run_visible(adapter: Any, run_id: str) -> bool:
    """Ownerless-run B2B gate for ``_request_owns_run``: enabled lanes hide
    durable B2B attempt runs from every generic surface; disabled/absent lanes
    skip the store lookup entirely. Lookup errors fail closed."""
    state = _state_for(adapter)
    if state is None or not state.config.enabled:
        return True
    try:
        if await asyncio.to_thread(
                adapter._run_idempotency_store.b2b_is_run, run_id) is True:
            return False
    except Exception:
        return False
    return True


async def _b2b_finalize(cap, result: Dict[str, Any], status: str, fields: Dict[str, Any]):
    """Only worker-attested durable output can become a fully sealed proposal."""
    from agent.b2b_execution import (
        B2BTerminalRefusal, bind_execution, reset_execution, recheck_context, validate_proposal,
        extract_allowed_refs)

    sink = cap.sink

    def blocked(reason, native_status="failed"):
        sink.block(reason)
        return native_status, {
            **fields, "completed": False, "partial": False,
            "interrupted": native_status in {"cancelled", "interrupted"}, "error": reason}, None

    token = bind_execution(cap)
    try:
        with sink._adapter._profile_scope(cap.profile if cap.profile != "default" else None):
            # First refusal wins: an attempt already blocked durably keeps its typed
            # reason - never reclassify it as a later, unrelated family.
            row = sink._store.b2b_attempt(profile=cap.profile, attempt_id=cap.attempt_id)
            if row is not None and row["status"] not in {
                    "admitted", "context_ready", "dispatch_committed", "result_received"}:
                return blocked(row["status"], "interrupted" if row["status"] in
                               {"cancelled", "interrupted"} else "failed")
            receipt = cap.context_receipt
            if receipt is None:
                return blocked("context_unavailable")
            if result.get("failed") or status != "completed":
                return blocked("b2b_run_failed", status if status in {"cancelled", "interrupted"} else "failed")
            artifact = sink._store.b2b_artifact(attempt_id=cap.attempt_id, kind="provider_result")
            if artifact is None:
                return blocked("result_unattested")
            public = json.loads(artifact["payload"])
            parsed, _ = validate_proposal(public["text"], extract_allowed_refs(receipt.view))
            if (parsed is None or parsed != public.get("proposal") or
                    result.get("final_response", "").strip() != public["text"].strip()):
                return blocked("result_invalid")
            # The rechecker runs in the copied profile/capability scope; original context stays immutable.
            # Bounded like the provider-boundary C1s: a blocking callback must
            # refuse on the prospective before_seal window, never hang sealing.
            fresh = await asyncio.to_thread(
                recheck_context, cap, receipt,
                deadline=sink.seal_recheck_deadline())
            source = await sink.resolve_before_seal()
            if source is None:
                return blocked("source_before_seal_denied")
            proposal = sink.seal(
                source_before_seal=source, rechecked_view=fresh,
                created_at=dt.datetime.now(dt.timezone.utc).isoformat())
            return "completed", {**fields, "completed": True}, {
                "output": json.dumps(parsed, ensure_ascii=False),
                "b2b": {key: proposal[key] for key in ("proposal_id", "state", "created_at")}}
    except B2BTerminalRefusal as exc:
        return blocked(str(exc))
    finally:
        reset_execution(token)
