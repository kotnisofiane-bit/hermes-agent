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
import hashlib
import json
import os
from contextlib import suppress
from typing import Any, Callable, Dict, Mapping, Optional

from agent.b2b_execution import (
    B2BTerminalRefusal, R2_SCHEMA_PINS, is_b2b_session_id,
)
from gateway.platforms.api_server_b2b import _state_for


def guard_agent_construction(
    adapter: Any, *, session_id: Optional[str],
    ephemeral_system_prompt: Optional[str], gateway_session_key: Optional[str],
    room_dispatch: Optional[Dict[str, Any]], room_execution_policy: Optional[Dict[str, Any]],
    session_model: Optional[str], model_options: Optional[Dict[str, Any]],
    route: Optional[Dict[str, Any]], requested_model: Optional[str],
    requested_provider: Optional[str],
) -> Optional[Any]:
    """Pre-construction B2B gate for ``_create_agent`` (the moved guard block).

    Absent/disabled state: ordinary ids return ``None`` immediately — no
    ``current_execution``, home resolve, or sink/policy checks. A reserved id
    still refuses ``b2b_capability_mismatch`` cheaply: no admission can exist
    on a disabled lane (and ``assert_current_policy`` would deny any stale cap
    the same way).

    Enabled: an ordinary id refuses only while a foreign cap is bound to this
    context. A reserved id requires a matching admitted cap whose policy_home
    and still-current operator policy verify, then rejects any caller-side
    override. With the project's execution-context inputs verified on disk,
    the gate RETURNS the bound cap so ``_create_agent`` can hand it to
    ``construct_b2b_agent``; without them it refuses durably at the sink
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
    # L2: governed construction is open only when the operator's real
    # execution context for THIS project is in place AND the C1 producer has
    # published it — b2b_execution_ready stays False until the producer is
    # integrated, so every stale admitted cap keeps the same durable terminal
    # refusal — before run_agent import, runtime/credential/tool resolution
    # or memory checkout.
    from gateway.run import _load_gateway_config
    if not b2b_execution_ready(project, _load_gateway_config()):
        cap.sink.block("context_unavailable")
        raise B2BTerminalRefusal("context_unavailable")
    return cap


def _abs_dir(value: Any) -> bool:
    """An existing absolute directory — the on-disk half of every
    host-supplied context root (config validation already enforces the
    absolute shape)."""
    return isinstance(value, str) and os.path.isdir(value)


def _contract_root_ready(root: Any) -> bool:
    """The pinned r2 contract root, verified by content: every schema file
    exists AND hashes to its production pin — a directory of lookalikes is
    not the contract."""
    if not _abs_dir(root):
        return False
    for name, pin in R2_SCHEMA_PINS.items():
        path = os.path.join(root, name)
        try:
            with open(path, "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest() != pin:
                    return False
        except OSError:
            return False
    return True


def _init_inert_config(config: Optional[Mapping]) -> bool:
    """The serving profile's effective config must pin away every provider
    reach ``AIAgent.__init__`` could make before the bounded policy exists —
    H1's withdrawal reason. ``model.context_length`` skips the lazy metadata
    probes; ``compression.enabled: false`` skips the init-time aux model
    feasibility probe. Both are explicit operator pins, never defaults."""
    if not isinstance(config, Mapping):
        return False
    model = config.get("model")
    context_length = model.get("context_length") if isinstance(model, Mapping) else None
    if (not isinstance(context_length, int) or isinstance(context_length, bool)
            or context_length <= 0):
        return False
    compression = config.get("compression")
    return isinstance(compression, Mapping) and compression.get("enabled") is False


def b2b_execution_inputs_ready(project: Any, config: Optional[Mapping]) -> bool:
    """Operator-input PREPARATION for ONE validated project entry: the on-disk
    artifacts the governed lane consumes — the verified r2 contract root and
    the My Work ``allocation_root``/``start`` directories C1 binds at context
    publication — plus the serving-profile pins that keep construction inert.
    All operator inputs; nothing inferred from defaults or ambient state.
    Preparation is necessary but NOT sufficient: see b2b_execution_ready."""
    if not isinstance(project, Mapping):
        return False
    context = project.get("project_context")
    return (
        _contract_root_ready(project.get("context_contract_root"))
        and isinstance(context, Mapping)
        and context.get("project_id") == project.get("project_id")
        and all(_abs_dir(context.get(key)) for key in ("allocation_root", "start"))
        and _init_inert_config(config))


def b2b_execution_unavailable_code(project: Any, config: Optional[Mapping]) -> str:
    """Typed refusal for ONE project: ``execution_inputs_unavailable`` when the
    preparation predicate fails, ``c1_producer_unavailable`` when preparation is
    complete and only the missing C1 producer keeps the lane closed."""
    if b2b_execution_inputs_ready(project, config):
        return "c1_producer_unavailable"
    return "execution_inputs_unavailable"


def b2b_execution_ready(project: Any, config: Optional[Mapping]) -> bool:
    """EXECUTION readiness for ONE validated project entry — CLOSED in this
    delivery: the C1 context producer is not integrated, so no input set opens
    execution and no config/env switch reopens it. Deliberately a single
    predicate: the producer integration lands HERE (and only here), so every
    caller — the pre-admission gate, the admitted-cap guard, health — fails
    closed by construction until then."""
    return False


def b2b_execution_status(adapter: Any) -> Dict[str, Any]:
    """The smoke-visible lane diagnostic — SYNCHRONOUS; the health handler runs
    it via ``asyncio.to_thread`` so per-profile config/schema reads and contract
    hashing never touch the event loop (and it performs no credential or
    network probes).

    Shape: absent/disabled lane → ``not-configured``/``null``/``{}``. Enabled →
    every profile is evaluated under its OWN profile scope against its OWN
    serving config (A→B→A), and reported ``not-ready`` — never ``ready`` —
    with a typed code: ``execution_inputs_unavailable`` for any preparation
    hole (including empty profiles/projects and evaluation errors) and
    ``c1_producer_unavailable`` when preparation is complete and only the
    missing C1 producer holds the lane closed. The aggregate is the fail-closed
    combination: any ``execution_inputs_unavailable`` wins."""
    state = _state_for(adapter)
    if state is None or not state.config.enabled:
        return {"b2b_execution": "not-configured", "b2b_execution_code": None,
                "b2b_execution_profiles": {}}
    profiles: Dict[str, Any] = {}
    for name, entry in state.config.profiles.items():
        code = "execution_inputs_unavailable"
        try:
            with adapter._profile_scope(name if name != "default" else None):
                from gateway.run import _load_gateway_config
                config = _load_gateway_config()
                projects = entry.get("projects") or {}
                if projects and all(
                        b2b_execution_inputs_ready(project, config)
                        for project in projects.values()):
                    code = "c1_producer_unavailable"
        except Exception:
            code = "execution_inputs_unavailable"
        profiles[name] = {"state": "not-ready", "code": code}
    aggregate = ("execution_inputs_unavailable"
                 if not profiles or any(
                     p["code"] == "execution_inputs_unavailable"
                     for p in profiles.values())
                 else "c1_producer_unavailable")
    return {"b2b_execution": "not-ready", "b2b_execution_code": aggregate,
            "b2b_execution_profiles": profiles}


def construct_b2b_agent(adapter: Any, cap: Any, *, session_id: Optional[str],
                        stream_delta_callback: Any, tool_progress_callback: Any,
                        tool_start_callback: Any, tool_complete_callback: Any,
                        interim_assistant_callback: Any, reasoning_callback: Any,
                        status_callback: Any) -> Any:
    """Bounded B2B agent for ONE admitted execution. Every policy-visible
    value comes from the frozen project policy — model/provider/base_url/
    api_mode, one iteration, no toolsets, no memory checkout, no context
    files, no checkpoints, no fallback or credential pool. Credentials resolve
    ONLY through the project's pinned provider
    (``_resolve_runtime_agent_kwargs_for_provider``) under the owning
    profile's scope — never the serving profile's default route, credential
    pool, or a fallback provider. The pin's canonical expected provider comes
    from registry alias resolution (or ``custom`` for a saved named-custom
    entry); the resolved runtime's EFFECTIVE provider must equal it —
    ``requested_provider`` is an echo, not proof — the endpoint must match
    after trimming a trailing '/' only, a credential must exist, and a
    reported api_mode must equal the pin's, else the attempt is blocked
    ``policy_provider_unavailable`` BEFORE AIAgent exists. The
    serving config's explicit ``model.context_length`` rides as a runtime pin
    so init never needs provider metadata. ``install_bounded_agent_policy``
    freezes the dispatch surface before the agent leaves this worker."""
    project = cap.policy_get("project")
    from run_agent import AIAgent
    from gateway.run import (
        _load_gateway_config, _resolve_runtime_agent_kwargs_for_provider)

    def _refuse_provider():
        cap.sink.block("policy_provider_unavailable")
        raise B2BTerminalRefusal("policy_provider_unavailable") from None

    # Canonical expected provider: registry alias resolution for ordinary pins,
    # a saved providers:/custom_providers: entry for named-custom (``custom:<name>``
    # and bare ``<name>`` spellings). Empty/"auto"/unknown refuse BEFORE the
    # resolver runs — the pin names one provider, never a search.
    raw_provider = str(project["provider"] or "").strip().lower()
    from hermes_cli.auth import resolve_provider
    from hermes_cli.runtime_provider_custom import has_named_custom_provider
    expected_provider = None
    if raw_provider and raw_provider != "auto":
        try:
            expected_provider = ("custom"
                                 if has_named_custom_provider(raw_provider)
                                 else resolve_provider(raw_provider))
        except Exception:
            expected_provider = None
    if not expected_provider or expected_provider == "auto":
        _refuse_provider()

    try:
        runtime_kwargs = _resolve_runtime_agent_kwargs_for_provider(
            project["provider"], target_model=project["model"])
    except Exception:
        _refuse_provider()
    # Only the EFFECTIVE provider proves the route — requested_provider merely
    # echoes the request and hides a ladder fallback. Endpoint match trims a
    # trailing '/' only; a missing credential is a refusal, not a 401 later.
    if runtime_kwargs.get("provider") != expected_provider:
        _refuse_provider()
    if (str(runtime_kwargs.get("base_url") or "").rstrip("/")
            != str(project["base_url"] or "").rstrip("/")):
        _refuse_provider()
    if not runtime_kwargs.get("api_key"):
        _refuse_provider()
    runtime_api_mode = runtime_kwargs.get("api_mode")
    if runtime_api_mode and runtime_api_mode != project["api_mode"]:
        _refuse_provider()
    model_cfg = _load_gateway_config().get("model") or {}
    agent = AIAgent(
        model=project["model"], provider=project["provider"],
        api_mode=project["api_mode"], base_url=project["base_url"],
        api_key=runtime_kwargs.get("api_key"),
        context_length=model_cfg.get("context_length"),
        max_iterations=1, quiet_mode=True, verbose_logging=False,
        ephemeral_system_prompt=None, enabled_toolsets=[],
        session_id=session_id, platform="api_server",
        stream_delta_callback=stream_delta_callback,
        tool_progress_callback=tool_progress_callback,
        tool_start_callback=tool_start_callback,
        tool_complete_callback=tool_complete_callback,
        interim_assistant_callback=interim_assistant_callback,
        reasoning_callback=reasoning_callback,
        status_callback=status_callback,
        session_db=adapter._ensure_session_db(),
        fallback_model=None, reasoning_config=None,
        gateway_session_key=None, memory_manager=None,
        checkpoints_enabled=False,
        skip_memory=True, skip_context_files=True)
    agent._hermes_api_runtime = {
        "provider": project["provider"], "model": project["model"],
        "route_source": "b2b_policy"}
    from agent.b2b_execution import install_bounded_agent_policy
    install_bounded_agent_policy(agent, cap)
    return agent


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
