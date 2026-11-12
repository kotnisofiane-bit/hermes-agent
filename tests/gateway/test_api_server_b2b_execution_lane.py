"""L2 governed construction + dispatch: an admitted attempt whose operator
supplied the real execution-context inputs (pinned r2 contract root, My Work
roots, inert-init serving config) constructs a bounded agent that dispatches
through execute_terminal; without those inputs the SAME durable
``context_unavailable`` refusal the withdrawn path emitted still lands first.

All context/source data are UNIT DOUBLES; the construction itself is real.
"""

from __future__ import annotations

import hashlib
import os
from types import SimpleNamespace
from typing import Optional

import pytest

from agent.b2b_execution import (
    B2BTerminalRefusal, R2_SCHEMA_PINS, bind_execution, reset_execution,
)
from gateway.platforms import api_server_b2b as b2b
from gateway.platforms.api_server import APIServerAdapter, _api_request_profile
from gateway.platforms.api_server_b2b_execution import (
    b2b_execution_ready, b2b_execution_status)
from hermes_state import SessionDB
from tests.gateway import b2b_unit_fixtures
from tests.gateway.b2b_process_harness import extract_contract_root


_INERT_CONFIG = {
    "model": {"context_length": 256000},
    "compression": {"enabled": False}}


class _LaneAgent(SimpleNamespace):
    """Weakref-able agent stand-in carrying exactly the attrs the dispatch
    seam reads (SimpleNamespace itself cannot be weak-referenced)."""

    def _has_pending_redirect(self):
        return False


def _ready_lane(tmp_path):
    """The dispatch fixture upgraded to the operator-input-ready shape:
    real contract root, real My Work roots, a real session DB."""
    lane = b2b_unit_fixtures.build_b2b_dispatch_lane(tmp_path)
    alloc = tmp_path / "mywork-alloc"
    start = tmp_path / "mywork-start"
    alloc.mkdir()
    start.mkdir()
    project = dict(lane.policy["project"])
    project["project_context"] = {
        "allocation_root": str(alloc), "project_id": project["project_id"],
        "start": str(start)}
    policy = dict(lane.policy)
    policy["project"] = project
    # Rebind the frozen policy the cap already captured: the fixture built the
    # cap from its own dict, so a ready lane needs a cap whose policy carries
    # the on-disk project_context.
    from agent.b2b_execution import BoundExecution
    import dataclasses
    cap = BoundExecution(
        profile=lane.cap.profile, session_id=lane.cap.session_id,
        binding_digest=lane.cap.binding_digest, attempt_id=lane.cap.attempt_id,
        run_id=lane.cap.run_id, policy=policy, sink=lane.sink,
        created_at=lane.cap.created_at)
    lane.cap = cap
    lane.policy = policy
    lane.project = project
    return lane


def _cfg(model_ctx: Optional[int] = 256000, compression_enabled=False):
    return {
        "model": ({"context_length": model_ctx} if model_ctx is not None else {}),
        "compression": ({"enabled": compression_enabled}
                        if compression_enabled is not None else {})}


# ---------------------------------------------------------------------------
# b2b_execution_ready — the operator-input predicate
# ---------------------------------------------------------------------------

def test_execution_ready_when_all_inputs_on_disk(tmp_path):
    lane = _ready_lane(tmp_path)
    assert b2b_execution_ready(lane.project, _INERT_CONFIG) is True


@pytest.mark.parametrize("mutation", [
    "no_project_context", "missing_start_dir", "missing_alloc_dir",
    "wrong_project_id", "bad_schema_bytes", "missing_schema",
    "no_context_length", "compression_on"])
def test_execution_not_ready_when_inputs_missing_or_incoherent(tmp_path, mutation):
    lane = _ready_lane(tmp_path)
    project = dict(lane.project)
    config = _INERT_CONFIG
    if mutation == "no_project_context":
        project["project_context"] = None
    elif mutation == "missing_start_dir":
        project["project_context"] = {**project["project_context"],
                                      "start": str(tmp_path / "absent")}
    elif mutation == "missing_alloc_dir":
        project["project_context"] = {**project["project_context"],
                                      "allocation_root": str(tmp_path / "absent")}
    elif mutation == "wrong_project_id":
        project["project_context"] = {**project["project_context"],
                                      "project_id": "other"}
    elif mutation == "bad_schema_bytes":
        name = next(iter(R2_SCHEMA_PINS))
        with open(os.path.join(project["context_contract_root"], name), "wb") as fh:
            fh.write(b"not the pinned schema")
    elif mutation == "missing_schema":
        os.unlink(os.path.join(
            project["context_contract_root"], next(iter(R2_SCHEMA_PINS))))
    elif mutation == "no_context_length":
        config = _cfg(model_ctx=None)
    elif mutation == "compression_on":
        config = _cfg(compression_enabled=True)
    assert b2b_execution_ready(project, config) is False, mutation
    lane.store.close()


def test_execution_ready_rejects_unpinned_contract(tmp_path):
    """A directory of lookalike schemas is not the contract: every pinned file
    must hash to its production pin."""
    lane = _ready_lane(tmp_path)
    root = lane.project["context_contract_root"]
    name = next(iter(R2_SCHEMA_PINS))
    path = os.path.join(root, name)
    with open(path, "ab") as fh:
        fh.write(b" ")
    assert b2b_execution_ready(lane.project, _INERT_CONFIG) is False
    assert hashlib.sha256(open(path, "rb").read()).hexdigest() != R2_SCHEMA_PINS[name]
    lane.store.close()


# ---------------------------------------------------------------------------
# b2b_execution_status — the smoke-visible lane state
# ---------------------------------------------------------------------------

def _state(profiles):
    return b2b._B2BState(b2b.B2BConfig({"enabled": True, "profiles": profiles}))


def test_execution_status_not_configured_without_lane():
    assert b2b_execution_status(None, _INERT_CONFIG) == "not-configured"
    state = b2b._B2BState(b2b.B2BConfig(None))
    assert b2b_execution_status(state, _INERT_CONFIG) == "not-configured"


def test_execution_status_ready_and_refused(tmp_path):
    lane = _ready_lane(tmp_path)
    profile = "hub"
    entry = {"source_url": "http://127.0.0.1:1/internal/dubsar/b2b/source",
             "portal_issuer": "portal-h1", "hermes_issuer": "hermes-h1-hub",
             "portal_public_key_pem": lane.entry["portal_public_key_pem"],
             "hermes_private_key_pem": lane.entry["hermes_private_key_pem"],
             "projects": {"b2b-bench": lane.project}}
    state = _state({profile: entry})
    assert b2b_execution_status(state, _INERT_CONFIG) == "ready"
    # Any project missing the on-disk inputs turns the whole lane refused.
    broken = dict(lane.project)
    broken["project_context"] = None
    state = _state({profile: {**entry, "projects": {"b2b-bench": broken}}})
    assert b2b_execution_status(state, _INERT_CONFIG) == "refused"
    lane.store.close()


# ---------------------------------------------------------------------------
# _create_agent — bounded construction vs durable refusal
# ---------------------------------------------------------------------------

def _adapter(lane):
    from pathlib import Path
    return SimpleNamespace(
        _b2b_state=lane.adapter._b2b_state,
        _ensure_session_db=lambda: SessionDB(
            Path(str(lane.db_path) + ".sess.db")),
        _ensure_session_db_async=None,
        _memory_sessions=SimpleNamespace(checkout=lambda _sid: None),
        _select_agent_runtime=None)


def _write_inert_config(home, provider_base_url):
    with open(os.path.join(str(home), "config.yaml"), "w") as fh:
        fh.write(
            "model:\n  default: unit-double\n  provider: custom\n"
            f'  base_url: "{provider_base_url}"\n'
            "  api_mode: chat_completions\n  context_length: 256000\n"
            "compression:\n  enabled: false\n")


def test_create_agent_b2b_constructs_bounded_agent_when_ready(
        tmp_path, monkeypatch):
    """GREEN: the admitted lane with real operator inputs builds a real
    AIAgent frozen by install_bounded_agent_policy — model/provider/base_url
    from the project policy, never the serving profile's default route."""
    lane = _ready_lane(tmp_path)
    from hermes_constants import get_hermes_home
    import gateway.run as gw_run
    monkeypatch.setattr(gw_run, "_hermes_home", get_hermes_home())
    _write_inert_config(get_hermes_home(), lane.project["base_url"])
    monkeypatch.setenv("OPENAI_API_KEY", "sk-unit-" + "0" * 8)
    token = _api_request_profile.set(lane.profile)
    cap_token = bind_execution(lane.cap)
    try:
        agent = APIServerAdapter._create_agent(
            _adapter(lane), session_id=lane.session_id)
    finally:
        reset_execution(cap_token)
        _api_request_profile.reset(token)
    project = lane.project
    assert agent.model == project["model"]
    assert agent.provider == project["provider"]
    assert agent.api_mode == project["api_mode"]
    assert str(agent.base_url).rstrip("/") == project["base_url"].rstrip("/")
    assert agent.max_iterations == 1
    assert agent._disable_streaming is True
    assert agent.compression_enabled is False
    assert agent._api_max_retries == 1
    assert agent._auto_recovery_cycles == 0
    assert agent._credential_pool is None
    assert not getattr(agent, "_fallback_chain", ())
    assert agent.tools == []
    assert vars(agent).get("_b2b_execution") is lane.cap
    assert lane.cap._agent_ref() is agent
    swapped = [name for name in
               ("_direct_api_call", "_interruptible_api_call",
                "_interruptible_streaming_api_call", "_streaming_api_call",
                "_compress_context")
               if callable(getattr(agent, name, None))]
    assert swapped, "bounded policy swapped no alternate API path"
    for name in swapped:
        with pytest.raises(B2BTerminalRefusal) as exc:
            getattr(agent, name)()
        assert str(exc.value) == "b2b_alternate_api_call"
    lane.store.close()


def test_create_agent_b2b_refuses_when_inputs_missing(tmp_path, monkeypatch):
    """RED guard: the fixture lane has ``project_context: None`` — the SAME
    durable context_unavailable refusal the withdrawn path emitted."""
    lane = b2b_unit_fixtures.build_b2b_dispatch_lane(tmp_path)
    token = _api_request_profile.set(lane.profile)
    cap_token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            APIServerAdapter._create_agent(
                _adapter(lane), session_id=lane.session_id)
    finally:
        reset_execution(cap_token)
        _api_request_profile.reset(token)
    assert str(exc.value) == "context_unavailable"
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)[
            "status"] == "context_unavailable"
    lane.store.close()


# ---------------------------------------------------------------------------
# _perform_api_call — the only dispatch seam
# ---------------------------------------------------------------------------

def test_perform_api_call_dispatches_terminal_for_bound_lane(
        tmp_path, monkeypatch):
    """A bound lane's api kwargs go through execute_terminal +
    validate_terminal_result, with the live turn_id — never the relay path."""
    from agent import b2b_execution as be
    from agent import turn_api_call as tac

    lane = _ready_lane(tmp_path)
    calls = {}
    sentinel = object()

    def _terminal(agent, kwargs, cap, *, turn_id=""):
        calls["terminal"] = (agent, kwargs, cap, turn_id)
        return sentinel

    def _validate(agent, response):
        calls["validated"] = (agent, response)

    monkeypatch.setattr(be, "execute_terminal", _terminal)
    monkeypatch.setattr(be, "validate_terminal_result", _validate)

    agent = _LaneAgent(
        session_id=lane.session_id, api_mode="chat_completions",
        provider=lane.project["provider"], model=lane.project["model"],
        base_url=lane.project["base_url"], platform="api_server",
        is_subagent=False, _fallback_index=0, _disable_streaming=True,
        thinking_callback=None, _b2b_execution=lane.cap,
        _model_request_active=None, _pending_redirect_lock=None,
        _pending_redirect=None)
    import weakref
    object.__setattr__(lane.cap, "_agent_ref", weakref.ref(agent))
    cap_token = bind_execution(lane.cap)
    try:
        verdict = tac.perform_api_call(
            agent, api_kwargs={"model": "unit-double", "messages": []},
            _original_api_kwargs={}, _llm_middleware_trace=[],
            _moa_prepared_request=None, _retry=SimpleNamespace(),
            thinking_spinner=None, retry_count=0, api_call_count=0,
            api_request_id="req", effective_task_id="task",
            turn_id="t0", interrupted=False)
    finally:
        reset_execution(cap_token)
    assert verdict.action == "fallthrough" and verdict.response is sentinel
    called_agent, called_kwargs, called_cap, called_turn = calls["terminal"]
    assert called_agent is agent and called_kwargs == {
        "model": "unit-double", "messages": []}
    assert called_cap is lane.cap and called_turn == "t0"
    assert calls["validated"] == (agent, sentinel)
    lane.store.close()


def test_perform_api_call_ordinary_lane_unchanged(monkeypatch):
    """Ordinary session: no cap, require_execution returns None, the relay
    path is used and the B2B seam never runs."""
    from agent import b2b_execution as be
    from agent import turn_api_call as tac

    def _terminal(*a, **k):
        raise AssertionError("execute_terminal must not run on ordinary lanes")

    monkeypatch.setattr(be, "execute_terminal", _terminal)

    agent = _LaneAgent(
        session_id="api_ordinary", api_mode="chat_completions",
        provider="custom", base_url="http://127.0.0.1:9/v1",
        model="unit-double", platform="api_server", is_subagent=False,
        _fallback_index=0, _disable_streaming=True, thinking_callback=None,
        _b2b_execution=None, _model_request_active=None,
        _pending_redirect_lock=None, _pending_redirect=None,
        client=object())
    agent._interruptible_api_call = lambda *a, **k: None
    sentinel = object()
    monkeypatch.setattr(
        "agent.relay_llm.execute", lambda *a, **k: sentinel)
    verdict = tac.perform_api_call(
        agent, api_kwargs={}, _original_api_kwargs={}, _llm_middleware_trace=[],
        _moa_prepared_request=None, _retry=SimpleNamespace(),
        thinking_spinner=None, retry_count=0, api_call_count=0,
        api_request_id="req", effective_task_id="task",
        turn_id="t9", interrupted=False)
    assert verdict.action == "fallthrough" and verdict.response is sentinel
