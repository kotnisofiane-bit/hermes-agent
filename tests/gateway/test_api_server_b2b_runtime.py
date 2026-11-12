"""_create_agent B2B lane: an admitted attempt refuses durably BEFORE any
runtime/credential/tool resolution, agent construction or memory checkout.

Regression for the Codex finding that a post-construction bounded-policy install
let ``AIAgent.__init__`` perform unguarded provider I/O (lazy context_length
metadata probes) even on lanes that only ever refuse. The terminal seam must
block ``context_unavailable`` at the entry guards -- the FIRST durable terminal
state -- with every downstream construction seam untouched.

All context/source data are UNIT DOUBLES; the disk store and sink are real.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent.b2b_execution import B2BTerminalRefusal, bind_execution, reset_execution
from gateway.platforms.api_server import APIServerAdapter, _api_request_profile
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from tests.gateway import b2b_unit_fixtures


@pytest.fixture
def b2b_runtime_lane(tmp_path):
    lane = b2b_unit_fixtures.build_b2b_dispatch_lane(tmp_path)
    try:
        yield lane
    finally:
        lane.store.close()


def _sentinel(name):
    def _raise(*a, **k):
        raise AssertionError(f"{name} must not run on a refused B2B lane")
    return _raise


def _adapter(lane):
    """Adapter stand-in: every seam _create_agent could touch past the B2B
    entry guards is a tripwire, so any leaked construction step fails loudly."""
    return SimpleNamespace(
        _b2b_state=lane.adapter._b2b_state,
        _ensure_session_db=_sentinel("_ensure_session_db"),
        _ensure_session_db_async=_sentinel("_ensure_session_db_async"),
        _memory_sessions=SimpleNamespace(checkout=_sentinel("memory_checkout")),
        _select_agent_runtime=_sentinel("_select_agent_runtime"))


def _guarded_create(lane, adapter, monkeypatch, *, session_id, **kwargs):
    """Call _create_agent under the admitted profile/capability scope with
    runtime-resolution imports and the agent constructor turned into tripwires.

    ``_load_gateway_config`` is NOT tripwired: the readiness gate reads the
    effective serving config to verify the operator's inert-init inputs --
    it returns {} on error and never touches runtime/provider state."""
    for name in (
            "_resolve_runtime_agent_kwargs", "_resolve_gateway_model",
            "_checkpoint_agent_kwargs", "_current_max_iterations"):
        monkeypatch.setattr(
            f"gateway.run.{name}", _sentinel(f"gateway.run.{name}"), raising=False)
    monkeypatch.setattr(
        "gateway.platforms.api_server._resolve_request_runtime_agent_kwargs",
        _sentinel("_resolve_request_runtime_agent_kwargs"), raising=False)
    monkeypatch.setattr(
        "hermes_cli.tools_config._get_platform_tools",
        _sentinel("_get_platform_tools"), raising=False)
    monkeypatch.setattr(
        "run_agent.AIAgent", _sentinel("AIAgent"), raising=False)
    token = _api_request_profile.set(lane.profile)
    cap_token = bind_execution(lane.cap)
    try:
        return APIServerAdapter._create_agent(adapter, session_id=session_id, **kwargs)
    finally:
        reset_execution(cap_token)
        _api_request_profile.reset(token)


def _attempt_status(lane):
    return lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)["status"]


def test_create_agent_b2b_refuses_context_unavailable_before_runtime(
        b2b_runtime_lane, monkeypatch):
    lane = b2b_runtime_lane
    with pytest.raises(B2BTerminalRefusal) as exc:
        _guarded_create(lane, _adapter(lane), monkeypatch, session_id=lane.session_id)
    assert str(exc.value) == "context_unavailable"
    # The refusal is the FIRST durable terminal state -- persisted by the sink,
    # not inferred later from an exception string.
    assert _attempt_status(lane) == "context_unavailable"
    # Reopen the disk store: the block was a committed transaction.
    reopened = RunIdempotencyStore(str(lane.db_path))
    try:
        assert reopened.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "context_unavailable"
    finally:
        reopened.close()


def test_create_agent_b2b_refuses_missing_capability(b2b_runtime_lane):
    lane = b2b_runtime_lane
    # No bind_execution at all: a reserved session id with no admitted cap.
    token = _api_request_profile.set(lane.profile)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            APIServerAdapter._create_agent(_adapter(lane), session_id=lane.session_id)
    finally:
        _api_request_profile.reset(token)
    assert str(exc.value) == "b2b_capability_mismatch"
    # Nothing reached the terminal seam -- the attempt stays untouched.
    assert _attempt_status(lane) == "context_ready"


def test_create_agent_b2b_refuses_foreign_session_and_profile(b2b_runtime_lane):
    lane = b2b_runtime_lane
    cap_token = bind_execution(lane.cap)
    try:
        # Wrong request profile: the cap is bound but not for this profile.
        token = _api_request_profile.set("ci")
        try:
            with pytest.raises(B2BTerminalRefusal) as exc:
                APIServerAdapter._create_agent(_adapter(lane), session_id=lane.session_id)
        finally:
            _api_request_profile.reset(token)
        assert str(exc.value) == "b2b_capability_mismatch"
        # Right profile, a different reserved session id: no cap for it.
        token = _api_request_profile.set(lane.profile)
        try:
            with pytest.raises(B2BTerminalRefusal) as exc:
                APIServerAdapter._create_agent(
                    _adapter(lane), session_id="b2b_" + "b" * 64)
        finally:
            _api_request_profile.reset(token)
        assert str(exc.value) == "b2b_capability_mismatch"
    finally:
        reset_execution(cap_token)
    assert _attempt_status(lane) == "context_ready"


def test_create_agent_b2b_refuses_caller_overrides(b2b_runtime_lane, monkeypatch):
    lane = b2b_runtime_lane
    project = lane.policy["project"]
    for override in (
            {"requested_model": "other-model"},
            {"requested_model": None, "requested_provider": "other-provider"},
            {"route": {"model": project["model"]}},
            {"session_model": project["model"]},
            {"model_options": {}},
            {"ephemeral_system_prompt": "x"},
            {"gateway_session_key": "k"},
            {"room_dispatch": {}},
            {"room_execution_policy": {}}):
        with pytest.raises(B2BTerminalRefusal) as exc:
            _guarded_create(
                lane, _adapter(lane), monkeypatch,
                session_id=lane.session_id, **override)
        assert str(exc.value) == "b2b_policy_override", override
    assert _attempt_status(lane) == "context_ready"


def test_create_agent_b2b_refuses_active_cap_on_generic_session(b2b_runtime_lane):
    lane = b2b_runtime_lane
    cap_token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            APIServerAdapter._create_agent(_adapter(lane), session_id="api_ordinary")
    finally:
        reset_execution(cap_token)
    assert str(exc.value) == "b2b_capability_mismatch"
    assert _attempt_status(lane) == "context_ready"
