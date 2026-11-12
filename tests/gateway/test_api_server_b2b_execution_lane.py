"""L2 governed construction + dispatch, CLOSED until the C1 context producer
ships (``website/docs/developer-guide/b2b-c1-producer-contract.md``):
preparation (pinned r2 contract root, My Work roots, inert-init serving
config) is validated separately from readiness, and readiness stays False
even on complete preparation. The preparation helpers stay correct and are
exercised directly; the admitted-cap guard remains fail-closed.

All context/source data are UNIT DOUBLES; the construction itself is real.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import weakref
from types import SimpleNamespace
from typing import Optional

import pytest

from agent.b2b_execution import (
    B2BTerminalRefusal, R2_SCHEMA_PINS, bind_execution, reset_execution,
    extract_allowed_refs, validate_proposal,
)
from gateway.platforms import api_server_b2b as b2b
from gateway.platforms import api_server_b2b_execution as b2b_exec
from gateway.platforms.api_server import APIServerAdapter, _api_request_profile
from gateway.platforms.api_server_b2b_execution import (
    b2b_execution_ready, b2b_execution_status, construct_b2b_agent)
from hermes_state import SessionDB
from tests.gateway import b2b_unit_fixtures
from tests.gateway.b2b_process_harness import (
    extract_contract_root, renew_unit_oc_read)


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
# b2b_execution_inputs_ready + typed code — the preparation predicate, and
# b2b_execution_ready, closed until the C1 producer ships
# ---------------------------------------------------------------------------

def test_inputs_ready_when_all_inputs_on_disk(tmp_path):
    """Complete preparation is still not readiness: with every operator input
    on disk the lane reports ``c1_producer_unavailable`` and stays closed."""
    lane = _ready_lane(tmp_path)
    assert b2b_exec.b2b_execution_inputs_ready(lane.project, _INERT_CONFIG) is True
    assert b2b_exec.b2b_execution_unavailable_code(
        lane.project, _INERT_CONFIG) == "c1_producer_unavailable"
    assert b2b_execution_ready(lane.project, _INERT_CONFIG) is False
    lane.store.close()


def test_execution_ready_never_opens_without_c1(tmp_path):
    """No input set opens execution in this delivery: fully prepared and
    unprepared projects both leave ``b2b_execution_ready`` False."""
    lane = _ready_lane(tmp_path)
    assert b2b_execution_ready(lane.project, _INERT_CONFIG) is False
    unprepared = dict(lane.project)
    unprepared["project_context"] = None
    assert b2b_execution_ready(unprepared, _INERT_CONFIG) is False
    assert b2b_execution_ready(unprepared, {}) is False
    lane.store.close()


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
    assert b2b_exec.b2b_execution_inputs_ready(project, config) is False, mutation
    assert b2b_exec.b2b_execution_unavailable_code(
        project, config) == "execution_inputs_unavailable", mutation
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
    assert b2b_exec.b2b_execution_inputs_ready(lane.project, _INERT_CONFIG) is False
    assert hashlib.sha256(open(path, "rb").read()).hexdigest() != R2_SCHEMA_PINS[name]
    lane.store.close()


# ---------------------------------------------------------------------------
# b2b_execution_status — the smoke-visible lane diagnostic (per profile)
# ---------------------------------------------------------------------------

def _state(profiles):
    return b2b._B2BState(b2b.B2BConfig({"enabled": True, "profiles": profiles}))


def _status_adapter(state):
    return SimpleNamespace(
        _b2b_state=state, _profile_scope=APIServerAdapter._profile_scope)


def _profile_config_dir(profile):
    """``<HERMES_HOME>/profiles/<profile>`` — the named home the profile scope
    resolves; created so its own config.yaml is the serving config."""
    from hermes_constants import get_hermes_home
    home = get_hermes_home() / "profiles" / profile
    home.mkdir(parents=True, exist_ok=True)
    return home


def _write_serving_config(home, *, context_length=256000,
                          compression_enabled=False):
    ctx = f"  context_length: {context_length}\n" if context_length else ""
    with open(os.path.join(str(home), "config.yaml"), "w") as fh:
        fh.write(
            "model:\n  default: unit-double\n  provider: custom\n"
            '  base_url: "http://127.0.0.1:1/v1"\n'
            f"  api_mode: chat_completions\n{ctx}"
            f"compression:\n  enabled: {'true' if compression_enabled else 'false'}\n")


def _lane_entry(lane, **over):
    entry = {"source_url": "http://127.0.0.1:1/internal/dubsar/b2b/source",
             "portal_issuer": "portal-h1", "hermes_issuer": "hermes-h1-hub",
             "portal_public_key_pem": lane.entry["portal_public_key_pem"],
             "hermes_private_key_pem": lane.entry["hermes_private_key_pem"],
             "projects": {"b2b-bench": lane.project}}
    entry.update(over)
    return entry


def test_execution_status_not_configured_without_lane():
    for state in (None, b2b._B2BState(b2b.B2BConfig(None))):
        assert b2b_execution_status(_status_adapter(state)) == {
            "b2b_execution": "not-configured", "b2b_execution_code": None,
            "b2b_execution_profiles": {}}


def test_execution_status_not_ready_codes(tmp_path):
    """Enabled lane health is never ``ready``: complete preparation maps to
    ``c1_producer_unavailable``; anything missing/incoherent maps to
    ``execution_inputs_unavailable``."""
    lane = _ready_lane(tmp_path)
    _write_serving_config(_profile_config_dir("hub"))
    state = _state({"hub": _lane_entry(lane)})
    status = b2b_execution_status(_status_adapter(state))
    assert status == {
        "b2b_execution": "not-ready",
        "b2b_execution_code": "c1_producer_unavailable",
        "b2b_execution_profiles": {
            "hub": {"state": "not-ready", "code": "c1_producer_unavailable"}}}

    broken = dict(lane.project)
    broken["project_context"] = None
    state = _state({"hub": _lane_entry(lane, projects={"b2b-bench": broken})})
    status = b2b_execution_status(_status_adapter(state))
    assert status["b2b_execution"] == "not-ready"
    assert status["b2b_execution_code"] == "execution_inputs_unavailable"
    assert status["b2b_execution_profiles"] == {
        "hub": {"state": "not-ready", "code": "execution_inputs_unavailable"}}
    lane.store.close()


def test_execution_status_empty_profiles_fail_closed(tmp_path):
    """An enabled lane with an empty profiles map — unreachable through
    B2BConfig validation but defensible against — fails closed, never ready."""
    state = SimpleNamespace(
        config=SimpleNamespace(enabled=True, profiles={}))
    status = b2b_execution_status(_status_adapter(state))
    assert status == {
        "b2b_execution": "not-ready",
        "b2b_execution_code": "execution_inputs_unavailable",
        "b2b_execution_profiles": {}}


def test_execution_status_each_profile_under_own_scope(tmp_path):
    """Multiplex A->B->A: each profile's projects are judged under ITS OWN
    serving config — hub's inert config must never mask ci's missing pin —
    and revisiting hub after ci rebinds hub's scope (no cross-profile leak)."""
    import contextlib
    lane = _ready_lane(tmp_path)
    _write_serving_config(_profile_config_dir("hub"))
    _write_serving_config(_profile_config_dir("ci"), context_length=None)
    state = _state({"hub": _lane_entry(lane), "ci": _lane_entry(lane)})

    from agent.secret_scope import set_multiplex_active
    from hermes_cli.profiles import get_active_profile_name
    seen = []
    real_scope = APIServerAdapter._profile_scope

    @contextlib.contextmanager
    def _spy_scope(profile):
        with real_scope(profile):
            seen.append((profile, get_active_profile_name()))
            yield

    adapter = _status_adapter(state)
    adapter._profile_scope = _spy_scope
    set_multiplex_active(True)
    try:
        status = b2b_execution_status(adapter)
        second = b2b_execution_status(adapter)
    finally:
        set_multiplex_active(False)
    assert status["b2b_execution"] == "not-ready"
    assert status["b2b_execution_profiles"] == {
        "hub": {"state": "not-ready", "code": "c1_producer_unavailable"},
        "ci": {"state": "not-ready", "code": "execution_inputs_unavailable"}}
    assert status["b2b_execution_code"] == "execution_inputs_unavailable"
    assert second["b2b_execution_profiles"] == status["b2b_execution_profiles"]
    # A->B->A->B: every evaluation saw the profile it claimed to be under.
    assert seen == [("hub", "hub"), ("ci", "ci"), ("hub", "hub"), ("ci", "ci")]
    lane.store.close()


def test_execution_status_classifies_through_single_function(tmp_path, monkeypatch):
    """``/health/detailed`` and the POST gate share ONE classification
    function — never a second inline implementation: patch
    ``b2b_execution_unavailable_code`` and the reported per-profile code
    follows it."""
    lane = _ready_lane(tmp_path)
    _write_serving_config(_profile_config_dir("hub"))
    state = _state({"hub": _lane_entry(lane)})
    adapter = _status_adapter(state)
    calls = []

    def _spy(project, config):
        calls.append(project)
        return "execution_inputs_unavailable"

    monkeypatch.setattr(
        b2b_exec, "b2b_execution_unavailable_code", _spy)
    status = b2b_execution_status(adapter)
    assert calls, "status bypassed the single classifier"
    assert status["b2b_execution_profiles"] == {
        "hub": {"state": "not-ready", "code": "execution_inputs_unavailable"}}
    lane.store.close()


def test_execution_status_default_profile_under_own_home(tmp_path):
    """Multiplex ``/p/<other>/health/detailed`` binds the OTHER profile's
    home as ambient (prefix middleware -> ``asyncio.to_thread`` copies the
    context): the B2B ``default`` entry must still be judged under the
    DEFAULT home's own serving config, never the request's ambient home."""
    import contextlib
    from agent.secret_scope import set_multiplex_active
    from gateway.run import _profile_runtime_scope
    from hermes_cli.profiles import get_active_profile_name, get_profile_dir
    lane = _ready_lane(tmp_path)
    hub_home = _profile_config_dir("hub")
    _write_serving_config(hub_home, context_length=None)   # non-inert
    _write_serving_config(get_profile_dir("default"))       # inert pins
    state = _state({"default": _lane_entry(lane), "hub": _lane_entry(lane)})

    seen = []
    real_scope = APIServerAdapter._profile_scope

    @contextlib.contextmanager
    def _spy_scope(profile):
        with real_scope(profile):
            seen.append((profile, get_active_profile_name()))
            yield

    adapter = _status_adapter(state)
    adapter._profile_scope = _spy_scope
    set_multiplex_active(True)
    try:
        with _profile_runtime_scope(hub_home):   # /p/hub/ ambient binding
            status = b2b_execution_status(adapter)
    finally:
        set_multiplex_active(False)
    assert status["b2b_execution_profiles"] == {
        "default": {"state": "not-ready", "code": "c1_producer_unavailable"},
        "hub": {"state": "not-ready", "code": "execution_inputs_unavailable"}}
    assert status["b2b_execution_code"] == "execution_inputs_unavailable"
    assert seen == [("default", "default"), ("hub", "hub")]
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


def _write_inert_config(home, provider_base_url, *, provider="custom",
                        default_model="serving-double"):
    with open(os.path.join(str(home), "config.yaml"), "w") as fh:
        fh.write(
            f"model:\n  default: {default_model}\n  provider: {provider}\n"
            f'  base_url: "{provider_base_url}"\n'
            "  api_mode: chat_completions\n  context_length: 256000\n"
            "compression:\n  enabled: false\n")


def test_create_agent_b2b_constructs_bounded_agent_when_ready(
        tmp_path, monkeypatch):
    """The admitted lane with real operator inputs builds a real AIAgent
    frozen by install_bounded_agent_policy — model/provider/base_url/api_key
    from the PROJECT-pinned provider resolution, never the serving profile's
    default route. Production admission never reaches this path (readiness
    is closed until C1); the test-only harness lifts availability to keep
    the preparation code itself verified."""
    lane = _ready_lane(tmp_path)
    _rebind_project(lane, model="b2b-pinned-model")
    from hermes_constants import get_hermes_home
    import gateway.run as gw_run
    monkeypatch.setattr(gw_run, "_hermes_home", get_hermes_home())
    _write_inert_config(get_hermes_home(), lane.project["base_url"])
    # An UNRELATED default-route credential is present: a bare loopback custom
    # pin must resolve its own placeholder, never adopt the foreign key.
    monkeypatch.setenv("OPENAI_API_KEY", "sk-unit-unrelated-" + "0" * 8)
    # TEST-ONLY availability lift: production ``b2b_execution_ready`` stays
    # False until the C1 producer ships — no production bypass is added.
    monkeypatch.setattr(
        b2b_exec, "b2b_execution_ready", lambda *a, **k: True)
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
    assert agent.api_key == "no-key-required"
    assert agent._runtime_context_length == 256000
    assert agent.context_compressor.context_length == 256000
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
# construct_b2b_agent — preparation code kept correct under the closed lane:
# ONLY the project's pinned provider resolution may supply credentials; any
# mismatch or missing pinned auth refuses before AIAgent exists.
# ---------------------------------------------------------------------------

def _construction_adapter(lane):
    from pathlib import Path
    return SimpleNamespace(
        _b2b_state=lane.adapter._b2b_state,
        _ensure_session_db=lambda: SessionDB(
            Path(str(lane.db_path) + ".sess.db")))


def _rebind_project(lane, **over):
    """Re-point the cap's frozen policy at a mutated project (same shape the
    fixture's policy binding produced — fingerprint covers the ORIGINAL
    entry project, so the admission-time fingerprint stays consistent)."""
    from agent.b2b_execution import BoundExecution
    project = dict(lane.project)
    project.update(over)
    policy = dict(lane.policy)
    policy["project"] = project
    lane.cap = BoundExecution(
        profile=lane.cap.profile, session_id=lane.cap.session_id,
        binding_digest=lane.cap.binding_digest, attempt_id=lane.cap.attempt_id,
        run_id=lane.cap.run_id, policy=policy, sink=lane.sink,
        created_at=lane.cap.created_at)
    lane.project = project


def _construct(lane):
    return construct_b2b_agent(
        _construction_adapter(lane), lane.cap, session_id=lane.session_id,
        stream_delta_callback=None, tool_progress_callback=None,
        tool_start_callback=None, tool_complete_callback=None,
        interim_assistant_callback=None, reasoning_callback=None,
        status_callback=None)


def _agent_tripwire(monkeypatch):
    """Fail if construction reaches AIAgent at all; also tripwire model
    metadata/network fetches a bounded project must never need."""
    import run_agent
    import agent.agent_init as ainit

    def _no_agent(*a, **k):
        raise AssertionError("AIAgent must not be constructed")

    def _no_metadata(*a, **k):
        raise AssertionError("model metadata fetch must not run")

    monkeypatch.setattr(run_agent, "AIAgent", _no_agent)
    monkeypatch.setattr(ainit, "fetch_model_metadata", _no_metadata)


def test_construct_b2b_agent_refuses_runtime_route_mismatch(
        tmp_path, monkeypatch):
    """The resolver's route must match the project pin exactly (trailing '/'
    aside): a resolved base_url pointing anywhere else refuses durably and
    no AIAgent is built."""
    lane = _ready_lane(tmp_path)
    from hermes_constants import get_hermes_home
    _write_inert_config(get_hermes_home(), "http://127.0.0.1:9/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-unit-" + "0" * 8)
    _agent_tripwire(monkeypatch)
    cap_token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            _construct(lane)
    finally:
        reset_execution(cap_token)
    assert str(exc.value) == "policy_provider_unavailable"
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)[
            "status"] == "failed"
    lane.store.close()


def test_construct_b2b_agent_refuses_missing_pinned_auth(
        tmp_path, monkeypatch):
    """No credential for the project's pinned provider refuses even when an
    UNRELATED key exists (ANTHROPIC_API_KEY is never an OpenRouter
    credential home — resolver semantics, not a leak)."""
    lane = _ready_lane(tmp_path)
    from hermes_constants import get_hermes_home, OPENROUTER_BASE_URL
    _write_inert_config(get_hermes_home(), "http://127.0.0.1:9/v1")
    _rebind_project(lane, provider="openrouter", base_url=OPENROUTER_BASE_URL)
    for name in ("OPENROUTER_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-unit-unrelated-" + "0" * 8)
    _agent_tripwire(monkeypatch)

    def _no_pool(*a, **k):
        raise AssertionError("default-profile resolution must not run")

    monkeypatch.setattr(
        "gateway.run._resolve_runtime_agent_kwargs", _no_pool)
    cap_token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            _construct(lane)
    finally:
        reset_execution(cap_token)
    assert str(exc.value) == "policy_provider_unavailable"
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)[
            "status"] == "failed"
    lane.store.close()


def test_construct_b2b_agent_pinned_openrouter_route(tmp_path, monkeypatch):
    """Different-route construction: the project pins openrouter while the
    serving profile's default route is an unrelated custom endpoint. Only
    the openrouter credential/route may be used; the explicit context pin
    lands on agent + compressor and the OpenRouter metadata prewarm is
    skipped (no metadata/HTTP needed for a pinned bounded project)."""
    lane = _ready_lane(tmp_path)
    from hermes_constants import get_hermes_home, OPENROUTER_BASE_URL
    import gateway.run as gw_run
    monkeypatch.setattr(gw_run, "_hermes_home", get_hermes_home())
    # Serving default route deliberately unrelated to the project pin.
    _write_inert_config(get_hermes_home(), "http://127.0.0.1:9/v1")
    _rebind_project(lane, provider="openrouter", base_url=OPENROUTER_BASE_URL)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-unit-" + "1" * 8)
    for name in ("OPENAI_API_KEY", "OPENAI_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        b2b_exec, "b2b_execution_ready", lambda *a, **k: True)
    import agent.agent_init as ainit
    ainit._ra()._openrouter_prewarm_done.clear()

    def _no_metadata(*a, **k):
        raise AssertionError("model metadata fetch must not run")

    monkeypatch.setattr(ainit, "fetch_model_metadata", _no_metadata)
    token = _api_request_profile.set(lane.profile)
    cap_token = bind_execution(lane.cap)
    try:
        agent = APIServerAdapter._create_agent(
            _adapter(lane), session_id=lane.session_id)
    finally:
        reset_execution(cap_token)
        _api_request_profile.reset(token)
    assert agent.provider == "openrouter"
    assert agent.api_key == "sk-or-unit-" + "1" * 8
    assert str(agent.base_url).rstrip("/") == OPENROUTER_BASE_URL
    assert agent._runtime_context_length == 256000
    assert agent.context_compressor.context_length == 256000
    assert agent.compression_enabled is False
    assert agent._credential_pool is None
    assert not ainit._ra()._openrouter_prewarm_done.is_set()
    lane.store.close()


def _write_named_provider_config(home, *, named_url, default_url):
    """Serving config whose DEFAULT route is unrelated (openrouter) while a
    ``providers:`` entry owns the pinned endpoint the project names."""
    with open(os.path.join(str(home), "config.yaml"), "w") as fh:
        fh.write(
            'model:\n  default: serving-double\n  provider: openrouter\n'
            f'  base_url: "{default_url}"\n'
            "  api_mode: chat_completions\n  context_length: 256000\n"
            "compression:\n  enabled: false\n"
            "providers:\n  b2b-g2:\n"
            '    name: "b2b-g2"\n'
            f'    base_url: "{named_url}"\n'
            '    key_env: "B2B_G2_API_KEY"\n'
            '    api_mode: "chat_completions"\n')


def test_construct_b2b_agent_named_custom_provider(tmp_path, monkeypatch):
    """``custom:b2b-g2`` pin: the named ``providers:`` entry supplies the ONLY
    route — its key_env credential lands on the agent while the unrelated
    openrouter default route and foreign keys are never touched."""
    lane = _ready_lane(tmp_path)
    named_url = "http://127.0.0.1:8443/v1"
    sentinel = "sk-unit-b2bg2-" + "7" * 8
    _rebind_project(lane, provider="custom:b2b-g2", base_url=named_url,
                    model="b2b-g2-model")
    from hermes_constants import get_hermes_home
    import gateway.run as gw_run
    monkeypatch.setattr(gw_run, "_hermes_home", get_hermes_home())
    _write_named_provider_config(
        get_hermes_home(), named_url=named_url,
        default_url="http://127.0.0.1:9/v1")
    monkeypatch.setenv("B2B_G2_API_KEY", sentinel)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-unit-unrelated-" + "0" * 8)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-unit-unrelated-" + "1" * 8)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    def _no_default(*a, **k):
        raise AssertionError("default-profile resolution must not run")

    monkeypatch.setattr(
        "gateway.run._resolve_runtime_agent_kwargs", _no_default)
    import agent.agent_init as ainit

    def _no_metadata(*a, **k):
        raise AssertionError("model metadata fetch must not run")

    monkeypatch.setattr(ainit, "fetch_model_metadata", _no_metadata)
    monkeypatch.setattr(
        b2b_exec, "b2b_execution_ready", lambda *a, **k: True)
    token = _api_request_profile.set(lane.profile)
    cap_token = bind_execution(lane.cap)
    try:
        agent = APIServerAdapter._create_agent(
            _adapter(lane), session_id=lane.session_id)
    finally:
        reset_execution(cap_token)
        _api_request_profile.reset(token)
    assert agent.api_key == sentinel
    assert agent.model == "b2b-g2-model"
    assert str(agent.base_url).rstrip("/") == named_url.rstrip("/")
    assert agent._runtime_context_length == 256000
    assert agent.context_compressor.context_length == 256000
    lane.store.close()


def test_construct_b2b_agent_refuses_resolved_provider_mismatch(
        tmp_path, monkeypatch):
    """Echo is not proof: a resolver returning a DIFFERENT effective provider
    than the pin's canonical one — even with requested_provider echoing the
    pin and a matching URL — refuses before any constructor runs."""
    lane = _ready_lane(tmp_path)
    from hermes_constants import get_hermes_home
    _write_inert_config(get_hermes_home(), lane.project["base_url"])
    _agent_tripwire(monkeypatch)
    seen = {}

    def _forged(provider, target_model=None):
        seen["args"] = (provider, target_model)
        return {"provider": "openrouter",
                "requested_provider": lane.project["provider"],
                "base_url": lane.project["base_url"],
                "api_key": "sk-or-unit-forged",
                "api_mode": lane.project["api_mode"],
                "command": None, "args": [], "credential_pool": None,
                "request_overrides": {}, "capabilities": {}}

    import gateway.run as gw_run
    monkeypatch.setattr(
        gw_run, "_resolve_runtime_agent_kwargs_for_provider", _forged)
    cap_token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            _construct(lane)
    finally:
        reset_execution(cap_token)
    assert str(exc.value) == "policy_provider_unavailable"
    assert seen["args"][0] == lane.project["provider"]
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)[
            "status"] == "failed"
    lane.store.close()


@pytest.mark.parametrize(
    "provider", ["auto", "", "no-such-provider", "custom:no-such-entry"])
def test_construct_b2b_agent_refuses_unknown_provider_pin(
        tmp_path, monkeypatch, provider):
    """An empty/"auto"/unknown provider pin — or a named-custom entry that
    does not exist — refuses BEFORE the credential resolver runs: the pin
    names one provider, never a search."""
    lane = _ready_lane(tmp_path)
    _rebind_project(lane, provider=provider)
    from hermes_constants import get_hermes_home
    _write_inert_config(get_hermes_home(), lane.project["base_url"])
    _agent_tripwire(monkeypatch)

    def _no_resolver(*a, **k):
        raise AssertionError("credential resolver must not run")

    import gateway.run as gw_run
    monkeypatch.setattr(
        gw_run, "_resolve_runtime_agent_kwargs_for_provider", _no_resolver)
    cap_token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            _construct(lane)
    finally:
        reset_execution(cap_token)
    assert str(exc.value) == "policy_provider_unavailable"
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)[
            "status"] == "failed"
    lane.store.close()


@pytest.mark.parametrize("value", [True, 0, -5, "256000"])
def test_init_agent_context_length_rejects_invalid(
        tmp_path, monkeypatch, value):
    """A supplied runtime context pin must be a positive non-bool int —
    validated before routing/metadata can run; ``None`` stays allowed."""
    import agent.agent_init as ainit

    def _no_metadata(*a, **k):
        raise AssertionError("model metadata fetch must not run")

    monkeypatch.setattr(ainit, "fetch_model_metadata", _no_metadata)
    import run_agent
    with pytest.raises(ValueError):
        run_agent.AIAgent(
            model="unit-double", provider="custom",
            api_mode="chat_completions", base_url="http://127.0.0.1:1/v1",
            api_key="no-key-required", session_id="api_unit_ctx",
            context_length=value)


def test_init_agent_context_length_none_allowed(tmp_path, monkeypatch):
    """``context_length=None`` is the default — no pin, ordinary resolution."""
    import agent.agent_init as ainit

    def _no_metadata(*a, **k):
        raise AssertionError("model metadata fetch must not run")

    monkeypatch.setattr(ainit, "fetch_model_metadata", _no_metadata)
    import run_agent
    agent = run_agent.AIAgent(
        model="unit-double", provider="custom",
        api_mode="chat_completions", base_url="http://127.0.0.1:1/v1",
        api_key="no-key-required", session_id="api_unit_ctx_none",
        context_length=None, skip_memory=True, skip_context_files=True)
    assert agent._runtime_context_length is None


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


def _bound_lane_agent(lane):
    """Dispatch-lane agent with the real cap binding perform_api_call reads."""
    agent = _LaneAgent(
        session_id=lane.session_id, api_mode="chat_completions",
        provider=lane.project["provider"], model=lane.project["model"],
        base_url=lane.project["base_url"], platform="api_server",
        is_subagent=False, _fallback_index=0, _disable_streaming=True,
        thinking_callback=None, _b2b_execution=lane.cap,
        _model_request_active=None, _pending_redirect_lock=None,
        _pending_redirect=None)
    object.__setattr__(lane.cap, "_agent_ref", weakref.ref(agent))
    return agent


def _api_call_args(agent, **over):
    args = dict(
        api_kwargs={"model": "unit-double", "messages": []},
        _original_api_kwargs={}, _llm_middleware_trace=[],
        _moa_prepared_request=None, _retry=SimpleNamespace(),
        thinking_spinner=None, retry_count=0, api_call_count=0,
        api_request_id="req", effective_task_id="task",
        turn_id="t0", interrupted=False)
    args.update(over)
    return args


def test_perform_api_call_requires_execution_at_entry(tmp_path, monkeypatch):
    """The capability check runs BEFORE middleware: a bound cap on a foreign
    session refuses at entry — middleware can never launder the lane."""
    from agent import turn_api_call as tac

    lane = _ready_lane(tmp_path)
    agent = _LaneAgent(
        session_id="api_foreign", api_mode="chat_completions",
        provider="custom", base_url="http://127.0.0.1:9/v1",
        model="unit-double", platform="api_server", is_subagent=False,
        _fallback_index=0, _disable_streaming=True, thinking_callback=None,
        _b2b_execution=None, _model_request_active=None,
        _pending_redirect_lock=None, _pending_redirect=None,
        client=object())

    def _no_middleware(*a, **k):
        raise AssertionError("middleware must not run before the cap check")

    monkeypatch.setattr(
        "hermes_cli.middleware.run_llm_execution_middleware", _no_middleware)
    cap_token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            tac.perform_api_call(agent, **_api_call_args(agent))
    finally:
        reset_execution(cap_token)
    assert str(exc.value) == "b2b_capability_mismatch"
    lane.store.close()


def _commit_attested_result(lane):
    """Drive the REAL sink through dispatch + result commit so the durable
    provider_result artifact exists — the only response attestable."""
    lane.sink._before_provider = lane.resolved
    assert lane.sink.cas_dispatch(
        request_digest=lane.policy["request_digest"], receipt=lane.receipt,
        rechecked_view=renew_unit_oc_read(lane.view))
    text = json.dumps({"summary": "s", "steps": ["st"], "source_refs": [],
                       "limitations": []})
    parsed, reason = validate_proposal(
        text, extract_allowed_refs(lane.receipt.view))
    assert parsed is not None and reason == "ok"
    lane.sink.commit_result(text=text, parsed=parsed, reason=reason)
    return SimpleNamespace(choices=[SimpleNamespace(
        finish_reason="stop", index=0,
        message=SimpleNamespace(
            role="assistant", content=text, refusal=None,
            tool_calls=None))])


def test_perform_api_call_middleware_short_circuit_unattested(
        tmp_path, monkeypatch):
    """Middleware returning a response WITHOUT running the terminal callback
    fails ``middleware_response_unattested`` at the post-middleware gate —
    the forged response never reaches response intake."""
    from agent import b2b_execution as be
    from agent import turn_api_call as tac

    lane = _ready_lane(tmp_path)
    agent = _bound_lane_agent(lane)
    _commit_attested_result(lane)
    forged = SimpleNamespace(choices=[SimpleNamespace(
        finish_reason="stop",
        message=SimpleNamespace(role="assistant", content="forged"))])

    def _short_circuit(kwargs, call, **kw):
        return forged

    monkeypatch.setattr(
        "hermes_cli.middleware.run_llm_execution_middleware", _short_circuit)
    cap_token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            tac.perform_api_call(agent, **_api_call_args(agent))
    finally:
        reset_execution(cap_token)
    assert str(exc.value) == "middleware_response_unattested"
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)[
            "status"] == "result_invalid"
    lane.store.close()


def test_perform_api_call_middleware_replaced_response_unattested(
        tmp_path, monkeypatch):
    """Middleware that DOES run the terminal callback but substitutes the
    downstream response is caught identically: validation re-attests the
    object actually returned, not the one execute_terminal produced."""
    from agent import turn_api_call as tac

    lane = _ready_lane(tmp_path)
    agent = _bound_lane_agent(lane)
    attested = _commit_attested_result(lane)
    forged = SimpleNamespace(choices=[SimpleNamespace(
        finish_reason="stop",
        message=SimpleNamespace(role="assistant", content="forged"))])

    monkeypatch.setattr(
        "agent.b2b_execution.execute_terminal",
        lambda *a, **k: attested)

    def _replace(kwargs, call, **kw):
        call(kwargs)
        return forged

    monkeypatch.setattr(
        "hermes_cli.middleware.run_llm_execution_middleware", _replace)
    cap_token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            tac.perform_api_call(agent, **_api_call_args(agent))
    finally:
        reset_execution(cap_token)
    assert str(exc.value) == "middleware_response_unattested"
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)[
            "status"] == "result_invalid"
    lane.store.close()


def test_perform_api_call_middleware_passthrough_validated(
        tmp_path, monkeypatch):
    """Pass-through middleware + the real attested response: the real
    validate_terminal_result accepts and the verdict falls through."""
    from agent import turn_api_call as tac

    lane = _ready_lane(tmp_path)
    agent = _bound_lane_agent(lane)
    attested = _commit_attested_result(lane)

    monkeypatch.setattr(
        "agent.b2b_execution.execute_terminal",
        lambda *a, **k: attested)
    cap_token = bind_execution(lane.cap)
    try:
        verdict = tac.perform_api_call(agent, **_api_call_args(agent))
    finally:
        reset_execution(cap_token)
    assert verdict.action == "fallthrough" and verdict.response is attested
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)[
            "status"] == "result_received"
    lane.store.close()


# ---------------------------------------------------------------------------
# _handle_health_detailed — B2B diagnostic off the event loop, per profile
# ---------------------------------------------------------------------------

def test_health_detailed_reports_b2b_not_ready_off_loop(
        tmp_path, monkeypatch):
    """Real handler path: ``b2b_execution_status`` runs off the event loop
    (witness: a held config read cannot stall a heartbeat) and each enabled
    profile is judged under its own serving config."""
    from gateway.config import PlatformConfig

    lane = _ready_lane(tmp_path)
    _write_serving_config(_profile_config_dir("hub"))
    _write_serving_config(_profile_config_dir("ci"), context_length=None)
    extra = {"key": "k" * 32,
             "b2b": {"enabled": True, "profiles": {
                 "hub": _lane_entry(lane), "ci": _lane_entry(lane)}}}
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra=extra))
    adapter.gateway_runner = SimpleNamespace(
        config=SimpleNamespace(multiplex_profiles=False))

    held = threading.Event()
    release = threading.Event()
    idents = []
    real_contract_ready = b2b_exec._contract_root_ready

    def _witness(root):
        idents.append(threading.get_ident())
        held.set()
        # Bounded even if the releasing side never runs (worker error, base
        # code blocking the loop): wait out the cap, never hang the suite.
        release.wait(10)
        return real_contract_ready(root)

    monkeypatch.setattr(b2b_exec, "_contract_root_ready", _witness)

    main_ident = threading.get_ident()
    heartbeat_done = []

    async def _run():
        request = SimpleNamespace(
            headers={"Authorization": "Bearer " + "k" * 32})
        task = asyncio.create_task(
            adapter._handle_health_detailed(request))
        # While contract hashing is HELD in a worker, the loop still turns.
        while not held.is_set():
            await asyncio.sleep(0)
        await asyncio.sleep(0)
        heartbeat_done.append(threading.get_ident())
        # Heartbeat proven while the config read was still held — release
        # the worker now rather than waiting out the bounded cap.
        release.set()
        return await task

    loop = asyncio.new_event_loop()
    try:
        response = loop.run_until_complete(
            asyncio.wait_for(_run(), timeout=30))
    finally:
        release.set()
        loop.close()
    payload = json.loads(response.body)
    assert idents, "preparation evaluation never ran"
    assert all(ident != main_ident for ident in idents)
    assert heartbeat_done == [main_ident]
    assert payload["b2b_execution"] == "not-ready"
    assert payload["b2b_execution_code"] == "execution_inputs_unavailable"
    assert payload["b2b_execution_profiles"] == {
        "hub": {"state": "not-ready", "code": "c1_producer_unavailable"},
        "ci": {"state": "not-ready", "code": "execution_inputs_unavailable"}}
    lane.store.close()
