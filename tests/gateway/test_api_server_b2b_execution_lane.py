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
import time
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
    """Without a bound native preparation, fully configured and
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
    # TEST-ONLY availability lift: a unit preparation stand-in supplies the
    # per-capability proof; production keeps requiring the real read.
    lane.sink._context_preparation = _UnitPreparation(lane.cap)
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
    # TEST-ONLY availability lift: a unit preparation stand-in supplies the
    # per-capability proof; production keeps requiring the real read.
    lane.sink._context_preparation = _UnitPreparation(lane.cap)
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
    # TEST-ONLY availability lift: a unit preparation stand-in supplies the
    # per-capability proof; production keeps requiring the real read.
    lane.sink._context_preparation = _UnitPreparation(lane.cap)
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


# ---------------------------------------------------------------------------
# P2 — context preparation + proof-driven readiness + hook receipt enforcement
#
# The producer plugin is NOT installed under the unit homes below, so
# prepare_b2b_context's real fail-closed refusal is exercised directly; the
# preparation OBJECT is stubbed where marked UNIT (attachment plumbing only —
# no readiness is faked through the production gate).
# ---------------------------------------------------------------------------

def _collect(agent, turn_id="t0", hook_results=None, monkeypatch=None):
    """Drive the REAL _collect_pre_llm_call_context with a scripted lifecycle
    invoke — the only patched seam is the hook dispatcher itself."""
    import hermes_cli.lifecycle as lifecycle
    from agent.turn_context import _collect_pre_llm_call_context
    monkeypatch.setattr(
        lifecycle, "invoke_hook", lambda *a, **k: list(hook_results or []))
    return _collect_pre_llm_call_context(
        agent, effective_task_id="task", turn_id=turn_id,
        original_user_message="m",
        messages=[{"role": "user", "content": "m"}],
        conversation_history=None)


def _prepped_lane(tmp_path):
    """A bound dispatch lane whose cap carries a registered recheck — the
    shape the plugin leaves after bound_context() publishes. The fixture's
    rebuilt cap never ran publish_context, so the receipt + agent/turn ref
    are restored onto it."""
    lane = _ready_lane(tmp_path)
    agent = _bound_lane_agent(lane)
    agent._current_turn_id = lane.turn_id
    object.__setattr__(lane.cap, "_receipt", lane.receipt)
    lane.agent = agent
    try:
        lane.cap.register_context_recheck(lambda _c: lane.view)
    except B2BTerminalRefusal:
        pass
    return lane


@pytest.fixture
def opened():
    """Close every SessionDB/RunIdempotencyStore the test registered."""
    resources = []
    yield resources
    for resource in resources:
        try:
            resource.close()
        except Exception:
            pass


def _status(lane):
    return lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)["status"]


def test_pre_llm_hook_b2b_exact_receipt_passes(tmp_path, monkeypatch):
    """Bound lane, plugin published the receipt for this turn and rendered it
    verbatim: the seam returns the receipt text unchanged (UNIT lane — the
    hook result is the only scripted input)."""
    lane = _prepped_lane(tmp_path)
    agent = lane.agent
    rendered = lane.receipt.rendered.decode("utf-8")
    token = bind_execution(lane.cap)
    try:
        out = _collect(agent, hook_results=[{"context": rendered}],
                       monkeypatch=monkeypatch)
    finally:
        reset_execution(token)
    assert out == rendered
    lane.store.close()


def test_pre_llm_hook_b2b_missing_receipt_refuses(tmp_path, monkeypatch):
    """Hook ran but no receipt was accepted for the cap: the seam refuses
    context_unavailable BEFORE the provider call — never passes "" onward."""
    lane = _prepped_lane(tmp_path)
    object.__setattr__(lane.cap, "_receipt", None)
    lane.sink.context_receipt = None
    agent = lane.agent
    token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            _collect(agent, hook_results=[], monkeypatch=monkeypatch)
    finally:
        reset_execution(token)
    assert str(exc.value) == "context_unavailable"
    assert _status(lane) == "context_unavailable"
    lane.store.close()


def test_pre_llm_hook_b2b_turn_mismatch_refuses(tmp_path, monkeypatch):
    """A receipt minted for t0 cannot serve t1 — wrong-turn publication is a
    stale-context refusal, classified context_stale on the sink."""
    lane = _prepped_lane(tmp_path)
    agent = lane.agent
    rendered = lane.receipt.rendered.decode("utf-8")
    token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            _collect(agent, turn_id="t1",
                     hook_results=[{"context": rendered}],
                     monkeypatch=monkeypatch)
    finally:
        reset_execution(token)
    assert str(exc.value) == "context_turn_mismatch"
    assert _status(lane) == "context_stale"
    lane.store.close()


def test_pre_llm_hook_b2b_unregistered_recheck_refuses(tmp_path, monkeypatch):
    """No registered fresh-read callback on the cap: publication cannot be
    re-proven at the boundaries, so the seam refuses before dispatch."""
    lane = _ready_lane(tmp_path)  # no register_context_recheck
    agent = _bound_lane_agent(lane)
    agent._current_turn_id = lane.turn_id
    object.__setattr__(lane.cap, "_receipt", lane.receipt)
    rendered = lane.receipt.rendered.decode("utf-8")
    token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            _collect(agent, hook_results=[{"context": rendered}],
                     monkeypatch=monkeypatch)
    finally:
        reset_execution(token)
    assert str(exc.value) == "context_recheck_unavailable"
    lane.store.close()


def test_pre_llm_hook_b2b_missing_contribution_refuses(tmp_path, monkeypatch):
    """Fail-open is a failure: the hook returning NOTHING on a bound lane
    refuses — the terminal must never run on unvalidated content."""
    lane = _prepped_lane(tmp_path)
    agent = lane.agent
    token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            _collect(agent, hook_results=[], monkeypatch=monkeypatch)
    finally:
        reset_execution(token)
    assert str(exc.value) == "context_absent_from_kwargs"
    assert _status(lane) == "context_stale"
    lane.store.close()


def test_pre_llm_hook_b2b_rewritten_contribution_refuses(tmp_path, monkeypatch):
    """A hook piece that differs from the receipt bytes is a rewrite — refused,
    never forwarded."""
    lane = _prepped_lane(tmp_path)
    agent = lane.agent
    token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            _collect(agent, hook_results=[{"context": "tampered"}],
                     monkeypatch=monkeypatch)
    finally:
        reset_execution(token)
    assert str(exc.value) == "context_absent_from_kwargs"
    lane.store.close()


@pytest.mark.parametrize("extra", ["extra", "dup"])
def test_pre_llm_hook_b2b_second_contribution_refuses(
        tmp_path, monkeypatch, extra):
    """Exactly ONE contribution may carry the receipt: a second nonempty piece
    — foreign OR a verbatim duplicate — is a publication conflict."""
    lane = _prepped_lane(tmp_path)
    agent = lane.agent
    rendered = lane.receipt.rendered.decode("utf-8")
    second = "foreign plugin output" if extra == "extra" else rendered
    token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            _collect(agent, hook_results=[{"context": rendered},
                                          {"context": second}],
                     monkeypatch=monkeypatch)
    finally:
        reset_execution(token)
    assert str(exc.value) == "context_publication_conflict"
    lane.store.close()


def test_pre_llm_hook_ordinary_lane_unchanged(tmp_path, monkeypatch):
    """No cap anywhere: hook context still flows through verbatim — the B2B
    seam never engages on ordinary sessions."""
    lane = _ready_lane(tmp_path)
    agent = _LaneAgent(
        session_id="api_ordinary", api_mode="chat_completions",
        provider="custom", base_url="http://127.0.0.1:9/v1",
        model="unit-double", platform="api_server", is_subagent=False,
        _b2b_execution=None)
    out = _collect(agent, hook_results=[{"context": "plugin ctx"}],
                   monkeypatch=monkeypatch)
    assert out == "plugin ctx"
    lane.store.close()


# --- prepare_b2b_context / prepared_context_ready / producer_available ------

def test_prepare_b2b_context_refuses_without_producer(tmp_path):
    """Real call, real failure: no installed dubsar-agent-context under this
    home -> typed context_unavailable, and NOTHING is attached to the sink."""
    from gateway.platforms.api_server_b2b_context import prepare_b2b_context
    lane = _ready_lane(tmp_path)
    with pytest.raises(B2BTerminalRefusal) as exc:
        prepare_b2b_context(lane.cap, resolved=lane.resolved)
    assert str(exc.value) == "context_unavailable"
    assert lane.sink._context_preparation is None
    lane.store.close()


def test_producer_available_is_local_introspection(tmp_path):
    """Diagnostics only: False without the plugin in THIS home — it can never
    stand in for mission proof (prepared_context_ready answers separately)."""
    from gateway.platforms.api_server_b2b_context import producer_available
    lane = _ready_lane(tmp_path)
    assert producer_available() is False
    lane.store.close()


def test_prepared_context_ready_requires_attached_preparation(tmp_path):
    """UNIT: a cap with no preparation attached answers False even under
    bind_execution — readiness is the preparation's, not the inputs'."""
    from gateway.platforms.api_server_b2b_context import prepared_context_ready
    lane = _ready_lane(tmp_path)
    token = bind_execution(lane.cap)
    try:
        assert prepared_context_ready(lane.cap, lane.project) is False
        assert b2b_execution_ready(lane.project, _INERT_CONFIG) is False
    finally:
        reset_execution(token)
    lane.store.close()


class _UnitPreparation:
    """UNIT stand-in for the frozen preparation — attachment plumbing only;
    it never feeds readiness (assert_* are explicit stubs)."""

    def __init__(self, cap, *, current=True, configuration=True,
                 publication=None, current_error=None,
                 configuration_error=None):
        from agent.b2b_execution import json_utf8
        self.cap = cap
        self.project_utf8 = json_utf8(cap.policy_get("project"))
        self._current, self._configuration, self._publication = (
            current, configuration, publication)
        self._current_error = current_error or "source_window_closed"
        self._configuration_error = configuration_error

    def assert_current(self, cap):
        if not self._current:
            raise B2BTerminalRefusal(self._current_error)

    def assert_configuration_current(self):
        if self._configuration_error is not None:
            raise B2BTerminalRefusal(self._configuration_error)
        return self._configuration

    def assert_publication(self, cap, receipt):
        if self._publication is not None:
            raise B2BTerminalRefusal(self._publication)


def test_prepared_context_ready_consults_preparation(tmp_path):
    """UNIT: readiness tracks the attached preparation's live check — True
    when current, False the moment the window/config check refuses."""
    from agent.b2b_execution import json_utf8
    from gateway.platforms.api_server_b2b_context import prepared_context_ready
    lane = _ready_lane(tmp_path)
    prep = _UnitPreparation(lane.cap)
    lane.sink._context_preparation = prep
    token = bind_execution(lane.cap)
    try:
        assert prepared_context_ready(lane.cap, lane.project) is True
        prep._current = False
        assert prepared_context_ready(lane.cap, lane.project) is False
        assert b2b_execution_ready(lane.project, _INERT_CONFIG) is False
    finally:
        reset_execution(token)
    lane.store.close()


def test_prepared_context_ready_rejects_project_mismatch(tmp_path):
    """UNIT: the preparation is bound to ITS project's exact policy bytes —
    a foreign project asking is not proof."""
    from gateway.platforms.api_server_b2b_context import prepared_context_ready
    lane = _ready_lane(tmp_path)
    lane.sink._context_preparation = _UnitPreparation(lane.cap)
    other = dict(lane.project)
    other["model"] = "other-model"
    assert prepared_context_ready(lane.cap, other) is False
    lane.store.close()


def test_sink_policy_gate_consults_preparation(tmp_path):
    """UNIT: once a preparation is attached, assert_current_policy fails
    closed on configuration drift — legacy sinks (None) are untouched."""
    lane = _ready_lane(tmp_path)
    assert lane.sink.assert_current_policy() is True
    prep = _UnitPreparation(lane.cap, configuration=False)
    lane.sink._context_preparation = prep
    assert lane.sink.assert_current_policy() is False
    prep._configuration = True
    assert lane.sink.assert_current_policy() is True
    lane.store.close()


def test_put_context_consults_preparation_publication(tmp_path):
    """UNIT: a preparation that cannot prove the receipt refuses BEFORE the
    durable artifact write — and the artifact stays absent."""
    lane = _ready_lane(tmp_path)
    prep = _UnitPreparation(lane.cap, publication="context_stale")
    lane.sink._context_preparation = prep
    lane.sink.context_receipt = None
    object.__setattr__(lane.cap, "_receipt", None)
    agent = _bound_lane_agent(lane)
    agent._current_turn_id = lane.turn_id
    token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            lane.cap.publish_context(lane.view, lane.receipt.rendered,
                                     turn_id="t0")
    finally:
        reset_execution(token)
    assert str(exc.value) == "context_stale"
    assert lane.sink.context_receipt is None
    lane.store.close()


# --- the single classifier's three codes ------------------------------------

def test_unavailable_code_distinguishes_producer_vs_proof(tmp_path, monkeypatch):
    """Inputs ready: producer MISSING -> c1_producer_unavailable; producer
    present but no current mission proof -> c1_context_required. Health can
    never answer ready on presence alone (no cap bound here, by design)."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    lane = _ready_lane(tmp_path)
    code = b2b_exec.b2b_execution_unavailable_code(lane.project, _INERT_CONFIG)
    assert code == "c1_producer_unavailable"
    monkeypatch.setattr(b2b_ctx, "producer_available", lambda: True)
    code = b2b_exec.b2b_execution_unavailable_code(lane.project, _INERT_CONFIG)
    assert code == "c1_context_required"
    lane.store.close()


def test_execution_status_reports_context_required(tmp_path, monkeypatch):
    """Health with the producer present but no mission binding: every profile
    reports c1_context_required — never an aggregate ready."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    monkeypatch.setattr(b2b_ctx, "producer_available", lambda: True)
    lane = _ready_lane(tmp_path)
    _write_serving_config(_profile_config_dir("hub"))
    state = _state({"hub": _lane_entry(lane)})
    status = b2b_execution_status(_status_adapter(state))
    assert status["b2b_execution"] == "not-ready"
    assert status["b2b_execution_code"] == "c1_context_required"
    assert status["b2b_execution_profiles"] == {
        "hub": {"state": "not-ready", "code": "c1_context_required"}}
    lane.store.close()


# --- _launch_b2b_run ordering: preparation before admission ------------------

def _launch_resolved(lane, profile="hub", session_id=None, expires_in=30):
    """A resolved source body in the exact shape _launch_b2b_run consumes —
    all signed envelopes + the mission policy fields, keyed to THIS lane."""
    session_id = session_id or lane.session_id
    now = time.time()
    p = lane.policy
    return {"source_state": "active",
            **{k: p[k] for k in
               ("attempt_id", "binding_digest", "requester_id", "project_id",
                "project_binding_id", "mission_id", "mission_revision",
                "profile", "session_id", "reservation_ref", "request_digest",
                "ticket_digest", "authority_basis_digest", "authority_digest",
                "observation_genesis", "mission_request")},
            "mission_source_digest": "c" * 64,
            "_signed_request": {"issued_at": now - 1,
                                "expires_at": now + expires_in},
            "_signed_response": {"issued_at": now - 1,
                                 "expires_at": now + expires_in - 1},
            "_request_raw": b"{}", "_response_raw": b"{}"}


@pytest.mark.asyncio
async def test_launch_prepare_refusal_denies_with_no_writes(
        tmp_path, monkeypatch, opened):
    """A refused preparation denies 503 execution_unavailable BEFORE
    admission: no attempt row, no binding, no title, no run — the in-memory
    sink/cap simply die."""
    from tests.gateway import test_api_server_b2b_admission as adm
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    prof = adm._profile_home(tmp_path, monkeypatch, "hub")
    _write_serving_config(prof)
    adapter = adm._adapter(tmp_path, monkeypatch, "hub")
    adapter._session_db = SessionDB(prof / "state.db")
    opened.extend([adapter._session_db, adapter._run_idempotency_store])
    lane = _ready_lane(tmp_path)
    entry = _lane_entry(
        lane, portal_issuer="portal-hub", hermes_issuer="hermes-hub")
    session_id = "b2b_" + "b" * 64
    adapter._session_db.create_session(session_id, "api_server")
    resolved = _launch_resolved(lane, session_id=session_id)
    policy_session = dict(resolved["observation_genesis"])
    policy_session["id"], policy_session["profile"] = session_id, "hub"
    resolved["observation_genesis"] = policy_session
    resolved["session_id"] = session_id
    resolved["binding_digest"] = session_id[4:]
    resolved["attempt_id"] = b2b._attempt_id_for(session_id[4:])

    def _refuse(cap, *, resolved):
        raise B2BTerminalRefusal("source_window_closed")

    monkeypatch.setattr(b2b_ctx, "prepare_b2b_context", _refuse)
    for target in ("_spawn_run",):
        monkeypatch.setattr(b2b, target, _adm_tripwire(target))
    monkeypatch.setattr(adapter, "_create_agent", _adm_tripwire("_create_agent"))
    store = adapter._run_idempotency_store
    before = adm._store_counts(store)
    response = await b2b._launch_b2b_run(
        adapter, None, profile="hub", entry=entry, keys=b2b._KeyRing(entry),
        session_id=session_id, binding_digest=session_id[4:],
        attempt_id=resolved["attempt_id"], resolved=resolved,
        store=store, db=adapter._session_db)
    assert response.status == 503
    assert json.loads(response.body)["error"] == "execution_unavailable"
    assert adm._store_counts(store) == before
    assert adapter._session_db.get_session(session_id)["title"] is None
    lane.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", [
    # The producer registers prepare_context but never pre_llm_call: it can
    # never publish, so no admission is consumed.
    "missing_publisher",
    # pre_llm_call registered — but by a DIFFERENT plugin: preparer and
    # publisher must share one owner.
    "other_owner_publisher",
    # A callback appended straight to manager._hooks (the shape a configured
    # outbound webhook takes): not plugin-owned, never a producer — even when
    # it would return a fully qualifying preparation.
    "raw_direct_callback"])
async def test_launch_refuses_producer_without_plugin_owned_pair(
        tmp_path, monkeypatch, opened, scenario):
    """REAL plugin discovery (no stubbed prepare_b2b_context): only a
    ``prepare_context`` registered through ``PluginContext.register_hook``
    whose SAME plugin also registered ``pre_llm_call`` may produce. Every
    other shape refuses 503 execution_unavailable BEFORE admission — no
    attempt row, no binding, no title, no run."""
    from tests.gateway import test_api_server_b2b_admission as adm
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    prof = adm._profile_home(tmp_path, monkeypatch, "hub")
    _write_serving_config(prof)
    adapter = adm._adapter(tmp_path, monkeypatch, "hub")
    adapter._session_db = SessionDB(prof / "state.db")
    opened.extend([adapter._session_db, adapter._run_idempotency_store])
    lane = _ready_lane(tmp_path)
    entry = _lane_entry(
        lane, portal_issuer="portal-hub", hermes_issuer="hermes-hub")
    session_id = "b2b_" + "b" * 64
    adapter._session_db.create_session(session_id, "api_server")
    resolved = _launch_resolved(lane, session_id=session_id)
    obs = dict(resolved["observation_genesis"])
    obs["id"], obs["profile"] = session_id, "hub"
    resolved["observation_genesis"] = obs
    resolved["session_id"] = session_id
    resolved["binding_digest"] = session_id[4:]
    resolved["attempt_id"] = b2b._attempt_id_for(session_id[4:])
    # The unit view's source_observed_at is a fixed instant; freeze the
    # source clock so a would-be producer (the RED side) really qualifies —
    # the refusal must come from ownership, never a stale window.
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: 1793361605.0))

    if scenario == "raw_direct_callback":
        from tests.gateway.b2b_process_harness import (
            UNIT_RENDERED, build_unit_native_oc_view)

        def _raw_prepare(*, execution):
            return {"view": build_unit_native_oc_view(
                        execution.policy,
                        {"mission_source_digest": "c" * 64}, ordered=True),
                    "rendered": UNIT_RENDERED,
                    "validate_configuration": lambda: True}

        from hermes_cli.plugins import get_plugin_manager
        get_plugin_manager()._hooks.setdefault(
            "prepare_context", []).append(_raw_prepare)
    else:
        names = [_FAKE_PLUGIN_NAME]
        _write_fake_plugin(prof, init=_FAKE_PLUGIN_PREPARE_ONLY_INIT)
        if scenario == "other_owner_publisher":
            _write_fake_plugin(prof, name="unitctx-publisher",
                               init=_FAKE_PLUGIN_PUBLISHER_ONLY_INIT)
            names.append("unitctx-publisher")
        _plugin_config(prof, names=tuple(names))
    for target in ("_spawn_run",):
        monkeypatch.setattr(b2b, target, _adm_tripwire(target))
    monkeypatch.setattr(adapter, "_create_agent", _adm_tripwire("_create_agent"))
    store = adapter._run_idempotency_store
    before = adm._store_counts(store)
    response = await b2b._launch_b2b_run(
        adapter, None, profile="hub", entry=entry, keys=b2b._KeyRing(entry),
        session_id=session_id, binding_digest=session_id[4:],
        attempt_id=resolved["attempt_id"], resolved=resolved,
        store=store, db=adapter._session_db)
    assert response.status == 503
    expected_error = (
        "non_plugin_hook_subscribers" if scenario == "raw_direct_callback"
        else "execution_unavailable")
    assert json.loads(response.body)["error"] == expected_error
    assert adm._store_counts(store) == before
    assert adapter._session_db.get_session(session_id)["title"] is None
    lane.store.close()


@pytest.mark.asyncio
async def test_launch_attaches_preparation_to_winning_cap(
        tmp_path, monkeypatch, opened):
    """UNIT: the SAME cap/sink that survive the durable admit carry the
    attached preparation into _spawn_run — proof travels with the attempt,
    not a side cache."""
    from tests.gateway import test_api_server_b2b_admission as adm
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    prof = adm._profile_home(tmp_path, monkeypatch, "hub")
    _write_serving_config(prof)
    adapter = adm._adapter(tmp_path, monkeypatch, "hub")
    adapter._session_db = SessionDB(prof / "state.db")
    opened.extend([adapter._session_db, adapter._run_idempotency_store])
    lane = _ready_lane(tmp_path)
    entry = _lane_entry(
        lane, portal_issuer="portal-hub", hermes_issuer="hermes-hub")
    session_id = "b2b_" + "b" * 64
    adapter._session_db.create_session(session_id, "api_server")
    resolved = _launch_resolved(lane, session_id=session_id)
    obs = dict(resolved["observation_genesis"])
    obs["id"], obs["profile"] = session_id, "hub"
    resolved["observation_genesis"] = obs
    resolved["session_id"] = session_id
    resolved["binding_digest"] = session_id[4:]
    resolved["attempt_id"] = b2b._attempt_id_for(session_id[4:])

    captured = {}

    def _prepare(cap, *, resolved):
        prep = _UnitPreparation(cap)
        return prep

    async def _spawn(adapter, request, *, cap, resolved, session_id, run_id,
                     profile):
        captured["cap"] = cap
        return SimpleNamespace()  # stand-in task; never awaited by callers

    monkeypatch.setattr(b2b_ctx, "prepare_b2b_context", _prepare)
    monkeypatch.setattr(b2b, "_spawn_run", _spawn)
    store = adapter._run_idempotency_store
    response = await b2b._launch_b2b_run(
        adapter, None, profile="hub", entry=entry, keys=b2b._KeyRing(entry),
        session_id=session_id, binding_digest=session_id[4:],
        attempt_id=resolved["attempt_id"], resolved=resolved,
        store=store, db=adapter._session_db)
    assert response.status == 200, response.body
    cap = captured["cap"]
    assert cap.sink._context_preparation is not None
    assert cap.sink._context_preparation.cap is cap
    row = store.b2b_attempt(profile="hub", attempt_id=resolved["attempt_id"])
    assert row["status"] == "admitted"
    assert adapter._session_db.get_session(session_id)["title"] == (
        "B2B " + session_id)
    lane.store.close()


def _adm_tripwire(name):
    def _raise(*a, **k):
        raise AssertionError(f"{name} must not run for a refused admission")
    return _raise


def test_execution_status_never_triggers_plugin_discovery(tmp_path, monkeypatch):
    """Health/diagnostics introspect only the already-loaded plugin table:
    ``discover_plugins`` (``register()`` may do IO) is never invoked, and no
    source or model probe rides along — presence alone still reports
    ``c1_producer_unavailable`` for a complete lane."""
    import hermes_cli.plugins as plugins_mod
    lane = _ready_lane(tmp_path)
    _write_serving_config(_profile_config_dir("hub"))
    state = _state({"hub": _lane_entry(lane)})

    def _no_discovery(*a, **k):
        raise AssertionError("health must not discover/load plugins")

    monkeypatch.setattr(plugins_mod, "discover_plugins", _no_discovery)
    from gateway.platforms.api_server_b2b_context import producer_available
    assert producer_available() is False
    status = b2b_execution_status(_status_adapter(state))
    assert status["b2b_execution_profiles"] == {
        "hub": {"state": "not-ready", "code": "c1_producer_unavailable"}}
    lane.store.close()


def test_execution_status_ignores_ambient_bound_execution(tmp_path, monkeypatch):
    """A health query issued while an unrelated bound execution is ambient
    must NOT inherit its preparation: the evaluation clears the ContextVar,
    so the code stays ``not-ready`` even if a preparation is attached."""
    from agent.b2b_execution import _execution_var
    lane = _ready_lane(tmp_path)
    _write_serving_config(_profile_config_dir("hub"))
    state = _state({"hub": _lane_entry(lane)})

    lane.sink._context_preparation = _UnitPreparation(lane.cap)
    token = bind_execution(lane.cap)
    try:
        assert b2b_execution_ready(lane.project, _INERT_CONFIG) is True
        status = b2b_execution_status(_status_adapter(state))
        assert _execution_var.get() is lane.cap
    finally:
        reset_execution(token)
    assert status["b2b_execution"] == "not-ready"
    assert status["b2b_execution_code"] != "ready"
    assert status["b2b_execution_profiles"]["hub"]["code"] != "ready"
    lane.store.close()


# --- P2 source-observation window: the SOURCE's own timestamp, never the
# capture instant. Frozen b2b_context.time drives exact boundary cases.


def _oc2_view(*, observed_ms, max_age=900_000,
              result_kind="measured",
              fmt="dubsar.my-work-oc-context-view/2"):
    from datetime import datetime, timezone
    instant = (datetime.fromtimestamp(observed_ms / 1000, tz=timezone.utc)
               .isoformat(timespec="milliseconds").replace("+00:00", "Z"))
    return {"operational_context": {"view": {
        "format": fmt, "view_instant": instant,
        "state_projection": {
            "candidate": {"result_kind": result_kind, "source_observed_at": instant},
            "freshness_max_age_ms": max_age}}}}


@pytest.fixture
def frozen_source_now(monkeypatch):
    from gateway.platforms import api_server_b2b_context as b2b_context
    now = [1_800_000_000_000]
    monkeypatch.setattr(b2b_context.time, "time", lambda: now[0] / 1000)
    return now


def test_source_window_accepts_within_bound(frozen_source_now):
    from gateway.platforms.api_server_b2b_context import _assert_source_window
    now = frozen_source_now[0]
    observed, deadline = _assert_source_window(
        _oc2_view(observed_ms=now - 899_999))
    assert observed == now - 899_999
    assert deadline == observed + 900_000


def test_source_window_uses_governed_bound(frozen_source_now):
    from gateway.platforms.api_server_b2b_context import (
        _assert_source_window, _source_observed_ms)
    now = frozen_source_now[0]
    observed, bound = _source_observed_ms(_oc2_view(observed_ms=now, max_age=50))
    assert bound == 50
    with pytest.raises(B2BTerminalRefusal) as excinfo:
        _assert_source_window(_oc2_view(observed_ms=now - 100, max_age=50))
    assert excinfo.value.args[0] == "context_oc_source_stale"


@pytest.mark.parametrize("delta_ms,max_age", [
    (900_000, 900_000), (-1, 900_000), (200, 100)])
def test_source_window_stale_or_future_refused(frozen_source_now, delta_ms, max_age):
    from gateway.platforms.api_server_b2b_context import _assert_source_window
    now = frozen_source_now[0]
    with pytest.raises(B2BTerminalRefusal) as excinfo:
        _assert_source_window(_oc2_view(observed_ms=now - delta_ms, max_age=max_age))
    assert excinfo.value.args[0] == "context_oc_source_stale"


@pytest.mark.parametrize("max_age", [True, 0, -1, "900", None])
def test_source_window_invalid_bound_unqualified(frozen_source_now, max_age):
    from gateway.platforms.api_server_b2b_context import _assert_source_window
    now = frozen_source_now[0]
    with pytest.raises(B2BTerminalRefusal) as excinfo:
        _assert_source_window(_oc2_view(observed_ms=now, max_age=max_age))
    assert excinfo.value.args[0] == "context_oc_unqualified"


@pytest.mark.parametrize("view", [
    # A /1 receipt can never prove a source timestamp — even when its capture
    # instant is exactly now.
    _oc2_view(observed_ms=1_800_000_000_000, fmt="dubsar.my-work-oc-context-view/1"),
    _oc2_view(observed_ms=1_800_000_000_000, result_kind="failed")])
def test_source_window_unqualified_receipts(frozen_source_now, view):
    from gateway.platforms.api_server_b2b_context import _assert_source_window
    with pytest.raises(B2BTerminalRefusal) as excinfo:
        _assert_source_window(view)
    assert excinfo.value.args[0] == "context_oc_unqualified"


# ======================================================================
# Generic ``prepare_context`` plugin hook — profile-scoped producer
# selection through the real plugin manager (no named plugin).
# ======================================================================

_FAKE_PLUGIN_NAME = "unitctx-producer"

_FAKE_PLUGIN_INIT = '''\
def register(ctx):
    def prepare_context(*, execution):
        from agent.b2b_execution import B2BTerminalRefusal
        from tests.gateway.b2b_process_harness import (
            UNIT_RENDERED, build_unit_native_oc_view)
        stamp = ctx.get_config("preparation_stamp")

        def validate_configuration():
            if ctx.get_config("preparation_stamp") != stamp:
                raise B2BTerminalRefusal("b2b_policy_changed")
            return True

        view = build_unit_native_oc_view(
            execution.policy, {"mission_source_digest": "c" * 64},
            ordered=True)
        return {"view": view, "rendered": UNIT_RENDERED,
                "validate_configuration": validate_configuration}
    ctx.register_hook("prepare_context", prepare_context)
    ctx.register_hook("pre_llm_call", lambda **kwargs: None)
'''

# A producer that prepares but never publishes: prepare_context without the
# SAME plugin's pre_llm_call — the contract refuses it before admission.
_FAKE_PLUGIN_PREPARE_ONLY_INIT = _FAKE_PLUGIN_INIT.replace(
    '    ctx.register_hook("pre_llm_call", lambda **kwargs: None)\n', '')

# A publisher with no preparation of its own: owned by a DIFFERENT plugin, it
# cannot complete another plugin's producer contract.
_FAKE_PLUGIN_PUBLISHER_ONLY_INIT = '''\
def register(ctx):
    ctx.register_hook("pre_llm_call", lambda **kwargs: None)
'''

_FAKE_PLUGIN_TRIPWIRE_INIT = '''\
def register(ctx):
    def prepare_context(*, execution):
        raise AssertionError("callback must not run for a foreign-home cap")
    ctx.register_hook("prepare_context", prepare_context)
    ctx.register_hook("pre_llm_call", lambda **kwargs: None)
'''


def _write_fake_plugin(home, *, name=_FAKE_PLUGIN_NAME, init=_FAKE_PLUGIN_INIT):
    """One unrelated directory plugin under ``<home>/plugins`` — loaded only
    through the real discovery/manifest path, never by test fiat."""
    plug = home / "plugins" / name
    plug.mkdir(parents=True, exist_ok=True)
    (plug / "plugin.yaml").write_text(
        f"name: {name}\nversion: 1.0.0\ndescription: unit fake producer\n")
    (plug / "__init__.py").write_text(init)


def _plugin_config(home, *, stamp="stamp-a", names=(_FAKE_PLUGIN_NAME,)):
    """Append the serving config's plugin opt-in + entry settings."""
    enabled = "".join(f"    - {n}\n" for n in names)
    entries = "".join(
        f"    {n}:\n      settings:\n        preparation_stamp: {stamp}\n"
        for n in names)
    with open(os.path.join(str(home), "config.yaml"), "a") as fh:
        fh.write("plugins:\n  enabled:\n" + enabled +
                 "  entries:\n" + entries)


@pytest.fixture
def fake_plugin_home(tmp_path, monkeypatch):
    """A separate HERMES_HOME carrying the fake producer; the active home is
    bound by set_hermes_home_override so the manager cache stays real."""
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    home = tmp_path / "plugin-home"
    home.mkdir()
    _write_fake_plugin(home)
    _plugin_config(home)
    now = [1793361605.0]
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: now[0]))
    token = set_hermes_home_override(home)
    yield SimpleNamespace(home=home, now=now)
    reset_hermes_home_override(token)


def _prepare_resolved(now_s):
    """The resolved envelope shape prepare consumed pre-refactor; the hook
    contract itself only needs the mission source digest."""
    return {"mission_source_digest": "c" * 64,
            "_signed_request": {"issued_at": now_s - 1,
                                "expires_at": now_s + 30},
            "_signed_response": {"issued_at": now_s - 1,
                                 "expires_at": now_s + 29}}


def test_prepare_context_hook_generic_producer(tmp_path, fake_plugin_home):
    """REAL discovery: an unrelated directory plugin registering
    ``prepare_context`` under THIS home supplies the mission view — the
    returned preparation is bound to this cap and passes its own gates."""
    from hermes_cli.plugins import discover_plugins
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    lane = _ready_lane(tmp_path)
    discover_plugins()
    assert b2b_ctx.producer_available() is True
    prep = b2b_ctx.prepare_b2b_context(
        lane.cap, resolved=_prepare_resolved(fake_plugin_home.now[0]))
    assert prep.cap is lane.cap
    prep.assert_current(lane.cap)
    assert prep.assert_configuration_current() is True
    lane.store.close()


def test_prepare_context_profile_scope_a_b_a(tmp_path, monkeypatch,
                                             fake_plugin_home):
    """Profile scope is the plugin manager's own: a proof produced under home
    A fails closed while home B is active (different manager, foreign
    callback), is valid again on return to A's cached manager — and a cap
    minted under A can never be PREPARED under B: the host binding refuses
    before B's own producer callback may run."""
    from hermes_cli.plugins import discover_plugins
    from hermes_constants import (
        reset_hermes_home_override, set_hermes_home_override)
    from agent.secret_scope import is_multiplex_active, set_multiplex_active
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    lane = _ready_lane(tmp_path)
    home_b = tmp_path / "plugin-home-b"
    home_b.mkdir()
    _write_fake_plugin(home_b, init=_FAKE_PLUGIN_TRIPWIRE_INIT)
    _plugin_config(home_b)
    # The profile manager cache is exercised under the real multiplexer latch,
    # so each scoped home is an actual isolated profile, not a loose path.
    previous_multiplex = is_multiplex_active()
    set_multiplex_active(True)
    try:
        prep = b2b_ctx.prepare_b2b_context(
            lane.cap, resolved=_prepare_resolved(fake_plugin_home.now[0]))
        token_b = set_hermes_home_override(home_b)
        try:
            discover_plugins()
            # B carries a real producer of its own — but A's cap is foreign
            # here: the host refuses before B's callback can run.
            assert b2b_ctx.producer_available() is True
            with pytest.raises(B2BTerminalRefusal) as exc:
                b2b_ctx.prepare_b2b_context(
                    lane.cap,
                    resolved=_prepare_resolved(fake_plugin_home.now[0]))
            assert str(exc.value) == "b2b_policy_changed"
            with pytest.raises(B2BTerminalRefusal):
                prep.assert_current(lane.cap)
            with pytest.raises(B2BTerminalRefusal):
                prep.assert_configuration_current()
        finally:
            reset_hermes_home_override(token_b)
        # Back under home A the SAME preparation is live again.
        prep.assert_current(lane.cap)
        assert prep.assert_configuration_current() is True
    finally:
        set_multiplex_active(previous_multiplex)
    lane.store.close()


def test_prepare_context_config_mutation_and_unload_reject(
        tmp_path, fake_plugin_home):
    """The returned validator re-reads plugin-owned configuration: mutating
    the entry's settings revokes the proof (typed b2b_policy_changed), and
    unloading the plugin removes the callback (context_unavailable)."""
    from hermes_cli.plugins import discover_plugins, get_plugin_manager
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    lane = _ready_lane(tmp_path)
    discover_plugins()
    prep = b2b_ctx.prepare_b2b_context(
        lane.cap, resolved=_prepare_resolved(fake_plugin_home.now[0]))
    _plugin_config(fake_plugin_home.home, stamp="stamp-b")
    with pytest.raises(B2BTerminalRefusal):
        prep.assert_current(lane.cap)
    _plugin_config(fake_plugin_home.home, stamp="stamp-a")
    prep.assert_current(lane.cap)
    manager = get_plugin_manager()
    manager.unload(_FAKE_PLUGIN_NAME)
    with pytest.raises(B2BTerminalRefusal) as exc:
        prep.assert_current(lane.cap)
    assert str(exc.value) == "context_unavailable"
    lane.store.close()


def test_prepare_context_ambiguity_fails_closed(tmp_path, monkeypatch,
                                                fake_plugin_home):
    """Exactly ONE prepare_context callback is permitted per profile: a second
    registering plugin makes the producer unavailable — never first-wins."""
    from hermes_cli.plugins import discover_plugins
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    lane = _ready_lane(tmp_path)
    _write_fake_plugin(fake_plugin_home.home, name="unitctx-second")
    _plugin_config(fake_plugin_home.home,
                   names=(_FAKE_PLUGIN_NAME, "unitctx-second"))
    discover_plugins()
    assert b2b_ctx.producer_available() is False
    with pytest.raises(B2BTerminalRefusal) as exc:
        b2b_ctx.prepare_b2b_context(
            lane.cap, resolved=_prepare_resolved(fake_plugin_home.now[0]))
    assert str(exc.value) == "context_unavailable"
    lane.store.close()


def test_prepare_context_producer_presence_is_not_readiness(
        tmp_path, monkeypatch, fake_plugin_home):
    """A registered producer changes the UNAVAILABLE CODE only: health stays
    not-ready (c1_context_required) until a per-capability proof exists."""
    from pathlib import Path
    from hermes_constants import (
        reset_hermes_home_override, set_hermes_home_override)
    from hermes_cli.plugins import discover_plugins
    from hermes_cli.profiles import get_profile_dir
    lane = _ready_lane(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    hub_home = get_profile_dir("hub")
    hub_home.mkdir(parents=True, exist_ok=True)
    _write_serving_config(hub_home)
    _write_fake_plugin(hub_home)
    _plugin_config(hub_home)
    token = set_hermes_home_override(hub_home)
    try:
        discover_plugins()
    finally:
        reset_hermes_home_override(token)
    state = _state({"hub": _lane_entry(lane)})
    status = b2b_execution_status(_status_adapter(state))
    assert status["b2b_execution_profiles"] == {
        "hub": {"state": "not-ready", "code": "c1_context_required"}}
    lane.store.close()


# --- Goal B: preparation/publication obey the OC source deadline only -----


def _bare_prepared(cap, *, source_deadline_ms):
    """A _PreparedContext instance populated field-by-field (frozen dataclass
    on either side of the refactor); the stamp hook is stubbed by callers."""
    from agent.b2b_execution import json_utf8
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_constants import get_hermes_home
    prep = object.__new__(b2b_ctx._PreparedContext)
    for name, value in {
            "cap": cap, "view": None, "manager": None, "prepare": None,
            "validate_configuration": lambda: True,
            "source_deadline_ms": source_deadline_ms,
            "project_utf8": json_utf8(cap.policy_get("project")),
            "profile": cap.profile,
            "home": str(get_hermes_home().resolve()),
            "policy_home": cap.policy_get("profile_home")}.items():
        object.__setattr__(prep, name, value)
    return prep


def test_prepared_context_governed_by_oc_deadline_not_post_ttl(
        tmp_path, monkeypatch):
    """The signed envelope TTL gates ADMISSION only: a preparation made while
    the POST window was open must still pass assert_current AND
    assert_publication after that window closed — the source's own OC
    deadline is the only freshness bound left."""
    from agent.b2b_execution import qualify_context_view, source_basis
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from tests.gateway.b2b_process_harness import build_unit_native_oc_view
    lane = _ready_lane(tmp_path)
    lane.sink.context_receipt = None
    object.__setattr__(lane.cap, "_receipt", None)
    now = [1793361605.0]
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: now[0]))
    raw = build_unit_native_oc_view(
        lane.cap.policy, {"mission_source_digest": "c" * 64}, ordered=True)
    plain = qualify_context_view(lane.cap, raw)
    # A legitimate publication carries the NEXT attested read of the same
    # source (read_id 2 > 1), the way pre_llm_call re-reads before publish.
    fresh = qualify_context_view(lane.cap, renew_unit_oc_read(raw, read_id=2))
    prep = _bare_prepared(lane.cap, source_deadline_ms=1793361610000)
    object.__setattr__(prep, "view", plain)
    monkeypatch.setattr(
        b2b_ctx._PreparedContext, "_assert_stamp", lambda *a, **k: None)
    prep.assert_current(lane.cap)
    now[0] += 2  # the POST window closes BETWEEN preparation and publication
    prep.assert_current(lane.cap)
    receipt = SimpleNamespace(
        turn_id=lane.cap.current_turn_id, view=fresh,
        source_basis=source_basis(fresh))
    prep.assert_publication(lane.cap, receipt)
    now[0] = 1793361611.0  # past observed + governed OC bound
    with pytest.raises(B2BTerminalRefusal) as exc:
        prep.assert_current(lane.cap)
    assert str(exc.value) == "context_oc_source_stale"
    lane.store.close()


@pytest.mark.parametrize("cause", ["context_oc_source_stale",
                                   "b2b_policy_changed",
                                   "context_unavailable"])
def test_preparation_typed_cause_reaches_durable_block(tmp_path, cause):
    """A typed refusal from the configuration gate must NOT be flattened to
    a boolean: it propagates out of assert_current_policy AND the durable
    attempt row classifies through _BLOCK_STATUS[cause]."""
    lane = _ready_lane(tmp_path)
    lane.sink._context_preparation = _UnitPreparation(
        lane.cap, configuration_error=cause)
    with pytest.raises(B2BTerminalRefusal) as exc:
        lane.sink.assert_current_policy()
    assert str(exc.value) == cause
    row = lane.store.b2b_attempt(
        profile=lane.cap.profile, attempt_id=lane.cap.attempt_id)
    assert row["status"] == b2b._BLOCK_STATUS[cause]
    lane.store.close()


@pytest.mark.parametrize("cause", ["context_oc_source_stale",
                                   "b2b_policy_changed",
                                   "context_unavailable"])
def test_prepared_context_assert_propagates_typed_cause(
        tmp_path, monkeypatch, cause):
    """The typed assertion (not the boolean readiness wrapper) preserves the
    preparation's exact durable cause through assert_current."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    lane = _ready_lane(tmp_path)
    lane.sink._context_preparation = _UnitPreparation(
        lane.cap, current=False, current_error=cause)
    token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            b2b_ctx.assert_prepared_context_current(lane.cap, lane.project)
    finally:
        reset_execution(token)
    assert str(exc.value) == cause
    lane.store.close()


@pytest.mark.parametrize("cause", ["context_oc_source_stale",
                                   "b2b_policy_changed",
                                   "context_unavailable"])
def test_construction_guard_blocks_with_typed_cause(
        tmp_path, monkeypatch, cause):
    """guard_agent_construction's final readiness check blocks the attempt
    with the preparation's TYPED cause — never a generic
    context_unavailable."""
    from gateway.platforms.api_server_b2b_execution import (
        guard_agent_construction)
    lane = _ready_lane(tmp_path)
    lane.sink._context_preparation = _UnitPreparation(
        lane.cap, current=False, current_error=cause)
    profile_token = _api_request_profile.set(lane.profile)
    cap_token = bind_execution(lane.cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            guard_agent_construction(
                _adapter(lane), session_id=lane.session_id,
                ephemeral_system_prompt=None, gateway_session_key=None,
                room_dispatch=None, room_execution_policy=None,
                session_model=None, model_options=None, route=None,
                requested_model=None, requested_provider=None)
    finally:
        reset_execution(cap_token)
        _api_request_profile.reset(profile_token)
    assert str(exc.value) == cause
    row = lane.store.b2b_attempt(
        profile=lane.cap.profile, attempt_id=lane.cap.attempt_id)
    assert row["status"] == b2b._BLOCK_STATUS[cause]
    lane.store.close()


# --- Goal C: concurrency checked before the expensive preparation --------


@pytest.mark.asyncio
@pytest.mark.parametrize("position", ["early", "post_prepare"])
async def test_launch_concurrency_check_order(
        tmp_path, monkeypatch, opened, position):
    """A NEW attempt checks capacity BEFORE the native preparation (early
    limit -> real 429, zero prepares) and again after it (first call None ->
    prepare runs once -> second call 429). Neither path writes the store,
    titles the session, or spawns a worker."""
    from aiohttp import web
    from tests.gateway import test_api_server_b2b_admission as adm
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    prof = adm._profile_home(tmp_path, monkeypatch, "hub")
    _write_serving_config(prof)
    adapter = adm._adapter(tmp_path, monkeypatch, "hub")
    adapter._session_db = SessionDB(prof / "state.db")
    opened.extend([adapter._session_db, adapter._run_idempotency_store])
    lane = _ready_lane(tmp_path)
    entry = _lane_entry(
        lane, portal_issuer="portal-hub", hermes_issuer="hermes-hub")
    session_id = "b2b_" + "b" * 64
    adapter._session_db.create_session(session_id, "api_server")
    resolved = _launch_resolved(lane, session_id=session_id)
    obs = dict(resolved["observation_genesis"])
    obs["id"], obs["profile"] = session_id, "hub"
    resolved["observation_genesis"] = obs
    resolved["session_id"] = session_id
    resolved["binding_digest"] = session_id[4:]
    resolved["attempt_id"] = b2b._attempt_id_for(session_id[4:])

    prepares = []

    def _prepare(cap, *, resolved):
        prepares.append(cap)
        return _UnitPreparation(cap)

    monkeypatch.setattr(b2b_ctx, "prepare_b2b_context", _prepare)
    monkeypatch.setattr(b2b, "_spawn_run", _adm_tripwire("_spawn_run"))
    limited = web.Response(status=429, text="capacity")
    calls = iter([limited] if position == "early" else [None, limited])
    monkeypatch.setattr(
        adapter, "_concurrency_limited_response", lambda: next(calls))
    store = adapter._run_idempotency_store
    before = adm._store_counts(store)
    response = await b2b._launch_b2b_run(
        adapter, None, profile="hub", entry=entry, keys=b2b._KeyRing(entry),
        session_id=session_id, binding_digest=session_id[4:],
        attempt_id=resolved["attempt_id"], resolved=resolved,
        store=store, db=adapter._session_db)
    assert response.status == 429
    if position == "early":
        assert prepares == []
    else:
        assert len(prepares) == 1
    assert adm._store_counts(store) == before
    assert adapter._session_db.get_session(session_id)["title"] is None
    lane.store.close()
