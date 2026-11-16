"""B2B context preparation — a bounded count of ABANDONED native reads.

A producer native read whose caller already walked away ("abandoned") is the
ONLY preparation state the lane budgets: once ``_MAX_ABANDONED_PREPARATIONS``
(2) orphaned worker threads exist for one canonical ``hermes_home_key``, NEW
launches on that home are refused 503 ``execution_unavailable`` until the
orphans actually exit. Healthy reads — however many run at once — never
count toward the cap; the cap never consults ``max_concurrent_runs`` (it
binds identically at 0); and the generic ``/v1/runs`` limiter stays the one
process-wide gate, shared across profile homes.
"""

from __future__ import annotations

import asyncio
import copy
import json
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from hermes_state import SessionDB
from tests.gateway import test_api_server_b2b_admission as admission
from tests.gateway import test_api_server_b2b_execution_lane as execution_lane
from tests.gateway.test_api_server_b2b_hook_admission import (
    _launch, _new_launch, opened)

# Probe state shared with the fake producer plugin below (the plugin imports
# this module from inside its worker thread): the gate it parks on, the enter
# signal, an optional barrier for genuine multi-worker rendezvous, an
# exit-mode flag, and the real Thread objects that entered it.
PREP_GATE = threading.Event()
PREP_ENTERED = threading.Event()
PREP_BARRIER = None
PREP_EXIT = threading.Event()
PREP_WORKER_THREADS = []

_PRODUCER_PLUGIN_NAME = "stuck-producer"
_PREPARATION_STAMP = "stamp-capacity"

# Same contract as execution_lane._FAKE_PLUGIN_INIT, but the callback parks
# on the probe controls so a launch can be held inside its native read —
# either on PREP_GATE (single blocked worker) or on PREP_BARRIER (released
# only once every expected worker has entered). PREP_EXIT switches it to a
# hard BaseException death.
_GATED_PLUGIN_INIT = '''\
def register(ctx):
    def prepare_context(*, execution):
        import threading as _threading
        from agent.b2b_execution import B2BTerminalRefusal
        from tests.gateway import test_api_server_b2b_context_capacity as probe
        from tests.gateway.b2b_process_harness import (
            UNIT_RENDERED, build_unit_native_oc_view)
        probe.PREP_WORKER_THREADS.append(_threading.current_thread())
        probe.PREP_ENTERED.set()
        if probe.PREP_EXIT.is_set():
            raise SystemExit(37)
        barrier = probe.PREP_BARRIER
        if barrier is not None:
            barrier.wait(timeout=15.0)
        else:
            probe.PREP_GATE.wait(timeout=30.0)
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


def _reset_probe():
    PREP_GATE.clear()
    PREP_ENTERED.clear()
    PREP_EXIT.clear()
    globals()["PREP_BARRIER"] = None
    del PREP_WORKER_THREADS[:]


def _assert_refused_503(response):
    assert response.status == 503
    assert json.loads(response.body)["error"] == "execution_unavailable"


def _install_gated_producer(profile_home):
    execution_lane._write_fake_plugin(
        profile_home, name=_PRODUCER_PLUGIN_NAME, init=_GATED_PLUGIN_INIT)
    execution_lane._plugin_config(
        profile_home, stamp=_PREPARATION_STAMP, names=(_PRODUCER_PLUGIN_NAME,))


def _freeze_preparation_clock(monkeypatch):
    """Inside the unit view's 10 s freshness window, like the lane tests."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: 1793361605.0))


def _profile_case(tmp_path, monkeypatch, opened, adapter, lane, profile,
                  letter, db=None):
    """A second launchable profile/session on the SAME adapter — a real home
    dir + real SessionDB inside it for another profile, or the launch db for
    a second session on the SAME home."""
    prof_home = tmp_path / "homes" / "profiles" / profile
    prof_home.mkdir(parents=True, exist_ok=True)
    execution_lane._write_serving_config(prof_home)
    if db is None:
        db = SessionDB(prof_home / "state.db")
        opened.append(db)
    session_id = "b2b_" + letter * 64
    db.create_session(session_id, "api_server")
    entry = execution_lane._lane_entry(
        lane, portal_issuer=f"portal-{profile}", hermes_issuer=f"hermes-{profile}",
        projects={"b2b-bench": dict(lane.project, profile_id=profile)})
    resolved = execution_lane._launch_resolved(
        lane, profile=profile, session_id=session_id)
    observation = dict(resolved["observation_genesis"])
    observation["id"], observation["profile"] = session_id, profile
    resolved["observation_genesis"] = observation
    resolved["session_id"] = session_id
    resolved["profile"] = profile
    resolved["binding_digest"] = session_id[4:]
    resolved["attempt_id"] = execution_lane.b2b._attempt_id_for(session_id[4:])
    return SimpleNamespace(
        adapter=adapter, lane=lane, entry=entry, profile_home=prof_home,
        session_id=session_id, resolved=resolved,
        store=adapter._run_idempotency_store, db=db)


async def _launch_profile(case, profile):
    """Launch under the profile's own scope — home/db/policy all follow it."""
    with case.adapter._profile_scope(profile):
        return await execution_lane.b2b._launch_b2b_run(
            case.adapter, None, profile=profile, entry=case.entry,
            keys=execution_lane.b2b._KeyRing(case.entry),
            session_id=case.session_id, binding_digest=case.session_id[4:],
            attempt_id=case.resolved["attempt_id"], resolved=case.resolved,
            store=case.store, db=case.db)


def _spawn_recorder(spawned):
    async def _spawn(adapter, request, *, cap, resolved, session_id, run_id,
                     profile):
        spawned.append((profile, run_id, session_id))
        return SimpleNamespace(done=lambda: True)
    return _spawn


def _join_prep_workers():
    for thread in set(PREP_WORKER_THREADS):
        thread.join(timeout=10.0)
    assert not any(t.is_alive() for t in PREP_WORKER_THREADS)
    del PREP_WORKER_THREADS[:]


def _abandoned_count(adapter, profile):
    """The abandoned-preparation count under the profile's own home scope."""
    from gateway.platforms.api_server_b2b_context import (
        abandoned_preparation_count)
    with adapter._profile_scope(profile):
        return abandoned_preparation_count()


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [1, 0])
async def test_two_abandoned_preparations_gate_new_launches(
        tmp_path, monkeypatch, opened, limit):
    """A's producer blocks past the read budget twice: every further A launch
    — whatever ``max_concurrent_runs`` says, including 0 — gets 503
    ``execution_unavailable`` with no new producer read and no durable write,
    health names ``context_preparation_stuck`` on A and
    ``c1_context_required`` on B, B still admits on its own home, and once
    the orphans actually exit the count returns to zero and A admits again.
    """
    from gateway.platforms.api_server_b2b import _B2BState, validate_b2b_config
    from gateway.platforms.api_server_b2b_execution import (
        b2b_execution_status)
    from hermes_cli.plugins import discover_plugins

    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    adapter._max_concurrent_runs = limit
    # Rebind the adapter's b2b state so health evaluates BOTH homes — with
    # operator inputs that are actually ON DISK (the ready lane's contract
    # root + My Work roots) so the stuck code can surface past the inputs
    # check.
    extra = admission._b2b_extra("hub", "ci")
    for _name in ("hub", "ci"):
        _project = extra["b2b"]["profiles"][_name]["projects"]["b2b-bench"]
        _project["context_contract_root"] = (
            case_a.lane.project["context_contract_root"])
        _project["project_context"] = dict(
            case_a.lane.project["project_context"],
            project_id=_project["project_id"])
    adapter._b2b_state = _B2BState(validate_b2b_config(extra))
    case_b = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "ci", "c")

    _freeze_preparation_clock(monkeypatch)
    _install_gated_producer(case_a.profile_home)
    # B keeps an ordinary working producer — it must admit while A is stuck.
    execution_lane._write_fake_plugin(case_b.profile_home, name="ci-producer")
    execution_lane._plugin_config(case_b.profile_home, names=("ci-producer",))
    with adapter._profile_scope("hub"):
        discover_plugins()
    with adapter._profile_scope("ci"):
        discover_plugins()

    _reset_probe()
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))
    before = admission._store_counts(case_a.store)
    changes_before = case_a.store._conn.total_changes

    # The first two launches each abandon one real producer worker; every
    # later launch is refused by the stuck gate — never by the run limiter.
    try:
        for _ in range(8):
            _assert_refused_503(await _launch_profile(case_a, "hub"))
        workers = set(PREP_WORKER_THREADS)
        assert len(workers) == 2
        assert all(t.is_alive() for t in workers)
        # Refused launches started no discovery, native read, spawn or write.
        assert admission._store_counts(case_a.store) == before
        assert case_a.store._conn.total_changes == changes_before
        assert case_a.db.get_session(case_a.session_id)["title"] is None
        assert spawned == []
        assert _abandoned_count(adapter, "hub") == 2

        # Health while still stuck: A names context_preparation_stuck, B the
        # ordinary context-required — through the aggregate function AND the
        # real /health/detailed handler.
        status = b2b_execution_status(adapter)
        assert status["b2b_execution_profiles"]["hub"]["code"] == (
            "context_preparation_stuck")
        assert status["b2b_execution_profiles"]["ci"]["code"] == (
            "c1_context_required")
        request = SimpleNamespace(
            headers={"Authorization": "Bearer " + admission._API_KEY})
        detailed = await adapter._handle_health_detailed(request)
        assert detailed.status == 200
        profiles = json.loads(detailed.body)["b2b_execution_profiles"]
        assert profiles["hub"]["code"] == "context_preparation_stuck"

        # A-B-A: B admits on its own home while A stays stuck, and A is
        # still refused afterwards.
        response_b = await _launch_profile(case_b, "ci")
        assert response_b.status == 200, response_b.body
        _assert_refused_503(await _launch_profile(case_a, "hub"))
    finally:
        # Even if an assertion fired, release and join every orphan so no
        # daemon outlives the test or contaminates the next one.
        PREP_GATE.set()
        _join_prep_workers()

    assert _abandoned_count(adapter, "hub") == 0
    response = await _launch_profile(case_a, "hub")
    assert response.status == 200, response.body
    assert case_a.db.get_session(case_a.session_id)["title"] == (
        "B2B " + case_a.session_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, 1, 2])
async def test_healthy_concurrent_launches_never_count_toward_the_cap(
        tmp_path, monkeypatch, opened, limit):
    """Two genuinely simultaneous healthy launches on ONE home: BOTH reach
    the producer barrier and both admit, at every ``max_concurrent_runs``
    value — a preparation-side gate must never refuse a healthy launch, and
    the abandoned count stays zero throughout."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli.plugins import discover_plugins

    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    adapter._max_concurrent_runs = limit
    case_d = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "hub", "d",
        db=adapter._session_db)

    _freeze_preparation_clock(monkeypatch)
    _install_gated_producer(case_a.profile_home)
    with adapter._profile_scope("hub"):
        discover_plugins()

    _reset_probe()
    # Genuine rendezvous: Barrier(3) — the two launches' real workers and the
    # test itself. While BOTH healthy workers are parked inside the producer,
    # nothing may be counted; the third participant's wait releases them.
    barrier = threading.Barrier(3)
    globals()["PREP_BARRIER"] = barrier
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    t1 = asyncio.create_task(_launch_profile(case_a, "hub"))
    t2 = asyncio.create_task(_launch_profile(case_d, "hub"))
    try:
        deadline = time.monotonic() + 10.0
        while barrier.n_waiting < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        assert barrier.n_waiting == 2, (
            "both launches' workers never entered the producer")
        assert len(set(PREP_WORKER_THREADS)) == 2
        # Both workers healthy and still running: the abandoned count stays 0.
        if hasattr(b2b_ctx, "abandoned_preparation_count"):
            assert _abandoned_count(adapter, "hub") == 0
        await asyncio.to_thread(barrier.wait, 10)
        r1, r2 = await asyncio.gather(t1, t2)
    finally:
        barrier.abort()
        await asyncio.gather(t1, t2, return_exceptions=True)
        _join_prep_workers()
    assert getattr(r1, "status", None) == 200, r1
    assert getattr(r2, "status", None) == 200, r2
    assert len(spawned) == 2
    if hasattr(b2b_ctx, "abandoned_preparation_count"):
        assert _abandoned_count(adapter, "hub") == 0


@pytest.mark.asyncio
async def test_generic_runs_limiter_counts_live_runs_across_homes(
        tmp_path, monkeypatch):
    """The generic ``/v1/runs`` limiter is the ONE process-wide gate: a live
    run task started under home A counts against a request routed under home
    B — the exact shared-limiter 429 — and frees the slot only when A's task
    actually retires."""
    from aiohttp.test_utils import TestClient, TestServer
    from gateway.config import PlatformConfig
    from gateway.platforms.api_server import APIServerAdapter
    from hermes_constants import (
        reset_hermes_home_override, set_hermes_home_override)
    from tests.gateway.test_api_server_runs import (
        _create_runs_app, _make_slow_agent)

    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    adapter._max_concurrent_runs = 1
    home_a = tmp_path / "home-a"
    home_b = tmp_path / "home-b"
    home_a.mkdir()
    home_b.mkdir()

    def _route_in(home):
        async def _handler(request):
            token = set_hermes_home_override(str(home))
            try:
                return await adapter._handle_runs(request)
            finally:
                reset_hermes_home_override(token)
        return _handler

    app = _create_runs_app(adapter)
    app.router.add_post("/a/v1/runs", _route_in(home_a))
    app.router.add_post("/b/v1/runs", _route_in(home_b))

    mock_agent, ready, interrupted = _make_slow_agent()
    with patch.object(adapter, "_create_agent", return_value=mock_agent):
        async with TestClient(TestServer(app)) as cli:
            started = await cli.post("/a/v1/runs", json={"input": "hello"})
            assert started.status == 202
            run_id = (await started.json())["run_id"]
            deadline = time.monotonic() + 10.0
            while not ready.is_set() and time.monotonic() < deadline:
                await asyncio.sleep(0.005)
            assert ready.is_set(), "A's run task never started"
            assert run_id in adapter._active_run_tasks

            # Home B is refused by the same limiter that just admitted A.
            refused = await cli.post("/b/v1/runs", json={"input": "hello"})
            assert refused.status == 429
            body = await refused.json()
            assert body["error"]["code"] == "rate_limit_exceeded"
            assert body["error"]["type"] == "rate_limit_error"
            assert refused.headers["Retry-After"] == "1"

            mock_agent.interrupt()
            task = adapter._active_run_tasks[run_id]
            await asyncio.wait_for(asyncio.shield(task), timeout=10.0)
            deadline = time.monotonic() + 10.0
            while run_id in adapter._active_run_tasks and (
                    time.monotonic() < deadline):
                await asyncio.sleep(0.005)
            assert run_id not in adapter._active_run_tasks

            admitted = await cli.post("/b/v1/runs", json={"input": "hello"})
            assert admitted.status == 202


@pytest.mark.asyncio
async def test_system_exit_producer_normalizes_to_context_unavailable(
        tmp_path, monkeypatch, opened):
    """A producer that dies with ``SystemExit(37)`` mid-read is an ordinary
    typed refusal — 503 ``execution_unavailable`` on the wire, never a
    BaseException into the event loop — and its worker exits immediately, so
    nothing is counted and the very next healthy launch admits."""
    from hermes_cli.plugins import discover_plugins

    case = _new_launch(tmp_path, monkeypatch, opened)
    case.db = case.adapter._session_db
    adapter = case.adapter

    _freeze_preparation_clock(monkeypatch)
    _install_gated_producer(case.profile_home)
    with adapter._profile_scope("hub"):
        discover_plugins()

    _reset_probe()
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))
    try:
        PREP_EXIT.set()  # producer dies with SystemExit(37) — no parking
        response = await _launch(case)
        _assert_refused_503(response)
        assert PREP_ENTERED.is_set()
        _join_prep_workers()
        from gateway.platforms import api_server_b2b_context as b2b_ctx
        if hasattr(b2b_ctx, "abandoned_preparation_count"):
            assert _abandoned_count(adapter, "hub") == 0

        # Next launch, healthy producer with the gate open: full admit.
        PREP_EXIT.clear()
        PREP_GATE.set()
        response = await _launch(case)
        assert response.status == 200, response.body
    finally:
        PREP_EXIT.clear()
        PREP_GATE.set()
        _join_prep_workers()


@pytest.mark.asyncio
async def test_cancelled_launch_orphans_its_worker_until_it_exits(
        tmp_path, monkeypatch, opened):
    """Cancelling the caller's launch task while its producer is parked does
    not kill the native-read worker — it becomes an abandoned preparation,
    counted until the worker actually exits; a follow-up launch after the
    orphan drains admits normally."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli.plugins import discover_plugins

    case = _new_launch(tmp_path, monkeypatch, opened)
    case.db = case.adapter._session_db
    adapter = case.adapter

    _freeze_preparation_clock(monkeypatch)
    _install_gated_producer(case.profile_home)
    with adapter._profile_scope("hub"):
        discover_plugins()

    _reset_probe()
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    task = asyncio.create_task(_launch(case))
    deadline = time.monotonic() + 10.0
    while not PREP_ENTERED.is_set() and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    assert PREP_ENTERED.is_set()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert spawned == []
    # The orphaned worker abandons itself once its own read budget ends.
    if hasattr(b2b_ctx, "abandoned_preparation_count"):
        deadline = time.monotonic() + 10.0
        while _abandoned_count(adapter, "hub") == 0 and (
                time.monotonic() < deadline):
            await asyncio.sleep(0.02)
        assert _abandoned_count(adapter, "hub") == 1
    # One orphan does NOT block the gate: the next launch's worker must
    # reach the producer too — then complete once the gate opens.
    second = asyncio.create_task(_launch(case))
    try:
        deadline = time.monotonic() + 10.0
        while len(set(PREP_WORKER_THREADS)) < 2 and (
                time.monotonic() < deadline):
            await asyncio.sleep(0.01)
        assert len(set(PREP_WORKER_THREADS)) == 2
    finally:
        PREP_GATE.set()
        _join_prep_workers()
    if hasattr(b2b_ctx, "abandoned_preparation_count"):
        assert _abandoned_count(adapter, "hub") == 0
    second_response = await second
    assert getattr(second_response, "status", None) == 200, second_response


@pytest.mark.asyncio
async def test_health_classification_orders_inputs_then_producer_then_stuck(
        tmp_path, monkeypatch, opened):
    """Severity order for the same stuck home: malformed inputs outrank
    everything, an absent/ambiguous producer outranks ``stuck``, and only
    then does the abandoned count surface ``context_preparation_stuck`` —
    ``c1_context_required`` remains the fully-prepared-else answer."""
    from gateway.platforms.api_server_b2b_context import (
        context_preparation_stuck)
    from gateway.platforms.api_server_b2b_execution import (
        b2b_execution_unavailable_code)
    from hermes_cli.plugins import discover_plugins

    case = _new_launch(tmp_path, monkeypatch, opened)
    case.db = case.adapter._session_db
    adapter = case.adapter

    _freeze_preparation_clock(monkeypatch)
    _install_gated_producer(case.profile_home)
    with adapter._profile_scope("hub"):
        discover_plugins()

    _reset_probe()
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    try:
        for _ in range(2):
            _assert_refused_503(await _launch(case))
        assert _abandoned_count(adapter, "hub") == 2

        ready_project = copy.deepcopy(case.lane.project)
        config = copy.deepcopy(execution_lane._INERT_CONFIG)
        with adapter._profile_scope("hub"):
            assert context_preparation_stuck() is True
            # Stuck surfaces only once inputs are fine AND a producer exists.
            assert b2b_execution_unavailable_code(
                ready_project, config) == "context_preparation_stuck"
            # Missing inputs still outrank the stuck gate.
            broken = copy.deepcopy(ready_project)
            broken["project_context"] = {
                **broken["project_context"],
                "start": str(tmp_path / "absent")}
            assert b2b_execution_unavailable_code(
                broken, config) == "execution_inputs_unavailable"

        # An absent producer outranks stuck: a home with NO producer plugin
        # reports absence, not stuck — the count never hides that hole.
        ci_home = tmp_path / "homes" / "profiles" / "ci"
        ci_home.mkdir(parents=True, exist_ok=True)
        execution_lane._write_serving_config(ci_home)
        with adapter._profile_scope("ci"):
            discover_plugins()
            assert b2b_execution_unavailable_code(
                ready_project, config) == "c1_producer_unavailable"

        # An AMBIGUOUS producer (two prepare_context hooks on one home) also
        # outranks stuck — registration holes are never hidden.
        execution_lane._write_fake_plugin(
            case.profile_home, name="decoy-producer")
        execution_lane._plugin_config(
            case.profile_home, stamp=_PREPARATION_STAMP,
            names=(_PRODUCER_PLUGIN_NAME, "decoy-producer"))
        with adapter._profile_scope("hub"):
            discover_plugins(force=True)
            assert b2b_execution_unavailable_code(
                ready_project, config) == "c1_producer_unavailable"
    finally:
        PREP_GATE.set()
        _join_prep_workers()
