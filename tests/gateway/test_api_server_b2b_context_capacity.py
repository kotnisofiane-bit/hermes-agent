"""B2B context preparation — bounded plugin workers, no capacity gates.

Every plugin callback in the launch path runs inside a daemon worker with a
per-request deadline, off the asyncio loop: the bootstrap (hydration,
config, plugin discovery), the ``prepare_context`` native read, and its
returned configuration validators. A request whose worker misses its
deadline is refused — THAT request alone — and the worker's late result is
discarded on its true finish. There is no cross-request accounting: no
abandoned counts, no stuck health, no single-flight admission, and no
interaction with the generic ``/v1/runs`` limiter.
"""

from __future__ import annotations

import asyncio
import copy
import json
import threading
import time
from pathlib import Path
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

# Validator probe state: the gated validator below blocks inside the plugin's
# OWN validate_configuration — call number VAL_BLOCK_CALL of a preparation
# parks on VAL_GATE (after VAL_BARRIER, when set) — so a launch can be held
# inside a validator rather than inside the native read itself.
VAL_GATE = threading.Event()
VAL_WORKER_THREADS = []   # (preparation_index, call_index, Thread)
VAL_BLOCK_CALL = 0        # which validate_configuration call parks; 0 = none
VAL_BARRIER = None
VAL_PROBE_LOCK = threading.Lock()

# Bootstrap probe state: REGISTER_* parks a plugin's OWN register() (cold
# discovery) or a patched _load_gateway_config — bootstrap work that must
# stay OUTSIDE the bounded preparation.
REGISTER_GATE = threading.Event()
REGISTER_ENTERED = threading.Event()

_PRODUCER_PLUGIN_NAME = "stuck-producer"
_VALIDATOR_PLUGIN_NAME = "stuck-validator"
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

# Same producer, but its native read answers FAST and the park point moves
# into the returned validate_configuration: call VAL_BLOCK_CALL of THIS
# preparation's validator blocks (VAL_BARRIER rendezvous first, when set),
# so the preparation is held hostage AFTER its read already produced a view.
_GATED_VALIDATOR_INIT = '''\
def register(ctx):
    def prepare_context(*, execution):
        import threading as _threading
        from agent.b2b_execution import B2BTerminalRefusal
        from tests.gateway import test_api_server_b2b_context_capacity as probe
        from tests.gateway.b2b_process_harness import (
            UNIT_RENDERED, build_unit_native_oc_view)
        with probe.VAL_PROBE_LOCK:
            index = len(probe.PREP_WORKER_THREADS)
            probe.PREP_WORKER_THREADS.append(_threading.current_thread())
        stamp = ctx.get_config("preparation_stamp")
        calls = [0]

        def validate_configuration():
            calls[0] += 1
            probe.VAL_WORKER_THREADS.append(
                (index, calls[0], _threading.current_thread()))
            if calls[0] == probe.VAL_BLOCK_CALL:
                barrier = probe.VAL_BARRIER
                if barrier is not None:
                    barrier.wait(timeout=15.0)
                probe.VAL_GATE.wait(timeout=30.0)
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

# The ordinary fast producer, but the park point is register() itself: a
# COLD discovery is held inside plugin-owned register code — bootstrap work,
# never preparation.
_COLD_REGISTER_INIT = execution_lane._FAKE_PLUGIN_INIT.replace(
    "def register(ctx):\n",
    "def register(ctx):\n"
    "    from tests.gateway import (\n"
    "        test_api_server_b2b_context_capacity as probe)\n"
    "    probe.REGISTER_ENTERED.set()\n"
    "    probe.REGISTER_GATE.wait(timeout=30.0)\n", 1)


def _reset_probe():
    PREP_GATE.clear()
    PREP_ENTERED.clear()
    PREP_EXIT.clear()
    VAL_GATE.clear()
    REGISTER_GATE.clear()
    REGISTER_ENTERED.clear()
    globals()["PREP_BARRIER"] = None
    globals()["VAL_BARRIER"] = None
    globals()["VAL_BLOCK_CALL"] = 0
    del PREP_WORKER_THREADS[:]
    del VAL_WORKER_THREADS[:]
    del REGISTER_THREADS[:]
    del HYDRATE_THREADS[:]


def _assert_refused_503(response):
    assert response.status == 503
    assert json.loads(response.body)["error"] == "execution_unavailable"


def _install_gated_producer(profile_home):
    execution_lane._write_fake_plugin(
        profile_home, name=_PRODUCER_PLUGIN_NAME, init=_GATED_PLUGIN_INIT)
    execution_lane._plugin_config(
        profile_home, stamp=_PREPARATION_STAMP, names=(_PRODUCER_PLUGIN_NAME,))


def _install_gated_validator(profile_home):
    execution_lane._write_fake_plugin(
        profile_home, name=_VALIDATOR_PLUGIN_NAME, init=_GATED_VALIDATOR_INIT)
    execution_lane._plugin_config(
        profile_home, stamp=_PREPARATION_STAMP, names=(_VALIDATOR_PLUGIN_NAME,))


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


def _profile_scope_unhydrated(profile_home):
    """A real profile scope that NEVER hydrates secret sources — the test
    loop must not queue on the global secret-source lock it holds shut, and
    a hydrating introspection would mask a lock-wait regression."""
    from gateway.run import _profile_runtime_scope
    return _profile_runtime_scope(profile_home, hydrate_secrets=False)


async def _launch_unhydrated(case, profile):
    """``_launch_profile`` without the hydrating scope entry — same real
    launch, credentials left to the production bootstrap/worker."""
    with _profile_scope_unhydrated(case.profile_home):
        return await execution_lane.b2b._launch_b2b_run(
            case.adapter, None, profile=profile, entry=case.entry,
            keys=execution_lane.b2b._KeyRing(case.entry),
            session_id=case.session_id, binding_digest=case.session_id[4:],
            attempt_id=case.resolved["attempt_id"], resolved=case.resolved,
            store=case.store, db=case.db)


@pytest.mark.asyncio
async def test_healthy_concurrent_launches_admit_together(
        tmp_path, monkeypatch, opened):
    """Two genuinely simultaneous healthy launches on ONE home: BOTH reach
    the producer barrier and both admit — no cross-request gate may refuse
    or serialize a healthy launch behind its sibling."""
    from hermes_cli.plugins import discover_plugins

    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    case_d = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "hub", "d",
        db=adapter._session_db)

    _freeze_preparation_clock(monkeypatch)
    _install_gated_producer(case_a.profile_home)
    with adapter._profile_scope("hub"):
        discover_plugins()

    _reset_probe()
    # Genuine rendezvous: Barrier(3) — the two launches' real workers and the
    # test itself. While BOTH healthy workers are parked inside the producer
    # nothing may interfere across requests; the third participant's wait
    # releases them together.
    barrier = threading.Barrier(3)
    globals()["PREP_BARRIER"] = barrier
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    t1 = asyncio.create_task(_launch_profile(case_a, "hub"))
    t2 = asyncio.create_task(_launch_profile(case_d, "hub"))
    try:
        deadline = time.monotonic() + 30.0
        while barrier.n_waiting < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        assert barrier.n_waiting == 2, (
            "both launches never entered the producer together")
        assert len(set(PREP_WORKER_THREADS)) == 2
        await asyncio.to_thread(barrier.wait, 10)
        r1, r2 = await asyncio.gather(t1, t2)
    finally:
        barrier.abort()
        await asyncio.gather(t1, t2, return_exceptions=True)
        _join_prep_workers()
    assert getattr(r1, "status", None) == 200, r1
    assert getattr(r2, "status", None) == 200, r2
    assert len(spawned) == 2


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
async def test_same_home_bootstraps_run_concurrently(
        tmp_path, monkeypatch, opened):
    """Two launches on ONE home started together BOTH enter a held config
    load inside their own bounded bootstrap workers — no single-flight
    admission may refuse or serialize the second behind the first — then
    both admit once the held work releases. The plugin is pre-discovered so
    the launches cannot queue on the plugin manager's discovery lock."""
    import gateway.run as gateway_run
    from hermes_cli.plugins import discover_plugins

    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    case_b = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "hub", "d",
        db=adapter._session_db)

    _freeze_preparation_clock(monkeypatch)
    execution_lane._write_fake_plugin(case_a.profile_home)
    execution_lane._plugin_config(
        case_a.profile_home, stamp=_PREPARATION_STAMP)
    with adapter._profile_scope("hub"):
        discover_plugins()

    _reset_probe()
    release = threading.Event()
    barrier = threading.Barrier(3)
    real_load = gateway_run._load_gateway_config

    def _held_load(*args, **kwargs):
        barrier.wait(timeout=30.0)
        release.wait(timeout=30.0)
        return real_load(*args, **kwargs)

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _held_load)
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    tasks = [asyncio.create_task(_launch_unhydrated(case_a, "hub")),
             asyncio.create_task(_launch_unhydrated(case_b, "hub"))]
    try:
        deadline = time.monotonic() + 30.0
        while barrier.n_waiting < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        assert barrier.n_waiting == 2, (
            "both launches never entered the held bootstrap work together")
        await asyncio.to_thread(barrier.wait, 10)
        release.set()
        r1, r2 = await asyncio.wait_for(asyncio.gather(*tasks), timeout=30.0)
    finally:
        release.set()
        barrier.abort()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert getattr(r1, "status", None) == 200, r1
    assert getattr(r2, "status", None) == 200, r2
    assert len(spawned) == 2


@pytest.mark.asyncio
async def test_timed_out_preparations_never_block_the_next_launch(
        tmp_path, monkeypatch, opened):
    """Three SEQUENTIAL launches whose producers park past the preparation
    deadline are EACH refused — each expires before the next is submitted,
    and all three workers stay parked — yet a healthy launch on the same
    home still registers its own worker and admits once the gate releases.
    A timed-out request discards its worker's late result; it never blocks
    a sibling request."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli.plugins import discover_plugins

    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    case_d = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "hub", "d",
        db=adapter._session_db)

    _freeze_preparation_clock(monkeypatch)
    _install_gated_producer(case_a.profile_home)
    with adapter._profile_scope("hub"):
        discover_plugins()

    _reset_probe()
    monkeypatch.setattr(b2b_ctx, "_SOURCE_DEADLINE_S", 0.2)
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    tasks = []
    try:
        # Sequential submissions: each request outlives its own 0.2 s
        # budget before the next is issued, so every refusal is provably
        # the request's own deadline — and all three workers stay parked.
        for _ in range(3):
            response = await asyncio.wait_for(
                _launch_profile(case_a, "hub"), timeout=15.0)
            _assert_refused_503(response)
        assert spawned == []
        assert len(PREP_WORKER_THREADS) == 3, (
            "three actually-entered parked workers expected")
        # All three workers are STILL parked inside the producer. A fresh
        # healthy launch must reach ITS OWN worker regardless — any
        # cross-request counting would refuse it at admission instead.
        monkeypatch.setattr(b2b_ctx, "_SOURCE_DEADLINE_S", 5.0)
        healthy = asyncio.create_task(_launch_profile(case_d, "hub"))
        deadline = time.monotonic() + 15.0
        while (len(PREP_WORKER_THREADS) == 3
               and not healthy.done() and time.monotonic() < deadline):
            await asyncio.sleep(0.005)
        assert len(PREP_WORKER_THREADS) == 4, (
            "the healthy launch never started its own preparation worker")
        PREP_GATE.set()
        response = await asyncio.wait_for(healthy, timeout=15.0)
    finally:
        PREP_GATE.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        _join_prep_workers()
    assert getattr(response, "status", None) == 200, response
    assert len(spawned) == 1


@pytest.mark.asyncio
async def test_cancelled_launch_orphans_its_worker_until_it_exits(
        tmp_path, monkeypatch, opened):
    """Cancelling the caller's launch task while its producer is parked does
    not kill the native-read worker — it keeps running until its callback
    returns and its late result is discarded; a follow-up launch admits
    normally with no cross-request accounting."""
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
    # The orphaned worker outlives its caller and blocks NOTHING: the next
    # launch's worker must reach the producer too — then complete once the
    # gate opens.
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
    second_response = await second
    assert getattr(second_response, "status", None) == 200, second_response


def _install_multi_b2b_state(adapter, lane, *names):
    """Rebind the adapter's b2b state so health evaluates ALL named homes —
    with operator inputs that are actually ON DISK (the ready lane's contract
    root + My Work roots) so the stuck code can surface past inputs."""
    from gateway.platforms.api_server_b2b import _B2BState, validate_b2b_config
    extra = admission._b2b_extra(*names)
    for _name in names:
        _project = extra["b2b"]["profiles"][_name]["projects"]["b2b-bench"]
        _project["context_contract_root"] = (
            lane.project["context_contract_root"])
        _project["project_context"] = dict(
            lane.project["project_context"],
            project_id=_project["project_id"])
    adapter._b2b_state = _B2BState(validate_b2b_config(extra))


def test_blocked_validators_cannot_starve_the_default_executor(
        tmp_path, monkeypatch, opened):
    """Eight preparations parked inside their plugin's validator must not
    consume a SINGLE default-executor slot: a REAL generic
    /api/sessions/{id} route on ANOTHER profile keeps answering through
    asyncio.to_thread + SessionDB while all eight are still blocked. The
    eight launches then hit their (large) source budget together and refuse
    as a group — each one its own request alone."""
    asyncio.run(_executor_starvation_scenario(tmp_path, monkeypatch, opened))


async def _executor_starvation_scenario(tmp_path, monkeypatch, opened):
    from concurrent.futures import ThreadPoolExecutor
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli.plugins import discover_plugins

    # Bound the loop's default executor to exactly the launch count: if a
    # preparation parked on it, the executor would be FULL — deterministic.
    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=8))
    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    adapter._max_concurrent_runs = 0
    case_b = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "ci", "c")
    # The session lives ONLY in ci's own database — the separation proof.
    case_b.db.create_session("ci_plain_session", "api_server")
    assert case_a.db.get_session("ci_plain_session") is None
    # A's launches carry their explicit db; with the adapter's default db
    # dropped, the generic route must follow the existing per-home cache.
    adapter._session_db = None

    _freeze_preparation_clock(monkeypatch)
    # A generous budget: the eight preparations must still be parked when the
    # generic route answers, and all eight must refuse as a group only once
    # the budget genuinely expires.
    monkeypatch.setattr(b2b_ctx, "_SOURCE_DEADLINE_S", 5.0)
    _install_gated_validator(case_a.profile_home)
    with adapter._profile_scope("hub"):
        discover_plugins()

    _reset_probe()
    globals()["VAL_BLOCK_CALL"] = 1
    # The barrier lets ALL eight validators enter before any parks on the
    # gate — genuinely simultaneous orphans, not a serialization artefact.
    globals()["VAL_BARRIER"] = threading.Barrier(8)
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder([]))

    app = web.Application()

    async def _ci_get_session(request):
        with adapter._profile_scope("ci"):
            return await adapter._handle_get_session(request)

    app.router.add_get("/p/ci/api/sessions/{session_id}", _ci_get_session)

    # All eight launches start genuinely together — nothing serializes a
    # sibling behind a still-bootstrapping launch — and every preparation
    # ends up parked inside the plugin's validator at once.
    deadline = time.monotonic() + 30.0
    tasks = [asyncio.create_task(_launch_profile(case_a, "hub"))
             for _ in range(8)]
    try:
        while (len(VAL_WORKER_THREADS) < 8
               and not all(t.done() for t in tasks)
               and time.monotonic() < deadline):
            await asyncio.sleep(0.005)
        assert len(VAL_WORKER_THREADS) == 8
        assert len({entry[2] for entry in VAL_WORKER_THREADS}) == 8

        # A REAL generic route on another profile keeps serving while the
        # validators hold their workers — its to_thread/SessionDB hop must
        # not queue behind preparation.
        async with TestClient(TestServer(app)) as client:
            response = await asyncio.wait_for(
                client.get(
                    "/p/ci/api/sessions/ci_plain_session",
                    headers={
                        "Authorization": "Bearer " + admission._API_KEY}),
                timeout=2.0)
            assert response.status == 200
            payload = await response.json()
        assert payload["session"]["id"] == "ci_plain_session"

        # Thread identity holds under the fix — asserted AFTER the route so a
        # tree without it fails on the starvation it is meant to prove.
        assert all(
            entry[2] is PREP_WORKER_THREADS[entry[0]]
            for entry in VAL_WORKER_THREADS)

        responses = await asyncio.wait_for(
            asyncio.gather(*tasks), timeout=60.0)
        for refused in responses:
            _assert_refused_503(refused)
    finally:
        # ALWAYS release — even on timeout — so no worker outlives the test.
        VAL_GATE.set()
        if VAL_BARRIER is not None:
            VAL_BARRIER.abort()
        await asyncio.gather(*tasks, return_exceptions=True)
        _join_prep_workers()
        adapter._close_cached_session_dbs()


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["plugin_register", "gateway_config"])
async def test_bootstrap_work_past_preparation_budget_still_admits(
        tmp_path, monkeypatch, opened, stage):
    """Bootstrap work — a COLD plugin discovery held inside the plugin's own
    ``register``, or the gateway config load — is OUTSIDE the preparation
    worker's budget: held past the whole source bound the launch stays
    pending rather than refuse, then admits once the work finishes. The
    register arm performs no ``discover_plugins`` of its own: the single
    real launch does the cold discovery itself."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx

    case = _new_launch(tmp_path, monkeypatch, opened)
    case.db = case.adapter._session_db
    adapter = case.adapter

    _freeze_preparation_clock(monkeypatch)
    monkeypatch.setattr(b2b_ctx, "_SOURCE_DEADLINE_S", 0.2)
    _reset_probe()
    if stage == "plugin_register":
        execution_lane._write_fake_plugin(
            case.profile_home, init=_COLD_REGISTER_INIT)
    else:
        execution_lane._write_fake_plugin(case.profile_home)
        import gateway.run as gateway_run
        real_load = gateway_run._load_gateway_config

        def _slow_load(*args, **kwargs):
            REGISTER_ENTERED.set()
            REGISTER_GATE.wait(timeout=30.0)
            return real_load(*args, **kwargs)

        monkeypatch.setattr(
            gateway_run, "_load_gateway_config", _slow_load)
    execution_lane._plugin_config(
        case.profile_home, stamp=_PREPARATION_STAMP)

    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    task = asyncio.create_task(_launch(case))
    try:
        deadline = time.monotonic() + 10.0
        while not REGISTER_ENTERED.is_set() and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        assert REGISTER_ENTERED.is_set(), f"{stage} never started"
        # Held past the WHOLE preparation budget, the launch itself stays
        # pending — bootstrap work is not what the preparation bound prices.
        await asyncio.sleep(0.2 + 0.4)
        assert not task.done()
    finally:
        REGISTER_GATE.set()
    response = await asyncio.wait_for(task, timeout=10.0)
    assert response.status == 200, response.body
    assert len(spawned) == 1


@pytest.mark.asyncio
async def test_secret_source_lock_wait_blocks_neither_home(
        tmp_path, monkeypatch, opened):
    """Profile A's external-secret hydration parks inside the inner
    implementation — under the REAL global ``_SECRET_SOURCE_CACHE_LOCK`` —
    past the whole source budget while B's launch queues behind the SAME
    lock. NEITHER wait is preparation plugin code, neither launch refuses:
    both admit once the hydration actually finishes."""
    import hermes_cli.env_loader as env_loader
    from gateway.platforms import api_server_b2b_context as b2b_ctx

    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    adapter._max_concurrent_runs = 0
    _install_multi_b2b_state(adapter, case_a.lane, "hub", "ci")
    case_b = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "ci", "c")

    _freeze_preparation_clock(monkeypatch)
    monkeypatch.setattr(b2b_ctx, "_SOURCE_DEADLINE_S", 0.2)
    execution_lane._write_fake_plugin(case_a.profile_home)
    execution_lane._plugin_config(
        case_a.profile_home, stamp=_PREPARATION_STAMP)
    execution_lane._write_fake_plugin(case_b.profile_home)
    execution_lane._plugin_config(
        case_b.profile_home, stamp=_PREPARATION_STAMP)

    # Hold A's hydration inside the inner implementation — under the REAL
    # global lock — so B's hydration queues on the same lock acquisition.
    real_inner = env_loader._hydrate_profile_secret_sources
    hydrate_gate = threading.Event()
    hydrate_entered = threading.Event()
    a_home = str(case_a.profile_home.resolve())

    def _blocked_inner(home):
        if str(Path(home).resolve()) == a_home:
            hydrate_entered.set()
            hydrate_gate.wait(timeout=30.0)
        return real_inner(home)

    monkeypatch.setattr(
        env_loader, "_hydrate_profile_secret_sources", _blocked_inner)

    # A spy on the PUBLIC entry point — the real global lock stays intact:
    # it proves B actually REACHED its hydration attempt (and is therefore
    # queued on the lock A holds), which a bare pending task cannot show.
    real_public = env_loader.hydrate_profile_secret_sources
    b_hydrate_attempted = threading.Event()
    b_home = str(case_b.profile_home.resolve())

    def _spy_public(home):
        if str(Path(home).resolve()) == b_home:
            b_hydrate_attempted.set()
        return real_public(home)

    monkeypatch.setattr(
        env_loader, "hydrate_profile_secret_sources", _spy_public)

    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    task_a = asyncio.create_task(_launch_unhydrated(case_a, "hub"))
    try:
        deadline = time.monotonic() + 10.0
        while not hydrate_entered.is_set() and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        assert hydrate_entered.is_set(), "A's hydration never started"
        task_b = asyncio.create_task(_launch_unhydrated(case_b, "ci"))
        deadline = time.monotonic() + 10.0
        while not b_hydrate_attempted.is_set() and (
                time.monotonic() < deadline):
            await asyncio.sleep(0.005)
        assert b_hydrate_attempted.is_set(), (
            "B never reached its hydration attempt")
        # BOTH waits exceed the WHOLE preparation budget — yet neither
        # launch refuses: a queued hydration is not preparation work.
        await asyncio.sleep(0.2 + 0.5)
        assert not task_a.done()
        assert not task_b.done()
    finally:
        hydrate_gate.set()
    response_a, response_b = await asyncio.wait_for(
        asyncio.gather(task_a, task_b), timeout=15.0)
    assert response_a.status == 200, response_a.body
    assert response_b.status == 200, response_b.body
    assert sorted(p for p, _run, _s in spawned) == ["ci", "hub"]


# ---------------------------------------------------------------------------
# P2: the launch bootstrap is itself a bounded NON-preparation operation —
# held off the loop's default executor entirely under its own deadline, with
# no cross-request admission: siblings bootstrap concurrently, and a timed
# out bootstrap fails its launch alone.
# ---------------------------------------------------------------------------

# Threads that ran plugin register()/secret hydration — the bootstrap probe
# variants below append to them so tests can assert NO plugin/bootstrap code
# ever ran on the API loop's own thread.
REGISTER_THREADS = []
HYDRATE_THREADS = []

# Cold register that BOTH parks on REGISTER_GATE and records its worker.
_COLD_REGISTER_THREADS_INIT = _COLD_REGISTER_INIT.replace(
    "    probe.REGISTER_ENTERED.set()\n",
    "    probe.REGISTER_THREADS.append(_t.current_thread())\n"
    "    probe.REGISTER_ENTERED.set()\n", 1).replace(
    "    from tests.gateway import (\n"
    "        test_api_server_b2b_context_capacity as probe)\n",
    "    import threading as _t\n"
    "    from tests.gateway import (\n"
    "        test_api_server_b2b_context_capacity as probe)\n", 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["plugin_register", "hydration"])
async def test_blocked_bootstrap_never_starves_default_executor(
        tmp_path, monkeypatch, opened, stage):
    """A bootstrap held inside cold plugin ``register()`` — or inside plugin
    secret-source hydration — consumes ZERO default-executor slots and ZERO
    API-loop time: with the loop's executor capped at ONE worker a real
    generic session route on ANOTHER profile (register arm) and the real
    ``/health/detailed`` handler (both arms) keep answering while the same
    launch stays pending — held inside the bounded bootstrap worker,
    never on the loop or the shared executor."""
    from concurrent.futures import ThreadPoolExecutor
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer
    import hermes_cli.env_loader as env_loader

    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=1))
    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    adapter._max_concurrent_runs = 0
    case_b = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "ci", "c")
    case_b.db.create_session("ci_plain_session", "api_server")
    assert case_a.db.get_session("ci_plain_session") is None
    adapter._session_db = None

    _freeze_preparation_clock(monkeypatch)
    _reset_probe()
    loop_thread = threading.current_thread()
    if stage == "plugin_register":
        execution_lane._write_fake_plugin(
            case_a.profile_home, init=_COLD_REGISTER_THREADS_INIT)
    else:
        execution_lane._write_fake_plugin(case_a.profile_home)
        real_inner = env_loader._hydrate_profile_secret_sources
        a_home = str(case_a.profile_home.resolve())

        def _blocked_inner(home):
            if str(Path(home).resolve()) == a_home:
                HYDRATE_THREADS.append(threading.current_thread())
                REGISTER_ENTERED.set()
                REGISTER_GATE.wait(timeout=30.0)
            return real_inner(home)

        monkeypatch.setattr(
            env_loader, "_hydrate_profile_secret_sources", _blocked_inner)
    execution_lane._plugin_config(
        case_a.profile_home, stamp=_PREPARATION_STAMP)
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    app = web.Application()

    async def _ci_get_session(request):
        with adapter._profile_scope("ci"):
            return await adapter._handle_get_session(request)

    app.router.add_get("/p/ci/api/sessions/{session_id}", _ci_get_session)

    task = asyncio.create_task(_launch_unhydrated(case_a, "hub"))
    try:
        deadline = time.monotonic() + 10.0
        while not REGISTER_ENTERED.is_set() and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        assert REGISTER_ENTERED.is_set(), f"bootstrap {stage} never started"
        assert not task.done()

        # On the hydration arm the bootstrap worker holds the REAL global
        # secret-source lock — ordinary routes legitimately queue there —
        # but health must stay non-hydrating and answer regardless.
        if stage == "plugin_register":
            async with TestClient(TestServer(app)) as client:
                response = await asyncio.wait_for(
                    client.get(
                        "/p/ci/api/sessions/ci_plain_session",
                        headers={
                            "Authorization": "Bearer " + admission._API_KEY}),
                    timeout=5.0)
                assert response.status == 200
                payload = await response.json()
            assert payload["session"]["id"] == "ci_plain_session"

        request = SimpleNamespace(
            headers={"Authorization": "Bearer " + admission._API_KEY})
        detailed = await asyncio.wait_for(
            adapter._handle_health_detailed(request), timeout=5.0)
        assert detailed.status == 200

        assert not task.done()
        assert spawned == []
    finally:
        REGISTER_GATE.set()
        results = await asyncio.gather(task, return_exceptions=True)
        adapter._close_cached_session_dbs()

    response = results[0]
    assert response.status == 200, getattr(response, "body", response)
    assert len(spawned) == 1
    # Bootstrap plugin code — register() or hydration — NEVER ran on the
    # API loop's own thread.
    bootstrap_threads = list(REGISTER_THREADS) + list(HYDRATE_THREADS)
    assert bootstrap_threads, "bootstrap instrumentation saw no callback"
    assert all(t is not loop_thread for t in bootstrap_threads), (
        bootstrap_threads)


@pytest.mark.asyncio
async def test_bootstrap_deadline_refuses_then_retry_admits(
        tmp_path, monkeypatch, opened):
    """A bootstrap that outlives its OWN bounded budget is refused 503
    ``execution_unavailable`` — the refusal is request-local: once the
    parked worker's callback returns, a retry on the SAME home admits end
    to end. No exclusion state outlives the timed-out request, and no
    durable side effects are written."""
    case = _new_launch(tmp_path, monkeypatch, opened)
    case.db = case.adapter._session_db
    adapter = case.adapter
    adapter._max_concurrent_runs = 0

    _freeze_preparation_clock(monkeypatch)
    # The bootstrap's own bound — far under the external test patience:
    # the launch must refuse on ITS deadline, not the harness's.
    monkeypatch.setattr(execution_lane.b2b, "_REQUEST_TTL_S", 0.3)
    _reset_probe()
    execution_lane._write_fake_plugin(
        case.profile_home, init=_COLD_REGISTER_INIT)
    execution_lane._plugin_config(
        case.profile_home, stamp=_PREPARATION_STAMP)
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))
    before = admission._store_counts(case.store)

    response = await asyncio.wait_for(
        _launch_unhydrated(case, "hub"), timeout=8.0)
    _assert_refused_503(response)
    # The register worker is STILL parked — its late result is simply
    # discarded; no exclusion state keeps the home refused.
    assert REGISTER_ENTERED.is_set()
    assert admission._store_counts(case.store) == before
    assert spawned == []
    try:
        # Releasing the parked register() lets the orphaned worker exit —
        # the next launch on the same home then admits end to end.
        REGISTER_GATE.set()
    finally:
        REGISTER_GATE.set()
    response = await _launch_unhydrated(case, "hub")
    assert response.status == 200, response.body
    assert len(spawned) == 1


@pytest.mark.asyncio
async def test_b2b_route_scope_entry_never_hydrates_on_loop(
        tmp_path, monkeypatch, opened):
    """Through the REAL profile-prefix middleware: a B2B proposal POST and
    ``/health`` must enter the request profile scope WITHOUT running plugin
    secret-source hydration on the API loop — hydration belongs to the
    launch's bounded bootstrap worker alone. The spy records the THREAD
    every hydration runs on; any loop-thread record is the regression."""
    from agent.secret_scope import is_multiplex_active, set_multiplex_active
    from aiohttp.test_utils import TestClient, TestServer
    import hermes_cli.env_loader as env_loader

    case = _new_launch(tmp_path, monkeypatch, opened)
    case.db = case.adapter._session_db
    adapter = case.adapter
    adapter._max_concurrent_runs = 0
    # The real POST handler reads the ADAPTER's lane state — install the
    # lane's full project entry, not the bare _b2b_extra stub.
    adapter._b2b_state = execution_lane._state({"hub": case.entry})

    _freeze_preparation_clock(monkeypatch)
    execution_lane._write_fake_plugin(case.profile_home)
    execution_lane._plugin_config(case.profile_home, stamp=_PREPARATION_STAMP)

    loop_thread = threading.current_thread()
    hydrate_calls = []
    real_inner = env_loader._hydrate_profile_secret_sources

    def _spy_inner(home):
        hydrate_calls.append((str(home), threading.current_thread()))
        return real_inner(home)

    monkeypatch.setattr(
        env_loader, "_hydrate_profile_secret_sources", _spy_inner)

    async def _resolved_source(*a, **k):
        return case.resolved, "ok"

    monkeypatch.setattr(
        execution_lane.b2b, "_resolve_source_async", _resolved_source)
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    previous = is_multiplex_active()
    set_multiplex_active(True)
    try:
        app = admission._app(adapter)
        app.router.add_get("/health", adapter._handle_health)
        async with TestClient(TestServer(app)) as client:
            response = await client.post(
                f"/p/hub/api/sessions/{case.session_id}/b2b-proposal",
                json={"attempt_id": case.resolved["attempt_id"],
                      "binding_digest": case.session_id[4:]},
                headers={"Authorization": "Bearer " + admission._API_KEY,
                         "Idempotency-Key": case.resolved["attempt_id"]})
            assert response.status == 200, await response.text()
            health = await client.get("/health")
            assert health.status == 200
    finally:
        set_multiplex_active(previous)

    assert hydrate_calls, "instrumentation never saw a hydration"
    assert all(thread is not loop_thread
               for _home, thread in hydrate_calls), hydrate_calls


@pytest.mark.asyncio
async def test_plugin_callbacks_never_run_on_api_loop_inventory(
        tmp_path, monkeypatch, opened):
    """Genuine launch inventory: cold ``register()``, the ``prepare_context``
    native read AND its returned ``validate_configuration`` — every observed
    plugin-callback phase is asserted POPULATED (a swallowed instrument
    fails here, never silently passes) and asserted OFF the API loop's own
    thread."""
    case = _new_launch(tmp_path, monkeypatch, opened)
    case.db = case.adapter._session_db
    adapter = case.adapter
    adapter._max_concurrent_runs = 0
    _freeze_preparation_clock(monkeypatch)
    _reset_probe()

    _INVENTORY_INIT = _GATED_VALIDATOR_INIT.replace(
        "def register(ctx):\n",
        "def register(ctx):\n"
        "    import threading as _t\n"
        "    from tests.gateway import (\n"
        "        test_api_server_b2b_context_capacity as probe)\n"
        "    probe.REGISTER_THREADS.append(_t.current_thread())\n", 1)
    execution_lane._write_fake_plugin(
        case.profile_home, name="inventory-producer", init=_INVENTORY_INIT)
    execution_lane._plugin_config(
        case.profile_home, stamp=_PREPARATION_STAMP,
        names=("inventory-producer",))
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))
    loop_thread = threading.current_thread()
    response = await _launch_unhydrated(case, "hub")
    assert response.status == 200, response.body
    assert len(spawned) == 1
    phases = {
        "register": list(REGISTER_THREADS),
        "prepare_context": list(PREP_WORKER_THREADS),
        "validate_configuration": [t for _i, _c, t in VAL_WORKER_THREADS]}
    assert all(threads for threads in phases.values()), phases
    assert all(
        thread is not loop_thread
        for threads in phases.values() for thread in threads), phases


@pytest.mark.asyncio
@pytest.mark.parametrize("helper", ["construct", "turn"])
async def test_bounded_api_worker_bounds_blocked_body(
        tmp_path, monkeypatch, opened, helper):
    """B2B construction and the synchronous turn body ride the SAME counted
    non-preparation bounded worker — never the default executor, never
    unbounded. A body parked on an event refuses on its derived window with
    ZERO consumed executor slots (a real health answer still arrives) and a
    live worker count that stays raised until the orphan's true exit —
    and on the turn arm the refusal lands durable: the attempt records
    ``context_unavailable`` and its dispatch CAS refuses outright."""
    from concurrent.futures import ThreadPoolExecutor
    from agent.b2b_execution import B2BTerminalRefusal
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from gateway.platforms import api_server_b2b_execution as b2b_exec
    from gateway.platforms import api_server_runs

    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=1))
    case = _new_launch(tmp_path, monkeypatch, opened)
    adapter = case.adapter
    lane = case.lane
    _install_multi_b2b_state(adapter, lane, "hub")
    _reset_probe()

    # Patched-down copies of the EXISTING budgets so the refusal lands fast.
    monkeypatch.setattr(execution_lane.b2b, "_REQUEST_TTL_S", 0.2)
    monkeypatch.setattr(execution_lane.b2b, "_SOURCE_DEADLINE_S", 0.1)
    policy = dict(lane.cap.policy)
    policy["project"] = dict(
        policy["project"], request_timeout_seconds=0.1)
    from agent.b2b_execution import BoundExecution
    cap = BoundExecution(
        profile=lane.cap.profile, session_id=lane.cap.session_id,
        binding_digest=lane.cap.binding_digest,
        attempt_id=lane.cap.attempt_id, run_id=lane.cap.run_id,
        policy=policy, sink=lane.sink, created_at=lane.cap.created_at)

    run = SimpleNamespace(b2b_execution=cap)
    gate = threading.Event()
    worker_threads = []

    def _blocked_body():
        worker_threads.append(threading.current_thread())
        gate.wait(timeout=30.0)
        return "done"

    loop = asyncio.get_running_loop()
    loop_thread = threading.current_thread()

    async def _submit():
        if helper == "construct":
            return await b2b_exec.construct_run_agent(
                adapter, run, _blocked_body, loop)
        return await b2b_exec.execute_run_agent(
            adapter, run, _blocked_body, loop)

    request = SimpleNamespace(
        headers={"Authorization": "Bearer " + admission._API_KEY})
    try:
        with pytest.raises(B2BTerminalRefusal, match="context_unavailable"):
            await asyncio.wait_for(_submit(), timeout=10.0)
        # The orphan is still parked: its live count stays raised, it ran
        # off the loop thread AND off the single executor slot — a real
        # health answer (itself a to_thread hop) arrives promptly.
        assert api_server_runs.api_worker_live_count() == 1
        assert worker_threads and worker_threads[0] is not loop_thread
        detailed = await asyncio.wait_for(
            adapter._handle_health_detailed(request), timeout=5.0)
        assert detailed.status == 200
        if helper == "turn":
            assert lane.store.b2b_attempt(profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "context_unavailable"
            assert not lane.store.b2b_cas_dispatch(profile=lane.profile, attempt_id=lane.attempt_id,
                                                  source_record=b"{}", dispatch_record=b"{}")
    finally:
        gate.set()
    deadline = time.monotonic() + 10.0
    while (api_server_runs.api_worker_live_count() != 0
           and time.monotonic() < deadline):
        await asyncio.sleep(0.01)
    assert api_server_runs.api_worker_live_count() == 0
