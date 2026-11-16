"""B2B launch capacity — ONE per-home ledger shared with the run limiter.

Every NEW B2B launch reserves exactly ONE unit on its own canonical
``hermes_home_key`` — before its first native read and until its last
host-created worker actually exits. At saturation the answer is the shared
limiter's, never a preparation-specific refusal: HTTP 429
``rate_limit_exceeded`` / ``Retry-After: 1``, with zero discovery, provider
or durable side effects. A sibling profile's home is judged independently, a
durable replay bypasses the ledger entirely, and a caller's
timeout/cancellation frees nothing while a worker still runs.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from types import SimpleNamespace

import pytest

from hermes_state import SessionDB
from tests.gateway import test_api_server_b2b_admission as admission
from tests.gateway import test_api_server_b2b_execution_lane as execution_lane
from tests.gateway.test_api_server_b2b_hook_admission import (
    _forbidden, _launch, _new_launch, opened)

# State shared with the fake producer plugin below (it imports this module):
# the gate the producer waits on, the enter signal, and the real Thread
# objects that entered its prepare_context callback.
PREP_GATE = threading.Event()
PREP_ENTERED = threading.Event()
PREP_WORKER_THREADS = []

_CAPACITY_PLUGIN_NAME = "capacity-producer"

# Same contract as execution_lane._FAKE_PLUGIN_INIT, but the callback parks
# on PREP_GATE so a launch can be held inside its native read.
_CAPACITY_PLUGIN_INIT = '''\
def register(ctx):
    def prepare_context(*, execution):
        import threading as _threading
        from agent.b2b_execution import B2BTerminalRefusal
        from tests.gateway import test_api_server_b2b_context_capacity as probe
        from tests.gateway.b2b_process_harness import (
            UNIT_RENDERED, build_unit_native_oc_view)
        probe.PREP_WORKER_THREADS.append(_threading.current_thread())
        probe.PREP_ENTERED.set()
        probe.PREP_GATE.wait()
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


def _assert_limiter_429(response):
    """The shared run limiter's exact wire shape — capacity refusal == run
    limiter refusal, never a preparation-specific one."""
    assert response.status == 429
    body = json.loads(response.body)
    assert body["error"]["code"] == "rate_limit_exceeded"
    assert body["error"]["type"] == "rate_limit_error"
    assert response.headers["Retry-After"] == "1"


def _profile_case(tmp_path, monkeypatch, opened, adapter, lane, profile,
                  letter, db=None):
    """A second launchable profile/session on the SAME adapter — a real home
    dir + real SessionDB inside it for another profile, or the launch db for
    a second session on the SAME home (the A/B home pair)."""
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


@pytest.mark.asyncio
async def test_blocked_launch_saturates_only_its_own_home(
        tmp_path, monkeypatch, opened):
    """A's producer blocked past the source budget: the ORIGINAL requester
    still gets 503 execution_unavailable, but every further A launch gets the
    shared limiter's 429 — zero extra worker, discovery or durable write —
    while B admits on its own home and stays healthy. Releasing A's worker
    frees the unit: A admits again."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from gateway.platforms.api_server_b2b_context import producer_available
    from gateway.platforms.api_server_b2b_execution import b2b_execution_status
    from hermes_cli.plugins import discover_plugins

    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    adapter._max_concurrent_runs = 1
    # Rebind the adapter's b2b state so health evaluates BOTH homes.
    from gateway.platforms.api_server_b2b import _B2BState, validate_b2b_config
    adapter._b2b_state = _B2BState(validate_b2b_config(
        admission._b2b_extra("hub", "ci")))
    case_b = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "ci", "c")

    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: 1793361605.0))
    execution_lane._write_fake_plugin(
        case_a.profile_home, name=_CAPACITY_PLUGIN_NAME,
        init=_CAPACITY_PLUGIN_INIT)
    execution_lane._plugin_config(
        case_a.profile_home, names=(_CAPACITY_PLUGIN_NAME,))
    # B keeps an ordinary working producer — it must admit while A is full.
    execution_lane._write_fake_plugin(case_b.profile_home, name="ci-producer")
    execution_lane._plugin_config(case_b.profile_home, names=("ci-producer",))
    with adapter._profile_scope("hub"):
        discover_plugins()
    with adapter._profile_scope("ci"):
        discover_plugins()

    PREP_GATE.clear()
    PREP_ENTERED.clear()
    del PREP_WORKER_THREADS[:]
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))
    before = admission._store_counts(case_a.store)
    changes_before = case_a.store._conn.total_changes

    response = await _launch_profile(case_a, "hub")
    assert response.status == 503
    assert json.loads(response.body)["error"] == "execution_unavailable"
    assert PREP_ENTERED.is_set()

    try:
        for _ in range(8):
            _assert_limiter_429(await _launch_profile(case_a, "hub"))
        # Refused launches started no second worker, discovery or native read.
        assert len(set(PREP_WORKER_THREADS)) == 1
        assert admission._store_counts(case_a.store) == before
        assert case_a.store._conn.total_changes == changes_before
        assert case_a.db.get_session(case_a.session_id)["title"] is None
        # Health reports the saturation on A's home only — through the
        # adapter-scoped probe AND the shared-ledger no-adapter probe, and
        # through the real /health/detailed handler once.
        with adapter._profile_scope("hub"):
            assert producer_available(adapter) is False
            assert producer_available() is False
        with adapter._profile_scope("ci"):
            assert producer_available() is True
        status = b2b_execution_status(adapter)
        assert status["b2b_execution_profiles"]["hub"] == {
            "state": "not-ready", "code": "capacity_exhausted",
            "producer_available": False}
        assert status["b2b_execution_profiles"]["ci"]["code"] != (
            "capacity_exhausted")
        request = SimpleNamespace(
            headers={"Authorization": "Bearer " + admission._API_KEY})
        detailed = await adapter._handle_health_detailed(request)
        assert detailed.status == 200
        assert json.loads(detailed.body)["b2b_execution_profiles"]["hub"] == {
            "state": "not-ready", "code": "capacity_exhausted",
            "producer_available": False}
        # A-B-A: B admits while A stays saturated; A is still refused after.
        response_b = await _launch_profile(case_b, "ci")
        assert response_b.status == 200, response_b.body
        _assert_limiter_429(await _launch_profile(case_a, "hub"))
    finally:
        PREP_GATE.set()
    _join_prep_workers()

    response = await _launch_profile(case_a, "hub")
    assert response.status == 200, response.body
    with adapter._profile_scope("hub"):
        assert producer_available(adapter) is True
    assert case_a.db.get_session(case_a.session_id)["title"] == (
        "B2B " + case_a.session_id)


@pytest.mark.asyncio
async def test_two_healthy_launches_admit_together_at_limit_two(
        tmp_path, monkeypatch, opened):
    """Two genuinely simultaneous healthy launches on ONE home under limit 2:
    BOTH reach the producer barrier and both admit — no healthy launch hears
    503 for capacity."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli.plugins import discover_plugins

    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    adapter._max_concurrent_runs = 2
    case_d = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "hub", "d",
        db=adapter._session_db)

    execution_lane._write_fake_plugin(
        case_a.profile_home, name=_CAPACITY_PLUGIN_NAME,
        init=_CAPACITY_PLUGIN_INIT)
    execution_lane._plugin_config(
        case_a.profile_home, names=(_CAPACITY_PLUGIN_NAME,))
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: 1793361605.0))
    with adapter._profile_scope("hub"):
        discover_plugins()

    # Genuine synchronization: the producer parks on the gate, which opens
    # only once BOTH launches' real workers have entered it — waiting on the
    # helper tasks entering would race (the first entry can wake a helper
    # before the second launch's worker ever ran).
    PREP_GATE.clear()
    PREP_ENTERED.clear()
    del PREP_WORKER_THREADS[:]
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    t1 = asyncio.create_task(_launch_profile(case_a, "hub"))
    t2 = asyncio.create_task(_launch_profile(case_d, "hub"))
    try:
        deadline = time.monotonic() + 15.0
        while len(set(PREP_WORKER_THREADS)) < 2:
            assert time.monotonic() < deadline, (
                "both launches' workers never entered the producer")
            await asyncio.sleep(0.005)
    finally:
        PREP_GATE.set()
    r1, r2 = await asyncio.gather(t1, t2)
    assert r1.status == 200, r1.body
    assert r2.status == 200, r2.body
    assert len(spawned) == 2


@pytest.mark.asyncio
async def test_second_healthy_launch_gets_limiter_429_at_limit_one(
        tmp_path, monkeypatch, opened):
    """Under limit 1 on one home: the first launch reaches the producer, the
    second hears the exact limiter 429 (never 503) and leaves no effects."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli.plugins import discover_plugins

    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    adapter._max_concurrent_runs = 1
    case_d = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "hub", "d",
        db=adapter._session_db)

    execution_lane._write_fake_plugin(
        case_a.profile_home, name=_CAPACITY_PLUGIN_NAME,
        init=_CAPACITY_PLUGIN_INIT)
    execution_lane._plugin_config(
        case_a.profile_home, names=(_CAPACITY_PLUGIN_NAME,))
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: 1793361605.0))
    with adapter._profile_scope("hub"):
        discover_plugins()

    PREP_GATE.clear()
    PREP_ENTERED.clear()
    del PREP_WORKER_THREADS[:]
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))
    before = admission._store_counts(case_a.store)

    first = asyncio.create_task(_launch_profile(case_a, "hub"))
    deadline = time.monotonic() + 10.0
    while not PREP_ENTERED.is_set() and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    assert PREP_ENTERED.is_set()
    try:
        _assert_limiter_429(await _launch_profile(case_d, "hub"))
        assert len(set(PREP_WORKER_THREADS)) == 1
        assert admission._store_counts(case_a.store) == before
        assert case_d.db.get_session(case_d.session_id)["title"] is None
    finally:
        PREP_GATE.set()
    r1 = await first
    assert r1.status == 200, r1.body
    _join_prep_workers()


@pytest.mark.asyncio
async def test_blocked_discovery_holds_unit_until_worker_exits(
        tmp_path, monkeypatch, opened):
    """The real discovery lock held by an independent thread: the launch's
    worker times out (503 to its requester) but stays blocked INSIDE
    discovery — the unit stays counted, repeats get 429 with no new worker
    and no native read, until the worker actually exits."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli import plugins
    from hermes_cli.plugins import discover_plugins, get_plugin_manager

    case = _new_launch(tmp_path, monkeypatch, opened)
    case.db = case.adapter._session_db
    adapter = case.adapter
    adapter._max_concurrent_runs = 1

    execution_lane._write_fake_plugin(
        case.profile_home, name=_CAPACITY_PLUGIN_NAME,
        init=_CAPACITY_PLUGIN_INIT)
    execution_lane._plugin_config(
        case.profile_home, names=(_CAPACITY_PLUGIN_NAME,))
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: 1793361605.0))
    with adapter._profile_scope("hub"):
        discover_plugins()
        manager = get_plugin_manager()

    real_discover = plugins.discover_plugins
    discovery_calls = []

    def _counting_discover(*args, **kwargs):
        discovery_calls.append(threading.current_thread())
        return real_discover(*args, **kwargs)

    monkeypatch.setattr(plugins, "discover_plugins", _counting_discover)
    get_session_calls = []
    real_get_session = case.db.get_session
    monkeypatch.setattr(case.db, "get_session",
                        lambda *a, **k: (get_session_calls.append(1),
                                        real_get_session(*a, **k))[1])
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _forbidden("_spawn_run"))
    before = admission._store_counts(case.store)

    # The gate stays OPEN here: the worker parks INSIDE the held discovery
    # lock, so releasing the lock lets it flow through the (unblocked)
    # producer to its real finally.
    PREP_GATE.set()
    PREP_ENTERED.clear()
    del PREP_WORKER_THREADS[:]
    manager._discovery_lock.acquire()
    try:
        response = await _launch(case)
        assert response.status == 503
        assert json.loads(response.body)["error"] == "execution_unavailable"
        assert len(discovery_calls) == 1  # the still-blocked worker only
        for _ in range(8):
            _assert_limiter_429(await _launch(case))
        assert len(discovery_calls) == 1, "refused launches ran discovery"
        assert len(get_session_calls) == 1, "refused launches read natively"
        assert admission._store_counts(case.store) == before
    finally:
        manager._discovery_lock.release()

    # The lease is freed at the worker's REAL exit — deterministic: the
    # blocked worker completes its preparation, then the same attempt admits.
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))
    deadline = time.monotonic() + 15.0
    while adapter._capacity.work_count() and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    assert adapter._capacity.work_count() == 0
    response = await _launch(case)
    assert response.status == 200, response.body
    _join_prep_workers()


@pytest.mark.asyncio
async def test_cancelled_launch_holds_unit_until_worker_exits(
        tmp_path, monkeypatch, opened):
    """Cancelling the launch task while its producer is blocked frees the
    ROOT hold only — the surviving worker still counts, so a new launch gets
    429 until the worker's real finally."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli.plugins import discover_plugins

    case = _new_launch(tmp_path, monkeypatch, opened)
    case.db = case.adapter._session_db
    adapter = case.adapter
    adapter._max_concurrent_runs = 1

    execution_lane._write_fake_plugin(
        case.profile_home, name=_CAPACITY_PLUGIN_NAME,
        init=_CAPACITY_PLUGIN_INIT)
    execution_lane._plugin_config(
        case.profile_home, names=(_CAPACITY_PLUGIN_NAME,))
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: 1793361605.0))
    with adapter._profile_scope("hub"):
        discover_plugins()

    PREP_GATE.clear()
    PREP_ENTERED.clear()
    del PREP_WORKER_THREADS[:]
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    task = asyncio.create_task(_launch(case))
    deadline = time.monotonic() + 10.0
    while not PREP_ENTERED.is_set() and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    assert PREP_ENTERED.is_set()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    try:
        _assert_limiter_429(await _launch(case))
    finally:
        PREP_GATE.set()
    _join_prep_workers()
    response = await _launch(case)
    assert response.status == 200, response.body


@pytest.mark.asyncio
async def test_durable_replay_bypasses_saturated_home(
        tmp_path, monkeypatch, opened):
    """An already-durable attempt is served outside the ledger entirely —
    replayed even while the home's count is at the cap."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli.plugins import discover_plugins

    case = _new_launch(tmp_path, monkeypatch, opened)
    case.db = case.adapter._session_db
    adapter = case.adapter

    execution_lane._write_fake_plugin(case.profile_home)
    execution_lane._plugin_config(case.profile_home)
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: 1793361605.0))
    with adapter._profile_scope("hub"):
        discover_plugins()
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    first = await _launch(case)
    assert first.status == 200, first.body

    adapter._max_concurrent_runs = 1
    gate = asyncio.Event()
    stuck = asyncio.create_task(gate.wait())
    adapter._active_run_tasks["run_stuck"] = stuck
    try:
        response = await _launch(case)
        assert response.status == 200, response.body
        assert json.loads(response.body)["status"] == "replayed"
    finally:
        gate.set()
        await stuck
        adapter._active_run_tasks.pop("run_stuck", None)


@pytest.mark.asyncio
async def test_late_recheck_worker_holds_unit(tmp_path, monkeypatch, opened):
    """A nested recheck daemon that outlives its bounded wait still counts —
    the unit drops only at the worker's real finally, so the SAME shared
    limiter still answers 429 meanwhile."""
    import agent.b2b_execution as bexec
    from gateway.platforms.api_server_capacity import acquire_launch_lease

    case = _new_launch(tmp_path, monkeypatch, opened)
    adapter = case.adapter
    adapter._max_concurrent_runs = 1
    lane = case.lane

    lease, refusal = acquire_launch_lease(
        adapter, adapter._capacity.launch_home_key)
    assert refusal is None and lease is not None
    lane.sink._work_lease = lease

    recheck_gate = threading.Event()
    recheck_entered = threading.Event()

    def _blocking_recheck(_cap):
        recheck_entered.set()
        recheck_gate.wait(timeout=30.0)
        raise RuntimeError("late")

    lane.cap.register_context_recheck(_blocking_recheck)
    outcome = []

    def _run_recheck():
        # The bound execution travels as a ContextVar: bind INSIDE the thread,
        # like _b2b_finalize's own worker does.
        token = bexec.bind_execution(lane.cap)
        try:
            bexec.recheck_context(
                lane.cap, SimpleNamespace(view={}),
                deadline=time.monotonic() + 0.3)
        except Exception as exc:
            outcome.append(exc)
        finally:
            bexec.reset_execution(token)

    worker = threading.Thread(target=_run_recheck, daemon=True)
    worker.start()
    try:
        assert recheck_entered.wait(timeout=10.0)
        # The bounded caller gave up already (deadline 0.3s); the daemon is
        # still inside the callback.
        deadline = time.monotonic() + 10.0
        while not outcome and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        worker.join(timeout=10.0)
        # Drop the ROOT hold while the nested daemon stays blocked: the
        # surviving child ref is the ONLY thing that may still count —
        # anything less proves the child never retained.
        lease.release()
        assert adapter._capacity.work_count() == 1
        second, refusal = acquire_launch_lease(adapter, lease.home_key)
        assert second is None
        _assert_limiter_429(refusal)
    finally:
        recheck_gate.set()
        deadline = time.monotonic() + 10.0
        while adapter._capacity.work_count() and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
    assert adapter._capacity.work_count() == 0


@pytest.mark.asyncio
async def test_plugin_loader_timeout_holds_unit(tmp_path, monkeypatch, opened):
    """A plugin-load worker abandoned past its deadline keeps the bound
    launch's unit until ITS real finally — never freed by the parent
    timeout, refunded only if the thread fails to start."""
    import agent.b2b_execution as bexec
    from gateway.platforms.api_server_capacity import acquire_launch_lease
    from hermes_cli import plugins_loader
    from hermes_cli.plugins_loader import PluginLoadTimeout

    case = _new_launch(tmp_path, monkeypatch, opened)
    adapter = case.adapter
    adapter._max_concurrent_runs = 1
    lane = case.lane

    lease, refusal = acquire_launch_lease(
        adapter, adapter._capacity.launch_home_key)
    assert refusal is None and lease is not None
    lane.sink._work_lease = lease

    monkeypatch.setattr(
        plugins_loader, "_resolve_plugin_load_timeout", lambda: 0.2)
    load_gate = threading.Event()
    ctx = SimpleNamespace(_abandon_load=lambda: None)
    token = bexec.bind_execution(lane.cap)
    try:
        try:
            plugins_loader.run_with_load_deadline(
                "unit-plugin", ctx, lambda: load_gate.wait(timeout=30.0))
            raise AssertionError("load deadline must fire")
        except PluginLoadTimeout:
            pass
        # Drop the ROOT hold while the abandoned loader stays blocked: only
        # the worker's own ref may still count, and the real limiter must
        # refuse the next launch on this home.
        lease.release()
        assert adapter._capacity.work_count() == 1
        second, refusal = acquire_launch_lease(adapter, lease.home_key)
        assert second is None
        _assert_limiter_429(refusal)
    finally:
        bexec.reset_execution(token)
        load_gate.set()
        deadline = time.monotonic() + 10.0
        while adapter._capacity.work_count() and (
                time.monotonic() < deadline):
            await asyncio.sleep(0.01)
    assert adapter._capacity.work_count() == 0


@pytest.mark.asyncio
async def test_bounded_hook_worker_holds_unit(tmp_path, monkeypatch, opened):
    """A hook callback worker skipped past its bound keeps the bound
    launch's unit until ITS real finally."""
    import agent.b2b_execution as bexec
    from gateway.platforms.api_server_capacity import acquire_launch_lease
    from hermes_cli.plugins import get_plugin_manager
    from hermes_cli.plugins_dispatch import _HOOK_SKIPPED

    case = _new_launch(tmp_path, monkeypatch, opened)
    adapter = case.adapter
    adapter._max_concurrent_runs = 1
    lane = case.lane

    lease, refusal = acquire_launch_lease(
        adapter, adapter._capacity.launch_home_key)
    assert refusal is None and lease is not None
    lane.sink._work_lease = lease

    cb_gate = threading.Event()
    cb_entered = threading.Event()

    def _blocking_cb(**_kwargs):
        cb_entered.set()
        cb_gate.wait(timeout=30.0)
        return None

    token = bexec.bind_execution(lane.cap)
    try:
        manager = get_plugin_manager()
        result = manager._run_hook_callback_bounded(
            "pre_tool_call", _blocking_cb, {"tool_name": "unit"}, 0.2)
        assert result is _HOOK_SKIPPED
        assert cb_entered.is_set()
        # Drop the ROOT hold while the bounded worker stays blocked: only
        # its own ref may still count — the real limiter refuses meanwhile.
        lease.release()
        assert adapter._capacity.work_count() == 1
        second, refusal = acquire_launch_lease(adapter, lease.home_key)
        assert second is None
        _assert_limiter_429(refusal)
    finally:
        bexec.reset_execution(token)
        cb_gate.set()
        deadline = time.monotonic() + 10.0
        while adapter._capacity.work_count() and (
                time.monotonic() < deadline):
            await asyncio.sleep(0.01)
    assert adapter._capacity.work_count() == 0


@pytest.mark.asyncio
async def test_queued_stream_callback_holds_unit(tmp_path, monkeypatch, opened):
    """A queued stream-hook event retains the enqueuing launch's unit until
    the callback actually completes — idle dispatcher threads hold nothing."""
    import agent.b2b_execution as bexec
    import agent.plugin_stream_hooks as psh
    from gateway.platforms.api_server_capacity import acquire_launch_lease

    case = _new_launch(tmp_path, monkeypatch, opened)
    adapter = case.adapter
    adapter._max_concurrent_runs = 1
    lane = case.lane

    lease, refusal = acquire_launch_lease(
        adapter, adapter._capacity.launch_home_key)
    assert refusal is None and lease is not None
    lane.sink._work_lease = lease

    cb_gate = threading.Event()
    cb_entered = threading.Event()

    def _blocking_delta(**_kwargs):
        cb_entered.set()
        cb_gate.wait(timeout=30.0)

    monkeypatch.setattr(
        "hermes_cli.plugins.PluginManager._dispatch_hook_callbacks",
        lambda _self, _name: (_blocking_delta,))
    psh.shutdown_plugin_stream_hook_dispatcher()

    token = bexec.bind_execution(lane.cap)
    try:
        assert psh.enqueue_plugin_stream_hook("on_stream_delta", delta="x")
        assert cb_entered.wait(timeout=10.0)
        # Drop the ROOT hold while the queued callback stays blocked: only
        # the event's own ref may still count — the real limiter refuses.
        lease.release()
        assert adapter._capacity.work_count() == 1
        second, refusal = acquire_launch_lease(adapter, lease.home_key)
        assert second is None
        _assert_limiter_429(refusal)
    finally:
        bexec.reset_execution(token)
        cb_gate.set()
        deadline = time.monotonic() + 10.0
        while adapter._capacity.work_count() and (
                time.monotonic() < deadline):
            await asyncio.sleep(0.01)
        psh.shutdown_plugin_stream_hook_dispatcher()
    assert adapter._capacity.work_count() == 0


@pytest.mark.asyncio
async def test_completed_launch_frees_unit_for_next(
        tmp_path, monkeypatch, opened):
    """max1: a launch whose preparation AND scheduled work fully completed
    frees its unit — a second session on the same home admits with no stale
    preparation occupancy (no separate prep bound exists to leak one)."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli.plugins import discover_plugins

    case_a = _new_launch(tmp_path, monkeypatch, opened)
    case_a.db = case_a.adapter._session_db
    adapter = case_a.adapter
    adapter._max_concurrent_runs = 1
    case_d = _profile_case(
        tmp_path, monkeypatch, opened, adapter, case_a.lane, "hub", "d",
        db=adapter._session_db)

    execution_lane._write_fake_plugin(
        case_a.profile_home, name=_CAPACITY_PLUGIN_NAME,
        init=_CAPACITY_PLUGIN_INIT)
    execution_lane._plugin_config(
        case_a.profile_home, names=(_CAPACITY_PLUGIN_NAME,))
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: 1793361605.0))
    with adapter._profile_scope("hub"):
        discover_plugins()

    PREP_GATE.set()
    PREP_ENTERED.clear()
    del PREP_WORKER_THREADS[:]
    spawned = []
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _spawn_recorder(spawned))

    first = await _launch_profile(case_a, "hub")
    assert first.status == 200, first.body
    # No settling poll: the await returning means the root hold is gone and the
    # recorded spawn completed synchronously — any surviving count is a stale
    # lease bug this test exists to catch.
    assert adapter._capacity.work_count() == 0

    second = await _launch_profile(case_d, "hub")
    assert second.status == 200, second.body
    assert len(spawned) == 2


@pytest.mark.asyncio
async def test_signed_window_expiry_during_preparation_denies_403(
        tmp_path, monkeypatch, opened):
    """The freshness window is re-verified after the LAST awaited operation
    — the bounded preparation worker carrying the final subscriber recheck —
    immediately before the durable commit. An envelope that expires during
    that wait is a 403 source_denied with zero durable mutation, and the
    whole check still fits inside the ONE preparation budget."""
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli.plugins import discover_plugins, get_plugin_manager

    case = _new_launch(tmp_path, monkeypatch, opened)
    case.db = case.adapter._session_db
    adapter = case.adapter

    execution_lane._write_fake_plugin(
        case.profile_home, name=_CAPACITY_PLUGIN_NAME,
        init=_CAPACITY_PLUGIN_INIT)
    execution_lane._plugin_config(
        case.profile_home, names=(_CAPACITY_PLUGIN_NAME,))
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: 1793361605.0))
    with adapter._profile_scope("hub"):
        discover_plugins()
        manager = get_plugin_manager()

    # Envelopes minted against the real clock; the api_server_b2b module gets a
    # private fake clock parked INSIDE the window. The final subscriber recheck
    # — the last awaited operation inside the single preparation worker —
    # advances that clock past the earliest expiry, so the freshness
    # re-verification immediately before the durable commit must deny: no
    # timing guess, no shared-global time mutation.
    case.resolved = execution_lane._launch_resolved(
        case.lane, session_id=case.session_id, expires_in=30)
    observation = dict(case.resolved["observation_genesis"])
    observation["id"], observation["profile"] = case.session_id, "hub"
    case.resolved["observation_genesis"] = observation
    issued_at = max(case.resolved["_signed_request"]["issued_at"],
                    case.resolved["_signed_response"]["issued_at"])
    expires_at = min(case.resolved["_signed_request"]["expires_at"],
                     case.resolved["_signed_response"]["expires_at"])
    clock = [issued_at + 1.0]
    monkeypatch.setattr(
        execution_lane.b2b, "time",
        SimpleNamespace(time=lambda: clock[0], monotonic=time.monotonic,
                        sleep=time.sleep, perf_counter=time.perf_counter))

    subscriber_calls = []
    original_check = manager.has_non_plugin_hook_subscribers

    def _expiring_recheck():
        subscriber_calls.append(1)
        if len(subscriber_calls) == 2:
            clock[0] = expires_at + 1.0
        return original_check()

    monkeypatch.setattr(
        manager, "has_non_plugin_hook_subscribers", _expiring_recheck)

    PREP_GATE.set()
    PREP_ENTERED.clear()
    del PREP_WORKER_THREADS[:]
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _forbidden("_spawn_run"))
    before = admission._store_counts(case.store)
    changes_before = case.store._conn.total_changes

    response = await _launch(case)
    assert response.status == 403
    assert json.loads(response.body)["error"] == "source_denied"
    assert len(subscriber_calls) == 2
    assert admission._store_counts(case.store) == before
    assert case.store._conn.total_changes == changes_before
    _join_prep_workers()


@pytest.mark.asyncio
async def test_lease_to_thread_queued_cancel_frees_ref(
        tmp_path, monkeypatch, opened):
    """Queued cancellation is atomic, not Event-sampled: with the executor's
    single worker parked, cancelling the awaiter frees the lease ref AND the
    queued job never executes its payload."""
    from concurrent.futures import ThreadPoolExecutor
    from gateway.platforms.api_server_capacity import (
        acquire_launch_lease, lease_to_thread)

    case = _new_launch(tmp_path, monkeypatch, opened)
    adapter = case.adapter
    adapter._max_concurrent_runs = 1
    lease, refusal = acquire_launch_lease(
        adapter, adapter._capacity.launch_home_key)
    assert refusal is None and lease is not None

    blocker = threading.Event()
    ran = []
    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(executor)
    try:
        # Occupy the only executor thread so the to_thread job stays queued.
        occupied = loop.run_in_executor(None, blocker.wait)
        await asyncio.sleep(0.05)
        task = asyncio.create_task(
            lease_to_thread(lambda: ran.append(1), work_lease=lease))
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        lease.release()
        assert adapter._capacity.work_count() == 0
        blocker.set()
        await occupied
        await asyncio.sleep(0.05)
        assert ran == []
    finally:
        blocker.set()
        executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_lease_to_thread_running_cancel_holds_ref(
        tmp_path, monkeypatch, opened):
    """A cancellation landing while the worker RUNS frees nothing early: the
    ref rides the worker's real finally."""
    from gateway.platforms.api_server_capacity import (
        acquire_launch_lease, lease_to_thread)

    case = _new_launch(tmp_path, monkeypatch, opened)
    adapter = case.adapter
    adapter._max_concurrent_runs = 1
    lease, refusal = acquire_launch_lease(
        adapter, adapter._capacity.launch_home_key)
    assert refusal is None and lease is not None

    entered = threading.Event()
    gate = threading.Event()

    def _blocked():
        entered.set()
        gate.wait(timeout=30.0)
        return "done"

    task = asyncio.create_task(lease_to_thread(_blocked, work_lease=lease))
    deadline = time.monotonic() + 10.0
    while not entered.is_set() and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    assert entered.is_set()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    # Root released + worker still running: exactly the child ref counts.
    lease.release()
    assert adapter._capacity.work_count() == 1
    gate.set()
    deadline = time.monotonic() + 10.0
    while adapter._capacity.work_count() and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    assert adapter._capacity.work_count() == 0


@pytest.mark.asyncio
async def test_submit_api_worker_queued_cancel_frees_count(
        tmp_path, monkeypatch, opened):
    """``_submit_api_worker``: a future cancelled while the executor job is
    still queued frees the worker-lifetime count and the lease ref — and the
    payload never runs (never a shielded model turn after cancellation)."""
    from concurrent.futures import ThreadPoolExecutor
    from gateway.platforms import api_server_runs
    from gateway.platforms.api_server_capacity import acquire_launch_lease

    case = _new_launch(tmp_path, monkeypatch, opened)
    adapter = case.adapter
    adapter._max_concurrent_runs = 1
    lease, refusal = acquire_launch_lease(
        adapter, adapter._capacity.launch_home_key)
    assert refusal is None and lease is not None

    blocker = threading.Event()
    ran = []
    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(executor)
    baseline = api_server_runs.api_worker_live_count()
    try:
        occupied = loop.run_in_executor(None, blocker.wait)
        await asyncio.sleep(0.05)
        future = api_server_runs._submit_api_worker(
            loop, lambda: ran.append(1), work_lease=lease)
        assert api_server_runs.api_worker_live_count() == baseline + 1
        await asyncio.sleep(0.05)
        future.cancel()
        deadline = time.monotonic() + 10.0
        while api_server_runs.api_worker_live_count() != baseline and (
                time.monotonic() < deadline):
            await asyncio.sleep(0.01)
        assert api_server_runs.api_worker_live_count() == baseline
        lease.release()
        assert adapter._capacity.work_count() == 0
        blocker.set()
        await occupied
        await asyncio.sleep(0.05)
        assert ran == []
    finally:
        blocker.set()
        executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_submit_api_worker_running_cancel_holds_count(
        tmp_path, monkeypatch, opened):
    """``_submit_api_worker``: cancelling a future whose worker already
    started frees neither the count nor the ref until the worker's real
    finally — ``_API_WORKER_LIVE`` semantics unchanged."""
    from gateway.platforms import api_server_runs
    from gateway.platforms.api_server_capacity import acquire_launch_lease

    case = _new_launch(tmp_path, monkeypatch, opened)
    adapter = case.adapter
    adapter._max_concurrent_runs = 1
    lease, refusal = acquire_launch_lease(
        adapter, adapter._capacity.launch_home_key)
    assert refusal is None and lease is not None

    entered = threading.Event()
    gate = threading.Event()

    def _blocked():
        entered.set()
        gate.wait(timeout=30.0)
        return "done"

    loop = asyncio.get_running_loop()
    baseline = api_server_runs.api_worker_live_count()
    future = api_server_runs._submit_api_worker(
        loop, _blocked, work_lease=lease)
    assert entered.wait(timeout=10.0)
    future.cancel()
    # Still counted while the worker runs — a running cancel frees nothing.
    assert api_server_runs.api_worker_live_count() == baseline + 1
    lease.release()
    assert adapter._capacity.work_count() == 1
    gate.set()
    deadline = time.monotonic() + 10.0
    while (api_server_runs.api_worker_live_count() != baseline
           or adapter._capacity.work_count()) and (
            time.monotonic() < deadline):
        await asyncio.sleep(0.01)
    assert api_server_runs.api_worker_live_count() == baseline
    assert adapter._capacity.work_count() == 0
