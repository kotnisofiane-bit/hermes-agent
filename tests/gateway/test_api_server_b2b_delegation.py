"""B2B facade-delegation contracts (correction 5).

Policy for the B2B lane lives ONLY in ``gateway/platforms/api_server_b2b*.py``
topical siblings; the generic facade (``api_server.py``) and generic run
plumbing (``api_server_runs.py``) hold imports + thin calls, nothing else.

Contracts proven here, as behavior:

* **Ownership order.** ``_request_owns_run`` tests scope + in-memory owner
  FIRST — a legitimate owner is admitted and a foreign ``b2b:`` scope is
  denied with ZERO store I/O (no ``b2b_is_run``, no ``owns_run``), in every
  state mode (absent / disabled / enabled). Unknown owners drop to the B2B
  visibility gate, then the durable ``owns_run`` — both off the event loop.
* **Disabled fast paths.** Disabled lanes return from the construction guard,
  run-resets, construction, finalization and sink-block helpers BEFORE any
  ``current_execution`` / home / sink / store work. Reserved ``b2b_`` ids
  still refuse ``b2b_capability_mismatch`` cheaply — no admitted cap can
  exist on a disabled lane.
* **Carrier isolation.** ``run.b2b_execution`` belongs to the topical
  helpers. A ``_RunLaunch`` whose carrier READ explodes still drives a full
  generic ``_execute_run`` on absent/disabled lanes — the nominal turn AND
  every terminal except branch (``except Exception``, provider-auth,
  ``except asyncio.CancelledError``) plus ``_finish``/``finally``.
* **Facade-state trap.** On a disabled lane, a ``_b2b_state`` whose only
  readable attribute is ``.config.enabled`` — every deeper access raises —
  still lets generic session routes and OpenAI response routes answer
  normally: the ONLY state the generic surface may consume is the delegated
  lane check itself, exactly once per seam call. A fully opaque state cannot
  be the contract: the delegated check legitimately reads
  ``state.config.enabled`` — trapping it too would require a production
  change, which is out of scope (the residual a behavior test cannot see —
  a generic module inlining only that same cheap enabled read — is
  structural, not behavioral, and is explicitly abandoned with the removed
  source-reading guard).
"""

from __future__ import annotations

import asyncio
import inspect
import sqlite3
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import agent.b2b_execution as b2b_exec_mod
from gateway.platforms import api_server_runs as _runs
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from hermes_state import SessionDB
from tests.gateway import b2b_unit_fixtures


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _adapter(extra=None) -> APIServerAdapter:
    return APIServerAdapter(PlatformConfig(enabled=True, extra=extra or {}))


def _enabled_state():
    """Minimal enabled state — only ``state.config.enabled`` is ever consumed."""
    return SimpleNamespace(config=SimpleNamespace(enabled=True), keys={})


def _disabled_state():
    return SimpleNamespace(config=SimpleNamespace(enabled=False), keys={})


def _request():
    req = MagicMock()
    req.headers = {}
    return req


async def _owns(adapter, request, run_id):
    """Sync-old + async-new compatible ownership probe."""
    result = adapter._request_owns_run(request, run_id)
    if inspect.isawaitable(result):
        result = await result
    return result


class _Recorder:
    """Wrap a callable: count calls, record the calling thread, optionally blow up."""

    def __init__(self, fn=None, exc=None):
        self.calls = []
        self.threads = []
        self._fn = fn
        self._exc = exc

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        self.threads.append(threading.get_ident())
        if self._exc is not None:
            raise self._exc
        if self._fn is not None:
            return self._fn(*args, **kwargs)
        return None


def _install_store(adapter, tmp_path):
    """Swap in a tmp-path store without leaking the adapter's original one."""
    original = getattr(adapter, "_run_idempotency_store", None)
    if original is not None:
        original.close()
    store = RunIdempotencyStore(str(tmp_path / "runs.db"))
    adapter._run_idempotency_store = store
    return store


class _CapTrap:
    """Run double whose ``b2b_execution`` read explodes — proves the helpers
    check state BEFORE touching the carrier on a disabled/absent lane."""

    run_id = "run_t"

    @property
    def b2b_execution(self):
        raise AssertionError("b2b_execution inspected before the state check")


# ---------------------------------------------------------------------------
# a) Ownership: in-memory owner answers FIRST — zero store access, all modes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["absent", "disabled", "enabled"])
async def test_memory_owner_decides_with_zero_store_io(tmp_path, mode):
    """Legitimate owner True / foreign scope False — with ``b2b_is_run`` AND
    ``owns_run`` both turned into tripwires so any store consult explodes."""
    adapter = _adapter({"b2b": {"enabled": False, "profiles": {}}} if mode == "disabled" else {})
    if mode == "absent":
        adapter._b2b_state = None
    elif mode == "enabled":
        adapter._b2b_state = _enabled_state()
    store = _install_store(adapter, tmp_path)
    try:
        store.b2b_is_run = _Recorder(exc=AssertionError("b2b_is_run consulted for a known owner"))
        store.owns_run = _Recorder(exc=AssertionError("owns_run consulted for a known owner"))

        req = _request()
        scope = adapter._run_idempotency_scope(req)
        adapter._run_owners["run_legit"] = scope
        adapter._run_owners["run_foreign"] = "b2b:" + "f" * 64

        assert await _owns(adapter, req, "run_legit") is True
        assert await _owns(adapter, req, "run_foreign") is False
        assert store.b2b_is_run.calls == []
        assert store.owns_run.calls == []
    finally:
        store.close()


# ---------------------------------------------------------------------------
# b) Unknown owner: durable path, off-loop I/O, per-state gating
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["absent", "disabled"])
async def test_unknown_owner_disabled_lane_never_touches_b2b_lookup(tmp_path, mode):
    """Ownerless run: ``b2b_is_run`` must NEVER be consulted when the lane is
    absent/disabled; the durable ``owns_run`` fallback keeps its native scope
    contract — matching scope admitted, foreign scope denied — off-loop."""
    adapter = _adapter({"b2b": {"enabled": False, "profiles": {}}} if mode == "disabled" else {})
    if mode == "absent":
        adapter._b2b_state = None
    store = _install_store(adapter, tmp_path)
    try:
        req = _request()
        scope = adapter._run_idempotency_scope(req)
        # Real durable reservation under the caller's scope.
        store.reserve(scope, "idem-key-1", "fp", "run_durable",
                      {"status": "completed"}, retention_until=0)

        b2b_spy = _Recorder(exc=AssertionError("b2b_is_run ran on a disabled lane"))
        owns_spy = _Recorder(fn=store.owns_run)
        store.b2b_is_run = b2b_spy
        store.owns_run = owns_spy
        loop_tid = threading.get_ident()

        assert await _owns(adapter, req, "run_durable") is True
        assert await _owns(adapter, req, "run_never_reserved") is False
        assert b2b_spy.calls == []
        assert len(owns_spy.calls) == 2
        # SQLite must not be hit synchronously on the event loop.
        assert owns_spy.threads and all(t != loop_tid for t in owns_spy.threads)
    finally:
        store.close()


@pytest.mark.asyncio
async def test_unknown_owner_enabled_lane_b2b_row_is_hidden(tmp_path):
    """Enabled lane, ownerless run_id that IS a durable B2B attempt: invisible
    on generic surfaces — ``b2b_is_run`` True -> denied before ``owns_run``."""
    lane = b2b_unit_fixtures.build_b2b_dispatch_lane(tmp_path)
    try:
        adapter = _adapter()
        adapter._b2b_state = lane.adapter._b2b_state
        adapter._run_idempotency_store.close()  # drop the unused original
        adapter._run_idempotency_store = lane.store
        req = _request()

        owns_spy = _Recorder(fn=lane.store.owns_run)
        lane.store.owns_run = owns_spy

        assert await _owns(adapter, req, lane.run_id) is False
        assert owns_spy.calls == []  # b2b gate answered first
    finally:
        lane.store.close()


@pytest.mark.asyncio
async def test_unknown_owner_enabled_lane_store_error_fails_closed(tmp_path):
    """Enabled lane: a ``b2b_is_run`` failure denies the ownerless run —
    an unanswered B2B question is never an allow."""
    adapter = _adapter()
    adapter._b2b_state = _enabled_state()
    store = _install_store(adapter, tmp_path)
    try:
        req = _request()
        scope = adapter._run_idempotency_scope(req)
        store.reserve(scope, "idem-key-2", "fp", "run_durable",
                      {"status": "completed"}, retention_until=0)

        boom = _Recorder(exc=sqlite3.OperationalError("database is locked"))
        owns_spy = _Recorder(fn=store.owns_run)
        store.b2b_is_run = boom
        store.owns_run = owns_spy

        assert await _owns(adapter, req, "run_durable") is False
        assert len(boom.calls) == 1
        assert owns_spy.calls == []  # fail-closed before the native fallback
    finally:
        store.close()


@pytest.mark.asyncio
async def test_unknown_owner_enabled_lane_ordinary_durable_run_admitted(tmp_path):
    """Enabled lane: an ordinary ownerless durable run (b2b_is_run False)
    still resolves through the native owns_run scope check — off-loop."""
    adapter = _adapter()
    adapter._b2b_state = _enabled_state()
    store = _install_store(adapter, tmp_path)
    try:
        req = _request()
        scope = adapter._run_idempotency_scope(req)
        store.reserve(scope, "idem-key-3", "fp", "run_durable",
                      {"status": "completed"}, retention_until=0)

        b2b_spy = _Recorder(fn=store.b2b_is_run)
        owns_spy = _Recorder(fn=store.owns_run)
        store.b2b_is_run = b2b_spy
        store.owns_run = owns_spy
        loop_tid = threading.get_ident()

        assert await _owns(adapter, req, "run_durable") is True
        assert await _owns(adapter, req, "run_other") is False
        assert len(b2b_spy.calls) == 2
        assert len(owns_spy.calls) == 2
        assert all(t != loop_tid for t in b2b_spy.threads + owns_spy.threads)
    finally:
        store.close()


# ---------------------------------------------------------------------------
# c) Real aiohttp: memory-known run stays reachable on a broken B2B lookup
# ---------------------------------------------------------------------------

def _runs_app(adapter) -> web.Application:
    app = web.Application()
    app["api_server_adapter"] = adapter
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    app.router.add_get("/v1/runs/{run_id}/events", adapter._handle_run_events)
    app.router.add_post("/v1/runs/{run_id}/stop", adapter._handle_stop_run)
    return app


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["absent", "disabled", "enabled"])
async def test_memory_owned_run_routes_reachable_on_store_b2b_error(tmp_path, mode):
    """The memory-known run answers GET/events/stop even while the store's
    ``b2b_is_run`` is on fire — ownership never reaches for it."""
    adapter = _adapter({"b2b": {"enabled": False, "profiles": {}}} if mode == "disabled" else {})
    if mode == "absent":
        adapter._b2b_state = None
    elif mode == "enabled":
        adapter._b2b_state = _enabled_state()
    store = _install_store(adapter, tmp_path)
    try:
        store.b2b_is_run = _Recorder(exc=sqlite3.OperationalError("no such table: b2b_attempts"))
        req = _request()
        adapter._run_owners["run_live"] = adapter._run_idempotency_scope(req)
        adapter._run_statuses["run_live"] = {
            "object": "hermes.run", "run_id": "run_live",
            "status": "running", "updated_at": 1}
        adapter._run_streams["run_live"] = asyncio.Queue()

        async with TestClient(TestServer(_runs_app(adapter))) as cli:
            got = await cli.get("/v1/runs/run_live")
            assert got.status == 200, await got.text()

            ev = await cli.get("/v1/runs/run_live/events")
            assert ev.status == 200
            ev.release()

            stop = await cli.post("/v1/runs/run_live/stop")
            # No live agent/task -> 409 run_not_active: reached the handler,
            # i.e. ownership PASSED. A 404 would mean the B2B gate ate it.
            assert stop.status == 409, await stop.text()
            assert (await stop.json())["error"]["code"] == "run_not_active"

        assert store.b2b_is_run.calls == []
    finally:
        store.close()


# ---------------------------------------------------------------------------
# d) Construction guard: disabled lane does zero B2B work, native path builds
# ---------------------------------------------------------------------------

def _construction_tripwires(monkeypatch):
    """Tripwire every B2B-side seam the guard must not touch on a disabled
    ordinary path; returns the recorder for assertions."""
    rec = _Recorder(exc=AssertionError("B2B execution context touched on disabled lane"))
    monkeypatch.setattr(b2b_exec_mod, "current_execution", rec)
    monkeypatch.setattr("hermes_constants.get_hermes_home",
                        _Recorder(exc=AssertionError("home resolution on disabled lane")),
                        raising=False)
    return rec


def _native_agent_stubs(monkeypatch):
    """Stub the ordinary construction chain so a disabled lane can build the
    native sentinel agent without provider/config I/O."""
    import gateway.run as gw_run

    monkeypatch.setattr(gw_run, "_resolve_runtime_agent_kwargs",
                        lambda: {"model": "unit-model"}, raising=False)
    monkeypatch.setattr(gw_run, "_resolve_gateway_model", lambda: "unit-model", raising=False)
    monkeypatch.setattr(gw_run, "_load_gateway_config", lambda: {}, raising=False)
    monkeypatch.setattr(gw_run, "_checkpoint_agent_kwargs", lambda cfg: {}, raising=False)
    monkeypatch.setattr(gw_run, "_current_max_iterations", lambda: 1, raising=False)
    monkeypatch.setattr(gw_run.GatewayRunner, "_load_reasoning_config", staticmethod(lambda m: {}), raising=False)
    monkeypatch.setattr(gw_run.GatewayRunner, "_load_fallback_model", staticmethod(lambda: None), raising=False)
    monkeypatch.setattr("hermes_cli.tools_config._get_platform_tools",
                        lambda cfg, p: [], raising=False)
    monkeypatch.setattr("gateway.platforms.api_server.resolve_display_setting",
                        lambda *a, **k: True, raising=False)
    monkeypatch.setattr("run_agent.AIAgent",
                        lambda **kw: SimpleNamespace(_sentinel=True, kwargs=kw),
                        raising=False)


def _bare_adapter(state):
    """Adapter double carrying only the seams _create_agent reaches after the
    guard on a disabled ordinary lane."""
    return SimpleNamespace(
        _b2b_state=state,
        _ensure_session_db=lambda: None,
        _memory_sessions=SimpleNamespace(checkout=lambda sid: None),
        _select_agent_runtime=lambda *a, **k: ("unit-model", None, None, None),
        _last_resolved_model={}, _model_name="unit-model")


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["absent", "disabled"])
async def test_create_agent_disabled_ordinary_builds_native_with_zero_b2b_work(
        tmp_path, mode, monkeypatch):
    """Disabled lane + ordinary id: the guard must return BEFORE
    current_execution/home/sink work, and construction proceeds through the
    exact native path — proven by the sentinel agent actually materializing."""
    # Stubs first: importing gateway.run pulls modules that legitimately read
    # get_hermes_home at IMPORT time — the tripwire arms only after that, so it
    # measures what _create_agent itself touches.
    _native_agent_stubs(monkeypatch)
    rec = _construction_tripwires(monkeypatch)
    adapter = _bare_adapter(None if mode == "absent" else _disabled_state())

    agent = APIServerAdapter._create_agent(adapter, session_id="api_ordinary_1")
    assert getattr(agent, "_sentinel", False) is True
    assert rec.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["absent", "disabled"])
async def test_create_agent_disabled_reserved_still_refuses_capability_mismatch(
        tmp_path, mode, monkeypatch):
    """Cheap namespace safety stays: a reserved ``b2b_`` id refuses
    ``b2b_capability_mismatch`` on a disabled lane too — and still without
    execution-context / home / sink work."""
    from agent.b2b_execution import B2BTerminalRefusal

    rec = _construction_tripwires(monkeypatch)
    adapter = _bare_adapter(None if mode == "absent" else _disabled_state())

    with pytest.raises(B2BTerminalRefusal) as exc:
        APIServerAdapter._create_agent(adapter, session_id="b2b_" + "e" * 64)
    assert str(exc.value) == "b2b_capability_mismatch"
    assert rec.calls == []


# ---------------------------------------------------------------------------
# e) Run helpers: disabled fast paths never touch cap/sink/execution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["absent", "disabled"])
async def test_run_execution_resets_disabled_is_empty(mode, monkeypatch):
    """Disabled/absent state -> [] with no cap inspection and no bind."""
    from gateway.platforms import api_server_b2b_execution as bxe

    adapter = SimpleNamespace(
        _b2b_state=None if mode == "absent" else _disabled_state())
    bind = _Recorder(exc=AssertionError("bind_execution ran disabled"))
    monkeypatch.setattr("agent.b2b_execution.bind_execution", bind, raising=False)

    assert bxe.run_execution_resets(adapter, _CapTrap()) == []
    assert bind.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["absent", "disabled"])
async def test_construct_run_agent_disabled_calls_native_direct(mode):
    """Disabled construction executes ``construct_agent`` exactly native —
    direct call, no cap inspection, no executor hop."""
    from gateway.platforms import api_server_b2b_execution as bxe

    adapter = SimpleNamespace(
        _b2b_state=None if mode == "absent" else _disabled_state())
    native = _Recorder(fn=lambda: "NATIVE_AGENT")
    loop = MagicMock()
    loop.run_in_executor = _Recorder(exc=AssertionError("executor used disabled"))

    agent = await bxe.construct_run_agent(adapter, _CapTrap(), native, loop)
    assert agent == "NATIVE_AGENT"
    assert len(native.calls) == 1
    assert loop.run_in_executor.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["absent", "disabled"])
async def test_finalize_and_block_helpers_disabled_are_noops(mode):
    """Disabled lanes: finalize -> None, all three sink-block helpers -> no
    cap/sink contact at all (state is checked BEFORE the carrier is read)."""
    from gateway.platforms import api_server_b2b_execution as bxe

    adapter = SimpleNamespace(
        _b2b_state=None if mode == "absent" else _disabled_state())
    run = _CapTrap()

    assert await bxe.finalize_run(adapter, run, {"final_response": "x"}, "completed", {}) is None
    bxe.block_interrupted_run(adapter, run)
    bxe.block_provider_unavailable_run(adapter, run)
    bxe.block_failed_run(adapter, run, RuntimeError("x"))


# ---------------------------------------------------------------------------
# f) Carrier isolation: generic run plumbing never reads run.b2b_execution
# ---------------------------------------------------------------------------

class _CarrierTrapRun(_runs._RunLaunch):
    """``_RunLaunch`` whose ``b2b_execution`` READ explodes.

    The dataclass ``__init__`` still assigns the field through the setter —
    only READS are trapped. Generic plumbing must leave the carrier to the
    topical helpers, which consult it only after their own enabled-lane
    check (the ``_CapTrap`` cases above).
    """

    @property
    def b2b_execution(self):
        raise AssertionError("generic run plumbing read run.b2b_execution")

    @b2b_execution.setter
    def b2b_execution(self, _value):
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["absent", "disabled"])
@pytest.mark.parametrize("outcome", ["completed", "failed", "auth_failed", "cancelled"])
async def test_execute_run_generic_path_never_reads_b2b_carrier(
        tmp_path, mode, outcome, monkeypatch):
    """A full generic ``_execute_run`` — construction, executor turn, the
    terminal ``except`` branches, ``_finish``/``finally`` — runs NATIVE on an
    absent/disabled lane even though reading the carrier explodes.

    Branches exercised via the agent double: nominal ``completed`` turn;
    ``except Exception`` (``block_failed_run`` → ``failed`` + redacted
    message); ``except _ProviderAuthResolutionError`` (``block_provider_
    unavailable_run`` → ``failed`` + ``user_text``); ``except
    asyncio.CancelledError`` (``block_interrupted_run`` → ``cancelled`` then
    re-raise). ``construct_run_agent``/``run_execution_resets``/
    ``finalize_run``/``block_*`` consult the carrier only after their state
    check — a read in any traversed branch lands in the generic ``except``
    (or propagates the cancellation) instead of the asserted terminal
    state."""
    import gateway.platforms.api_server as _api_server

    adapter = _adapter({"b2b": {"enabled": False, "profiles": {}}} if mode == "disabled" else {})
    if mode == "absent":
        adapter._b2b_state = None
    store = _install_store(adapter, tmp_path)
    try:
        queue = asyncio.Queue()
        run_id = "run_trap"
        adapter._run_streams[run_id] = queue

        turn = {
            "completed": _Recorder(fn=lambda **kw: {"final_response": "ok"}),
            "failed": _Recorder(exc=RuntimeError("boom-run")),
            "auth_failed": _Recorder(
                exc=_api_server._ProviderAuthResolutionError("no key")),
            "cancelled": _Recorder(exc=asyncio.CancelledError()),
        }[outcome]
        agent = SimpleNamespace(session_id=None, run_conversation=turn)
        monkeypatch.setattr(adapter, "_create_agent", lambda **kw: agent)

        launch = _CarrierTrapRun(
            adapter, run_id, queue, None, None, False, "mission", [], False,
            dict(ephemeral_system_prompt=None, session_id=None,
                 gateway_session_key=None, route=None, room_dispatch=None,
                 room_execution_policy=None, requested_model=None,
                 requested_provider=None, model_options=None,
                 confirmed_runtime_lock=True),
            request_profile=None, browser_control_principal=None,
            browser_control_transport_family=None, turn_author=None,
            b2b_execution=None)

        if outcome == "cancelled":
            with pytest.raises(asyncio.CancelledError):
                await _runs._execute_run(adapter, launch, _api_server=_api_server)
        else:
            await _runs._execute_run(adapter, launch, _api_server=_api_server)

        record = adapter._run_statuses[run_id]
        if outcome == "completed":
            # A carrier read lands in the generic except → "failed";
            # "completed" proves the whole nominal path stayed native.
            assert record["status"] == "completed"
            assert len(agent.run_conversation.calls) == 1
        elif outcome == "cancelled":
            assert record["status"] == "cancelled"
        else:
            # A carrier read inside the block_* helper would explode the
            # except branch itself — reaching "failed" with the right error
            # proves the helpers checked state before the carrier.
            assert record["status"] == "failed"
            expected = ("boom-run" if outcome == "failed"
                        else "Provider authentication failed")
            assert expected in record["error"], record

        events = []
        while not queue.empty():
            events.append(queue.get_nowait())
        assert any(e and e.get("event") == f"run.{record['status']}" for e in events), events
        assert events[-1] is None
    finally:
        store.close()


# ---------------------------------------------------------------------------
# g) Facade-state trap: generic + OpenAI surfaces read ONLY the lane check
# ---------------------------------------------------------------------------

_SURFACE_KEY = "k" * 32
_SURFACE_AUTH = {"Authorization": f"Bearer {_SURFACE_KEY}"}


class _TrappedB2BConfig:
    """Disabled B2B config double: ``enabled`` is the ONLY readable attribute.

    The delegated lane check legitimately consumes ``config.enabled`` — every
    deeper attribute a real B2B policy would need (``profiles``,
    ``profile_entry``, keyrings) explodes on contact. Reads are counted so the
    test can relate them to the delegated seam calls that performed them.
    """

    def __init__(self):
        self.enabled_reads = 0

    @property
    def enabled(self):
        self.enabled_reads += 1
        return False

    def __getattr__(self, name):
        raise AssertionError(
            f"disabled-lane B2B config attribute {name!r} read — "
            "the delegated lane check needs .enabled only")


class _TrappedB2BState:
    """``_b2b_state`` double whose ONLY readable attribute is ``config``.

    This is the «piégé» contract as deep as production permits: a state that
    raised on EVERY attribute read cannot coexist with delegation, because
    the topical siblings' disabled-lane check itself reads
    ``state.config.enabled``. Everything the lane check does not need raises
    instead — so any B2B-state work on a generic surface explodes, and any
    state read the delegated seams did not perform shows in the read counts.
    """

    def __init__(self):
        self._config = _TrappedB2BConfig()
        self.config_reads = 0

    @property
    def config(self):
        self.config_reads += 1
        return self._config

    def __getattr__(self, name):
        raise AssertionError(
            f"disabled-lane _b2b_state attribute {name!r} read — "
            "only .config.enabled is delegated-check surface")


# Seams whose own body performs the ``state.config.enabled`` lane check —
# exactly one read per call today. Only these may read B2B state on the
# generic surfaces below; callers-in-the-middle delegate into them.
_LANE_CHECK_SEAMS = {
    "gateway.platforms.api_server_b2b_sessions": (
        "resolve_generic_session_id", "list_generic_sessions"),
    "gateway.platforms.api_server_b2b_execution": (
        "guard_agent_construction", "construct_run_agent",
        "run_execution_resets", "finalize_run", "generic_run_visible",
        "_cap_or_none"),
}


def _lane_check_calls(monkeypatch) -> list:
    """Record every invocation of the lane-check seams (module-global lookups
    and lazy imports both land on the patched attribute)."""
    import importlib
    calls = []
    for mod_name, names in _LANE_CHECK_SEAMS.items():
        mod = importlib.import_module(mod_name)
        for name in names:
            original = getattr(mod, name)

            def _spied(*args, _original=original, _name=name, **kwargs):
                calls.append(_name)
                return _original(*args, **kwargs)

            monkeypatch.setattr(mod, name, _spied)
    return calls


def _surface_app(adapter: APIServerAdapter) -> web.Application:
    """The full native route table — same shape ``connect()`` registers."""
    app = web.Application(
        middlewares=[adapter._make_profile_prefix_middleware()])
    app["api_server_adapter"] = adapter
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
    return app


@pytest.mark.asyncio
async def test_generic_and_openai_surfaces_consume_only_the_lane_check(
        tmp_path, monkeypatch):
    """Disabled lane + ``_b2b_state`` trapped beyond ``.config.enabled``:
    generic session routes and OpenAI response routes answer NORMALLY —
    proving the generic surface performs zero B2B-state work past the
    delegated lane check.

    Two assertions make the contract discriminating, not a smoke test:

    * Every trapped attribute (profiles, keyrings, ``profile_entry``, any
      other state/config member) raises — a generic surface doing real B2B
      work fails its request outright.
    * ``config_reads``/``enabled_reads`` must equal the lane-check seam call
      count: each delegated seam performs exactly one enabled read today, so
      a state read NO seam made — e.g. a facade inlining its own
      ``self._b2b_state.config.enabled`` — breaks the equality.

    Residual NOT covered (documented, not silently omitted): a generic
    module inlining only that same cheap enabled read is indistinguishable
    from the seam's own read *behaviorally* — no request-level contract can
    see WHERE a read happens, which is why the source-reading AST guard was
    the only tool for it and why its removal leaves that residual (follow-up:
    a dedicated architecture lint outside ``tests/``).
    """
    adapter = _adapter({"key": _SURFACE_KEY,
                        "b2b": {"enabled": False, "profiles": {}}})
    state = _TrappedB2BState()
    adapter._b2b_state = state
    adapter.gateway_runner = SimpleNamespace(
        config=SimpleNamespace(multiplex_profiles=False))
    db = SessionDB(tmp_path / "state.db")
    adapter._session_db = db
    monkeypatch.setattr(adapter, "_run_agent", AsyncMock(return_value=(
        {"final_response": "ok", "completed": True},
        {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})))

    db.create_session("api_surface_1", "api_server")
    db.create_session("api_surface_del", "api_server")
    db.append_message("api_surface_1", "user", content="seeded question")
    resp_id = "resp_" + "a" * 28
    adapter._current_response_store().put(resp_id, {
        "response": {"id": resp_id, "object": "response", "status": "completed"},
        "conversation_history": [{"role": "user", "content": "q"}],
        "session_id": "api_surface_1"})

    calls = _lane_check_calls(monkeypatch)
    try:
        async with TestClient(TestServer(_surface_app(adapter))) as client:
            cases = [
                # Generic session surfaces — each must answer normally.
                ("GET", "/api/sessions", {}, 200),
                ("GET", "/api/sessions/api_surface_1", {}, 200),
                ("GET", "/api/sessions/api_surface_1/messages", {}, 200),
                ("PATCH", "/api/sessions/api_surface_1",
                 {"json": {"title": "renamed"}}, 200),
                ("POST", "/api/sessions",
                 {"json": {"id": "api_created_1"}}, 201),
                ("POST", "/api/sessions/api_surface_1/fork",
                 {"json": {"id": "api_forked_1"}}, 201),
                ("DELETE", "/api/sessions/api_surface_del", {}, 200),
                # OpenAI response surfaces — same normal answers.
                ("POST", "/v1/chat/completions",
                 {"json": {"messages": [{"role": "user", "content": "hi"}]},
                  "headers": {"X-Hermes-Session-Id": "api_surface_1"}}, 200),
                ("POST", "/v1/chat/completions",
                 {"json": {"messages": [{"role": "user", "content": "hi"}]}}, 200),
                ("POST", "/v1/responses", {"json": {"input": "hi"}}, 200),
                ("POST", "/v1/responses",
                 {"json": {"input": "hi", "previous_response_id": resp_id}}, 200),
                ("GET", f"/v1/responses/{resp_id}", {}, 200),
                ("DELETE", f"/v1/responses/{resp_id}", {}, 200),
            ]
            for method, path, kwargs, expected in cases:
                headers = {**_SURFACE_AUTH, **kwargs.pop("headers", {})}
                resp = await client.request(method, path, headers=headers, **kwargs)
                assert resp.status == expected, (
                    method, path, resp.status, await resp.text())
    finally:
        db.close()
        adapter._run_idempotency_store.close()
        adapter._response_store.close()

    # Both session-seam families were actually exercised — the relation below
    # is not vacuously true on an empty call set.
    assert {"resolve_generic_session_id", "list_generic_sessions"} <= set(calls)
    # Every B2B-state read is accounted for by a delegated lane check: one
    # ``.config.enabled`` per seam call, nothing else, nothing more.
    assert state.config_reads == len(calls), (state.config_reads, calls)
    assert state._config.enabled_reads == len(calls), (
        state._config.enabled_reads, calls)
