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
* **Architecture (AST, not text matching).** Every ``api_server_b2b*`` import
  in the generic modules is used ONLY as a direct call; the facade carries no
  ``agent.b2b_execution`` imports, no ``_b2b_state`` reads, no B2B refusal
  strings; ``api_server_runs`` touches the ``b2b_execution`` carrier field
  only at its ``_RunLaunch`` declaration. This is the explicitly requested
  static-structure check — it pins the delegation invariant, not behavior;
  the parametrized tests above prove the behavior.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import agent.b2b_execution as b2b_exec_mod
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
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
# f) Architecture guard (AST contract — explicitly requested; see module doc)
# ---------------------------------------------------------------------------

_REPO = Path(__file__).resolve().parents[2]
_GENERIC_MODULES = tuple(
    _REPO / "gateway" / "platforms" / name for name in (
        "api_server.py", "api_server_runs.py", "api_server_openai_routes.py"))
_RUNS = _GENERIC_MODULES[1]


def _tree(path):
    return ast.parse(path.read_text(encoding="utf-8")), path


def _parents(tree):
    return {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}


def _b2b_names(tree):
    """Imported binding names sourced from api_server_b2b* modules —
    covering both ``from gateway.platforms.api_server_b2b_x import y`` and
    ``from gateway.platforms import api_server_b2b_x [as z]`` forms."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").startswith("gateway.platforms.api_server_b2b"):
                names.update(a.asname or a.name for a in node.names)
            elif node.module == "gateway.platforms":
                names.update(a.asname or a.name for a in node.names
                             if a.name.startswith("api_server_b2b"))
        elif isinstance(node, ast.Import):
            names.update((a.asname or a.name).split(".")[0]
                         for a in node.names if "api_server_b2b" in a.name)
    return names


def _b2b_usages_are_direct_calls(path):
    """Every reference to a b2b import must be Call.func (or Call.func's root
    Attribute) — never a predicate operand, assignment, or attribute walk."""
    tree, _ = _tree(path)
    names = _b2b_names(tree)
    parent = _parents(tree)
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in names:
            p = parent.get(node)
            if isinstance(p, ast.Call) and p.func is node:
                continue  # helper(...)
            if (isinstance(p, ast.Attribute) and p.value is node
                    and isinstance(parent.get(p), ast.Call)
                    and parent[p].func is p):
                continue  # module.helper(...)
            bad.append((node.id, node.lineno))
    return names, bad


def test_generic_modules_only_call_b2b_helpers_never_hold_policy():
    """api_server + api_server_runs + api_server_openai_routes: b2b imports
    exist ONLY as direct calls; no agent.b2b_execution imports, no
    ``_b2b_state`` reads, no B2B-named literals anywhere."""
    for path in _GENERIC_MODULES:
        names, bad = _b2b_usages_are_direct_calls(path)
        assert names, f"{path.name}: no api_server_b2b imports found — delegate missing?"
        assert bad == [], f"{path.name}: b2b import used outside a direct call: {bad}"

        tree, _ = _tree(path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mod = getattr(node, "module", "") or " ".join(a.name for a in node.names)
                assert "agent.b2b_execution" not in mod, \
                    f"{path.name}:{node.lineno} imports agent.b2b_execution directly"
            elif isinstance(node, ast.Attribute) and node.attr == "_b2b_state":
                pytest.fail(f"{path.name}:{node.lineno} reads _b2b_state — state is topical")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and "b2b" in node.value.lower():
                pytest.fail(
                    f"{path.name}:{node.lineno} holds B2B literal {node.value!r} — policy is topical")


def test_runs_module_only_touches_b2b_execution_at_carrier_declaration():
    """The ``b2b_execution`` carrier field may be READ nowhere in generic run
    plumbing except its ``_RunLaunch`` dataclass declaration — execution
    binding/finalization/sink policy belongs to the topical sibling."""
    tree, _ = _tree(_RUNS)
    parent = _parents(tree)
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "b2b_execution":
            bad.append(("attribute", node.lineno))
        elif isinstance(node, ast.Name) and node.id == "b2b_execution":
            # Allowed only as the dataclass field's AnnAssign/keyword target.
            p = parent.get(node)
            ok = isinstance(p, (ast.AnnAssign, ast.keyword))
            if not ok:
                bad.append(("name", node.lineno))
        elif isinstance(node, ast.AsyncFunctionDef) and node.name == "_b2b_finalize":
            bad.append(("def _b2b_finalize", node.lineno))
        elif isinstance(node, ast.FunctionDef) and node.name == "_b2b_finalize":
            bad.append(("def _b2b_finalize", node.lineno))
    assert bad == [], f"api_server_runs holds B2B policy: {bad}"
