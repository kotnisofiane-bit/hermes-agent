"""B2B lineage protection on generic session surfaces -- the one central seam.

KOT-263 H1, third review pass. Contracts under test:

* Disabled/absent ``b2b`` == the untouched base: every generic session surface
  answers an ordinary session of ANY ancestry depth (a 65-segment chain) with
  ZERO lineage work -- the only ``get_session``/``resolve_resume_session_id``
  traffic is what each route natively needed before the B2B lane existed.
  Reserved ``b2b_`` prefix denials still apply.
* Enabled: ``api_server_b2b_sessions.resolve_generic_session_id`` is the SINGLE
  resolution/validation point -- an ordinary-named DESCENDANT of a reserved
  root, a compression tip resolving into the namespace, and a raw reserved
  alias all refuse 404 BEFORE history load, agent spawn, or any run-keyed
  state. Both the requested id's chain AND the resolved tip's chain are
  walked, unbounded, with a per-call cache.
* The walk is fail-closed only on the enabled lane: cycles and DB lookup
  errors refuse; a missing ordinary ancestor stops the walk (ordinary); a
  finite ordinary chain of any depth is admitted. Disabled keeps the native
  fail-open resolver.
* A refused ``/v1/runs`` request leaves owner/status/stream/task/idempotency
  state untouched -- the seam runs BEFORE any run-keyed registration.

Real on-disk ``SessionDB`` + real ``APIServerAdapter`` behind a local aiohttp
``TestServer``; only the agent turn is doubled at the seam.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms import api_server_b2b_sessions as b2b_sessions
from gateway.platforms.api_server import APIServerAdapter
from hermes_state import SessionDB
from tests.gateway.b2b_process_harness import make_keypair

_API_KEY = "k" * 32
_AUTH = {"Authorization": f"Bearer {_API_KEY}"}
_RESERVED = "b2b_" + "e" * 64


@pytest.fixture
def opened():
    """Close every SessionDB/RunIdempotencyStore/ResponseStore registered."""
    resources = []
    yield resources
    for resource in resources:
        try:
            resource.close()
        except Exception:
            pass


def _seed(db: SessionDB, session_id: str, *, parent: str = None,
          source: str = "api_server", started_at: float = None,
          session_key: str = None) -> str:
    db.create_session(session_id, source, parent_session_id=parent)
    if started_at is not None:
        db._write_sql(
            "UPDATE sessions SET started_at = ?, last_activity_at = ? WHERE id = ?",
            (started_at, started_at, session_id))
    if session_key is not None:
        db._write_sql("UPDATE sessions SET session_key = ? WHERE id = ?",
                      (session_key, session_id))
    return session_id


def _ordinary_chain(db: SessionDB, prefix: str, ancestors: int, *,
                    root_parent: str = None) -> str:
    """``<prefix>_0`` with ``ancestors`` ordinary parents above it (the topmost
    hanging on ``root_parent`` -- a reserved id for protected chains)."""
    ids = [f"{prefix}_{i}" for i in range(ancestors + 1)]
    _seed(db, ids[-1], parent=root_parent)
    for i in range(ancestors - 1, -1, -1):
        _seed(db, ids[i], parent=ids[i + 1])
    return ids[0]


def _parent_cycle(db: SessionDB, id_a: str, id_b: str) -> None:
    """``id_a`` <-> ``id_b`` parent cycle -- both rows must exist before either
    can name the other as parent (sessions.parent_session_id is a real FK)."""
    _seed(db, id_a)
    _seed(db, id_b)
    db._write_sql("UPDATE sessions SET parent_session_id = ? WHERE id = ?", (id_b, id_a))
    db._write_sql("UPDATE sessions SET parent_session_id = ? WHERE id = ?", (id_a, id_b))


def _adapter(tmp_path, extra: dict) -> APIServerAdapter:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra=extra))
    adapter.gateway_runner = SimpleNamespace(
        config=SimpleNamespace(multiplex_profiles=False))
    adapter._session_db = SessionDB(tmp_path / "state.db")
    return adapter


def _disabled_adapter(tmp_path, mode: str) -> APIServerAdapter:
    """``absent`` == no _b2b_state at all; ``disabled`` == b2b.enabled false."""
    extra = {"key": _API_KEY}
    if mode == "disabled":
        extra["b2b"] = {"enabled": False, "profiles": {}}
    adapter = _adapter(tmp_path, extra)
    if mode == "absent":
        adapter._b2b_state = None
    return adapter


def _enabled_adapter(tmp_path) -> APIServerAdapter:
    _, _, portal_pub = make_keypair()
    _, hermes_priv, _ = make_keypair()
    entry = {
        "source_url": "http://127.0.0.1:1/internal/dubsar/b2b/source",
        "portal_issuer": "portal-h1", "hermes_issuer": "hermes-h1-hub",
        "portal_public_key_pem": portal_pub, "hermes_private_key_pem": hermes_priv,
        "projects": {"b2b-bench": {
            "project_id": "b2b-bench", "bot_id": "bot", "profile_id": "hub",
            "allowed_namespaces": ["ns"], "context_contract_root": None,
            "model": "unit-double", "provider": "custom",
            "base_url": "http://127.0.0.1:9/v1", "api_mode": "chat_completions",
            "logical_mission": None, "project_context": None}}}
    return _adapter(tmp_path, {
        "key": _API_KEY, "b2b": {"enabled": True, "profiles": {"hub": entry}}})


def _app(adapter: APIServerAdapter) -> web.Application:
    """The full native route table -- same shape ``connect()`` registers."""
    app = web.Application(
        middlewares=[adapter._make_profile_prefix_middleware()])
    app["api_server_adapter"] = adapter
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
    return app


class _DBSpy:
    """Counting wrappers over the SessionDB reads each route could issue."""

    _NAMES = ("get_session", "resolve_resume_session_id", "get_messages",
              "get_messages_as_conversation")

    def __init__(self, db: SessionDB):
        self._db = db
        self.counts = {}
        self._orig = {}

    def __enter__(self):
        for name in self._NAMES:
            orig = getattr(self._db, name)
            self._orig[name] = orig
            self.counts[name] = 0

            def _make(orig=orig, name=name):
                def _spy(*args, **kwargs):
                    self.counts[name] += 1
                    return orig(*args, **kwargs)
                return _spy

            setattr(self._db, name, _make())
        return self

    def __exit__(self, *exc):
        for name, orig in self._orig.items():
            setattr(self._db, name, orig)

    def __getitem__(self, name):
        return self.counts.get(name, 0)


def _install_lineage_spy(monkeypatch):
    """Count calls to the shared ancestry predicate; a no-op list when the
    seam does not exist yet (pre-fix production) -- the refusal/count
    assertions carry the RED signal there."""
    calls = []
    orig = getattr(b2b_sessions, "_protected_lineage", None)
    if orig is None:
        return calls

    def _spy(db, sid, cache):
        calls.append(str(sid))
        return orig(db, sid, cache)

    monkeypatch.setattr(b2b_sessions, "_protected_lineage", _spy)
    return calls


def _run_agent_double():
    return AsyncMock(return_value=(
        {"final_response": "ok", "completed": True},
        {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}))


def _tripwire(name):
    def _raise(*args, **kwargs):
        raise AssertionError(f"{name} must not run for a refused request")
    return _raise


# ---------------------------------------------------------------------------
# A. Disabled / absent == base: deep ordinary chain, zero lineage work
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("b2b_state", ["absent", "disabled"])
async def test_disabled_deep_chain_answers_without_lineage_work(
        tmp_path, monkeypatch, opened, b2b_state):
    """65-segment ordinary chain under disabled/absent B2B: metadata GET,
    messages and chat all succeed; the ONLY session reads are each route's
    native baseline (existence get_session, the messages-tip resolver) -- no
    ancestor walk, no extra resolver or DB traffic."""
    adapter = _disabled_adapter(tmp_path, b2b_state)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    leaf = _ordinary_chain(db, "deep", 64)  # EXACTLY 65 chain segments
    assert len(db._read_all("SELECT id FROM sessions")) == 65
    db.append_message(leaf, "user", content="seeded question")
    db.append_message(leaf, "assistant", content="seeded answer")
    lineage_calls = _install_lineage_spy(monkeypatch)
    run_agent = _run_agent_double()
    monkeypatch.setattr(adapter, "_run_agent", run_agent)

    # What each native op itself contributes, measured on this same DB --
    # the HTTP counts assert against the required native traffic, not a
    # magic number for whatever SessionDB internals add.
    with _DBSpy(db) as spy:
        db.resolve_resume_session_id(leaf)
        native_resolve = dict(spy.counts)
    with _DBSpy(db) as spy:
        db.get_messages(leaf, limit=500, offset=0, latest=True)
        native_msgs = dict(spy.counts)
    with _DBSpy(db) as spy:
        db.get_messages_as_conversation(leaf)
        native_conv = dict(spy.counts)

    counts, messages_data = {}, None
    async with TestClient(TestServer(_app(adapter))) as client:
        with _DBSpy(db) as spy:
            resp = await client.get(f"/api/sessions/{leaf}", headers=_AUTH)
            assert resp.status == 200, await resp.text()
            counts["get"] = dict(spy.counts)
        with _DBSpy(db) as spy:
            resp = await client.get(
                f"/api/sessions/{leaf}/messages", headers=_AUTH)
            assert resp.status == 200, await resp.text()
            messages_data = await resp.json()
            counts["messages"] = dict(spy.counts)
        with _DBSpy(db) as spy:
            resp = await client.post(
                f"/api/sessions/{leaf}/chat", json={"message": "hi"},
                headers=_AUTH)
            assert resp.status == 200, await resp.text()
            counts["chat"] = dict(spy.counts)

    # The native transcript round-trips -- never an empty/mocked substitute.
    contents = [m.get("content") for m in messages_data["data"]]
    assert "seeded question" in contents and "seeded answer" in contents
    kwargs = run_agent.await_args.kwargs
    assert kwargs["session_id"] == leaf
    assert [(m["role"], m["content"]) for m in kwargs["conversation_history"]] == [
        ("user", "seeded question"), ("assistant", "seeded answer")]

    # metadata GET: ONE native existence read; no resolver, no ancestry.
    assert counts["get"]["get_session"] == 1, counts["get"]
    assert counts["get"]["resolve_resume_session_id"] == 0, counts["get"]
    # messages: existence read, the native tip resolution EXACTLY once, one
    # native page read -- no second unguarded resolution, no ancestor walk.
    assert counts["messages"]["resolve_resume_session_id"] == 1, counts["messages"]
    assert counts["messages"]["get_messages"] == 1, counts["messages"]
    assert counts["messages"]["get_session"] == (
        1 + native_resolve["get_session"] + native_msgs["get_session"]), counts["messages"]
    # chat: the history helper adds nothing beyond the existence read + the
    # native conversation load; the agent double serves the turn.
    assert counts["chat"]["resolve_resume_session_id"] == 0, counts["chat"]
    assert counts["chat"]["get_session"] == 1 + native_conv["get_session"], counts["chat"]
    assert counts["chat"]["get_messages_as_conversation"] == 1, counts["chat"]
    assert run_agent.await_count == 1
    # The central ancestry predicate never ran -- disabled does zero lineage work.
    assert lineage_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("b2b_state", ["absent", "disabled"])
async def test_disabled_reserved_prefix_denials_still_apply(
        tmp_path, opened, b2b_state):
    """The cheap prefix denial is retained even with the lane off: a raw
    reserved id refuses mutation/history surfaces (the GET genesis exception
    is covered separately)."""
    adapter = _disabled_adapter(tmp_path, b2b_state)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])

    async with TestClient(TestServer(_app(adapter))) as client:
        for method, path, kwargs in (
                ("PATCH", f"/api/sessions/{_RESERVED}", {"json": {"title": "x"}}),
                ("DELETE", f"/api/sessions/{_RESERVED}", {}),
                ("GET", f"/api/sessions/{_RESERVED}/messages", {}),
                ("POST", f"/api/sessions/{_RESERVED}/fork", {"json": {}}),
                ("POST", f"/api/sessions/{_RESERVED}/chat", {"json": {"message": "x"}}),
                ("POST", f"/api/sessions/{_RESERVED}/model", {"json": {"model": "m"}}),
                ("POST", "/v1/runs", {"json": {"session_id": _RESERVED, "input": "x"}})):
            resp = await client.request(method, path, headers=_AUTH, **kwargs)
            assert resp.status == 404, (method, path, resp.status, await resp.text())


@pytest.mark.asyncio
async def test_enabled_deep_ordinary_chain_admitted_including_listing(
        tmp_path, opened):
    """Enabled B2B does NOT refuse an ordinary session for its depth: a chain
    past the old 64-hop bound answers GET/messages and still lists."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    leaf = _ordinary_chain(db, "deep", 70)

    async with TestClient(TestServer(_app(adapter))) as client:
        resp = await client.get(f"/api/sessions/{leaf}", headers=_AUTH)
        assert resp.status == 200, await resp.text()
        resp = await client.get(f"/api/sessions/{leaf}/messages", headers=_AUTH)
        assert resp.status == 200, await resp.text()
        # include_children so parented chain members actually list -- a depth-64
        # cutoff would silently drop the deep descendants as "protected".
        resp = await client.get(
            "/api/sessions", params={"limit": 200, "include_children": "true"},
            headers=_AUTH)
        assert resp.status == 200, await resp.text()
        payload = await resp.json()
        listed_ids = {row["id"] for row in payload["data"]}
        assert {f"deep_{i}" for i in range(71)} <= listed_ids


# ---------------------------------------------------------------------------
# B. Enabled: ordinary-named protected descendant refuses every generic surface
# ---------------------------------------------------------------------------

def _refusal_cases(protected_id: str, resp_id: str):
    """``(method, path, request_kwargs)`` refusals the enabled lane must issue
    for an ordinary-named session whose ancestry reaches a reserved row."""
    return [
        ("GET", f"/api/sessions/{protected_id}", {}),
        ("PATCH", f"/api/sessions/{protected_id}", {"json": {"title": "x"}}),
        ("DELETE", f"/api/sessions/{protected_id}", {}),
        ("GET", f"/api/sessions/{protected_id}/messages", {}),
        ("POST", f"/api/sessions/{protected_id}/fork", {"json": {}}),
        ("POST", f"/api/sessions/{protected_id}/model", {"json": {"model": "m"}}),
        ("POST", f"/api/sessions/{protected_id}/chat", {"json": {"message": "x"}}),
        ("POST", f"/api/sessions/{protected_id}/chat/stream", {"json": {"message": "x"}}),
        ("POST", "/v1/chat/completions",
         {"json": {"messages": [{"role": "user", "content": "x"}]},
          "headers": {"X-Hermes-Session-Id": protected_id}}),
        ("POST", "/v1/chat/completions",
         {"json": {"messages": [{"role": "user", "content": "x"}], "stream": True},
          "headers": {"X-Hermes-Session-Id": protected_id}}),
        ("POST", "/v1/runs", {"json": {"session_id": protected_id, "input": "x"}}),
        ("POST", "/v1/responses",
         {"json": {"input": "x", "previous_response_id": resp_id}}),
        ("GET", f"/v1/responses/{resp_id}", {}),
        ("DELETE", f"/v1/responses/{resp_id}", {}),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("case_index", range(14))
async def test_enabled_protected_descendant_refused(
        tmp_path, monkeypatch, opened, case_index):
    """A descendant with an ORDINARY name (never ``b2b_``-prefixed) under a
    reserved root refuses every generic surface: 404 before history load,
    agent spawn, run-keyed state or any persisted mutation."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _seed(db, _RESERVED)
    protected = _seed(db, "prot_child", parent=_RESERVED)
    _seed(db, "prot_grandchild", parent=protected)
    # Stored response chained to the protected session for the
    # previous_response_id / stored-GET / stored-DELETE cases.
    resp_id = "resp_" + "a" * 28
    adapter._current_response_store().put(resp_id, {
        "response": {"id": resp_id, "object": "response", "status": "completed"},
        "conversation_history": [{"role": "user", "content": "q"}],
        "session_id": protected})
    # Declared X-Hermes-Session-Key resolving to the protected session.
    _seed(db, "prot_keyed", parent=_RESERVED, session_key="declared-key")

    run_agent = _run_agent_double()
    monkeypatch.setattr(adapter, "_run_agent", run_agent)
    monkeypatch.setattr(adapter, "_create_agent", _tripwire("_create_agent"))
    persist_lock = MagicMock(return_value=True)
    monkeypatch.setattr(adapter, "_persist_session_runtime_lock", persist_lock)

    sessions_before = db._read_all("SELECT * FROM sessions")
    method, path, kwargs = _refusal_cases(protected, resp_id)[case_index]
    async with TestClient(TestServer(_app(adapter))) as client:
        with _DBSpy(db) as spy:
            resp = await client.request(
                method, path, headers={**_AUTH, **kwargs.pop("headers", {})},
                **kwargs)
        assert resp.status == 404, (method, path, resp.status, await resp.text())

    # No history loader and no agent ran; no runtime-lock write happened.
    assert spy["get_messages"] == 0
    assert spy["get_messages_as_conversation"] == 0
    assert run_agent.await_count == 0
    assert persist_lock.call_count == 0
    # Sessions are unchanged and the protected stored response is retained.
    assert db._read_all("SELECT * FROM sessions") == sessions_before
    assert adapter._current_response_store().get(resp_id) is not None
    # No run-keyed state leaked either.
    for table in (adapter._run_owners, adapter._run_statuses,
                  adapter._run_streams, adapter._run_streams_created,
                  adapter._active_run_tasks, adapter._active_run_agents,
                  adapter._run_approval_sessions):
        assert not table, table


@pytest.mark.asyncio
async def test_enabled_declared_key_resolving_protected_refused(
        tmp_path, monkeypatch, opened):
    """A declared X-Hermes-Session-Key whose stored conversation is the
    protected session refuses /v1/runs and /v1/responses too -- selection goes
    through the same seam, not just explicit session_id."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _seed(db, _RESERVED)
    _seed(db, "prot_keyed", parent=_RESERVED, session_key="declared-key")

    run_agent = _run_agent_double()
    monkeypatch.setattr(adapter, "_run_agent", run_agent)
    monkeypatch.setattr(adapter, "_create_agent", _tripwire("_create_agent"))

    headers = {**_AUTH, "X-Hermes-Session-Key": "declared-key"}
    async with TestClient(TestServer(_app(adapter))) as client:
        resp = await client.post("/v1/runs", json={"input": "x"}, headers=headers)
        assert resp.status == 404, await resp.text()
        resp = await client.post("/v1/responses", json={"input": "x"}, headers=headers)
        assert resp.status == 404, await resp.text()
    assert run_agent.await_count == 0
    assert not adapter._run_owners and not adapter._run_statuses


@pytest.mark.asyncio
async def test_enabled_compression_tip_into_reserved_refused(
        tmp_path, monkeypatch, opened):
    """An ORDINARY id whose live compression tip resolves into the reserved
    namespace refuses on tip-resolving surfaces -- the resolved tip's ancestry
    is walked, never just the requested id's."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _seed(db, "comp_root")
    db.end_session("comp_root", "compression")
    _seed(db, _RESERVED, parent="comp_root")

    run_agent = _run_agent_double()
    monkeypatch.setattr(adapter, "_run_agent", run_agent)

    cases = [
        ("GET", "/api/sessions/comp_root", {}),
        ("GET", "/api/sessions/comp_root/messages", {}),
        ("POST", "/api/sessions/comp_root/chat", {"json": {"message": "x"}}),
        ("POST", "/v1/chat/completions",
         {"json": {"messages": [{"role": "user", "content": "x"}]},
          "headers": {"X-Hermes-Session-Id": "comp_root"}}),
        ("POST", "/v1/runs", {"json": {"session_id": "comp_root", "input": "x"}}),
    ]
    async with TestClient(TestServer(_app(adapter))) as client:
        for method, path, kwargs in cases:
            resp = await client.request(
                method, path, headers={**_AUTH, **kwargs.pop("headers", {})},
                **kwargs)
            assert resp.status == 404, (method, path, resp.status, await resp.text())
    assert run_agent.await_count == 0
    assert not adapter._run_owners


@pytest.mark.asyncio
async def test_enabled_raw_reserved_alias_refused_and_genesis_get_preserved(
        tmp_path, monkeypatch, opened):
    """A raw ``b2b_`` id cannot alias past the seam on non-GET surfaces; the
    documented empty/unbound genesis GET exception still reads its row."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _seed(db, _RESERVED)  # empty, unbound -> the one generic GET exception

    run_agent = _run_agent_double()
    monkeypatch.setattr(adapter, "_run_agent", run_agent)

    cases = [
        ("PATCH", f"/api/sessions/{_RESERVED}", {"json": {"title": "x"}}),
        ("DELETE", f"/api/sessions/{_RESERVED}", {}),
        ("GET", f"/api/sessions/{_RESERVED}/messages", {}),
        ("POST", f"/api/sessions/{_RESERVED}/fork", {"json": {}}),
        ("POST", f"/api/sessions/{_RESERVED}/chat", {"json": {"message": "x"}}),
        ("POST", "/v1/chat/completions",
         {"json": {"messages": [{"role": "user", "content": "x"}]},
          "headers": {"X-Hermes-Session-Id": _RESERVED}}),
        ("POST", "/v1/runs", {"json": {"session_id": _RESERVED, "input": "x"}}),
    ]
    async with TestClient(TestServer(_app(adapter))) as client:
        for method, path, kwargs in cases:
            resp = await client.request(
                method, path, headers={**_AUTH, **kwargs.pop("headers", {})},
                **kwargs)
            assert resp.status == 404, (method, path, resp.status, await resp.text())
        # The genesis exception: empty + unbound + real key + durable store.
        resp = await client.get(f"/api/sessions/{_RESERVED}", headers=_AUTH)
        assert resp.status == 200, await resp.text()
        # Bound/non-empty rows lose the exception.
        db.end_session(_RESERVED, "ended")
        resp = await client.get(f"/api/sessions/{_RESERVED}", headers=_AUTH)
        assert resp.status == 404
    assert run_agent.await_count == 0


# ---------------------------------------------------------------------------
# C. /v1/runs refusals leave no run-keyed or durable state
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("b2b_state", ["absent", "disabled", "enabled"])
async def test_runs_refusals_leave_run_state_untouched(
        tmp_path, monkeypatch, opened, b2b_state):
    """Repeated refusals -- raw reserved, ordinary descendant, tip resolving
    into the namespace, and a caller-supplied-history run that skips the
    history load -- mint no run_id entries anywhere. A preexisting owner
    marker is byte-identical afterwards."""
    adapter = (_enabled_adapter(tmp_path) if b2b_state == "enabled"
               else _disabled_adapter(tmp_path, b2b_state))
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _seed(db, _RESERVED)
    _seed(db, "prot_child", parent=_RESERVED)
    _seed(db, "comp_root")
    db.end_session("comp_root", "compression")
    _seed(db, "b2b_" + "f" * 64, parent="comp_root")

    run_agent = _run_agent_double()
    monkeypatch.setattr(adapter, "_run_agent", run_agent)
    monkeypatch.setattr(adapter, "_create_agent", _tripwire("_create_agent"))

    adapter._run_owners["sentinel_run"] = "scope"
    adapter._run_statuses["sentinel_run"] = {"status": "completed"}
    owners_before = dict(adapter._run_owners)
    statuses_before = dict(adapter._run_statuses)
    idem_before = adapter._run_idempotency_store._conn.execute(
        "SELECT COUNT(*) FROM run_idempotency").fetchone()[0]

    # Disabled denies the raw reserved prefix only -- descendants stay
    # ordinary. EVERY selected body is driven at least 3 times, repeats of
    # the raw reserved id included.
    bodies = [{"session_id": _RESERVED, "input": "x"}] * 3
    if b2b_state == "enabled":
        bodies += [
            {"session_id": "prot_child", "input": "x"},
            {"session_id": "comp_root", "input": "x"},
            {"session_id": "prot_child", "input": "x",
             "conversation_history": [{"role": "user", "content": "q"}]},
        ] * 3
    async with TestClient(TestServer(_app(adapter))) as client:
        for body in bodies:
            resp = await client.post("/v1/runs", json=body, headers=_AUTH)
            assert resp.status == 404, (body, resp.status, await resp.text())

    assert adapter._run_owners == owners_before
    assert adapter._run_statuses == statuses_before
    for table in (adapter._run_streams, adapter._run_streams_created,
                  adapter._active_run_tasks, adapter._active_run_agents,
                  adapter._run_approval_sessions, adapter._run_idempotency_ids):
        assert not table, table
    assert adapter._run_idempotency_store._conn.execute(
        "SELECT COUNT(*) FROM run_idempotency").fetchone()[0] == idem_before
    assert run_agent.await_count == 0


# ---------------------------------------------------------------------------
# D. Fail-closed semantics apply on the enabled lane only
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enabled_lineage_cycle_refused(tmp_path, opened):
    """A parent-cycle in the ancestry walk fails closed -- never a hang, never
    an ordinary pass."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _parent_cycle(db, "cyc_a", "cyc_b")

    async with TestClient(TestServer(_app(adapter))) as client:
        resp = await client.get("/api/sessions/cyc_a", headers=_AUTH)
        assert resp.status == 404, await resp.text()
        resp = await client.get("/api/sessions/cyc_b/messages", headers=_AUTH)
        assert resp.status == 404, await resp.text()


@pytest.mark.asyncio
async def test_enabled_lookup_errors_fail_closed(
        tmp_path, monkeypatch, opened):
    """DB lookup errors inside the walk or the tip resolver fail closed 404 --
    an erroring ancestor is never silently treated as ordinary."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _seed(db, _RESERVED)
    _seed(db, "prot_child", parent=_RESERVED)

    orig_get = db.get_session

    def _flaky(sid, *args, **kwargs):
        if sid == "prot_child":
            raise RuntimeError("simulated lookup failure")
        return orig_get(sid, *args, **kwargs)

    monkeypatch.setattr(db, "get_session", _flaky)
    async with TestClient(TestServer(_app(adapter))) as client:
        resp = await client.get("/api/sessions/prot_child", headers=_AUTH)
        assert resp.status == 404, await resp.text()
    monkeypatch.setattr(db, "get_session", orig_get)

    monkeypatch.setattr(
        db, "resolve_resume_session_id",
        _tripwire("resolve_resume_session_id"))
    async with TestClient(TestServer(_app(adapter))) as client:
        resp = await client.get("/api/sessions/prot_child/messages", headers=_AUTH)
        assert resp.status == 404, await resp.text()


@pytest.mark.asyncio
async def test_disabled_cycle_and_resolver_failure_behave_like_base(
        tmp_path, monkeypatch, opened):
    """Disabled lane: a lineage cycle does NOT refuse (the guard never walks);
    the native tip resolver keeps BOTH of its native error contracts -- the
    OpenAI-header consumer fails OPEN to the requested id, while /messages
    lets a resolver exception surface as a native 500."""
    adapter = _disabled_adapter(tmp_path, "disabled")
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _parent_cycle(db, "cyc_a", "cyc_b")
    db.append_message("cyc_a", "user", content="seeded question")
    lineage_calls = _install_lineage_spy(monkeypatch)
    monkeypatch.setattr(adapter, "_run_agent", _run_agent_double())

    # Metadata GET on the cycle: 200, and ZERO lineage work -- the disabled
    # seam never walks ancestors.
    with _DBSpy(db) as spy:
        async with TestClient(TestServer(_app(adapter))) as client:
            resp = await client.get("/api/sessions/cyc_a", headers=_AUTH)
            assert resp.status == 200, await resp.text()
        assert spy["get_session"] == 1
        assert spy["resolve_resume_session_id"] == 0
        assert lineage_calls == []

    monkeypatch.setattr(
        db, "resolve_resume_session_id",
        _tripwire("resolve_resume_session_id"))
    async with TestClient(TestServer(_app(adapter))) as client:
        # OpenAI header: native fail-open -- the turn runs on the ORIGINAL
        # session's own history despite the resolver error.
        resp = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "x"}]},
            headers={**_AUTH, "X-Hermes-Session-Id": "cyc_a"})
        assert resp.status == 200, await resp.text()
        # /messages: native strict -- the resolver error is a 500, and no
        # history page is loaded.
        with _DBSpy(db) as spy:
            resp = await client.get("/api/sessions/cyc_a/messages", headers=_AUTH)
            assert resp.status == 500, await resp.text()
            assert spy["get_messages"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("b2b_state", ["absent", "disabled"])
async def test_disabled_missing_session_messages_404_before_resolver(
        tmp_path, opened, b2b_state):
    """Native ordering: /messages checks existence BEFORE the tip resolver --
    a missing id 404s with zero resolver calls, in either disabled shape."""
    adapter = _disabled_adapter(tmp_path, b2b_state)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])

    async with TestClient(TestServer(_app(adapter))) as client:
        with _DBSpy(db) as spy:
            resp = await client.get("/api/sessions/missing/messages", headers=_AUTH)
            assert resp.status == 404, await resp.text()
            assert spy["resolve_resume_session_id"] == 0
            assert spy["get_session"] == 1


@pytest.mark.asyncio
async def test_enabled_protected_ancestor_beyond_64_refused(tmp_path, opened):
    """A reserved ancestor DEEP in the chain (past the old 64-hop bound) is
    still found by the unbounded walk -- the descendant refuses; a same-depth
    fully ordinary chain is admitted."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _seed(db, _RESERVED)
    leaf = _ordinary_chain(db, "deep", 70, root_parent=_RESERVED)

    async with TestClient(TestServer(_app(adapter))) as client:
        resp = await client.get(f"/api/sessions/{leaf}", headers=_AUTH)
        assert resp.status == 404, await resp.text()
        resp = await client.post(
            "/v1/runs", json={"session_id": leaf, "input": "x"}, headers=_AUTH)
        assert resp.status == 404, await resp.text()


# ---------------------------------------------------------------------------
# E. Both chains are validated: the resolver cannot launder either direction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enabled_resolver_cannot_alias_protected_raw_to_safe_tip(
        tmp_path, monkeypatch, opened):
    """A resolver that maps an ordinary-named PROTECTED selector to a safe
    ordinary tip still refuses: the requested id's OWN ancestry is checked,
    not only the resolved tip's."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _seed(db, _RESERVED)
    _seed(db, "prot_child", parent=_RESERVED)
    _seed(db, "ord_safe")
    monkeypatch.setattr(db, "resolve_resume_session_id", lambda sid: "ord_safe")

    run_agent = _run_agent_double()
    monkeypatch.setattr(adapter, "_run_agent", run_agent)
    async with TestClient(TestServer(_app(adapter))) as client:
        resp = await client.get("/api/sessions/prot_child", headers=_AUTH)
        assert resp.status == 404, await resp.text()
        resp = await client.get("/api/sessions/prot_child/messages", headers=_AUTH)
        assert resp.status == 404, await resp.text()
    assert run_agent.await_count == 0


@pytest.mark.asyncio
async def test_enabled_protected_tip_refused_for_safe_raw(
        tmp_path, monkeypatch, opened):
    """The reverse direction: a SAFE ordinary selector whose resolved tip is
    the protected descendant still refuses -- the tip's ancestry is walked."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _seed(db, _RESERVED)
    _seed(db, "prot_child", parent=_RESERVED)
    _seed(db, "ord_safe")
    monkeypatch.setattr(db, "resolve_resume_session_id", lambda sid: "prot_child")

    run_agent = _run_agent_double()
    monkeypatch.setattr(adapter, "_run_agent", run_agent)
    async with TestClient(TestServer(_app(adapter))) as client:
        resp = await client.get("/api/sessions/ord_safe/messages", headers=_AUTH)
        assert resp.status == 404, await resp.text()
        resp = await client.post(
            "/v1/runs", json={"session_id": "ord_safe", "input": "x"},
            headers=_AUTH)
        assert resp.status == 404, await resp.text()
    assert run_agent.await_count == 0
    assert not adapter._run_owners


@pytest.mark.asyncio
async def test_enabled_raw_reserved_denied_before_any_resolver(
        tmp_path, monkeypatch, opened):
    """The cheap prefix denial short-circuits BEFORE tip resolution: a
    resolver spy that would alias to a safe ordinary id is never called by a
    denied non-GET request."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _seed(db, _RESERVED)
    _seed(db, "ord_safe")
    resolver_spy = MagicMock(return_value="ord_safe")
    monkeypatch.setattr(db, "resolve_resume_session_id", resolver_spy)

    async with TestClient(TestServer(_app(adapter))) as client:
        resp = await client.post(
            "/v1/runs", json={"session_id": _RESERVED, "input": "x"},
            headers=_AUTH)
        assert resp.status == 404, await resp.text()
    assert resolver_spy.call_count == 0


@pytest.mark.asyncio
async def test_enabled_runs_stored_chain_refused_despite_body_override(
        tmp_path, monkeypatch, opened):
    """``previous_response_id`` ancestry is checked BEFORE its stored
    transcript is consumed -- even when body.session_id overrides the final
    selection with a safe ordinary session."""
    adapter = _enabled_adapter(tmp_path)
    db = adapter._session_db
    opened.extend([db, adapter._run_idempotency_store, adapter._response_store])
    _seed(db, _RESERVED)
    _seed(db, "prot_child", parent=_RESERVED)
    _seed(db, "ord_safe")
    resp_id = "resp_" + "b" * 28
    adapter._current_response_store().put(resp_id, {
        "response": {"id": resp_id, "object": "response"},
        "conversation_history": [{"role": "assistant", "content": "leak"}],
        "session_id": "prot_child"})

    run_agent = _run_agent_double()
    monkeypatch.setattr(adapter, "_run_agent", run_agent)
    monkeypatch.setattr(adapter, "_create_agent", _tripwire("_create_agent"))

    async with TestClient(TestServer(_app(adapter))) as client:
        for _ in range(2):
            resp = await client.post(
                "/v1/runs",
                json={"input": "x", "session_id": "ord_safe",
                      "previous_response_id": resp_id},
                headers=_AUTH)
            assert resp.status == 404, await resp.text()

    assert run_agent.await_count == 0
    for table in (adapter._run_owners, adapter._run_statuses,
                  adapter._run_streams, adapter._active_run_tasks):
        assert not table, table
