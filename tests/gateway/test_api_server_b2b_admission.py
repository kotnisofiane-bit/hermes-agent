"""B2B proposal POST: a refused source exchange never consumes the single
attempt, and the typed surface resolves the owning profile from the
REQUEST's home -- never a literal ``"default"``.

The valid signed request reaches ``_resolve_source_async`` under the owning
profile; a source refusal lands as the classified denial BEFORE admission,
titling or spawn -- a repeated POST stays non-consuming. Signed GETs on
previously existing attempts remain usable; a proof on a never-admitted
tuple is a plain 404. All crypto is real Ed25519; only the source exchange
itself and the tripwires that must never run are patched.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms import api_server_b2b as b2b
from gateway.platforms.api_server import APIServerAdapter, _api_request_profile
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from hermes_state import SessionDB
from tests.gateway.b2b_process_harness import _sig, make_keypair

_API_KEY = "k" * 32


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


def _profile_home(tmp_path, monkeypatch, name: str) -> Path:
    """HERMES_HOME=<root>/profiles/<name> under a temp Path.home -- the real
    named-profile layout ``get_active_profile_name`` resolves."""
    home_root = tmp_path / "homes"
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    prof = home_root / "profiles" / name
    prof.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(prof))
    return prof


def _b2b_extra(*profile_names: str):
    entries = {}
    for name in profile_names:
        _, _, portal_pub = make_keypair()
        _, hermes_priv, _ = make_keypair()
        entries[name] = {
            "source_url": "http://127.0.0.1:1/internal/dubsar/b2b/source",
            "portal_issuer": f"portal-{name}", "hermes_issuer": f"hermes-{name}",
            "portal_public_key_pem": portal_pub, "hermes_private_key_pem": hermes_priv,
            "projects": {"b2b-bench": {
                "project_id": "b2b-bench", "bot_id": "bot", "profile_id": name,
                "allowed_namespaces": ["ns"], "context_contract_root": None,
                "model": "unit-double", "provider": "custom",
                "base_url": "http://127.0.0.1:9/v1", "api_mode": "chat_completions",
                "logical_mission": None, "project_context": None}}}
    return {"key": _API_KEY, "b2b": {"enabled": True, "profiles": entries}}


def _adapter(tmp_path, monkeypatch, *profile_names: str) -> APIServerAdapter:
    adapter = APIServerAdapter(PlatformConfig(
        enabled=True, extra=_b2b_extra(*profile_names)))
    # Single-profile gateway: multiplexing off, so a /p/<own>/ prefix resolves
    # to the selector-less (None) scope.
    adapter.gateway_runner = SimpleNamespace(
        config=SimpleNamespace(multiplex_profiles=False))
    adapter._session_db = SessionDB(tmp_path / "state.db")
    return adapter


def _app(adapter: APIServerAdapter) -> web.Application:
    app = web.Application(middlewares=[adapter._make_profile_prefix_middleware()])
    for method, path, handler in b2b.b2b_http_routes(adapter):
        app.router.add_route(method, path, handler)
        app.router.add_route(method, f"/p/{{profile}}{path}", handler)
    return app


def _post_body():
    binding = "a" * 64
    session_id = "b2b_" + binding
    attempt_id = b2b._attempt_id_for(binding)
    return session_id, attempt_id, binding, {
        "attempt_id": attempt_id, "binding_digest": binding}


def _store_counts(store: RunIdempotencyStore) -> dict:
    conn = store._conn
    return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("run_idempotency", "b2b_attempts", "b2b_bindings",
                          "b2b_artifacts")}


def _tripwire(name):
    def _raise(*a, **k):
        raise AssertionError(f"{name} must not run for a refused admission")
    return _raise


@pytest.mark.asyncio
async def test_b2b_proposal_post_refuses_before_admission_without_writes(
        tmp_path, monkeypatch, opened):
    """A valid signed POST whose source exchange refuses gets 503
    source_unavailable BEFORE admit, title or spawn -- and repeated POSTs
    stay non-consuming."""
    _profile_home(tmp_path, monkeypatch, "hub")
    adapter = _adapter(tmp_path, monkeypatch, "hub")
    opened.extend([adapter._session_db, adapter._run_idempotency_store])
    session_id, attempt_id, binding, body = _post_body()
    adapter._session_db.create_session(session_id, "api_server")

    async def _unavailable(*a, **k):
        return None, "source_unavailable"

    monkeypatch.setattr(b2b, "_resolve_source_async", _unavailable)
    for target in ("resolve_source", "_launch_b2b_run", "_spawn_run"):
        monkeypatch.setattr(b2b, target, _tripwire(f"b2b.{target}"))
    monkeypatch.setattr(adapter, "_create_agent", _tripwire("_create_agent"))

    session_before = adapter._session_db.get_session(session_id)
    counts_before = _store_counts(adapter._run_idempotency_store)
    changes_before = adapter._run_idempotency_store._conn.total_changes

    async with TestClient(TestServer(_app(adapter))) as client:
        for _ in range(2):
            resp = await client.post(
                f"/p/hub/api/sessions/{session_id}/b2b-proposal",
                json=body,
                headers={"Authorization": f"Bearer {_API_KEY}",
                         "Idempotency-Key": attempt_id})
            payload = await resp.json()
            assert resp.status == 503, payload
            assert payload.get("error") == "source_unavailable"
            assert payload.get("code") == "source_unavailable"

    # No durable writes of any kind: no run/attempt/binding/artifact rows, no
    # native session mutation (title etc.), no extra store transactions.
    assert adapter._session_db.get_session(session_id) == session_before
    assert _store_counts(adapter._run_idempotency_store) == counts_before
    assert adapter._run_idempotency_store._conn.total_changes == changes_before
    for table in (adapter._run_streams, adapter._run_streams_created,
                  adapter._active_run_agents, adapter._active_run_tasks,
                  adapter._run_statuses):
        assert not table


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", ["hub", "ci"])
async def test_b2b_proposal_post_resolves_owning_profile(
        tmp_path, monkeypatch, profile, opened):
    """Single-profile gateway serving a NAMED home: ``/p/<name>/`` resolves to
    the selector-less scope, so the typed surface must resolve the home's owner
    profile -- never literal ``"default"`` -- or every valid POST is a bogus 404."""
    _profile_home(tmp_path, monkeypatch, profile)
    adapter = _adapter(tmp_path, monkeypatch, "hub", "ci")
    opened.extend([adapter._session_db, adapter._run_idempotency_store])
    session_id, attempt_id, binding, body = _post_body()

    async def _unavailable(*a, **k):
        return None, "source_unavailable"

    monkeypatch.setattr(b2b, "_resolve_source_async", _unavailable)

    async with TestClient(TestServer(_app(adapter))) as client:
        resp = await client.post(
            f"/p/{profile}/api/sessions/{session_id}/b2b-proposal",
            json=body,
            headers={"Authorization": f"Bearer {_API_KEY}",
                     "Idempotency-Key": attempt_id})
        payload = await resp.json()
        assert resp.status == 503, payload
        assert payload.get("error") == "source_unavailable"
        # A foreign prefix still 404s in the middleware before the handler.
        resp = await client.post(
            f"/p/foreign/api/sessions/{session_id}/b2b-proposal",
            json=body,
            headers={"Authorization": f"Bearer {_API_KEY}",
                     "Idempotency-Key": attempt_id})
        assert resp.status == 404


def test_request_profile_selector_beats_launch_and_owner_resolves(
        tmp_path, monkeypatch):
    """``_request_profile``: an explicit multiplex selector wins over the launch
    home; a selector-less request resolves the real home owner (A->B->A)."""
    _profile_home(tmp_path, monkeypatch, "hub")

    def req(profile):
        return SimpleNamespace(match_info={"profile": profile})

    # Explicit selector: the selector IS the answer, never the launch home.
    token = _api_request_profile.set("ci")
    try:
        assert b2b._request_profile(req("ci")) == "ci"
        assert b2b._request_profile(req("hub")) is None
    finally:
        _api_request_profile.reset(token)

    # Selector-less: owner resolved from HERMES_HOME -- A(hub) -> B(ci) -> A(hub).
    assert b2b._request_profile(req("hub")) == "hub"
    assert b2b._request_profile(req("ci")) is None
    monkeypatch.setenv(
        "HERMES_HOME", str(tmp_path / "homes" / "profiles" / "ci"))
    assert b2b._request_profile(req("ci")) == "ci"
    assert b2b._request_profile(req("hub")) is None
    monkeypatch.setenv(
        "HERMES_HOME", str(tmp_path / "homes" / "profiles" / "hub"))
    assert b2b._request_profile(req("hub")) == "hub"


class _BoundedContent:
    """``request.content.iter_chunked`` the handler's bounded JSON reader uses."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def iter_chunked(self, size):
        async def _gen():
            for i in range(0, len(self._payload), size):
                yield self._payload[i:i + size]
        return _gen()


class _ProposalRequest:
    """Request stand-in for a DIRECT _handle_b2b_proposal_post call.

    The full route/middleware path is covered by the TestClient tests above;
    this boundary unit isolates the handler itself -- a request that exposes
    ``match_info``/``headers`` and a bounded async JSON read, with the trusted
    multiplex selector scope set explicitly on ``_api_request_profile``."""

    def __init__(self, *, profile, session_id, body, idempotency_key):
        self.match_info = {"profile": profile, "session_id": session_id}
        self.headers = {"Idempotency-Key": idempotency_key}
        self.content = _BoundedContent(
            json.dumps(body).encode("utf-8"))


@pytest.mark.asyncio
async def test_b2b_proposal_post_handler_source_denied_before_launch(
        tmp_path, monkeypatch, opened):
    """Direct-handler boundary: a fully valid request under a trusted selector
    scope whose source exchange denies -> 403 source_denied BEFORE admission
    -- independent of any profile-resolution fallback (selector explicit)."""
    _profile_home(tmp_path, monkeypatch, "hub")
    adapter = _adapter(tmp_path, monkeypatch, "hub")
    opened.extend([adapter._session_db, adapter._run_idempotency_store])
    session_id, attempt_id, binding, body = _post_body()
    adapter._session_db.create_session(session_id, "api_server")

    async def _denied(*a, **k):
        return None, "source_denied"

    monkeypatch.setattr(b2b, "_resolve_source_async", _denied)
    for target in ("resolve_source", "_launch_b2b_run", "_spawn_run"):
        monkeypatch.setattr(b2b, target, _tripwire(f"b2b.{target}"))

    session_before = adapter._session_db.get_session(session_id)
    counts_before = _store_counts(adapter._run_idempotency_store)
    changes_before = adapter._run_idempotency_store._conn.total_changes

    request = _ProposalRequest(profile="hub", session_id=session_id,
                               body=body, idempotency_key=attempt_id)
    token = _api_request_profile.set("hub")  # trusted multiplex selector scope
    try:
        response = await b2b._handle_b2b_proposal_post(adapter, request)
    finally:
        _api_request_profile.reset(token)

    assert response.status == 403
    payload = json.loads(response.body)
    assert payload.get("error") == "source_denied"
    assert adapter._session_db.get_session(session_id) == session_before
    assert _store_counts(adapter._run_idempotency_store) == counts_before
    assert adapter._run_idempotency_store._conn.total_changes == changes_before


# ---------------------------------------------------------------------------
# Signed GETs -- usable for real attempts; a never-admitted tuple is a 404
# ---------------------------------------------------------------------------

def _read_proof(entry, portal_priv, *, attempt_id, binding, profile, session_id):
    body = {"attempt_id": attempt_id, "binding_digest": binding,
            "requester_id": "1" * 24, "profile": profile,
            "session_id": session_id}
    now = int(time.time())
    envelope = {
        "version": b2b._VERSION, "issuer": entry["portal_issuer"],
        "audience": entry["hermes_issuer"], "operation": "read",
        "request_id": str(uuid.uuid4()), "issued_at": now,
        "expires_at": now + b2b._REQUEST_TTL_S, "body": body}
    envelope["signature"] = _sig(envelope, portal_priv)
    return json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)


def _enabled_adapter_with_keys(tmp_path, monkeypatch):
    """Adapter + the portal private key (tests keep it to sign read proofs)."""
    portal_priv, _, portal_pub = make_keypair()
    _, hermes_priv, _ = make_keypair()
    entry = {
        "source_url": "http://127.0.0.1:1/internal/dubsar/b2b/source",
        "portal_issuer": "portal-hub", "hermes_issuer": "hermes-hub",
        "portal_public_key_pem": portal_pub, "hermes_private_key_pem": hermes_priv,
        "projects": {"b2b-bench": {
            "project_id": "b2b-bench", "bot_id": "bot", "profile_id": "hub",
            "allowed_namespaces": ["ns"], "context_contract_root": None,
            "model": "unit-double", "provider": "custom",
            "base_url": "http://127.0.0.1:9/v1", "api_mode": "chat_completions",
            "logical_mission": None, "project_context": None}}}
    adapter = APIServerAdapter(PlatformConfig(
        enabled=True, extra={"key": _API_KEY,
                             "b2b": {"enabled": True, "profiles": {"hub": entry}}}))
    adapter.gateway_runner = SimpleNamespace(
        config=SimpleNamespace(multiplex_profiles=False))
    return adapter, entry, portal_priv


@pytest.mark.asyncio
async def test_b2b_get_never_admitted_requires_proof_then_404(
        tmp_path, monkeypatch, opened):
    """A signed proof on a tuple that was never admitted (refusal is
    non-consuming) reaches the typed read branch and returns a plain 404."""
    _profile_home(tmp_path, monkeypatch, "hub")
    adapter, entry, portal_priv = _enabled_adapter_with_keys(tmp_path, monkeypatch)
    opened.append(adapter._run_idempotency_store)
    session_id, attempt_id, binding, _ = _post_body()

    async with TestClient(TestServer(_app(adapter))) as client:
        # No proof at all -> 403, before any snapshot lookup.
        resp = await client.get(
            f"/p/hub/api/sessions/{session_id}/b2b-proposal/{attempt_id}",
            headers={"Authorization": f"Bearer {_API_KEY}"})
        assert resp.status == 403
        # Valid proof on the same tuple -> typed read branch -> 404 not-found
        # (nothing was ever admitted for it).
        proof = _read_proof(entry, portal_priv, attempt_id=attempt_id,
                            binding=binding, profile="hub",
                            session_id=session_id)
        resp = await client.get(
            f"/p/hub/api/sessions/{session_id}/b2b-proposal/{attempt_id}",
            headers={"Authorization": f"Bearer {_API_KEY}",
                     "X-Dubsar-Read-Proof": proof})
        assert resp.status == 404, await resp.text()


@pytest.mark.asyncio
async def test_b2b_get_seeded_historical_attempt_returns_200(
        tmp_path, monkeypatch, opened):
    """A previously existing attempt stays readable: seeded durable rows + a
    valid proof -> 200 typed snapshot, historical only."""
    from agent.b2b_execution import json_utf8
    _profile_home(tmp_path, monkeypatch, "hub")
    adapter, entry, portal_priv = _enabled_adapter_with_keys(tmp_path, monkeypatch)
    store = adapter._run_idempotency_store
    opened.append(store)
    session_id, attempt_id, binding, _ = _post_body()
    run_id = "run_" + uuid.uuid4().hex
    requester = "1" * 24
    source_body = {"requester_id": requester, "project_binding_id": "b2b-bench",
                   "project_id": "b2b-bench", "mission_id": "DUB-001",
                   "mission_revision": 1}
    admission = store.b2b_admit(
        profile="hub", session_id=session_id, binding_digest=binding,
        attempt_id=attempt_id, fingerprint="fp",
        binding_row={"profile": "hub", "session_id": session_id,
                     "binding_digest": binding, "policy_json": "{}"},
        attempt_row={"attempt_id": attempt_id, "binding_digest": binding,
                     "profile": "hub", "session_id": session_id,
                     "status": "admitted", "run_id": run_id,
                     "requester_id": requester,
                     "source_bind": json_utf8(
                         {"response": {"body": source_body}})},
        run_scope="b2b:" + attempt_id, run_key=attempt_id, run_id=run_id,
        run_fingerprint="fp",
        run_status={"session_id": session_id, "status": "running"},
        owner_pid=os.getpid(), owner_started=0)
    assert admission["status"] == "admitted"

    proof = _read_proof(entry, portal_priv, attempt_id=attempt_id,
                        binding=binding, profile="hub", session_id=session_id)
    async with TestClient(TestServer(_app(adapter))) as client:
        resp = await client.get(
            f"/p/hub/api/sessions/{session_id}/b2b-proposal/{attempt_id}",
            headers={"Authorization": f"Bearer {_API_KEY}",
                     "X-Dubsar-Read-Proof": proof})
        payload = await resp.json()
        assert resp.status == 200, payload
        assert payload["attempt_id"] == attempt_id
        assert payload["session_id"] == session_id
        assert payload["binding_digest"] == binding
        assert payload.get("current") is False and payload.get("historical") is True
        assert isinstance(payload.get("artifacts"), list) and payload["artifacts"]


# ---------------------------------------------------------------------------
# b2b_attempts(run_id) index -- the correlated prune exclusion must SEARCH
# ---------------------------------------------------------------------------

_PRUNE_PLAN_SQL = (
    "EXPLAIN QUERY PLAN SELECT scope, idempotency_key, status_json "
    "FROM run_idempotency r "
    "WHERE (acknowledged_at <= ? OR (retention_until > 0 AND retention_until <= ?) "
    "OR (retention_until <= 0 AND updated_at < ?)) "
    "AND NOT EXISTS (SELECT 1 FROM b2b_attempts a WHERE a.run_id = r.run_id)")


def _plan_text(store) -> str:
    rows = store._conn.execute(_PRUNE_PLAN_SQL, (0, 0, 0)).fetchall()
    return "\n".join(str(row[-1]) for row in rows)


def test_b2b_attempts_run_id_index_exists_and_is_used(tmp_path, opened):
    """The prune query's correlated ``b2b_attempts a WHERE a.run_id = r.run_id``
    lookup must SEARCH the run_id index, never SCAN the attempts table -- on a
    fresh store AND on a reopened pre-existing database."""
    db_path = str(tmp_path / "runs.db")
    for label in ("fresh", "reopened"):
        store = RunIdempotencyStore(db_path)
        opened.append(store)
        indexes = {row[1] for row in store._conn.execute(
            "PRAGMA index_list('b2b_attempts')")}
        assert "b2b_attempts_run_id" in indexes, (label, indexes)
        plan = _plan_text(store)
        assert "b2b_attempts_run_id" in plan, (label, plan)
        # The correlated attempt lookup searches the index -- never scans.
        assert "SCAN a" not in plan, plan
        store.close()


def test_prune_preserves_aged_b2b_and_drops_aged_ordinary(tmp_path, opened):
    """Real reserve-driven prune: an aged terminal ordinary row is deleted; the
    aged row a B2B attempt still references is preserved."""
    store = RunIdempotencyStore(str(tmp_path / "runs.db"))
    opened.append(store)
    old = time.time() - 2 * store.RETENTION_SECONDS
    store.reserve(scope="s", key="k-ord", fingerprint="f", run_id="run_ord",
                  status={"status": "failed", "session_id": "x"})
    store.reserve(scope="b2b:x", key="k-b2b", fingerprint="f", run_id="run_b2b",
                  status={"status": "failed", "session_id": "x"})
    store._conn.execute(
        "UPDATE run_idempotency SET updated_at=? WHERE run_id IN ('run_ord','run_b2b')",
        (old,))
    store._conn.execute(
        "INSERT INTO b2b_attempts(attempt_id,profile,session_id,binding_digest,"
        "status,fingerprint,run_id,requester_id,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        ("b2bp_" + "b" * 64, "hub", "b2b_" + "a" * 64, "a" * 64,
         "admitted", "f", "run_b2b", "1" * 24, old, old))
    store._conn.commit()
    # The next reserve runs the prune inside its BEGIN IMMEDIATE.
    store.reserve(scope="s", key="k-new", fingerprint="f", run_id="run_new",
                  status={"status": "queued"})
    remaining = {r[0] for r in store._conn.execute(
        "SELECT run_id FROM run_idempotency")}
    assert "run_ord" not in remaining
    assert "run_b2b" in remaining
    assert "run_new" in remaining


# ---------------------------------------------------------------------------
# L2-mw admission gate: signed + session-valid POSTs still refuse. Full
# preparation is real but execution stays CLOSED (no C1 producer), and any
# missing preparation is closed identically — either way the single attempt
# is never consumed: zero durable writes, untouched title, repeated POSTs.
# ---------------------------------------------------------------------------

class _SourceDouble:
    """Real signed-source loopback: verifies the Hermes Ed25519 request
    envelope and answers with a properly signed ``resolved`` envelope over
    real loopback HTTP. Only the counterparty is doubled — every check the
    production verifier runs is real (crypto, envelope shape, window)."""

    def __init__(self, *, portal_priv, portal_issuer, hermes_issuer,
                 hermes_pub_pem, body_for):
        import base64 as _b64
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from cryptography.hazmat.primitives.serialization import (
            load_pem_public_key)
        from tests.gateway.b2b_process_harness import DOMAIN, canonical

        self._portal_priv = portal_priv
        self._portal_issuer = portal_issuer
        self._hermes_issuer = hermes_issuer
        self._body_for = body_for
        self._hermes_pub = load_pem_public_key(hermes_pub_pem.encode())
        self._b64 = _b64
        self._domain = DOMAIN
        self._canonical = canonical
        double = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                try:
                    env = json.loads(raw)
                    unsigned = {k: v for k, v in env.items()
                                if k != "signature"}
                    double._hermes_pub.verify(
                        double._b64.urlsafe_b64decode(
                            env["signature"] + "=="),
                        double._domain + double._canonical(unsigned))
                    resp = double._envelope(double._body_for(env))
                except Exception:
                    self.send_response(400)
                    self.end_headers()
                    return
                payload = json.dumps(
                    resp, separators=(",", ":")).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.source_url = ("http://127.0.0.1:"
                           f"{self._server.server_address[1]}"
                           "/internal/dubsar/b2b/source")

    def _envelope(self, body):
        now = int(time.time())
        env = {"version": b2b._VERSION, "issuer": self._portal_issuer,
               "audience": self._hermes_issuer,
               "operation": b2b._RESPONSE_OPERATION,
               "request_id": str(uuid.uuid4()), "issued_at": now,
               "expires_at": now + b2b._REQUEST_TTL_S, "body": body}
        env["signature"] = _sig(env, self._portal_priv)
        return env

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(5)


def _valid_admission_lane(tmp_path, monkeypatch, opened, *, prepared: bool):
    """Adapter + REAL signed loopback source + a session/binding tuple whose
    resolved body passes every production check. ``prepared`` mounts the
    operator inputs (r2 contract root, My Work roots, inert serving config);
    either way the lane must refuse before admission."""
    import hashlib
    from tests.gateway.b2b_process_harness import (
        canonical, extract_contract_root)

    prof = _profile_home(tmp_path, monkeypatch, "hub")
    portal_priv, _, portal_pub = make_keypair()
    _, hermes_priv_pem, hermes_pub = make_keypair()
    requester_id = "1" * 24
    project_id = "b2b-bench"
    mission_id, mission_revision = "DUB-001", 1
    basis = {"format": "dubsar.b2b-agent-session-binding/1",
             "requester_id": requester_id, "project_id": project_id,
             "mission_id": mission_id, "mission_revision": mission_revision}
    binding = hashlib.sha256(canonical(basis)).hexdigest()
    session_id = "b2b_" + binding
    attempt_id = b2b._attempt_id_for(binding)

    project = {"project_id": project_id, "bot_id": "bot", "profile_id": "hub",
               "allowed_namespaces": ["ns"], "context_contract_root": None,
               "model": "unit-double", "provider": "custom",
               "base_url": "http://127.0.0.1:9/v1",
               "api_mode": "chat_completions",
               "logical_mission": None, "project_context": None}
    if prepared:
        alloc = tmp_path / "mywork-alloc"
        start = tmp_path / "mywork-start"
        alloc.mkdir()
        start.mkdir()
        project["context_contract_root"] = extract_contract_root(tmp_path)
        project["project_context"] = {
            "allocation_root": str(alloc), "project_id": project_id,
            "start": str(start)}
        (prof / "config.yaml").write_text(
            "model:\n  context_length: 256000\n"
            "compression:\n  enabled: false\n")

    lane = SimpleNamespace()

    def _body_for(request_env):
        req = request_env["body"]
        s = lane.db.get_session(req["session_id"])
        obs = {
            "id": s["id"], "source": s["source"], "title": s.get("title"),
            "model": s.get("model"),
            "parent_session_id": s.get("parent_session_id"),
            "has_system_prompt": s.get("system_prompt") is not None,
            "has_model_config": s.get("model_config") is not None,
            "ended_at": s.get("ended_at"), "end_reason": s.get("end_reason"),
            "message_count": int(s.get("message_count") or 0),
            "tool_call_count": int(s.get("tool_call_count") or 0),
            "api_call_count": int(s.get("api_call_count") or 0),
            "profile": "hub"}
        return {
            "attempt_id": req["attempt_id"], "profile": "hub",
            "session_id": req["session_id"], "binding_digest": binding,
            "source_state": "active",
            "reservation_ref": {"collection": "dubsar_b2b_agent_sessions",
                                "id": binding},
            "requester_id": requester_id, "project_id": project_id,
            "project_binding_id": project_id, "mission_id": mission_id,
            "mission_revision": mission_revision,
            "request_digest": "d" * 64, "mission_source_digest": "c" * 64,
            "ticket_digest": "e" * 64,
            "authority_basis_digest": "sha256:" + "b" * 64,
            "authority_digest": "sha256:" + "a" * 64,
            "observation_genesis": obs,
            "mission_request": {"title": "m", "objective": "o",
                                "criteria": ["c"], "source_refs": []},
            "source_request_id": request_env["request_id"],
            "source_request_digest": hashlib.sha256(
                canonical(request_env)).hexdigest()}

    source = _SourceDouble(
        portal_priv=portal_priv, portal_issuer="portal-hub",
        hermes_issuer="hermes-hub", hermes_pub_pem=hermes_pub,
        body_for=_body_for)
    extra = {"key": _API_KEY, "b2b": {"enabled": True, "profiles": {"hub": {
        "source_url": source.source_url, "portal_issuer": "portal-hub",
        "hermes_issuer": "hermes-hub", "portal_public_key_pem": portal_pub,
        "hermes_private_key_pem": hermes_priv_pem,
        "projects": {project_id: project}}}}}
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra=extra))
    adapter.gateway_runner = SimpleNamespace(
        config=SimpleNamespace(multiplex_profiles=False))
    adapter._session_db = SessionDB(prof / "state.db")
    adapter._session_db.create_session(session_id, "api_server")
    opened.extend([adapter._session_db, adapter._run_idempotency_store])
    lane.db = adapter._session_db
    lane.adapter = adapter
    lane.source = source
    lane.session_id = session_id
    lane.attempt_id = attempt_id
    lane.binding = binding
    return lane


@pytest.mark.asyncio
@pytest.mark.parametrize("prepared", [False, True],
                         ids=["missing_inputs", "fully_prepared"])
async def test_b2b_proposal_post_refuses_execution_unavailable_no_writes(
        tmp_path, monkeypatch, prepared, opened):
    """POST refusal E2E: a REAL aiohttp authenticated POST, a REAL signed
    loopback source resolving a REAL session on a REAL durable store —
    refused 503 execution_unavailable whether preparation is missing or
    complete (the C1 producer is not integrated), on REPEATED requests, with
    zero b2b_binding/attempt/run/artifact rows and an unchanged session."""
    lane = _valid_admission_lane(
        tmp_path, monkeypatch, opened, prepared=prepared)
    adapter = lane.adapter
    try:
        for target in ("resolve_source",):
            monkeypatch.setattr(b2b, target, _tripwire(f"b2b.{target}"))
        monkeypatch.setattr(
            adapter, "_create_agent", _tripwire("_create_agent"))
        session_before = adapter._session_db.get_session(lane.session_id)
        counts_before = _store_counts(adapter._run_idempotency_store)
        changes_before = adapter._run_idempotency_store._conn.total_changes

        async with TestClient(TestServer(_app(adapter))) as client:
            for _ in range(2):
                resp = await client.post(
                    f"/p/hub/api/sessions/{lane.session_id}/b2b-proposal",
                    json={"attempt_id": lane.attempt_id,
                          "binding_digest": lane.binding},
                    headers={"Authorization": f"Bearer {_API_KEY}",
                             "Idempotency-Key": lane.attempt_id})
                payload = await resp.json()
                assert resp.status == 503, payload
                assert payload.get("error") == "execution_unavailable"
                assert payload.get("code") == "execution_unavailable"

        assert adapter._session_db.get_session(
            lane.session_id) == session_before
        counts = _store_counts(adapter._run_idempotency_store)
        assert counts["b2b_bindings"] == 0
        assert counts["b2b_attempts"] == 0
        assert counts["b2b_artifacts"] == 0
        assert counts["run_idempotency"] == counts_before["run_idempotency"]
        assert (adapter._run_idempotency_store._conn.total_changes
                == changes_before)
        for table in (adapter._run_streams, adapter._run_streams_created,
                      adapter._active_run_agents, adapter._active_run_tasks,
                      adapter._run_statuses):
            assert not table
    finally:
        lane.source.stop()
