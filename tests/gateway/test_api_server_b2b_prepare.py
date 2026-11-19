"""POST /p/<profile>/api/sessions/{id}/b2b-prepare — the prepare-only
attestation (lot N3): the SAME verified binding/session/attempt/source
identity and the SAME bounded context preparation as the admission path —
then a hard stop. The answer is a signed-exchange-correlated attestation
carrying the context proof digests and the ordered piece tuple; NOTHING is
admitted, titled, spawned, dispatched or durably written, and a replayed POST
simply re-attests.

Real aiohttp POST + REAL signed loopback source + REAL plugin discovery for
the producer (``memory_mode: none`` from the trusted catalogue). The
producer's returned view/documents are explicitly labelled UNIT DOUBLES —
never a real AgentContext/C1 build — and the no-memory path must never touch
Memory, a provider, or any network beyond the one loopback source exchange.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import re
import threading
import urllib.request
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp.test_utils import TestClient, TestServer

from agent.b2b_execution import (
    SOURCE_BASIS_CONTRACT, json_utf8)
from agent.memory_manager import MemoryManager
from gateway.config import PlatformConfig
from gateway.platforms import api_server_b2b as b2b
from gateway.platforms import api_server_b2b_context as b2b_ctx
from gateway.platforms.api_server import APIServerAdapter
from hermes_state import SessionDB
from tests.gateway import test_api_server_b2b_admission as adm
from tests.gateway.test_api_server_b2b_execution_lane import (
    _plugin_config, _write_fake_plugin)
from tests.gateway.b2b_process_harness import (
    UNIT_RENDERED, canonical, extract_contract_root, make_keypair)
from tools.memory_tool import MemoryStore

_API_KEY = adm._API_KEY
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_FROZEN_NOW = 1793361605.0  # inside the unit OC window [12:00:00, +10s)
_MISSION_ID = "mis_0123456789abcdef0123456789abcdef"
_PREPARATION_KEYS = frozenset({
    "object", "attempt_id", "binding_digest", "profile", "session_id",
    "requester_id", "project_id", "project_binding_id", "mission_id",
    "mission_revision", "status", "run_id", "model_scheduled", "prepared_at",
    "context_digest", "view_digest", "source_basis_contract",
    "source_basis_digest", "rendered_digest", "source_request_id",
    "source_request_digest", "documents"})


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


def _never(name):
    def _raise(*a, **k):
        raise AssertionError(f"{name} must not run on the prepare-only path")
    return _raise


# ---------------------------------------------------------------------------
# The producer: REAL directory plugin discovered through the genuine manager —
# its returned view/documents are UNIT DOUBLES on the pinned r2 blobs.
# ---------------------------------------------------------------------------

_PLUGIN_NAME = "unitctx-n3"

_PREPARE_PLUGIN_INIT = '''\
def register(ctx):
    def prepare_context(*, execution):
        from agent.b2b_execution import B2BTerminalRefusal
        from tests.agent.test_b2b_execution import _no_memory_view
        from tests.gateway.b2b_process_harness import (
            UNIT_RENDERED, reseal_unit_context_view)
        stamp = ctx.get_config("preparation_stamp")

        def validate_configuration():
            if ctx.get_config("preparation_stamp") != stamp:
                raise B2BTerminalRefusal("b2b_policy_changed")
            return True

        view = _no_memory_view(execution.policy)
        view["mission_binding"]["source_digest"] = "c" * 64
        view["my_work"]["mission"]["source_digest"] = "c" * 64
        reseal_unit_context_view(view)
        result = {"view": view,
                  "rendered": UNIT_RENDERED,
                  "validate_configuration": validate_configuration}
        __RESULT_DOCUMENTS__
        return result
    prepare_context.b2b_memory_modes = ("none",)
    ctx.register_hook("prepare_context", prepare_context)
    ctx.register_hook("pre_llm_call", lambda **kwargs: None)
'''


def _plugin_init(*, documents=None):
    return _PREPARE_PLUGIN_INIT.replace(
        "__RESULT_DOCUMENTS__",
        "pass" if documents is None
        else f"result[\"documents\"] = {documents!r}")


def _doc(piece_id, text, *, mission=_MISSION_ID):
    digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    return {"id": piece_id, "revision": 1, "text": text,
            "content_digest": digest,
            "native_ref": f"dubsar:piece:{mission}:{piece_id}",
            "native_digest": digest}


def _proofs(documents):
    """The ordered (ref, digest) pairs both proof lists must carry."""
    refs = []
    for document in documents:
        refs += [document["native_ref"], document["native_digest"]]
    return refs


def _prepare_lane(tmp_path, monkeypatch, opened, *, plugin_init,
                  source_refs=()):
    """REAL signed loopback lane for prepare-only: every operator input on
    disk (pinned contract root, My Work roots, inert serving config), the
    project pinned ``memory_mode:none``, the producer written as a REAL
    directory plugin under the profile home, and a source body journaling the
    signed request's ``purpose``. The genesis observation is the fixed empty
    snapshot so native-session drift is exercised through the real checks."""
    prof = adm._profile_home(tmp_path, monkeypatch, "hub")
    portal_priv, _, portal_pub = make_keypair()
    hermes_priv, hermes_priv_pem, hermes_pub = make_keypair()
    requester_id = "1" * 24
    project_id = "b2b-bench"
    basis = {"format": "dubsar.b2b-agent-session-binding/1",
             "requester_id": requester_id, "project_id": project_id,
             "mission_id": _MISSION_ID, "mission_revision": 1}
    binding = hashlib.sha256(canonical(basis)).hexdigest()
    session_id = "b2b_" + binding
    attempt_id = b2b._attempt_id_for(binding)

    alloc = tmp_path / "mywork-alloc"
    start = tmp_path / "mywork-start"
    alloc.mkdir()
    start.mkdir()
    project = {"project_id": project_id, "bot_id": "bot", "profile_id": "hub",
               "allowed_namespaces": ["ns"],
               "context_contract_root": extract_contract_root(tmp_path),
               "model": "unit-double", "provider": "custom",
               "base_url": "http://127.0.0.1:9/v1",
               "api_mode": "chat_completions",
               "logical_mission": None,
               "project_context": {
                   "allocation_root": str(alloc), "project_id": project_id,
                   "start": str(start)},
               "memory_mode": "none"}
    (prof / "config.yaml").write_text(
        "model:\n  context_length: 256000\ncompression:\n  enabled: false\n")
    if plugin_init is not None:
        _write_fake_plugin(prof, name=_PLUGIN_NAME, init=plugin_init)
        _plugin_config(prof, names=(_PLUGIN_NAME,))

    lane = SimpleNamespace(purposes=[], request_envs=[])

    def _body_for(request_env):
        req = request_env["body"]
        lane.purposes.append(req.get("purpose"))
        lane.request_envs.append(request_env)
        obs = {
            "id": req["session_id"], "source": "api_server", "title": None,
            "model": None, "parent_session_id": None,
            "has_system_prompt": False, "has_model_config": False,
            "ended_at": None, "end_reason": None, "message_count": 0,
            "tool_call_count": 0, "api_call_count": 0, "profile": "hub"}
        return {
            "attempt_id": req["attempt_id"], "profile": "hub",
            "session_id": req["session_id"], "binding_digest": binding,
            "source_state": "active",
            "reservation_ref": {"collection": "dubsar_b2b_agent_sessions",
                                "id": binding},
            "requester_id": requester_id, "project_id": project_id,
            "project_binding_id": project_id, "mission_id": _MISSION_ID,
            "mission_revision": 1,
            "request_digest": "d" * 64, "mission_source_digest": "c" * 64,
            "ticket_digest": "e" * 64,
            "authority_basis_digest": "sha256:" + "b" * 64,
            "authority_digest": "sha256:" + "a" * 64,
            "observation_genesis": obs,
            "mission_request": {"title": "m", "objective": "o",
                                "criteria": ["c"],
                                "source_refs": list(source_refs)},
            "source_request_id": request_env["request_id"],
            "source_request_digest": hashlib.sha256(
                canonical(request_env)).hexdigest()}

    source = adm._SourceDouble(
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
    lane.prof = prof
    lane.hermes_priv = hermes_priv
    lane.session_id = session_id
    lane.attempt_id = attempt_id
    lane.binding = binding
    lane.requester_id = requester_id
    lane.project_id = project_id
    lane.mission_id = _MISSION_ID
    lane.mission_revision = 1
    return lane


def _prepare_headers(attempt_id):
    return {"Authorization": f"Bearer {_API_KEY}",
            "Idempotency-Key": attempt_id}


def _prepare_body(attempt_id, binding):
    """The closed three-key prepare body — the caller-minted UUIDv4
    ``request_id`` the signed attestation must echo exactly."""
    return {"attempt_id": attempt_id, "binding_digest": binding,
            "request_id": str(uuid.uuid4())}


def _memory_forbids(monkeypatch):
    """The no-memory path's zero-IO tripwires (the loopback source exchange
    aside): neither Memory plumbing nor any URL fetch may run."""
    hits = []

    def forbid(*args, **kwargs):
        hits.append(True)
        raise AssertionError(
            "prepare-only must not read Memory or fetch any URL")

    monkeypatch.setattr(MemoryStore, "load_from_disk", forbid)
    monkeypatch.setattr(MemoryManager, "prefetch_all", forbid)
    monkeypatch.setattr(urllib.request, "urlopen", forbid)
    return hits


def _freeze_oc_window(monkeypatch):
    """The unit OC view's source instant is fixed; freeze the governed clock
    inside its freshness window (the signed envelopes stay REAL)."""
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: _FROZEN_NOW))


def _run_tables_empty(adapter):
    for table in (adapter._run_streams, adapter._run_streams_created,
                  adapter._active_run_agents, adapter._active_run_tasks,
                  adapter._run_statuses):
        assert not table


# ---------------------------------------------------------------------------
# The attestation — 200/prepared with ZERO durable or native writes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_b2b_prepare_post_attests_preparation_with_zero_writes(
        tmp_path, monkeypatch, opened):
    """E2E: a REAL authenticated POST through a REAL signed loopback exchange
    (purpose ``prepare`` journaled) attests the qualified no-memory context —
    ``status:"prepared"``, ``run_id:null``, ``model_scheduled:false`` — and
    leaves NO binding/attempt/run/artifact row, no title, no session change,
    on REPEATED requests (replay re-attests, nothing is consumed)."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    adapter = lane.adapter
    try:
        _freeze_oc_window(monkeypatch)
        memory_io = _memory_forbids(monkeypatch)
        for target in ("_launch_b2b_run", "_spawn_run", "resolve_source"):
            monkeypatch.setattr(b2b, target, _never(f"b2b.{target}"))
        store = adapter._run_idempotency_store
        monkeypatch.setattr(store, "b2b_admit", _never("b2b_admit"))
        monkeypatch.setattr(
            store, "b2b_update_attempt", _never("b2b_update_attempt"))
        monkeypatch.setattr(
            adapter._session_db, "set_session_title",
            _never("set_session_title"))
        monkeypatch.setattr(adapter, "_create_agent", _never("_create_agent"))
        monkeypatch.setattr(
            adapter, "_concurrency_limited_response",
            _never("_concurrency_limited_response"))
        import run_agent
        monkeypatch.setattr(run_agent, "AIAgent", _never("AIAgent"))

        session_before = adapter._session_db.get_session(lane.session_id)
        counts_before = adm._store_counts(store)
        changes_before = store._conn.total_changes

        payloads = []
        posted = []
        async with TestClient(TestServer(adm._app(adapter))) as client:
            # Process-cold first request: plugin discovery + bounded-worker
            # machinery warm up once per process — a cold 1s-budget overrun
            # would be an environment flake, not a behavioral result, so this
            # warmup POST carries no assertion (zero writes either way).
            await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=_prepare_body(lane.attempt_id, lane.binding),
                headers=_prepare_headers(lane.attempt_id))
            for _ in range(2):
                sent = _prepare_body(lane.attempt_id, lane.binding)
                posted.append(sent)
                resp = await client.post(
                    f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                    json=sent,
                    headers=_prepare_headers(lane.attempt_id))
                payloads.append(await resp.json())
                assert resp.status == 200, payloads[-1]

        # The answer is a REAL signed envelope — cryptographically verified
        # here with the lane's own public key, never trusted on shape alone.
        # request_envs[0] is the warmup exchange; each asserted POST pairs
        # with its own fresh signed source exchange.
        first_env, second_env = payloads
        for envelope, sent, request_env in zip(
                (first_env, second_env), posted, lane.request_envs[1:]):
            assert set(envelope) == b2b._ENVELOPE_KEYS
            assert envelope["version"] == b2b._VERSION
            assert envelope["operation"] == "prepared"
            assert envelope["issuer"] == "hermes-hub"
            assert envelope["audience"] == "portal-hub"
            assert envelope["request_id"] == sent["request_id"]
            assert (isinstance(envelope["issued_at"], int)
                    and not isinstance(envelope["issued_at"], bool)
                    and isinstance(envelope["expires_at"], int)
                    and not isinstance(envelope["expires_at"], bool)
                    and envelope["issued_at"] < envelope["expires_at"])
            unsigned = {key: value for key, value in envelope.items()
                        if key != "signature"}
            lane.hermes_priv.public_key().verify(
                base64.urlsafe_b64decode(envelope["signature"] + "=="),
                b2b._DOMAIN + canonical(unsigned))
            body = envelope["body"]
            assert body["source_request_id"] == request_env["request_id"]
            assert body["source_request_digest"] == hashlib.sha256(
                canonical(request_env)).hexdigest()

        first, second = first_env["body"], second_env["body"]
        assert set(first) == _PREPARATION_KEYS
        assert first["object"] == "b2b.preparation"
        assert first["status"] == "prepared"
        assert first["run_id"] is None
        assert first["model_scheduled"] is False
        assert first["attempt_id"] == lane.attempt_id
        assert first["binding_digest"] == lane.binding
        assert first["profile"] == "hub"
        assert first["session_id"] == lane.session_id
        assert first["requester_id"] == lane.requester_id
        assert first["project_id"] == lane.project_id
        assert first["project_binding_id"] == lane.project_id
        assert first["mission_id"] == lane.mission_id
        assert first["mission_revision"] == lane.mission_revision
        assert first["source_basis_contract"] == SOURCE_BASIS_CONTRACT
        for key in ("context_digest", "view_digest", "source_basis_digest",
                    "rendered_digest", "source_request_digest"):
            assert _HEX64.fullmatch(first[key]), key
        assert _ISO_Z.fullmatch(first["prepared_at"])
        assert (isinstance(first["source_request_id"], str)
                and first["source_request_id"])
        assert first["documents"] == []
        # The rendered digest commits to the exact bytes the producer sealed.
        assert first["rendered_digest"] == hashlib.sha256(
            UNIT_RENDERED.encode("utf-8")).hexdigest()
        # Replay re-attests the same attempt under a fresh signed exchange —
        # never a consumed single-use answer.
        assert set(second) == _PREPARATION_KEYS
        assert second["status"] == "prepared"
        assert second["attempt_id"] == lane.attempt_id
        assert second["binding_digest"] == lane.binding
        assert second["context_digest"] == first["context_digest"]

        # Three exchanges, every purpose exactly "prepare" — never "bind".
        assert lane.purposes == ["prepare", "prepare", "prepare"]
        # Zero durable writes, zero native session mutation, no run plumbing.
        assert adapter._session_db.get_session(lane.session_id) == session_before
        assert adm._store_counts(store) == counts_before
        assert store._conn.total_changes == changes_before
        _run_tables_empty(adapter)
        assert memory_io == []
    finally:
        lane.source.stop()


@pytest.mark.asyncio
async def test_b2b_prepare_post_attests_ordered_documents(
        tmp_path, monkeypatch, opened):
    """The producer's structured piece attestation is re-proven host-side and
    echoed as the ordered (native_ref, revision, digest) tuple — the mission
    fingerprints the lot requires, without parsing rendered text."""
    documents = [_doc("piece_" + "1" * 32, "première pièce é"),
                 _doc("piece_" + "2" * 32, "deuxième pièce")]
    lane = _prepare_lane(
        tmp_path, monkeypatch, opened,
        plugin_init=_plugin_init(documents=documents),
        source_refs=_proofs(documents))
    adapter = lane.adapter
    try:
        _freeze_oc_window(monkeypatch)
        monkeypatch.setattr(b2b, "_spawn_run", _never("_spawn_run"))
        monkeypatch.setattr(adapter._session_db, "set_session_title",
                            _never("set_session_title"))
        store = adapter._run_idempotency_store
        counts_before = adm._store_counts(store)
        async with TestClient(TestServer(adm._app(adapter))) as client:
            resp = await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=_prepare_body(lane.attempt_id, lane.binding),
                headers=_prepare_headers(lane.attempt_id))
            payload = await resp.json()
            assert resp.status == 200, payload
        assert payload["operation"] == "prepared"
        assert payload["body"]["documents"] == [
            {"native_ref": d["native_ref"], "revision": 1,
             "digest": d["native_digest"]} for d in documents]
        assert adm._store_counts(store) == counts_before
        assert adapter._session_db.get_session(
            lane.session_id)["title"] is None
    finally:
        lane.source.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", [
    "digest_mismatch", "extra_key", "foreign_ref", "missing_proof",
    "proof_order", "not_list", "bad_unicode"])
async def test_b2b_prepare_post_refuses_invalid_documents(
        tmp_path, monkeypatch, opened, case):
    """A malformed, drifted or unproven document attestation refuses closed —
    503 with zero durable writes — never a partial attestation."""
    base = _doc("piece_" + "1" * 32, "contenu")
    if case == "digest_mismatch":
        broken = dict(base, content_digest="sha256:" + "0" * 64)
        documents, refs = [broken], _proofs([base])
    elif case == "extra_key":
        documents, refs = [dict(base, extra=1)], _proofs([base])
    elif case == "foreign_ref":
        foreign = _doc("piece_" + "1" * 32, "contenu",
                       mission="mis_" + "9" * 32)
        documents, refs = [foreign], _proofs([base])
    elif case == "missing_proof":
        documents, refs = [], _proofs([base])
    elif case == "proof_order":
        documents = [base]
        refs = [base["native_digest"], base["native_ref"]]
    elif case == "bad_unicode":
        documents, refs = [dict(base, text="\ud800")], _proofs([base])
    else:  # not_list
        documents, refs = "not-a-list", _proofs([base])
    lane = _prepare_lane(
        tmp_path, monkeypatch, opened,
        plugin_init=_plugin_init(documents=documents), source_refs=refs)
    adapter = lane.adapter
    try:
        _freeze_oc_window(monkeypatch)
        monkeypatch.setattr(b2b, "_spawn_run", _never("_spawn_run"))
        store = adapter._run_idempotency_store
        counts_before = adm._store_counts(store)
        changes_before = store._conn.total_changes
        async with TestClient(TestServer(adm._app(adapter))) as client:
            resp = await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=_prepare_body(lane.attempt_id, lane.binding),
                headers=_prepare_headers(lane.attempt_id))
            payload = await resp.json()
            assert resp.status == 503, payload
            assert payload.get("error") == "context_documents"
            assert payload.get("code") == "context_documents"
        assert adm._store_counts(store) == counts_before
        assert store._conn.total_changes == changes_before
        assert adapter._session_db.get_session(
            lane.session_id)["title"] is None
    finally:
        lane.source.stop()


# ---------------------------------------------------------------------------
# Refusals — typed surface, always before any durable effect
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("reason,status", [
    ("source_denied", 403), ("source_unavailable", 503)])
async def test_b2b_prepare_post_source_refusal_classifies(
        tmp_path, monkeypatch, opened, reason, status):
    """A signed-source refusal lands as the classified denial BEFORE any
    preparation — repeated POSTs stay non-consuming."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    adapter = lane.adapter
    try:
        async def _refuse(*a, **k):
            return None, reason

        monkeypatch.setattr(b2b, "_resolve_source_async", _refuse)
        monkeypatch.setattr(
            b2b, "_prepare_b2b_only", _never("_prepare_b2b_only"))
        monkeypatch.setattr(b2b, "_spawn_run", _never("_spawn_run"))
        store = adapter._run_idempotency_store
        counts_before = adm._store_counts(store)
        async with TestClient(TestServer(adm._app(adapter))) as client:
            for _ in range(2):
                resp = await client.post(
                    f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                    json=_prepare_body(lane.attempt_id, lane.binding),
                    headers=_prepare_headers(lane.attempt_id))
                payload = await resp.json()
                assert resp.status == status, payload
                assert payload.get("error") == reason
        assert adm._store_counts(store) == counts_before
    finally:
        lane.source.stop()


@pytest.mark.asyncio
async def test_b2b_prepare_post_without_producer_refuses(
        tmp_path, monkeypatch, opened):
    """No registered producer -> 503 execution_unavailable with zero writes
    (the exchange still happened with purpose ``prepare``)."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened, plugin_init=None)
    adapter = lane.adapter
    try:
        monkeypatch.setattr(b2b, "_spawn_run", _never("_spawn_run"))
        store = adapter._run_idempotency_store
        counts_before = adm._store_counts(store)
        async with TestClient(TestServer(adm._app(adapter))) as client:
            resp = await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=_prepare_body(lane.attempt_id, lane.binding),
                headers=_prepare_headers(lane.attempt_id))
            payload = await resp.json()
            assert resp.status == 503, payload
            assert payload.get("error") == "execution_unavailable"
        assert lane.purposes == ["prepare"]
        assert adm._store_counts(store) == counts_before
    finally:
        lane.source.stop()


@pytest.mark.asyncio
async def test_b2b_prepare_post_already_admitted_refuses(
        tmp_path, monkeypatch, opened):
    """A durable binding+attempt on the tuple makes the prepare path refuse
    409 — the attestation of record is the historical read, never a second
    minted answer."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    adapter = lane.adapter
    store = adapter._run_idempotency_store
    try:
        run_id = "run_" + "f" * 32
        admission = store.b2b_admit(
            profile="hub", session_id=lane.session_id,
            binding_digest=lane.binding, attempt_id=lane.attempt_id,
            fingerprint="fp",
            binding_row={"profile": "hub", "session_id": lane.session_id,
                         "binding_digest": lane.binding, "policy_json": "{}"},
            attempt_row={"attempt_id": lane.attempt_id,
                         "binding_digest": lane.binding, "profile": "hub",
                         "session_id": lane.session_id, "status": "admitted",
                         "run_id": run_id, "requester_id": lane.requester_id,
                         "source_bind": json_utf8(
                             {"response": {"body": {}}})},
            run_scope="b2b:" + lane.attempt_id, run_key=lane.attempt_id,
            run_id=run_id, run_fingerprint="fp",
            run_status={"session_id": lane.session_id, "status": "running"},
            owner_pid=os.getpid(), owner_started=0)
        assert admission["status"] == "admitted"
        monkeypatch.setattr(b2b, "_spawn_run", _never("_spawn_run"))
        counts_before = adm._store_counts(store)
        async with TestClient(TestServer(adm._app(adapter))) as client:
            resp = await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=_prepare_body(lane.attempt_id, lane.binding),
                headers=_prepare_headers(lane.attempt_id))
            payload = await resp.json()
            assert resp.status == 409, payload
            assert payload.get("error") == "already_admitted"
        assert adm._store_counts(store) == counts_before
    finally:
        lane.source.stop()


@pytest.mark.asyncio
async def test_b2b_prepare_post_mutated_session_refuses(
        tmp_path, monkeypatch, opened):
    """A session that is no longer the empty genesis row refuses 409
    genesis_native — the source still resolved (purpose ``prepare``), but
    preparation and durable writes never happen."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    adapter = lane.adapter
    try:
        adapter._session_db.set_session_title(lane.session_id, "titled")
        monkeypatch.setattr(b2b, "_spawn_run", _never("_spawn_run"))
        store = adapter._run_idempotency_store
        counts_before = adm._store_counts(store)
        async with TestClient(TestServer(adm._app(adapter))) as client:
            resp = await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=_prepare_body(lane.attempt_id, lane.binding),
                headers=_prepare_headers(lane.attempt_id))
            payload = await resp.json()
            assert resp.status == 409, payload
            assert payload.get("error") == "genesis_native"
        assert lane.purposes == ["prepare"]
        assert adm._store_counts(store) == counts_before
    finally:
        lane.source.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value,status", [
    ("binding_digest", "0" * 64, 403),
    ("attempt_id", "not-an-attempt", 400),
])
async def test_b2b_prepare_post_identity_mismatch_refuses(
        tmp_path, monkeypatch, opened, field, value, status):
    """The closed body must echo the URL-derived tuple: a wrong
    binding_digest or a malformed attempt_id refuses before the exchange."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    adapter = lane.adapter
    try:
        body = _prepare_body(lane.attempt_id, lane.binding)
        body[field] = value
        monkeypatch.setattr(
            b2b, "_resolve_source_async", _never("_resolve_source_async"))
        store = adapter._run_idempotency_store
        counts_before = adm._store_counts(store)
        async with TestClient(TestServer(adm._app(adapter))) as client:
            resp = await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=body, headers=_prepare_headers(lane.attempt_id))
            assert resp.status == status, await resp.text()
        assert lane.purposes == []
        assert adm._store_counts(store) == counts_before
    finally:
        lane.source.stop()


@pytest.mark.asyncio
async def test_b2b_prepare_post_foreign_attempt_refuses(
        tmp_path, monkeypatch, opened):
    """A regex-valid attempt_id FOREIGN to the binding tuple survives request
    parsing but fails the resolved-body pin (attempt_id ==
    _attempt_id_for(binding)) — the exchange is journaled, the answer is the
    classified 403, nothing is written."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    adapter = lane.adapter
    try:
        foreign = "b2bp_" + "0" * 64
        monkeypatch.setattr(
            b2b, "_prepare_b2b_only", _never("_prepare_b2b_only"))
        store = adapter._run_idempotency_store
        counts_before = adm._store_counts(store)
        async with TestClient(TestServer(adm._app(adapter))) as client:
            resp = await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=_prepare_body(foreign, lane.binding),
                headers=_prepare_headers(foreign))
            payload = await resp.json()
            assert resp.status == 403, payload
            assert payload.get("error") == "source_denied"
        assert lane.purposes == ["prepare"]
        assert adm._store_counts(store) == counts_before
    finally:
        lane.source.stop()


@pytest.mark.asyncio
async def test_b2b_prepare_post_idempotency_key_required(
        tmp_path, monkeypatch, opened):
    """A missing/wrong Idempotency-Key refuses 400 before the exchange."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    adapter = lane.adapter
    try:
        monkeypatch.setattr(
            b2b, "_resolve_source_async", _never("_resolve_source_async"))
        async with TestClient(TestServer(adm._app(adapter))) as client:
            resp = await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=_prepare_body(lane.attempt_id, lane.binding),
                headers={"Authorization": f"Bearer {_API_KEY}",
                         "Idempotency-Key": "wrong"})
            assert resp.status == 400, await resp.text()
        assert lane.purposes == []
    finally:
        lane.source.stop()


# ---------------------------------------------------------------------------
# Boundaries — the new purpose, the new refusal reason, route registration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_prepare_purpose_accepted_unknown_refused(
        tmp_path, monkeypatch, opened):
    """``_resolve_source_async`` admits exactly the new ``prepare`` purpose on
    the real signed exchange; an unknown purpose refuses before any IO."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    entry = lane.adapter._b2b_state.config.profile_entry("hub")
    keys = lane.adapter._b2b_state.keys["hub"]
    try:
        resolved, reason = await b2b._resolve_source_async(
            entry, keys, "prepare", attempt_id=lane.attempt_id,
            profile="hub", session_id=lane.session_id)
        assert reason == "ok" and resolved is not None
        assert resolved["attempt_id"] == lane.attempt_id
        assert lane.purposes == ["prepare"]
        resolved, reason = await b2b._resolve_source_async(
            entry, keys, "bogus", attempt_id=lane.attempt_id,
            profile="hub", session_id=lane.session_id)
        assert resolved is None and reason == "purpose"
        assert lane.purposes == ["prepare"]  # no second exchange
    finally:
        lane.source.stop()


def test_prepare_route_registered(tmp_path, monkeypatch):
    """The route table exposes the prepare-only POST (mirrored under /p/)."""
    adapter = adm._adapter(tmp_path, monkeypatch, "hub")
    paths = {(method, path) for method, path, _ in b2b.b2b_http_routes(adapter)}
    assert ("POST", "/api/sessions/{session_id}/b2b-prepare") in paths


# ---------------------------------------------------------------------------
# N3 pass 2 — request_id contract, last-mile race, shared document gate,
# hydration placement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("mutate,error", [
    pytest.param(lambda body: body.pop("request_id"), "invalid_body",
                 id="missing"),
    pytest.param(lambda body: body.update(extra=1), "invalid_body",
                 id="extra_key"),
    pytest.param(lambda body: body.update(request_id="not-a-uuid"),
                 "invalid_request_id", id="not_uuid"),
    pytest.param(lambda body: body.update(request_id=12345),
                 "invalid_request_id", id="not_str"),
    pytest.param(lambda body: body.update(
        request_id="00000000-0000-1000-8000-000000000000"),
        "invalid_request_id", id="not_v4"),
    pytest.param(lambda body: body.update(
        request_id="123e4567-e89b-42d3-a456-426614174000".upper()),
        "invalid_request_id", id="uppercase"),
])
async def test_b2b_prepare_post_request_id_validation(
        tmp_path, monkeypatch, opened, mutate, error):
    """The prepare body is a closed three-key shape whose ``request_id`` is
    a bounded UUIDv4 — anything else refuses 400 BEFORE the source exchange
    or any durable effect."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    adapter = lane.adapter
    try:
        body = _prepare_body(lane.attempt_id, lane.binding)
        mutate(body)
        monkeypatch.setattr(
            b2b, "_resolve_source_async", _never("_resolve_source_async"))
        store = adapter._run_idempotency_store
        counts_before = adm._store_counts(store)
        async with TestClient(TestServer(adm._app(adapter))) as client:
            resp = await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=body, headers=_prepare_headers(lane.attempt_id))
            payload = await resp.json()
            assert resp.status == 400, payload
            assert payload["error"] == error
        assert lane.purposes == []
        assert adm._store_counts(store) == counts_before
    finally:
        lane.source.stop()


@pytest.mark.asyncio
async def test_b2b_prepare_post_refuses_when_proposal_admits_mid_preparation(
        tmp_path, monkeypatch, opened):
    """Last-mile race: a proposal that admits the same tuple while THIS
    prepare is held AFTER its real bounded preparation makes the prepare
    answer 409 already_admitted — never a stale signed attestation minted
    beside an owned admission."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    adapter = lane.adapter
    store = adapter._run_idempotency_store
    entered = asyncio.Event()
    release = asyncio.Event()
    original = b2b._b2b_run_bounded_preparation

    async def _gated(_adapter, *, profile, project, cap, sink, resolved):
        denied = await original(
            _adapter, profile=profile, project=project, cap=cap, sink=sink,
            resolved=resolved)
        if (resolved["_signed_request"]["body"]["purpose"] == "prepare"
                and denied is None):
            entered.set()
            await release.wait()
        return denied

    spawn_calls = []

    async def _spawn_spy(*a, **k):
        spawn_calls.append((a, k))
        return SimpleNamespace(done=lambda: True)

    try:
        _freeze_oc_window(monkeypatch)
        monkeypatch.setattr(b2b, "_b2b_run_bounded_preparation", _gated)
        monkeypatch.setattr(b2b, "_spawn_run", _spawn_spy)
        async with TestClient(TestServer(adm._app(adapter))) as client:
            prepare_task = asyncio.ensure_future(client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=_prepare_body(lane.attempt_id, lane.binding),
                headers=_prepare_headers(lane.attempt_id)))
            try:
                await asyncio.wait_for(entered.wait(), 30)
                admitted = await client.post(
                    f"/p/hub/api/sessions/{lane.session_id}/b2b-proposal",
                    json={"attempt_id": lane.attempt_id,
                          "binding_digest": lane.binding},
                    headers=_prepare_headers(lane.attempt_id))
                admitted_payload = await admitted.json()
                assert admitted.status == 200, admitted_payload
                assert admitted_payload["status"] == "admitted"
            finally:
                release.set()
            response = await prepare_task
            payload = await response.json()
            assert response.status == 409, payload
            assert payload["error"] == "already_admitted"
        # Exactly one run was scheduled — the proposal's — and the prepare
        # minted no attestation beside the owned admission.
        assert len(spawn_calls) == 1
        assert lane.purposes == ["prepare", "bind"]
        assert store.b2b_binding(
            session_id=lane.session_id, profile="hub") is not None
        assert store.b2b_attempt(
            profile="hub", attempt_id=lane.attempt_id) is not None
    finally:
        lane.source.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("has_manifest", [False, True])
async def test_b2b_proposal_post_gates_cited_documents(
        tmp_path, monkeypatch, opened, has_manifest):
    """The SAME document proof bar gates b2b-proposal as b2b-prepare — a
    piece cited in the signed mission_request without a verified manifest
    refuses 503 context_documents BEFORE admission; a verified manifest
    admits and spawns exactly once."""
    document = _doc("piece_" + "1" * 32, "pièce citée")
    lane = _prepare_lane(
        tmp_path, monkeypatch, opened,
        plugin_init=_plugin_init(
            documents=[document] if has_manifest else None),
        source_refs=_proofs([document]))
    adapter = lane.adapter
    store = adapter._run_idempotency_store
    spawn_calls = []

    async def _spawn_spy(*a, **k):
        spawn_calls.append((a, k))
        return SimpleNamespace(done=lambda: True)

    try:
        _freeze_oc_window(monkeypatch)
        monkeypatch.setattr(b2b, "_spawn_run", _spawn_spy)
        counts_before = adm._store_counts(store)
        async with TestClient(TestServer(adm._app(adapter))) as client:
            resp = await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-proposal",
                json={"attempt_id": lane.attempt_id,
                      "binding_digest": lane.binding},
                headers=_prepare_headers(lane.attempt_id))
            payload = await resp.json()
        assert lane.purposes == ["bind"]
        if has_manifest:
            assert resp.status == 200, payload
            assert payload["status"] == "admitted"
            assert len(spawn_calls) == 1
            assert store.b2b_binding(
                session_id=lane.session_id, profile="hub") is not None
            assert store.b2b_attempt(
                profile="hub", attempt_id=lane.attempt_id) is not None
        else:
            assert resp.status == 503, payload
            assert payload["error"] == "context_documents"
            assert spawn_calls == []
            assert adm._store_counts(store) == counts_before
            assert adapter._session_db.get_session(
                lane.session_id)["title"] is None
    finally:
        lane.source.stop()


def _record_secret_scope_loads(monkeypatch):
    """EXTERNAL SEAM — wrap the real profile secret loader, recording
    ``(home, thread)`` per call: hydration placement is proven by WHERE the
    loader ran, never by a mocked scope."""
    import gateway.run as _run
    calls = []
    real_load = _run._load_profile_secret_scope

    def load(home):
        calls.append((Path(home).resolve(), threading.current_thread()))
        return real_load(home)

    monkeypatch.setattr(_run, "_load_profile_secret_scope", load)
    return calls


@pytest.mark.asyncio
async def test_b2b_prepare_route_never_hydrates_on_loop(
        tmp_path, monkeypatch, opened):
    """Multiplex regression (A→B→A): unauthenticated prepare POSTs to two
    served profiles are denied with ZERO profile-secret hydration on the
    loop — hydration belongs to the bounded bootstrap worker, never the
    profile-prefix middleware's request scope."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    adapter = lane.adapter
    adapter.gateway_runner.config.multiplex_profiles = True
    beta = tmp_path / "homes" / "profiles" / "beta"
    beta.mkdir(parents=True)
    (beta / "config.yaml").write_text(
        "model:\n  context_length: 256000\n")
    calls = _record_secret_scope_loads(monkeypatch)
    try:
        async with TestClient(TestServer(adm._app(adapter))) as client:
            for profile in ("hub", "beta", "hub"):
                resp = await client.post(
                    f"/p/{profile}/api/sessions/"
                    f"{lane.session_id}/b2b-prepare",
                    json=_prepare_body(lane.attempt_id, lane.binding))
                assert resp.status == 401, await resp.text()
        assert calls == []
        assert lane.purposes == []
    finally:
        lane.source.stop()


@pytest.mark.asyncio
async def test_b2b_prepare_valid_request_hydrates_on_worker(
        tmp_path, monkeypatch, opened):
    """A VALID multiplexed prepare hydrates the profile secret scope ONLY on
    the bounded bootstrap worker — the middleware scope and the handler's
    own awaits never run the loader on the loop thread."""
    lane = _prepare_lane(tmp_path, monkeypatch, opened,
                         plugin_init=_plugin_init())
    adapter = lane.adapter
    adapter.gateway_runner.config.multiplex_profiles = True
    # The profile-scoped API_SERVER_KEY the multiplexed auth check reads —
    # a real .env inside the lane's real profile home.
    (lane.prof / ".env").write_text(f"API_SERVER_KEY={_API_KEY}\n")
    calls = _record_secret_scope_loads(monkeypatch)
    loop_thread = threading.current_thread()
    try:
        _freeze_oc_window(monkeypatch)
        monkeypatch.setattr(b2b, "_spawn_run", _never("_spawn_run"))
        async with TestClient(TestServer(adm._app(adapter))) as client:
            resp = await client.post(
                f"/p/hub/api/sessions/{lane.session_id}/b2b-prepare",
                json=_prepare_body(lane.attempt_id, lane.binding),
                headers=_prepare_headers(lane.attempt_id))
            payload = await resp.json()
            assert resp.status == 200, payload
        assert lane.purposes == ["prepare"]
        assert calls != []
        assert all(home == lane.prof.resolve() and thread is not loop_thread
                   for home, thread in calls)
    finally:
        lane.source.stop()
