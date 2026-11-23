"""Lot-1 native N2 lane: REAL boundary tests, no doubles for the verified data.

Every proof here crosses the product boundary: real Ed25519 request/response
envelopes signed and verified through ``_signed_envelope`` / ``_verify_envelope``
on a real loopback aiohttp source, the native body shape verifier, the real
``_AttemptSink._matches_source`` (with a real ``_B2BState``/fingerprint), the
protected manifest reader, the canonical ``_b2b_documents`` host check through a
real ``BoundExecution``, and the ``assert_terminal_runtime`` recipe gate through
the real ``bind_execution`` contextvar.

Protected-file tests use real Linux files and descriptors under a private
trusted root. They inject only the trusted root, boot-id path and expected
owner; reads, fstat/open, pins and schema validation remain real.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from agent.b2b_execution import (
    B2BTerminalRefusal, BoundExecution, assert_terminal_runtime, bind_execution,
    canonical_json, install_bounded_agent_policy, reset_execution,
)
from gateway.platforms import api_server_b2b as m
from gateway.platforms import api_server_b2b_native_authorization as native_auth
from gateway.platforms.api_server_b2b_context import _b2b_documents
from hermes_constants import get_hermes_home

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pem_priv = priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("utf-8")
    pem_pub = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
    return priv, pem_priv, pem_pub


PORTAL_PRIV, PORTAL_PRIV_PEM, PORTAL_PUB_PEM = _keypair()
HERMES_PRIV, HERMES_PRIV_PEM, _ = _keypair()

PORTAL_ISSUER = "portal-lot1-n2"
HERMES_ISSUER = "hermes/deploy"
TENANT = "tenant-alpha"
MISSION = "mis_" + "a" * 32
PROJECT = "prj_" + "b" * 32
LEGACY_ALIAS = "legacy-lane"
LEGACY_PROJECT = "legacy-prj-1"
REQUESTER = "5" * 24
MODEL = "b2b-g2/large-instruct"
BASE_URL = "http://127.0.0.1:8921/v1"


def _binding_for(project=PROJECT, mission=MISSION, requester=REQUESTER):
    basis = {"format": "dubsar.b2b-agent-session-binding/1",
             "requester_id": requester, "project_id": project,
             "mission_id": mission, "mission_revision": 1}
    return hashlib.sha256(canonical_json(basis)).hexdigest()


BINDING = _binding_for()
SESSION = "b2b_" + BINDING
ATTEMPT = m._attempt_id_for(BINDING)


def _docs(mission=MISSION, count=2):
    """Two real six-key piece manifests with genuine UTF-8 text digests."""
    out = []
    samples = ("pièce α — première", "pièce β — seconde")
    for index in range(count):
        text = samples[index] if index < len(samples) else f"pièce {index + 1} — donnée"
        piece = f"piece_{(index + 1):032x}"
        digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        out.append({
            "id": piece, "revision": 1, "text": text,
            "content_digest": digest, "native_digest": digest,
            "native_ref": f"dubsar:piece:{mission}:{piece}"})
    return out


def test_native_signed_refs_keep_twenty_originals_and_twenty_ordered_pairs():
    entry, keys = _entry_and_keys()
    for count in (10, 11, 20):
        documents = _docs(count=count)
        ordinary = [f"dubsar:mission:ref-{index}" for index in range(20)]
        refs = _flat(ordinary, documents)
        assert len(refs) == 20 + 2 * count
        assert m._valid_native_source_refs(refs, MISSION)
        resolved, reason = _resolve(
            entry, keys,
            respond=lambda env: _response_envelope(
                env, _resolved_body(env, docs=documents, refs=refs)))
        assert reason == "ok"
        assert resolved["mission_request"]["source_refs"] == refs

    documents = _docs(count=20)
    assert not m._valid_native_source_refs(
        _flat([f"ordinary-{index}" for index in range(21)], documents), MISSION)
    assert not m._valid_native_source_refs(
        _flat(["ordinary"], _docs(count=21)), MISSION)


def test_replay_only_admission_does_not_recreate_a_missing_attempt(tmp_path):
    from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore

    store = RunIdempotencyStore(str(tmp_path / "replay-only.sqlite3"))
    binding = "1" * 64
    session_id = "b2b_" + binding
    attempt_id = "b2bp_" + "2" * 64
    fingerprint = "3" * 64
    try:
        result = store.b2b_admit(
            profile="deploy", session_id=session_id, binding_digest=binding,
            attempt_id=attempt_id, fingerprint=fingerprint,
            binding_row={"profile": "deploy", "session_id": session_id,
                         "binding_digest": binding, "policy_json": "{}"},
            attempt_row={
                "profile": "deploy", "session_id": session_id,
                "binding_digest": binding, "attempt_id": attempt_id,
                "run_id": "run_" + "4" * 32, "status": "admitted",
                "requester_id": REQUESTER, "source_bind": "{}",
            },
            run_scope="b2b:deploy:unit", run_key=attempt_id,
            run_id="run_" + "4" * 32, run_fingerprint=fingerprint,
            run_status={"status": "queued", "session_id": session_id},
            replay_only=True)
        assert result == {"status": "conflict"}
        for table in ("run_idempotency", "b2b_attempts", "b2b_bindings", "b2b_artifacts"):
            assert store._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    finally:
        store.close()


def _flat(refs, docs):
    return list(refs) + [part for d in docs
                         for part in (d["native_ref"], d["native_digest"])]


def _observation(session_id):
    return {
        "id": session_id, "source": "api_server", "title": None,
        "model": None, "parent_session_id": None, "has_system_prompt": False,
        "has_model_config": False, "ended_at": None, "end_reason": None,
        "message_count": 0, "tool_call_count": 0, "api_call_count": 0,
        "profile": "deploy"}


def _manifest_digest(docs):
    return "sha256:" + hashlib.sha256(canonical_json(docs)).hexdigest()


def _pointer(docs=None, **over):
    pointer = {
        "inputs_revision": 3,
        "manifest_digest": _manifest_digest(_docs() if docs is None else docs),
        "inputs_digest": "sha256:" + "33" * 32}
    pointer.update(over)
    return pointer


def _project_entry(native=True, run_ref=None, project_id=PROJECT, **over):
    entry = {
        "project_id": project_id, "bot_id": "deploy", "profile_id": "deploy",
        "memory_mode": "none",
        "allowed_namespaces": ["private/bot/deploy"],
        "context_contract_root": None,
        "model": MODEL, "provider": "custom:b2b-g2",
        "base_url": BASE_URL, "api_mode": "chat_completions",
        "logical_mission": "alpha-default",
        "project_context": {"project_id": project_id,
                            "allocation_root": "/srv/alloc",
                            "start": "/srv/start"}}
    if native:
        entry["native_n2"] = {"tenant_id": TENANT}
        if run_ref is not None:
            entry["native_n2"]["run_authorization"] = dict(run_ref)
    entry.update(over)
    return entry


def _raw_config(source_port=21000, projects=None, profile_name="deploy"):
    if projects is None:
        projects = {PROJECT: _project_entry()}
    return {"enabled": True, "profiles": {profile_name: {
        "source_url": f"http://127.0.0.1:{source_port}/internal/dubsar/b2b/source",
        "portal_issuer": PORTAL_ISSUER, "hermes_issuer": HERMES_ISSUER,
        "portal_public_key_pem": PORTAL_PUB_PEM,
        "hermes_private_key_pem": HERMES_PRIV_PEM,
        "projects": projects}}}


class _SourceServer:
    """A real loopback aiohttp source: it receives the actual signed Hermes
    request bytes and answers with an actually-signed portal envelope."""

    def __init__(self, respond):
        self._respond = respond
        self.requests = []
        self.errors = []

    def __enter__(self):
        ready = threading.Event()
        self._loop = asyncio.new_event_loop()

        async def handle(request):
            from aiohttp import web
            raw = await request.read()
            try:
                envelope = json.loads(raw)
            except Exception:
                return web.Response(status=400)
            self.requests.append(envelope)
            try:
                reply = self._respond(envelope)
            except Exception as exc:
                self.errors.append(exc)
                return web.Response(status=500)
            if reply is None:
                return web.Response(status=403)
            return web.Response(
                status=200,
                text=json.dumps(reply, ensure_ascii=False,
                                separators=(",", ":")),
                content_type="application/json")

        def run():
            asyncio.set_event_loop(self._loop)

            async def main():
                from aiohttp import web
                app = web.Application()
                app.router.add_post("/internal/dubsar/b2b/source", handle)
                self._runner = web.AppRunner(app)
                await self._runner.setup()
                self._site = web.TCPSite(self._runner, "127.0.0.1", 0)
                await self._site.start()
                self.port = self._site._server.sockets[0].getsockname()[1]
                ready.set()

            self._loop.create_task(main())
            self._loop.run_forever()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert ready.wait(10), "source server did not start"
        return self

    def __exit__(self, *exc):
        async def cleanup():
            await self._runner.cleanup()

        asyncio.run_coroutine_threadsafe(cleanup(), self._loop).result(timeout=5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()


def _response_envelope(request_env, body):
    now = int(time.time())
    env = {"version": m._VERSION, "issuer": PORTAL_ISSUER,
           "audience": HERMES_ISSUER, "operation": "resolved",
           "request_id": request_env["request_id"], "issued_at": now,
           "expires_at": now + 15, "body": body}
    env["signature"] = m._b64url(
        PORTAL_PRIV.sign(m._DOMAIN + canonical_json(env)))
    return env


def _native_e2e_plugin_init(documents, ordinary_refs, native_references, rendered,
                            source_digest):
    return f'''\
def register(ctx):
    from agent.b2b_execution import B2BTerminalRefusal
    from tests.agent.test_b2b_execution import _no_memory_view
    from tests.gateway.b2b_process_harness import (
        reseal_unit_context_view, renew_unit_oc_read)
    documents = {documents!r}
    ordinary_refs = {ordinary_refs!r}
    native_references = {native_references!r}
    rendered = {rendered!r}
    source_digest = {source_digest!r}
    next_read_id = [2]

    def build_view(policy):
        view = _no_memory_view(policy)
        view["mission_binding"]["source_digest"] = source_digest
        view["my_work"]["mission"]["source_digest"] = source_digest
        view["my_work"]["mission"]["references"] = ordinary_refs
        view["bounds"]["render_chars"] = len(rendered)
        reseal_unit_context_view(view)
        fresh = renew_unit_oc_read(view, read_id=next_read_id[0])
        next_read_id[0] += 1
        return fresh

    def prepare_context(*, execution):
        stamp = ctx.get_config("preparation_stamp")
        def validate_configuration():
            if ctx.get_config("preparation_stamp") != stamp:
                raise B2BTerminalRefusal("b2b_policy_changed")
            return True
        return {{"view": build_view(execution.policy),
                "rendered": rendered,
                "documents": documents,
                "native_references": native_references,
                "validate_configuration": validate_configuration}}
    prepare_context.b2b_memory_modes = ("none",)

    def pre_llm_call(**kwargs):
        from agent.b2b_execution import current_execution
        cap = current_execution(profile="deploy")
        if cap is None or cap.context_receipt is not None:
            return
        view = build_view(cap.policy)
        cap.register_context_recheck(lambda active: build_view(active.policy))
        cap.publish_context(
            view, rendered.encode("utf-8"), turn_id=cap.current_turn_id)
        return rendered

    ctx.register_hook("prepare_context", prepare_context)
    ctx.register_hook("pre_llm_call", pre_llm_call)
'''


def _resolved_body(request_env, *, project=PROJECT, mission=MISSION,
                   binding=None, tenant=TENANT, docs=None, refs=None,
                   pointer=None, native=True, profile=None, **over):
    req_body = request_env["body"]
    binding = binding if binding is not None else _binding_for(
        project=project, mission=mission)
    docs = _docs(mission) if docs is None else docs
    source_refs = (_flat(["dubsar:mission:objective"], docs)
                   if refs is None else refs)
    body = {
        "attempt_id": req_body["attempt_id"],
        "authority_basis_digest": "ab" * 32,
        "authority_digest": "cd" * 32,
        "binding_digest": binding,
        "mission_id": mission, "mission_revision": 1,
        "mission_request": {"criteria": ["prove the lane"], "objective": "o",
                            "source_refs": source_refs, "title": "t"},
        "mission_source_digest": "ef" * 32,
        "observation_genesis": _observation(req_body["session_id"]),
        "profile": profile if profile is not None else req_body["profile"],
        "project_binding_id": project, "project_id": project,
        "request_digest": "11" * 32, "requester_id": REQUESTER,
        "reservation_ref": {"collection": "dubsar_b2b_agent_sessions",
                            "id": binding},
        "session_id": req_body["session_id"],
        "source_request_digest": hashlib.sha256(
            canonical_json(request_env)).hexdigest(),
        "source_request_id": request_env["request_id"],
        "source_state": "active", "ticket_digest": "22" * 32}
    if native:
        body["tenant_id"] = tenant
        body["mission_inputs"] = _pointer(docs) if pointer is None else pointer
    body.update(over)
    return body


def _resolve(entry, keys, purpose="bind", *, attempt_id=ATTEMPT,
             session_id=SESSION, respond=None):
    if respond is None:
        respond = lambda env: _response_envelope(env, _resolved_body(env))
    with _SourceServer(respond) as server:
        entry = dict(entry)
        entry["source_url"] = (
            f"http://127.0.0.1:{server.port}/internal/dubsar/b2b/source")
        resolved, reason = m.resolve_source(
            entry, keys, purpose, attempt_id=attempt_id, profile="deploy",
            session_id=session_id)
    return resolved, reason


def _entry_and_keys(config=None):
    config = m.B2BConfig(_raw_config()) if config is None else config
    entry = config.profiles["deploy"]
    return entry, m._KeyRing(entry)


# ---------------------------------------------------------------------------
# Catalogue: the native stanza is exact and opt-in only.
# ---------------------------------------------------------------------------

def test_config_native_prepare_only_stanza():
    config = m.B2BConfig(_raw_config(projects={PROJECT: _project_entry(
        run_ref={"path": "/srv/n2/recipe.json", "sha256": "a" * 64})}))
    project = config.profiles["deploy"]["projects"][PROJECT]
    assert project["native_n2"] == {
        "tenant_id": TENANT,
        "run_authorization": {"path": "/srv/n2/recipe.json",
                              "sha256": "a" * 64}}
    with pytest.raises(TypeError):
        project["native_n2"]["tenant_id"] = "other"


def test_config_native_stanza_parses_and_freezes():
    config = m.B2BConfig(_raw_config())
    project = config.profiles["deploy"]["projects"][PROJECT]
    assert project["native_n2"] == {"tenant_id": TENANT}


@pytest.mark.parametrize("mutate", [
    lambda p: p.update({"bot_id": "hub"}),
    lambda p: p.update({"profile_id": "hub"}),
    lambda p: p.update({"memory_mode": "required"}),
    lambda p: p.update({"provider": "custom:other"}),
    lambda p: p.pop("project_context"),
    lambda p: p.update({"native_n2": None}),
    lambda p: p.update({"native_n2": {"tenant_id": TENANT, "extra": 1}}),
    lambda p: p.update({"native_n2": {"run_authorization": {}}}),
    lambda p: p.update({"native_n2": {"tenant_id": "bad tenant "}}),
    lambda p: p.update({"native_n2": {"tenant_id": TENANT,
        "run_authorization": {"path": "relative/x.json", "sha256": "a" * 64}}}),
    lambda p: p.update({"native_n2": {"tenant_id": TENANT,
        "run_authorization": {"path": "/x.json", "sha256": "zz"}}}),
])
def test_config_native_wrong_lane_refuses(mutate):
    project = _project_entry()
    mutate(project)
    with pytest.raises(m.B2BConfigError):
        m.B2BConfig(_raw_config(projects={PROJECT: project}))


def test_config_native_requires_deploy_profile_name():
    with pytest.raises(m.B2BConfigError):
        m.B2BConfig(_raw_config(profile_name="hub"))


def test_config_native_requires_prj_binding_and_project():
    with pytest.raises(m.B2BConfigError):
        m.B2BConfig(_raw_config(projects={"not-prj": _project_entry()}))
    entry = _project_entry(project_id="not-a-prj")
    with pytest.raises(m.B2BConfigError):
        m.B2BConfig(_raw_config(projects={PROJECT: entry}))


def test_config_native_alias_refused():
    alias = _project_entry(native=False, project_id=PROJECT)
    with pytest.raises(m.B2BConfigError):
        m.B2BConfig(_raw_config(projects={PROJECT: _project_entry(),
                                         LEGACY_ALIAS: alias}))


# ---------------------------------------------------------------------------
# Real signed exchange: extended body verifies for every real purpose.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("purpose", sorted(m._PURPOSES))
def test_native_resolve_real_envelope_each_purpose(purpose):
    entry, keys = _entry_and_keys()
    resolved, reason = _resolve(entry, keys, purpose)
    assert reason == "ok", reason
    binding = m._native_binding(resolved)
    assert binding == {
        "tenant_id": TENANT, "project_id": PROJECT, "mission_id": MISSION,
        "mission_revision": 1, "profile": "deploy", "session_id": SESSION,
        "attempt_id": ATTEMPT, "binding_digest": BINDING,
        "requester_id": REQUESTER,
        "mission_inputs": _pointer()}


def test_native_signed_source_requires_ordered_piece_pairs():
    entry, keys = _entry_and_keys()
    resolved, reason = _resolve(
        entry, keys,
        respond=lambda env: _response_envelope(
            env, _resolved_body(env, refs=["dubsar:mission:objective"])))
    assert resolved is None
    assert reason == "body_native"


@pytest.mark.parametrize(("original_count", "piece_count", "expected_reason"), [
    (10, 10, "ok"),
    (11, 11, "ok"),
    (20, 20, "ok"),
    (21, 1, "body_native"),
    (0, 21, "body_native"),
])
def test_native_signed_source_combined_reference_cap(
        original_count, piece_count, expected_reason):
    entry, keys = _entry_and_keys()
    refs = _flat(
        [f"source:{index}" for index in range(original_count)],
        _docs(count=piece_count))
    resolved, reason = _resolve(
        entry, keys,
        respond=lambda env: _response_envelope(
            env, _resolved_body(env, refs=refs)))
    assert reason == expected_reason
    assert (resolved is not None) is (expected_reason == "ok")


def test_signed_non_string_project_binding_fails_closed():
    entry, keys = _entry_and_keys()
    resolved, reason = _resolve(
        entry, keys,
        respond=lambda env: _response_envelope(
            env, _resolved_body(env, project_binding_id=["not", "a", "key"])))
    assert resolved is None
    assert reason == "body_native_downgrade"


def test_native_legacy_crossing_refuses_both_ways():
    entry, keys = _entry_and_keys()
    # Legacy 20-key body on the NATIVE catalogue entry: the extended shape
    # is demanded — a downgrade to historical shape refuses.
    resolved, reason = _resolve(
        entry, keys, respond=lambda env: _response_envelope(
            env, _resolved_body(env, native=False)))
    assert resolved is None and reason == "body_shape"
    # Extended body fields on a LEGACY catalogue entry refuse just as hard.
    config = m.B2BConfig(_raw_config(projects={
        LEGACY_ALIAS: _project_entry(native=False, project_id=LEGACY_PROJECT)}))
    entry, keys = config.profiles["deploy"], m._KeyRing(config.profiles["deploy"])
    binding = _binding_for(project=LEGACY_ALIAS)
    session = "b2b_" + binding
    resolved, reason = _resolve(
        entry, keys, attempt_id=m._attempt_id_for(binding),
        session_id=session,
        respond=lambda env: _response_envelope(env, _resolved_body(
            env, project=LEGACY_ALIAS, binding=binding, native=True)))
    assert resolved is None and reason == "body_shape"


def test_native_downgrade_alias_refused():
    # The attacker binds the LEGACY catalogue alias but claims the native
    # project_id — the claimed id is in the native set and the selected
    # entry is not native, so this refuses before any shape check.
    config = m.B2BConfig(_raw_config(projects={
        PROJECT: _project_entry(),
        LEGACY_ALIAS: _project_entry(native=False, project_id=LEGACY_PROJECT)}))
    entry, keys = config.profiles["deploy"], m._KeyRing(config.profiles["deploy"])
    binding = _binding_for(project=LEGACY_ALIAS)
    resolved, reason = _resolve(
        entry, keys, attempt_id=m._attempt_id_for(binding),
        session_id="b2b_" + binding,
        respond=lambda env: _response_envelope(env, _resolved_body(
            env, project=LEGACY_ALIAS, binding=binding, native=False,
            project_id=PROJECT)))
    assert resolved is None and reason == "body_native_downgrade"


@pytest.mark.parametrize("mutation,expected", [
    ({"tenant": "tenant-foreign"}, "body_native"),     # foreign tenant
    ({"profile": "hub"}, "body_correlation"),          # non-deploy attempt profile
    ({"pointer": {"inputs_revision": 0,                # bad revision
                  "manifest_digest": _pointer()["manifest_digest"],
                  "inputs_digest": _pointer()["inputs_digest"]}}, "body_native"),
    ({"pointer": {"inputs_revision": 3,                # unprefixed digests
                  "manifest_digest": "a" * 64,
                  "inputs_digest": "sha256:" + "b" * 64}}, "body_native"),
    ({"refs": ["dubsar:piece:" + MISSION + ":piece_" + "f" * 32]},
     "body_native"),                                   # unpaired
    ({"refs": ["dubsar:piece:mis_" + "9" * 32 + ":piece_" + "f" * 32,
               "sha256:" + "a" * 64]}, "body_native"),  # foreign mission
    ({"refs": [f"ref-{i}" for i in range(61)]}, "body_native"),  # ref bound
])
def test_native_body_mutations_refuse(mutation, expected):
    entry, keys = _entry_and_keys()
    resolved, reason = _resolve(
        entry, keys, respond=lambda env: _response_envelope(
            env, _resolved_body(env, **mutation)))
    assert resolved is None and reason == expected, (reason, mutation)


def test_native_doc_pair_order_and_adjacency_enforced():
    entry, keys = _entry_and_keys()
    docs = _docs()
    flat = _flat(["dubsar:mission:objective"], docs)
    # Reordered pairs: a different mission_request — the signed body still
    # verifies syntactically but is NOT the attested manifest the sink
    # compares; the ordered-suffix shape itself must hold, so swap the ref
    # and digest of one pair (adjacency broken).
    swapped = list(flat)
    swapped[1], swapped[2] = swapped[2], swapped[1]
    resolved, reason = _resolve(
        entry, keys, respond=lambda env: _response_envelope(
            env, _resolved_body(env, refs=swapped)))
    assert resolved is None and reason == "body_native"


def test_native_legacy_lane_still_verifies():
    config = m.B2BConfig(_raw_config(projects={
        LEGACY_ALIAS: _project_entry(native=False, project_id=LEGACY_PROJECT)}))
    entry, keys = config.profiles["deploy"], m._KeyRing(config.profiles["deploy"])
    binding = _binding_for(project=LEGACY_ALIAS)
    session = "b2b_" + binding
    resolved, reason = _resolve(
        entry, keys, attempt_id=m._attempt_id_for(binding),
        session_id=session,
        respond=lambda env: _response_envelope(env, _resolved_body(
            env, project=LEGACY_ALIAS, binding=binding, native=False,
            refs=["dubsar:mission:objective"])))
    assert reason == "ok", reason
    assert m._native_binding(resolved) is None


# ---------------------------------------------------------------------------
# _matches_source: the admitted capability binds exactly the native body.
# ---------------------------------------------------------------------------

def _policy_for(resolved, *, messages_digest=None):
    native = resolved.get("_native_binding")
    return {
        "profile": "deploy", "session_id": resolved["session_id"],
        "binding_digest": resolved["binding_digest"],
        "attempt_id": resolved["attempt_id"],
        "profile_home": str(get_hermes_home().resolve()),
        "schema_pins": m.R2_SCHEMA_PINS, "execution_policy": "h1/proposal-v1",
        "requester_id": resolved["requester_id"],
        "project_id": resolved["project_id"],
        "project_binding_id": resolved["project_binding_id"],
        "mission_id": resolved["mission_id"],
        "mission_revision": resolved["mission_revision"],
        "reservation_ref": resolved["reservation_ref"],
        "request_digest": resolved["request_digest"],
        "ticket_digest": resolved["ticket_digest"],
        "authority_basis_digest": resolved["authority_basis_digest"],
        "authority_digest": resolved["authority_digest"],
        "observation_genesis": resolved["observation_genesis"],
        "mission_request": resolved["mission_request"],
        "project": dict(_entry_and_keys()[0]["projects"][PROJECT]),
        **({"native_n2_binding": native} if native is not None else {}),
        **({"native_n2_messages_digest": messages_digest}
           if messages_digest is not None else {})}


def _sink(entry, keys, policy):
    config = m.B2BConfig(_raw_config())
    adapter = SimpleNamespace(_b2b_state=m._B2BState(config))
    return m._AttemptSink(
        adapter, SimpleNamespace(), profile="deploy", entry=entry, keys=keys,
        attempt_id=policy["attempt_id"], session_id=policy["session_id"],
        binding_digest=policy["binding_digest"], run_id="run_" + uuid.uuid4().hex,
        policy=policy)


def test_matches_source_native_binding_exact():
    entry, keys = _entry_and_keys()
    resolved, reason = _resolve(entry, keys)
    assert reason == "ok"
    sink = _sink(entry, keys, _policy_for(resolved))
    assert sink._matches_source(resolved) is True
    # A mutated native binding — foreign tenant, foreign mission, foreign
    # pointer — never matches the admitted capability.
    for key, value in (("tenant_id", "tenant-foreign"),
                       ("mission_id", "mis_" + "9" * 32),
                       ("mission_inputs", {"inputs_revision": 4,
                                           "manifest_digest": "sha256:" + "0" * 64,
                                           "inputs_digest": "sha256:" + "0" * 64})):
        drifted = dict(resolved)
        drifted[key] = value
        drifted["_native_binding"] = m._native_binding(drifted)
        assert sink._matches_source(drifted) is False, key
    # A legacy-verified resolved (no extended marker) never satisfies a
    # native policy.
    legacy = dict(resolved)
    legacy["_native_verified"] = False
    assert sink._matches_source(legacy) is False


def test_current_policy_fingerprint_revokes_changed_or_removed_native_stanza():
    entry, keys = _entry_and_keys()
    resolved, reason = _resolve(entry, keys)
    assert reason == "ok"
    sink = _sink(entry, keys, _policy_for(resolved))
    assert sink.assert_current_policy() is True

    changed = _project_entry()
    changed["native_n2"]["tenant_id"] = "tenant-bravo"
    changed_config = m.B2BConfig(_raw_config(projects={PROJECT: changed}))
    sink._adapter._b2b_state = m._B2BState(changed_config)
    assert sink.assert_current_policy() is False

    removed_sink = _sink(entry, keys, _policy_for(resolved))
    removed_config = m.B2BConfig(_raw_config(projects={
        PROJECT: _project_entry(native=False)}))
    removed_sink._adapter._b2b_state = m._B2BState(removed_config)
    assert removed_sink.assert_current_policy() is False


# ---------------------------------------------------------------------------
# Protected manifest read: every fabricable state refuses closed.
# ---------------------------------------------------------------------------

def test_native_manifest_absent_and_unsafe_refuse():
    ref = {"path": os.path.join(tempfile.gettempdir(),
                                f"n2-missing-{os.getpid()}.json"),
           "sha256": "a" * 64}
    assert native_auth._read_native_run_authorization(ref) is None
    # A file we can create fails every proof: /tmp is world-writable and our
    # UID is never 32013 — the refusal is the fail-closed side only.
    directory = tempfile.mkdtemp(prefix="n2-manifest-")
    path = os.path.join(directory, "recipe.json")
    payload = json.dumps({
        "format": "dubsar.b2b-n2-recipe/1", "boot_id": native_auth._boot_id(),
        "classification": "public_synthetic", "dataset_id": "ds-1",
        "binding": {}, "request_digest": "a" * 64,
        "mission_source_digest": "b" * 64, "messages_digest": "c" * 64})
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(payload)
    assert native_auth._read_native_run_authorization(
        {"path": path,
         "sha256": hashlib.sha256(payload.encode()).hexdigest()}) is None
    for ref in (None, {}, {"path": "relative/x", "sha256": "a" * 64},
                {"path": path, "sha256": "b" * 64},
                {"path": path}):
        assert native_auth._read_native_run_authorization(ref) is None, ref


_NATIVE_IO_AVAILABLE = (
    sys.platform.startswith("linux")
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "getuid")
)
_FIXTURE_BOOT_ID = "fixture-boot-id"


def _write_native_manifest(path, record, mode=0o640):
    payload = json.dumps(
        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    with open(path, "wb") as stream:
        stream.write(payload)
    os.chmod(path, mode)
    return {"path": path, "sha256": hashlib.sha256(payload).hexdigest()}


def _native_manifest_fixture(tmp_path, monkeypatch):
    root = os.path.join(str(tmp_path), "trusted")
    os.mkdir(root, 0o700)
    boot_path = os.path.join(root, "boot-id")
    with open(boot_path, "w", encoding="ascii") as stream:
        stream.write(_FIXTURE_BOOT_ID + "\n")
    monkeypatch.setattr(native_auth, "_NATIVE_TRUSTED_ROOT", root)
    monkeypatch.setattr(native_auth, "_NATIVE_BOOT_ID_PATH", Path(boot_path))
    monkeypatch.setattr(native_auth, "_NATIVE_SECURITY_UID", getattr(os, "getuid")())
    record = {
        "format": "dubsar.b2b-n2-recipe/1",
        "boot_id": _FIXTURE_BOOT_ID,
        "classification": "public_synthetic",
        "dataset_id": "ds-1",
        "binding": {
            "tenant_id": TENANT,
            "project_id": PROJECT,
            "mission_id": MISSION,
            "mission_revision": 1,
            "profile": "deploy",
            "session_id": SESSION,
            "attempt_id": ATTEMPT,
            "binding_digest": BINDING,
            "requester_id": REQUESTER,
            "mission_inputs": {
                "inputs_revision": 1,
                "manifest_digest": "sha256:" + "d" * 64,
                "inputs_digest": "sha256:" + "e" * 64,
            },
        },
        "request_digest": "a" * 64,
        "mission_source_digest": "b" * 64,
        "messages_digest": "c" * 64,
    }
    path = os.path.join(root, "recipe.json")
    ref = _write_native_manifest(path, record)
    return root, path, record, ref


@pytest.mark.skipif(not _NATIVE_IO_AVAILABLE, reason="Linux O_NOFOLLOW fixture required")
def test_native_manifest_real_file_accepts_and_rejects_repinned_schema_drift(
        tmp_path, monkeypatch):
    _root, path, record, ref = _native_manifest_fixture(tmp_path, monkeypatch)
    assert native_auth._read_native_run_authorization(ref) == record

    mutations = (
        lambda value: value.update(boot_id="other-boot"),
        lambda value: value["binding"].update(profile="main"),
        lambda value: value.update(classification="private"),
        lambda value: value.update(dataset_id="not a dataset"),
        lambda value: value.update(messages_digest="not-hex"),
        lambda value: value.update(unexpected=True),
    )
    for mutate in mutations:
        changed = json.loads(json.dumps(record))
        mutate(changed)
        repinned = _write_native_manifest(path, changed)
        assert native_auth._read_native_run_authorization(repinned) is None


@pytest.mark.skipif(not _NATIVE_IO_AVAILABLE, reason="Linux O_NOFOLLOW fixture required")
def test_native_manifest_real_file_refuses_bad_pin_mode_link_and_symlink(
        tmp_path, monkeypatch):
    root, path, record, ref = _native_manifest_fixture(tmp_path, monkeypatch)
    assert native_auth._read_native_run_authorization(
        {**ref, "sha256": "f" * 64}) is None

    os.chmod(path, 0o600)
    assert native_auth._read_native_run_authorization(ref) is None
    os.chmod(path, 0o640)

    hardlink = os.path.join(root, "hardlink.json")
    os.link(path, hardlink)
    assert native_auth._read_native_run_authorization(
        {"path": hardlink, "sha256": ref["sha256"]}) is None

    symlink = os.path.join(root, "symlink.json")
    os.symlink(path, symlink)
    assert native_auth._read_native_run_authorization(
        {"path": symlink, "sha256": ref["sha256"]}) is None


@pytest.mark.skipif(not _NATIVE_IO_AVAILABLE, reason="Linux O_NOFOLLOW fixture required")
def test_native_manifest_real_file_refuses_wrong_expected_owner(tmp_path, monkeypatch):
    _root, _path, record, ref = _native_manifest_fixture(tmp_path, monkeypatch)
    assert native_auth._read_native_run_authorization(ref) == record
    monkeypatch.setattr(native_auth, "_native_parents_safe", lambda path: path == ref["path"])
    monkeypatch.setattr(
        native_auth, "_NATIVE_SECURITY_UID", getattr(os, "getuid")() + 1)
    assert native_auth._read_native_run_authorization(ref) is None


def test_native_parents_check_filesystem_root(monkeypatch):
    info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)

    def lstat(path):
        assert path == os.path.sep
        return info

    monkeypatch.setattr(native_auth, "_NATIVE_TRUSTED_ROOT", os.path.sep)
    monkeypatch.setattr(
        native_auth, "os", SimpleNamespace(path=os.path, lstat=lstat))
    path = os.path.join(os.path.sep, "recipe.json")
    assert native_auth._native_parents_safe(path)
    info.st_mode |= 0o020
    assert not native_auth._native_parents_safe(path)


# ---------------------------------------------------------------------------
# _b2b_documents: canonical manifest + ordered pair enumeration.
# ---------------------------------------------------------------------------

def _cap(policy):
    return BoundExecution(
        profile="deploy", session_id=SESSION, binding_digest=BINDING,
        attempt_id=ATTEMPT, run_id="run_" + uuid.uuid4().hex, policy=policy,
        sink=SimpleNamespace(assert_current_policy=lambda: True),
        created_at=time.time())


def _documents_case():
    docs = _docs()
    flat = _flat(["dubsar:mission:objective"], docs)
    policy = {"mission_id": MISSION,
              "native_n2_binding": {"tenant_id": TENANT, "project_id": PROJECT,
                                    "mission_inputs": _pointer(docs)}}
    plain = {"my_work": {"mission": {
        "references": flat[:1]}}}
    resolved = {"mission_request": {
        "source_refs": flat}}
    return docs, _cap(policy), plain, resolved, flat


def test_b2b_documents_native_exact_manifest():
    docs, cap, plain, resolved, flat = _documents_case()
    proven = _b2b_documents(
        docs, cap=cap, plain=plain, resolved=resolved, native_references=flat)
    assert [d["native_ref"] for d in proven] == [d["native_ref"] for d in docs]


@pytest.mark.parametrize("mutate", [
    "missing_documents", "empty_documents", "reordered_pairs",
    "foreign_mission_ref", "wrong_manifest_digest", "sidecar_reorder",
])
def test_b2b_documents_native_mutations_refuse(mutate):
    docs, cap, plain, resolved, flat = _documents_case()
    native_references = flat
    if mutate == "missing_documents":
        raw = None
    elif mutate == "empty_documents":
        raw = []
    else:
        raw = docs
    if mutate == "reordered_pairs":
        resolved = {"mission_request": {
            "source_refs": flat[:1] + flat[3:] + flat[1:3]}}
    elif mutate == "sidecar_reorder":
        native_references = flat[:1] + flat[3:] + flat[1:3]
    elif mutate == "foreign_mission_ref":
        foreign = _docs("mis_" + "9" * 32)
        resolved = {"mission_request": {"source_refs": _flat([], foreign)}}
        raw = foreign
        cap = _cap({"mission_id": MISSION, "native_n2_binding": {
            "tenant_id": TENANT, "project_id": PROJECT,
            "mission_inputs": _pointer(docs)}})
    elif mutate == "wrong_manifest_digest":
        cap = _cap({"mission_id": MISSION, "native_n2_binding": {
            "tenant_id": TENANT, "project_id": PROJECT,
            "mission_inputs": _pointer(docs,
                                       manifest_digest="sha256:" + "0" * 64)}})
    with pytest.raises(B2BTerminalRefusal, match="context_documents"):
        _b2b_documents(
            raw, cap=cap, plain=plain, resolved=resolved,
            native_references=native_references)


def test_b2b_documents_native_refuses_missing_sidecar():
    docs, cap, plain, resolved, flat = _documents_case()
    plain["my_work"]["mission"]["references"] = flat
    with pytest.raises(B2BTerminalRefusal, match="context_documents"):
        _b2b_documents(docs, cap=cap, plain=plain, resolved=resolved)


# ---------------------------------------------------------------------------
# assert_terminal_runtime: the recipe messages gate.
# ---------------------------------------------------------------------------

class _Agent:
    """Plain object the real install path can weakref (SimpleNamespace cannot)."""


def _agent_for(session_id):
    agent = _Agent()
    agent.session_id = session_id
    agent.model = MODEL
    agent.provider = "custom:b2b-g2"
    agent.api_mode = "chat_completions"
    agent.base_url = BASE_URL
    agent.max_iterations = 1
    agent._disable_streaming = True
    agent.compression_enabled = False
    agent._api_max_retries = 1
    agent._auto_recovery_cycles = 0
    agent.credential_pool = None
    agent._credential_pool = None
    agent._fallback_chain = []
    return agent


def test_terminal_native_recipe_gate():
    messages = [{"role": "system", "content": "ctx"},
                {"role": "user", "content": "go"}]
    digest = hashlib.sha256(canonical_json(messages)).hexdigest()
    policy = {
        "profile_home": str(get_hermes_home().resolve()),
        "project": {"model": MODEL, "provider": "custom:b2b-g2",
                    "api_mode": "chat_completions", "base_url": BASE_URL},
        "native_n2_binding": BINDING,
        "native_n2_messages_digest": digest}
    cap = _cap(policy)
    agent = _agent_for(SESSION)
    token = bind_execution(cap)
    try:
        install_bounded_agent_policy(agent, cap)
        kwargs = {"model": MODEL, "messages": messages}
        assert_terminal_runtime(agent, kwargs, cap)  # the approved recipe passes
        for bad in ([{"role": "user", "content": "other"}],
                    [{"role": "user", "content": "go", "extra": 1}],
                    [{"role": "assistant", "content": "go"}], [],
                    [{"role": "system", "content": "ctx"},
                     {"role": "user", "content": "go"},
                     {"role": "user", "content": "again"}],
                    [{"role": "system", "content": "ctx"},
                     {"role": "user", "content": "go"},
                     {"role": "system", "content": "history"}]):
            with pytest.raises(B2BTerminalRefusal,
                               match="b2b_recipe_messages_mismatch"):
                assert_terminal_runtime(agent, {"model": MODEL, "messages": bad}, cap)
    finally:
        reset_execution(token)


def test_terminal_historical_lane_untouched():
    policy = {
        "profile_home": str(get_hermes_home().resolve()),
        "project": {"model": MODEL, "provider": "custom:b2b-g2",
                    "api_mode": "chat_completions", "base_url": BASE_URL}}
    cap = _cap(policy)
    agent = _agent_for(SESSION)
    token = bind_execution(cap)
    try:
        install_bounded_agent_policy(agent, cap)
        assert_terminal_runtime(
            agent,
            {"model": MODEL, "messages": [{"role": "user", "content": "any"}]},
            cap)
    finally:
        reset_execution(token)


def test_recipe_reason_classified():
    assert "b2b_recipe_messages_mismatch" in m._BLOCK_POLICY_CHANGED_REASONS
    from agent.b2b_execution import BLOCK_REASONS
    assert "b2b_recipe_messages_mismatch" in BLOCK_REASONS


@pytest.mark.asyncio
@pytest.mark.skipif(
    not _NATIVE_IO_AVAILABLE, reason="Linux O_NOFOLLOW fixture required")
@pytest.mark.parametrize(("revoke_at", "authorization"), [
    pytest.param(None, "valid", id="valid"),
    pytest.param("before_provider", "valid", id="before-provider-revocation"),
    pytest.param("before_seal", "valid", id="before-seal-revocation"),
    pytest.param(None, "no_ref", id="missing-authorization-ref"),
    pytest.param(None, "missing_file", id="missing-authorization-file"),
    pytest.param(None, "binding", id="wrong-authorization-binding"),
    pytest.param(None, "request_digest", id="wrong-authorization-request"),
    pytest.param(None, "mission_source_digest", id="wrong-authorization-source"),
    pytest.param(None, "messages_digest", id="wrong-authorization-recipe"),
    pytest.param(None, "unattested-view-piece", id="unattested-view-piece"),
    pytest.param(None, "different-view-prefix", id="different-view-prefix"),
    pytest.param(None, "revoke_after_prepare", id="revoke-after-preparation"),
])
async def test_native_http_prepare_admission_replay_and_revocation(
        tmp_path, monkeypatch, revoke_at, authorization):
    import base64
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer
    from gateway.config import PlatformConfig
    from gateway.platforms.api_server import APIServerAdapter
    from gateway.platforms import api_server_b2b_native_authorization as auth
    from hermes_state import SessionDB
    from tests.gateway import test_api_server_b2b_admission as adm
    from tests.gateway import test_api_server_b2b_execution_lane as execution_lane
    from tests.gateway import test_api_server_b2b_prepare as prepare_tests
    from tests.gateway.b2b_process_harness import UNIT_RENDERED
    from agent.b2b_execution import NATIVE_RECIPE_SYSTEM_PROMPT, mission_prompt

    profile_home = adm._profile_home(tmp_path, monkeypatch, "deploy")
    documents = _docs(count=20)
    ordinary_refs = [f"dubsar:mission:ref-{index}" for index in range(20)]
    view_refs = ordinary_refs
    native_references = _flat(ordinary_refs, documents)
    if authorization == "unattested-view-piece":
        view_refs = [*ordinary_refs[:-1], f"dubsar:piece:{MISSION}:piece_{'f' * 32}"]
    elif authorization == "different-view-prefix":
        view_refs = list(reversed(ordinary_refs))
    mission_request = {
        "criteria": ["prove the lane"], "objective": "o",
        "source_refs": native_references, "title": "t"}
    rendered = UNIT_RENDERED + "".join(
        "\nb2b_document=" + json.dumps(
            document, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False)
        for document in documents)
    assert len(rendered) <= 9000
    messages_digest = hashlib.sha256(canonical_json([
        {"role": "system", "content": NATIVE_RECIPE_SYSTEM_PROMPT},
        {"role": "user", "content": mission_prompt(mission_request)
         + "\n\n" + rendered},
    ])).hexdigest()

    seed_request = {
        "request_id": str(uuid.uuid4()),
        "body": {"attempt_id": ATTEMPT, "profile": "deploy", "session_id": SESSION},
    }
    resolved_body = _resolved_body(
        seed_request, docs=documents, refs=native_references)
    native_binding = {
        key: resolved_body[key] for key in m._NATIVE_BINDING_KEYS}
    trusted_root = tmp_path / "native-trusted"
    trusted_root.mkdir(mode=0o700)
    boot_path = trusted_root / "boot-id"
    boot_path.write_text("test-boot-id\n", encoding="ascii")
    manifest_path = trusted_root / "recipe.json"
    record = {
        "format": auth._NATIVE_MANIFEST_FORMAT,
        "boot_id": "test-boot-id",
        "classification": auth._NATIVE_MANIFEST_CLASS,
        "dataset_id": "unit-native-e2e",
        "binding": native_binding,
        "request_digest": resolved_body["request_digest"],
        "mission_source_digest": resolved_body["mission_source_digest"],
        "messages_digest": messages_digest,
    }
    if authorization == "binding":
        record["binding"] = dict(native_binding, tenant_id="tenant-bravo")
    elif authorization == "request_digest":
        record["request_digest"] = "22" * 32
    elif authorization == "mission_source_digest":
        record["mission_source_digest"] = "33" * 32
    elif authorization == "messages_digest":
        record["messages_digest"] = "44" * 32
    manifest_bytes = canonical_json(record)
    manifest_path.write_bytes(manifest_bytes)
    manifest_path.chmod(0o640)
    monkeypatch.setattr(auth, "_NATIVE_TRUSTED_ROOT", str(trusted_root))
    monkeypatch.setattr(auth, "_NATIVE_BOOT_ID_PATH", boot_path)
    monkeypatch.setattr(auth, "_NATIVE_SECURITY_UID", getattr(os, "getuid")())
    run_ref = {"path": str(manifest_path), "sha256": hashlib.sha256(
        manifest_bytes).hexdigest()}

    revoked = False
    changed_authority = False

    def respond(request_env):
        nonlocal revoked
        purpose = request_env["body"].get("purpose")
        if revoke_at == purpose and not revoked:
            manifest_path.unlink(missing_ok=True)
            revoked = True
        body = _resolved_body(
            request_env, docs=documents, refs=native_references)
        body["authority_basis_digest"] = "sha256:" + "ab" * 32
        body["authority_digest"] = "sha256:" + "cd" * 32
        if changed_authority:
            body["authority_basis_digest"] = "sha256:" + "fa" * 32
            body["authority_digest"] = "sha256:" + "de" * 32
        return _response_envelope(request_env, body)

    provider_requests = []
    proposal_result = {
        "summary": "Prepare the bound work.",
        "steps": ["Review the supplied piece."],
        "source_refs": [documents[-1]["native_ref"]],
        "limitations": [],
    }

    async def provider_chat(request):
        raw = await request.read()
        if not request.headers.get("Authorization"):
            return web.Response(status=401)
        provider_requests.append(json.loads(raw))
        return web.json_response({
            "id": "cmpl-native-e2e", "object": "chat.completion",
            "choices": [{"index": 0, "message": {
                "role": "assistant", "content": json.dumps(proposal_result)},
                "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })

    provider_app = web.Application()
    provider_app.router.add_post("/v1/chat/completions", provider_chat)
    provider_server = TestServer(provider_app, host="127.0.0.1")
    await provider_server.start_server()
    provider_url = f"http://127.0.0.1:{provider_server.port}/v1"
    source = _SourceServer(respond)
    adapter = None
    resources = []
    try:
        with source:
            from hermes_constants import get_hermes_home
            import gateway.run as gateway_run
            monkeypatch.setattr(gateway_run, "_hermes_home", get_hermes_home())
            (profile_home / ".env").write_text(
                "B2B_G2_API_KEY=unit-native-provider-key\n", encoding="utf-8")
            monkeypatch.setenv("B2B_G2_API_KEY", "unit-native-provider-key")
            alloc, start = tmp_path / "alloc", tmp_path / "start"
            alloc.mkdir()
            start.mkdir()
            project = _project_entry(
                run_ref=None if authorization == "no_ref" else run_ref,
                base_url=provider_url,
                context_contract_root=prepare_tests.extract_contract_root(tmp_path),
                project_context={"project_id": PROJECT,
                                 "allocation_root": str(alloc), "start": str(start)})
            b2b_raw = _raw_config(
                source_port=source.port, projects={PROJECT: project})
            extra = {"key": adm._API_KEY, "b2b": b2b_raw}
            execution_lane._write_named_provider_config(
                profile_home, named_url=provider_url,
                default_url="http://127.0.0.1:9/v1")
            plugin_name = "unitctx-native-e2e"
            execution_lane._write_fake_plugin(
                profile_home, name=plugin_name,
                init=_native_e2e_plugin_init(
                    documents, view_refs, native_references, rendered,
                    resolved_body["mission_source_digest"]))
            execution_lane._plugin_config(profile_home, names=(plugin_name,))

            adapter = APIServerAdapter(PlatformConfig(enabled=True, extra=extra))
            adapter.gateway_runner = SimpleNamespace(
                config=SimpleNamespace(multiplex_profiles=False))
            adapter._session_db = SessionDB(profile_home / "state.db")
            adapter._session_db.create_session(
                SESSION, "api_server", profile_name="deploy")
            resources.extend([
                adapter._session_db, adapter._run_idempotency_store,
                adapter._response_store])
            prepare_tests._freeze_oc_window(monkeypatch)
            headers = {
                "Authorization": f"Bearer {adm._API_KEY}",
                "Idempotency-Key": ATTEMPT,
            }
            route = f"/p/deploy/api/sessions/{SESSION}"
            async with TestClient(TestServer(adm._app(adapter))) as client:
                warmup_id = str(uuid.uuid4())
                warmup_response = await client.post(
                    route + "/b2b-prepare",
                    json={"attempt_id": ATTEMPT, "binding_digest": BINDING,
                          "request_id": warmup_id},
                    headers=headers)
                await warmup_response.read()
                # This fixture explicitly warms process-cold plugin discovery.
                prepare_request_id = str(uuid.uuid4())
                prepared_response = await client.post(
                    route + "/b2b-prepare",
                    json={"attempt_id": ATTEMPT, "binding_digest": BINDING,
                          "request_id": prepare_request_id},
                    headers=headers)
                prepared = await prepared_response.json()
                if authorization in {"unattested-view-piece", "different-view-prefix"}:
                    assert prepared_response.status == 503, prepared
                    assert prepared == {
                        "error": "context_documents", "code": "context_documents"}
                    assert provider_requests == []
                    return
                assert prepared_response.status == 200, prepared
                signature = base64.urlsafe_b64decode(
                    prepared["signature"] + "=" * (-len(prepared["signature"]) % 4))
                unsigned = {key: value for key, value in prepared.items()
                            if key != "signature"}
                HERMES_PRIV.public_key().verify(
                    signature, m._DOMAIN + canonical_json(unsigned))
                assert prepared["request_id"] == prepare_request_id
                assert prepared["body"]["messages_digest"] == messages_digest
                assert prepared["body"]["documents"] == [
                    {"native_ref": document["native_ref"], "revision": 1,
                     "digest": document["native_digest"]}
                    for document in documents]

                store = adapter._run_idempotency_store
                if authorization != "valid":
                    if authorization == "missing_file":
                        manifest_path.unlink(missing_ok=True)
                    if authorization == "revoke_after_prepare":
                        original_preparation = m._b2b_run_bounded_preparation

                        async def prepare_then_revoke(*args, **kwargs):
                            outcome = await original_preparation(*args, **kwargs)
                            assert outcome is None, outcome
                            manifest_path.unlink(missing_ok=True)
                            return outcome

                        monkeypatch.setattr(
                            m, "_b2b_run_bounded_preparation", prepare_then_revoke)
                    counts_before = adm._store_counts(store)
                    title_before = adapter._session_db.get_session(SESSION)["title"]
                    assert title_before is None
                    proposal_response = await client.post(
                        route + "/b2b-proposal",
                        json={"attempt_id": ATTEMPT, "binding_digest": BINDING},
                        headers=headers)
                    denial = await proposal_response.json()
                    assert proposal_response.status == 503, denial
                    assert denial == {
                        "error": "execution_unavailable",
                        "code": "execution_unavailable"}
                    assert adm._store_counts(store) == counts_before
                    assert store.b2b_attempt(
                        profile="deploy", attempt_id=ATTEMPT) is None
                    assert store.b2b_binding(
                        session_id=SESSION, profile="deploy") is None
                    assert adapter._session_db.get_session(SESSION)["title"] is None
                    assert not provider_requests
                    purposes = [
                        envelope["body"]["purpose"] for envelope in source.requests]
                    assert "before_provider" not in purposes
                    assert "before_seal" not in purposes
                    assert not source.errors
                    return

                if revoke_at is None:
                    import agent.system_prompt as system_prompt

                    def fail_timestamp(*args, **kwargs):
                        raise AssertionError("native prompt consulted the timestamp")

                    monkeypatch.setattr(
                        system_prompt, "_timestamp_line", fail_timestamp)

                proposal_response = await client.post(
                    route + "/b2b-proposal",
                    json={"attempt_id": ATTEMPT, "binding_digest": BINDING},
                    headers=headers)
                admission = await proposal_response.json()
                assert proposal_response.status == 200, admission
                run_id = admission["run_id"]
                settled = False
                for _ in range(400):
                    attempt = store.b2b_attempt(
                        profile="deploy", attempt_id=ATTEMPT)
                    if (store.b2b_artifact(attempt_id=ATTEMPT, kind="proposal")
                            is not None or (attempt and attempt["status"] in {
                                "context_unavailable", "context_stale",
                                "source_denied", "policy_changed",
                                "result_invalid", "failed", "sealed",
                                "completed", "cancelled", "interrupted",
                                "indeterminate"})):
                        settled = True
                        break
                    await asyncio.sleep(0.05)
                assert settled, store.b2b_attempt(
                    profile="deploy", attempt_id=ATTEMPT)
                artifact_kinds = {
                    row["kind"] for row in store._conn.execute(
                        "SELECT kind FROM b2b_artifacts WHERE attempt_id=?",
                        (ATTEMPT,)).fetchall()}
                if revoke_at is None:
                    assert store.b2b_artifact(
                        attempt_id=ATTEMPT, kind="proposal") is not None
                    assert {"context", "provider_dispatch", "provider_result",
                            "proposal"} <= artifact_kinds
                    assert len(provider_requests) == 1
                    sent = provider_requests[0]
                    assert [message["role"] for message in sent["messages"]] == [
                        "system", "user"]
                    assert sent["messages"][0]["content"] == NATIVE_RECIPE_SYSTEM_PROMPT
                    assert hashlib.sha256(canonical_json(
                        sent["messages"])).hexdigest() == messages_digest
                    assert not sent.get("tools")
                elif revoke_at == "before_provider":
                    assert not provider_requests
                    assert "provider_dispatch" not in artifact_kinds
                    assert store.b2b_artifact(
                        attempt_id=ATTEMPT, kind="proposal") is None
                else:
                    assert len(provider_requests) == 1
                    assert "provider_dispatch" in artifact_kinds
                    assert store.b2b_artifact(
                        attempt_id=ATTEMPT, kind="provider_result") is not None
                    assert store.b2b_artifact(
                        attempt_id=ATTEMPT, kind="proposal") is None

                counts_before = adm._store_counts(store)
                title_before = adapter._session_db.get_session(SESSION)["title"]
                manifest_path.unlink(missing_ok=True)
                replay_response = await client.post(
                    route + "/b2b-proposal",
                    json={"attempt_id": ATTEMPT, "binding_digest": BINDING},
                    headers=headers)
                replay = await replay_response.json()
                assert replay_response.status == 200, replay
                assert replay["status"] == "replayed"
                assert replay["run_id"] == run_id
                assert adm._store_counts(store) == counts_before
                assert adapter._session_db.get_session(SESSION)["title"] == title_before
                assert len(provider_requests) == (1 if revoke_at == "before_seal" or
                                                  revoke_at is None else 0)

                if revoke_at is None:
                    changed_authority = True
                    changed_response = await client.post(
                        route + "/b2b-proposal",
                        json={"attempt_id": ATTEMPT, "binding_digest": BINDING},
                        headers=headers)
                    assert changed_response.status in {403, 409}
                    assert adm._store_counts(store) == counts_before
            assert not source.errors
            purposes = [envelope["body"]["purpose"] for envelope in source.requests]
            if revoke_at is not None:
                assert "before_provider" in purposes
            if revoke_at == "before_seal":
                assert "before_seal" in purposes
    finally:
        if adapter is not None:
            tasks = list(getattr(adapter, "_active_run_tasks", {}).values())
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        await provider_server.close()
        for resource in resources:
            try:
                resource.close()
            except Exception:
                pass
