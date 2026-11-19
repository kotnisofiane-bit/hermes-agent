"""Lot-1 native N2 lane: REAL boundary tests, no doubles for the verified data.

Every proof here crosses the product boundary: real Ed25519 request/response
envelopes signed and verified through ``_signed_envelope`` / ``_verify_envelope``
on a real loopback aiohttp source, the native body shape verifier, the real
``_AttemptSink._matches_source`` (with a real ``_B2BState``/fingerprint), the
protected manifest reader, the canonical ``_b2b_documents`` host check through a
real ``BoundExecution``, and the ``assert_terminal_runtime`` recipe gate through
the real ``bind_execution`` contextvar.

Honest scope note: the security-owned manifest/installation records require
UID 32013 ancestors and ownership this host cannot fabricate, so every
manifest/installation proof asserted here is the fail-closed side — absent,
unsafe-owner, wrong-pin files all refuse. A positive manifest proof would
need the privileged fixture slot; it is not simulated.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import time
import uuid
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from agent.b2b_execution import (
    B2BTerminalRefusal, BoundExecution, assert_terminal_runtime, bind_execution,
    canonical_json, install_bounded_agent_policy, reset_execution,
)
from gateway.platforms import api_server_b2b as m
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


def _docs(mission=MISSION):
    """Two real six-key piece manifests with genuine UTF-8 text digests."""
    out = []
    for index, text in enumerate(("pièce α — première", "pièce β — seconde")):
        piece = f"piece_{(index + 1):032x}"
        digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        out.append({
            "id": piece, "revision": 1, "text": text,
            "content_digest": digest, "native_digest": digest,
            "native_ref": f"dubsar:piece:{mission}:{piece}"})
    return out


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
            reply = self._respond(envelope)
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
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)


def _response_envelope(request_env, body):
    now = int(time.time())
    env = {"version": m._VERSION, "issuer": PORTAL_ISSUER,
           "audience": HERMES_ISSUER, "operation": "resolved",
           "request_id": request_env["request_id"], "issued_at": now,
           "expires_at": now + 15, "body": body}
    env["signature"] = m._b64url(
        PORTAL_PRIV.sign(m._DOMAIN + canonical_json(env)))
    return env


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


@pytest.mark.parametrize(("original_count", "expected_reason"), [
    (16, "ok"),
    (17, "body_native"),
])
def test_native_signed_source_combined_reference_cap(original_count, expected_reason):
    entry, keys = _entry_and_keys()
    refs = _flat([f"source:{index}" for index in range(original_count)], _docs())
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
    assert m._read_native_run_authorization(ref) is None
    # A file we can create fails every proof: /tmp is world-writable and our
    # UID is never 32013 — the refusal is the fail-closed side only.
    directory = tempfile.mkdtemp(prefix="n2-manifest-")
    path = os.path.join(directory, "recipe.json")
    payload = json.dumps({
        "format": "dubsar.b2b-n2-recipe/1", "boot_id": m._boot_id(),
        "classification": "public_synthetic", "dataset_id": "ds-1",
        "binding": {}, "request_digest": "a" * 64,
        "mission_source_digest": "b" * 64, "messages_digest": "c" * 64})
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(payload)
    assert m._read_native_run_authorization(
        {"path": path,
         "sha256": hashlib.sha256(payload.encode()).hexdigest()}) is None
    for ref in (None, {}, {"path": "relative/x", "sha256": "a" * 64},
                {"path": path, "sha256": "b" * 64},
                {"path": path}):
        assert m._read_native_run_authorization(ref) is None, ref


# ---------------------------------------------------------------------------
# _b2b_documents: canonical manifest + ordered pair enumeration.
# ---------------------------------------------------------------------------

def _cap(policy):
    return BoundExecution(
        profile="deploy", session_id=SESSION, binding_digest=BINDING,
        attempt_id=ATTEMPT, run_id="run_" + uuid.uuid4().hex, policy=policy,
        sink=SimpleNamespace(assert_current_policy=lambda: True),
        created_at=time.time())


def _documents_case(refs=None, view_refs=None):
    docs = _docs()
    flat = _flat(["dubsar:mission:objective"], docs)
    policy = {"mission_id": MISSION,
              "native_n2_binding": {"tenant_id": TENANT, "project_id": PROJECT,
                                    "mission_inputs": _pointer(docs)}}
    plain = {"my_work": {"mission": {
        "references": flat if view_refs is None else view_refs}}}
    resolved = {"mission_request": {
        "source_refs": flat if refs is None else refs}}
    return docs, _cap(policy), plain, resolved


def test_b2b_documents_native_exact_manifest():
    docs, cap, plain, resolved = _documents_case()
    proven = _b2b_documents(docs, cap=cap, plain=plain, resolved=resolved)
    assert [d["native_ref"] for d in proven] == [d["native_ref"] for d in docs]


@pytest.mark.parametrize("mutate", [
    "missing_documents", "empty_documents", "reordered_pairs",
    "foreign_mission_ref", "wrong_manifest_digest", "view_only_reorder",
])
def test_b2b_documents_native_mutations_refuse(mutate):
    docs, cap, plain, resolved = _documents_case()
    flat = _flat(["dubsar:mission:objective"], docs)
    if mutate == "missing_documents":
        raw = None
    elif mutate == "empty_documents":
        raw = []
    else:
        raw = docs
    if mutate == "reordered_pairs":
        resolved = {"mission_request": {
            "source_refs": flat[:1] + flat[3:] + flat[1:3]}}
    elif mutate == "view_only_reorder":
        plain = {"my_work": {"mission": {
            "references": flat[:1] + flat[3:] + flat[1:3]}}}
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
        _b2b_documents(raw, cap=cap, plain=plain, resolved=resolved)


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
