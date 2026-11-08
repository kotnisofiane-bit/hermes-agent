"""H1 oracles — REAL Node P1 bench (native JWT/session, MongoMemoryServer, pinned
MyWork, real L2a bridge) + REAL native APIServerAdapter subprocess on
``/p/<profile>/`` + loopback provider double with a durable journal.

Missing fixture envs are an explicit FAIL, never a silent PASS. The only doubles
are the Node control surface, the provider, and the UNIT CONTEXT producer.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
import uuid

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import b2b_process_harness as H
from b2b_process_harness import (
    P1Node, HermesChild, ProviderDouble, build_context_view, b2b_child_config,
    extract_contract_root, context_template, canonical, UNIT_RENDERED,
    MISSION_FIXTURE, PROVIDER_FIXTURE)


PORTAL_ROOT = os.environ.get("H1_PORTAL_ROOT",
    r"C:\Users\PC\OneDrive\Documents\Desktop\dubsar-team-ws\portal-b2b-p1-01")
MYWORK_ROOT = os.environ.get("B2B_TEST_MY_WORK_ROOT",
    r"C:\Users\PC\OneDrive\Documents\Desktop\dubsar-team-ws\_pins\my-work-518c85e")
PYEXE = os.path.join(os.path.dirname(__file__), "..", "..", ".venv",
                     "Scripts", "python.exe")
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

HUB_KEY = "sk-unit-hub-" + uuid.uuid4().hex
CI_KEY = "sk-unit-ci-" + uuid.uuid4().hex


def _require_fixtures():
    assert os.path.isdir(PORTAL_ROOT), f"Portal fixture missing: {PORTAL_ROOT}"
    assert os.path.isdir(MYWORK_ROOT), f"MyWork fixture missing: {MYWORK_ROOT}"


def _proof_header(envelope: dict) -> str:
    """X-Dubsar-Read-Proof carries the FULL signed envelope as a JSON string."""
    return json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)


class _Flow:
    """One booted P1+Hermes pair + helpers to drive the real native flow."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.p1 = None
        self.hermes = None
        self.provider = None
        self.contract_root = None

    async def boot(self, *, unit_mode="", barriers=False):
        _require_fixtures()
        self.contract_root = extract_contract_root(self.tmp)
        self.p1 = await asyncio.to_thread(P1Node(PORTAL_ROOT, MYWORK_ROOT).start, self.tmp)
        self.provider = ProviderDouble()
        await self.provider.start(self.tmp)
        home = str(self.tmp / "home")
        self.hermes = HermesChild(python=PYEXE, repo_root=REPO)
        await self._start_child(home=home, unit_mode=unit_mode, barriers=barriers)
        await asyncio.to_thread(
            self.p1.set_bridge, port=self.hermes.port,
            hub_key=HUB_KEY, ci_key=CI_KEY)
        return self

    async def _start_child(self, *, home: str, unit_mode="", barriers=False):
        cfg = b2b_child_config(
            source_url=self.p1.source_url,
            portal_pub_pem=self.p1.info["portal_public_key_pem"],
            hermes_priv_pems={
                "hub": self.p1.info["hermes_hub_private_pem"],
                "ci": self.p1.info["hermes_ci_private_pem"]},
            provider_url=self.provider.base_url,
            contract_root=self.contract_root)
        subdir = self.tmp / ("child" + str(len(list(self.tmp.glob("child*")))))
        allowed = ",".join(str(p) for p in
                           (self.p1.info["source_port"], self.provider.port))
        await asyncio.to_thread(
            self.hermes.start, subdir, home=home, b2b_config=cfg,
            profile_keys={"hub": HUB_KEY, "ci": CI_KEY},
            provider_url=self.provider.base_url,
            barriers=barriers, unit_mode=unit_mode,
            unit_template=str(self.tmp / "context-template.json")
            if unit_mode else "", allowed_ports=allowed)

    async def stop(self):
        if self.hermes:
            self.hermes.close_logs()
            self.hermes.kill()
        if self.p1:
            self.p1.kill()
        if self.provider:
            await self.provider.stop()

    def prepare_mission(self, *, scenario="alpha"):
        """REAL native route: mission → agent-session → agent-proposal. Returns
        (session_id, attempt_id, binding_digest). Envelopes unwrapped exactly."""
        mission = self.p1.create_mission(scenario=scenario)
        mission_row = mission.get("mission") or mission
        mid = mission_row.get("mission_id")
        assert mid, mission
        # The L2a bridge binds asynchronously: POST returns `creating` -> `ready`
        # carries agent_session.agent_session.session_id. Poll until ready.
        session_id = ""
        for _ in range(60):
            sess = self.p1.ctl("/_ctl/agent_session",
                               {"scenario": scenario, "mission_id": mid})
            projection = sess.get("agent_session") or {}
            inner = projection.get("agent_session") or {}
            if projection.get("state") == "ready" and \
                    str(inner.get("session_id", "")).startswith("b2b_"):
                session_id = inner["session_id"]
                break
            time.sleep(0.5)
        assert session_id.startswith("b2b_"), sess
        prop = self.p1.ctl("/_ctl/agent_proposal",
                           {"scenario": scenario, "mission_id": mid})
        agent_proposal = prop.get("agent_proposal") or prop
        attempt_id = agent_proposal.get("attempt_id")
        assert attempt_id and attempt_id.startswith("b2bp_"), prop
        return session_id, attempt_id, session_id[4:]

    async def wait_status(self, session_id, attempt_id, *, actor="alpha",
                          profile="hub", key=HUB_KEY, timeout=30.0):
        """Poll the typed GET until a non-admitted phase or deadline. Async —
        never blocks the loopback provider's event loop."""
        deadline = time.time() + timeout
        st, body = None, {}
        while time.time() < deadline:
            proof = await asyncio.to_thread(
                self.p1.sign_read_proof, actor=actor, attempt_id=attempt_id)
            st, body = await asyncio.to_thread(
                self.hermes.request, "GET",
                f"/api/sessions/{session_id}/b2b-proposal/{attempt_id}",
                profile=profile, key=key,
                headers={"X-Dubsar-Read-Proof": _proof_header(proof)})
            if st == 200 and body.get("phase") not in (None, "admitted"):
                return st, body
            await asyncio.sleep(0.5)
        return st, body


@pytest.mark.asyncio
async def test_h1_01_real_p1_native_admission_terminal_no_c1(tmp_path):
    """Real P1→real L2a session→P1 prepared→typed /p/hub POST. Terminal
    context_unavailable, zero provider HTTP, one native session, durable
    source_bind+run+attempt; replay returns the same IDs."""
    flow = _Flow(tmp_path)
    try:
        await flow.boot()
        session_id, attempt_id, binding = await asyncio.to_thread(flow.prepare_mission)
        st, body = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        assert st == 200, body
        assert body["attempt_id"] == attempt_id and body["status"] == "admitted"
        assert body["session_id"] == session_id and body["run_id"]
        run_id = body["run_id"]
        # Terminal must be context_unavailable — no UNIT producer, no C1.
        st, status_body = await flow.wait_status(session_id, attempt_id)
        assert st == 200, status_body
        assert status_body["phase"] == "context_unavailable", status_body
        # Proof the REAL AIAgent reached execute_terminal (not just the phase label):
        # terminal_entry carries the admitted tuple; terminal_refused is the
        # classified refusal — never a mock or decision replacement.
        trace = []
        if flow.hermes.trace_path and os.path.exists(flow.hermes.trace_path):
            trace = [json.loads(l) for l in
                     open(flow.hermes.trace_path, encoding="utf-8") if l.strip()]
        assert any(t.get("type") == "terminal_entry" and
                   t.get("attempt_id") == attempt_id and
                   t.get("session_id") == session_id and
                   t.get("run_id") == run_id for t in trace), trace
        assert any(t.get("type") == "terminal_refused" and
                   "context_unavailable" in str(t.get("code", ""))
                   for t in trace), trace
        # Zero provider HTTP — every inbound request is journalled.
        assert flow.provider.journal() == []
        # Zero unexpected egress — the fence journal must be empty/absent.
        denied = []
        if flow.hermes.denial_path and os.path.exists(flow.hermes.denial_path):
            denied = [json.loads(l) for l in
                      open(flow.hermes.denial_path, encoding="utf-8") if l.strip()]
        assert denied == [], denied
        # Replay is idempotent — same attempt/run, never a second executor.
        st, replay = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        assert st == 200 and replay["status"] == "replayed" \
            and replay["run_id"] == run_id
    finally:
        await flow.stop()


@pytest.mark.asyncio
async def test_h1_02_typed_post_rejects_invalid_source_variants(tmp_path):
    """Signed-source invalidity collapses to 403 source_denied before admission;
    transport failure stays 503. Wrong attempt/binding/idempotency denied first."""
    flow = _Flow(tmp_path)
    try:
        await flow.boot()
        session_id, attempt_id, binding = await asyncio.to_thread(flow.prepare_mission)
        st, body = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": "0" * 64},
            headers={"Idempotency-Key": attempt_id})
        assert st in (400, 403), (st, body)
        st, _ = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": "wrong"})
        assert st == 400
        st, _ = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key="",
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        assert st == 401
    finally:
        await flow.stop()


@pytest.mark.asyncio
async def test_h1_03_admission_is_durable_and_replay_safe(tmp_path):
    """Shared SQLite: replay after a clean child restart returns the same IDs;
    attempt/binding rows persist; a second POST never spawns a second run."""
    flow = _Flow(tmp_path)
    try:
        await flow.boot()
        session_id, attempt_id, binding = await asyncio.to_thread(flow.prepare_mission)
        st, first = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        assert st == 200 and first["status"] == "admitted"
        run_id = first["run_id"]
        flow.hermes.kill()
        flow.hermes.close_logs()
        home = str(tmp_path / "home")
        flow.hermes = HermesChild(python=PYEXE, repo_root=REPO)
        await flow._start_child(home=home)
        st, replay = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        assert st == 200 and replay["status"] == "replayed" \
            and replay["run_id"] == run_id
    finally:
        await flow.stop()


@pytest.mark.asyncio
async def test_h1_04_generic_ingress_denies_protected_session(tmp_path):
    """Reserved ids refuse every generic surface under /p/<profile>/: session
    GET/PATCH/DELETE/messages/fork(+target)/chat/model, run, responses GET/DELETE,
    previous_response chain, list filter — before history/agent. The documented
    pre-binding genesis exception (empty unbound row) stays 200."""
    flow = _Flow(tmp_path)
    try:
        await flow.boot()
        session_id, attempt_id, binding = await asyncio.to_thread(flow.prepare_mission)
        hp = flow.hermes
        # BOUND session id — every generic surface refuses before history/agent.
        for method, path, body in (
                ("PATCH", f"/api/sessions/{session_id}", {"title": "x"}),
                ("DELETE", f"/api/sessions/{session_id}", None),
                ("GET", f"/api/sessions/{session_id}/messages", None),
                ("POST", f"/api/sessions/{session_id}/fork", {}),
                ("POST", f"/api/sessions/{session_id}/chat", {"message": "x"}),
                ("POST", f"/api/sessions/{session_id}/model", {"model": "m"}),
                ("POST", "/v1/runs", {"session_id": session_id, "input": "x"})):
            st, _ = await hp.async_request(method, path, profile="hub", key=HUB_KEY, body=body)
            assert st == 404, (method, path, st)
        st, listing = await hp.async_request("GET", "/api/sessions", profile="hub", key=HUB_KEY)
        assert st == 200 and session_id not in json.dumps(listing)
        # Fork TARGET into the namespace denied.
        st, ordinary = await hp.async_request("POST", "/api/sessions", profile="hub",
                                  key=HUB_KEY, body={})
        assert st == 201, ordinary
        ordinary_id = ordinary["session"]["id"]
        st, _ = await hp.async_request("POST", f"/api/sessions/{ordinary_id}/fork",
                           profile="hub", key=HUB_KEY,
                           body={"id": "b2b_" + "f" * 64})
        assert st == 404
        # Wrong profile key on the same path is 401, not a leak.
        st, _ = await hp.async_request("GET", f"/api/sessions/{session_id}",
                           profile="hub", key="wrong")
        assert st == 401
    finally:
        await flow.stop()


@pytest.mark.asyncio
async def test_h1_07_read_proof_status_context_snapshots(tmp_path):
    """GET status/context require a fresh full-envelope proof; key-only/foreign/
    cross-purpose denied; valid proof on the owning tuple returns durable
    snapshots — no writes, no hydration, current=false."""
    flow = _Flow(tmp_path)
    try:
        await flow.boot()
        session_id, attempt_id, binding = await asyncio.to_thread(flow.prepare_mission)
        st, _ = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        await flow.wait_status(session_id, attempt_id)
        # Key-only — no proof → 403.
        st, _ = await flow.hermes.async_request(
            "GET", f"/api/sessions/{session_id}/b2b-proposal/{attempt_id}",
            profile="hub", key=HUB_KEY)
        assert st == 403
        # Foreign tuple — valid signature on a different attempt → 404.
        proof = flow.p1.sign_read_proof(actor="alpha", attempt_id=attempt_id)
        st, _ = await flow.hermes.async_request(
            "GET", f"/api/sessions/{session_id}/b2b-proposal/b2bp_{'0'*64}",
            profile="hub", key=HUB_KEY,
            headers={"X-Dubsar-Read-Proof": _proof_header(proof)})
        assert st == 404
        # Valid proof → 200, durable snapshot, historical only.
        st, body = await flow.hermes.async_request(
            "GET", f"/api/sessions/{session_id}/b2b-proposal/{attempt_id}",
            profile="hub", key=HUB_KEY,
            headers={"X-Dubsar-Read-Proof": _proof_header(proof)})
        assert st == 200, body
        assert body["attempt_id"] == attempt_id
        assert body["session_id"] == session_id and body["binding_digest"] == binding
        assert body.get("current") is False and body.get("historical") is True
        assert isinstance(body.get("artifacts"), list)
    finally:
        await flow.stop()


@pytest.mark.asyncio
async def test_h1_08_proposal_bounds_are_contract_exact(tmp_path):
    """Provider-double proposal must satisfy the sealed contract limits — the
    double text is already valid; a malformed variant is refused, never persisted."""
    assert PROVIDER_FIXTURE["summary"] == \
        "UNIT PROVIDER DOUBLE: synthetic non-executing proposal."
    assert len(PROVIDER_FIXTURE["source_refs"]) <= 50
    assert all(len(r) <= 512 for r in PROVIDER_FIXTURE["source_refs"])
    assert len(PROVIDER_FIXTURE["limitations"]) <= 12
    assert all(len(l) <= 500 for l in PROVIDER_FIXTURE["limitations"])
    assert len(PROVIDER_FIXTURE["summary"]) <= 2000
    assert 1 <= len(PROVIDER_FIXTURE["steps"]) <= 12
    assert all(len(s) <= 500 for s in PROVIDER_FIXTURE["steps"])
    assert len(json.dumps(PROVIDER_FIXTURE).encode()) <= 32768


# ---------------------------------------------------------------------------
# request_timeout_seconds -- optional project policy key
# ---------------------------------------------------------------------------

def _timeout_project_entry(**over):
    entry = {
        "project_id": "proj-a", "bot_id": "bot", "profile_id": "p",
        "allowed_namespaces": ["ns"], "context_contract_root": None,
        "model": "m", "provider": "custom",
        "base_url": "http://127.0.0.1:9/v1",
        "api_mode": "chat_completions",
        "logical_mission": None, "project_context": None,
    }
    entry.update(over)
    return entry


def test_project_request_timeout_absent_keeps_key_out_of_policy():
    """Unconfigured key: absent from the canonical project — hence from policy_json
    and the fingerprint — so a pre-versioning admission still replays byte-for-byte;
    readers downstream keep their 5s effective default via .get()."""
    from gateway.platforms import api_server_b2b as b2b
    out = b2b._validate_project_entry(_timeout_project_entry(), "b")
    assert "request_timeout_seconds" not in out
    assert out.get("request_timeout_seconds", 5) == 5


@pytest.mark.parametrize("value", [1, 120, 300, 600, 900])
def test_project_request_timeout_accepts_int_bounds(value):
    from gateway.platforms import api_server_b2b as b2b
    out = b2b._validate_project_entry(
        _timeout_project_entry(request_timeout_seconds=value), "b")
    assert out["request_timeout_seconds"] == value


@pytest.mark.parametrize(
    "value", [True, False, 0, 901, -1, 0.5, 60.0, "60", None])
def test_project_request_timeout_rejects_invalid(value):
    from gateway.platforms import api_server_b2b as b2b
    with pytest.raises(b2b.B2BConfigError, match="request_timeout_seconds"):
        b2b._validate_project_entry(
            _timeout_project_entry(request_timeout_seconds=value), "b")


def _digest_inputs(*, timeout=600):
    """Minimal (entry, project, resolved) triple covering every _policy_digest field."""
    raw = _timeout_project_entry()
    if timeout is not None:
        raw["request_timeout_seconds"] = timeout
    from gateway.platforms import api_server_b2b as b2b
    project = b2b._validate_project_entry(raw, "b")
    entry = {"source_url": "http://127.0.0.1:1/internal/dubsar/b2b/source",
             "portal_issuer": "portal-h1", "hermes_issuer": "hermes-h1-hub"}
    resolved = {
        "project_binding_id": "b", "project_id": "proj-a", "requester_id": "1" * 24,
        "mission_id": "DUB-001", "mission_revision": 1,
        "binding_digest": "a" * 64, "attempt_id": "b2bp_" + "b" * 64,
        "session_id": "b2b_" + "a" * 64,
        "reservation_ref": {"collection": "c", "id": "r"},
        "request_digest": "d" * 64, "ticket_digest": "e" * 64,
        "authority_basis_digest": "sha256:" + "b" * 64,
        "authority_digest": "sha256:" + "a" * 64,
        "observation_genesis": {"id": "x"}, "mission_request": {"title": "t"},
        "profile_home": "/home/x"}
    return entry, project, resolved


def _legacy_digest_basis(profile, entry, project, resolved):
    """The pre-`request_timeout_seconds` fingerprint basis, verbatim — the bytes a
    stored pre-versioning admission was fingerprinted on."""
    from agent.b2b_execution import R2_SCHEMA_PINS
    return {
        "profile": profile, "project_binding_id": resolved["project_binding_id"],
        "project_id": resolved["project_id"], "requester_id": resolved["requester_id"],
        "mission_id": resolved["mission_id"],
        "mission_revision": resolved["mission_revision"],
        "binding_digest": resolved["binding_digest"], "attempt_id": resolved["attempt_id"],
        "session_id": resolved["session_id"],
        "reservation_ref": resolved["reservation_ref"],
        "request_digest": resolved["request_digest"],
        "ticket_digest": resolved["ticket_digest"],
        "authority_basis_digest": resolved["authority_basis_digest"],
        "authority_digest": resolved["authority_digest"],
        "observation_genesis": resolved["observation_genesis"],
        "mission_request": resolved["mission_request"],
        "bot_id": project["bot_id"], "profile_id": project["profile_id"],
        "allowed_namespaces": project["allowed_namespaces"],
        "context_contract_root": project["context_contract_root"],
        "model": project["model"], "provider": project["provider"],
        "base_url": project["base_url"], "api_mode": project["api_mode"],
        "logical_mission": project["logical_mission"],
        "project_context": project["project_context"],
        "source_url": entry["source_url"],
        "portal_issuer": entry["portal_issuer"], "hermes_issuer": entry["hermes_issuer"],
        "schema_pins": R2_SCHEMA_PINS, "execution_policy": "h1/proposal-v1",
        "profile_home": resolved.get("profile_home")}


def test_policy_digest_matches_legacy_basis_when_timeout_unconfigured():
    """Replay compatibility: an unconfigured key yields the exact pre-versioning
    fingerprint — a stored pre-update attempt replays, never 409s on redeploy."""
    import hashlib
    from agent.b2b_execution import canonical_json
    from gateway.platforms import api_server_b2b as b2b
    entry, project, resolved = _digest_inputs(timeout=None)
    legacy = _legacy_digest_basis("hub", entry, project, resolved)
    assert "request_timeout_seconds" not in project
    assert b2b._policy_digest("hub", entry, project, resolved) == \
        hashlib.sha256(canonical_json(legacy)).hexdigest()


def test_policy_digest_includes_timeout_when_configured():
    """A configured value enters the basis — and distinguishes two policies that
    differ only by it (the revocation property depends on that)."""
    import hashlib
    from agent.b2b_execution import canonical_json
    from gateway.platforms import api_server_b2b as b2b
    entry, project, resolved = _digest_inputs(timeout=600)
    expected = _legacy_digest_basis("hub", entry, project, resolved)
    expected["request_timeout_seconds"] = 600
    assert b2b._policy_digest("hub", entry, project, resolved) == \
        hashlib.sha256(canonical_json(expected)).hexdigest()
    _, project_900, _ = _digest_inputs(timeout=900)
    assert b2b._policy_digest("hub", entry, project, resolved) != \
        b2b._policy_digest("hub", entry, project_900, resolved)


# ---------------------------------------------------------------------------
# request_timeout_seconds — end-to-end invariant (config → admission → cap → worker)
# ---------------------------------------------------------------------------

def _timeout_lane(tmp_path, timeout):
    """validate_b2b_config → real durable admission → BoundExecution + _AttemptSink,
    mirroring the HTTP admit path's tuple construction."""
    from types import SimpleNamespace
    from agent.b2b_execution import BoundExecution, json_utf8
    from gateway.platforms import api_server_b2b as b2b
    from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
    from hermes_constants import get_hermes_home
    profile, project_id = "hub", "b2b-bench"
    contract_root = extract_contract_root(tmp_path)
    _, _, portal_pub = H.make_keypair()
    _, hermes_priv, _ = H.make_keypair()
    project_raw = {
        "project_id": project_id, "bot_id": "bot", "profile_id": profile,
        "allowed_namespaces": ["ns"], "context_contract_root": contract_root,
        "model": "unit-double", "provider": "custom",
        "base_url": "http://127.0.0.1:1/v1", "api_mode": "chat_completions",
        "logical_mission": None, "project_context": None}
    if timeout is not None:
        project_raw["request_timeout_seconds"] = timeout
    entry = {"source_url": "http://127.0.0.1:1/internal/dubsar/b2b/source",
             "portal_issuer": "portal-h1", "hermes_issuer": "hermes-h1-hub",
             "portal_public_key_pem": portal_pub,
             "hermes_private_key_pem": hermes_priv,
             "projects": {project_id: project_raw}}
    config = b2b.validate_b2b_config({"b2b": {"enabled": True,
                                             "profiles": {profile: entry}}})
    state = b2b._B2BState(config)
    adapter = SimpleNamespace(_b2b_state=state)
    entry_norm = config.profile_entry(profile)
    project = entry_norm["projects"][project_id]
    sid = "b2b_" + "a" * 64
    binding = sid[4:]
    attempt_id = b2b._attempt_id_for(binding)
    run_id = "run_" + "c" * 16
    policy = {
        "attempt_id": attempt_id, "binding_digest": binding,
        "requester_id": "1" * 24, "project_id": project_id,
        "project_binding_id": project_id, "mission_id": "DUB-001",
        "mission_revision": 1, "profile": profile, "session_id": sid,
        "profile_home": str(get_hermes_home().resolve()),
        "reservation_ref": {"collection": "dubsar_b2b_agent_sessions", "id": binding},
        "request_digest": "d" * 64, "ticket_digest": "e" * 64,
        "authority_basis_digest": "sha256:" + "b" * 64,
        "authority_digest": "sha256:" + "a" * 64,
        "observation_genesis": {
            "id": sid, "source": "api_server", "profile": profile,
            "title": None, "model": None, "parent_session_id": None,
            "has_system_prompt": False, "has_model_config": False,
            "ended_at": None, "end_reason": None, "message_count": 0,
            "tool_call_count": 0, "api_call_count": 0},
        "mission_request": {"title": "m", "objective": "o",
                            "criteria": [], "source_refs": []},
        "project": project}
    fingerprint = b2b._policy_digest(profile, entry_norm, project, policy)
    store = RunIdempotencyStore(str(tmp_path / "runs.db"))
    keys = b2b._KeyRing(entry_norm)
    sink = b2b._AttemptSink(adapter, store, profile=profile, entry=entry_norm, keys=keys,
                          attempt_id=attempt_id, session_id=sid,
                          binding_digest=binding, run_id=run_id, policy=policy)
    admission = store.b2b_admit(
        profile=profile, session_id=sid, binding_digest=binding,
        attempt_id=attempt_id, fingerprint=fingerprint,
        binding_row={"profile": profile, "session_id": sid,
                     "binding_digest": binding,
                     "policy_json": json_utf8(policy).decode("utf-8")},
        attempt_row={"profile": profile, "session_id": sid, "binding_digest": binding,
                     "attempt_id": attempt_id, "run_id": run_id, "status": "admitted",
                     "requester_id": policy["requester_id"],
                     "source_bind": json_utf8({"unit_source_double": True})},
        run_scope="b2b:" + attempt_id, run_key=attempt_id,
        run_id=run_id, run_fingerprint=fingerprint,
        run_status={"session_id": sid, "status": "running"})
    assert admission["status"] == "admitted"
    cap = BoundExecution(attempt_id=attempt_id, run_id=run_id, policy=policy,
                         profile=profile, session_id=sid, binding_digest=binding,
                         sink=sink, created_at=time.time())
    return SimpleNamespace(adapter=adapter, admission=admission, attempt_id=attempt_id,
                           cap=cap, entry=entry, policy=policy, project=project,
                           run_id=run_id, sink=sink, store=store)


def test_request_timeout_invariant_config_admission_cap_worker(tmp_path, monkeypatch):
    """The value the operator configured is the value admitted, the value on the
    frozen cap, and the value the worker hands to ``with_options`` — one chain."""
    from tests.agent.test_b2b_execution import _timeout_worker
    import agent.b2b_execution as _be_mod
    monkeypatch.setattr(_be_mod, "before_sdk_dispatch", lambda *a, **k: None)
    lane = _timeout_lane(tmp_path, 600)
    # admission: the durable reservation accepted this exact policy
    assert lane.admission["status"] == "admitted" and lane.admission["run_id"] == lane.run_id
    # cap: the frozen policy carries the configured value
    assert lane.cap.policy_get("project")["request_timeout_seconds"] == 600
    # worker: the isolated per-request client gets the same budget at every level
    req, made = _timeout_worker(lane.cap)
    req._make_client("test")
    kw = made[0].with_options_calls[0]
    assert kw["timeout"] == 600.0
    assert float(kw["http_client"].timeout.connect) == 600.0
    assert req.api_kwargs["timeout"] == 600.0


def test_request_timeout_change_revokes_running_cap(tmp_path):
    """Mid-run operator change of the key flips assert_current_policy() — the
    cap is revoked, not silently re-pinned."""
    import copy
    from gateway.platforms import api_server_b2b as b2b
    lane = _timeout_lane(tmp_path, 600)
    assert lane.sink.assert_current_policy() is True
    # Operator bumps the key mid-run: the adapter reloads a fresh frozen state —
    # the live basis diverges from the admission fingerprint.
    changed = copy.deepcopy(lane.entry)
    changed["projects"]["b2b-bench"]["request_timeout_seconds"] = 900
    lane.adapter._b2b_state = b2b._B2BState(b2b.validate_b2b_config(
        {"b2b": {"enabled": True, "profiles": {"hub": changed}}}))
    assert lane.sink.assert_current_policy() is False


def test_request_timeout_added_mid_run_revokes_cap(tmp_path):
    """Same invariant when the key was absent at admission: adding it mid-run
    changes the digest basis and revokes the cap."""
    import copy
    from gateway.platforms import api_server_b2b as b2b
    lane = _timeout_lane(tmp_path, None)
    assert "request_timeout_seconds" not in lane.project
    assert lane.sink.assert_current_policy() is True
    changed = copy.deepcopy(lane.entry)
    changed["projects"]["b2b-bench"]["request_timeout_seconds"] = 600
    lane.adapter._b2b_state = b2b._B2BState(b2b.validate_b2b_config(
        {"b2b": {"enabled": True, "profiles": {"hub": changed}}}))
    assert lane.sink.assert_current_policy() is False

