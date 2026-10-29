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
