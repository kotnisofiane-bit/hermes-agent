"""H1 oracles — REAL Node P1 bench (native JWT/session, MongoMemoryServer, pinned
MyWork, real L2a bridge) + REAL native APIServerAdapter subprocess on
``/p/<profile>/`` + loopback provider double with a durable journal.

Integration lane ONLY (``pytest -m integration``): the normal suite deselects
this whole file. It requires two EXTERNAL checkouts provisioned by the runner —
``H1_PORTAL_ROOT`` (P1 Portal checkout) and ``B2B_TEST_MY_WORK_ROOT`` (pinned
MyWork fixture) — and a Node toolchain. Missing fixture envs are an explicit
FAIL, never a silent PASS. The only doubles are the Node control surface, the
provider, and the UNIT CONTEXT producer.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sqlite3
import sys
import time
import uuid

import pytest

pytestmark = pytest.mark.integration

sys.path.insert(0, os.path.dirname(__file__))
import b2b_process_harness as H
from b2b_process_harness import (
    P1Node, HermesChild, ProviderDouble, build_context_view, b2b_child_config,
    extract_contract_root, context_template, canonical, UNIT_RENDERED,
    MISSION_FIXTURE)


# External checkouts the lane's runner must provision explicitly — no local
# developer paths are ever inferred.
PORTAL_ROOT = os.environ.get("H1_PORTAL_ROOT") or ""
MYWORK_ROOT = os.environ.get("B2B_TEST_MY_WORK_ROOT") or ""
PYEXE = sys.executable
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

HUB_KEY = "sk-unit-hub-" + uuid.uuid4().hex
CI_KEY = "sk-unit-ci-" + uuid.uuid4().hex


def _require_fixtures():
    missing = [name for name, value in
               (("H1_PORTAL_ROOT", PORTAL_ROOT), ("B2B_TEST_MY_WORK_ROOT", MYWORK_ROOT))
               if not value]
    assert not missing, (
        "integration lane selected but fixture envs unset: "
        + ", ".join(missing)
        + " — provision the external checkouts or run the normal suite")
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


def _journal_counts(home: str) -> dict:
    """Durable b2b/native rows inside the child's runs_idempotency.db.

    The store is at the adapter's own HERMES_HOME root — a missing DB or schema
    is a provisioning failure to surface, not a silent all-zero "no writes"."""
    db = os.path.join(home, "runs_idempotency.db")
    assert os.path.isfile(db), f"run idempotency store missing: {db}"
    conn = sqlite3.connect(db)
    try:
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        wanted = ("run_idempotency", "b2b_attempts", "b2b_bindings", "b2b_artifacts")
        assert set(wanted) <= tables, f"store schema incomplete: {tables}"
        return {table: conn.execute(
            f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in wanted}
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_h1_01_real_p1_native_admission_refuses_at_construction(tmp_path):
    """Real P1→real L2a session→P1 prepared→typed /p/hub POST. The lane
    admits (durable attempt), the spawned run reaches construction, and the
    child's lane — whose operator inputs (``project_context``) are absent —
    durably refuses ``context_unavailable`` before runtime/provider/CAS. A
    repeat POST replays non-consuming."""
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
        assert body.get("status") == "admitted"
        # The admitted run refuses at construction: durable context_unavailable.
        st, status = await flow.wait_status(session_id, attempt_id)
        assert st == 200, status
        assert status.get("phase") == "context_unavailable", status
        # A repeat POST replays the recorded admission — never a second attempt.
        st, body = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        assert st == 200 and body.get("status") == "replayed", body
        counts_after = _journal_counts(str(tmp_path / "home"))
        st, body = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        assert st == 200 and body.get("status") == "replayed", body
        assert _journal_counts(str(tmp_path / "home")) == counts_after
        # The refusal never reaches the terminal seam or the run executor:
        # zero terminal trace entries.
        trace = []
        if flow.hermes.trace_path and os.path.exists(flow.hermes.trace_path):
            trace = [json.loads(l) for l in
                     open(flow.hermes.trace_path, encoding="utf-8") if l.strip()]
        assert not any(t.get("type") == "terminal_entry" for t in trace), trace
        # Zero provider HTTP — every inbound request is journalled.
        assert flow.provider.journal() == []
        # Zero unexpected egress — the fence journal must be empty/absent.
        denied = []
        if flow.hermes.denial_path and os.path.exists(flow.hermes.denial_path):
            denied = [json.loads(l) for l in
                      open(flow.hermes.denial_path, encoding="utf-8") if l.strip()]
        assert denied == [], denied
    finally:
        await flow.stop()


@pytest.mark.asyncio
async def test_h1_02_typed_post_rejects_invalid_variants_before_admission(tmp_path):
    """Request validation still runs before admission: wrong binding digest →
    403, wrong idempotency key → 400, missing key → 401; a fully valid request
    reaches admission (the signed source exchange + durable admit)."""
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
        st, body = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        assert st == 200 and body.get("status") == "admitted", body
    finally:
        await flow.stop()


@pytest.mark.asyncio
async def test_h1_03_replay_stays_non_consuming_across_restart(tmp_path):
    """Shared SQLite + child restart: the admitted attempt is durable, so a
    POST after a clean restart replays it — never a second consumed attempt
    or a re-admission."""
    flow = _Flow(tmp_path)
    try:
        await flow.boot()
        session_id, attempt_id, binding = await asyncio.to_thread(flow.prepare_mission)
        st, first = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        assert st == 200 and first.get("status") == "admitted", first
        st, status = await flow.wait_status(session_id, attempt_id)
        assert st == 200 and status.get("phase") == "context_unavailable", status
        flow.hermes.kill()
        flow.hermes.close_logs()
        home = str(tmp_path / "home")
        counts_before = _journal_counts(home)
        flow.hermes = HermesChild(python=PYEXE, repo_root=REPO)
        await flow._start_child(home=home)
        st, second = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        assert st == 200 and second.get("status") == "replayed", second
        assert _journal_counts(home) == counts_before
    finally:
        await flow.stop()


@pytest.mark.asyncio
async def test_h1_04_generic_ingress_denies_protected_session(tmp_path):
    """Reserved ids refuse every generic surface under /p/<profile>/: session
    GET/PATCH/DELETE/messages/fork(+target)/chat/model, run, responses GET/DELETE,
    previous_response chain, list filter — before history/agent."""
    flow = _Flow(tmp_path)
    try:
        await flow.boot()
        session_id, attempt_id, binding = await asyncio.to_thread(flow.prepare_mission)
        hp = flow.hermes
        # Reserved genesis session id (L2a-created, never admitted — the POST
        # lane refuses) — every generic surface refuses before history/agent.
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
        # Wrong profile key on the same path is 401, not a leak — and even the
        # documented pre-binding genesis exception never applies here: this row
        # was L2a-created but a foreign credential still gets 401, not a peek.
        st, _ = await hp.async_request("GET", f"/api/sessions/{session_id}",
                           profile="hub", key="wrong")
        assert st == 401
    finally:
        await flow.stop()


@pytest.mark.asyncio
async def test_h1_07_read_proof_gates_status_then_refused_snapshot(tmp_path):
    """GET status/context still require a fresh full-envelope proof — key-only
    403, foreign tuple 404 — and a VALID proof on the owning tuple reads the
    durable ``context_unavailable`` snapshot the admitted lane recorded."""
    flow = _Flow(tmp_path)
    try:
        await flow.boot()
        session_id, attempt_id, binding = await asyncio.to_thread(flow.prepare_mission)
        st, body = await flow.hermes.async_request(
            "POST", f"/api/sessions/{session_id}/b2b-proposal",
            profile="hub", key=HUB_KEY,
            body={"attempt_id": attempt_id, "binding_digest": binding},
            headers={"Idempotency-Key": attempt_id})
        assert st == 200 and body.get("status") == "admitted", body
        st, status = await flow.wait_status(session_id, attempt_id)
        assert st == 200 and status.get("phase") == "context_unavailable", status
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
        # Valid proof on the owning tuple → typed snapshot of the durable
        # refusal: the lane is auditable even when it never reached dispatch.
        st, body = await flow.hermes.async_request(
            "GET", f"/api/sessions/{session_id}/b2b-proposal/{attempt_id}",
            profile="hub", key=HUB_KEY,
            headers={"X-Dubsar-Read-Proof": _proof_header(proof)})
        assert st == 200, body
        assert body.get("phase") == "context_unavailable", body
        assert body.get("historical") is True and body.get("current") is False
    finally:
        await flow.stop()
