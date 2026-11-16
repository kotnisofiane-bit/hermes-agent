"""P2 native C1 integration, no model or external effect.

Real: API authentication/source signatures, plugin discovery, bound factory,
My Work B2B mission ports, release helper, OC kernel/PostgreSQL, AIAgent turn,
publication, SDK HTTP transport, dispatch CAS and seal.
Doubles: Portal source service, Memory Plane HTTP, model HTTP, OC trust.
The stdio test host composes native My Work ports; it is not an installed MW-O
child, Portal browser proof, or qualification of deployment/network policy.

Select explicitly with --include-integration. B2B_TEST_MY_WORK_ROOT must contain
.p2-native-runtime.json naming explicit mywork/contracts/profile/node/pg_bin and
postgres_url. No runtime dependency is downloaded by the tests.
"""
from __future__ import annotations

import base64
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

import pytest
import yaml

from agent.b2b_execution import canonical_json, mission_prompt
from gateway.platforms import api_server_b2b as b2b
from tests.gateway.b2b_process_harness import extract_contract_root, make_keypair, _sig

pytestmark = pytest.mark.integration
HERE = Path(__file__).parent / "native_b2b"
REPO = HERE.parents[2]


def dump(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        value = sock.getsockname()[1]
    assert value >= 20000
    return value


def http(url, body=None, headers=None):
    request = urllib.request.Request(
        url, data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class Doubles:
    def __init__(self):
        self.sources = {}
        self.provider_calls = []
        self.source_calls = []
        self.memory_calls = []
        self.memory_mode = "valid"
        self.before_provider_hook = None
        self.portal_private, _, self.portal_public = make_keypair()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                raw_body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                # The B2B model-gateway startup probe POSTs an empty,
                # unauthenticated body and requires 401; the real agent
                # request always carries the resolved bearer key.
                if self.path == "/v1/chat/completions" and not (
                        raw_body and self.headers.get("Authorization")):
                    self.send_error(401)
                    return
                body = json.loads(raw_body)
                if self.path == "/internal/dubsar/b2b/source":
                    owner.source_calls.append(copy.deepcopy(body))
                    if (body["body"].get("purpose") == "before_provider"
                            and body["body"].get("profile") == "hub"
                            and owner.before_provider_hook is not None):
                        hook, owner.before_provider_hook = owner.before_provider_hook, None
                        hook()
                    subject = owner.sources[body["body"]["session_id"]]
                    # Verify the actual Hermes request signature too.
                    from cryptography.hazmat.primitives.serialization import load_pem_public_key
                    pub = load_pem_public_key(subject["hermes_public"].encode())
                    unsigned = {k: v for k, v in body.items() if k != "signature"}
                    pub.verify(base64.urlsafe_b64decode(body["signature"] + "=="),
                               b2b._DOMAIN + canonical_json(unsigned))
                    result = dict(subject["resolved"])
                    result.update(source_request_id=body["request_id"],
                                  source_request_digest=hashlib.sha256(canonical_json(body)).hexdigest())
                    now = int(time.time())
                    response = dict(
                        version=b2b._VERSION, issuer="portal-p2", audience=body["issuer"],
                        operation="resolved", request_id=str(uuid.uuid4()),
                        issued_at=now, expires_at=now + 30, body=result)
                    response["signature"] = _sig(response, owner.portal_private)
                elif self.path == "/v2/qualified-context-view":
                    owner.memory_calls.append(copy.deepcopy(body))
                    if owner.memory_mode == "late":
                        time.sleep(2)
                    binding = body["mission_binding"]
                    ns = body["namespace_id"]
                    relation = {
                        "depth": 1, "namespace_id": ns, "predicate": "recorded_context",
                        "relation_id": "p2-" + ns.replace("/", "-"),
                        "statement": "SYNTHETIC P2 " + ns,
                        "subject_key": body.get("subject_key", "project:alpha"),
                        "provenance": {"source_id": "p2-synthetic", "content_digest": "d" * 64,
                                       "mywork_mission_id": binding["mission_id"],
                                       "mywork_mission_revision": binding["revision"],
                                       "mywork_mission_authority_digest": binding["authority_digest"]}}
                    recorded = dict(binding)
                    if owner.memory_mode == "crossed":
                        recorded["mission_id"] = "mis_" + "f" * 32
                    response = {"ok": True, "verb": "qualified-context-view", "result": {
                        "namespace_id": ns,
                        "freshness": "stale" if owner.memory_mode == "stale" else "current",
                        "mission_qualification": "qualified", "mission_binding": recorded,
                        "contradictions": [],
                        "relations": [] if owner.memory_mode == "missing" else [relation]}}
                elif self.path == "/v1/chat/completions":
                    owner.provider_calls.append(copy.deepcopy(body))
                    content = json.dumps({"summary": "Synthetic local proposal",
                                          "steps": ["Review the supplied context"],
                                          "source_refs": [], "limitations": ["Local test double"]})
                    response = {"id": "p2-local", "object": "chat.completion",
                                "created": int(time.time()), "model": "unit-double",
                                "choices": [{"index": 0, "finish_reason": "stop",
                                             "message": {"role": "assistant", "content": content}}],
                                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
                else:
                    self.send_error(404)
                    return
                raw = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        assert self.server.server_port >= 20000
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class NativeLane:
    def __init__(self, root, runtime, mode):
        self.root, self.runtime, self.mode = root, runtime, mode
        self.processes, self.logs = [], []
        self.doubles = Doubles()
        self.home = root / "home"
        self.home.mkdir()
        self.env = {k: os.environ[k] for k in ("PATH", "TMPDIR", "LANG", "TZ") if k in os.environ}
        self.env.update(HOME=str(root), HERMES_HOME=str(self.home), PYTHONPATH=str(REPO),
                        HERMES_DISABLE_LAZY_INSTALLS="1", TIRITH_ENABLED="false",
                        API_SERVER_KEY="p2-root-local-" + "a" * 32)
        self.subjects = {}
        self.database = "p2_" + uuid.uuid4().hex[:12]

    def spawn(self, name, args, env=None, pipe=False):
        log = open(self.root / (name + ".log"), "w+", encoding="utf-8")
        self.logs.append(log)
        proc = subprocess.Popen(args, cwd=REPO, env=env or self.env,
                                stdin=subprocess.PIPE if pipe else subprocess.DEVNULL,
                                stdout=subprocess.PIPE if pipe else log, stderr=log, text=True)
        self.processes.append(proc)
        return proc

    def line(self, proc):
        assert select.select([proc.stdout], [], [], 30)[0], "native child did not answer"
        line = proc.stdout.readline()
        assert line, "native child exited; inspect logs"
        return json.loads(line)

    def control(self, action):
        self.kernel.stdin.write(json.dumps({"action": action}) + "\n")
        self.kernel.stdin.flush()
        return self.line(self.kernel)

    def boot(self):
        runtime = self.runtime
        postgres = runtime["postgres_url"]
        subprocess.run([str(Path(runtime["pg_bin"]) / "createdb"), "--maintenance-db=" + postgres,
                        self.database], check=True, timeout=30, env=self.env)
        dburl = postgres.rsplit("/", 1)[0] + "/" + self.database
        kernel_cfg = {**runtime, "postgres_url": dburl, "root": str(self.root)}
        dump(self.root / "kernel.json", kernel_cfg)
        self.kernel = self.spawn("kernel", [runtime["node"], str(HERE / "kernel_host.mjs"),
                                            str(self.root / "kernel.json")], pipe=True)
        helper = self.line(self.kernel)["helperSocket"]
        contract_root = extract_contract_root(self.root)
        catalog = {}
        for name, logical in (("hub", "alpha"), ("ci", "alpha")):
            project = "hermes-mywork-pilot"
            mid = "mis_" + uuid.uuid4().hex
            start = self.root / name
            start.mkdir()
            allocation = self.root / (name + "-allocation")
            allocation.mkdir()
            mission = json.loads(subprocess.check_output([
                runtime["node"], str(HERE / "make_store.mjs"), runtime["mywork"],
                str(start), "tenant:hostinger-lab", project, mid],
                env=self.env, text=True, timeout=30))
            assert mission["availability"] == "available", mission
            _, private, public = make_keypair()
            requester = ("a" if name == "hub" else "b") * 24
            basis = {"format": "dubsar.b2b-agent-session-binding/1", "requester_id": requester,
                     "project_id": project, "mission_id": mid, "mission_revision": 1}
            binding = hashlib.sha256(canonical_json(basis)).hexdigest()
            sid = "b2b_" + binding
            attempt = b2b._attempt_id_for(binding)
            authority = mission["mission_authority"]
            resolved = {
                "attempt_id": attempt, "authority_basis_digest": authority["basis_digest"],
                "authority_digest": authority["authority_digest"], "binding_digest": binding,
                "mission_id": mid, "mission_revision": authority["revision"],
                "mission_request": {"title": "P2 native lane mission",
                                    "objective": "P2 native qualification mission: bound context read end-to-end.",
                                    "criteria": ["P2 native lane bound read"],
                                    "source_refs": ["native:p2"]},
                "mission_source_digest": mission["source_digest"],
                "observation_genesis": {"id": sid, "source": "api_server", "profile": name,
                    "title": None, "model": None, "parent_session_id": None,
                    "has_system_prompt": False, "has_model_config": False,
                    "ended_at": None, "end_reason": None, "message_count": 0,
                    "tool_call_count": 0, "api_call_count": 0},
                "profile": name, "project_binding_id": project, "project_id": project,
                "request_digest": "d" * 64, "requester_id": requester,
                "reservation_ref": {"collection": "dubsar_b2b_agent_sessions", "id": binding},
                "session_id": sid, "source_state": "active", "ticket_digest": "e" * 64}
            self.doubles.sources[sid] = {"resolved": resolved, "hermes_public": public}
            self.subjects[name] = resolved
            project_context = {"start": str(start), "allocation_root": str(allocation), "project_id": project}
            catalog[name] = {"source_url": self.doubles.origin + "/internal/dubsar/b2b/source",
                "portal_issuer": "portal-p2", "hermes_issuer": "hermes-p2-" + name,
                "portal_public_key_pem": self.doubles.portal_public, "hermes_private_key_pem": private,
                "projects": {project: {"project_id": project, "bot_id": name, "profile_id": name,
                    "allowed_namespaces": ["private/bot/" + name, "shared/project/" + logical],
                    "context_contract_root": contract_root, "model": "unit-double",
                    "provider": "custom", "base_url": self.doubles.origin + "/v1",
                    "api_mode": "chat_completions", "logical_mission": logical + "-default",
                    "project_context": project_context}}}
            home = self.home / "profiles" / name
            (home / "plugins").mkdir(parents=True)
            (home / "plugins/dubsar-agent-context").symlink_to(
                Path(runtime["unpatched_profile"] if self.mode == "legacy_plugin"
                     else runtime["profile"]) / "plugins/dubsar-agent-context")
            settings = {
                "agent_context_readonly": True, "agent_context_version": "v2.r2",
                "b2b_context_automation_results": False, "mission_id": logical + "-default",
                "memory_plane_origin": self.doubles.origin,
                "my_work_mcp_server": "work-" + name, "operational_context_mcp_server": "work-" + name,
                "my_work_start": str(start), "my_work_allocation_root": str(allocation),
                "my_work_project_id": project, "my_work_mission_id": mid}
            cfg = {
                "model": {"default": "unit-double", "provider": "custom",
                          "base_url": self.doubles.origin + "/v1", "api_mode": "chat_completions",
                          "context_length": 256000},
                "compression": {"enabled": False}, "agent": {"max_iterations": 1},
                "plugins": {"enabled": ["dubsar-agent-context"], "entries": {
                    "dubsar-agent-context": {"mcp_allowlist": ["work-" + name], "settings": settings}}},
                "mcp_servers": {"work-" + name: {
                    "command": runtime["node"], "args": [str(HERE / "mcp_host.mjs")],
                    "env": {"MW_REPO": runtime["mywork"], "MW_START": str(start),
                        "MW_ALLOCATION_ROOT": str(allocation), "MW_PROJECT_ID": project,
                        "MW_MISSION_ID": mid, "MW_TENANT_ID": "tenant:hostinger-lab",
                        "DUBSAR_MYWORK_RELEASE_HELPER_SOCKET": helper,
                        "DUBSAR_OC_STATE_PROJECTION": "ordered_snapshot", "HERDR_ENV": "1"},
                    "enabled": True, "supports_parallel_tool_calls": False,
                    "tools": {"include": ["get_mission_context", "get_oc_context_view"],
                              "resources": False, "prompts": False}}}}
            if self.mode == "no_plugin" and name == "hub":
                cfg["plugins"] = {"enabled": [], "entries": {}}
            (home / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
            (home / ".env").write_text(
                f"API_SERVER_KEY=p2-{name}-{'k'*32}\nOPENAI_API_KEY=sk-local-test\n"
                "DUBSAR_MEMORY_PLANE_TOKEN=p2-local-memory\n", encoding="utf-8")
            # Synthetic genesis through the native SessionDB API; no context/proposal fixture.
            from hermes_state import SessionDB
            db = SessionDB(home / "state.db")
            db.create_session(sid, "api_server")
            db.close()
        (self.home / "config.yaml").write_text(yaml.safe_dump({
            "model": {"context_length": 256000}, "compression": {"enabled": False},
            "plugins": {"enabled": []}}), encoding="utf-8")
        self.api_port = port()
        cfg = {"home": str(self.home), "port": self.api_port,
               "ready": str(self.root / "ready.json"),
               "b2b": {"enabled": True, "profiles": catalog},
               "allowed_ports": [self.api_port, self.doubles.server.server_port]}
        dump(self.root / "host.json", cfg)
        self.host = self.spawn("host", [sys.executable, str(HERE / "host.py"), str(self.root / "host.json")])
        deadline = time.monotonic() + 60
        while not (self.root / "ready.json").exists():
            assert self.host.poll() is None, (self.root / "host.log").read_text(encoding="utf-8")[-8000:]
            assert time.monotonic() < deadline, "API host startup timed out"
            time.sleep(.1)
        self.doubles.memory_mode = self.mode if self.mode in ("missing", "stale", "crossed", "late") else "valid"
        if self.mode == "oc_changed":
            self.doubles.before_provider_hook = lambda: self.control("observe")
        elif self.mode == "config_changed":
            self.doubles.before_provider_hook = self._drift_hub_config
        return self

    def _drift_hub_config(self):
        path = self.home / "profiles" / "hub" / "config.yaml"
        cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
        cfg["plugins"]["entries"]["dubsar-agent-context"]["settings"][
            "operational_context_mcp_server"] = "drifted-server"
        path.write_text(yaml.safe_dump(cfg), encoding="utf-8")

    def post(self, profile="hub"):
        s = self.subjects[profile]
        return http(f"http://127.0.0.1:{self.api_port}/p/{profile}/api/sessions/{s['session_id']}/b2b-proposal",
                    {"attempt_id": s["attempt_id"], "binding_digest": s["binding_digest"]},
                    {"Authorization": f"Bearer p2-{profile}-{'k'*32}", "Idempotency-Key": s["attempt_id"]})

    def rows(self, table):
        dbpath = self.home / "runs_idempotency.db"
        with sqlite3.connect(dbpath) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(f"SELECT * FROM {table}")]

    def wait_attempt(self, profile="hub"):
        aid = self.subjects[profile]["attempt_id"]
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            rows = [r for r in self.rows("b2b_attempts") if r["attempt_id"] == aid]
            if rows and rows[0]["status"] not in (
                    "admitted", "context_ready", "dispatch_committed", "result_received"):
                return rows[0]
            time.sleep(.1)
        raise AssertionError((rows, (self.root / "host.log").read_text(encoding="utf-8")[-9000:]))

    def close(self):
        for proc in reversed(self.processes):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        self.doubles.close()
        for log in self.logs:
            log.close()
        subprocess.run([str(Path(self.runtime["pg_bin"]) / "dropdb"),
                        "--maintenance-db=" + self.runtime["postgres_url"], "--if-exists", "--force",
                        self.database], timeout=30, env=self.env, check=True)


@pytest.fixture
def native_lane(tmp_path, request):
    root = os.environ.get("B2B_TEST_MY_WORK_ROOT")
    assert root, "select this integration suite with B2B_TEST_MY_WORK_ROOT provisioned"
    runtime = json.loads((Path(root) / ".p2-native-runtime.json").read_text(encoding="utf-8"))
    # Keep AF_UNIX paths below Linux's 108-byte limit.
    import tempfile
    short = Path(tempfile.mkdtemp(prefix="c1-", dir=os.environ.get("TMPDIR")))
    lane = NativeLane(short, runtime, request.param)
    try:
        yield lane.boot()
    finally:
        lane.close()
        for log in short.glob("*.log"):
            shutil.copy2(log, tmp_path / log.name)
        shutil.rmtree(short)


@pytest.mark.parametrize("native_lane", ["valid"], indirect=True)
def test_native_post_publishes_seals_and_replays_across_profiles(native_lane):
    lane = native_lane
    for profile in ("hub", "ci"):
        status, result = lane.post(profile)
        assert status == 200, (
            result, "prepare_context plugin patch required for native admission")
        row = lane.wait_attempt(profile)
        assert row["status"] == "proposal_ready", (row, (lane.root / "host.log").read_text(encoding="utf-8")[-8000:])
        replay_status, replay = lane.post(profile)
        assert replay_status == 200 and replay["run_id"] == result["run_id"]
    # A -> B -> A: a removed source cannot cause redispatch of admitted A.
    lane.doubles.memory_mode = "missing"
    assert lane.post("hub")[0] == 200
    assert len(lane.doubles.provider_calls) == 2
    for body, profile in zip(lane.doubles.provider_calls, ("hub", "ci")):
        assert not body.get("tools") and body.get("stream") is not True
        assert sum(m["role"] == "user" for m in body["messages"]) == 1
        content = body["messages"][-1]["content"]
        assert content.startswith(mission_prompt(lane.subjects[profile]["mission_request"]) + "\n\n")
        assert lane.subjects[profile]["mission_id"] in content
        other = "ci" if profile == "hub" else "hub"
        assert lane.subjects[other]["mission_id"] not in content
    assert lane.control("status")["observations"] == 1
    # Durable artifacts carry the native evidence at every boundary.
    for body, profile in zip(lane.doubles.provider_calls, ("hub", "ci")):
        aid = lane.subjects[profile]["attempt_id"]
        arts = {r["kind"]: json.loads(r["payload"])
                for r in lane.rows("b2b_artifacts") if r["attempt_id"] == aid}
        assert {"context", "source_before_provider", "provider_dispatch",
                "provider_result", "source_before_seal", "context_recheck",
                "proposal"} <= set(arts), sorted(arts)
        published = arts["context"]
        assert published["format"] == "dubsar.b2b-context-artifact/1"
        # The provider's user message IS exactly mission prompt + persisted bytes.
        assert body["messages"][-1]["content"] == (
            mission_prompt(lane.subjects[profile]["mission_request"])
            + "\n\n" + published["rendered"])
        published_oc = published["view"]["operational_context"]["view"]
        assert published_oc["format"] == "dubsar.my-work-oc-context-view/2"
        obs_ref = published_oc["state_projection"]["candidate"]["observation_ref"]
        assert published_oc["view_ref"].startswith("ocv_") and obs_ref.startswith("oco_")
        # Dispatch and seal each carried a FRESH native OC read of the same source.
        view_refs = [published_oc["view_ref"]]
        for kind in ("provider_dispatch", "context_recheck"):
            recheck = arts[kind].get("context_recheck", arts[kind])
            assert recheck["format"] == "dubsar.b2b-context-recheck/2"
            oc = recheck["view"]["operational_context"]["view"]
            view_refs.append(oc["view_ref"])
            assert oc["state_projection"]["candidate"]["observation_ref"] == obs_ref
        assert len(set(view_refs)) == 3, view_refs
        proposal = arts["proposal"]
        assert proposal["state"] == "prepared" and proposal["attempt_id"] == aid
        assert proposal["context_digest"] == published["context_digest"]
        assert proposal["mission_id"] == lane.subjects[profile]["mission_id"]


@pytest.mark.parametrize("native_lane,expected", [
    # Second OC observation between publication and dispatch: the recheck
    # refuses context_stale inside the conversation loop -> run failure.
    ("oc_changed", "failed"),
    # The signed before_provider exchange rewrites the plugin read-port.
    # _matches_source revalidates the preparation: the plugin raises
    # b2b_policy_changed, durably classified as policy_changed before dispatch.
    ("config_changed", "policy_changed")], indirect=["native_lane"])
def test_native_drift_blocks_dispatch_without_model_calls(native_lane, expected):
    lane = native_lane
    status, result = lane.post("hub")
    assert status == 200, (
        result, "prepare_context plugin patch required for native admission")
    row = lane.wait_attempt("hub")
    assert row["status"] == expected, (row, (lane.root / "host.log").read_text(encoding="utf-8")[-8000:])
    assert lane.doubles.provider_calls == []
    aid = lane.subjects["hub"]["attempt_id"]
    kinds = {r["kind"] for r in lane.rows("b2b_artifacts") if r["attempt_id"] == aid}
    # The drift landed at the real boundary: the signed before_provider
    # exchange ran, but no dispatch/result/proposal artifact was committed.
    assert any(c["body"].get("purpose") == "before_provider"
               for c in lane.doubles.source_calls)
    assert kinds <= {"source_bind", "context"}
    # Replay returns the same durable run and never redispatches the provider.
    replay_status, replay = lane.post("hub")
    assert replay_status == 200 and replay["run_id"] == result["run_id"]
    assert lane.doubles.provider_calls == []


@pytest.mark.parametrize("native_lane", [
    pytest.param("no_plugin", id="no-plugin-503"),
    # The shipped producer at 05d7394c does not register prepare_context:
    # same fail-closed 503 as no plugin at all, zero durable rows.
    pytest.param("legacy_plugin", id="unchanged-plugin-without-prepare-context-503"),
    "missing", "stale", "crossed", "late"], indirect=True)
def test_native_bad_context_never_consumes_admission(native_lane):
    lane = native_lane
    status, result = lane.post()
    assert status == 503 and result["error"] == "execution_unavailable", result
    time.sleep(2.2 if lane.mode == "late" else .1)
    assert lane.rows("b2b_attempts") == []
    assert lane.rows("b2b_bindings") == []
    assert lane.doubles.provider_calls == []
