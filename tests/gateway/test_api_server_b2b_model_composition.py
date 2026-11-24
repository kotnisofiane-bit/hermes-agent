"""Opt-in composition with genuine Core issuance, G2, Core-LLM and Unix relay."""
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path

import pytest
from aiohttp import web
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from agent.b2b_execution import native_recipe_messages
from tests.gateway import test_api_server_b2b_native_n2 as lane


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        value = sock.getsockname()[1]
        assert value >= 20000
        return value


class Installation:
    def __init__(self, stack, temp, core_root):
        from scribe.core_mission_boundary import core_mission_boundary as missions
        from scribe.model_authorization import PUBLIC_PIECES

        self.stack, self.temp, self.core_root = stack, temp, core_root
        self.gateway_port, self.core_port = port(), port()
        while self.core_port == self.gateway_port:
            self.core_port = port()
        self.store = temp / "core-store"
        store = missions._MissionStore(str(self.store))
        store.write_index({"by_project_ref": {"synthetic-project": lane.PROJECT}, "by_idempotency": {}})
        now = "2026-01-01T00:00:00Z"
        missions.create_mission_draft({
            "schema": missions.REQUEST_SCHEMA, "contract_version": "0.1", "request_id": "create1",
            "project_ref": "synthetic-project", "workspace_ref": "synthetic-workspace",
            "objective": "o", "session_ref": "session1", "correlation_id": "correlation1",
            "idempotency_key": "create1",
            "workspace_summary": {"manifest_digest": "1"*64, "manifest_entry_count": 0, "markers": []}},
            store_dir=str(self.store), now=now, new_id=lambda p: lane.MISSION if p == "mis" else p + "_aaaa")
        key = os.urandom(32)
        missions.activate_mission({"schema": missions.ACTIVATE_SCHEMA, "contract_version": "0.1",
                                   "request_id": "activate1", "mission_id": lane.MISSION},
                                  store_dir=str(self.store), now=now, attestation_key=key,
                                  authenticated_actor={"actor_kind": "human", "actor_id": "synthetic-actor",
                                                       "attestation": missions._mission_go_attestation(
                                                           key, "synthetic-actor", lane.MISSION)})
        self.frozen = missions.freeze_exact_revision(store_dir=str(self.store), mission_id=lane.MISSION)
        self.documents = lane._docs()
        for doc, text in zip(self.documents, PUBLIC_PIECES):
            digest = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
            doc.update(text=text, native_digest=digest, content_digest=digest)

    def issue_and_start(self, prepared, core_key, hermes_key, provider_url, request, rendered, manifest):
        from backend.control_plane_g1.b2b_n4_config import load_n4_config
        from backend.control_plane_g1.b2b_n4_provider import load_n4_provider_arm, result_public_key, result_signer
        from backend.control_plane_g1.b2b_n4_recipe import N4RecipeCompletion
        from backend.control_plane_g1.b2b_n4_relay import N4RelayClient, N4RelayServer
        from backend.control_plane_g1.core_server import CoreDecisionServer
        from backend.control_plane_g1.core_transport import HttpCoreTransport
        from backend.control_plane_g1.gateway_server import GatewayServer
        from backend.control_plane_g1.nvidia_nim import NvidiaNimTransport
        from backend.control_plane_g1.provider_transport import BoundedUrllibExecutor
        from scribe.model_authorization import ENDPOINT, ROUTE

        integrity = b"synthetic-integrity-key-integration-only"
        review = {"mission_id": lane.MISSION, "snapshot_digest": self.frozen["snapshot_digest"],
                  "result_public_key": result_public_key(result_signer(integrity)),
                  "ports": {"core_llm": self.core_port, "gateway": self.gateway_port},
                  "endpoint": ENDPOINT, "model_route": ROUTE, "tenant_id": lane.TENANT,
                  "requester_id": lane.REQUESTER, "request_id": prepared["request_id"],
                  "hermes_key": hermes_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
                  "issuer": lane.HERMES_ISSUER, "audience": lane.PORTAL_ISSUER,
                  "documents": [{"native_ref": d["native_ref"], "revision": 1, "digest": d["native_digest"]}
                                for d in self.documents],
                  "messages": native_recipe_messages(request, rendered.encode())}
        source = lane._resolved_body({"request_id": "synthetic-prepared", "body": {
            "attempt_id": lane.ATTEMPT, "profile": "deploy", "session_id": lane.SESSION}}, docs=self.documents)
        review.update(mission_inputs=source["mission_inputs"], request_digest=source["request_digest"],
                      mission_source_digest=source["mission_source_digest"])
        review_path, prep, seed = (self.temp / n for n in ("review.json", "prepared.json", "seed"))
        prep.write_text(json.dumps(prepared))
        review_path.write_text(json.dumps(review))
        seed.write_bytes(base64.b64encode(core_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())))
        seed.chmod(0o600)
        review_path.chmod(0o600)
        cmd = [os.environ.get("DUBSAR_CORE_PYTHON", sys.executable), "-m", "scribe.model_authorization",
               "--store", str(self.store), "--prepared", str(prep), "--review", str(review_path),
               "--signing-key", str(seed)]
        kwargs = dict(cwd=self.core_root, capture_output=True, text=True, timeout=3)
        # Re-signing for the same attempt must not replace the first decision.
        result = subprocess.run(cmd, check=True, **kwargs)
        issued = json.loads(result.stdout)
        assert subprocess.run(cmd, **kwargs).returncode != 0
        raw = Path(issued["path"]).read_bytes()
        manifest.write_bytes(raw)
        self.sha = issued["sha256"]
        public = core_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

        def load():
            return load_n4_config(manifest, self.sha, public)

        cfg = load()
        sock = self.temp / "relay.sock"
        self.relay = N4RelayServer(load(), sock, os.geteuid())
        self.relay.start()
        self.stack.callback(self.relay.stop)
        core_cfg = load()
        service = "synthetic-core-service-key-integration-only"
        core = CoreDecisionServer(catalog=core_cfg.catalog, integrity_key=integrity,
                                  governance_profile=core_cfg.profile, host="127.0.0.1",
                                  port=self.core_port, service_key=service)
        core.start()
        self.stack.callback(core.stop)
        target = provider_url + "/chat/completions"
        assert target.startswith("http://127.0.0.1:") and int(provider_url.split(":")[-1].split("/")[0]) >= 20000

        class LoopbackExecutor:
            def post(self, url, headers, body, *, timeout):
                assert url == ENDPOINT
                return BoundedUrllibExecutor().post(target, headers, body, timeout=timeout)

        directory = self.temp / "security"
        directory.mkdir()
        arm_path = directory / "arm"
        arm_raw = json.dumps({"schema": "dubsar.g2-n4-provider-arm/1", "approval_sha256": self.sha,
                              "armed": True, "provider_id": ROUTE["provider_id"], "model": lane.MODEL}).encode()
        arm_path.write_bytes(arm_raw)
        arm_path.chmod(0o400)
        directory.chmod(0o555)
        self.stack.callback(directory.chmod, 0o700)
        arm = load_n4_provider_arm(arm_path, hashlib.sha256(arm_raw).hexdigest(), os.geteuid(),
                                   self.sha, NvidiaNimTransport(api_key="test-only", http_executor=LoopbackExecutor()),
                                   service_uid=os.geteuid()+1)
        arm.claim_path = self.temp / lane.ATTEMPT
        gateway = GatewayServer(core_transport=HttpCoreTransport(cfg.core_decide_url, service_key=service),
                                integrity_key=integrity, governance_profile=cfg.profile, catalog=cfg.catalog,
                                proof_events=[], gateway_access_secret="synthetic-probe-key-integration-only",
                                n4_relay=N4RelayClient(cfg, sock, os.geteuid()),
                                n4_recipe=N4RecipeCompletion(self.sha, "unit-native-provider-key"),
                                n4_provider=arm, host="127.0.0.1", port=self.gateway_port)
        gateway.start()
        self.stack.callback(gateway.stop)
        self.gateway = gateway
        self.core_context = core_cfg.context_id
        self.provider_port = int(provider_url.split(":")[-1].split("/")[0])
        return json.loads(raw)

    @staticmethod
    def provider_response(proposal):
        def chunk(delta, finish):
            return "data: " + json.dumps({"id": "local", "object": "chat.completion.chunk",
                                          "model": lane.MODEL, "choices": [{"index": 0, "delta": delta,
                                                                            "finish_reason": finish}]}) + "\n\n"
        return web.Response(text=chunk({"role": "assistant", "content": json.dumps(proposal)}, None)
                            + chunk({}, "stop") + "data: [DONE]\n\n", content_type="text/event-stream")


@pytest.mark.asyncio
@pytest.mark.linux_only
async def test_core_preparation_to_one_fake_provider_receipt(tmp_path, monkeypatch, record_property):
    core, backend = os.environ.get("DUBSAR_SCRIBE_BUILDER"), os.environ.get("DUBSAR_SCRIBE_BACKEND")
    if not core or not backend:
        pytest.skip("set both Scribe checkout roots for the local composition")
    monkeypatch.syspath_prepend(core)
    monkeypatch.syspath_prepend(backend)
    monkeypatch.setenv("TOOL_LAYER_PROVIDER_ARMED", "0")
    with ExitStack() as stack:
        # The privileged install contract rejects any world-writable ancestor,
        # including /tmp. Do not bypass its check in the composition.
        path = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix=".authz-", dir=core)))
        installation = Installation(stack, path, core)
        await lane.test_native_http_prepare_admission_replay_and_revocation(
            tmp_path, monkeypatch, None, "valid", installation=installation)
        assert len(installation.relay.records) == 1
        assert (path / lane.ATTEMPT).read_text() == installation.sha
        state = installation.gateway.state
        assert state.provider_forward_count == state.provider_egress_attempt_count == 1
        assert installation.core_context == "n4-" + installation.sha
        assert state.n4_relay.config.approval_sha256 == installation.relay.config.approval_sha256 == installation.sha
        for name, value in {"attempt_id": lane.ATTEMPT, "approval_sha256": installation.sha,
                            "core_context_id": installation.core_context, "gateway_port": installation.gateway_port,
                            "fake_provider_port": installation.provider_port, "relay_ack": installation.relay.records[0]["ack"],
                            "provider_forward_count": state.provider_forward_count,
                            "provider_egress_attempt_count": state.provider_egress_attempt_count}.items():
            record_property(name, value)
