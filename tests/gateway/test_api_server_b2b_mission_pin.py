"""Lot 7 PIN (AUTORITE-PRODUCTION §6.4 / §7 line 7): one production mission id.

The shared §5.2 vectors (byte-identical copy across the PIN repositories) cross
the real B2B boundaries of this repository:

* the signed resolved-source body (``_verify_resolved_body``), first gate of the
  POST admission path;
* the per-execution AgentContext qualification (``qualify_context_view``), which
  validates against the pinned Contracts r2 schemas and keeps every identity
  equality (context, binding, My Work ticket/authority, Memory provenance, OC).

An old Contracts pin or a DUB/wide ``mis_`` regex left on the active production
path fails these tests. No private test child: the real functions are called.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import tempfile
import zlib
from pathlib import Path

import pytest

import agent.b2b_execution as be
from agent.b2b_execution import B2BTerminalRefusal, BoundExecution
from gateway.platforms import api_server_b2b as b2b
from hermes_constants import get_hermes_home
from tests.gateway import b2b_process_harness as H

ROOT = Path(__file__).resolve().parents[2]
VECTORS_PATH = ROOT / "tests" / "fixtures" / "b2b" / "b2b-mission-id-vectors.json"
VECTORS_SHA256 = "46cac1d7ca6ddef8f19da3e754bcffd4171507f3cb10242076347d7244529068"
VECTORS = json.loads(VECTORS_PATH.read_bytes())
A, B = VECTORS["identity_pairs"]["crossed"]
INVALID = [item["value"] for item in VECTORS["invalid"]]

# Active production B2B path of this repository.
PRODUCTION_FILES = sorted(
    [*ROOT.glob("gateway/platforms/api_server_b2b*.py"), *ROOT.glob("agent/b2b_*.py")])
LEGACY_R2_CONTRACTS_COMMIT = "2b0865261e80432103e6beb38e5beea0ce60dad0"


# --------------------------------------------------------------------------
# Shared vectors and pin attestation
# --------------------------------------------------------------------------

def test_shared_vectors_are_the_byte_identical_copy():
    assert hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest() == VECTORS_SHA256
    assert VECTORS["format"] == "dubsar.b2b-pin.mission-id-vectors/1"
    assert VECTORS["pattern"] == "^mis_[a-f0-9]{32}$"


def test_r2_schema_pins_attest_the_common_contracts_head():
    contracts = VECTORS["contracts"]
    assert be.R2_SCHEMA_CONTRACTS == {
        "repository": contracts["repository"], "commit": contracts["commit"],
        "tree": contracts["tree"]}
    # The embedded schema bytes are the Contracts head bytes the pins name.
    assert dict(be.R2_SCHEMA_PINS) == H.R2_PINS
    assert not set(be.R2_SCHEMA_PINS.values()) & set(H.LEGACY_R2_PINS.values())
    root = H.extract_contract_root(tempfile.mkdtemp(prefix="b2b-pin-"))
    for name in be.R2_SCHEMA_PINS:
        text = Path(root, name).read_text("utf-8")
        assert "DUB-" not in text, name
    binding = json.loads(Path(root, "mission-binding.schema.json").read_text("utf-8"))
    assert '"pattern": "^mis_[a-f0-9]{32}$"' in json.dumps(binding)


def test_no_old_pin_or_dub_regex_on_the_active_production_path():
    refused_commits = set(VECTORS["contracts_commits_refused_on_production_path"])
    refused_commits.add(LEGACY_R2_CONTRACTS_COMMIT)
    refused_hashes = set(H.LEGACY_R2_PINS.values())
    assert PRODUCTION_FILES
    for path in PRODUCTION_FILES:
        text = path.read_text("utf-8")
        assert not re.search(r"DUB-", text), path
        assert not re.search(r"mis_\[a-f0-9\]\{1[0-9]?,", text), path  # Mlarge
        for value in refused_commits | refused_hashes:
            assert value not in text, (path, value)
    assert be.B2B_MISSION_ID.pattern == r"\Amis_[a-f0-9]{32}\Z"
    assert b2b._MISSION_ID is be.B2B_MISSION_ID


def test_mission_regex_matches_the_vectors_exactly():
    for value in VECTORS["valid"]:
        assert be.is_b2b_mission_id(value), value
    for value in INVALID:
        assert not be.is_b2b_mission_id(value), value
    for value in (None, 1, b"mis_" + b"0" * 32, ["mis_" + "0" * 32]):
        assert not be.is_b2b_mission_id(value)


# --------------------------------------------------------------------------
# Boundary 1: signed resolved-source body (POST admission path)
# --------------------------------------------------------------------------

def _resolved(mission_id: str, *, tuple_mission: str | None = None):
    profile, requester, project = "hub", "1" * 24, "b2b-bench"
    basis = {"format": "dubsar.b2b-agent-session-binding/1",
             "requester_id": requester, "project_id": project,
             "mission_id": tuple_mission if tuple_mission is not None else mission_id,
             "mission_revision": 1}
    binding = hashlib.sha256(be.canonical_json(basis)).hexdigest()
    session_id = "b2b_" + binding
    attempt_id = b2b._attempt_id_for(binding)
    request = {"request_id": "req-pin-1", "signature": "sig",
               "body": {"attempt_id": attempt_id, "profile": profile,
                        "session_id": session_id}}
    body = {
        "attempt_id": attempt_id, "profile": profile, "session_id": session_id,
        "binding_digest": binding, "source_state": "active",
        "reservation_ref": {"collection": "dubsar_b2b_agent_sessions", "id": binding},
        "requester_id": requester, "project_id": project,
        "project_binding_id": project, "mission_id": mission_id,
        "mission_revision": 1, "request_digest": "d" * 64,
        "mission_source_digest": "c" * 64, "ticket_digest": "e" * 64,
        "authority_basis_digest": "sha256:" + "b" * 64,
        "authority_digest": "sha256:" + "a" * 64,
        "observation_genesis": {
            "id": session_id, "source": "api_server", "profile": profile,
            "title": None, "model": None, "parent_session_id": None,
            "has_system_prompt": False, "has_model_config": False,
            "ended_at": None, "end_reason": None, "message_count": 0,
            "tool_call_count": 0, "api_call_count": 0},
        "mission_request": {"title": "m", "objective": "o", "criteria": ["c"],
                            "source_refs": []},
        "source_request_id": request["request_id"],
        "source_request_digest": hashlib.sha256(
            be.canonical_json(request)).hexdigest(),
    }
    return body, request, profile, session_id


@pytest.mark.parametrize("mission_id", VECTORS["valid"])
def test_resolved_body_accepts_m32(mission_id):
    body, request, profile, session_id = _resolved(mission_id)
    checked, reason = b2b._verify_resolved_body(
        body, request=request, profile=profile, session_id=session_id)
    assert reason == "ok"
    assert checked["mission_id"] == mission_id  # propagated without conversion


@pytest.mark.parametrize("mission_id", INVALID)
def test_resolved_body_refuses_every_non_m32_vector(mission_id):
    body, request, profile, session_id = _resolved(mission_id)
    checked, reason = b2b._verify_resolved_body(
        body, request=request, profile=profile, session_id=session_id)
    assert (checked, reason) == (None, "body_mission")


def test_resolved_body_refuses_crossed_m32_binding_tuple():
    body, request, profile, session_id = _resolved(B, tuple_mission=A)
    checked, reason = b2b._verify_resolved_body(
        body, request=request, profile=profile, session_id=session_id)
    assert (checked, reason) == (None, "body_binding_tuple")


# --------------------------------------------------------------------------
# Boundary 2: AgentContext qualification against the pinned Contracts schemas
# --------------------------------------------------------------------------

def _policy(mission_id: str, contract_root: str) -> dict:
    return {
        "profile": "p", "profile_home": str(get_hermes_home().resolve()),
        "project_id": "proj-a", "mission_id": mission_id, "mission_revision": 1,
        "authority_basis_digest": "sha256:" + "b" * 64,
        "authority_digest": "sha256:" + "a" * 64,
        "requester_id": "req-1", "mission_request": {"title": "T", "objective": "O"},
        "project": {
            "project_id": "proj-a", "bot_id": "bot", "profile_id": "p",
            "allowed_namespaces": ["ns"], "context_contract_root": contract_root,
            "model": "unit-double", "provider": "custom",
            "base_url": "http://127.0.0.1:9/unit-double",
            "api_mode": "chat_completions"},
    }


def _cap(mission_id: str, contract_root: str | None = None) -> BoundExecution:
    class _Sink:
        context_receipt = None

        def put_context(self, receipt):
            self.context_receipt = receipt

    root = contract_root or H.extract_contract_root(tempfile.mkdtemp(prefix="b2b-pin-"))
    return BoundExecution(
        profile="p", session_id="b2b_" + "a" * 64, binding_digest="a" * 64,
        attempt_id="b2bp_" + "b" * 64, run_id="r", policy=_policy(mission_id, root),
        sink=_Sink(), created_at=0)


def _refusal(cap, view) -> str:
    with pytest.raises(B2BTerminalRefusal) as exc:
        be.qualify_context_view(cap, view)
    return str(exc.value)


@pytest.mark.parametrize("mission_id", VECTORS["valid"])
def test_context_accepts_the_same_m32_end_to_end(mission_id):
    cap = _cap(mission_id)
    view = H.build_context_view(cap.policy, {})
    plain = be.qualify_context_view(cap, view)
    assert plain["mission_id"] == mission_id
    assert plain["mission_binding"]["mission_id"] == mission_id
    assert plain["my_work"]["mission"]["ticket_id"] == mission_id
    assert plain["resolved_focus_key"] == "mission:" + mission_id


@pytest.mark.parametrize("mission_id", INVALID)
def test_context_schema_refuses_every_non_m32_vector(mission_id):
    cap = _cap(mission_id)
    view = H.build_context_view(cap.policy, {})
    # Schema first; the exact grammar check catches what JSON Schema "$"
    # tolerates (trailing newline) and an empty bound policy mission.
    assert _refusal(cap, view) in {"context_schema_invalid", "context_mission_id"}


def test_context_exact_grammar_refuses_trailing_newline_after_schema():
    cap = _cap(A + "\n")
    view = H.build_context_view(cap.policy, {})
    assert _refusal(cap, view) == "context_mission_id"


def _crossed(mutate) -> str:
    cap = _cap(A)
    view = H.build_context_view(cap.policy, {})
    mutate(view)
    H.reseal_unit_context_view(view)
    return _refusal(cap, view)


def test_context_refuses_view_of_another_m32_mission():
    cap = _cap(A)
    other = H.build_context_view(_policy(B, cap.policy["project"]["context_contract_root"]), {})
    assert _refusal(cap, other) == "context_identity_mismatch"


def test_context_refuses_my_work_ticket_of_another_mission():
    def mutate(view):
        view["my_work"]["mission"]["ticket_id"] = B
    assert _crossed(mutate) == "context_my_work_mismatch"


def test_context_refuses_my_work_authority_of_another_mission():
    def mutate(view):
        view["my_work"]["mission"]["mission_authority"]["mission_id"] = B
    assert _crossed(mutate) == "context_my_work_authority"


def test_context_refuses_memory_provenance_of_another_mission():
    def mutate(view):
        provenance = view["memory"]["relations"][0]["provenance"]
        provenance.update({
            "mywork_mission_id": B, "mywork_mission_revision": 1,
            "mywork_mission_authority_digest": "sha256:" + "a" * 64})
    assert _crossed(mutate) == "context_memory_mission"


def test_context_refuses_focus_key_of_another_mission():
    def mutate(view):
        view["resolved_focus_key"] = "mission:" + B
    assert _crossed(mutate) == "context_selection_mismatch"


def test_context_refuses_oc_view_of_another_mission():
    def mutate(view):
        view["operational_context"]["view"]["mission_id"] = B
    assert _crossed(mutate) in {"context_oc_mismatch", "context_schema_invalid"}


def test_legacy_dub_contracts_bytes_are_refused_as_contract_root():
    root = os.path.join(tempfile.mkdtemp(prefix="b2b-pin-legacy-"), "contracts")
    os.makedirs(root)
    for key, encoded in H.LEGACY_R2_SCHEMA_B64.items():
        Path(root, H._SCHEMA_FILES[key]).write_bytes(zlib.decompress(base64.b64decode(encoded)))
    cap = _cap(A, root)
    view = H.build_context_view(cap.policy, {})
    assert _refusal(cap, view) == "context_contract_unavailable"


def test_legacy_dub_context_template_is_refused_by_production():
    raw = zlib.decompress(base64.b64decode(H.LEGACY_CONTEXT_TEMPLATE_B64))
    assert hashlib.sha256(raw).hexdigest() == H.LEGACY_CONTEXT_TEMPLATE_SHA256
    legacy = json.loads(raw)
    assert legacy["mission_id"] == "DUB-001"
    cap = _cap("DUB-001")
    view = copy.deepcopy(legacy)
    view["context_digest"] = be.native_context_digest(view)
    assert _refusal(cap, view) == "context_schema_invalid"
