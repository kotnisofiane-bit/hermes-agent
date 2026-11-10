"""Shared UNIT fixture builders for B2B governed-lane tests.

All context / source / provider data below are UNIT CONTEXT/SOURCE DOUBLES --
never a real AgentContext/C1 build or P1 exchange. The RunIdempotencyStore is a
real disk SQLite file, ``_AttemptSink`` is the production sink, the r2 schemas
are the pinned production blobs and every admission/commit goes through the
real BEGIN IMMEDIATE transactions.
"""

from __future__ import annotations

import os
import time
import weakref
from types import SimpleNamespace

from agent.b2b_execution import (
    BoundExecution, bind_execution, json_utf8, reset_execution,
)
from gateway.platforms import api_server_b2b as b2b
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from hermes_constants import get_hermes_home
from tests.gateway.b2b_process_harness import (
    UNIT_RENDERED, build_context_view, extract_contract_root, make_keypair,
)


def build_b2b_dispatch_lane(tmp_path, *,
                            provider_base_url="http://127.0.0.1:1/v1",
                            mission_source_refs=(),
                            project_id="b2b-bench",
                            view_factory=build_context_view):
    """One admitted B2B attempt with a published context receipt -- ready for the
    dispatch fence. NO CAS and NO result commit: ``status == "context_ready"``.

    Returns a namespace: ``store, sink, cap, receipt, resolved, view, policy,
    entry, adapter, agent, db_path`` plus the identity ids. ``resolved`` is the
    unit ``before_provider`` source double; tests drive ``cas_dispatch`` /
    ``commit_result`` through the real sink when they need them.
    """
    contract_root = extract_contract_root(tmp_path)
    profile = "hub"
    sid = "b2b_" + "a" * 64
    binding = sid[4:]
    attempt_id = b2b._attempt_id_for(binding)
    run_id = "run_" + "c" * 16
    now = time.time()
    _, _, portal_pub = make_keypair()
    _, hermes_priv, _ = make_keypair()
    entry = {"source_url": "http://127.0.0.1:1/internal/dubsar/b2b/source",
             "portal_issuer": "portal-h1", "hermes_issuer": "hermes-h1-hub",
             "portal_public_key_pem": portal_pub,
             "hermes_private_key_pem": hermes_priv,
             "projects": {project_id: {
                 "project_id": project_id, "bot_id": "bot", "profile_id": profile,
                 "allowed_namespaces": ["ns"], "context_contract_root": contract_root,
                 "model": "unit-double", "provider": "custom",
                 "base_url": provider_base_url, "api_mode": "chat_completions",
                 "logical_mission": None, "project_context": None}}}
    config = b2b.B2BConfig({"enabled": True, "profiles": {profile: entry}})
    state = b2b._B2BState(config)
    adapter = SimpleNamespace(_b2b_state=state)
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
                             "criteria": [], "source_refs": list(mission_source_refs)},
        "project": entry["projects"][project_id]}
    view = view_factory(policy, {"mission_source_digest": "c" * 64})
    db_path = os.path.join(str(tmp_path), "runs.db")
    store = RunIdempotencyStore(db_path)
    keys = b2b._KeyRing(entry)
    sink = b2b._AttemptSink(adapter, store, profile=profile, entry=entry, keys=keys,
                          attempt_id=attempt_id, session_id=sid,
                          binding_digest=binding, run_id=run_id, policy=policy)
    binding_row = {"profile": profile, "session_id": sid,
                   "binding_digest": binding,
                   "policy_json": json_utf8(policy).decode("utf-8")}
    attempt_row = {"profile": profile, "session_id": sid, "binding_digest": binding,
                   "attempt_id": attempt_id, "run_id": run_id, "status": "admitted",
                   "requester_id": policy["requester_id"],
                   "source_bind": json_utf8({"unit_source_double": True})}
    admission = store.b2b_admit(profile=profile, session_id=sid, binding_digest=binding,
                    attempt_id=attempt_id, fingerprint=sink._fingerprint,
                    binding_row=binding_row, attempt_row=attempt_row,
                    run_scope="b2b:" + attempt_id, run_key=attempt_id,
                    run_id=run_id, run_fingerprint=sink._fingerprint,
                    run_status={"session_id": sid, "status": "running"})
    assert admission["status"] == "admitted"
    cap = BoundExecution(attempt_id=attempt_id, run_id=run_id, policy=policy,
                         profile=profile, session_id=sid, binding_digest=binding,
                         sink=sink, created_at=now)

    class UnitAgent:
        pass
    agent = UnitAgent()
    agent.session_id, agent._b2b_execution, agent._current_turn_id = sid, cap, "t0"
    object.__setattr__(cap, "_agent_ref", weakref.ref(agent))
    token = bind_execution(cap)
    try:
        receipt = cap.publish_context(view, UNIT_RENDERED, turn_id="t0")
    finally:
        reset_execution(token)
    assert sink.context_receipt is receipt

    resolved = {"source_state": "active", **{k: policy[k] for k in
        ("attempt_id", "binding_digest", "requester_id", "project_id",
         "project_binding_id", "mission_id", "mission_revision", "profile",
         "session_id", "reservation_ref", "request_digest", "ticket_digest",
         "authority_basis_digest", "authority_digest", "observation_genesis",
         "mission_request")},
        "mission_source_digest": view["my_work"]["mission"]["source_digest"],
        "_signed_request": {"issued_at": now - 1, "expires_at": now + 30},
        "_signed_response": {"issued_at": now - 1, "expires_at": now + 29},
        "_request_raw": b'{"unit_source_double":"request"}',
        "_response_raw": b'{"unit_source_double":"response"}'}
    return SimpleNamespace(
        store=store, sink=sink, cap=cap, receipt=receipt, resolved=resolved,
        view=view, policy=policy, entry=entry, adapter=adapter, agent=agent,
        db_path=db_path, profile=profile, session_id=sid, attempt_id=attempt_id,
        binding=binding, run_id=run_id, turn_id="t0")
