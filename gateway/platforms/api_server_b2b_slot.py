"""B2B authorization-slot orchestration extracted from ``api_server_b2b``.

The admission lane (``_launch_b2b_run``) and the prepare-only attestation
(``_prepare_b2b_only``) own the slot checks, the bounded preparation, the
publication decision and the single durable admission. They live here so the
HTTP facade stays below the god-file threshold; every helper they call is
looked up on the facade at call time (``_facade``), preserving the existing
monkeypatch seams and import graph. Behaviour is unchanged.
"""

from __future__ import annotations

import hashlib
import math
import uuid
from pathlib import Path
from typing import Any, Dict


def _facade():
    from gateway.platforms import api_server_b2b
    return api_server_b2b


async def _launch_b2b_run(adapter: Any, request: Any, *, profile: str, entry, keys,
                          session_id: str, binding_digest: str, attempt_id: str,
                          resolved: Dict[str, Any], store: Any, db: Any):
    """Keep the immutable empty origin, but accept worked sessions through their owned binding."""
    import asyncio as _a
    b2b = _facade()
    from hermes_constants import get_hermes_home
    home = get_hermes_home().resolve()
    if (not getattr(db, "db_path", None) or str(db.db_path) == ":memory:" or
            db.db_path.resolve().parent != home):
        return b2b._deny(503, "store_unavailable")
    run_id = "run_" + uuid.uuid4().hex
    session = await _a.to_thread(db.get_session, session_id)
    if (not session or session.get("id") != session_id or session.get("source") != "api_server"
            or any(session.get(key) is not None for key in
                   ("parent_session_id", "ended_at", "end_reason"))):
        return b2b._deny(409, "session_incompatible")
    try:
        tip = await _a.to_thread(db.resolve_resume_session_id, session_id)
    except Exception:
        return b2b._deny(409, "genesis_resume")
    if tip != session_id:
        return b2b._deny(409, "genesis_resume")
    existing = store.b2b_binding(session_id=session_id, profile=profile)
    if existing is None:
        if not b2b._genesis_vs_native(session or {}, session_id, profile):
            # A concurrent winner may already have started the exact session.
            existing = store.b2b_binding(session_id=session_id, profile=profile)
            if existing is None:
                return b2b._deny(409, "genesis_native")
    if existing is None:
        if not b2b._valid_observation(resolved.get("observation_genesis"), profile, session_id):
            return b2b._deny(403, "genesis_proof")
        obs = resolved["observation_genesis"]
        native_obs = {
            "id": session.get("id"), "source": session.get("source"),
            "title": session.get("title"), "model": session.get("model"),
            "parent_session_id": session.get("parent_session_id"),
            "has_system_prompt": session.get("system_prompt") is not None,
            "has_model_config": session.get("model_config") is not None,
            "ended_at": session.get("ended_at"), "end_reason": session.get("end_reason"),
            "message_count": int(session.get("message_count") or 0),
            "tool_call_count": int(session.get("tool_call_count") or 0),
            "api_call_count": int(session.get("api_call_count") or 0),
            "profile": profile}
        if native_obs != {k: obs[k] for k in b2b._OBSERVATION_KEYS}:
            return b2b._deny(409, "genesis_mismatch")
    project = entry["projects"].get(str(resolved.get("project_binding_id") or ""))
    if project is None or project["project_id"] != resolved["project_id"]:
        return b2b._deny(404, "not_found")
    slot = project.get("native_n2", {}).get("authorization_slot")
    existing_attempt = store.b2b_attempt(profile=profile, attempt_id=attempt_id)
    if existing_attempt is not None and project.get("native_n2") is not None:
        return b2b._consumed_response(
            store, profile=profile, attempt_id=attempt_id,
            binding_digest=binding_digest, session_id=session_id)
    if (slot is not None and store.b2b_slot_in_use(
            slot=slot, exclude_profile=profile, exclude_attempt_id=attempt_id)):
        # One physical approval slot cannot protect two live runs: a later
        # publication would revoke the earlier one before its result is sealed.
        return b2b._deny(409, "slot_busy")
    state = b2b._state_for(adapter)
    if state is not None:
        native_models = state.config.g2_models
        native_urls = state.config.g2_base_urls
        provider_aliases = state.config.g2_provider_aliases
    else:
        native_models, native_urls = b2b._native_catalogue({})
        provider_aliases = frozenset()
    if b2b._legacy_targets_native_gateway(
            project, native_models, native_urls, provider_aliases):
        return b2b._deny(403, "model_authorization_missing")
    native_binding = resolved.get("_native_binding")
    native_messages_digest = None
    slot = project.get("native_n2", {}).get("authorization_slot")
    stamp = None
    run_project = project
    if project.get("native_n2") is not None:
        try:
            run_project = b2b._native_auth.pin_run_project(project)
            claim = b2b._native_auth.read_approval(run_project)
            b2b._native_auth.check_source(claim, resolved)
            if slot is not None:
                if state is None or state.config.profile_entry(profile) is not entry:
                    raise b2b._native_auth.AuthorizationRefused("preparation")
                stamp = state.preparations.for_claim(resolved, claim)
        except b2b._native_auth.AuthorizationRefused as exc:
            return b2b._deny(403, str(exc))
        native_messages_digest = claim["n2"]["messages_digest"]
    # P2 admission gate: NEW work proves its mission context BEFORE the single
    # durable attempt is consumed — the sink/cap are built in memory first,
    # then the bounded bootstrap enters the owning profile scope (secret
    # hydration included), loads the gateway config and discovers plugins,
    # and only THEN does the one bounded worker run the plugin-owned
    # preparation — the real native read (the profile's prepare_context
    # plugin callback, bound to THIS cap) AND its configuration validators —
    # inside the captured scope, attach the frozen preparation to the sink,
    # and consult readiness (the same single classifier /health/detailed
    # reports). Any source/producer error is 503 execution_unavailable with
    # NO binding/attempt/run/title/provider side effects — the in-memory
    # sink/cap are simply dropped. Legacy lanes keep their idempotent replay;
    # a native retry is a consumed authorization: answer with the durable
    # attempt identity and never launch a second worker.
    policy = b2b._source_policy(resolved, home, run_project)
    if native_binding is not None:
        policy.update(native_n2_messages_digest=native_messages_digest,
                      native_n4_result_public_key=claim["result_public_key"])
    fingerprint = b2b._policy_digest(profile, entry, project, policy)
    scope = b2b._run_scope(profile, resolved["requester_id"], binding_digest)
    initial_status = {"status": "queued", "session_id": session_id, "created_at": b2b.time.time()}
    sink = None
    cap = None
    # Lost-ACK replay is allowed even while the original holds the final native worker slot.
    if existing_attempt is None:
        from gateway.platforms.api_server_b2b_context import (
            assert_context_source_current, run_bounded_context_operation)
        from gateway.run import _profile_runtime_scope
        # The sink + cap exist ONLY in memory until b2b_admit commits the
        # attempt — a failed preparation drops them with zero durable trace.
        sink = b2b._AttemptSink(adapter, store, profile=profile, entry=entry, keys=keys,
                            attempt_id=attempt_id, session_id=session_id,
                            binding_digest=binding_digest, run_id=run_id, policy=policy)
        cap = b2b.BoundExecution(
            profile=profile, session_id=session_id, binding_digest=binding_digest,
            attempt_id=attempt_id, run_id=run_id, policy=dict(policy),
            sink=sink, created_at=b2b.time.time())
        denied = await b2b._b2b_run_bounded_preparation(
            adapter, profile=profile, project=run_project, cap=cap, sink=sink,
            resolved=resolved)
        if denied is not None:
            return denied
        if (native_binding is not None
                and b2b.native_recipe_messages_digest(
                    resolved["mission_request"], sink._context_preparation.rendered
                ) != native_messages_digest):
            return b2b._deny(403, "model_authorization_raw_digest")
        if native_binding is not None:
            try:
                b2b._native_auth.check_preparation(claim, resolved, sink._context_preparation)
                if slot is not None:
                    state.preparations.verify(stamp, resolved, claim, sink._context_preparation)
                    await b2b.probe_model_gateways((project["base_url"],))
            except b2b._native_auth.AuthorizationRefused as exc:
                return b2b._deny(403, str(exc))
            except (b2b.B2BConfigError, b2b.B2BModelGatewayUnavailable):
                return b2b._deny(503, "model_gateway_unavailable")
    if existing_attempt is None:
        # Inherited generic API admission, kept at
        # its original place — not a B2B capacity gate.
        limited = adapter._concurrency_limited_response()
        if limited is not None:
            return limited
    if existing_attempt is None:
        # Non-hydrating scope entry — introspection only, never plugin
        # secret-source code on the loop.
        try:
            with _profile_runtime_scope(home, hydrate_secrets=False):
                from hermes_cli.plugins import get_plugin_manager

                has_non_plugin_hooks = (
                    get_plugin_manager().has_non_plugin_hook_subscribers())
        except Exception:
            return b2b._deny(503, "execution_unavailable")
        if has_non_plugin_hooks:
            return b2b._deny(503, "non_plugin_hook_subscribers")
    binding_row = {"profile": profile, "session_id": session_id,
                   "binding_digest": binding_digest,
                   "policy_json": b2b.json_utf8(policy).decode("utf-8")}
    attempt_row = {"attempt_id": attempt_id, "binding_digest": binding_digest,
                   "profile": profile, "session_id": session_id, "status": "admitted",
                   "run_id": run_id, "requester_id": resolved["requester_id"],
                   "source_bind": b2b._source_record(resolved)}
    if cap is not None:
        if slot is not None and (state is not b2b._state_for(adapter)
                                 or not state.preparations.current(resolved, stamp)):
            if store.b2b_attempt(profile=profile, attempt_id=attempt_id) is not None:
                return b2b._consumed_response(store, profile=profile, attempt_id=attempt_id,
                                          binding_digest=binding_digest, session_id=session_id)
            return b2b._deny(403, "model_authorization_preparation")
        if native_binding is not None and not sink._native_run_current(resolved):
            return b2b._deny(403, "model_authorization_revoked")
        try:
            assert_context_source_current(sink._context_preparation)
        except b2b.B2BTerminalRefusal as exc:
            return b2b._deny(503, str(exc))
    # The source exchange, live publication and OC proof can expire during
    # preflight, including the G2 probe. Never extend a window for the commit.
    now = int(b2b.time.time())
    if not all(env["issued_at"] <= now < env["expires_at"] for env in
               (resolved["_signed_request"], resolved["_signed_response"])):
        return b2b._deny(403, "source_denied")
    # Last synchronous point before the durable admission: the preflight probe
    # awaited, so another proposal may have taken the slot meanwhile.
    if (slot is not None and store.b2b_slot_in_use(
            slot=slot, exclude_profile=profile, exclude_attempt_id=attempt_id)):
        return b2b._deny(409, "slot_busy")
    outcome = store.b2b_admit(
        profile=profile, session_id=session_id, binding_digest=binding_digest,
        attempt_id=attempt_id, fingerprint=fingerprint,
        binding_row=binding_row,
        attempt_row=attempt_row,
        run_scope=scope, run_key=attempt_id, run_id=run_id,
        run_fingerprint=fingerprint, run_status=initial_status,
        owner_pid=getattr(adapter, "_run_owner_pid", 0),
        owner_started=getattr(adapter, "_run_owner_started", 0),
        replay_only=existing_attempt is not None)
    if outcome.get("status") == "conflict":
        return b2b._deny(409, "conflict")
    stored_run_id = outcome.get("run_id") or (
        (outcome.get("attempt") or {}).get("run_id") if outcome.get("status") == "replayed" else run_id)
    if outcome.get("status") == "replayed":
        if native_binding is not None:
            return b2b._consumed_response(
                store, profile=profile, attempt_id=attempt_id,
                binding_digest=binding_digest, session_id=session_id)
        return b2b._replayed_response(adapter, stored_run_id, attempt_id, binding_digest, profile, session_id)
    adapter._run_idempotency_ids.add(stored_run_id)
    if slot is not None:
        state.preparations.forget(resolved)
    if native_binding is not None:
        # The attempt row was committed inside b2b_admit: its created_at IS the
        # consumption instant. Freeze it for every later manifest re-read.
        try:
            admitted_row = store.b2b_attempt(profile=profile, attempt_id=attempt_id)
            created_at = admitted_row.get("created_at") if admitted_row else None
            if (isinstance(created_at, bool)
                    or not isinstance(created_at, (int, float))
                    or not math.isfinite(created_at)):
                raise ValueError("admission timestamp unavailable")
            sink._admission_now = int(created_at)
        except Exception:
            sink.block("store_unavailable")
            return b2b._deny(503, "store_unavailable")
    try:
        await _a.to_thread(db.set_session_title, session_id, f"B2B {session_id}")
    except Exception:
        store.b2b_update_attempt(profile=profile, attempt_id=attempt_id, status="failed")
        return b2b._deny(500, "title_commit_failed")
    # The admitted winner's run_id is the chosen one — the sink/cap built
    # pre-admission already carry it (a replayed outcome returned above).
    # P1: the post-consumption policy/manifest recheck consults the plugin's
    # validator, so it runs in the bounded daemon worker under the owning
    # profile scope — never synchronously on the API event loop. A validator
    # that parks fails THIS attempt closed without blocking the loop.
    if native_binding is not None:
        try:
            with _profile_runtime_scope(Path(policy["profile_home"]),
                                        hydrate_secrets=False):
                current = await run_bounded_context_operation(
                    lambda: (sink.assert_current_policy()
                             and sink._native_run_current(resolved)),
                    timeout=b2b._SOURCE_DEADLINE_S)
        except b2b.B2BTerminalRefusal as exc:
            sink.block(str(exc))
            return b2b._deny(503, str(exc))
        except Exception:
            sink.block("context_unavailable")
            return b2b._deny(503, "context_unavailable")
        if not current:
            store.b2b_update_attempt(
                profile=profile, attempt_id=attempt_id, status="failed")
            return b2b._deny(403, "model_authorization_revoked")
    launched = await b2b._spawn_run(adapter, request, cap=cap, resolved=resolved,
                                session_id=session_id, run_id=stored_run_id, profile=profile)
    if launched is None:
        sink.block("launch_failed")
        return b2b._deny(503, "launch_failed")
    from aiohttp import web
    return web.json_response({
        "object": "b2b.proposal_attempt", "attempt_id": attempt_id,
        "binding_digest": binding_digest, "run_id": stored_run_id, "profile": profile,
        "session_id": session_id, "status": "admitted"})


async def _prepare_b2b_only(adapter: Any, request: Any, *, profile: str, entry, keys,
                            session_id: str, binding_digest: str, attempt_id: str,
                            request_id: str, resolved: Dict[str, Any],
                            store: Any, db: Any):
    """The prepare-only attestation (N3): verify the exact
    binding/session/attempt/source identities and run the SAME bounded
    bootstrap + plugin-owned context preparation as admission — then STOP:
    no b2b_admit, no title, no concurrency gate, no run, no provider, no
    durable write of any kind. The prepare-only attestation is signed by the
    owning Hermes profile; it binds the caller request_id and the signed
    source exchange. It does not create a Hermes record, authorize a run, or
    assert that a later admission has not occurred. The answer is a
    ``b2b.preparation`` attestation correlated to THIS signed exchange: the
    context proof digests, the source-basis contract, the rendered digest
    and the ordered piece tuple — ``run_id: null``,
    ``model_scheduled: false``. A replayed POST simply re-attests under a
    fresh signed exchange; an already durable binding/attempt refuses 409."""
    import asyncio as _a
    b2b = _facade()
    from aiohttp import web
    from datetime import datetime, timezone
    from gateway.platforms.api_server_b2b_context import (
        assert_context_source_current)
    from gateway.run import _profile_runtime_scope
    from hermes_constants import get_hermes_home
    home = get_hermes_home().resolve()
    if (not getattr(db, "db_path", None) or str(db.db_path) == ":memory:" or
            db.db_path.resolve().parent != home):
        return b2b._deny(503, "store_unavailable")
    session = await _a.to_thread(db.get_session, session_id)
    if (not session or session.get("id") != session_id or session.get("source") != "api_server"
            or any(session.get(key) is not None for key in
                   ("parent_session_id", "ended_at", "end_reason"))):
        return b2b._deny(409, "session_incompatible")
    try:
        tip = await _a.to_thread(db.resolve_resume_session_id, session_id)
    except Exception:
        return b2b._deny(409, "genesis_resume")
    if tip != session_id:
        return b2b._deny(409, "genesis_resume")
    # The single-use durable lane: a committed binding or attempt row means
    # the tuple was already consumed — refuse rather than attest beside it.
    if (store.b2b_binding(session_id=session_id, profile=profile) is not None
            or store.b2b_attempt(profile=profile, attempt_id=attempt_id) is not None):
        return b2b._deny(409, "already_admitted")
    if not b2b._genesis_vs_native(session, session_id, profile):
        return b2b._deny(409, "genesis_native")
    if not b2b._valid_observation(resolved.get("observation_genesis"), profile, session_id):
        return b2b._deny(403, "genesis_proof")
    obs = resolved["observation_genesis"]
    native_obs = {
        "id": session.get("id"), "source": session.get("source"),
        "title": session.get("title"), "model": session.get("model"),
        "parent_session_id": session.get("parent_session_id"),
        "has_system_prompt": session.get("system_prompt") is not None,
        "has_model_config": session.get("model_config") is not None,
        "ended_at": session.get("ended_at"), "end_reason": session.get("end_reason"),
        "message_count": int(session.get("message_count") or 0),
        "tool_call_count": int(session.get("tool_call_count") or 0),
        "api_call_count": int(session.get("api_call_count") or 0),
        "profile": profile}
    if native_obs != {k: obs[k] for k in b2b._OBSERVATION_KEYS}:
        return b2b._deny(409, "genesis_mismatch")
    project = entry["projects"].get(str(resolved.get("project_binding_id") or ""))
    if project is None or project["project_id"] != resolved["project_id"]:
        return b2b._deny(404, "not_found")
    slot = project.get("native_n2", {}).get("authorization_slot")
    if slot is not None and store.b2b_slot_in_use(slot=slot):
        # Refuse to prepare beside a live run: publishing its approval into the
        # project's single slot would revoke the run already in flight.
        return b2b._deny(409, "slot_busy")
    policy = b2b._source_policy(resolved, home, project)
    # The sink + cap exist ONLY in memory — the run_id minted here is the
    # capability's identity, NEVER admitted, scheduled or returned: the
    # attestation's run_id is null. A failed preparation drops both with
    # zero durable trace.
    run_id = "run_" + uuid.uuid4().hex
    sink = b2b._AttemptSink(adapter, store, profile=profile, entry=entry, keys=keys,
                        attempt_id=attempt_id, session_id=session_id,
                        binding_digest=binding_digest, run_id=run_id, policy=policy)
    cap = b2b.BoundExecution(
        profile=profile, session_id=session_id, binding_digest=binding_digest,
        attempt_id=attempt_id, run_id=run_id, policy=dict(policy),
        sink=sink, created_at=b2b.time.time())
    denied = await b2b._b2b_run_bounded_preparation(
        adapter, profile=profile, project=project, cap=cap, sink=sink,
        resolved=resolved)
    if denied is not None:
        return denied
    # Non-hydrating scope entry — introspection only, never plugin
    # secret-source code on the loop.
    try:
        with _profile_runtime_scope(home, hydrate_secrets=False):
            from hermes_cli.plugins import get_plugin_manager
            has_non_plugin_hooks = (
                get_plugin_manager().has_non_plugin_hook_subscribers())
    except Exception:
        return b2b._deny(503, "execution_unavailable")
    if has_non_plugin_hooks:
        return b2b._deny(503, "non_plugin_hook_subscribers")
    preparation = sink._context_preparation
    proof = b2b.context_proof(preparation.view)
    documents = [
        {"native_ref": document["native_ref"], "revision": document["revision"],
         "digest": document["native_digest"]}
        for document in preparation.documents]
    # Last-mile race gate: a proposal admitted between the early durable
    # check above and this boundary consumed the same tuple — refuse rather
    # than mint a stale attestation beside an owned admission.
    if (store.b2b_binding(session_id=session_id, profile=profile) is not None
            or store.b2b_attempt(profile=profile, attempt_id=attempt_id) is not None):
        return b2b._deny(409, "already_admitted")
    # A proposal admitted while this preparation was running now owns the
    # project's single slot: publishing beside it would revoke that live run.
    if slot is not None and store.b2b_slot_in_use(slot=slot):
        return b2b._deny(409, "slot_busy")
    # Signed proof can expire while session/DB checks were awaited: re-verify
    # the freshness window on BOTH envelopes immediately before signing —
    # the same predicate the commit path applies to its own source reads.
    now = int(b2b.time.time())
    if not all(env["issued_at"] <= now < env["expires_at"] for env in
               (resolved["_signed_request"], resolved["_signed_response"])):
        return b2b._deny(403, "source_denied")
    try:
        assert_context_source_current(preparation)
    except b2b.B2BTerminalRefusal as exc:
        return b2b._deny(503, str(exc))
    body = {
        "object": "b2b.preparation",
        "attempt_id": attempt_id, "binding_digest": binding_digest,
        "profile": profile, "session_id": session_id,
        "requester_id": resolved["requester_id"],
        "project_id": resolved["project_id"],
        "project_binding_id": resolved["project_binding_id"],
        "mission_id": resolved["mission_id"],
        "mission_revision": resolved["mission_revision"],
        "status": "prepared", "run_id": None, "model_scheduled": False,
        "prepared_at": datetime.now(timezone.utc).isoformat(
            timespec="milliseconds").replace("+00:00", "Z"),
        "context_digest": proof["context_digest"],
        "view_digest": proof["view_digest"],
        "source_basis_contract": proof["source_basis_contract"],
        "source_basis_digest": proof["source_basis_digest"],
        "rendered_digest": hashlib.sha256(preparation.rendered).hexdigest(),
        "source_request_id": resolved["source_request_id"],
        "source_request_digest": resolved["source_request_digest"],
        "documents": documents}
    if resolved.get("_native_binding") is not None:
        body["messages_digest"] = b2b.native_recipe_messages_digest(
            resolved["mission_request"], preparation.rendered)
        if project.get("native_n4") is not None:
            body.update(native_binding=resolved["_native_binding"],
                        request_digest=resolved["request_digest"],
                        mission_source_digest=resolved["mission_source_digest"],
                        dataset_id=project["native_n4"]["dataset_id"],
                        normalized_messages_digest=b2b.native_recipe_normalized_messages_digest(
                            resolved["mission_request"], preparation.rendered))
    envelope, _ = b2b._signed_envelope(
        entry, keys, b2b._PREPARED_OPERATION, body, request_id=request_id)
    if "authorization_slot" in project.get("native_n2", {}):
        state = b2b._state_for(adapter)
        if state is None or state.config.profile_entry(profile) is not entry:
            return b2b._deny(403, "model_authorization_preparation")
        try:
            state.preparations.remember(resolved, envelope, proof["view"])
        except b2b._native_auth.AuthorizationRefused as exc:
            return b2b._deny(409, str(exc))
    return web.json_response(envelope)
