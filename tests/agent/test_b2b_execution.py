"""Unit tests for ``agent.b2b_execution`` — the frozen capability, context publication,
proposal validation, terminal ordering and the worker-side result check.

Every context producer/rechecker below is an EXPLICIT TEST DOUBLE, never a real
AgentContext/C1 builder — H1's context seam is a placeholder contract.
"""

from __future__ import annotations

import copy
import tempfile
import threading
import time
from types import SimpleNamespace

import pytest

import agent.b2b_nonstream as _b2b_ns_mod
import agent.chat_completion_helpers as _helpers
from agent import b2b_execution as be
from agent.b2b_execution import (
    BoundExecution, B2BTerminalRefusal, ContextReceipt, _deep_freeze,
    _public_text, bind_execution, canonical_json, current_execution,
    execute_terminal, extract_allowed_refs, install_bounded_agent_policy,
    is_b2b_attempt_id, is_b2b_session_id, json_utf8, mission_prompt,
    native_context_digest, publish_context, require_execution,
    reset_execution, validate_proposal)
from agent.b2b_nonstream import _B2BNonStreamRequest
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from hermes_constants import get_hermes_home
from tests.gateway.b2b_process_harness import (
    UNIT_RENDERED, build_context_view, build_unit_native_oc_view, extract_contract_root,
    renew_unit_oc_read, reseal_unit_context_view)
from tests.gateway.b2b_unit_fixtures import _FakeClock
from tests.gateway.test_api_server_b2b_terminal import (
    _api_kwargs, _terminal_lane)


# ---------------------------------------------------------------------------
# canonical_json — UTF-16-BE sort regression (U+10000 BEFORE U+E000 under JS)
# ---------------------------------------------------------------------------

def test_canonical_json_utf16_sort():
    # JS orders keys by UTF-16 code units: "\U00010000" (surrogate pair, first unit
    # 0xD800 < 0xE000) sorts BEFORE "\ue000". A codepoint sort reverses this.
    out = canonical_json({"\ue000": 1, "\U00010000": 2})
    expected = ('{"' + "\U00010000" + '":2,"' + "\ue000" + '":1}').encode("utf-8")
    assert out == expected


def test_canonical_json_rejects_floats_and_surrogates():
    with pytest.raises(ValueError):
        canonical_json({"x": 1.5})
    with pytest.raises(ValueError):
        canonical_json({"x": "\ud800"})


# ---------------------------------------------------------------------------
# validate_proposal — exact closed schema, bounds, ref whitelist
# ---------------------------------------------------------------------------

def _good_proposal(**over):
    base = {"summary": "s", "steps": ["a"], "source_refs": [], "limitations": []}
    base.update(over)
    import json
    return json.dumps(base)


def test_validate_proposal_accepts_exact_shape():
    parsed, reason = validate_proposal(_good_proposal(), ())
    assert reason == "ok" and parsed is not None


def test_validate_proposal_rejects_extra_field():
    parsed, reason = validate_proposal(_good_proposal(extra=1), ())
    assert parsed is None and "fields" in reason


def test_validate_proposal_rejects_non_whitelist_ref():
    parsed, reason = validate_proposal(
        _good_proposal(source_refs=["not-in-context"]), ("allowed-ref",))
    assert parsed is None and "not_in_context" in reason


def test_validate_proposal_rejects_ref_when_no_context_refs():
    parsed, reason = validate_proposal(_good_proposal(source_refs=["r"]), ())
    assert parsed is None and "no_context_refs" in reason


def test_validate_proposal_bounds():
    parsed, reason = validate_proposal(_good_proposal(summary=""), ())
    assert parsed is None and "summary_bounds" in reason
    parsed, reason = validate_proposal(_good_proposal(steps=[]), ())
    assert parsed is None and "steps_bounds" in reason
    parsed, reason = validate_proposal(_good_proposal(steps=["x"] * 13), ())
    assert parsed is None and "steps_bounds" in reason


def test_validate_proposal_rejects_tool_output_not_json():
    parsed, reason = validate_proposal("hello not json", ())
    assert parsed is None


# ---------------------------------------------------------------------------
# extract_allowed_refs — reference-designated fields only
# ---------------------------------------------------------------------------

def test_extract_allowed_refs_only_ref_fields():
    view = {
        "references": ["r1"], "title": "not-a-ref",
        "nested": {"evidence_refs": ["r2"], "other": "x"},
        "list": [{"source_refs": ["r3"]}, "not-ref"]}
    assert sorted(extract_allowed_refs(view)) == ["r1", "r2", "r3"]
    assert "not-a-ref" not in extract_allowed_refs(view)


# ---------------------------------------------------------------------------
# _public_text — strict single clean public answer
# ---------------------------------------------------------------------------

class _Msg:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class _Resp:
    def __init__(self, content=None, tool_calls=None, reasoning=None, n_choices=1,
                 finish_reason="stop"):
        m = _Msg(role="assistant", content=content, tool_calls=tool_calls,
                 reasoning=reasoning)
        self.choices = [_Msg(message=m, finish_reason=finish_reason)
                        for _ in range(n_choices)]


def test_public_text_accepts_plain():
    assert _public_text(_Resp(content="hi")) == "hi"


def test_public_text_rejects_tool_calls():
    assert _public_text(_Resp(content="x", tool_calls=[{"f": 1}])) is None


def test_public_text_rejects_reasoning():
    assert _public_text(_Resp(content="x", reasoning="priv")) is None


def test_public_text_rejects_multi_choice_and_multi_part():
    assert _public_text(_Resp(content="x", n_choices=2)) is None
    assert _public_text(_Resp(content=[{"type": "text", "text": "a"},
                                       {"type": "image"}])) is None


# ---------------------------------------------------------------------------
# require_execution — no-cap B2B refuses, active cap + foreign session refuses
# ---------------------------------------------------------------------------

def _agent(sid):
    class A:
        session_id = sid
    return A()


def test_require_execution_refuses_no_cap_b2b():
    token = bind_execution(None)
    try:
        with pytest.raises(B2BTerminalRefusal):
            require_execution(_agent("b2b_" + "a" * 64))
    finally:
        reset_execution(token)


def test_require_execution_refuses_active_cap_foreign_session():
    cap = BoundExecution(
        profile="p", session_id="b2b_" + "a" * 64, binding_digest="a" * 64,
        attempt_id="b2bp_" + "b" * 64, run_id="r", policy={}, sink=None, created_at=0)
    token = bind_execution(cap)
    try:
        # A NON-b2b session_id inside a context that carries a b2b cap must refuse —
        # it can never fall through to the unguarded branch.
        with pytest.raises(B2BTerminalRefusal):
            require_execution(_agent("api_123"))
    finally:
        reset_execution(token)


def test_require_execution_returns_cap_on_match():
    sid = "b2b_" + "a" * 64
    cap = _cap()
    agent = _bound_agent(cap)
    token = bind_execution(cap)
    try:
        assert require_execution(agent) is cap
        with pytest.raises(B2BTerminalRefusal):
            require_execution(_agent("api_other"))
    finally:
        reset_execution(token)


def test_current_execution_none_without_cap():
    token = bind_execution(None)
    try:
        assert current_execution("p", "s") is None
    finally:
        reset_execution(token)


# ---------------------------------------------------------------------------
# BoundExecution — frozen, tuple, per-cap recheck, publish
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ordered", [False, True], ids=["receipt-v1", "receipt-v2"])
def test_native_read_metadata_changes_preserve_source_identity(ordered):
    cap = _cap()
    agent = _bound_agent(cap)
    original = build_unit_native_oc_view(cap.policy, {}, ordered=ordered)
    original_bytes = be.json_utf8(original)
    fresh = renew_unit_oc_read(original)
    be.assert_source_equivalent(original, fresh)
    assert be.json_utf8(original) == original_bytes
    assert be.json_utf8(be.source_basis(original)) == be.json_utf8(be.source_basis(fresh))
    before, after = be.context_proof(original), be.context_proof(fresh)
    assert before["view_digest"] != after["view_digest"]
    assert before["context_digest"] != after["context_digest"]
    assert before["source_basis_digest"] == after["source_basis_digest"]
    assert before["source_basis_contract"] == "dubsar.b2b-source-basis/2"
    reads = []
    cap.register_context_recheck(lambda execution: reads.append(execution) or fresh)
    token = bind_execution(cap)
    try:
        receipt = cap.publish_context(original, UNIT_RENDERED, turn_id="t1")
        assert be.recheck_context(cap, receipt) == fresh
    finally:
        reset_execution(token)
    assert reads == [cap] and agent._b2b_execution is cap
    assert receipt.view_digest == before["view_digest"]
    assert be.json_utf8(receipt.view) == original_bytes


_NATIVE_SOURCE_MUTATIONS = [
    # (path, replacement, exact refusal reason)
    # Qualification breakage: the native read qualifier itself refuses first.
    (("qualification", "freshness"), "stale", "context_oc_unqualified"),
    (("qualification", "status"), "pending_recalculation", "context_oc_unqualified"),
    (("qualification", "admissibility"), "limited", "context_oc_unqualified"),
    (("qualification", "agreement"), "conflict", "context_oc_unqualified"),
    (("bounds", "truncated"), True, "context_oc_unqualified"),
    # Source-basis drift: the mutated view still qualifies, so only the
    # source-basis comparer can catch it (context_stale).
    (("qualification", "values", 0, "observation_ref"), "oco_" + "c" * 32,
     "context_stale"),
    (("qualification", "values", 0, "value"), "b" * 40, "context_stale"),
    (("qualification", "values", 0, "source_observed_at"),
     "2026-10-30T11:59:59.000Z", "context_stale"),
    (("qualification", "values", 0, "received_at"), "2026-10-30T12:00:00.002Z",
     "context_stale"),
    (("qualification", "mapping_ref"), "mapping:changed", "context_stale"),
    (("qualification", "mapping_version"), 2, "context_stale"),
    (("qualification", "rule_ref"), "rule:changed", "context_stale"),
    (("qualification", "rule_version"), 2, "context_stale"),
    (("qualification", "limits"), [{"code": "SOURCE_CHANGED"}], "context_stale"),
    (("reserves",), [{"code": "SOURCE_CHANGED"}], "context_stale"),
    (("bounds", "max_observations_examined"), 199, "context_stale"),
    (("unknown_future_source_field",), "changed", "context_stale"),
]


@pytest.mark.parametrize(("path", "replacement", "reason"), _NATIVE_SOURCE_MUTATIONS)
def test_native_receipt_mutation_qualification_vs_source_drift(
        path, replacement, reason):
    """Every receipt mutation is refused with the EXACT typed reason:
    ``context_oc_unqualified`` when the read qualifier rejects the mutation,
    ``context_stale`` when the mutated view still qualifies and only the
    source-basis comparer can catch the drift."""
    original = build_unit_native_oc_view(_cap().policy, {})
    fresh = renew_unit_oc_read(original)
    target = fresh["operational_context"]["view"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement
    reseal_unit_context_view(fresh)
    if reason == "context_stale":
        # Not a qualification break: both views still qualify, so the refusal
        # below provably comes from the comparer, not the qualifier.
        be.context_proof(original)
        be.context_proof(fresh)
    with pytest.raises(B2BTerminalRefusal) as exc:
        be.assert_source_equivalent(original, fresh)
    assert str(exc.value) == reason


_ORDERED_PROJECTION_MUTATIONS = [
    # (field, replacement, exact refusal reason)
    ("age_ms", 2001, "context_oc_source_stale"),
    ("freshness_max_age_ms", 1999, "context_oc_source_stale"),
    ("eligible", False, "context_oc_projection"),
    ("head_complete", False, "context_oc_projection"),
    ("history_truncated", True, "context_oc_projection"),
    ("freshness", "stale", "context_oc_projection"),
    ("instant", "2026-10-30T12:00:01.000Z", "context_oc_projection"),
    ("binding_version", 2, "context_stale"),
    ("mapping_version", 2, "context_stale"),
    ("rule_version", 2, "context_stale"),
    ("producer_epoch", "epoch:changed", "context_stale"),
]


@pytest.mark.parametrize(("field", "replacement", "reason"),
                         _ORDERED_PROJECTION_MUTATIONS)
def test_ordered_projection_mutation_qualification_vs_source_drift(
        field, replacement, reason):
    """``state_projection`` drift: fields the governed projection guards fire
    their own typed reasons (``context_oc_projection``/``context_oc_source_stale``);
    fields it never reads still qualify and are caught only by the source-basis
    comparer (``context_stale``)."""
    original = build_unit_native_oc_view(_cap().policy, {}, ordered=True)
    fresh = renew_unit_oc_read(original)
    fresh["operational_context"]["view"]["state_projection"][field] = replacement
    reseal_unit_context_view(fresh)
    if reason == "context_stale":
        be.context_proof(original)
        be.context_proof(fresh)
    with pytest.raises(B2BTerminalRefusal) as exc:
        be.assert_source_equivalent(original, fresh)
    assert str(exc.value) == reason


@pytest.mark.parametrize("fault", ["cached", "backwards", "malformed_ref", "malformed_time"])
def test_native_receipt_replay_and_malformed_metadata_refused(fault):
    original = build_unit_native_oc_view(_cap().policy, {})
    fresh = renew_unit_oc_read(original)
    oc_view = fresh["operational_context"]["view"]
    if fault == "cached":
        oc_view["view_ref"] = original["operational_context"]["view"]["view_ref"]
    elif fault == "backwards":
        oc_view["view_instant"] = "2026-10-30T12:00:00.999Z"
    elif fault == "malformed_ref":
        oc_view["view_ref"] = "copied-view"
    else:
        oc_view["view_instant"] = "not-an-instant"
    reseal_unit_context_view(fresh)
    with pytest.raises(B2BTerminalRefusal):
        be.assert_source_equivalent(original, fresh)


@pytest.mark.parametrize("field", [
    "context_digest", "view_digest", "source_basis_digest", "source_basis_contract",
])
def test_context_proof_recomputes_all_versions_and_digests(field):
    proof = be.context_proof(build_unit_native_oc_view(_cap().policy, {}))
    assert be.verify_context_proof(proof) == proof
    proof[field] = "forged"
    with pytest.raises(B2BTerminalRefusal, match="context_proof_invalid"):
        be.verify_context_proof(proof)


@pytest.mark.parametrize("ordered", [False, True], ids=["receipt-v1", "receipt-v2"])
def test_recheck_cannot_reuse_receipt_from_an_intermediate_boundary(ordered):
    cap = _cap()
    agent = _bound_agent(cap)
    original = build_unit_native_oc_view(cap.policy, {}, ordered=ordered)
    fresh = renew_unit_oc_read(original)
    cap.register_context_recheck(lambda execution: fresh)
    token = bind_execution(cap)
    try:
        receipt = cap.publish_context(original, UNIT_RENDERED, turn_id="t1")
        assert be.recheck_context(cap, receipt) == fresh
        with pytest.raises(B2BTerminalRefusal, match="context_oc_read_replayed"):
            be.recheck_context(cap, receipt)
        assert agent._b2b_execution is cap
    finally:
        reset_execution(token)


def _unit_policy():
    """Cap policy carrying the REAL pinned contract root -- the schema validation
    exercised below is the production one, against the four frozen r2 blobs."""
    return {
        "profile": "p",
        "profile_home": str(get_hermes_home().resolve()),
        "project_id": "proj-a", "mission_id": "DUB-001", "mission_revision": 1,
        "authority_basis_digest": "sha256:" + "b" * 64,
        "authority_digest": "sha256:" + "a" * 64,
        "requester_id": "req-1",
        "mission_request": {"title": "T", "objective": "O"},
        "project": {
            "project_id": "proj-a", "bot_id": "bot", "profile_id": "p",
            "allowed_namespaces": ["ns"],
            "context_contract_root": extract_contract_root(
                tempfile.mkdtemp(prefix="b2b-unit-contracts-")),
            "model": "unit-double", "provider": "custom",
            "base_url": "http://127.0.0.1:9/unit-double",
            "api_mode": "chat_completions"},
    }


def _cap(**over):
    class _Sink:
        context_receipt = None
        def put_context(self, receipt):
            self.context_receipt = receipt
    kw = dict(profile="p", session_id="b2b_" + "a" * 64, binding_digest="a" * 64,
              attempt_id="b2bp_" + "b" * 64, run_id="r", policy=_unit_policy(),
              sink=_Sink(), created_at=0)
    kw.update(over)
    return BoundExecution(**kw)


def _bound_agent(cap, *, turn_id="t1"):
    """Attach an agent stand-in through the real bounded policy install: the
    catalogue's model/provider/api_mode/base_url and every bounded runtime
    field assert_terminal_runtime verifies — never a bare namespace that a
    weakened guard could trip over for the wrong reason."""
    class A:
        pass
    agent = A()
    agent.session_id = cap.session_id
    agent._current_turn_id = turn_id
    project = cap.policy.get("project") or {}
    agent.model = project.get("model")
    agent.provider = project.get("provider")
    agent.api_mode = project.get("api_mode")
    agent.base_url = project.get("base_url")
    agent.max_iterations = 1
    agent.credential_pool = None
    agent._credential_pool = None
    token = bind_execution(cap)
    try:
        install_bounded_agent_policy(agent, cap)
    finally:
        reset_execution(token)
    return agent


def test_bound_execution_tuple_and_freeze():
    cap = _cap()
    assert cap.tuple["session_id"] == "b2b_" + "a" * 64
    with pytest.raises(TypeError):
        cap.policy["x"] = 1  # MappingProxyType is read-only


def test_register_context_recheck_single():
    cap = _cap()
    cap.register_context_recheck(lambda c: {"source_basis": []})
    with pytest.raises(B2BTerminalRefusal):
        cap.register_context_recheck(lambda c: {})


def test_publish_context_requires_structured_accepted():
    cap = _cap()
    agent = _bound_agent(cap, turn_id="t1")  # bound weakref target must stay alive
    # A fully valid bound context carrying a schema-invalid accepted_context:
    # the pinned r2 schema rejects it with the exact typed reason and nothing is
    # persisted. Digest and serialized size are recomputed to the fixpoint so the
    # schema guard is the ONLY guard that can fire — a schema-skip mutant would
    # then fall through to the typed accepted_context qualifier, not a digest error.
    view = build_context_view(cap.policy, {})
    view["accepted_context"] = {"availability": "not_applicable",
                                "bindings": "not-a-list"}
    view["context_digest"] = native_context_digest(view)
    size = -1
    for _ in range(8):
        current = len(json_utf8(view))
        view["bounds"]["serialized_bytes"] = current
        if current == size:
            break
        size = current
    token = bind_execution(cap)
    try:
        with pytest.raises(B2BTerminalRefusal) as exc:
            cap.publish_context(view, UNIT_RENDERED.encode("utf-8"), turn_id="t1")
    finally:
        reset_execution(token)
    assert str(exc.value) == "context_schema_invalid"
    assert agent._b2b_execution is cap
    assert cap.context_receipt is None
    assert cap.sink.context_receipt is None


def test_publish_context_validates_and_persists():
    cap = _cap()
    agent = _bound_agent(cap, turn_id="t1")  # weakref target must outlive publish
    # UNIT CONTEXT PRODUCER DOUBLE view -- validated by the real r2 contract root.
    view = build_context_view(cap.policy, {})
    token = bind_execution(cap)
    try:
        receipt = cap.publish_context(view, UNIT_RENDERED.encode("utf-8"), turn_id="t1")
    finally:
        reset_execution(token)
    assert isinstance(receipt, ContextReceipt)
    assert receipt.rendered == UNIT_RENDERED.encode("utf-8") and receipt.turn_id == "t1"
    assert cap.context_receipt is receipt
    assert cap.sink.context_receipt is receipt  # sink persistence wired


# ---------------------------------------------------------------------------
# qualify_recorded_memory — one advisory-Memory rule at every boundary:
# freshness must be "current" (unknown is stale, never an authority grant)
# and limits must be an empty list/tuple.
# ---------------------------------------------------------------------------

_MEMORY_FRESHNESS_UNKNOWN_LIMIT = {
    "component": "memory", "code": "MEMORY_FRESHNESS_UNKNOWN",
    "detail": "Source freshness is unknown."}

_MEMORY_QUALIFICATION_CASES = [
    ("current_empty_limits", "current", [], None),
    ("unknown_uncertainty_limit", "unknown",
     [dict(_MEMORY_FRESHNESS_UNKNOWN_LIMIT)], "context_source_stale"),
    ("unknown_empty_limits", "unknown", [], "context_source_stale"),
    ("stale_empty_limits", "stale", [], "context_source_stale"),
]


@pytest.mark.parametrize(
    ("case", "freshness", "limits", "reason"), _MEMORY_QUALIFICATION_CASES,
    ids=[c[0] for c in _MEMORY_QUALIFICATION_CASES])
def test_recorded_memory_freshness_full_qualification_boundary(
        case, freshness, limits, reason):
    """Full qualification on the REAL pinned contract: a recorded view whose
    advisory Memory cannot attest ``current`` freshness is refused
    ``context_source_stale`` — ``unknown`` never rides an uncertainty limit
    into the lane — at BOTH common boundary seams
    (``qualify_context_view`` and ``verify_context_proof``)."""
    cap = _cap()
    view = build_context_view(cap.policy, {})
    view["memory"]["freshness"] = freshness
    view["memory"]["limits"] = limits
    # Reseal so digests/bounds stay valid: the Memory freshness/limits guard
    # is the only qualification that can fire.
    reseal_unit_context_view(view)
    if reason is None:
        assert be.qualify_context_view(cap, view) is not None
        checked = be.verify_context_proof(be.context_proof(view))
        assert checked["view"]["memory"]["freshness"] == "current"
        return
    with pytest.raises(B2BTerminalRefusal) as exc:
        be.qualify_context_view(cap, view)
    assert str(exc.value) == reason
    with pytest.raises(B2BTerminalRefusal) as exc:
        be.verify_context_proof(be.context_proof(view))
    assert str(exc.value) == reason


# ---------------------------------------------------------------------------
# execute_terminal — ordering: context → recheck → kwargs → before_provider → CAS
# ---------------------------------------------------------------------------

def _exec_agent():
    class A:
        session_id = "b2b_" + "a" * 64
    return A()


class _TSink:
    def __init__(self, ok=True):
        self.context_receipt = None
        self.ok = ok
        self.dispatched = 0
        self.committed = None
        self.blocked = []
    def put_context(self, receipt):
        self.context_receipt = receipt
    def block(self, reason):
        self.blocked.append(reason)
    def assert_current_policy(self):
        return self.ok
    def context_recheck_deadline(self):
        return time.monotonic() + 5.0
    def resolve_before_provider(self):
        return self.ok
    def cas_dispatch(self, **kw):
        self.dispatched += 1
        return True
    def commit_result(self, **kw):
        self.committed = kw


def test_execute_terminal_refuses_without_context():
    cap = _cap(sink=_TSink())
    agent = _bound_agent(cap)
    token = bind_execution(cap)
    try:
        with pytest.raises(B2BTerminalRefusal):
            execute_terminal(agent, {"messages": []}, cap, turn_id="t")
    finally:
        reset_execution(token)
    assert cap.sink.blocked == ["context_unavailable"]


def test_execute_terminal_refuses_wrong_turn():
    cap = _cap(sink=_TSink())
    agent = _bound_agent(cap, turn_id="t1")
    view = build_context_view(cap.policy, {})
    token = bind_execution(cap)
    try:
        cap.publish_context(view, UNIT_RENDERED.encode("utf-8"), turn_id="t1")
        # Rechecker replays the SAME published view — never a regenerated one
        # whose timestamps/digest could diverge.
        cap.register_context_recheck(lambda c: copy.deepcopy(view))
        # Valid surroundings: catalogue model and the exact native sidecar
        # (mission_prompt + rendered bytes) as the FINAL user message, so the
        # only guard that can fire is the turn check itself.
        kwargs = {
            "model": cap.policy_get("project")["model"],
            "messages": [{"role": "user", "content":
                          mission_prompt(cap.policy_get("mission_request"))
                          + "\n\n" + UNIT_RENDERED}]}
        with pytest.raises(B2BTerminalRefusal) as exc:
            execute_terminal(agent, kwargs, cap, turn_id="t-OTHER")
    finally:
        reset_execution(token)
    # The EXACT guard that fired: a runtime/policy refusal leaking through here
    # would hide a missing turn check.
    assert str(exc.value) == "context_turn_mismatch"
    assert cap.sink.dispatched == 0 and cap.sink.committed is None


def test_is_b2b_predicates():
    assert is_b2b_session_id("b2b_" + "a" * 64)
    assert not is_b2b_session_id("b2b_" + "a" * 63)
    assert not is_b2b_session_id("api_x")
    assert is_b2b_attempt_id("b2bp_" + "b" * 64)
    assert not is_b2b_attempt_id("b2b_" + "b" * 64)


# ---------------------------------------------------------------------------
# request_timeout_seconds -- worker propagation into the request-local client
# ---------------------------------------------------------------------------

class _TimeoutFakeClient:
    def __init__(self):
        self.max_retries = 0
        self.with_options_calls = []

    def with_options(self, **kw):
        self.with_options_calls.append(kw)
        new = _TimeoutFakeClient()
        new.max_retries = kw.get("max_retries", self.max_retries)
        return new


class _TimeoutClients:
    def __init__(self):
        self.calls = []

    def set_client(self, client, kind=None):
        self.calls.append((client, kind))
        return client


def _timeout_worker(cap):
    from agent.b2b_nonstream import _B2BNonStreamRequest
    made = []

    def _factory(reason, api_kwargs=None):
        c = _TimeoutFakeClient()
        made.append(c)
        return c

    agent = _TimeoutFakeClient()
    agent.api_mode = "chat_completions"
    agent.client = None
    agent._create_request_openai_client = _factory
    agent._close_request_openai_client = lambda *a, **k: None
    req = _B2BNonStreamRequest.__new__(_B2BNonStreamRequest)
    req.agent = agent
    req.api_kwargs = {"model": "m"}
    req.clients = _TimeoutClients()
    req._b2b_execution = cap
    req._b2b_receipt = object()
    req._b2b_request_digest = "d" * 64
    return req, made


def _cap_with_timeout(seconds, **over):
    policy = _unit_policy()
    if seconds is not None:
        project = dict(policy["project"])
        project["request_timeout_seconds"] = seconds
        policy = dict(policy)
        policy["project"] = project
    return _cap(policy=policy, **over)


def test_make_client_uses_project_request_timeout(monkeypatch):
    import agent.b2b_nonstream as _b2b_ns_mod
    monkeypatch.setattr(_b2b_ns_mod, "before_sdk_dispatch", lambda *a, **k: None)
    req, made = _timeout_worker(_cap_with_timeout(600))
    req._make_client("test")
    assert len(made) == 1
    kw = made[0].with_options_calls[0]
    try:
        assert kw["max_retries"] == 0
        assert kw["timeout"] == 600.0
        assert float(kw["http_client"].timeout.connect) == 600.0
        assert req.api_kwargs["timeout"] == 600.0
        assert req.clients.calls[0][1] == "openai"
    finally:
        kw["http_client"].close()


def test_make_client_request_timeout_defaults_to_five(monkeypatch):
    import agent.b2b_nonstream as _b2b_ns_mod
    monkeypatch.setattr(_b2b_ns_mod, "before_sdk_dispatch", lambda *a, **k: None)
    req, made = _timeout_worker(_cap_with_timeout(None))
    req._make_client("test")
    kw = made[0].with_options_calls[0]
    try:
        assert kw["timeout"] == 5.0
        assert float(kw["http_client"].timeout.connect) == 5.0
        assert req.api_kwargs["timeout"] == 5.0
    finally:
        kw["http_client"].close()


def test_make_client_rejects_invalid_runtime_timeout(monkeypatch):
    import agent.b2b_nonstream as _b2b_ns_mod
    monkeypatch.setattr(_b2b_ns_mod, "before_sdk_dispatch", lambda *a, **k: None)
    req, made = _timeout_worker(_cap_with_timeout(901))
    with pytest.raises(B2BTerminalRefusal, match="b2b_timeout_policy"):
        req._make_client("test")
    # The refusal lands BEFORE any request client is built — nothing leaks.
    assert made == []


def test_make_client_closes_client_when_isolation_impossible(monkeypatch):
    import agent.b2b_nonstream as _b2b_ns_mod
    monkeypatch.setattr(_b2b_ns_mod, "before_sdk_dispatch", lambda *a, **k: None)
    closed = []

    class _NoCloneClient:
        max_retries = 0

    req, made = _timeout_worker(_cap_with_timeout(60))
    req.agent._create_request_openai_client = lambda **kw: made.append(1) or _NoCloneClient()
    req.agent._close_request_openai_client = lambda c, **kw: closed.append(c)
    with pytest.raises(B2BTerminalRefusal, match="b2b_retries_not_disabled"):
        req._make_client("test")
    assert len(closed) == 1 and isinstance(closed[0], _NoCloneClient)


# ---------------------------------------------------------------------------
# stale watchdog on the B2B lane — the provider timeout arms at the actual send
# ---------------------------------------------------------------------------

def _b2b_env(tmp_path, monkeypatch):
    """Isolated HERMES_HOME + no ambient timeout env leaking into the watchdog math."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / ".env").write_text("", encoding="utf-8")
    (tmp_path / "config.yaml").write_text("{}\n", encoding="utf-8")
    for var in ("HERMES_API_CALL_STALE_TIMEOUT", "HERMES_API_TIMEOUT",
                "HERMES_CODEX_TTFB_TIMEOUT_SECONDS",
                "HERMES_CODEX_EVENT_STALE_TIMEOUT_SECONDS"):
        monkeypatch.delenv(var, raising=False)


def _fresh_agent(*, base_url="https://llm.example.com/v1", session_id=None):
    """A REAL AIAgent on a remote endpoint. The first ``import run_agent`` (and
    agent init) exports ``TMPDIR``/``TMP``/``TEMP``/``HERMES_SCRATCH_DIR`` →
    ``<HERMES_HOME>/cache/scratch`` as a process-global; snapshot BEFORE the
    import and restore afterwards so later fixtures (P1Node's authorized-temp
    check) keep the platform temp root."""
    import os as _os
    import tempfile as _tf
    saved = {k: _os.environ.get(k) for k in ("TMPDIR", "TEMP", "TMP", "HERMES_SCRATCH_DIR")}
    saved_tempdir = _tf.tempdir
    kw = {} if session_id is None else {"session_id": session_id}
    try:
        from run_agent import AIAgent
        agent = AIAgent(
            model="unit-double", provider="custom", api_key="sk-dummy",
            base_url=base_url, quiet_mode=True, skip_context_files=True,
            skip_memory=True, platform="cli", **kw)
    finally:
        for k, v in saved.items():
            if v is None:
                _os.environ.pop(k, None)
            else:
                _os.environ[k] = v
        _tf.tempdir = saved_tempdir
    agent.api_mode = "chat_completions"
    return agent


def _remote_b2b_agent(tmp_path, monkeypatch, cap, *,
                      base_url="https://llm.example.com/v1"):
    """A REAL AIAgent on a REMOTE endpoint, bound to ``cap`` the way the host binds it."""
    agent = _fresh_agent(base_url=base_url, session_id=cap.session_id)
    token = bind_execution(cap)
    try:
        install_bounded_agent_policy(agent, cap)
    finally:
        reset_execution(token)
    return agent


def _drive_b2b_run(tmp_path, monkeypatch, cap, *, clock=None, prep_seconds=0.0,
                   dispatch_seconds=0.0, run_budget=None, budget_started=None,
                   gated=False):
    """Drive a REAL ``_B2BNonStreamRequest`` through ``run()``/``_call`` — real
    worker thread, real poll loop — with a fake SDK ``create`` and, optionally,
    a fake ``h.time`` clock. The fake client's ``create`` records the armed
    ``wd.stale_timeout``/``call_start``/now AT the actual send. The dispatch
    stub simulates the fence's elapsed time, then invokes the worker's REAL
    budget/cancel ``dispatch_gate`` when the production call passes one, so
    the single pre-CAS gate is exercised rather than bypassed. ``finish()``
    releases the gate, joins driver AND worker, closes the httpx handles the
    real ``_make_client`` built, and drops the execution binding."""
    def _stub_dispatch(*a, **k):
        if clock is not None and dispatch_seconds:
            clock.advance(dispatch_seconds)
        gate = k.get("dispatch_gate")
        if gate is not None:
            gate()
    monkeypatch.setattr(_b2b_ns_mod, "before_sdk_dispatch", _stub_dispatch)

    send_flag, release, aborted = (threading.Event() for _ in range(3))
    outcome = {"sends": [], "made": [], "with_options": [],
               "send_flag": send_flag, "release": release, "aborted": aborted}
    response = _Resp(content=_good_proposal())
    req = None

    def _create(**_kw):
        outcome["sends"].append({
            "stale_timeout": req.wd.stale_timeout, "call_start": req.call_start,
            "now": clock.time() if clock is not None else time.time()})
        send_flag.set()
        if not gated:
            return response
        # The stale-kill path must outlive the poll's 2s worker-join for the
        # TimeoutError to surface, so the abort alone never releases the send.
        released = release.wait(timeout=15.0)
        if aborted.is_set() or not released:
            raise ConnectionError("request client aborted mid-send")
        return response

    class _GateClient:
        def __init__(self):
            self.max_retries = 0
            self.base_url = "https://llm.example.com/v1"
            self.chat = SimpleNamespace(
                completions=SimpleNamespace(create=_create))

        def with_options(self, **kw):
            clone = _GateClient()
            clone.max_retries = kw.get("max_retries", 0)
            outcome["with_options"].append(kw)
            return clone

    def _factory(**_kw):
        if clock is not None and prep_seconds:
            clock.advance(prep_seconds)
        outcome["prep_stale_timeout"] = req.wd.stale_timeout
        client = _GateClient()
        outcome["made"].append(client)
        return client

    agent = _remote_b2b_agent(tmp_path, monkeypatch, cap)
    if run_budget is not None:
        agent.run_budget_seconds = run_budget
        agent._run_budget_started_at = budget_started
    agent._create_request_openai_client = _factory
    agent._close_request_openai_client = lambda *a, **k: None
    agent._abort_request_openai_client = lambda *a, **k: aborted.set()
    if clock is not None:
        monkeypatch.setattr(_helpers, "time", clock)
    token = bind_execution(cap)
    try:
        req = _B2BNonStreamRequest(
            agent, {"model": "unit-double",
                    "messages": [{"role": "user", "content": "hi"}]},
            cap=cap, receipt=object(), request_digest="d" * 64)
    except Exception:
        reset_execution(token)
        raise
    outcome["req"] = req
    outcome["agent"] = agent

    def _drive():
        try:
            outcome["response"] = req.run()
        except Exception as exc:  # noqa: BLE001 — surfaced by the assertions
            outcome["error"] = exc

    driver = threading.Thread(target=_drive, daemon=True)
    driver.start()
    outcome["driver"] = driver

    def finish():
        try:
            release.set()
            driver.join(timeout=10.0)
            # ``run()`` returns before the worker finishes unwinding a killed
            # send — join it too so post-release normalization is visible.
            if req is not None and req.thread is not None:
                req.thread.join(timeout=10.0)
            # The fake SDK clone does not own the real httpx.Client _make_client
            # built — close every handle handed to with_options.
            for call in outcome["with_options"]:
                handle = call.get("http_client")
                if handle is not None:
                    handle.close()
            assert not driver.is_alive()
            assert req is None or req.thread is None or not req.thread.is_alive()
        finally:
            reset_execution(token)

    outcome["finish"] = finish
    return outcome


@pytest.mark.parametrize("policy_timeout,armed", [(600, 600.0), (None, 5.0)],
                         ids=["configured-600", "default-5"])
def test_b2b_send_arms_policy_timeout_without_run_budget(
        tmp_path, monkeypatch, policy_timeout, armed):
    """No active run budget: the preparation ceiling is unbounded (never the
    implicit 90s generic fuse) and the send arms the validated provider
    timeout — 600 configured, 5 unconfigured."""
    _b2b_env(tmp_path, monkeypatch)
    from agent.chat_completion_helpers import _resolve_nonstream_watchdogs
    clock = _FakeClock(1000.0)
    cap = _cap_with_timeout(policy_timeout, sink=_TSink())
    out = _drive_b2b_run(tmp_path, monkeypatch, cap, clock=clock)
    try:
        out["driver"].join(timeout=10.0)
        send = out["sends"][0]
        assert out["prep_stale_timeout"] == float("inf")
        assert send["now"] == 1000.0 and send["call_start"] == 1000.0
        assert send["stale_timeout"] == armed
        assert out.get("error") is None and out["response"] is not None
        assert cap.sink.committed is not None
        # Control: the generic resolver keeps its implicit 90s fuse — the lane
        # owns the send-time arming, not shared state.
        assert _resolve_nonstream_watchdogs(
            out["agent"], {"model": "unit-double", "messages": []}
        ).stale_timeout == 90.0
    finally:
        out["finish"]()


def test_b2b_send_arms_policy_timeout_under_wide_run_budget(tmp_path, monkeypatch):
    """Wide run budget (900s): the policy 600 still wins at the send — the
    preparation ceiling was the run budget, never the 60s floor."""
    _b2b_env(tmp_path, monkeypatch)
    clock = _FakeClock(1000.0)
    cap = _cap_with_timeout(600, sink=_TSink())
    out = _drive_b2b_run(tmp_path, monkeypatch, cap, clock=clock,
                         run_budget=900.0, budget_started=1000.0)
    try:
        out["driver"].join(timeout=10.0)
        send = out["sends"][0]
        assert out["prep_stale_timeout"] == 900.0
        assert send["call_start"] == 1000.0
        assert send["stale_timeout"] == 600.0
        assert out.get("error") is None and cap.sink.committed is not None
    finally:
        out["finish"]()


def test_b2b_send_arms_policy_timeout_despite_tight_run_budget(
        tmp_path, monkeypatch):
    """budget 120s with 115s already elapsed: the single pre-CAS gate still
    sees remaining >0 so the dispatch commits — and the send then arms the
    FULL policy window (600), never the remaining 5s. A committed dispatch
    may overrun by up to request_timeout_seconds; the preparation ceiling
    itself stays the remaining run budget."""
    _b2b_env(tmp_path, monkeypatch)
    clock = _FakeClock(1000.0)
    cap = _cap_with_timeout(600, sink=_TSink())
    out = _drive_b2b_run(tmp_path, monkeypatch, cap, clock=clock,
                         run_budget=120.0, budget_started=885.0)
    try:
        out["driver"].join(timeout=10.0)
        send = out["sends"][0]
        assert out["prep_stale_timeout"] == 5.0
        assert send["call_start"] == 1000.0
        assert send["stale_timeout"] == 600.0
        assert out.get("error") is None and cap.sink.committed is not None
    finally:
        out["finish"]()


def test_b2b_send_arms_policy_timeout_after_slow_preparation(tmp_path, monkeypatch):
    """Fake clock: budget 120 from t1000, +8s of client/dispatch preparation —
    the raw deadline covers preparation (8 + 600) while the effective window
    at the send is the full policy 600, never the fresh remaining 112."""
    _b2b_env(tmp_path, monkeypatch)
    clock = _FakeClock(1000.0)
    cap = _cap_with_timeout(600, sink=_TSink())
    out = _drive_b2b_run(tmp_path, monkeypatch, cap, clock=clock,
                         prep_seconds=4.0, dispatch_seconds=4.0,
                         run_budget=120.0, budget_started=1000.0)
    try:
        out["driver"].join(timeout=10.0)
        send = out["sends"][0]
        assert out["prep_stale_timeout"] == 120.0
        assert send["call_start"] == 1000.0 and send["now"] == 1008.0
        assert send["stale_timeout"] == 608.0
        assert send["stale_timeout"] - (send["now"] - send["call_start"]) == 600.0
        assert out.get("error") is None and cap.sink.committed is not None
    finally:
        out["finish"]()


def test_b2b_policy_timeout_beats_generic_stale_override(tmp_path, monkeypatch):
    """An operator's explicit generic stale (900s env) must NOT ride onto the
    B2B lane: the pinned 600 policy timeout is what arms at the send."""
    _b2b_env(tmp_path, monkeypatch)
    monkeypatch.setenv("HERMES_API_CALL_STALE_TIMEOUT", "900")
    from agent.chat_completion_helpers import _resolve_nonstream_watchdogs
    clock = _FakeClock(1000.0)
    cap = _cap_with_timeout(600, sink=_TSink())
    out = _drive_b2b_run(tmp_path, monkeypatch, cap, clock=clock)
    try:
        out["driver"].join(timeout=10.0)
        send = out["sends"][0]
        assert send["stale_timeout"] == 600.0
        # The generic resolver really carried the 900s override — the lane
        # dropped it, it was never absent.
        assert _resolve_nonstream_watchdogs(
            out["agent"], {"model": "unit-double", "messages": []}
        ).stale_timeout == 900.0
        assert out.get("error") is None and cap.sink.committed is not None
    finally:
        out["finish"]()


def test_b2b_short_policy_send_still_runs_after_slow_preparation(
        tmp_path, monkeypatch):
    """request_timeout_seconds=1 with 8s of client/dispatch preparation:
    preparation never spends the provider timeout — raw deadline 9 (8 prep +
    1 provider), effective window 1, the send still reaches the wire."""
    _b2b_env(tmp_path, monkeypatch)
    clock = _FakeClock(1000.0)
    cap = _cap_with_timeout(1, sink=_TSink())
    out = _drive_b2b_run(tmp_path, monkeypatch, cap, clock=clock,
                         prep_seconds=4.0, dispatch_seconds=4.0,
                         run_budget=60.0, budget_started=1000.0)
    try:
        out["driver"].join(timeout=10.0)
        send = out["sends"][0]
        assert send["call_start"] == 1000.0 and send["now"] == 1008.0
        assert send["stale_timeout"] == 9.0
        assert send["stale_timeout"] - (send["now"] - send["call_start"]) == 1.0
        assert out.get("error") is None and cap.sink.committed is not None
    finally:
        out["finish"]()


def test_b2b_pre_arm_poll_elapsed_cannot_expire_armed_window(
        tmp_path, monkeypatch):
    """The construction clock never moves: a poll that captured elapsed BEFORE
    the send arming compares it to the absolute deadline (elapsed + window),
    so a freshly armed window can never be falsely expired by a stale cached
    elapsed. prep 8s + policy 600 → deadline 608 ≥ a cached elapsed of 8
    (run budget 13 still has 5s left at the pre-CAS gate, so the dispatch
    commits)."""
    _b2b_env(tmp_path, monkeypatch)
    clock = _FakeClock(1000.0)
    cap = _cap_with_timeout(600, sink=_TSink())
    out = _drive_b2b_run(tmp_path, monkeypatch, cap, clock=clock,
                         prep_seconds=4.0, dispatch_seconds=4.0,
                         run_budget=13.0, budget_started=1000.0)
    try:
        out["driver"].join(timeout=10.0)
        send = out["sends"][0]
        assert send["call_start"] == 1000.0 and send["now"] == 1008.0
        elapsed_at_send = send["now"] - send["call_start"]
        assert elapsed_at_send == 8.0
        assert send["stale_timeout"] == 608.0
        # The invariant: an older poll's cached elapsed (8) sits below the
        # armed deadline (608) — the fresh 600s window is never falsely expired.
        assert send["stale_timeout"] >= elapsed_at_send
        assert send["stale_timeout"] - elapsed_at_send == 600.0
        assert out.get("error") is None and cap.sink.committed is not None
    finally:
        out["finish"]()


@pytest.mark.parametrize("provider_seconds", [595.0, 601.0],
                         ids=["answer-inside-budget", "answer-past-budget"])
def test_b2b_provider_timeout_counts_from_actual_send(
        tmp_path, monkeypatch, provider_seconds):
    """Codex regression: construction t1000, client/dispatch preparation +8s,
    SDK send at t1008. The 600s provider allowance starts AT THE SEND — armed
    as the absolute deadline elapsed+window on the construction clock — so 595
    provider-seconds (603 total) commits while 601 hits the real
    ``_stale_kill``. The response is released only after a full poll has
    completed at the chosen elapsed, proven by a SECOND time-read."""
    _b2b_env(tmp_path, monkeypatch)
    clock = _FakeClock(1000.0)
    killed = threading.Event()
    second_poll = threading.Event()
    cap = _cap_with_timeout(600, sink=_TSink())
    out = _drive_b2b_run(tmp_path, monkeypatch, cap, clock=clock,
                         prep_seconds=4.0, dispatch_seconds=4.0, gated=True)
    try:
        req = out["req"]
        # Record the REAL kill before the clock advances: kills are impossible
        # while the armed deadline is inf or elapsed stays inside preparation.
        orig_kill = req._stale_kill

        def _recording_kill(elapsed):
            killed.set()
            return orig_kill(elapsed)
        req._stale_kill = _recording_kill
        assert out["send_flag"].wait(4.0), "worker never reached the SDK send"
        send = out["sends"][0]
        # The poll reads h.time once per iteration; a SECOND read at the target
        # proves one full previous poll (incl. its stale comparison) completed.
        target = 1008.0 + provider_seconds
        send_flag = out["send_flag"]
        reads = {"at_target": 0}

        def _on_read(v):
            if send_flag.is_set() and v >= target:
                reads["at_target"] += 1
                if reads["at_target"] >= 2:
                    second_poll.set()
        clock.on_read = _on_read
        clock.advance(provider_seconds)
        deadline = time.time() + 4.0
        while (not killed.is_set() and not second_poll.is_set()
               and time.time() < deadline):
            time.sleep(0.02)
        if provider_seconds <= 600.0:
            # BEHAVIOR FIRST: a whole poll at 603 total seconds passed without
            # any stale kill — the send-armed 600s budget covers 595.
            assert second_poll.is_set() and not killed.is_set()
            out["release"].set()
            out["driver"].join(timeout=10.0)
            assert out.get("error") is None and out["response"] is not None
            assert cap.sink.committed is not None
        else:
            assert killed.is_set()
            out["driver"].join(timeout=10.0)
            assert isinstance(out.get("error"), TimeoutError)
            assert cap.sink.committed is None
        # The armed representation: stable construction clock, absolute
        # deadline = preparation elapsed + effective provider window.
        assert send["call_start"] == 1000.0 and send["now"] == 1008.0
        assert send["stale_timeout"] == 608.0
        assert send["stale_timeout"] - (send["now"] - send["call_start"]) == 600.0
    finally:
        out["finish"]()
    if provider_seconds > 600.0:
        # The aborted send unwound through ordinary worker normalization —
        # the existing reason, never a new one.
        assert cap.sink.blocked == ["provider_result_unavailable"]


@pytest.mark.parametrize("budget", [0.0, -5.0], ids=["zero", "negative"])
def test_b2b_exhausted_run_budget_stops_at_dispatch_gate(
        tmp_path, monkeypatch, budget):
    """A run budget already spent BEFORE the worker starts stops the dispatch
    at the SINGLE pre-CAS gate — the client was built (the gate is after
    preparation, not before it), the SDK send never ran, classified
    provider_result_unavailable."""
    _b2b_env(tmp_path, monkeypatch)
    cap = _cap_with_timeout(600, sink=_TSink())
    out = _drive_b2b_run(tmp_path, monkeypatch, cap, run_budget=budget,
                         budget_started=time.time())
    try:
        out["driver"].join(timeout=10.0)
        assert len(out["made"]) == 1 and out["sends"] == []
        assert isinstance(out.get("error"), B2BTerminalRefusal)
        assert str(out["error"]) == "provider_result_unavailable"
        assert cap.sink.blocked == ["provider_result_unavailable"]
    finally:
        out["finish"]()


def test_b2b_run_budget_start_at_epoch_zero_is_a_real_start(tmp_path, monkeypatch):
    """``_run_budget_started_at=0`` is a VALID numeric start (epoch), not a
    falsy "no budget" marker — a 600s budget from epoch 0 is long spent, so the
    dispatch stops at the pre-CAS gate after the client build."""
    _b2b_env(tmp_path, monkeypatch)
    cap = _cap_with_timeout(600, sink=_TSink())
    out = _drive_b2b_run(tmp_path, monkeypatch, cap, run_budget=600.0,
                         budget_started=0.0)
    try:
        out["driver"].join(timeout=10.0)
        assert len(out["made"]) == 1 and out["sends"] == []
        assert isinstance(out.get("error"), B2BTerminalRefusal)
        assert str(out["error"]) == "provider_result_unavailable"
        assert cap.sink.blocked == ["provider_result_unavailable"]
    finally:
        out["finish"]()


def _terminal_gate_probe(tmp_path, monkeypatch, *, run_budget=None,
                         budget_started=None, on_resolve=None):
    """Real ``_terminal_lane`` driven through ``request._call()`` under the
    execution binding: real ``_AttemptSink``/disk store/SDK -> loopback
    double, REAL ``before_sdk_dispatch`` + CAS fence -- never a stubbed
    dispatch. A ``_FakeClock`` binds ``_helpers.time`` only; the sink's
    signed-window checks keep real clocks. Invocation counts of the
    worker-side C1, the source renewal and ``cas_dispatch`` are recorded;
    ``on_resolve(request, clock)`` runs inside the REAL renewal after it
    returns True and before the gate (clock spend / cancel injection).
    ``request._call()`` isolates the generic poll loop exactly like the
    post-CAS witness did. Caller closes via ``_close_probe``."""
    request = None
    recheck_calls = []

    def _recheck(_cap):
        recheck_calls.append(len(recheck_calls) + 1)
        return copy.deepcopy(lane.view)

    lane, provider, agent = _terminal_lane(
        tmp_path, monkeypatch, recheck=_recheck)
    try:
        clock = _FakeClock(time.time())
        monkeypatch.setattr(_helpers, "time", clock)
        if run_budget is not None:
            agent.run_budget_seconds = run_budget
            agent._run_budget_started_at = (
                clock.time() if budget_started is None else budget_started)

        resolve_calls = []
        original_resolve = lane.sink.resolve_before_provider

        def _resolve_probe():
            resolve_calls.append(len(resolve_calls) + 1)
            ok = original_resolve()
            if ok and on_resolve is not None:
                on_resolve(request, clock)
            return ok
        monkeypatch.setattr(
            lane.sink, "resolve_before_provider", _resolve_probe)

        cas_calls = []
        original_cas = lane.sink.cas_dispatch

        def _cas_spy(**kw):
            cas_calls.append(kw)
            return original_cas(**kw)
        monkeypatch.setattr(lane.sink, "cas_dispatch", _cas_spy)

        api_kwargs = copy.deepcopy(_api_kwargs(lane))
        request = _B2BNonStreamRequest(
            agent, api_kwargs, cap=lane.cap, receipt=lane.receipt,
            request_digest=be.provider_request_digest(api_kwargs))

        token = bind_execution(lane.cap)
        try:
            request._call()
        finally:
            reset_execution(token)

        return SimpleNamespace(
            lane=lane, provider=provider, agent=agent, request=request,
            clock=clock, recheck_calls=recheck_calls,
            resolve_calls=resolve_calls, cas_calls=cas_calls)
    except BaseException:
        if request is not None:
            request.clients.close_once("gate_probe_error_cleanup")
        agent.client.close()
        lane.store.close()
        provider.stop()
        raise


def _close_probe(probe, reason):
    if probe.request is not None:
        probe.request.clients.close_once(reason)
    probe.agent.client.close()
    probe.lane.store.close()
    probe.provider.stop()


def test_b2b_budget_spent_inside_preparation_stops_before_send(
        tmp_path, monkeypatch):
    """REAL durable lane (real ``_AttemptSink``, disk store, real
    ``before_sdk_dispatch`` + CAS fence, real SDK client -> loopback double):
    a 10s run budget spent INSIDE the source renewal stops at the single
    pre-CAS gate — the worker-side C1 and the renewal provably ran,
    ``cas_dispatch`` was NEVER invoked and no provider POST happened, so the
    attempt has no dispatch uncertainty at all: durable ``failed`` via the
    existing ``provider_result_unavailable`` classification (no committed
    marker -> never ``indeterminate``), no dispatch/result artifacts —
    verified again on a reopened disk connection."""
    probe = _terminal_gate_probe(
        tmp_path, monkeypatch, run_budget=10.0,
        on_resolve=lambda request, clock: clock.advance(15.0))
    try:
        request = probe.request
        # The gate refusal normalized inside the worker like any classified
        # refusal: no response, the typed error surfaced.
        assert request.result["response"] is None
        assert isinstance(request.result["error"], B2BTerminalRefusal)
        assert str(request.result["error"]) == "provider_result_unavailable"
        # The worker-side C1 and the renewal ran; the gate sits between the
        # renewal and the CAS -- the CAS never executed.
        assert probe.recheck_calls == [1]
        assert probe.resolve_calls == [1]
        assert probe.cas_calls == []
        assert probe.provider.posts == []
        for kind in ("provider_dispatch", "provider_result"):
            assert probe.lane.store.b2b_artifact(
                attempt_id=probe.lane.attempt_id, kind=kind) is None
        # Durable on a second connection: failed, never indeterminate.
        probe.lane.store.close()
        reopened = RunIdempotencyStore(str(probe.lane.db_path))
        try:
            assert reopened.b2b_attempt(
                profile=probe.lane.profile, attempt_id=probe.lane.attempt_id)[
                    "status"] == "failed"
        finally:
            reopened.close()
    finally:
        _close_probe(probe, "budget_gate_teardown")


@pytest.mark.parametrize("budget", [0.0, -5.0], ids=["zero", "negative"])
def test_b2b_exhausted_budget_blocks_real_sink_as_failed(
        tmp_path, monkeypatch, budget):
    """REAL durable lane (real ``_AttemptSink``, disk store, real
    ``before_sdk_dispatch`` + CAS fence): an already-spent run budget is
    refused by the single pre-CAS gate — AFTER the real C1 + renewal, before
    any ``cas_dispatch`` invocation — so no dispatch was ever committed and
    there is no provider-side uncertainty to resolve: durable ``failed``
    (never ``indeterminate``), no provider POST, no dispatch/result
    artifacts."""
    probe = _terminal_gate_probe(
        tmp_path, monkeypatch, run_budget=budget)
    try:
        request = probe.request
        assert request.result["response"] is None
        assert isinstance(request.result["error"], B2BTerminalRefusal)
        assert str(request.result["error"]) == "provider_result_unavailable"
        assert probe.recheck_calls == [1]
        assert probe.resolve_calls == [1]
        assert probe.cas_calls == []
        assert probe.provider.posts == []
        assert probe.lane.store.b2b_attempt(
            profile="hub", attempt_id=probe.lane.attempt_id)[
                "status"] == "failed"
        for kind in ("provider_dispatch", "provider_result"):
            assert probe.lane.store.b2b_artifact(
                attempt_id=probe.lane.attempt_id, kind=kind) is None
    finally:
        _close_probe(probe, "exhausted_budget_teardown")


def test_b2b_cancel_during_preparation_blocks_failed_at_gate(
        tmp_path, monkeypatch):
    """REAL durable lane, real ``before_sdk_dispatch`` + CAS fence: the cancel
    flag lands INSIDE the wrapped real source renewal — the SAME pre-CAS gate
    refuses (``self.cancelled`` branch): C1 and the renewal provably ran, no
    ``cas_dispatch``, no provider POST, durable ``failed`` even though
    ``_call`` swallows the cancelled worker's exception -- the durable block
    lands BEFORE the raise so a swallowed refusal can never leave the attempt
    ``context_ready``."""
    probe = _terminal_gate_probe(
        tmp_path, monkeypatch,
        on_resolve=lambda request, clock: setattr(
            request, "cancelled", True))
    try:
        request = probe.request
        # _call swallowed the refusal as an ordinary cancel: neither response
        # nor error surfaced -- but the durable block already landed.
        assert request.result["response"] is None
        assert request.result["error"] is None
        # The worker-side C1 and the renewal ran; the gate is AFTER them and
        # BEFORE the CAS, which never executed.
        assert probe.recheck_calls == [1]
        assert probe.resolve_calls == [1]
        assert probe.cas_calls == []
        assert probe.provider.posts == []
        assert probe.lane.store.b2b_attempt(
            profile=probe.lane.profile, attempt_id=probe.lane.attempt_id)[
                "status"] == "failed"
        for kind in ("provider_dispatch", "provider_result"):
            assert probe.lane.store.b2b_artifact(
                attempt_id=probe.lane.attempt_id, kind=kind) is None
    finally:
        _close_probe(probe, "cancel_gate_teardown")
