"""Unit tests for ``agent.b2b_execution`` — the frozen capability, context publication,
proposal validation, terminal ordering and the worker-side result check.

Every context producer/rechecker below is an EXPLICIT TEST DOUBLE, never a real
AgentContext/C1 builder — H1's context seam is a placeholder contract.
"""

from __future__ import annotations

import tempfile
import weakref

import pytest

from agent import b2b_execution as be
from agent.b2b_execution import (
    BoundExecution, B2BTerminalRefusal, ContextReceipt, _deep_freeze,
    _public_text, bind_execution, canonical_json, current_execution,
    execute_terminal, extract_allowed_refs, is_b2b_attempt_id, is_b2b_session_id,
    publish_context, require_execution, reset_execution, validate_proposal)
from hermes_constants import get_hermes_home
from tests.gateway.b2b_process_harness import (
    UNIT_RENDERED, build_context_view, build_unit_native_oc_view, extract_contract_root,
    renew_unit_oc_read, reseal_unit_context_view)


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
    (("qualification", "values", 0, "observation_ref"), "oco_" + "c" * 32),
    (("qualification", "values", 0, "value"), "b" * 40),
    (("qualification", "values", 0, "source_observed_at"), "2026-10-30T11:59:59.000Z"),
    (("qualification", "values", 0, "received_at"), "2026-10-30T12:00:00.002Z"),
    (("qualification", "mapping_ref"), "mapping:changed"),
    (("qualification", "mapping_version"), 2),
    (("qualification", "rule_ref"), "rule:changed"),
    (("qualification", "rule_version"), 2),
    (("qualification", "freshness"), "stale"),
    (("qualification", "status"), "pending_recalculation"),
    (("qualification", "admissibility"), "limited"),
    (("qualification", "agreement"), "conflict"),
    (("qualification", "limits"), [{"code": "SOURCE_CHANGED"}]),
    (("reserves",), [{"code": "SOURCE_CHANGED"}]),
    (("bounds", "max_observations_examined"), 199),
    (("bounds", "truncated"), True),
    (("unknown_future_source_field",), "changed"),
]


@pytest.mark.parametrize(("path", "replacement"), _NATIVE_SOURCE_MUTATIONS)
def test_native_source_drift_is_never_normalized_away(path, replacement):
    original = build_unit_native_oc_view(_cap().policy, {})
    fresh = renew_unit_oc_read(original)
    target = fresh["operational_context"]["view"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement
    reseal_unit_context_view(fresh)
    with pytest.raises(B2BTerminalRefusal):
        be.assert_source_equivalent(original, fresh)


@pytest.mark.parametrize(("field", "replacement"), [
    ("age_ms", 2001), ("freshness_max_age_ms", 1999), ("eligible", False),
    ("head_complete", False), ("history_truncated", True),
    ("binding_version", 2), ("mapping_version", 2), ("rule_version", 2),
    ("producer_epoch", "epoch:changed"), ("freshness", "stale"),
    ("instant", "2026-10-30T12:00:01.000Z"),
])
def test_ordered_snapshot_age_is_checked_before_excluding_read_metadata(field, replacement):
    original = build_unit_native_oc_view(_cap().policy, {}, ordered=True)
    fresh = renew_unit_oc_read(original)
    fresh["operational_context"]["view"]["state_projection"][field] = replacement
    reseal_unit_context_view(fresh)
    with pytest.raises(B2BTerminalRefusal):
        be.assert_source_equivalent(original, fresh)


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
    """Attach a minimal agent stand-in through the real binding fields the host
    sets (capability tag + weakref), carrying the current turn id."""
    class A:
        session_id = cap.session_id
    agent = A()
    agent._b2b_execution = cap  # instance attr -- require_execution reads vars(agent)
    agent._current_turn_id = turn_id
    object.__setattr__(cap, "_agent_ref", weakref.ref(agent))
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
    with pytest.raises(B2BTerminalRefusal):
        cap.publish_context({"accepted_context": True, "resolution": "governed_bound"},
                            b"r", turn_id="t")


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
        cap.register_context_recheck(lambda c: build_context_view(c.policy, {}))
        with pytest.raises(B2BTerminalRefusal):
            execute_terminal(
                agent, {"messages": [{"role": "user", "content": UNIT_RENDERED}]},
                cap, turn_id="t-OTHER")
    finally:
        reset_execution(token)


def test_is_b2b_predicates():
    assert is_b2b_session_id("b2b_" + "a" * 64)
    assert not is_b2b_session_id("b2b_" + "a" * 63)
    assert not is_b2b_session_id("api_x")
    assert is_b2b_attempt_id("b2bp_" + "b" * 64)
    assert not is_b2b_attempt_id("b2b_" + "b" * 64)
