"""Unit tests for ``agent.b2b_execution`` — the frozen capability, context publication,
proposal validation, terminal ordering and the worker-side result check.

Every context producer/rechecker below is an EXPLICIT TEST DOUBLE, never a real
AgentContext/C1 builder — H1's context seam is a placeholder contract.
"""

from __future__ import annotations

import tempfile
import weakref

import pytest

from agent.b2b_execution import (
    BoundExecution, B2BTerminalRefusal, ContextReceipt, _deep_freeze,
    _public_text, bind_execution, canonical_json, current_execution,
    execute_terminal, extract_allowed_refs, is_b2b_attempt_id, is_b2b_session_id,
    publish_context, require_execution, reset_execution, validate_proposal)
from hermes_constants import get_hermes_home
from tests.gateway.b2b_process_harness import (
    UNIT_RENDERED, build_context_view, extract_contract_root)


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
