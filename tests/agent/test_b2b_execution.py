"""Unit tests for ``agent.b2b_execution`` — the frozen capability, context publication,
proposal validation, terminal ordering and the worker-side result check.

Every context producer/rechecker below is an EXPLICIT TEST DOUBLE, never a real
AgentContext/C1 builder — H1's context seam is a placeholder contract.
"""

from __future__ import annotations

import copy
import tempfile
import time

import pytest

from agent import b2b_execution as be
from agent.b2b_execution import (
    BoundExecution, B2BTerminalRefusal, ContextReceipt, _deep_freeze,
    _public_text, bind_execution, canonical_json, current_execution,
    execute_terminal, extract_allowed_refs, install_bounded_agent_policy,
    is_b2b_attempt_id, is_b2b_session_id, json_utf8, mission_prompt,
    native_context_digest, publish_context, require_execution,
    reset_execution, validate_proposal)
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
    assert kw["max_retries"] == 0
    assert kw["timeout"] == 600.0
    assert float(kw["http_client"].timeout.connect) == 600.0
    assert req.api_kwargs["timeout"] == 600.0
    assert req.clients.calls[0][1] == "openai"


def test_make_client_request_timeout_defaults_to_five(monkeypatch):
    import agent.b2b_nonstream as _b2b_ns_mod
    monkeypatch.setattr(_b2b_ns_mod, "before_sdk_dispatch", lambda *a, **k: None)
    req, made = _timeout_worker(_cap_with_timeout(None))
    req._make_client("test")
    kw = made[0].with_options_calls[0]
    assert kw["timeout"] == 5.0
    assert float(kw["http_client"].timeout.connect) == 5.0
    assert req.api_kwargs["timeout"] == 5.0


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
# stale watchdog on the B2B lane — policy floor, run-budget bound
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
    from agent.b2b_execution import install_bounded_agent_policy
    agent = _fresh_agent(base_url=base_url, session_id=cap.session_id)
    token = bind_execution(cap)
    try:
        install_bounded_agent_policy(agent, cap)
    finally:
        reset_execution(token)
    return agent


def test_b2b_watchdog_floors_at_project_timeout_on_remote(tmp_path, monkeypatch):
    """Remote endpoint + request_timeout_seconds=600: the dedicated request's
    stale watchdog tracks the project policy — never the implicit 90s fuse that
    fires mid-call on slow upstreams — and stays bounded by the remaining run
    budget. The generic resolver is untouched."""
    _b2b_env(tmp_path, monkeypatch)
    import time as _time
    from agent.b2b_nonstream import _B2BNonStreamRequest
    from agent.chat_completion_helpers import _resolve_nonstream_watchdogs
    kwargs = {"model": "unit-double", "messages": [{"role": "user", "content": "hi"}]}

    cap = _cap_with_timeout(600)
    agent = _remote_b2b_agent(tmp_path, monkeypatch, cap)
    req = _B2BNonStreamRequest(agent, dict(kwargs), cap=cap,
                               receipt=object(), request_digest="d" * 64)
    assert req.wd.stale_timeout == 600.0

    # Bounded by the run budget: the policy floor can never outlive the run.
    agent.run_budget_seconds = 300.0
    agent._run_budget_started_at = _time.time()
    req = _B2BNonStreamRequest(agent, dict(kwargs), cap=cap,
                               receipt=object(), request_digest="d" * 64)
    assert 280.0 < req.wd.stale_timeout <= 300.0

    # Control: the ordinary generic helper keeps the 90s implicit fuse even on
    # the SAME cap-bound agent — the lane owns the floor, not shared state.
    assert _resolve_nonstream_watchdogs(agent, kwargs).stale_timeout == 90.0


def _gate_run(tmp_path, monkeypatch, cap, *, elapsed_offset):
    """Run a REAL _B2BNonStreamRequest whose worker answers only when the gate
    opens, with the call clock already ``elapsed_offset`` seconds in. Returns
    (response|None, error|None, cap)."""
    import threading
    import agent.b2b_nonstream as _b2b_ns_mod
    from agent.b2b_nonstream import _B2BNonStreamRequest
    from types import SimpleNamespace
    monkeypatch.setattr(_b2b_ns_mod, "before_sdk_dispatch", lambda *a, **k: None)
    gate = threading.Event()
    response = _Resp(content=_good_proposal())
    outcome = {}

    class _GateClient:
        def __init__(self):
            self.max_retries = 0
            self.base_url = "https://llm.example.com/v1"
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

        def with_options(self, **kw):
            clone = _GateClient()
            clone.max_retries = kw.get("max_retries", 0)
            return clone

        def _create(self, **_kw):
            gate.wait(30)
            return response

    agent = _remote_b2b_agent(tmp_path, monkeypatch, cap)
    agent._create_request_openai_client = lambda **kw: _GateClient()
    agent._close_request_openai_client = lambda *a, **k: None
    agent._abort_request_openai_client = lambda *a, **k: None
    token = bind_execution(cap)
    try:
        req = _B2BNonStreamRequest(
            agent, {"model": "unit-double",
                    "messages": [{"role": "user", "content": "hi"}]},
            cap=cap, receipt=object(), request_digest="d" * 64)
        req.call_start -= elapsed_offset

        def _drive():
            try:
                outcome["response"] = req.run()
            except Exception as exc:  # noqa: BLE001 — surfaced by the assertion
                outcome["error"] = exc

        driver = threading.Thread(target=_drive, daemon=True)
        try:
            driver.start()
            driver.join(timeout=4.0)
            outcome["killed_early"] = not driver.is_alive()
        finally:
            gate.set()
        driver.join(timeout=10.0)
    finally:
        gate.set()
        reset_execution(token)
    outcome["req"] = req
    return outcome


def test_b2b_remote_run_survives_past_implicit_stale(tmp_path, monkeypatch):
    """Through run(): a remote worker answering at elapsed>90s is NOT stale-killed
    when the project pins 600s — the defect the review scenario described."""
    _b2b_env(tmp_path, monkeypatch)
    cap = _cap_with_timeout(600, sink=_TSink())
    out = _gate_run(tmp_path, monkeypatch, cap, elapsed_offset=100.0)
    assert out["req"].wd.stale_timeout == 600.0
    assert not out["killed_early"]          # still polling at ~103s, past 90
    assert out.get("error") is None and out.get("response") is not None
    assert cap.sink.committed is not None   # result passed the B2B result fence


def test_b2b_remote_run_still_killed_without_policy_floor(tmp_path, monkeypatch):
    """Control: without the configured key the implicit 90s fuse still cuts the
    remote call — proving the policy floor, not the lane, carries the 600s."""
    _b2b_env(tmp_path, monkeypatch)
    cap = _cap_with_timeout(None, sink=_TSink())
    out = _gate_run(tmp_path, monkeypatch, cap, elapsed_offset=100.0)
    assert out["req"].wd.stale_timeout == 90.0
    assert out["killed_early"]
    assert isinstance(out.get("error"), TimeoutError)
