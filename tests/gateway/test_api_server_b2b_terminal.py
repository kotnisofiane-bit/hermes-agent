"""B2B terminal seam coverage -- the ONLY path that physically reaches a
provider: ``execute_terminal`` -> ``_NonStreamRequest`` -> real OpenAI SDK ->
loopback provider double.

Covers the durable ordering Claude's review found untested: CAS before the one
SDK send, request-local client with ``max_retries == 0``, ``X-Dubsar-*``
headers, result validated + persisted inside the worker, error normalization to
``provider_result_unavailable`` -> durable ``indeterminate``, second passage
refused, plus the ``_AttemptSink.block`` reason->status table and proposal
bounds through the real validator + disk sink.

All context/source/provider data are UNIT DOUBLES; the OpenAI SDK, the disk
store, the sink, the schemas and the transactions are real. Nothing here proves
or claims product B2B execution -- ``_create_agent`` refuses before runtime by
design (see tests/gateway/test_api_server_b2b_runtime.py).
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import http.server
import json
import logging
import sqlite3
import threading
import time
import types
import uuid

import openai
import pytest

from agent import chat_completion_helpers as h
from agent.b2b_execution import (
    BLOCK_REASONS, B2BTerminalRefusal, bind_execution, current_execution,
    execute_terminal, extract_allowed_refs, install_bounded_agent_policy,
    json_utf8, mission_prompt, provider_request_digest, recheck_context,
    reset_execution, validate_proposal, validate_terminal_result,
)
from agent.b2b_nonstream import _B2BNonStreamRequest
from gateway.platforms import api_server_b2b as b2b
from gateway.platforms import api_server_b2b_execution as bxe
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from tests.gateway import b2b_unit_fixtures
from tests.gateway.b2b_unit_fixtures import _FakeClock
from tests.gateway.b2b_process_harness import (
    UNIT_RENDERED, build_unit_native_oc_view, renew_unit_oc_read)


@pytest.fixture
def b2b_dispatch_lane(tmp_path):
    lane = b2b_unit_fixtures.build_b2b_dispatch_lane(tmp_path)
    try:
        yield lane
    finally:
        lane.store.close()


# ---------------------------------------------------------------------------
# _AttemptSink.block -- explicit reason -> durable status table
#
# The emitted reason universe is agent.b2b_execution.BLOCK_REASONS -- the
# shared production enumeration (raise sites + block() literals across the
# lane). The durable invariants below walk THAT constant, so a new emitted
# reason with no explicit _BLOCK_STATUS entry fails the suite instead of
# silently recording "failed".
# ---------------------------------------------------------------------------

# Arbitrary exception text must never be mined for a classification.
_UNTYPED_REASON_TEXT = [
    "sqlite3.OperationalError: no such context table",
    "RuntimeError: policy file missing",
    "TimeoutError: source read exceeded deadline",
    "ValueError: result could not decode",
]

# Table-only entries with no current emitter still classify explicitly
# (pre-declared families + the durable status passthrough).
_TABLE_ONLY_PAIRS = (
    [("b2b_alternate_provider", "policy_changed"),
     ("response_not_public", "result_invalid")]
    + [(s, s) for s in sorted(b2b._BLOCK_TERMINAL_STATUSES)])


@pytest.mark.parametrize("reason", sorted(BLOCK_REASONS))
def test_block_every_emitted_reason_classifies_explicitly(
        b2b_dispatch_lane, reason):
    """Every refusal reason the lane can emit has an EXPLICIT durable status:
    ``_BLOCK_STATUS`` must contain it (a ``.get`` fallback is not a
    classification) and ``block()`` must persist exactly the mapped status."""
    lane = b2b_dispatch_lane
    expected = b2b._BLOCK_STATUS[reason]  # KeyError: emitted reason unclassified
    lane.sink.block(reason)
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)["status"] == expected


def test_emitted_reason_families_match_review_semantics():
    """The classification contract stated INDEPENDENTLY of the table: every
    context-qualification/proof refusal is ``context_stale``
    (``context_unavailable`` is the withdrawn-context refusal and
    ``context_sink_missing`` is missing plumbing, not staleness); every
    ``b2b_*`` capability/policy refusal is ``policy_changed``; signed-source
    denials are ``source_denied``; public-result refusals are
    ``result_invalid``. The remaining known reasons -- ``json_*`` serializer
    guards (they also fire on non-context payloads), missing plumbing,
    no-receipt conditions, commit integrity and untyped run exits -- are
    explicitly ``failed``."""
    expected = {}
    for reason in BLOCK_REASONS:
        if reason == "context_unavailable":
            expected[reason] = "context_unavailable"
        elif (reason.startswith("context_")
                and reason != "context_sink_missing"
                and not reason.endswith(("_failed", "_unattested"))):
            expected[reason] = "context_stale"
        elif reason.startswith("source_"):
            expected[reason] = "source_denied"
        elif (reason.startswith("b2b_")
                and not reason.endswith(("_failed", "_unavailable"))
                or reason in {"kwargs_not_permitted", "terminal_guard_required"}):
            expected[reason] = "policy_changed"
        elif reason in {"result_invalid", "proposal_invalid"}:
            expected[reason] = "result_invalid"
        else:
            expected[reason] = "failed"
    wrong = {r: (expected[r], b2b._BLOCK_STATUS.get(r)) for r in expected
             if b2b._BLOCK_STATUS.get(r) != expected[r]}
    assert not wrong, wrong


@pytest.mark.parametrize(
    ("reason", "expected"),
    _TABLE_ONLY_PAIRS + [(r, "failed") for r in _UNTYPED_REASON_TEXT])
def test_block_maps_reason_to_explicit_status(b2b_dispatch_lane, reason, expected):
    lane = b2b_dispatch_lane
    lane.sink.block(reason)
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)["status"] == expected


def _commit_dispatch(lane):
    lane.sink._before_provider = lane.resolved
    assert lane.sink.cas_dispatch(
        request_digest=lane.policy["request_digest"], receipt=lane.receipt,
        rechecked_view=renew_unit_oc_read(lane.view))
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)[
            "status"] == "dispatch_committed"


@pytest.mark.parametrize("reason", sorted(
    r for r in BLOCK_REASONS if b2b._BLOCK_STATUS[r] != "result_invalid"))
def test_block_after_committed_dispatch_is_indeterminate(b2b_dispatch_lane, reason):
    """CAS committed + NO durable provider result => indeterminate, whatever the
    reason -- the dispatch may have reached the provider."""
    lane = b2b_dispatch_lane
    _commit_dispatch(lane)
    lane.sink.block(reason)
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)["status"] == "indeterminate"


@pytest.mark.parametrize(
    "reason", sorted(b2b._BLOCK_RESULT_INVALID_REASONS)
    + ["result_invalid:summary_bounds;steps[0]_bounds"])
def test_block_after_committed_dispatch_keeps_result_invalid(
        b2b_dispatch_lane, reason):
    """A proven-invalid result is a KNOWN outcome, not an unknown one: the
    indeterminate override never applies to result_invalid -- including the
    ``result_invalid:<validator detail>`` raises that embed the validator
    reason in the exception string."""
    lane = b2b_dispatch_lane
    _commit_dispatch(lane)
    lane.sink.block(reason)
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)["status"] == "result_invalid"


def test_block_first_terminal_status_is_immutable(b2b_dispatch_lane):
    lane = b2b_dispatch_lane
    lane.sink.block("context_stale")
    lane.sink.block("result_invalid")
    lane.sink.block("policy_provider_unavailable")
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)["status"] == "context_stale"


# ---------------------------------------------------------------------------
# Proposal validation + real-sink persistence (replaces the fixture snapshot)
# ---------------------------------------------------------------------------

def _proposal_text(**over):
    base = {"summary": "s", "steps": ["st"], "source_refs": [], "limitations": []}
    base.update(over)
    return json.dumps(base)


_VALID_CASES = [
    ("summary_min", {"summary": "s"}, ()),
    ("summary_max", {"summary": "x" * 2000}, ()),
    ("steps_min", {"steps": ["a"]}, ()),
    ("steps_max", {"steps": ["a"] * 12}, ()),
    ("step_len_min", {"steps": ["a"]}, ()),
    ("step_len_max", {"steps": ["a" * 500]}, ()),
    ("source_refs_min", {"source_refs": []}, ()),
    ("source_refs_max", {"source_refs": ["r%d" % i for i in range(50)]},
     tuple("r%d" % i for i in range(50))),
    ("source_ref_len_max", {"source_refs": ["r" * 512]}, ("r" * 512,)),
    ("limitations_min", {"limitations": []}, ()),
    ("limitations_max", {"limitations": ["l"] * 12}, ()),
    ("limitation_len_max", {"limitations": ["l" * 500]}, ()),
    # 2000 CHARS of a 2-byte glyph: field bounds are character counts.
    ("summary_multibyte", {"summary": "\u00e9" * 2000}, ()),
]

_INVALID_CASES = [
    ("summary_too_short", {"summary": ""}, (), "summary"),
    ("summary_too_long", {"summary": "x" * 2001}, (), "summary"),
    ("steps_too_few", {"steps": []}, (), "steps"),
    ("steps_too_many", {"steps": ["a"] * 13}, (), "steps"),
    ("step_too_long", {"steps": ["a" * 501]}, (), "steps"),
    ("source_refs_too_many", {"source_refs": ["r%d" % i for i in range(51)]},
     tuple("r%d" % i for i in range(51)), "source_refs"),
    ("source_ref_too_long", {"source_refs": ["r" * 513]}, ("r" * 513,), "source_refs"),
    ("source_ref_not_whitelisted", {"source_refs": ["other"]}, ("allowed",), "not_in_context"),
    ("source_ref_no_context_refs", {"source_refs": ["r"]}, (), "no_context_refs"),
    ("limitations_too_many", {"limitations": ["l"] * 13}, (), "limitations"),
    ("limitation_too_long", {"limitations": ["l" * 501]}, (), "limitations"),
]


@pytest.mark.parametrize(("case", "over", "allowed"), _VALID_CASES,
                         ids=[c[0] for c in _VALID_CASES])
def test_validate_proposal_accepts_valid_bounds(case, over, allowed):
    parsed, reason = validate_proposal(_proposal_text(**over), allowed)
    assert parsed is not None and reason == "ok"


@pytest.mark.parametrize(("case", "over", "allowed", "family"), _INVALID_CASES,
                         ids=[c[0] for c in _INVALID_CASES])
def test_validate_proposal_rejects_out_of_bounds(case, over, allowed, family):
    parsed, reason = validate_proposal(_proposal_text(**over), allowed)
    assert parsed is None and family in reason


def test_validate_proposal_rejects_max_public_bytes_via_utf8():
    """The total bound is UTF-8 BYTES, not characters: a payload under every
    per-field CHARACTER bound still refuses once the encoded body exceeds
    max_public_bytes."""
    ref = "\u00e9" * 512  # 512 chars (at bound) but 1024 utf-8 bytes
    obj = {"summary": "s", "steps": ["a"], "limitations": [],
           "source_refs": [ref] * 40}
    text = json.dumps(obj, ensure_ascii=False)
    # Every field satisfies its character bound; the wire body is 40KB+.
    assert len(text.encode("utf-8")) > 32768
    parsed, reason = validate_proposal(text, (ref,))
    assert parsed is None and reason == "response_too_large"


def test_validate_proposal_rejects_malformed_json():
    parsed, reason = validate_proposal("not json at all", ())
    assert parsed is None and reason == "response_not_json"


def test_validate_proposal_rejects_missing_and_extra_fields():
    parsed, reason = validate_proposal(
        json.dumps({"summary": "s", "steps": ["a"], "source_refs": []}), ())
    assert parsed is None and reason == "response_fields"
    parsed, reason = validate_proposal(
        _proposal_text(extra="x"), ())
    assert parsed is None and reason == "response_fields"


def test_validate_proposal_rejects_private_marker():
    parsed, reason = validate_proposal(
        _proposal_text(summary="ok <think>private</think>"), ())
    assert parsed is None and reason == "response_private_marker"


_SINK_VALID_CASES = [
    ("summary_bounds", {"summary": "x" * 2000}),
    ("steps_bounds", {"steps": ["a"] * 12}),
    ("limitations_bounds", {"limitations": ["l"] * 12}),
    ("whitelisted_refs", {"source_refs": ["unit-ref-1", "unit-ref-2"]}),
    ("full_minimal", {}),
]

_SINK_INVALID_CASES = [
    ("summary_too_long", {"summary": "x" * 2001}),
    ("steps_too_many", {"steps": ["a"] * 13}),
    ("step_too_long", {"steps": ["a" * 501]}),
    ("source_refs_too_many", {"source_refs": ["unit-ref-1"] * 51}),
    ("source_ref_too_long", {"source_refs": ["r" * 513]}),
    ("source_ref_not_whitelisted", {"source_refs": ["not-in-context"]}),
    ("limitations_too_many", {"limitations": ["l"] * 13}),
    ("limitation_too_long", {"limitations": ["l" * 501]}),
    ("malformed_json", "__NOT_JSON__"),
    ("missing_field", '{"summary":"s","steps":["a"],"source_refs":[]}'),
    ("extra_field", {"extra": "x"}),
    ("private_marker", {"summary": "ok <think>private</think>"}),
]


def _refs_lane(tmp_path):
    """Dispatch lane whose context view carries whitelisted reference strings."""
    return b2b_unit_fixtures.build_b2b_dispatch_lane(
        tmp_path, mission_source_refs=("unit-ref-1", "unit-ref-2"))


def _commit_case(lane, over):
    text = over if isinstance(over, str) else _proposal_text(**over)
    parsed, reason = validate_proposal(
        text, extract_allowed_refs(lane.receipt.view))
    return text, parsed, reason


@pytest.mark.parametrize(("case", "over"), _SINK_VALID_CASES,
                         ids=[c[0] for c in _SINK_VALID_CASES])
def test_sink_persists_valid_proposal_through_dispatch(tmp_path, case, over):
    lane = _refs_lane(tmp_path)
    try:
        _commit_dispatch(lane)
        text, parsed, reason = _commit_case(lane, over)
        assert parsed is not None and reason == "ok", (case, reason)
        lane.sink.commit_result(text=text, parsed=parsed, reason=reason)
        assert lane.store.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "result_received"
        row = lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_result")
        assert row is not None
        assert json.loads(row["payload"])["proposal"] == parsed
    finally:
        lane.store.close()


@pytest.mark.parametrize(("case", "over"), _SINK_INVALID_CASES,
                         ids=[c[0] for c in _SINK_INVALID_CASES])
def test_sink_refuses_invalid_proposal_no_artifacts(tmp_path, case, over):
    lane = _refs_lane(tmp_path)
    try:
        _commit_dispatch(lane)
        text, parsed, reason = _commit_case(lane, over)
        assert parsed is None, (case, reason)
        with pytest.raises(B2BTerminalRefusal) as exc:
            lane.sink.commit_result(text=text, parsed=parsed, reason=reason)
        assert str(exc.value) == "result_invalid"
        assert lane.store.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "result_invalid"
        snap = lane.store.b2b_snapshot(
            profile=lane.profile, attempt_id=lane.attempt_id)
        assert "provider_result" not in snap["artifacts"]
        assert "proposal" not in snap["artifacts"]
    finally:
        lane.store.close()


# ---------------------------------------------------------------------------
# Loopback provider double + stand-in agent (real OpenAI SDK, real disk sink)
# ---------------------------------------------------------------------------

_SENSITIVE_MARKER = "UNIT-SECRET-PROVIDER-BODY-9f3a2c"


class _LoopbackProvider:
    """Threaded loopback chat-completions double. Every POST is journalled with
    its X-Dubsar-* headers; while a request is in flight the handler reads the
    durable attempt state through a SEPARATE sqlite connection -- the dispatch
    CAS must already be committed before the provider is contacted."""

    def __init__(self, db_path=None, *, fail_body=None):
        self.db_path = db_path
        self.fail_body = fail_body
        self.posts = []
        self.db_observations = []

        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.posts.append({
                    "path": self.path,
                    "attempt_id": self.headers.get("X-Dubsar-Attempt-Id"),
                    "request_digest": self.headers.get("X-Dubsar-Request-Digest"),
                    "body": body})
                conn = sqlite3.connect(outer.db_path, timeout=30)
                try:
                    status = conn.execute(
                        "SELECT status FROM b2b_attempts").fetchone()[0]
                    dispatch = conn.execute(
                        "SELECT COUNT(*) FROM b2b_artifacts "
                        "WHERE kind='provider_dispatch'").fetchone()[0]
                    result = conn.execute(
                        "SELECT COUNT(*) FROM b2b_artifacts "
                        "WHERE kind='provider_result'").fetchone()[0]
                finally:
                    conn.close()
                outer.db_observations.append(
                    {"status": status, "provider_dispatch": dispatch,
                     "provider_result": result})
                if outer.fail_body is not None:
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(outer.fail_body.encode("utf-8"))
                    return
                content = json.dumps({
                    "summary": "unit provider double proposal",
                    "steps": ["read the supplied synthetic context"],
                    "source_refs": [], "limitations": []})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "id": "chatcmpl-unit-double", "object": "chat.completion",
                    "created": 1700000000, "model": "unit-double",
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant",
                                             "content": content}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                              "total_tokens": 2}}).encode("utf-8"))

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}/v1"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class _UnitSDKAgent:
    """Stand-in agent for the terminal seam: real OpenAI SDK client to the
    loopback double with a locally generated dummy key. Supplies the real
    per-request client factory + cleanup hooks ``_NonStreamRequest`` calls --
    never an ``AIAgent`` construction (that path refuses before runtime)."""

    def __init__(self, cap, base_url):
        project = cap.policy["project"]
        self.session_id = cap.session_id
        self.api_mode = "chat_completions"
        self.provider = project["provider"]
        self.model = project["model"]
        self.base_url = base_url
        self.max_iterations = 1
        self.platform = "api_server"
        self.credential_pool = None
        self._credential_pool = None
        self._current_turn_id = "t0"
        self._interrupt_requested = False
        self._consecutive_stale_streams = 0
        self.reasoning_config = None
        self.closed_request_clients = []
        # Shared client: a real SDK object, non-zero retries so the request-local
        # clone's max_retries=0 is distinguishable.
        self.client = openai.OpenAI(
            api_key="sk-unit-" + uuid.uuid4().hex, base_url=base_url,
            max_retries=2, timeout=30.0)

    # -- hooks _NonStreamRequest / the poll loop call --
    def _compute_non_stream_stale_timeout(self, api_payload):
        return float("inf")

    def _touch_activity(self, *a, **k):
        pass

    def _emit_wait_notice(self, *a, **k):
        pass

    def _buffer_diagnostic_status(self, *a, **k):
        pass

    def _emit_diagnostic_wait(self, *a, **k):
        pass

    def _client_log_context(self):
        return "[unit sdk agent]"

    def _create_request_openai_client(self, *, reason, api_kwargs=None):
        return self.client

    def _close_request_openai_client(self, client, *, reason):
        if client is not self.client:
            client.close()
            self.closed_request_clients.append(client)

    def _abort_request_openai_client(self, client, *, reason):
        self._close_request_openai_client(client, reason=reason)


def _terminal_lane(tmp_path, monkeypatch, *, fail_body=None, view_factory=None,
                   recheck=None, request_timeout_seconds=None):
    """Dispatch lane bound to a live loopback provider; real SDK stand-in agent
    installed through install_bounded_agent_policy; only ``resolve_source`` is
    mocked to the supplied resolved unit double.

    ``view_factory``/``recheck`` extend the shared fixture IN THIS FILE ONLY:
    a real native-receipt unit view and a labelled C1 callback double.
    """
    provider = _LoopbackProvider(fail_body=fail_body)
    lane = None
    try:
        lane_kw = {} if view_factory is None else {"view_factory": view_factory}
        if request_timeout_seconds is not None:
            lane_kw["request_timeout_seconds"] = request_timeout_seconds
        lane = b2b_unit_fixtures.build_b2b_dispatch_lane(
            tmp_path, provider_base_url=provider.base_url, **lane_kw)
        provider.db_path = lane.db_path
        monkeypatch.setattr(
            b2b, "resolve_source", lambda *a, **k: (lane.resolved, "ok"))
        agent = _UnitSDKAgent(lane.cap, provider.base_url)
        object.__setattr__(lane.cap, "_agent_ref", None)
        # Registered qualified context rechecker (unit double): re-qualifies the
        # same view, so recheck_context passes with an identical source_basis.
        lane.cap.register_context_recheck(
            recheck if recheck is not None else
            (lambda _cap: copy.deepcopy(lane.view)))
        token = bind_execution(lane.cap)
        try:
            install_bounded_agent_policy(agent, lane.cap)
        finally:
            reset_execution(token)
        agent._current_turn_id = lane.turn_id
        return lane, provider, agent
    except BaseException:
        if lane is not None:
            lane.store.close()
        provider.stop()
        raise


def _api_kwargs(lane):
    return {
        "model": lane.policy["project"]["model"],
        "messages": [{"role": "user", "content":
                      mission_prompt(lane.policy["mission_request"])
                      + "\n\n" + UNIT_RENDERED}]}


def test_execute_terminal_full_path_real_sdk(tmp_path, monkeypatch):
    lane, provider, agent = _terminal_lane(tmp_path, monkeypatch)
    try:
        with_options_calls = []
        orig_with_options = agent.client.with_options

        def spy_with_options(**kwargs):
            clone = orig_with_options(**kwargs)
            with_options_calls.append({"kwargs": kwargs, "clone": clone})
            return clone
        agent.client.with_options = spy_with_options

        kwargs = _api_kwargs(lane)
        expected_digest = provider_request_digest(kwargs)

        token = bind_execution(lane.cap)
        try:
            response = execute_terminal(agent, copy.deepcopy(kwargs), lane.cap,
                                        turn_id=lane.turn_id)
        finally:
            reset_execution(token)

        # Exactly one request-local clone, max_retries==0, shared client untouched.
        assert len(with_options_calls) == 1
        call = with_options_calls[0]
        assert call["kwargs"]["max_retries"] == 0
        assert call["clone"] is not agent.client
        assert call["clone"].max_retries == 0
        assert agent.client not in agent.closed_request_clients
        assert not agent.client.is_closed()

        # Exactly one POST, after a single durable CAS; headers attest the digests.
        assert len(provider.posts) == 1
        post = provider.posts[0]
        assert post["path"] == "/v1/chat/completions"
        assert post["attempt_id"] == lane.attempt_id
        assert post["request_digest"] == expected_digest
        obs = provider.db_observations[0]
        assert obs["status"] == "dispatch_committed", obs
        assert obs["provider_dispatch"] == 1 and obs["provider_result"] == 0, obs
        dispatch = lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_dispatch")
        assert json.loads(dispatch["payload"])["request_digest"] == expected_digest

        # Result validated + persisted BEFORE the response returned.
        assert lane.store.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "result_received"
        result = lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_result")
        assert result is not None
        text = json.loads(result["payload"])["text"]
        assert response.choices[0].message.content == text

        # A second terminal passage on the STILL-SUCCESSFUL attempt can never
        # re-dispatch: CAS only once, provider untouched.
        token = bind_execution(lane.cap)
        try:
            with pytest.raises(B2BTerminalRefusal) as exc:
                execute_terminal(agent, copy.deepcopy(kwargs), lane.cap,
                                 turn_id=lane.turn_id)
        finally:
            reset_execution(token)
        assert str(exc.value) == "dispatch_already_committed"
        assert len(provider.posts) == 1
        conn = sqlite3.connect(lane.db_path)
        try:
            assert conn.execute(
                "SELECT COUNT(*) FROM b2b_artifacts "
                "WHERE kind='provider_dispatch'").fetchone()[0] == 1
        finally:
            conn.close()

        # The worker-attested response revalidates; an unattested one refuses.
        token = bind_execution(lane.cap)
        try:
            validate_terminal_result(agent, response)
            forged = copy.deepcopy(response)
            forged.choices[0].message.content = json.dumps(
                {"summary": "forged", "steps": [], "source_refs": [],
                 "limitations": []})
            with pytest.raises(B2BTerminalRefusal) as exc:
                validate_terminal_result(agent, forged)
            assert str(exc.value) == "middleware_response_unattested"
        finally:
            reset_execution(token)
    finally:
        agent.client.close()
        lane.store.close()
        provider.stop()


def test_execute_terminal_provider_error_is_safe_indeterminate(
        tmp_path, monkeypatch, caplog):
    lane, provider, agent = _terminal_lane(
        tmp_path, monkeypatch,
        fail_body='{"error": "' + _SENSITIVE_MARKER + '"}')
    try:
        caplog.set_level(logging.DEBUG)
        token = bind_execution(lane.cap)
        try:
            with pytest.raises(B2BTerminalRefusal) as exc:
                execute_terminal(agent, _api_kwargs(lane), lane.cap,
                                 turn_id=lane.turn_id)
        finally:
            reset_execution(token)
        # Safe classified refusal -- never the raw provider bytes, in the
        # exception OR in anything logged while handling it.
        assert str(exc.value) == "provider_result_unavailable"
        assert _SENSITIVE_MARKER not in str(exc.value)
        assert _SENSITIVE_MARKER not in caplog.text
        # Zero SDK retries: one POST even on a 500.
        assert len(provider.posts) == 1
        # CAS committed + no durable result => indeterminate, persisted.
        lane.store.close()
        reopened = RunIdempotencyStore(str(lane.db_path))
        try:
            assert reopened.b2b_attempt(
                profile=lane.profile, attempt_id=lane.attempt_id)[
                    "status"] == "indeterminate"
            assert reopened.b2b_artifact(
                attempt_id=lane.attempt_id, kind="provider_result") is None
        finally:
            reopened.close()
    finally:
        agent.client.close()
        lane.store.close()
        provider.stop()


# ---------------------------------------------------------------------------
# C1 bounded-deadline invariants -- a context recheck must never outlive the
# signed source window it has to fit inside, and the worker boundary renews
# the before_provider exchange AFTER the final C1, immediately before the CAS.
#
# The lane is REAL (disk store, _AttemptSink, execute_terminal -> worker ->
# real SDK -> loopback provider); the C1 callback and the source envelopes are
# explicitly labelled UNIT DOUBLES.
# ---------------------------------------------------------------------------

def _resolved_with_window(lane, request_ttl_s, response_ttl_s=None):
    """The same attested unit source double, re-windowed: distinct
    ``expires_at`` per signed envelope (negative ttl => already expired), so a
    shorter response window provably drives the deadline's ``min``. Only the
    window fields differ -- identity/policy matching is untouched."""
    resolved = copy.deepcopy(lane.resolved)
    now = time.time()
    req_expires = now + request_ttl_s
    resp_expires = now + (request_ttl_s if response_ttl_s is None
                          else response_ttl_s)
    resolved["_signed_request"] = {
        "issued_at": min(now - 0.1, req_expires - 0.1), "expires_at": req_expires}
    resolved["_signed_response"] = {
        "issued_at": min(now - 0.1, resp_expires - 0.1),
        "expires_at": resp_expires}
    return resolved


def _table_dump(db_path, table):
    """Reopen the disk store file on a second connection: proof of durable
    content, not an in-memory view of the store's own connection."""
    conn = sqlite3.connect(db_path, timeout=30)
    try:
        return conn.execute(f"SELECT * FROM {table}").fetchall()
    finally:
        conn.close()


def _persisted_baseline(lane):
    return {table: _table_dump(lane.db_path, table) for table in
            ("run_idempotency", "b2b_bindings", "b2b_attempts", "b2b_artifacts")}


def _assert_zero_new_durable_rows(lane, baseline, *, expect_status):
    """The fixture starts with an ADMITTED binding+attempt+run+context already
    durable: a refusal must create ZERO new rows in run_idempotency /
    b2b_bindings / b2b_artifacts and flip ONLY the pre-existing attempt's
    status (reopened from disk). History is never deleted to look clean."""
    for table in ("run_idempotency", "b2b_bindings", "b2b_artifacts"):
        assert _table_dump(lane.db_path, table) == baseline[table], table
    attempts = _table_dump(lane.db_path, "b2b_attempts")
    assert len(attempts) == len(baseline["b2b_attempts"]) == 1
    reopened = RunIdempotencyStore(str(lane.db_path))
    try:
        row = reopened.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)
        assert row["status"] == expect_status
    finally:
        reopened.close()


@pytest.mark.parametrize("boundary", ["pre_terminal", "worker"])
def test_execute_terminal_slow_c1_refuses_source_window_closed(
        tmp_path, monkeypatch, boundary):
    """A C1 callback that outlives the signed source window must refuse
    ``source_window_closed`` BEFORE the stalled callback returns -- never an
    unbounded wait inside the context lock, never
    ``dispatch_already_committed`` -- with zero provider posts, zero new
    durable rows and no late ``_last_context_read`` mutation.

    ``pre_terminal``: the FIRST C1 (prospective ``_REQUEST_TTL_S`` window,
    shortened here so the deadline is ~0.4 s) stalls.
    ``worker``: the initial C1 is fast, the initial exchange reports a short
    signed RESPONSE window (request +10 s, response +2.5 s -- the earlier
    expiry drives the ~1.4 s C1 budget), and the SECOND C1 stalls.
    """
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    state = {"calls": 0, "cb_thread": None}

    def _recheck(_cap):
        state["calls"] += 1
        if boundary == "worker" and state["calls"] == 1:
            return copy.deepcopy(lane.view)      # initial C1: fast
        state["cb_thread"] = threading.current_thread()
        entered.set()
        try:
            release.wait(30)
            return copy.deepcopy(lane.view)
        finally:
            finished.set()

    lane, provider, agent = _terminal_lane(tmp_path, monkeypatch, recheck=_recheck)
    try:
        resolve_calls = []
        if boundary == "pre_terminal":
            # Shrink the prospective first-boundary budget ONLY (not a generic
            # timeout): TTL 1.5 s - (1 s reserve + 0.1 s slack) ~= 0.4 s.
            monkeypatch.setattr(b2b, "_REQUEST_TTL_S", 1.5)

        def _resolve(entry, keys, purpose, **kw):
            resolve_calls.append(purpose)
            return (_resolved_with_window(lane, 10.0, 2.5)
                    if boundary == "worker" else lane.resolved), "ok"
        monkeypatch.setattr(b2b, "resolve_source", _resolve)
        baseline = _persisted_baseline(lane)
        outcome = {}

        def _drive():
            token = bind_execution(lane.cap)
            try:
                outcome["response"] = execute_terminal(
                    agent, _api_kwargs(lane), lane.cap, turn_id=lane.turn_id)
            except Exception as exc:  # noqa: BLE001 -- asserted below
                outcome["error"] = exc
            finally:
                reset_execution(token)

        driver = threading.Thread(target=_drive, daemon=True)
        last_read = None
        try:
            driver.start()
            assert entered.wait(5.0), "the C1 callback never started"
            driver.join(timeout=5.0)            # outer guard: refusal << 30 s stall
            assert not driver.is_alive(), (
                "terminal did not refuse before the stalled callback returned")
            # The refusal landed while the callback is STILL blocked: pin the
            # published read before releasing anything.
            last_read = lane.cap._last_context_read
        finally:
            release.set()
            driver.join(timeout=10.0)
        # The late callback ran to completion AFTER the refusal -- its result
        # was discarded, never published.
        state["cb_thread"].join(timeout=5.0)
        assert finished.is_set() and not state["cb_thread"].is_alive()
        assert lane.cap._last_context_read is last_read
        # The classified refusal, not a mislabeled duplicate-CAS error.
        assert str(outcome.get("error")) == "source_window_closed"
        # No source renewal / CAS / provider send ever ran.
        expected = [] if boundary == "pre_terminal" else ["before_provider"]
        assert resolve_calls == expected
        assert provider.posts == []
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_dispatch") is None
        assert json_utf8(lane.cap._last_context_read) == json_utf8(lane.view)
        # A timed-out capability refuses any later boundary callback on EITHER
        # seam (fresh deadline AND the legacy direct one), without invoking it.
        expected_calls = 2 if boundary == "worker" else 1
        assert state["calls"] == expected_calls
        with pytest.raises(B2BTerminalRefusal) as retry_exc:
            recheck_context(lane.cap, lane.receipt,
                            deadline=time.monotonic() + 5.0)
        assert str(retry_exc.value) == "source_window_closed"
        with pytest.raises(B2BTerminalRefusal) as retry_exc:
            recheck_context(lane.cap, lane.receipt)
        assert str(retry_exc.value) == "source_window_closed"
        assert state["calls"] == expected_calls
        assert lane.cap._last_context_read is last_read
        assert getattr(lane.cap, "_context_recheck_timed_out", False) is True
        # The context lock was released and stays reusable.
        assert lane.cap._context_lock.acquire(timeout=1.0)
        lane.cap._context_lock.release()
        # Durable: source_denied on the pre-existing attempt; zero new rows.
        _assert_zero_new_durable_rows(lane, baseline, expect_status="source_denied")
    finally:
        agent.client.close()
        lane.store.close()
        provider.stop()


def test_execute_terminal_renews_source_after_final_c1_before_cas(
        tmp_path, monkeypatch):
    """Native /2 view through the REAL lane: C1(initial) -> resolve(initial) ->
    client build -> C1(final) -> resolve(RENEWED) -> CAS -> exactly one SDK
    call, dispatch+result persisted, the last C1 read published."""
    events = []
    views = {}
    reads = {"n": 0}
    ctx_seen = []

    def _view_factory(policy, source_body):
        # Real native-receipt UNIT DOUBLE view (ordered /2 projection).
        return build_unit_native_oc_view(policy, source_body, ordered=True)

    def _recheck(_cap):
        reads["n"] += 1
        events.append("c1")
        # The callback runs under a copied context: the bound execution /
        # profile scope must still resolve inside it.
        ctx_seen.append(
            current_execution(_cap.profile, _cap.session_id) is _cap)
        return copy.deepcopy(views[min(reads["n"], 2)])

    lane, provider, agent = _terminal_lane(
        tmp_path, monkeypatch, view_factory=_view_factory, recheck=_recheck)
    try:
        # Fresh native reads with new view_refs: never a replayed receipt.
        views[1] = renew_unit_oc_read(lane.view, read_id=2)
        views[2] = renew_unit_oc_read(lane.view, read_id=3)
        resolve_calls = []

        def _resolve(entry, keys, purpose, **kw):
            resolve_calls.append(purpose)
            events.append("resolve")
            return lane.resolved, "ok"
        monkeypatch.setattr(b2b, "resolve_source", _resolve)
        orig_cas = lane.sink.cas_dispatch

        def _cas(**kw):
            events.append("cas")
            return orig_cas(**kw)
        lane.sink.cas_dispatch = _cas
        orig_with_options = agent.client.with_options

        def _spy(**kw):
            events.append("client")
            return orig_with_options(**kw)
        agent.client.with_options = _spy

        token = bind_execution(lane.cap)
        try:
            response = execute_terminal(
                agent, _api_kwargs(lane), lane.cap, turn_id=lane.turn_id)
        finally:
            reset_execution(token)

        # The RENEWED before_provider exchange lands after the final C1 and
        # before the durable CAS; the SDK send follows the committed marker.
        assert resolve_calls == ["before_provider", "before_provider"]
        assert events == ["c1", "resolve", "client", "c1", "resolve", "cas"]
        assert len(provider.posts) == 1
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_dispatch") is not None
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_result") is not None
        assert lane.store.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "result_received"
        assert response.choices[0].message.content
        # The FINAL C1's fresh native read is the published last read.
        assert lane.cap._last_context_read[
            "operational_context"]["view"]["view_ref"] == "ocv_" + format(3, "032x")
        # Both C1 invocations ran inside the copied execution/profile context.
        assert ctx_seen == [True, True]
    finally:
        agent.client.close()
        lane.store.close()
        provider.stop()


@pytest.mark.parametrize("scenario", ["expired_envelope", "clock_advance"])
def test_execute_terminal_expired_renewal_at_cas_is_source_window_closed(
        tmp_path, monkeypatch, scenario):
    """The renewed before_provider exchange can arrive with its signed window
    already closed -- or still valid but closed by the time dispatch records
    are serialized: the sink must refuse ``source_window_closed`` at the final
    CAS check -- never the duplicate-CAS ``dispatch_already_committed`` --
    with zero SDK posts and zero new durable rows/artifacts."""
    lane, provider, agent = _terminal_lane(tmp_path, monkeypatch)
    try:
        resolve_calls = []
        renewal = {}

        def _resolve(entry, keys, purpose, **kw):
            resolve_calls.append(purpose)
            if len(resolve_calls) == 1:
                return lane.resolved, "ok"       # fresh initial exchange
            if scenario == "expired_envelope":
                return _resolved_with_window(lane, -5.0), "ok"
            renewal["resolved"] = _resolved_with_window(lane, 30.0)
            return renewal["resolved"], "ok"     # still-valid renewal
        monkeypatch.setattr(b2b, "resolve_source", _resolve)

        if scenario == "clock_advance":
            # No wall sleep: a fake clock drives the sink's time.time; the
            # dispatch-record serialization itself advances it past the renewed
            # expires_at, so a stale check-time would wrongly commit.
            fake_now = {"value": None}
            real_time = time.time
            monkeypatch.setattr(b2b, "time", types.SimpleNamespace(
                time=lambda: (fake_now["value"]
                              if fake_now["value"] is not None
                              else real_time()),
                monotonic=time.monotonic))
            orig_ju = b2b.json_utf8

            def _ju(value):
                if (isinstance(value, dict) and value.get("format")
                        == "dubsar.b2b-provider-dispatch/1"):
                    fake_now["value"] = (
                        renewal["resolved"]["_signed_request"]["expires_at"]
                        + 60.0)
                return orig_ju(value)
            monkeypatch.setattr(b2b, "json_utf8", _ju)

        baseline = _persisted_baseline(lane)
        token = bind_execution(lane.cap)
        try:
            with pytest.raises(B2BTerminalRefusal) as exc:
                execute_terminal(agent, _api_kwargs(lane), lane.cap,
                                 turn_id=lane.turn_id)
        finally:
            reset_execution(token)
        assert str(exc.value) == "source_window_closed"
        assert len(resolve_calls) == 2          # initial + renewal
        assert provider.posts == []
        for kind in ("source_before_provider", "provider_dispatch",
                     "provider_result", "proposal"):
            assert lane.store.b2b_artifact(
                attempt_id=lane.attempt_id, kind=kind) is None
        _assert_zero_new_durable_rows(lane, baseline, expect_status="source_denied")
    finally:
        agent.client.close()
        lane.store.close()
        provider.stop()


# ---------------------------------------------------------------------------
# Seal-time C1 -- the sealing seam bounds its context recheck on the same
# prospective signed window the provider-boundary checkpoints use; a blocking
# callback can never hang finalization.
# ---------------------------------------------------------------------------

def test_seal_recheck_deadline_is_prospective(b2b_dispatch_lane):
    """The seal-time C1 must fit inside the PROSPECTIVE ``before_seal``
    exchange -- never the already-spent ``before_provider`` window: with an
    EXPIRED provider exchange on the sink the seal deadline stays a full
    prospective budget where ``context_recheck_deadline`` collapses."""
    lane = b2b_dispatch_lane
    lane.sink._before_provider = _resolved_with_window(lane, -5.0)
    seal_budget = lane.sink.seal_recheck_deadline() - time.monotonic()
    provider_budget = lane.sink.context_recheck_deadline() - time.monotonic()
    prospective = (b2b._REQUEST_TTL_S
                   - (b2b._SOURCE_DEADLINE_S + b2b._CONTEXT_RECHECK_SAFETY_S))
    assert provider_budget <= 0 < seal_budget <= prospective + 0.5


def test_seal_recheck_stalled_c1_refuses_source_window_closed(
        b2b_dispatch_lane, monkeypatch):
    """A producer callback that outlives the seal-time prospective window
    refuses ``source_window_closed`` BEFORE it returns -- durable
    ``source_denied``, the late result discarded, the lock reusable, the cap
    refusing every later recheck on either seam."""
    lane = b2b_dispatch_lane
    monkeypatch.setattr(b2b, "_REQUEST_TTL_S", 1.5)
    entered, release, finished = (threading.Event() for _ in range(3))

    def _stalled(_cap):
        entered.set()
        try:
            release.wait(30)
            return copy.deepcopy(lane.view)
        finally:
            finished.set()

    lane.cap.register_context_recheck(_stalled)
    last_read = lane.cap._last_context_read
    outcome = {}

    def _drive():
        try:
            outcome["view"] = recheck_context(
                lane.cap, lane.receipt,
                deadline=lane.cap.sink.seal_recheck_deadline())
        except Exception as exc:  # noqa: BLE001 -- asserted below
            outcome["error"] = exc

    driver = threading.Thread(target=_drive, daemon=True)
    driver.start()
    try:
        assert entered.wait(5.0), "the C1 callback never started"
        driver.join(timeout=5.0)    # outer guard: refusal << 30 s stall
        assert not driver.is_alive(), (
            "seal recheck did not refuse before the stalled callback returned")
    finally:
        release.set()
        driver.join(timeout=10.0)
    # The late callback ran to completion AFTER the refusal.
    assert finished.wait(5.0)
    assert str(outcome["error"]) == "source_window_closed"
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)[
            "status"] == "source_denied"
    # The timed-out cap refuses every later boundary callback on EITHER seam.
    assert getattr(lane.cap, "_context_recheck_timed_out", False) is True
    with pytest.raises(B2BTerminalRefusal) as retry_exc:
        recheck_context(lane.cap, lane.receipt,
                        deadline=time.monotonic() + 5.0)
    assert str(retry_exc.value) == "source_window_closed"
    with pytest.raises(B2BTerminalRefusal) as retry_exc:
        recheck_context(lane.cap, lane.receipt)
    assert str(retry_exc.value) == "source_window_closed"
    assert lane.cap._last_context_read is last_read
    assert lane.cap._context_lock.acquire(timeout=1.0)
    lane.cap._context_lock.release()


@pytest.mark.asyncio
async def test_b2b_finalize_seal_recheck_is_bounded(
        b2b_dispatch_lane, monkeypatch):
    """``_b2b_finalize`` hands the seal-time C1 the sink's prospective
    deadline: a stalled producer ends the run ``failed`` with durable
    ``source_denied`` -- the sealing path can never hang on a C1 callback."""
    lane = b2b_dispatch_lane
    _commit_dispatch(lane)
    text = _proposal_text()
    parsed, reason = validate_proposal(
        text, extract_allowed_refs(lane.receipt.view))
    assert parsed is not None, reason
    lane.sink.commit_result(text=text, parsed=parsed, reason=reason)
    # The fixture adapter only carries ``_b2b_state``; the profile scope the
    # finalize path enters is a no-op here.
    lane.adapter._profile_scope = lambda profile: contextlib.nullcontext()
    monkeypatch.setattr(b2b, "_REQUEST_TTL_S", 1.5)
    entered, release = threading.Event(), threading.Event()

    def _stalled(_cap):
        entered.set()
        release.wait(30)
        return copy.deepcopy(lane.view)

    lane.cap.register_context_recheck(_stalled)
    try:
        status, fields, extra = await asyncio.wait_for(
            bxe._b2b_finalize(
                lane.cap, {"final_response": text}, "completed", {}),
            timeout=10.0)
        assert entered.is_set(), "the C1 callback never started"
        assert status == "failed" and fields["error"] == "source_window_closed"
        assert extra is None
        assert lane.store.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "source_denied"
    finally:
        release.set()


# ---------------------------------------------------------------------------
# Post-CAS budget overrun -- the dispatch gate sits BEFORE the committed CAS;
# once cas_dispatch commits there is NO voluntary abort: a run budget spent BY
# the CAS itself must not stop the send (a bounded overrun, never an invented
# retry) -- durable result_received, then the real seal path.
#
# Converted from the pass-4 post-CAS-window witness: real _AttemptSink, real
# disk store, real worker, real SDK -> loopback double. Only
# ``agent.chat_completion_helpers.time`` is the controllable _FakeClock; the
# sink's signed-window checks, the store and the source rechecks keep real
# clocks, exactly like production.
# ---------------------------------------------------------------------------

RUN_BUDGET_S = 10.0
CAS_COST_S = 11.0


def test_b2b_post_cas_budget_overrun_still_sends_and_seals(
        tmp_path, monkeypatch):
    """A run budget still positive at the pre-CAS gate but spent BY the CAS
    itself leaves the send committed: one real POST, worker response with no
    error, durable ``provider_result``/``result_received`` (never
    ``indeterminate``), then ``_b2b_finalize``/``seal`` produce the proposal.
    The send arms the full policy ``request_timeout_seconds`` (600) -- no
    run-budget clamp past the gate."""
    lane, provider, agent = _terminal_lane(
        tmp_path, monkeypatch, request_timeout_seconds=600)
    request = None
    try:
        clock = _FakeClock(time.time())
        monkeypatch.setattr(h, "time", clock)
        agent.run_budget_seconds = RUN_BUDGET_S
        agent._run_budget_started_at = clock.time()

        api_kwargs = copy.deepcopy(_api_kwargs(lane))
        request = _B2BNonStreamRequest(
            agent, api_kwargs, cap=lane.cap, receipt=lane.receipt,
            request_digest=provider_request_digest(api_kwargs))
        # Armed AT construction from the remaining run budget alone.
        init_stale_timeout = request.wd.stale_timeout

        evidence = {"pre_cas_remaining": None, "committed_status": None,
                    "dispatch_marker_at_commit": None}
        original_cas_dispatch = lane.sink.cas_dispatch

        def cas_dispatch_witness(*, request_digest, receipt,
                                 rechecked_view=None):
            # The pre-CAS gate already passed: the budget is still positive.
            remaining = (RUN_BUDGET_S
                         - (clock.time() - agent._run_budget_started_at))
            evidence["pre_cas_remaining"] = remaining
            assert remaining > 0, remaining
            committed = original_cas_dispatch(
                request_digest=request_digest, receipt=receipt,
                rechecked_view=rechecked_view)
            assert committed is True
            evidence["committed_status"] = lane.store.b2b_attempt(
                profile=lane.profile, attempt_id=lane.attempt_id)["status"]
            evidence["dispatch_marker_at_commit"] = (
                lane.store.b2b_artifact(
                    attempt_id=lane.attempt_id,
                    kind="provider_dispatch") is not None)
            # The CAS itself (proof validation, record serialization, disk
            # CAS) consumed 11s of the 10s run budget.
            clock.advance(CAS_COST_S)
            return committed

        monkeypatch.setattr(lane.sink, "cas_dispatch", cas_dispatch_witness)

        arm_calls = []
        original_arm = request._arm_stale_window

        def arm_spy(requested_timeout):
            window = original_arm(requested_timeout)
            arm_calls.append({
                "requested": requested_timeout, "now": clock.time(),
                "window": window, "stale_timeout": request.wd.stale_timeout})
            return window

        monkeypatch.setattr(request, "_arm_stale_window", arm_spy)

        token = bind_execution(lane.cap)
        try:
            request._call()
        finally:
            reset_execution(token)

        # The pre-CAS gate passed with the full budget; the real CAS committed
        # durably before the budget ran out INSIDE it.
        assert evidence["pre_cas_remaining"] == RUN_BUDGET_S
        assert evidence["committed_status"] == "dispatch_committed"
        assert evidence["dispatch_marker_at_commit"] is True

        # The send still ran: exactly one POST, worker response, no error,
        # durable provider_result / result_received -- never indeterminate.
        assert len(provider.posts) == 1
        obs = provider.db_observations[0]
        assert obs["status"] == "dispatch_committed", obs
        assert request.result["error"] is None
        assert request.result["response"] is not None
        assert lane.store.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "result_received"
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_result") is not None

        # Armed-window detail: the init arm was the remaining run budget
        # alone (10); the send arm is the full policy window (600) with NO
        # run-budget clamp -- raw deadline = the 11s preparation elapsed
        # (spent inside the CAS) + 600.
        assert init_stale_timeout == RUN_BUDGET_S
        assert arm_calls[-1]["requested"] == 600.0
        assert arm_calls[-1]["window"] == 600.0
        assert arm_calls[-1]["stale_timeout"] == CAS_COST_S + 600.0

        # The real finalize/seal path: attested result -> sealed proposal.
        lane.adapter._profile_scope = (
            lambda profile: contextlib.nullcontext())

        async def _seal_resolve(*a, **k):
            return lane.resolved, "ok"
        monkeypatch.setattr(b2b, "_resolve_source_async", _seal_resolve)
        text = request.result["response"].choices[0].message.content
        status, fields, extra = asyncio.run(bxe._b2b_finalize(
            lane.cap, {"final_response": text}, "completed", {}))
        assert status == "completed" and fields["completed"] is True
        assert extra["b2b"]["state"] == "prepared"
        assert lane.store.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "proposal_ready"
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="proposal") is not None
    finally:
        if request is not None:
            request.clients.close_once("post_cas_witness_teardown")
        agent.client.close()
        lane.store.close()
        provider.stop()
