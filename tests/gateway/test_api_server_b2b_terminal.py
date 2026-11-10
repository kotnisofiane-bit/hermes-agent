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

import copy
import http.server
import json
import logging
import sqlite3
import threading
import uuid

import openai
import pytest

from agent.b2b_execution import (
    B2BTerminalRefusal, bind_execution, execute_terminal, extract_allowed_refs,
    install_bounded_agent_policy, json_utf8, mission_prompt,
    provider_request_digest, reset_execution, validate_proposal,
    validate_terminal_result,
)
from gateway.platforms import api_server_b2b as b2b
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from tests.gateway import b2b_unit_fixtures
from tests.gateway.b2b_process_harness import UNIT_RENDERED, renew_unit_oc_read


@pytest.fixture
def b2b_dispatch_lane(tmp_path):
    lane = b2b_unit_fixtures.build_b2b_dispatch_lane(tmp_path)
    try:
        yield lane
    finally:
        lane.store.close()


# ---------------------------------------------------------------------------
# _AttemptSink.block -- explicit reason -> durable status table
# ---------------------------------------------------------------------------

_CONTEXT_STALE_REASONS = [
    "context_schema_invalid", "context_contract_unavailable",
    "context_digest_invalid", "context_identity_source",
    "context_identity_mismatch", "context_catalogue_mismatch",
    "context_authority_mismatch", "context_selection_mismatch",
    "context_namespaces", "context_source_unavailable", "context_source_stale",
    "context_my_work_mismatch", "context_my_work_authority",
    "context_memory_unqualified", "context_memory_namespace",
    "context_memory_provenance", "context_memory_mission",
    "context_contradictions", "context_oc_malformed", "context_oc_mismatch",
    "context_oc_unavailable", "context_accepted_unavailable",
    "context_accepted_malformed", "context_accepted_unqualified",
    "context_support_unqualified", "context_relation_bounds",
    "context_view_bounds", "context_view_not_object",
    "context_recheck_unavailable", "context_recheck_already_registered",
    "context_render_bounds", "context_rendered_type",
    "context_rendered_encoding", "context_too_large", "context_turn_id",
    "context_turn_mismatch", "context_publication_conflict",
    "context_absent_from_kwargs", "context_changed_before_sdk",
    "context_stale",
]

_POLICY_CHANGED_REASONS = [
    "b2b_capability_mismatch", "b2b_capability_missing",
    "b2b_agent_binding_missing", "b2b_agent_binding_mismatch",
    "b2b_profile_mismatch", "b2b_policy_override", "b2b_policy_changed",
    "b2b_runtime_mismatch", "b2b_runtime_policy", "b2b_destination_mismatch",
    "b2b_model_mismatch", "b2b_alternate_provider", "b2b_alternate_api_call",
    "b2b_sdk_override", "b2b_sdk_headers", "b2b_client_policy",
    "b2b_retries_not_disabled", "b2b_request_client_not_isolated",
    "terminal_guard_required", "kwargs_not_permitted",
]

_SOURCE_DENIED_REASONS = [
    "source_before_provider_denied", "source_before_seal_denied",
    "source_window_closed",
]

_RESULT_INVALID_REASONS = ["result_invalid", "proposal_invalid",
                           "response_not_public"]

_FAILED_REASONS = [
    # policy_provider_unavailable once classified as policy_changed purely
    # because its name contains "policy".
    "policy_provider_unavailable",
    # NO-RECEIPT conditions default failed pre-CAS (post-CAS -> indeterminate).
    "result_unattested", "middleware_response_unattested",
    "provider_result_unavailable",
    # Commit/seal storage failures and launch/run failures.
    "result_commit_failed", "context_commit_failed", "seal_commit_failed",
    "seal_unattested", "launch_failed", "native_run_interrupted",
    "b2b_run_failed", "sink_missing", "dispatch_already_committed",
    "request_changed_before_sdk",
    # Arbitrary exception text must never be mined for a classification.
    "sqlite3.OperationalError: no such context table",
    "RuntimeError: policy file missing",
    "TimeoutError: source read exceeded deadline",
    "ValueError: result could not decode",
]


@pytest.mark.parametrize(
    ("reason", "expected"),
    ([(r, "context_stale") for r in _CONTEXT_STALE_REASONS]
     + [(r, "policy_changed") for r in _POLICY_CHANGED_REASONS]
     + [(r, "source_denied") for r in _SOURCE_DENIED_REASONS]
     + [(r, "result_invalid") for r in _RESULT_INVALID_REASONS]
     + [(r, "failed") for r in _FAILED_REASONS]
     + [("context_unavailable", "context_unavailable")]))
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


@pytest.mark.parametrize("reason", _FAILED_REASONS + _CONTEXT_STALE_REASONS[:6]
                         + _POLICY_CHANGED_REASONS[:6] + _SOURCE_DENIED_REASONS
                         + ["context_unavailable"])
def test_block_after_committed_dispatch_is_indeterminate(b2b_dispatch_lane, reason):
    """CAS committed + NO durable provider result => indeterminate, whatever the
    reason -- the dispatch may have reached the provider."""
    lane = b2b_dispatch_lane
    _commit_dispatch(lane)
    lane.sink.block(reason)
    assert lane.store.b2b_attempt(
        profile=lane.profile, attempt_id=lane.attempt_id)["status"] == "indeterminate"


def test_block_after_committed_dispatch_keeps_result_invalid(b2b_dispatch_lane):
    """A proven-invalid result is a KNOWN outcome, not an unknown one: the
    indeterminate override never applies to result_invalid."""
    lane = b2b_dispatch_lane
    _commit_dispatch(lane)
    lane.sink.block("result_invalid")
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


def _terminal_lane(tmp_path, monkeypatch, *, fail_body=None):
    """Dispatch lane bound to a live loopback provider; real SDK stand-in agent
    installed through install_bounded_agent_policy; only ``resolve_source`` is
    mocked to the supplied resolved unit double."""
    provider = _LoopbackProvider(fail_body=fail_body)
    lane = None
    try:
        lane = b2b_unit_fixtures.build_b2b_dispatch_lane(
            tmp_path, provider_base_url=provider.base_url)
        provider.db_path = lane.db_path
        monkeypatch.setattr(
            b2b, "resolve_source", lambda *a, **k: (lane.resolved, "ok"))
        agent = _UnitSDKAgent(lane.cap, provider.base_url)
        object.__setattr__(lane.cap, "_agent_ref", None)
        # Registered qualified context rechecker (unit double): re-qualifies the
        # same view, so recheck_context passes with an identical source_basis.
        lane.cap.register_context_recheck(lambda _cap: copy.deepcopy(lane.view))
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
