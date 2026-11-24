"""N4 provider attestation — verify and persist the gateway's provenance.

RED first: Hermes used to discard ``dubsar_provenance`` and
``dubsar_receipt_ref``. The durable result must carry both, bound to this
attempt's normalized messages digest, and a partial or foreign attestation is
``result_unattested`` — never silently dropped.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agent.b2b_execution import (
    B2BTerminalRefusal, native_recipe_normalized_content_digest,
    native_recipe_normalized_messages_digest, provider_attestation,
    validate_proposal)
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from tests.gateway import b2b_unit_fixtures
from tests.gateway.test_api_server_b2b_terminal import _commit_dispatch

PROVIDER_ID = "nvidia-nim-integrate"
ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
MODEL = "nvidia/nemotron-3-nano-30b-a3b"
CALL_ID = "n4-call-1"
REQUEST_SHA = "11" * 32
APPROVAL_SHA = "22" * 32
EGRESS_DIGEST = "44" * 32


def _lane(tmp_path, **over):
    return b2b_unit_fixtures.build_b2b_dispatch_lane(tmp_path, **over)


def _digest(lane):
    return native_recipe_normalized_messages_digest(
        lane.policy["mission_request"], lane.receipt.rendered)


def _content_digest(lane):
    return native_recipe_normalized_content_digest(
        lane.policy["mission_request"], lane.receipt.rendered)


def _provenance(**over):
    value = {
        "schema": "dubsar.g2-n4-provenance/1", "kind": "provider",
        "provider_id": PROVIDER_ID, "model": MODEL,
        "request_sha256": REQUEST_SHA, "approval_sha256": APPROVAL_SHA,
        "call_id": CALL_ID}
    value.update(over)
    return value


def _receipt(lane, **over):
    value = {
        "call_id": CALL_ID, "decision": "ALLOW", "reason_codes": [],
        "content_digest": _content_digest(lane), "messages_digest": _digest(lane),
        "authorized_egress_messages_digest": EGRESS_DIGEST,
        "provider_id": PROVIDER_ID, "endpoint": ENDPOINT, "model": MODEL,
        "request_sha256": REQUEST_SHA}
    value.update(over)
    return value


def _text():
    return json.dumps({
        "summary": "s", "steps": ["a"], "source_refs": [], "limitations": []})


def _commit(lane, *, provenance=None, receipt_ref=None, messages_digest=None):
    text = _text()
    parsed, reason = validate_proposal(text, ())
    assert parsed is not None
    lane.sink.commit_result(
        text=text, parsed=parsed, reason=reason,
        provenance=provenance, receipt_ref=receipt_ref,
        messages_digest=messages_digest)


def test_provider_attestation_reads_attributes_and_model_extra():
    provenance, receipt = _provenance(), {"call_id": CALL_ID}
    response = SimpleNamespace(
        dubsar_provenance=provenance, dubsar_receipt_ref=receipt)
    assert provider_attestation(response) == (provenance, receipt)
    response = SimpleNamespace(model_extra={
        "dubsar_provenance": provenance, "dubsar_receipt_ref": receipt})
    assert provider_attestation(response) == (provenance, receipt)


def test_commit_result_persists_verified_attestation(tmp_path):
    lane = _lane(tmp_path)
    try:
        _commit_dispatch(lane)
        provenance, receipt = _provenance(), _receipt(lane)
        _commit(lane, provenance=provenance, receipt_ref=receipt,
                messages_digest=_digest(lane))
        row = lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_result")
        payload = json.loads(row["payload"])
        assert payload["attempt_id"] == lane.attempt_id
        assert payload["dubsar_provenance"] == provenance
        assert payload["dubsar_receipt_ref"] == receipt
        assert lane.store.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "result_received"
    finally:
        lane.store.close()


def test_commit_result_attestation_survives_store_reopen(tmp_path):
    """Durable means after restart: a fresh store handle reads the same
    attempt-scoped provenance and receipt."""
    lane = _lane(tmp_path)
    provenance, receipt = _provenance(), _receipt(lane)
    try:
        _commit_dispatch(lane)
        _commit(lane, provenance=provenance, receipt_ref=receipt,
                messages_digest=_digest(lane))
        db_path, attempt_id = lane.db_path, lane.attempt_id
    finally:
        lane.store.close()
    reopened = RunIdempotencyStore(db_path)
    try:
        payload = json.loads(reopened.b2b_artifact(
            attempt_id=attempt_id, kind="provider_result")["payload"])
        assert payload["attempt_id"] == attempt_id
        assert payload["dubsar_provenance"] == provenance
        assert payload["dubsar_receipt_ref"] == receipt
    finally:
        reopened.close()


@pytest.mark.parametrize("which", ["provenance", "receipt", "neither"])
def test_commit_result_refuses_partial_attestation(tmp_path, which):
    lane = _lane(tmp_path)
    try:
        _commit_dispatch(lane)
        provenance = None if which in ("receipt", "neither") else _provenance()
        receipt = None if which in ("provenance", "neither") else _receipt(lane)
        with pytest.raises(B2BTerminalRefusal) as exc:
            _commit(lane, provenance=provenance, receipt_ref=receipt,
                    messages_digest=_digest(lane))
        assert str(exc.value) == "result_unattested"
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_result") is None
    finally:
        lane.store.close()


def test_native_n4_missing_attestation_is_refused(tmp_path):
    """An N4 lane may not persist a provider result with no attestation at
    all: the native project means the N4 docs are required, not optional."""
    lane = _lane(tmp_path, native_n4="unit-native-n4")
    try:
        _commit_dispatch(lane)
        with pytest.raises(B2BTerminalRefusal) as exc:
            _commit(lane)
        assert str(exc.value) == "result_unattested"
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_result") is None
        assert lane.store.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "indeterminate"
    finally:
        lane.store.close()


def test_commit_result_refuses_content_digest_not_bound_to_transcript(tmp_path):
    """The receipt content digest must cover this attempt's normalized
    transcript, exactly like Scribe's ``content_digest_from_messages``."""
    lane = _lane(tmp_path)
    try:
        _commit_dispatch(lane)
        receipt = _receipt(lane, content_digest="55" * 32)
        with pytest.raises(B2BTerminalRefusal) as exc:
            _commit(lane, provenance=_provenance(), receipt_ref=receipt,
                    messages_digest=_digest(lane))
        assert str(exc.value) == "result_unattested"
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_result") is None
    finally:
        lane.store.close()


def test_commit_result_refuses_worker_messages_digest_mismatch(tmp_path):
    """The worker computes the normalized digest; a mismatch with the receipt
    is refused before either document is persisted."""
    lane = _lane(tmp_path)
    try:
        _commit_dispatch(lane)
        with pytest.raises(B2BTerminalRefusal) as exc:
            _commit(lane, provenance=_provenance(), receipt_ref=_receipt(lane),
                    messages_digest="55" * 32)
        assert str(exc.value) == "result_unattested"
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_result") is None
    finally:
        lane.store.close()


def test_worker_refuses_unattested_when_transcript_cannot_normalize():
    """The worker's ValueError branch maps a non-normalizable transcript to
    ``result_unattested`` — never to a completed response."""
    from types import SimpleNamespace

    from agent.b2b_nonstream import _B2BNonStreamRequest

    blocked = []
    sink = SimpleNamespace(
        block=blocked.append, context_receipt=None)
    cap = SimpleNamespace(
        sink=sink, context_receipt=SimpleNamespace(view={}),
        proposal_refs=lambda view: ())
    response = SimpleNamespace(
        choices=[SimpleNamespace(
            finish_reason="stop",
            message=SimpleNamespace(role="assistant", content=_text()))],
        dubsar_provenance=_provenance(),
        dubsar_receipt_ref={"call_id": CALL_ID})
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kw: response)))
    req = _B2BNonStreamRequest.__new__(_B2BNonStreamRequest)
    req.agent = SimpleNamespace()
    req.api_kwargs = {"messages": [], "timeout": 1.0}
    req.result = {"response": None, "error": None}
    req.clients = SimpleNamespace(close_once=lambda reason: None)
    req.cancelled = False
    req.codex_token = None
    req.codex_retired = False
    req.codex_watchdog_state = None
    req.call_start = 0.0
    req.wd = SimpleNamespace(stale_timeout=0.0)
    req._b2b_execution = cap
    req._b2b_receipt = object()
    req._b2b_request_digest = "d" * 64
    req._make_client = lambda reason: client
    req._call()
    assert blocked == ["result_unattested"]
    assert isinstance(req.result["error"], B2BTerminalRefusal)
    assert str(req.result["error"]) == "result_unattested"
    assert req.result["response"] is None


@pytest.mark.parametrize("field,value", [
    ("call_id", "n4-call-foreign"),
    ("provider_id", "other-provider"),
    ("model", "other-model"),
    ("request_sha256", "99" * 32),
    ("messages_digest", "55" * 32),
    ("decision", "DENY"),
])
def test_commit_result_refuses_foreign_receipt(tmp_path, field, value):
    lane = _lane(tmp_path)
    try:
        _commit_dispatch(lane)
        receipt = _receipt(lane, **{field: value})
        with pytest.raises(B2BTerminalRefusal) as exc:
            _commit(lane, provenance=_provenance(), receipt_ref=receipt,
                    messages_digest=_digest(lane))
        assert str(exc.value) == "result_unattested"
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_result") is None
    finally:
        lane.store.close()


@pytest.mark.parametrize("field,value", [
    ("schema", "dubsar.g2-n4-provenance/0"),
    ("kind", "qualification"),
    ("provider_id", None),
    ("model", ""),
    ("request_sha256", "not-a-digest"),
    ("approval_sha256", "not-a-digest"),
    ("call_id", ""),
    ("refusal", "n4_provider_error"),
])
def test_commit_result_refuses_invalid_provenance(tmp_path, field, value):
    lane = _lane(tmp_path)
    try:
        _commit_dispatch(lane)
        provenance = _provenance(**{field: value})
        with pytest.raises(B2BTerminalRefusal) as exc:
            _commit(lane, provenance=provenance, receipt_ref=_receipt(lane),
                    messages_digest=_digest(lane))
        assert str(exc.value) == "result_unattested"
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind="provider_result") is None
    finally:
        lane.store.close()
