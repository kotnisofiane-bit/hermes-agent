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
    B2BTerminalRefusal, native_recipe_normalized_messages_digest,
    provider_attestation, validate_proposal)
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from tests.gateway import b2b_unit_fixtures
from tests.gateway.test_api_server_b2b_terminal import _commit_dispatch

PROVIDER_ID = "nvidia-nim-integrate"
ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
MODEL = "nvidia/nemotron-3-nano-30b-a3b"
CALL_ID = "n4-call-1"
REQUEST_SHA = "11" * 32
APPROVAL_SHA = "22" * 32
CONTENT_DIGEST = "33" * 32
EGRESS_DIGEST = "44" * 32


def _lane(tmp_path):
    return b2b_unit_fixtures.build_b2b_dispatch_lane(tmp_path)


def _digest(lane):
    return native_recipe_normalized_messages_digest(
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
        "content_digest": CONTENT_DIGEST, "messages_digest": _digest(lane),
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
    finally:
        lane.store.close()
