"""N4 native admission producer — contract RED/GREEN.

The consumer half is copied from Scribe-backend #131 @
9248374fb95f3965f88e19e726b2f56fcacf3d4b:

- ``backend/control_plane_g1/b2b_n4_config.py:79-110`` — ``_validate_binding``
- ``backend/control_plane_g1/b2b_n4_config.py:184-192`` — dataset approval
- ``deploy/control-plane-g2/approval.g2.n4.template.json`` — operator seals
  ``authorized: true``; Hermes emits ``false`` and never the route/ports.
"""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.b2b_execution import native_recipe_messages_digest
from gateway.platforms import api_server_b2b_native_admission as n4
from tests.gateway import test_api_server_b2b_native_n2 as n2

_ID = re.compile(r"[A-Za-z0-9._:-]{2,128}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PROFILE_ID = "deploy"
_B2B_DATA_CLASS = "public_synthetic"


def _shape(value, keys, error):
    if type(value) is not dict or value.keys() != keys:
        raise ValueError(error)
    return value


def _matches(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def _is_digest(value):
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _validate_binding(binding):
    """Copied from Scribe-backend #131 ``b2b_n4_config.py:79-110``."""
    _shape(binding, {
        "tenant_id", "project_id", "mission_id", "mission_revision", "profile",
        "session_id", "attempt_id", "binding_digest", "documents",
    }, "n4_binding_shape")
    if (
        type(binding["tenant_id"]) is not str or _ID.fullmatch(binding["tenant_id"]) is None
        or not _matches(binding["project_id"], r"prj_[0-9a-f]{32}")
        or not _matches(binding["mission_id"], r"mis_[0-9a-f]{32}")
        or type(binding["mission_revision"]) is not int
        or not 1 <= binding["mission_revision"] <= 2**53 - 1
        or binding["profile"] != _PROFILE_ID
        or not _is_digest(binding["binding_digest"])
        or binding["session_id"] != "b2b_" + binding["binding_digest"]
        or not _matches(binding["attempt_id"], r"b2bp_[0-9a-f]{64}")
    ):
        raise ValueError("n4_binding_invalid")
    documents = binding["documents"]
    if type(documents) is not list or not 1 <= len(documents) <= 20:
        raise ValueError("n4_documents_invalid")
    refs = set()
    for doc in documents:
        _shape(doc, {"native_ref", "revision", "digest"}, "n4_document_shape")
        ref = doc["native_ref"]
        if (
            not _matches(ref, rf"dubsar:piece:{binding['mission_id']}:piece_[0-9a-f]{{32}}")
            or ref in refs
            or type(doc["revision"]) is not int or doc["revision"] != 1
            or not _matches(doc["digest"], r"sha256:[0-9a-f]{64}")
        ):
            raise ValueError("n4_document_invalid")
        refs.add(ref)
    return binding


def _validate_dataset(dataset):
    """Copied from Scribe-backend #131 ``b2b_n4_config.py:184-192``."""
    _shape(
        dataset, {"dataset_id", "classification", "authorized", "messages_digest"},
        "n4_dataset_shape")
    if (
        dataset["classification"] != _B2B_DATA_CLASS or dataset["authorized"] is not True
        or type(dataset["dataset_id"]) is not str or _ID.fullmatch(dataset["dataset_id"]) is None
        or not _is_digest(dataset["messages_digest"])
    ):
        raise ValueError("n4_dataset_not_approved")
    return dataset


def _consume(admission, *, request_digest, attempt_id):
    """The consumer: #131 predicates plus the replay correlation it requires."""
    assert type(admission) is dict
    assert set(admission) == {
        "schema", "approval_schema", "binding", "dataset",
        "request_digest", "mission_source_digest"}
    assert admission["schema"] == n4.ADMISSION_SCHEMA
    assert admission["approval_schema"] == n4.APPROVAL_SCHEMA
    _validate_binding(admission["binding"])
    sealed = json.loads(json.dumps(admission["dataset"]))
    assert sealed["authorized"] is False
    sealed["authorized"] = True
    _validate_dataset(sealed)
    if admission["request_digest"] != request_digest:
        raise ValueError("n4_admission_request_mismatch")
    if admission["binding"]["attempt_id"] != attempt_id:
        raise ValueError("n4_admission_attempt_mismatch")
    return admission


def _unit():
    request = {"request_id": "req-unit", "body": {
        "attempt_id": n2.ATTEMPT, "profile": "deploy", "session_id": n2.SESSION}}
    body = n2._resolved_body(request)
    resolved = {key: body[key] for key in (
        "project_id", "mission_id", "mission_revision", "request_digest",
        "mission_source_digest", "requester_id", "mission_request")}
    native_binding = {key: body[key] for key in n2.m._NATIVE_BINDING_KEYS}
    preparation = SimpleNamespace(documents=n2._docs(), rendered=b"unit-rendered")
    digest = native_recipe_messages_digest(
        resolved["mission_request"], preparation.rendered)
    return resolved, native_binding, preparation, digest


_UNSET = object()


def _emit(tmp_path, *, resolved=_UNSET, native_binding=_UNSET,
          preparation=_UNSET, messages_digest=_UNSET, stanza=_UNSET, **over):
    unit_resolved, unit_binding, unit_prepared, unit_digest = _unit()
    kwargs = {
        "home": tmp_path, "stanza": {"dataset_id": "unit-n4-dataset"},
        "native_binding": unit_binding, "resolved": unit_resolved,
        "preparation": unit_prepared, "messages_digest": unit_digest,
        "session_id": n2.SESSION, "attempt_id": n2.ATTEMPT,
        "binding_digest": n2.BINDING, "profile": "deploy",
        "configured_tenant": n2.TENANT}
    for key, value in {
            "resolved": resolved, "native_binding": native_binding,
            "preparation": preparation, "messages_digest": messages_digest,
            "stanza": stanza}.items():
        if value is not _UNSET:
            kwargs[key] = value
    kwargs.update(over)
    return n4.emit_native_admission(**kwargs)


def _path(tmp_path):
    return tmp_path / "b2b" / "n4-admissions" / (n2.ATTEMPT + ".json")


def test_config_native_n4_requires_native_n2():
    project = n2._project_entry(native=False, native_n4={"dataset_id": "unit-native-n4"})
    with pytest.raises(n2.m.B2BConfigError):
        n2.m.B2BConfig(n2._raw_config(projects={n2.PROJECT: project}))


@pytest.mark.parametrize("stanza", [
    None, [], {}, {"dataset_id": "bad id"}, {"dataset_id": "unit-native-n4", "extra": 1},
    {"dataset_id": 1}, {"dataset_id": "x"}])
def test_config_native_n4_is_closed(stanza):
    project = n2._project_entry()
    project["native_n4"] = stanza
    with pytest.raises(n2.m.B2BConfigError):
        n2.m.B2BConfig(n2._raw_config(projects={n2.PROJECT: project}))


def test_config_native_n4_parses_closed_stanza():
    project = n2._project_entry(native_n4={"dataset_id": "unit-native-n4"})
    config = n2.m.B2BConfig(n2._raw_config(projects={n2.PROJECT: project}))
    entry = config.profiles["deploy"]["projects"][n2.PROJECT]
    assert entry["native_n4"] == {"dataset_id": "unit-native-n4"}


def test_emission_is_mission_bound_and_consumer_accepts(tmp_path):
    path = _emit(tmp_path)
    assert path == _path(tmp_path)
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    admission = json.loads(path.read_text(encoding="utf-8"))
    assert admission["binding"]["project_id"] == n2.PROJECT
    assert admission["binding"]["mission_id"] == n2.MISSION
    assert admission["binding"]["session_id"] == n2.SESSION
    assert admission["binding"]["attempt_id"] == n2.ATTEMPT
    assert admission["binding"]["documents"] == [
        {"native_ref": document["native_ref"], "revision": 1,
         "digest": document["native_digest"]}
        for document in n2._docs()]
    assert admission["dataset"] == {
        "dataset_id": "unit-n4-dataset",
        "classification": "public_synthetic",
        "authorized": False,
        "messages_digest": _unit()[3]}
    _consume(admission, request_digest=admission["request_digest"],
             attempt_id=n2.ATTEMPT)


def test_emission_is_one_shot(tmp_path):
    path = _emit(tmp_path)
    before = path.read_bytes()
    with pytest.raises(n4.NativeAdmissionRefusal, match="^n4_admission_consumed$"):
        _emit(tmp_path)
    assert path.read_bytes() == before
    assert [entry.name for entry in path.parent.iterdir()] == [path.name]


def test_unbound_mission_writes_nothing(tmp_path):
    with pytest.raises(n4.NativeAdmissionRefusal, match="^n4_mission_unbound$"):
        _emit(tmp_path, native_binding=None)
    assert not _path(tmp_path).exists()


def test_foreign_mission_writes_nothing(tmp_path):
    resolved, _, _, _ = _unit()
    foreign = dict(resolved, mission_id="mis_" + "c" * 32)
    with pytest.raises(n4.NativeAdmissionRefusal, match="^n4_mission_foreign$"):
        _emit(tmp_path, resolved=foreign)
    assert not _path(tmp_path).exists()


def test_falsified_binding_writes_nothing(tmp_path):
    _, binding, _, _ = _unit()
    forged = dict(binding, tenant_id="tenant-bravo")
    with pytest.raises(n4.NativeAdmissionRefusal, match="^n4_binding_invalid$"):
        _emit(tmp_path, native_binding=forged)
    assert not _path(tmp_path).exists()


def test_bad_documents_write_nothing(tmp_path):
    with pytest.raises(n4.NativeAdmissionRefusal, match="^n4_documents_invalid$"):
        _emit(tmp_path, preparation=SimpleNamespace(documents=(), rendered=b"x"))
    assert not _path(tmp_path).exists()


def test_bad_dataset_writes_nothing(tmp_path):
    with pytest.raises(n4.NativeAdmissionRefusal, match="^n4_dataset_invalid$"):
        _emit(tmp_path, stanza={"dataset_id": "bad id"})
    assert not _path(tmp_path).exists()


def test_unavailable_store_writes_nothing(tmp_path):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="ascii")
    with pytest.raises(n4.NativeAdmissionRefusal, match="^n4_admission_unavailable$"):
        _emit(blocker)
    assert not (blocker / "b2b").exists()


def test_admission_cannot_be_replayed_for_another_request(tmp_path):
    path = _emit(tmp_path)
    admission = json.loads(path.read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="^n4_admission_request_mismatch$"):
        _consume(admission, request_digest="99" * 32, attempt_id=n2.ATTEMPT)
    with pytest.raises(ValueError, match="^n4_admission_attempt_mismatch$"):
        _consume(admission, request_digest=admission["request_digest"],
                 attempt_id=n2.m._attempt_id_for("f" * 64))


@pytest.mark.asyncio
@pytest.mark.skipif(
    not n2._NATIVE_IO_AVAILABLE, reason="Linux O_NOFOLLOW fixture required")
async def test_native_http_without_stanza_writes_no_admission(tmp_path, monkeypatch):
    from hermes_constants import get_hermes_home

    await n2.test_native_http_prepare_admission_replay_and_revocation(
        tmp_path, monkeypatch, None, "valid")
    home = Path(get_hermes_home())
    assert not (home / "b2b" / "n4-admissions").exists()


@pytest.mark.asyncio
@pytest.mark.skipif(
    not n2._NATIVE_IO_AVAILABLE, reason="Linux O_NOFOLLOW fixture required")
async def test_native_http_n4_admission_is_emitted_once(tmp_path, monkeypatch):
    from hermes_constants import get_hermes_home

    await n2.test_native_http_prepare_admission_replay_and_revocation(
        tmp_path, monkeypatch, None, "valid", native_n4="unit-native-n4")
    path = Path(get_hermes_home()) / "b2b" / "n4-admissions" / (n2.ATTEMPT + ".json")
    assert path.exists()
    admission = json.loads(path.read_text(encoding="utf-8"))
    assert admission["dataset"]["dataset_id"] == "unit-native-n4"
    assert admission["binding"]["attempt_id"] == n2.ATTEMPT
    _consume(admission, request_digest=admission["request_digest"],
             attempt_id=n2.ATTEMPT)
    assert [entry.name for entry in path.parent.iterdir()] == [path.name]
