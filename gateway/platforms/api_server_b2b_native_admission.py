"""N4 native admission producer (opt-in, strictly additive).

Scribe-backend #131 is the consumer and verifies exactly one shape:

- ``backend/control_plane_g1/b2b_n4_config.py:79-110`` — the 9-key binding.
- ``backend/control_plane_g1/b2b_n4_config.py:184-192`` — the dataset.
- ``deploy/control-plane-g2/approval.g2.n4.template.json`` — the operator
  approval the Core seals.

Hermes is only the producer: it emits the mission-bound binding it just
admitted, with ``authorized: false``. Only the Core/operator may seal
``authorized: true`` and supply ``classification`` from its approval
template; Hermes never writes either value because the signed source does
not provide one. Hermes never writes ``model_route`` or ``ports``.
Emission happens after the existing recipe-lane run was admitted, so a
refusal here never changes that run. One file per attempt, published once
atomically without overwriting an existing admission.
"""

from __future__ import annotations

import errno
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from agent.b2b_execution import canonical_json
from gateway.platforms.api_server_b2b import _SHA256_FIELD

ADMISSION_SCHEMA = "dubsar.g2-n4-native-admission/1"
APPROVAL_SCHEMA = "dubsar.g2-n4-approval/1"

_ID = re.compile(r"^[A-Za-z0-9._:-]{2,128}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROJECT = re.compile(r"^prj_[0-9a-f]{32}$")
_MISSION = re.compile(r"^mis_[0-9a-f]{32}$")
_ATTEMPT = re.compile(r"^b2bp_[0-9a-f]{64}$")
_PIECE = re.compile(r"^dubsar:piece:(mis_[0-9a-f]{32}):piece_[0-9a-f]{32}$")

_BINDING_KEYS = frozenset({
    "tenant_id", "project_id", "mission_id", "mission_revision", "profile",
    "session_id", "attempt_id", "binding_digest", "documents"})
_NATIVE_BINDING_KEYS = frozenset({
    "tenant_id", "project_id", "mission_id", "mission_revision", "profile",
    "session_id", "attempt_id", "binding_digest", "requester_id",
    "mission_inputs"})
_POINTER_KEYS = frozenset({"inputs_revision", "manifest_digest", "inputs_digest"})
_STANZA_KEYS = frozenset({"dataset_id"})


class NativeAdmissionRefusal(Exception):
    """Typed refusal; ``code`` is the explicit reason no admission was written."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(code: str) -> None:
    raise NativeAdmissionRefusal(code)


def _mapping(value: Any, keys: frozenset, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value.keys()) != keys:
        _refuse(code)
    return value


def _matches(value: Any, pattern: re.Pattern) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _documents(preparation: Any, mission_id: str) -> list:
    raw = getattr(preparation, "documents", None)
    if not isinstance(raw, (list, tuple)) or not 1 <= len(raw) <= 20:
        _refuse("n4_documents_invalid")
    assert isinstance(raw, (list, tuple))
    documents = []
    refs = set()
    for item in raw:
        if not isinstance(item, Mapping):
            _refuse("n4_documents_invalid")
        ref = item.get("native_ref")
        digest = item.get("native_digest")
        if (not _matches(ref, _PIECE)
                or ref.split(":")[2] != mission_id
                or ref in refs
                or type(item.get("revision")) is not int
                or item.get("revision") != 1
                or not _matches(digest, _SHA256)):
            _refuse("n4_documents_invalid")
        refs.add(ref)
        documents.append({"native_ref": ref, "revision": 1, "digest": digest})
    return documents


def _source_binding(native_binding: Any) -> Mapping[str, Any]:
    if native_binding is None:
        _refuse("n4_mission_unbound")
    if not isinstance(native_binding, Mapping) or set(native_binding.keys()) != _NATIVE_BINDING_KEYS:
        _refuse("n4_binding_invalid")
    pointer = native_binding["mission_inputs"]
    if not isinstance(pointer, Mapping) or set(pointer.keys()) != _POINTER_KEYS:
        _refuse("n4_binding_invalid")
    if (type(pointer.get("inputs_revision")) is not int
            or pointer["inputs_revision"] < 1
            or not _matches(pointer.get("manifest_digest"), _SHA256)
            or not _matches(pointer.get("inputs_digest"), _SHA256)):
        _refuse("n4_binding_invalid")
    return native_binding


def _binding(*, native_binding: Mapping[str, Any], resolved: Mapping[str, Any],
             preparation: Any, session_id: str, attempt_id: str,
             binding_digest: str, profile: str, configured_tenant: str) -> Dict[str, Any]:
    mission_id = resolved.get("mission_id")
    if (not isinstance(mission_id, str) or not _matches(mission_id, _MISSION)
            or mission_id != native_binding["mission_id"]):
        _refuse("n4_mission_foreign")
    assert isinstance(mission_id, str)
    if (native_binding["project_id"] != resolved.get("project_id")
            or native_binding["mission_revision"] != resolved.get("mission_revision")):
        _refuse("n4_mission_foreign")
    if native_binding["requester_id"] != resolved.get("requester_id"):
        _refuse("n4_binding_invalid")
    if (not _matches(native_binding["tenant_id"], _ID)
            or native_binding["tenant_id"] != configured_tenant
            or not _matches(native_binding["project_id"], _PROJECT)
            or type(native_binding["mission_revision"]) is not int
            or not 1 <= native_binding["mission_revision"] <= 2**53 - 1
            or native_binding["profile"] != "deploy" or profile != "deploy"
            or not _matches(binding_digest, _HEX64)
            or native_binding["binding_digest"] != binding_digest
            or session_id != "b2b_" + binding_digest
            or native_binding["session_id"] != session_id
            or not _matches(attempt_id, _ATTEMPT)
            or native_binding["attempt_id"] != attempt_id):
        _refuse("n4_binding_invalid")
    binding = {
        "tenant_id": native_binding["tenant_id"],
        "project_id": native_binding["project_id"],
        "mission_id": native_binding["mission_id"],
        "mission_revision": native_binding["mission_revision"],
        "profile": "deploy",
        "session_id": session_id,
        "attempt_id": attempt_id,
        "binding_digest": binding_digest,
        "documents": _documents(preparation, mission_id)}
    _mapping(binding, _BINDING_KEYS, "n4_binding_invalid")
    return binding


def _dataset(stanza: Mapping[str, Any], messages_digest: Any) -> Dict[str, Any]:
    _mapping(stanza, _STANZA_KEYS, "n4_dataset_invalid")
    dataset_id = stanza["dataset_id"]
    if not _matches(dataset_id, _ID):
        _refuse("n4_dataset_invalid")
    if not _matches(messages_digest, _HEX64):
        _refuse("n4_documents_invalid")
    return {"dataset_id": dataset_id, "authorized": False,
            "messages_digest": messages_digest}


def _admission(*, stanza: Mapping[str, Any], native_binding: Any,
               resolved: Mapping[str, Any], preparation: Any,
               messages_digest: Any, session_id: str, attempt_id: str,
               binding_digest: str, profile: str,
               configured_tenant: str) -> Dict[str, Any]:
    if not _matches(attempt_id, _ATTEMPT):
        _refuse("n4_binding_invalid")
    source = _source_binding(native_binding)
    binding = _binding(
        native_binding=source, resolved=resolved, preparation=preparation,
        session_id=session_id, attempt_id=attempt_id,
        binding_digest=binding_digest, profile=profile,
        configured_tenant=configured_tenant)
    dataset = _dataset(stanza, messages_digest)
    request_digest = resolved.get("request_digest")
    mission_source_digest = resolved.get("mission_source_digest")
    if (not _matches(request_digest, _SHA256_FIELD)
            or not _matches(mission_source_digest, _SHA256_FIELD)):
        _refuse("n4_binding_invalid")
    return {"schema": ADMISSION_SCHEMA, "approval_schema": APPROVAL_SCHEMA,
            "binding": binding, "dataset": dataset,
            "request_digest": request_digest,
            "mission_source_digest": mission_source_digest}


def _owned_by_euid(info: os.stat_result) -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and info.st_uid == geteuid()


def _directory(home: Path) -> Path:
    home = Path(home)
    for parent in (home, home / "b2b"):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            _refuse("n4_admission_unavailable")
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or not _owned_by_euid(info) or info.st_mode & 0o022):
            _refuse("n4_admission_unavailable")
    directory = home / "b2b" / "n4-admissions"
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.lstat()
    except OSError:
        _refuse("n4_admission_unavailable")
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or not _owned_by_euid(info) or info.st_mode & 0o077):
        _refuse("n4_admission_unavailable")
    return directory


def _unlink_quiet(name: str, dir_fd: int) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass


def _write(directory: Path, attempt_id: str, payload: bytes) -> None:
    name = attempt_id + ".json"
    temporary = f".{attempt_id}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        dir_fd = os.open(directory, dir_flags)
    except OSError:
        _refuse("n4_admission_unavailable")
    try:
        try:
            fd = os.open(temporary, flags, 0o640, dir_fd=dir_fd)
        except OSError:
            _refuse("n4_admission_unavailable")
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError(errno.EIO, "short write")
                view = view[written:]
            os.fsync(fd)
        except OSError:
            _unlink_quiet(temporary, dir_fd)
            _refuse("n4_admission_unavailable")
        finally:
            os.close(fd)
        try:
            os.link(temporary, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd,
                    follow_symlinks=False)
        except FileExistsError:
            _unlink_quiet(temporary, dir_fd)
            _refuse("n4_admission_consumed")
        except OSError:
            _unlink_quiet(temporary, dir_fd)
            _refuse("n4_admission_unavailable")
        _unlink_quiet(temporary, dir_fd)
        try:
            os.fsync(dir_fd)
        except OSError:
            _unlink_quiet(name, dir_fd)
            _refuse("n4_admission_unavailable")
    finally:
        os.close(dir_fd)


def emit_native_admission(*, home: Path, stanza: Mapping[str, Any],
                          native_binding: Optional[Mapping[str, Any]],
                          resolved: Mapping[str, Any], preparation: Any,
                          messages_digest: Any, session_id: str, attempt_id: str,
                          binding_digest: str, profile: str,
                          configured_tenant: str) -> Path:
    """Write the one-shot N4 admission for an already-admitted native run."""
    admission = _admission(
        stanza=stanza, native_binding=native_binding, resolved=resolved,
        preparation=preparation, messages_digest=messages_digest,
        session_id=session_id, attempt_id=attempt_id,
        binding_digest=binding_digest, profile=profile,
        configured_tenant=configured_tenant)
    directory = _directory(home)
    _write(directory, attempt_id, canonical_json(admission))
    return directory / (attempt_id + ".json")
