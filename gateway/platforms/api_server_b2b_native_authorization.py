"""Protected native B2B run-authorization manifest reader."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

_NATIVE_SECURITY_UID = 32013
_NATIVE_TRUSTED_ROOT = "/"
_NATIVE_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
_NATIVE_MANIFEST_MAX = 65536
_NATIVE_MANIFEST_FORMAT = "dubsar.b2b-n2-recipe/1"
_NATIVE_MANIFEST_CLASS = "public_synthetic"
_NATIVE_MANIFEST_KEYS = frozenset({
    "format", "boot_id", "classification", "dataset_id", "binding",
    "request_digest", "mission_source_digest", "messages_digest",
})
_DATASET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")


def _boot_id() -> str:
    try:
        return _NATIVE_BOOT_ID_PATH.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return ""


def _native_parents_safe(path: str) -> bool:
    """Every ancestor directory: a real dir, owned by root or the security uid,
    never group/world writable."""
    root = _NATIVE_TRUSTED_ROOT
    try:
        if os.path.commonpath((path, root)) != root:
            return False
    except ValueError:
        return False
    if path == root:
        return False
    current = os.path.dirname(path)
    while True:
        if root == os.path.sep and current == root:
            return True
        try:
            info = os.lstat(current)
        except OSError:
            return False
        if (not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in (0, _NATIVE_SECURITY_UID)
                or stat.S_IMODE(info.st_mode) & 0o022):
            return False
        if current == root:
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def _read_native_run_authorization(ref: Any) -> Optional[Dict[str, Any]]:
    """Protected manifest read — same discipline as the Portal installation
    record: canonical path, safe parents, O_NOFOLLOW, security-owned 0640
    nlink=1 regular file, byte-pinned sha256, current-boot JSON record.
    Returns the closed eight-key manifest or ``None`` (fail closed)."""
    from .api_server_b2b import (
        _ATTEMPT_ID_RE,
        _HEX64,
        _MISSION_ID,
        _NATIVE_BINDING_KEYS,
        _NATIVE_PROJECT_ID,
        _NATIVE_TENANT_ID,
        _OBJECT_ID,
        _POINTER_KEYS,
        _SESSION_ID_RE,
        _SHA256_FIELD,
        _SHA256_PREFIXED,
        _strict_json_loads,
    )

    if not isinstance(ref, Mapping) or set(ref) != {"path", "sha256"}:
        return None
    path, pinned = ref.get("path"), ref.get("sha256")
    if (not isinstance(path, str) or not path or "\x00" in path
            or os.path.abspath(path) != path
            or not isinstance(pinned, str) or _HEX64.fullmatch(pinned) is None
            or not _native_parents_safe(path)):
        return None
    boot_id = _boot_id()
    if not boot_id:
        return None
    try:
        with os.fdopen(
                os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o640
                    or info.st_uid != _NATIVE_SECURITY_UID or info.st_nlink != 1
                    or info.st_size > _NATIVE_MANIFEST_MAX):
                return None
            data = stream.read(_NATIVE_MANIFEST_MAX + 1)
    except OSError:
        return None
    if (len(data) > _NATIVE_MANIFEST_MAX
            or hashlib.sha256(data).hexdigest() != pinned):
        return None
    try:
        record = _strict_json_loads(data)
    except (ValueError, RecursionError):
        return None
    binding = record.get("binding") if isinstance(record, Mapping) else None
    pointer = binding.get("mission_inputs") if isinstance(binding, Mapping) else None
    if (not isinstance(record, Mapping) or set(record) != _NATIVE_MANIFEST_KEYS
            or record.get("format") != _NATIVE_MANIFEST_FORMAT
            or record.get("boot_id") != boot_id
            or record.get("classification") != _NATIVE_MANIFEST_CLASS
            or not isinstance(record.get("dataset_id"), str)
            or _DATASET_ID.fullmatch(record["dataset_id"]) is None
            or not isinstance(binding, Mapping)
            or set(binding) != set(_NATIVE_BINDING_KEYS)
            or type(binding.get("mission_revision")) is not int
            or not 1 <= binding["mission_revision"] <= 2**53 - 1
            or any(type(binding.get(key)) is not str for key in (
                "tenant_id", "project_id", "mission_id", "profile", "session_id",
                "attempt_id", "binding_digest", "requester_id"))
            or _NATIVE_TENANT_ID.fullmatch(binding["tenant_id"]) is None
            or _NATIVE_PROJECT_ID.fullmatch(binding["project_id"]) is None
            or _MISSION_ID.fullmatch(binding["mission_id"]) is None
            or binding["profile"] != "deploy"
            or _SESSION_ID_RE.fullmatch(binding["session_id"]) is None
            or _ATTEMPT_ID_RE.fullmatch(binding["attempt_id"]) is None
            or _HEX64.fullmatch(binding["binding_digest"]) is None
            or _OBJECT_ID.fullmatch(binding["requester_id"]) is None
            or not isinstance(pointer, Mapping)
            or set(pointer) != _POINTER_KEYS
            or type(pointer.get("inputs_revision")) is not int
            or not 1 <= pointer["inputs_revision"] <= 2**53 - 1
            or type(pointer.get("manifest_digest")) is not str
            or _SHA256_PREFIXED.fullmatch(pointer["manifest_digest"]) is None
            or type(pointer.get("inputs_digest")) is not str
            or _SHA256_PREFIXED.fullmatch(pointer["inputs_digest"]) is None
            or type(record.get("request_digest")) is not str
            or _SHA256_FIELD.fullmatch(record["request_digest"]) is None
            or type(record.get("mission_source_digest")) is not str
            or _SHA256_FIELD.fullmatch(record["mission_source_digest"]) is None
            or type(record.get("messages_digest")) is not str
            or _HEX64.fullmatch(record["messages_digest"]) is None):
        return None
    return dict(record)
