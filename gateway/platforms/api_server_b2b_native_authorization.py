"""Protected native B2B run-authorization manifest reader."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent.b2b_execution import (
    _native_oc_read_metadata, canonical_json, context_proof, native_recipe_normalized_messages_digest)

_NATIVE_SECURITY_UID = 32013
_NATIVE_TRUSTED_ROOT = "/"
_NATIVE_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
_NATIVE_MANIFEST_MAX = 65536
_CLAIM_TTL_SECONDS = 900
_NATIVE_MANIFEST_FORMAT = "dubsar.b2b-n2-recipe/1"
_NATIVE_MANIFEST_CLASS = "public_synthetic"
_NATIVE_MANIFEST_KEYS = frozenset({
    "format", "boot_id", "classification", "dataset_id", "binding",
    "request_digest", "mission_source_digest", "messages_digest",
})
_DATASET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
SCHEMA = "dubsar.core-model-authorization/1"


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


class AuthorizationRefused(ValueError):
    def __init__(self, reason):
        super().__init__("model_authorization_" + reason)


def _read_protected_bytes(path):
    """Check the descriptor we read, for both the signed envelope and its publication pin."""
    if (not isinstance(path, str) or not path or "\x00" in path
            or os.path.abspath(path) != path or not _native_parents_safe(path)):
        raise AuthorizationRefused("unprotected")
    try:
        with os.fdopen(
                os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o640
                    or info.st_uid != _NATIVE_SECURITY_UID or info.st_nlink != 1
                    or info.st_size > _NATIVE_MANIFEST_MAX):
                raise AuthorizationRefused("unprotected")
            data = stream.read(_NATIVE_MANIFEST_MAX + 1)
    except FileNotFoundError:
        raise AuthorizationRefused("missing") from None
    except OSError:
        raise AuthorizationRefused("unprotected") from None
    if len(data) > _NATIVE_MANIFEST_MAX:
        raise AuthorizationRefused("unprotected")
    return data


def _decode(data):
    from .api_server_b2b import _strict_json_loads

    try:
        return _strict_json_loads(data)
    except (ValueError, RecursionError):
        raise AuthorizationRefused("schema") from None


def _read_protected_record(ref):
    from .api_server_b2b import _HEX64

    if not isinstance(ref, Mapping) or set(ref) != {"path", "sha256"}:
        raise AuthorizationRefused("missing")
    pinned = ref["sha256"]
    if not isinstance(pinned, str) or not _HEX64.fullmatch(pinned):
        raise AuthorizationRefused("unprotected")
    data = _read_protected_bytes(ref["path"])
    if hashlib.sha256(data).hexdigest() != pinned:
        raise AuthorizationRefused("sha_mismatch")
    return _decode(data)


def pin_run_project(project):
    """Project snapshot for ONE run. No rebinding: only this capability gets a ref."""
    from .api_server_b2b import _HEX64

    native = project["native_n2"]
    slot = native.get("authorization_slot")
    if slot is None:
        return project
    pin = _decode(_read_protected_bytes(slot + ".pin"))
    if (type(pin) is not dict or set(pin) != {"sha256"}
            or not isinstance(pin["sha256"], str) or not _HEX64.fullmatch(pin["sha256"])):
        raise AuthorizationRefused("pin")
    return {**project, "native_n2": {"tenant_id": native["tenant_id"],
                                     "run_authorization": {"path": slot, "sha256": pin["sha256"]}}}


@dataclass(frozen=True)
class _PreparationStamp:
    source: str
    oc_read: tuple
    issued_at: int
    expires_at: int


class SlotPreparations:
    """API-loop owned; retain fingerprints, never plugin callbacks, documents or a stale view."""

    def __init__(self):
        self._stamps = {}

    @staticmethod
    def _key(resolved):
        return resolved["profile"], resolved["attempt_id"]

    @staticmethod
    def _source(resolved, raw_digest, basis_digest):
        # The two signed resolves have different correlations; compare every
        # semantic field, including the reservation, genesis and authority.
        body = {k: v for k, v in resolved["_signed_response"]["body"].items()
                if k not in ("source_request_digest", "source_request_id")}
        return hashlib.sha256(canonical_json([body, raw_digest, basis_digest])).hexdigest()

    def _prune(self):
        # Core must issue INSIDE the prepared envelope's original window.
        # After this horizon even the latest such approval has expired.
        now = time.time()
        for key, stamp in list(self._stamps.items()):
            if now >= stamp.expires_at + _CLAIM_TTL_SECONDS:
                del self._stamps[key]

    def remember(self, resolved, envelope, plain_view):
        self._prune()
        key = self._key(resolved)
        body = envelope["body"]
        stamp = _PreparationStamp(
            self._source(resolved, body["messages_digest"], body["source_basis_digest"]),
            _native_oc_read_metadata(plain_view), envelope["issued_at"], envelope["expires_at"])
        previous = self._stamps.get(key)
        if previous is None and len(self._stamps) >= 256:
            raise AuthorizationRefused("preparation_capacity")
        # An existing Core /1 claim signs semantic identities, not the
        # preparation nonce. Never issue overlapping windows for DIFFERENT
        # source fingerprints: an old claim could otherwise fit both.
        if (previous and previous.source != stamp.source
                and stamp.issued_at < previous.expires_at):
            raise AuthorizationRefused("preparation_conflict")
        self._stamps[key] = stamp

    def for_claim(self, resolved, claim):
        self._prune()
        stamp = self._stamps.get(self._key(resolved))
        if stamp is None or not stamp.issued_at <= claim["issued_at"] < stamp.expires_at:
            raise AuthorizationRefused("preparation")
        return stamp

    def verify(self, stamp, resolved, claim, fresh):
        proof = context_proof(fresh.view)
        ref, instant = _native_oc_read_metadata(proof["view"])
        if (stamp.source != self._source(resolved, claim["n2"]["messages_digest"],
                                         proof["source_basis_digest"])
                or ref == stamp.oc_read[0] or instant < stamp.oc_read[1]):
            raise AuthorizationRefused("preparation")

    def current(self, resolved, stamp):
        return stamp is not None and self._stamps.get(self._key(resolved)) is stamp

    def forget(self, resolved):
        self._stamps.pop(self._key(resolved), None)


def _validate_n2(record):
    from .api_server_b2b import (
        _ATTEMPT_ID_RE, _HEX64, _OBJECT_ID, _SESSION_ID_RE, _SHA256_FIELD)
    from .api_server_b2b_native_validation import (
        _MISSION_ID, _NATIVE_BINDING_KEYS, _NATIVE_PROJECT_ID, _NATIVE_TENANT_ID,
        _POINTER_KEYS, _SHA256_PREFIXED)

    boot_id = _boot_id()
    if not boot_id:
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


def read_approval(project: Mapping[str, Any], *, now: Optional[int] = None) -> Dict[str, Any]:
    stanza = project.get("native_n4")
    if not stanza:
        raise AuthorizationRefused("missing")
    envelope = _read_protected_record(project["native_n2"].get("run_authorization"))
    if type(envelope) is not dict or set(envelope) != {"claim", "signature"}:
        raise AuthorizationRefused("schema")
    claim = envelope["claim"]
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(stanza["core_public_key"])).verify(
            base64.b64decode(envelope["signature"], validate=True),
            SCHEMA.encode() + b"\0" + canonical_json(claim))
    except (InvalidSignature, TypeError, ValueError, RecursionError):
        raise AuthorizationRefused("signature") from None
    if (type(claim) is not dict or set(claim) != {
            "schema", "n2", "n4", "endpoint", "result_public_key",
            "issued_at", "expires_at", "approver_id"} or claim.get("schema") != SCHEMA):
        raise AuthorizationRefused("schema")
    issued_at, expires_at = claim.get("issued_at"), claim.get("expires_at")
    current = int(time.time()) if now is None else now
    if (type(issued_at) is not int or type(expires_at) is not int
            or not issued_at <= current < expires_at
            or expires_at - issued_at > _CLAIM_TTL_SECONDS):
        raise AuthorizationRefused("expired")
    try:
        requester_id = claim["n2"]["binding"]["requester_id"]
    except (KeyError, TypeError):
        raise AuthorizationRefused("schema") from None
    approver_id = claim.get("approver_id")
    if not isinstance(approver_id, str) or re.fullmatch(r"[0-9a-f]{24}", approver_id) is None:
        raise AuthorizationRefused("approver_invalid")
    if approver_id == requester_id:
        raise AuthorizationRefused("approver_not_distinct")
    try:
        n4 = claim["n4"]
        dataset, ports, n2 = n4["dataset"], n4["ports"], claim["n2"]
        if (dataset["classification"] != _NATIVE_MANIFEST_CLASS or dataset["authorized"] is not True
                or n2["classification"] != _NATIVE_MANIFEST_CLASS
                or dataset["dataset_id"] != stanza["dataset_id"] or n2["dataset_id"] != stanza["dataset_id"]):
            raise AuthorizationRefused("classification")
        route = {"provider_id": stanza["provider_id"], "model": stanza["model"],
                 "model_version": stanza["model_version"]}
        if (claim["endpoint"] != stanza["endpoint"] or n4["model_route"] != route
                or project["model"] != route["model"]
                or set(ports) != {"gateway", "core_llm"}
                or any(type(p) is not int or not 20000 <= p <= 65535 for p in ports.values())
                or ports["gateway"] == ports["core_llm"]
                or project["base_url"] != f"http://127.0.0.1:{ports['gateway']}/v1"):
            raise AuthorizationRefused("route")
        if (set(claim) != {"schema", "n2", "n4", "endpoint", "result_public_key",
                            "issued_at", "expires_at", "approver_id"} or claim["schema"] != SCHEMA
                or not re.fullmatch(r"[0-9a-f]{64}", claim["result_public_key"])
                or claim["result_public_key"] == stanza["core_public_key"]
                or not _validate_n2(n2) or set(n4) != {"schema", "binding", "dataset", "model_route", "ports"}
                or n4["schema"] != "dubsar.g2-n4-approval/1"
                or set(dataset) != {"classification", "authorized", "dataset_id", "messages_digest"}
                or type(n4["binding"]) is not dict
                or set(n4["binding"]) != (n2["binding"].keys() - {"mission_inputs", "requester_id"}) | {"documents"}):
            raise AuthorizationRefused("schema")
    except (KeyError, TypeError):
        raise AuthorizationRefused("schema") from None
    return claim


def check_source(claim, resolved):
    expected = resolved.get("_native_binding")
    if not expected:
        raise AuthorizationRefused("binding")
    n2 = claim["n2"]
    for binding in (n2["binding"], claim["n4"]["binding"]):
        for key in binding.keys() - {"documents"}:
            if canonical_json(binding[key]) != canonical_json(expected[key]):
                reason = {"attempt_id": "attempt", "mission_id": "mission", "mission_revision": "revision",
                          "mission_inputs": "pieces"}.get(key, "binding")
                raise AuthorizationRefused(reason)
    if (n2["request_digest"] != resolved["request_digest"]
            or n2["mission_source_digest"] != resolved["mission_source_digest"]):
        raise AuthorizationRefused("source_digest")


def check_preparation(claim, resolved, preparation):
    docs = [{"native_ref": d["native_ref"], "revision": d["revision"],
             "digest": d["native_digest"]} for d in preparation.documents]
    if canonical_json(claim["n4"]["binding"]["documents"]) != canonical_json(docs):
        raise AuthorizationRefused("pieces")
    if claim["n4"]["dataset"]["messages_digest"] != native_recipe_normalized_messages_digest(
            resolved["mission_request"], preparation.rendered):
        raise AuthorizationRefused("normalized_digest")


def authentic_result(public_key, signature, proof):
    try:
        if not re.fullmatch(r"[0-9a-f]{128}", signature):
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
            bytes.fromhex(signature), b"dubsar.n4-result/1\0" + canonical_json(proof))
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False
