"""B2B governed launch surface (KOT-263 H1): closed operator config, signed P1 source client,
typed routes and admission. Only the operator's ``config.extra["b2b"]`` enables it; every value
is validated at startup — nothing request-supplied is authority.

Routes (mirrored under ``/p/<profile>/``):
    POST /api/sessions/{id}/b2b-proposal
    POST /api/sessions/{id}/b2b-prepare
    GET  /api/sessions/{id}/b2b-proposal/{attempt_id}
    GET  /api/sessions/{id}/b2b-proposal/{attempt_id}/context
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import re
import time
import types
import uuid
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from agent.b2b_execution import (
    B2BTerminalRefusal, BoundExecution, B2B_MISSION_ID, R2_SCHEMA_PINS, _deep_freeze,
    _plain_json,
    _public_text, canonical_json, is_b2b_attempt_id, is_b2b_session_id, json_utf8,
    assert_source_equivalent, context_proof, qualify_context_view, verify_context_proof,
    mission_prompt, native_recipe_messages_digest, recheck_context, validate_proposal,
    extract_allowed_refs)
from gateway.platforms import api_server_b2b_native_authorization as _native_auth

logger = logging.getLogger("gateway.platforms.api_server")

_DOMAIN = b"dubsar.b2b-source/1\x00"
_VERSION = "dubsar.b2b-source/1"
_OPERATION = "resolve"
_RESPONSE_OPERATION = "resolved"
_READ_OPERATION = "read"
_PURPOSES = frozenset({"bind", "before_provider", "before_seal", "prepare"})
_BODY_MAX = 65536
_SOURCE_DEADLINE_S = 1.0
# Slack between a bounded C1 deadline and the hard signed-window edge, so the
# renewal exchange itself still fits inside the window the C1 respected.
_CONTEXT_RECHECK_SAFETY_S = 0.1
_REQUEST_TTL_S = 10
_MAX_WINDOW_S = 30

_SIG_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256_FIELD = re.compile(r"^(sha256:)?[0-9a-f]{64}$")
_SESSION_ID_RE = re.compile(r"^b2b_[0-9a-f]{64}$")
_ATTEMPT_ID_RE = re.compile(r"^b2bp_[0-9a-f]{64}$")
_PREPARE_REQUEST_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_OBJECT_ID = re.compile(r"^[0-9a-f]{24}$")
_PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
# Lot-1 native N2 lane: the catalogue may opt a project in with an exact
# {tenant_id, run_authorization?} stanza; only a deploy-bound prj_32 lane may
# carry it and its resolved body is the strictly extended shape.
_NATIVE_PROJECT_ID = re.compile(r"^prj_[0-9a-f]{32}$")
_N4_DATASET_ID = re.compile(r"^[A-Za-z0-9._:-]{2,128}$")
_NATIVE_TENANT_ID = re.compile(
    r"^[^\x00-\x1f\s](?:[^\x00-\x1f]{0,62}[^\x00-\x1f\s])?$")
_SHA256_PREFIXED = re.compile(r"^sha256:[0-9a-f]{64}$")
_POINTER_KEYS = frozenset({"inputs_revision", "manifest_digest", "inputs_digest"})
_NATIVE_BINDING_KEYS = (
    "tenant_id", "project_id", "mission_id", "mission_revision", "profile",
    "session_id", "attempt_id", "binding_digest", "requester_id",
    "mission_inputs",
)
_MISSION_ID = B2B_MISSION_ID  # AUTORITE-PRODUCTION §6.4, Contracts da9bc826
_UNPAIRED = re.compile(
    r"[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ABS_PATH_RE = re.compile(r"^(?:/|[A-Za-z]:[\\/]|\\\\)")

_ENVELOPE_KEYS = frozenset(
    {"version", "issuer", "audience", "operation", "request_id", "issued_at", "expires_at",
     "body", "signature"})
_RESOLVE_BODY_KEYS = frozenset({"attempt_id", "profile", "purpose", "session_id"})
_READ_BODY_KEYS = frozenset(
    {"attempt_id", "binding_digest", "requester_id", "profile", "session_id"})
_RESPONSE_BODY_KEYS = frozenset({
    "attempt_id", "authority_basis_digest", "authority_digest", "binding_digest",
    "mission_id", "mission_revision", "mission_request", "mission_source_digest",
    "observation_genesis", "profile", "project_binding_id", "project_id",
    "request_digest", "requester_id", "reservation_ref", "session_id",
    "source_request_digest", "source_request_id", "source_state", "ticket_digest"})
_RESPONSE_BODY_KEYS_NATIVE = _RESPONSE_BODY_KEYS | frozenset(
    {"tenant_id", "mission_inputs"})
_OBSERVATION_KEYS = frozenset({
    "id", "source", "title", "model", "parent_session_id", "has_system_prompt",
    "has_model_config", "ended_at", "end_reason", "message_count", "tool_call_count",
    "api_call_count", "profile"})
_TITLE_MAX, _OBJECTIVE_MAX = 160, 1000
_CRITERION_MAX, _CRITERIA_MAX = 300, 20
_SOURCE_REF_MAX, _SOURCE_REFS_MAX = 300, 20
_MAX_NATIVE_PIECES = 20
_NATIVE_N4_KEYS = frozenset({"dataset_id"})

_B2B_CONFIG_ROOT_KEYS = frozenset({"enabled", "profiles"})
_PROFILE_ENTRY_KEYS = frozenset({
    "source_url", "portal_issuer", "hermes_issuer",
    "portal_public_key_pem", "hermes_private_key_pem", "projects"})
_PROJECT_ENTRY_KEYS = frozenset({
    "project_id", "bot_id", "profile_id", "allowed_namespaces", "context_contract_root",
    "model", "provider", "base_url", "api_mode", "logical_mission", "project_context",
    "request_timeout_seconds", "memory_mode", "native_n2", "native_n4"})
_PROJECT_ENTRY_REQUIRED_KEYS = _PROJECT_ENTRY_KEYS - {
    "request_timeout_seconds", "memory_mode", "native_n2", "native_n4"}
_PROJECT_CONTEXT_KEYS = frozenset({"allocation_root", "project_id", "start"})
_API_MODES = frozenset({"chat_completions"})
_PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ECMA_WHITESPACE = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005" \
                   "\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"

_ATTEMPT_FORMAT = "dubsar.b2b-proposal-attempt/1"
_ATTEMPT_OPERATION = "proposal-v1"
_PREPARED_OPERATION = "prepared"


class B2BConfigError(ValueError):
    pass


class B2BModelGatewayUnavailable(RuntimeError):
    """A transient startup probe failure; the lane stays closed until retry."""


# ---------------------------------------------------------------------------
# Scalar / wire helpers (exact P1 mirrors)
# ---------------------------------------------------------------------------

def _plain_object(v: Any) -> bool:
    return isinstance(v, Mapping)


def _scalar_ok(v: Any, _depth: int = 0) -> bool:
    """Mirror of P1 scalarOk: depth<=12, strings free of unpaired surrogates."""
    if _depth > 12:
        return False
    if isinstance(v, str):
        return not _UNPAIRED.search(v)
    if isinstance(v, (list, tuple)):
        return all(_scalar_ok(x, _depth + 1) for x in v)
    if _plain_object(v):
        return all(_scalar_ok(x, _depth + 1) for x in v.values())
    if isinstance(v, bool) or v is None:
        return True
    if isinstance(v, int):
        return -(2 ** 53) + 1 <= v <= 2 ** 53 - 1
    return False  # floats/other scalars are not wire-safe


def _exact_keys(value: Any, names) -> bool:
    return _plain_object(value) and set(value.keys()) == set(names)


def _strict_json_loads(raw: bytes) -> Any:
    """Bounded strict decode: UTF-8 fatal, no duplicate keys, no nonfinite constants,
    unpaired-surrogate scalars rejected (mirror of P1 decode+scalarOk gating)."""
    if len(raw) > _BODY_MAX:
        raise ValueError("body_too_large")
    text = raw.decode("utf-8", errors="strict")

    def _pairs(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate_key")
        return dict(pairs)

    def _const(name):
        raise ValueError("nonfinite")

    value = json.loads(
        text, object_pairs_hook=_pairs,
        parse_constant=lambda n: _const(n),
        parse_float=lambda n: _const(n))
    if not _scalar_ok(value):
        raise ValueError("scalar")
    return value


def _bounded_field(value: Any, max_len: int) -> bool:
    return (isinstance(value, str) and not _UNPAIRED.search(value) and
            1 <= len(value.encode("utf-16-le")) // 2 <= max_len and
            value.strip(_ECMA_WHITESPACE) == value and not _CONTROL_CHARS.search(value))


def _valid_mission_request(mr: Any) -> bool:
    """Exact P1 mirror: 4 keys, trim-stable strings, L1 UTF bounds."""
    return (_exact_keys(mr, {"criteria", "objective", "source_refs", "title"})
            and _bounded_field(mr["title"], _TITLE_MAX)
            and _bounded_field(mr["objective"], _OBJECTIVE_MAX)
            and isinstance(mr["criteria"], list)
            and 1 <= len(mr["criteria"]) <= _CRITERIA_MAX
            and all(_bounded_field(c, _CRITERION_MAX) for c in mr["criteria"])
            and isinstance(mr["source_refs"], list)
            and len(mr["source_refs"]) <= _SOURCE_REFS_MAX
            and all(_bounded_field(r, _SOURCE_REF_MAX) for r in mr["source_refs"]))


def _valid_observation(obs: Any, profile: str, session_id: str) -> bool:
    """Exact P1 validObservation mirror: closed 13-key empty-genesis snapshot."""
    if not _exact_keys(obs, _OBSERVATION_KEYS):
        return False
    return (obs["id"] == session_id and obs["profile"] == profile
            and obs["source"] == "api_server"
            and obs["title"] is None and obs["model"] is None
            and obs["parent_session_id"] is None
            and obs["has_system_prompt"] is False and obs["has_model_config"] is False
            and obs["ended_at"] is None and obs["end_reason"] is None
            and all(type(obs[key]) is int and obs[key] == 0 for key in
                    ("message_count", "tool_call_count", "api_call_count")))


def _attempt_id_for(binding_digest: str) -> str:
    return "b2bp_" + hashlib.sha256(canonical_json(
        {"format": _ATTEMPT_FORMAT, "binding_digest": binding_digest,
         "operation": _ATTEMPT_OPERATION})).hexdigest()


def _request_profile(request: Any) -> Optional[str]:
    """Only the explicit, natively resolved /p/<profile>/ typed surface is admitted.
    The selector-less scope (single-profile gateway serving a named home) resolves
    the real home owner, never a literal ``"default"``; unknown/foreign still refuse."""
    from gateway.platforms.api_server import _api_request_profile
    declared = request.match_info.get("profile")
    if not isinstance(declared, str) or not _PROFILE_NAME.fullmatch(declared):
        return None
    active = _api_request_profile.get()
    if active is None:
        from hermes_cli.profiles import get_active_profile_name
        active = get_active_profile_name()
    if declared != active:
        return None
    return declared


# ---------------------------------------------------------------------------
# Operator config (closed, frozen)
# ---------------------------------------------------------------------------

def _req_str(value: Any, name: str, *, allow_none: bool = True) -> Optional[str]:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not value.strip() or _CONTROL_CHARS.search(value):
        raise B2BConfigError(f"b2b config: {name} must be a nonempty control-free string")
    return value


def _req_pem(value: Any, name: str) -> str:
    """PEM material allows \\r\\n (block armoring) but no other control characters."""
    if not isinstance(value, str) or not value.strip():
        raise B2BConfigError(f"b2b config: {name} must be a nonempty PEM string")
    for ch in value:
        o = ord(ch)
        if (o < 0x20 or o == 0x7F or 0x80 <= o <= 0x9F) and ch not in "\r\n\t":
            raise B2BConfigError(f"b2b config: {name} contains control characters")
    return value


def _validate_source_url(value: Any) -> str:
    if not isinstance(value, str):
        raise B2BConfigError("b2b config: source_url must be a string")
    m = re.fullmatch(r"http://127\.0\.0\.1:(\d{1,5})/internal/dubsar/b2b/source", value)
    if not m or not (0 < int(m.group(1)) <= 65535):
        raise B2BConfigError(
            "b2b config: source_url must be exactly "
            "http://127.0.0.1:<port>/internal/dubsar/b2b/source")
    return value


def _validate_model_url(value: Any) -> str:
    if not isinstance(value, str):
        raise B2BConfigError("b2b config: base_url must be a string")
    match = re.fullmatch(r"http://127\.0\.0\.1:([0-9]{1,5})/v1", value)
    if not match or not 0 < int(match.group(1)) <= 65535:
        raise B2BConfigError(
            "b2b config: base_url must be exactly http://127.0.0.1:<port>/v1")
    return value


def _validate_project_entry(entry: Any, binding_id: str) -> Dict[str, Any]:
    if (not isinstance(entry, Mapping)
            or not set(entry.keys()).issubset(_PROJECT_ENTRY_KEYS)
            or not set(entry.keys()).issuperset(_PROJECT_ENTRY_REQUIRED_KEYS)):
        raise B2BConfigError(f"b2b config: project {binding_id}: closed keys required")
    project_id = entry["project_id"]
    if not isinstance(project_id, str) or not _PROJECT_ID.fullmatch(project_id):
        raise B2BConfigError(f"b2b config: project {binding_id}: invalid project_id")
    for key in ("bot_id", "profile_id", "model", "provider"):
        _req_str(entry.get(key), f"project.{key}", allow_none=False)
    ns = entry.get("allowed_namespaces")
    if not isinstance(ns, list) or not ns or not all(
            isinstance(s, str) and s and not _CONTROL_CHARS.search(s) for s in ns):
        raise B2BConfigError(f"b2b config: project {binding_id}: allowed_namespaces")
    root = _req_str(entry.get("context_contract_root"), "project.context_contract_root")
    if root is not None and not _ABS_PATH_RE.match(root):
        raise B2BConfigError(f"b2b config: project {binding_id}: context root must be absolute")
    _validate_model_url(entry.get("base_url"))
    if entry.get("api_mode") not in _API_MODES:
        raise B2BConfigError(f"b2b config: project {binding_id}: api_mode chat_completions only")
    logical_mission = entry.get("logical_mission")
    if logical_mission is not None:
        _req_str(logical_mission, "project.logical_mission", allow_none=False)
    # Integer seconds: the project policy is canonical JSON (floats are refused).
    raw_timeout = entry.get("request_timeout_seconds", 5)
    if (isinstance(raw_timeout, bool) or not isinstance(raw_timeout, int)
            or not 1 <= raw_timeout <= 900):
        raise B2BConfigError(
            f"b2b config: project {binding_id}: request_timeout_seconds")
    request_timeout_seconds = raw_timeout
    memory_mode = entry.get("memory_mode", "required")
    if memory_mode not in ("required", "none"):
        raise B2BConfigError(f"b2b config: project {binding_id}: memory_mode")
    pc = entry.get("project_context")
    if pc is not None:
        if not isinstance(pc, Mapping) or set(pc.keys()) != _PROJECT_CONTEXT_KEYS:
            raise B2BConfigError(
                f"b2b config: project {binding_id}: project_context closed 3 keys")
        if pc["project_id"] != project_id:
            raise B2BConfigError(
                f"b2b config: project {binding_id}: project_context.project_id must equal project_id")
        for k in ("allocation_root", "start"):
            v = pc.get(k)
            if not isinstance(v, str) or not v or _CONTROL_CHARS.search(v) or not _ABS_PATH_RE.match(v):
                raise B2BConfigError(
                    f"b2b config: project {binding_id}: project_context.{k} must be absolute")
    native = entry.get("native_n2")
    native_n2 = None
    if "native_n2" in entry:
        # The native N2 lane is a strict opt-in: only an exact deploy-bound
        # prj_32 project with provider custom:b2b-g2 and a validated loopback
        # URL, no memory and a required project_context may carry it.
        if (not _NATIVE_PROJECT_ID.fullmatch(binding_id)
                or not _NATIVE_PROJECT_ID.fullmatch(project_id)
                or binding_id != project_id
                or entry["bot_id"] != "deploy" or entry["profile_id"] != "deploy"
                or memory_mode != "none" or entry["provider"] != "custom:b2b-g2"
                or pc is None):
            raise B2BConfigError(
                f"b2b config: project {binding_id}: native_n2 requires exact deploy lane")
        if (not isinstance(native, Mapping)
                or not set(native.keys()).issubset({"tenant_id", "run_authorization"})
                or "tenant_id" not in native):
            raise B2BConfigError(
                f"b2b config: project {binding_id}: native_n2 closed keys")
        tenant_id = native["tenant_id"]
        if not isinstance(tenant_id, str) or not _NATIVE_TENANT_ID.fullmatch(tenant_id):
            raise B2BConfigError(
                f"b2b config: project {binding_id}: native_n2.tenant_id")
        native_n2 = {"tenant_id": tenant_id}
        if "run_authorization" in native:
            ref = native["run_authorization"]
            if not isinstance(ref, Mapping) or set(ref.keys()) != {"path", "sha256"}:
                raise B2BConfigError(
                    f"b2b config: project {binding_id}: run_authorization closed keys")
            path, sha256 = ref.get("path"), ref.get("sha256")
            if (not isinstance(path, str) or not path or "\x00" in path
                    or os.path.abspath(path) != path
                    or not isinstance(sha256, str)
                    or _HEX64.fullmatch(sha256) is None):
                raise B2BConfigError(
                    f"b2b config: project {binding_id}: run_authorization ref")
            native_n2["run_authorization"] = {"path": path, "sha256": sha256}
    native_n4 = None
    if "native_n4" in entry:
        # N4 is an additive admission artifact, never a lane switch: it may
        # only ride an already-opted native N2 project, and stays absent by
        # default so the recipe lane is byte-for-byte unchanged.
        if native_n2 is None:
            raise B2BConfigError(
                f"b2b config: project {binding_id}: native_n4 requires native_n2")
        config_n4 = entry.get("native_n4")
        if (not isinstance(config_n4, Mapping)
                or set(config_n4.keys()) != _NATIVE_N4_KEYS):
            raise B2BConfigError(
                f"b2b config: project {binding_id}: native_n4 closed keys")
        dataset_id = config_n4["dataset_id"]
        if (not isinstance(dataset_id, str)
                or _N4_DATASET_ID.fullmatch(dataset_id) is None):
            raise B2BConfigError(
                f"b2b config: project {binding_id}: native_n4.dataset_id")
        native_n4 = {"dataset_id": dataset_id}
    normalized = {
        "project_id": project_id,
        "bot_id": entry["bot_id"], "profile_id": entry["profile_id"],
        "allowed_namespaces": list(entry["allowed_namespaces"]),
        "context_contract_root": entry["context_contract_root"],
        "model": entry["model"], "provider": entry["provider"],
        "base_url": entry["base_url"], "api_mode": entry["api_mode"],
        "logical_mission": logical_mission,
        "project_context": dict(pc) if pc is not None else None}
    # Replay compatibility: the optional key enters the canonical project — hence
    # policy_json and the fingerprint — only when the operator sets it. An attempt
    # admitted before this key existed keeps replaying instead of conflicting on
    # the injected default.
    if "request_timeout_seconds" in entry:
        normalized["request_timeout_seconds"] = request_timeout_seconds
    if "memory_mode" in entry:
        normalized["memory_mode"] = memory_mode
    if native_n2 is not None:
        normalized["native_n2"] = native_n2
    if native_n4 is not None:
        normalized["native_n4"] = native_n4
    return normalized


@dataclasses.dataclass(frozen=True, init=False)
class B2BConfig:
    enabled: bool
    profiles: Mapping[str, Any]

    """Frozen, fully-validated ``config.extra["b2b"]``."""

    def __init__(self, raw: Any):
        if raw is None:
            object.__setattr__(self, "enabled", False)
            object.__setattr__(self, "profiles", types.MappingProxyType({}))
            return
        if not isinstance(raw, Mapping) or set(raw.keys()) != _B2B_CONFIG_ROOT_KEYS:
            raise B2BConfigError("b2b config: closed root keys {enabled,profiles}")
        enabled = raw.get("enabled")
        if not isinstance(enabled, bool):
            raise B2BConfigError("b2b config: enabled must be boolean")
        profiles = raw.get("profiles")
        if not isinstance(profiles, Mapping):
            raise B2BConfigError("b2b config: profiles must be a mapping")
        parsed: Dict[str, Dict[str, Any]] = {}
        for name, entry in profiles.items():
            if not isinstance(name, str) or not _PROFILE_NAME.fullmatch(name):
                raise B2BConfigError("b2b config: profile names must be strings")
            if not isinstance(entry, Mapping) or set(entry.keys()) != _PROFILE_ENTRY_KEYS:
                raise B2BConfigError(f"b2b config: profile {name}: closed keys required")
            projects = entry.get("projects")
            if not isinstance(projects, Mapping) or not projects:
                raise B2BConfigError(f"b2b config: profile {name}: projects mapping required")
            parsed_projects = {}
            for binding_id, p in projects.items():
                if not isinstance(binding_id, str) or not _PROJECT_ID.fullmatch(binding_id):
                    raise B2BConfigError(
                        f"b2b config: profile {name}: invalid project binding id")
                parsed_projects[binding_id] = _validate_project_entry(p, binding_id)
            native_ids = [
                project["project_id"] for project in parsed_projects.values()
                if project.get("native_n2") is not None]
            if native_ids:
                if name != "deploy":
                    raise B2BConfigError(
                        f"b2b config: profile {name}: "
                        "native_n2 requires the deploy profile")
                # A native project id may be bound exactly once in this
                # catalogue: no second entry — native or legacy — may alias it.
                if any(sum(1 for project in parsed_projects.values()
                           if project["project_id"] == pid) != 1
                       for pid in native_ids):
                    raise B2BConfigError(
                        f"b2b config: profile {name}: native_n2 project aliased")
            parsed[name] = {
                "source_url": _validate_source_url(entry.get("source_url")),
                "portal_issuer": _req_str(
                    entry.get("portal_issuer"), "portal_issuer", allow_none=False),
                "hermes_issuer": _req_str(
                    entry.get("hermes_issuer"), "hermes_issuer", allow_none=False),
                "portal_public_key_pem": _req_pem(entry.get("portal_public_key_pem"), "portal_public_key_pem"),
                "hermes_private_key_pem": _req_pem(entry.get("hermes_private_key_pem"), "hermes_private_key_pem"),
                "projects": parsed_projects}
        if enabled and not parsed:
            raise B2BConfigError("b2b config: enabled profiles must be explicit")
        object.__setattr__(self, "enabled", enabled)
        object.__setattr__(self, "profiles", _deep_freeze(parsed))

    def profile_entry(self, profile: str) -> Optional[Dict[str, Any]]:
        return self.profiles.get(profile)


def validate_b2b_config(extra: Any) -> B2BConfig:
    raw = (extra or {}).get("b2b") if isinstance(extra, Mapping) else None
    return B2BConfig(raw)


# ---------------------------------------------------------------------------
# Keys + signed envelopes
# ---------------------------------------------------------------------------

class _KeyRing:
    """Loaded once at config bind; Ed25519 types enforced, portal public verifies,
    hermes private signs."""

    def __init__(self, entry: Mapping[str, Any]):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key, load_pem_public_key)
        pub = load_pem_public_key(entry["portal_public_key_pem"].encode("utf-8"))
        priv = load_pem_private_key(entry["hermes_private_key_pem"].encode("utf-8"), password=None)
        if not isinstance(pub, Ed25519PublicKey) or not isinstance(priv, Ed25519PrivateKey):
            raise B2BConfigError("b2b config: keys must be Ed25519 PEM")
        self.portal_pub = pub
        self.hermes_priv = priv


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_sig(text: Any) -> Optional[bytes]:
    """Canonical 64-byte Ed25519 signature in base64url; alternate encodings of the
    same bytes (nonzero trailing bits) are rejected exactly as P1 does."""
    if not isinstance(text, str) or not _SIG_RE.fullmatch(text):
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "==")
    except Exception:
        return None
    if len(raw) != 64 or _b64url(raw) != text:
        return None
    return raw


def _signed_envelope(entry: Mapping[str, Any], keys: _KeyRing, operation: str,
                     body: Mapping, *, audience: Optional[str] = None,
                     request_id: Optional[str] = None) -> Tuple[Dict[str, Any], bytes]:
    """Mint a Hermes-signed envelope; returns (envelope, exact signed bytes)."""
    now = int(time.time())
    env = {
        "version": _VERSION,
        "issuer": entry["hermes_issuer"],
        "audience": audience or entry["portal_issuer"],
        "operation": operation,
        "request_id": request_id if request_id is not None else str(uuid.uuid4()),
        "issued_at": now,
        "expires_at": now + _REQUEST_TTL_S,
        "body": dict(body)}
    env["signature"] = _b64url(keys.hermes_priv.sign(_DOMAIN + canonical_json(env)))
    raw = json.dumps(env, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return env, raw


def _verify_envelope(parsed: Any, *, entry: Mapping[str, Any], keys: _KeyRing,
                     operation: str, issuer: str, audience: str,
                     now: Optional[float] = None) -> Tuple[Optional[Dict[str, Any]], str]:
    """Closed-envelope check: exact keys, scalars, parties, op, id, window, canonical sig."""
    now_ms = (time.time() if now is None else now) * 1000
    if not _exact_keys(parsed, _ENVELOPE_KEYS) or not _scalar_ok(parsed):
        return None, "envelope_shape"
    if parsed.get("version") != _VERSION:
        return None, "envelope_version"
    if parsed.get("issuer") != issuer or parsed.get("audience") != audience:
        return None, "envelope_party"
    if parsed.get("operation") != operation:
        return None, "envelope_operation"
    rid = parsed.get("request_id")
    if (not isinstance(rid, str) or
            not (1 <= len(rid.encode("utf-16-le")) // 2 <= 256)):
        return None, "envelope_request_id"
    issued, expires = parsed.get("issued_at"), parsed.get("expires_at")
    if not isinstance(issued, int) or isinstance(issued, bool) or \
            not isinstance(expires, int) or isinstance(expires, bool):
        return None, "envelope_window_type"
    if not (issued * 1000 <= now_ms and expires * 1000 > now_ms
            and expires > issued and expires - issued <= _MAX_WINDOW_S):
        return None, "envelope_window"
    sig = _decode_sig(parsed.get("signature"))
    if sig is None:
        return None, "envelope_signature"
    unsigned = {k: v for k, v in parsed.items() if k != "signature"}
    try:
        keys.portal_pub.verify(sig, _DOMAIN + canonical_json(unsigned))
    except Exception:
        return None, "envelope_signature"
    return parsed, "ok"


def _verify_resolved_body(body: Any, *, request: Dict[str, Any], profile: str,
                          session_id: str,
                          native_n2: Optional[Mapping[str, Any]] = None
                          ) -> Tuple[Optional[Dict[str, Any]], str]:
    """Closed resolved response; every P1 verifyResolvedSource check mirrored.
    ``native_n2`` is the configured stanza of the catalogue entry the signed
    ``project_binding_id`` selects — never the body's own claim. When it is
    set the body must carry exactly the extended 22-field shape."""
    expected = (_RESPONSE_BODY_KEYS_NATIVE if native_n2 is not None
                else _RESPONSE_BODY_KEYS)
    if not _exact_keys(body, expected) or not _scalar_ok(body):
        return None, "body_shape"
    req_body = request["body"]
    if (body.get("source_request_id") != request.get("request_id")
            or body.get("attempt_id") != req_body.get("attempt_id")
            or body.get("profile") != req_body.get("profile")
            or body.get("session_id") != req_body.get("session_id")):
        return None, "body_correlation"
    full_signed = dict(request)  # request already carries its signature
    if not _HEX64.fullmatch(str(body.get("source_request_digest") or "")) or \
            not hmac.compare_digest(
                str(body["source_request_digest"]),
                hashlib.sha256(canonical_json(full_signed)).hexdigest()):
        return None, "body_correlation_digest"
    binding = str(body.get("binding_digest") or "")
    if not _HEX64.fullmatch(binding):
        return None, "body_binding"
    if body.get("session_id") != "b2b_" + binding or body.get("session_id") != session_id:
        return None, "body_binding_session"
    if not _ATTEMPT_ID_RE.fullmatch(str(body.get("attempt_id") or "")) or \
            body["attempt_id"] != _attempt_id_for(binding):
        return None, "body_attempt"
    if body.get("source_state") != "active":
        return None, "body_state"
    ref = body.get("reservation_ref")
    if not _exact_keys(ref, {"collection", "id"}) or \
            ref.get("collection") != "dubsar_b2b_agent_sessions" or ref.get("id") != binding:
        return None, "body_reservation"
    if not _OBJECT_ID.fullmatch(str(body.get("requester_id") or "")):
        return None, "body_requester"
    for k in ("project_id", "project_binding_id"):
        v = body.get(k)
        if not isinstance(v, str) or not _PROJECT_ID.fullmatch(v):
            return None, "body_project"
    if not isinstance(body.get("mission_id"), str) or not _MISSION_ID.fullmatch(body["mission_id"]):
        return None, "body_mission"
    rev = body.get("mission_revision")
    if not isinstance(rev, int) or isinstance(rev, bool) or rev < 1 or rev > 2 ** 53 - 1:
        return None, "body_revision"
    for k in ("request_digest", "mission_source_digest", "ticket_digest",
              "authority_basis_digest", "authority_digest"):
        if not _SHA256_FIELD.fullmatch(str(body.get(k) or "")):
            return None, f"body_{k}"
    if not _valid_observation(body.get("observation_genesis"), profile, session_id):
        return None, "body_observation"
    # Both variants share the 20-entry cap; the native response also
    # validates the ordered piece suffix in _verify_native_body.
    if native_n2 is None and not _valid_mission_request(body.get("mission_request")):
        return None, "body_mission_request"
    basis = {
        "format": "dubsar.b2b-agent-session-binding/1", "requester_id": body["requester_id"],
        "project_id": body["project_binding_id"], "mission_id": body["mission_id"],
        "mission_revision": body["mission_revision"]}
    if hashlib.sha256(canonical_json(basis)).hexdigest() != binding:
        return None, "body_binding_tuple"
    if native_n2 is not None and not _verify_native_body(body, native_n2):
        return None, "body_native"
    return dict(body), "ok"


def _valid_native_source_refs(values: Any, mission_id: str) -> bool:
    """Native refs preserve the ordinary 20-ref prefix and bounded piece suffix."""
    if (not isinstance(values, list)
            or not 1 <= len(values) <= _SOURCE_REFS_MAX + 2 * _MAX_NATIVE_PIECES):
        return False
    if not all(_bounded_field(v, _SOURCE_REF_MAX) for v in values):
        return False
    piece = re.compile(
        rf"^dubsar:piece:{re.escape(mission_id)}:piece_[0-9a-f]{{32}}$")
    docs = [i for i, v in enumerate(values) if v.startswith("dubsar:piece:")]
    count = len(docs)
    ordinary_count = len(values) - 2 * count
    if not 1 <= count <= _MAX_NATIVE_PIECES or not 0 <= ordinary_count <= _SOURCE_REFS_MAX:
        return False
    if docs != list(range(len(values) - 2 * count, len(values), 2)):
        return False
    seen = set()
    for i in docs:
        value = values[i]
        if (piece.fullmatch(value) is None
                or _SHA256_PREFIXED.fullmatch(values[i + 1]) is None):
            return False
        piece_id = value.rsplit(":", 1)[1]
        if piece_id in seen:
            return False
        seen.add(piece_id)
    return True


def _verify_native_body(body: Mapping[str, Any], native_n2: Mapping[str, Any]) -> bool:
    """The extended native body admits only the exact tenant/project/pointer
    binding the opted catalogue entry declares."""
    if (body.get("tenant_id") != native_n2.get("tenant_id")
            or body.get("profile") != "deploy"
            or not isinstance(body.get("project_id"), str)
            or _NATIVE_PROJECT_ID.fullmatch(body["project_id"]) is None
            or body.get("project_binding_id") != body["project_id"]):
        return False
    pointer = body.get("mission_inputs")
    if (not isinstance(pointer, Mapping) or set(pointer) != _POINTER_KEYS
            or type(pointer.get("inputs_revision")) is not int
            or not 1 <= pointer["inputs_revision"] <= 2**53 - 1
            or type(pointer.get("manifest_digest")) is not str
            or _SHA256_PREFIXED.fullmatch(pointer["manifest_digest"]) is None
            or type(pointer.get("inputs_digest")) is not str
            or _SHA256_PREFIXED.fullmatch(pointer["inputs_digest"]) is None):
        return False
    mission_request = body.get("mission_request")
    if (not _exact_keys(mission_request,
                        {"criteria", "objective", "source_refs", "title"})
            or not _bounded_field(mission_request["title"], _TITLE_MAX)
            or not _bounded_field(mission_request["objective"], _OBJECTIVE_MAX)
            or not isinstance(mission_request["criteria"], list)
            or not 1 <= len(mission_request["criteria"]) <= _CRITERIA_MAX
            or not all(_bounded_field(c, _CRITERION_MAX)
                       for c in mission_request["criteria"])):
        return False
    return _valid_native_source_refs(
        mission_request.get("source_refs"), body.get("mission_id", ""))


def _native_binding(resolved: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Canonical ten-key native run binding — present only after the extended
    body shape verified; a legacy resolve never carries it."""
    if resolved.get("_native_verified") is not True:
        return None
    return {key: resolved[key] for key in _NATIVE_BINDING_KEYS}


# ---------------------------------------------------------------------------
# Source client — aiohttp, hard 1 s total, streamed bounded read, no redirects
# ---------------------------------------------------------------------------

async def _resolve_source_async(entry: Mapping[str, Any], keys: _KeyRing, purpose: str, *,
                                attempt_id: str, profile: str, session_id: str) -> Tuple[
                                    Optional[Dict[str, Any]], str]:
    import aiohttp
    if purpose not in _PURPOSES:
        return None, "purpose"
    body = {"attempt_id": attempt_id, "profile": profile,
            "purpose": purpose, "session_id": session_id}
    env, req_raw = _signed_envelope(entry, keys, _OPERATION, body)
    if len(req_raw) > _BODY_MAX:
        return None, "request_too_large"
    try:
        timeout = aiohttp.ClientTimeout(total=_SOURCE_DEADLINE_S)
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as client:
            async with client.post(
                    entry["source_url"], data=req_raw,
                    headers={"content-type": "application/json; charset=utf-8"},
                    allow_redirects=False) as resp:
                if resp.status != 200:
                    return None, "source_denied"
                chunks, size = [], 0
                async for chunk in resp.content.iter_any():
                    size += len(chunk)
                    if size > _BODY_MAX:
                        return None, "response_too_large"
                    chunks.append(chunk)
                resp_raw = b"".join(chunks)
    except Exception:
        return None, "source_unavailable"
    try:
        parsed = _strict_json_loads(resp_raw)
    except Exception:
        return None, "response_decode"
    verified, reason = _verify_envelope(
        parsed, entry=entry, keys=keys, operation=_RESPONSE_OPERATION,
        issuer=entry["portal_issuer"], audience=entry["hermes_issuer"])
    if verified is None:
        return None, reason
    # Exact legacy-vs-extended selection comes from the configured project the
    # signed body binds — never the body's own claim. A body that names a
    # configured native project_id but binds a non-native catalogue alias is a
    # downgrade and refuses before any shape check.
    signed_body = verified.get("body")
    catalogue_key = (signed_body.get("project_binding_id")
                     if isinstance(signed_body, Mapping) else None)
    project = (entry["projects"].get(catalogue_key)
               if isinstance(catalogue_key, str) else None)
    native_n2 = (project.get("native_n2")
                 if isinstance(project, Mapping) else None)
    native_ids = {p["project_id"] for p in entry["projects"].values()
                  if isinstance(p, Mapping) and p.get("native_n2") is not None}
    claimed = signed_body.get("project_id") if isinstance(signed_body, Mapping) else None
    if (isinstance(claimed, str) and claimed in native_ids
            and native_n2 is None):
        return None, "body_native_downgrade"
    out, reason = _verify_resolved_body(
        verified.get("body"), request=env, profile=profile, session_id=session_id,
        native_n2=native_n2)
    if out is None:
        return None, reason
    if native_n2 is not None:
        out["_native_verified"] = True
        out["_native_binding"] = _native_binding(out)
    if not (env["issued_at"] <= int(time.time()) < env["expires_at"]):
        return None, "request_window_closed"
    out["_signed_request"] = env
    out["_signed_response"] = verified
    out["_request_raw"] = req_raw
    out["_response_raw"] = resp_raw
    return out, "ok"


def _source_record(resolved: Mapping[str, Any]) -> bytes:
    return json_utf8({
        "format": "dubsar.b2b-source-artifact/1",
        "request": resolved["_signed_request"], "response": resolved["_signed_response"],
        "request_utf8": resolved["_request_raw"].decode("utf-8"),
        "response_utf8": resolved["_response_raw"].decode("utf-8")})


def resolve_source(entry: Mapping[str, Any], keys: _KeyRing, purpose: str, *,
                   attempt_id: str, profile: str, session_id: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Sync wrapper: from the executor worker thread, never inside the serving loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_resolve_source_async(
            entry, keys, purpose, attempt_id=attempt_id, profile=profile, session_id=session_id))
    raise RuntimeError("resolve_source must not run inside the API event loop")


def verify_read_proof(header: Any, *, entry: Mapping[str, Any], keys: _KeyRing,
                      expected: Optional[Mapping[str, Any]] = None) -> Tuple[Optional[Dict[str, Any]], str]:
    """Verify ``X-Dubsar-Read-Proof``: complete JSON envelope as a header string."""
    if not isinstance(header, str) or not header:
        return None, "proof_missing"
    raw = header.encode("utf-8")
    try:
        parsed = _strict_json_loads(raw)
    except Exception:
        return None, "proof_decode"
    verified, reason = _verify_envelope(
        parsed, entry=entry, keys=keys, operation=_READ_OPERATION,
        issuer=entry["portal_issuer"], audience=entry["hermes_issuer"])
    if verified is None:
        return None, reason
    body = verified.get("body")
    if not _exact_keys(body, _READ_BODY_KEYS) or not _scalar_ok(body):
        return None, "proof_body"
    binding = body.get("binding_digest")
    if (not isinstance(binding, str) or not _HEX64.fullmatch(binding) or
            body.get("attempt_id") != _attempt_id_for(binding) or
            body.get("session_id") != "b2b_" + binding or
            not isinstance(body.get("profile"), str) or not _PROFILE_NAME.fullmatch(body["profile"]) or
            not isinstance(body.get("requester_id"), str) or not _OBJECT_ID.fullmatch(body["requester_id"])):
        return None, "proof_tuple"
    if expected is not None and any(body[key] != value for key, value in expected.items()):
        return dict(body), "proof_tuple"
    return dict(body), "ok"


# ---------------------------------------------------------------------------
# Frozen state + policy + admission
# ---------------------------------------------------------------------------

class _B2BState:
    """Per-adapter frozen runtime: config, keyrings."""

    def __init__(self, config: B2BConfig):
        self.config = config
        keys = {}
        if config.enabled:
            for name, entry in config.profiles.items():
                keys[name] = _KeyRing(entry)
        self.keys = types.MappingProxyType(keys)


def _state_for(adapter: Any) -> Optional[_B2BState]:
    return getattr(adapter, "_b2b_state", None)


def bind_b2b_state(adapter: Any) -> None:
    """Called once from ``__init__`` — parses + freezes operator config."""
    extra = getattr(adapter, "_extra", None) or getattr(
        getattr(adapter, "config", None), "extra", None) or {}
    adapter._b2b_state = _B2BState(validate_b2b_config(extra))


async def validate_b2b_model_gateway(adapter: Any) -> None:
    """Require G2's unauthenticated refusal before exposing the B2B lane."""
    state = _state_for(adapter)
    if state is None or not state.config.enabled:
        return
    import aiohttp
    urls = sorted({project["base_url"]
                   for entry in state.config.profiles.values()
                   for project in entry["projects"].values()})
    try:
        async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=1.0), trust_env=False,
                cookie_jar=aiohttp.DummyCookieJar()) as client:
            for url in urls:
                async with client.post(
                        url + "/chat/completions", data=b"",
                        allow_redirects=False) as response:
                    if response.status != 401:
                        raise B2BConfigError(
                            "b2b config: model gateway must refuse unauthenticated POST with 401; redirects forbidden")
    except (aiohttp.ClientError, asyncio.TimeoutError):
        raise B2BModelGatewayUnavailable("b2b model gateway startup probe unavailable") from None


def _deny(code: int, reason: str):
    from aiohttp import web
    return web.json_response({"error": reason, "code": reason}, status=code)


def _policy_digest(profile: str, entry: Mapping[str, Any], project: Mapping[str, Any],
                   resolved: Mapping[str, Any]) -> str:
    """Stable identity/policy fingerprint: semantic entry/settings/schema pins + trusted
    roots + logical label only — never keys, nonces, signatures, timestamps or the
    registry-global mission_source_digest."""
    basis = {
        "profile": profile, "project_binding_id": resolved["project_binding_id"],
        "project_id": resolved["project_id"], "requester_id": resolved["requester_id"],
        "mission_id": resolved["mission_id"], "mission_revision": resolved["mission_revision"],
        "binding_digest": resolved["binding_digest"], "attempt_id": resolved["attempt_id"],
        "session_id": resolved["session_id"],
        "reservation_ref": resolved["reservation_ref"],
        "request_digest": resolved["request_digest"], "ticket_digest": resolved["ticket_digest"],
        "authority_basis_digest": resolved["authority_basis_digest"],
        "authority_digest": resolved["authority_digest"],
        "observation_genesis": resolved["observation_genesis"],
        "mission_request": resolved["mission_request"],
        "bot_id": project["bot_id"], "profile_id": project["profile_id"],
        "allowed_namespaces": project["allowed_namespaces"],
        "context_contract_root": project["context_contract_root"],
        "model": project["model"], "provider": project["provider"],
        "base_url": project["base_url"], "api_mode": project["api_mode"],
        "logical_mission": project["logical_mission"],
        "project_context": project["project_context"],
        "source_url": entry["source_url"],
        "portal_issuer": entry["portal_issuer"], "hermes_issuer": entry["hermes_issuer"],
        "schema_pins": R2_SCHEMA_PINS, "execution_policy": "h1/proposal-v1",
        "profile_home": resolved.get("profile_home"),
    }
    if "native_n2" in project:
        basis["native_n2"] = project["native_n2"]
        basis["native_n2_binding"] = resolved.get("native_n2_binding")
        basis["native_n2_messages_digest"] = resolved.get("native_n2_messages_digest")
    # Optional operator key: absent from the digest basis unless explicitly
    # configured, so a pre-versioning admission replays byte-for-byte while a
    # configured value still revokes a running cap when changed mid-run.
    if "request_timeout_seconds" in project:
        basis["request_timeout_seconds"] = project["request_timeout_seconds"]
    if "memory_mode" in project:
        basis["memory_mode"] = project["memory_mode"]
    return hashlib.sha256(canonical_json(basis)).hexdigest()


def _run_scope(profile: str, requester_id: str, binding_digest: str) -> str:
    return "b2b:" + hashlib.sha256(canonical_json(
        {"profile": profile, "requester_id": requester_id,
         "binding_digest": binding_digest})).hexdigest()


async def _read_bounded_json(request: Any):
    try:
        parts, size = [], 0
        async for chunk in request.content.iter_chunked(8192):
            size += len(chunk)
            if size > _BODY_MAX:
                return None, _deny(400, "body_too_large")
            parts.append(chunk)
        raw = b"".join(parts)
        parsed = _strict_json_loads(raw)
    except Exception:
        return None, _deny(400, "invalid_body")
    if not isinstance(parsed, dict):
        return None, _deny(400, "invalid_body")
    return parsed, None


def _store_durable(store: Any) -> bool:
    """Strict durability: native property + real non-blank main db filename."""
    if store is None or not getattr(store, "durable", False):
        return False
    try:
        row = store._conn.execute(
            "SELECT file FROM pragma_database_list WHERE name='main'").fetchone()
    except Exception:
        return False
    f = (row[0] or "") if row else ""
    return bool(f) and f != ":memory:"


def _genesis_vs_native(session: Mapping[str, Any], session_id: str, profile: str) -> bool:
    """Compare the signed 13-key observation against the ACTUAL native empty session on
    first attachment: exact id/profile/source + empty counters + null runtime/title."""
    if not session or str(session.get("id") or "") != session_id:
        return False
    if str(session.get("source") or "") != "api_server":
        return False
    if session.get("title") is not None or session.get("model") is not None:
        return False
    if session.get("parent_session_id") is not None:
        return False
    if session.get("system_prompt") is not None or session.get("model_config") is not None:
        return False
    if session.get("ended_at") is not None or session.get("end_reason") is not None:
        return False
    for key in ("message_count", "tool_call_count", "api_call_count"):
        if type(session.get(key)) is not int or session[key] != 0:
            return False
    return True


# Durable terminal classification for _AttemptSink.block: explicit reason ->
# status entries; anything unlisted defaults to "failed". Exception text is
# never mined for substrings — a reason not in this table is a bug or an
# untyped failure, and both are "failed". The emitted refusal universe is
# enumerated in agent.b2b_execution.BLOCK_REASONS; every member MUST have an
# explicit entry below — the classification tests walk that constant against
# this table, so a new raise site or block() call extends BOTH in one change.
_BLOCK_CONTEXT_STALE_REASONS = frozenset({
    "context_schema_invalid", "context_contract_unavailable",
    "context_digest_invalid", "context_identity_source",
    "context_mission_id",
    "context_identity_mismatch", "context_catalogue_mismatch",
    "context_authority_mismatch", "context_selection_mismatch",
    "context_namespaces", "context_source_unavailable", "context_source_stale",
    "context_my_work_mismatch", "context_my_work_authority",
    "context_memory_unqualified", "context_memory_namespace",
    "context_memory_provenance", "context_memory_mission",
    "context_memory_malformed_globals", "context_memory_malformed",
    "context_memory_malformed_api", "context_memory_malformed_source_contract",
    "context_memory_malformed_v1_fallback",
    "context_memory_malformed_truncated", "context_memory_malformed_limits",
    "context_memory_missing", "context_memory_mode",
    "context_memory_unexpected",
    "context_contradictions", "context_oc_malformed", "context_oc_mismatch",
    "context_oc_unavailable", "context_oc_read_metadata",
    "context_oc_unqualified", "context_oc_projection",
    "context_oc_source_stale", "context_oc_read_replayed",
    "context_proof_missing", "context_proof_invalid",
    "context_accepted_unavailable",
    "context_accepted_malformed", "context_accepted_unqualified",
    "context_support_unqualified", "context_relation_bounds",
    "context_view_bounds", "context_view_not_object",
    "context_recheck_unavailable", "context_recheck_already_registered",
    "context_render_bounds", "context_rendered_type",
    "context_rendered_encoding", "context_too_large", "context_turn_id",
    "context_turn_mismatch", "context_publication_conflict",
    "context_absent_from_kwargs", "context_changed_before_sdk",
    "context_stale",
})
_BLOCK_POLICY_CHANGED_REASONS = frozenset({
    "b2b_capability_mismatch", "b2b_capability_missing",
    "b2b_agent_binding_missing", "b2b_agent_binding_mismatch",
    "b2b_profile_mismatch", "b2b_policy_override", "b2b_policy_changed",
    "b2b_runtime_mismatch", "b2b_runtime_policy", "b2b_destination_mismatch",
    "b2b_model_mismatch", "b2b_alternate_provider", "b2b_alternate_api_call",
    "b2b_sdk_override", "b2b_sdk_headers", "b2b_client_policy",
    "b2b_retries_not_disabled", "b2b_request_client_not_isolated",
    "b2b_timeout_policy", "terminal_guard_required", "kwargs_not_permitted",
    "b2b_recipe_messages_mismatch",
})
_BLOCK_SOURCE_DENIED_REASONS = frozenset({
    "source_before_provider_denied", "source_before_seal_denied",
    "source_window_closed",
})
_BLOCK_RESULT_INVALID_REASONS = frozenset({
    "result_invalid", "proposal_invalid", "response_not_public",
})
# Emitted refusal reasons whose classified status IS "failed": serializer
# invariant failures (host-side data defects — the same json_* guards run on
# non-context payloads), missing capability plumbing, no-receipt/commit-
# integrity conditions and untyped run exits. Explicit membership makes the
# durable "failed" deliberate; genuinely untyped exception text re-fed by
# block_failed_run still lands on the generic default below.
_BLOCK_FAILED_REASONS = frozenset({
    "json_depth", "json_key", "json_scalar",
    "sink_missing", "context_sink_missing",
    "dispatch_already_committed", "request_changed_before_sdk",
    "provider_result_unavailable", "result_unattested",
    "middleware_response_unattested",
    "result_commit_failed", "context_commit_failed", "seal_commit_failed",
    "seal_unattested", "launch_failed", "native_run_interrupted",
    "b2b_run_failed", "policy_provider_unavailable",
})
# Terminal durable statuses re-fed to block() by _b2b_finalize's already-
# blocked fast path are known values, not untyped text — self-mapping.
_BLOCK_TERMINAL_STATUSES = frozenset({
    "context_unavailable", "context_stale", "policy_changed",
    "source_denied", "result_invalid", "indeterminate", "failed",
    "interrupted",
})
_BLOCK_STATUS = {
    "context_unavailable": "context_unavailable",
    **{r: "context_stale" for r in _BLOCK_CONTEXT_STALE_REASONS},
    **{r: "policy_changed" for r in _BLOCK_POLICY_CHANGED_REASONS},
    **{r: "source_denied" for r in _BLOCK_SOURCE_DENIED_REASONS},
    **{r: "result_invalid" for r in _BLOCK_RESULT_INVALID_REASONS},
    **{r: "failed" for r in _BLOCK_FAILED_REASONS},
    **{s: s for s in _BLOCK_TERMINAL_STATUSES},
}
# NO-RECEIPT conditions (provider_result_unavailable, result_unattested,
# middleware_response_unattested) intentionally classify "failed" here: the
# dispatch may or may not have reached the provider, so the post-CAS override
# below turns them "indeterminate" once a committed marker exists with no
# durable result — never the known-invalid result_invalid.


class _AttemptSink:
    """Durable sink bound to one admitted attempt: source artifacts, dispatch CAS,
    context receipt, result commit. All mutations are single logical transactions."""

    def __init__(self, adapter: Any, store: Any, *, profile: str, entry: Mapping[str, Any],
                 keys: _KeyRing, attempt_id: str, session_id: str,
                 binding_digest: str, run_id: str, policy: Mapping[str, Any]):
        self._adapter = adapter
        self._store = store
        self.profile, self.entry, self.keys = profile, entry, keys
        self.attempt_id, self.session_id = attempt_id, session_id
        self.binding_digest, self.run_id = binding_digest, run_id
        self.policy = _deep_freeze(policy)
        self._fingerprint = _policy_digest(profile, entry, self.policy["project"], self.policy)
        self._before_provider = None
        self.context_receipt = None
        # The frozen context preparation attached by _launch_b2b_run before
        # admission; None on every sink the launch path did not prepare.
        self._context_preparation = None

    def assert_current_policy(self) -> bool:
        state = _state_for(self._adapter)
        if state is None or not state.config.enabled:
            return False
        entry = state.config.profile_entry(self.profile)
        if entry is None:
            return False
        # Trust-root / signing-identity change revokes the running cap even when the
        # identity fingerprint (which deliberately excludes keys) is stable — the
        # original operator pins are compared in-process, never logged.
        if (entry.get("portal_public_key_pem") != self.entry.get("portal_public_key_pem") or
                entry.get("hermes_private_key_pem") != self.entry.get("hermes_private_key_pem")):
            return False
        project = entry.get("projects", {}).get(self.policy["project_binding_id"])
        if not (project is not None and
                _policy_digest(self.profile, entry, project, self.policy) == self._fingerprint):
            return False
        # P2: when a preparation is attached, the producer's live configuration
        # must still satisfy the plugin's own validator — config drift revokes
        # the lane like policy drift. A TYPED refusal is a durable terminal
        # cause: block with that exact reason and rethrow, never flatten it.
        preparation = self._context_preparation
        if preparation is not None:
            try:
                if not preparation.assert_configuration_current():
                    return False
            except B2BTerminalRefusal as exc:
                self.block(str(exc))
                raise
            except Exception:
                return False
        return True

    def _matches_source(self, resolved: Mapping[str, Any]) -> bool:
        fields = (
            "attempt_id", "binding_digest", "requester_id", "project_id",
            "project_binding_id", "mission_id", "mission_revision", "profile", "session_id",
            "reservation_ref", "request_digest", "ticket_digest", "authority_basis_digest",
            "authority_digest", "observation_genesis", "mission_request")
        if not (resolved.get("source_state") == "active" and self.assert_current_policy() and
                all(json_utf8(resolved.get(key)) == json_utf8(self.policy.get(key))
                    for key in fields)):
            return False
        native = _native_binding(resolved)
        expected_native = self.policy.get("native_n2_binding")
        if (native is None) != (expected_native is None):
            return False
        if expected_native is not None:
            if canonical_json(native) != canonical_json(expected_native):
                return False
            # A native RUN policy additionally re-proves its manifest: the
            # protected record must still pin the same binding and digests at
            # every source recheck (resolve_before_provider and before_seal).
            if (self.policy.get("native_n2_messages_digest") is not None
                    and not self._native_run_current(resolved)):
                return False
        return True

    def _native_run_current(self, resolved: Mapping[str, Any]) -> bool:
        """Protected manifest re-read: the record must still pin exactly this
        run's binding, this exchange's request/source digests and the approved
        messages digest."""
        project = self.policy.get("project")
        native = project.get("native_n2") if isinstance(project, Mapping) else None
        ref = native.get("run_authorization") if isinstance(native, Mapping) else None
        manifest = _native_auth._read_native_run_authorization(ref)
        if manifest is None:
            return False
        try:
            return (canonical_json(manifest["binding"]) ==
                    canonical_json(self.policy.get("native_n2_binding"))
                    and manifest["request_digest"] == resolved.get("request_digest")
                    and manifest["mission_source_digest"] ==
                    resolved.get("mission_source_digest")
                    and manifest["messages_digest"] ==
                    self.policy.get("native_n2_messages_digest"))
        except (TypeError, ValueError):
            return False

    def _source_matches_context(self, resolved: Mapping[str, Any]) -> bool:
        receipt = self.context_receipt
        return (receipt is not None and
                resolved.get("mission_source_digest") ==
                receipt.view["my_work"]["mission"]["source_digest"])

    def block(self, reason: str) -> None:
        # Durable classification comes from the explicit reason -> status table:
        # arbitrary exception text is NEVER mined for substrings.
        # ``result_invalid:<validator detail>`` raises embed the validator
        # reason in the exception string — classify on their prefix.
        status = _BLOCK_STATUS.get(reason.partition(":")[0], "failed")
        self._store.b2b_update_attempt(profile=self.profile, attempt_id=self.attempt_id, status=status)

    def resolve_before_provider(self) -> bool:
        resolved, reason = resolve_source(
            self.entry, self.keys, "before_provider", attempt_id=self.attempt_id,
            profile=self.profile, session_id=self.session_id)
        if (resolved is None or not self._matches_source(resolved) or
                not self._source_matches_context(resolved)):
            self.block("source_before_provider_denied")
            return False
        self._before_provider = resolved
        return True

    def _proposal_refs(self, view: Any) -> Tuple[str, ...]:
        native = self.policy.get("native_n2_binding") is not None
        return extract_allowed_refs(
            view,
            native_request=self.policy.get("mission_request") if native else None,
        )

    def context_recheck_deadline(self) -> float:
        """Monotonic deadline for the next bounded C1 recheck: an explicit
        source/C1 budget, never the worker/provider timeout. With a completed
        ``before_provider`` exchange it is the earliest request/response
        ``expires_at`` minus ``now`` minus the renewal reserve — strictly below
        the remaining TTL, short response window included; before any exchange
        it is the prospective ``_REQUEST_TTL_S`` window."""
        resolved = self._before_provider
        if resolved is not None:
            remaining = min(
                resolved["_signed_request"]["expires_at"],
                resolved["_signed_response"]["expires_at"]) - time.time()
        else:
            remaining = float(_REQUEST_TTL_S)
        budget = max(
            0.0, remaining - (_SOURCE_DEADLINE_S + _CONTEXT_RECHECK_SAFETY_S))
        return time.monotonic() + budget

    def seal_recheck_deadline(self) -> float:
        """Monotonic deadline for the SEAL-time bounded C1 recheck: the
        ``before_seal`` exchange is only issued AFTER this read returns, so
        the prospective ``_REQUEST_TTL_S`` window applies — never the
        already-spent ``before_provider`` budget."""
        return time.monotonic() + max(
            0.0, _REQUEST_TTL_S - (_SOURCE_DEADLINE_S + _CONTEXT_RECHECK_SAFETY_S))

    def _qualify_context(self, view: Mapping[str, Any]) -> Dict[str, Any]:
        # Validate against the sink's frozen policy, without minting a capability.
        policy = types.SimpleNamespace(policy_get=self.policy.get)
        return qualify_context_view(policy, view)

    def cas_dispatch(self, *, request_digest: str, receipt: Any,
                     rechecked_view: Optional[Mapping[str, Any]] = None) -> bool:
        from gateway.platforms.api_server_b2b_context import (
            assert_context_source_current)
        resolved = self._before_provider
        if (receipt is not self.context_receipt or resolved is None or
                not self._matches_source(resolved) or not self._source_matches_context(resolved) or
                not isinstance(rechecked_view, Mapping)):
            return False
        fresh = self._qualify_context(rechecked_view)
        assert_source_equivalent(receipt.view, fresh)
        proof = context_proof(fresh)
        # Serialize BOTH durable records before the final signed-window check so
        # no local preparation stands between the check and the store CAS.
        source_record = _source_record(resolved)
        now = time.time()
        dispatch_record = json_utf8({
            "format": "dubsar.b2b-provider-dispatch/1",
            "attempt_id": self.attempt_id, "run_id": self.run_id,
            "binding_digest": self.binding_digest, "request_digest": request_digest,
            "context_digest": receipt.digest,
            "source_basis_digest": receipt.source_basis_digest,
            "source_basis_contract": receipt.source_basis_contract,
            "view_digest": receipt.view_digest,
            "context_recheck": {
                "format": "dubsar.b2b-context-recheck/2",
                "attempt_id": self.attempt_id, "run_id": self.run_id, **proof},
            "rendered_digest": receipt.rendered_digest,
            "model": self.policy["project"]["model"],
            "provider": self.policy["project"]["provider"], "committed_at": now})
        window_now = time.time()
        if not all(env["issued_at"] <= window_now < env["expires_at"] for env in
                   (resolved["_signed_request"], resolved["_signed_response"])):
            # The signed window closed after the last exchange: a typed refusal,
            # never the duplicate-CAS False (that answer stays exclusive to a
            # genuinely committed dispatch marker).
            self.block("source_window_closed")
            raise B2BTerminalRefusal("source_window_closed")
        try:
            assert_context_source_current(self._context_preparation)
        except B2BTerminalRefusal as exc:
            self.block(str(exc))
            raise
        return self._store.b2b_cas_dispatch(
            profile=self.profile, attempt_id=self.attempt_id,
            source_record=source_record, dispatch_record=dispatch_record)

    def commit_result(self, *, text: Any, parsed: Any, reason: str) -> None:
        receipt = self.context_receipt
        valid, checked = validate_proposal(
            text, self._proposal_refs(receipt.view) if receipt else ())
        marker = self._store.b2b_artifact(attempt_id=self.attempt_id, kind="provider_dispatch")
        if receipt is None or marker is None or valid is None or valid != parsed or checked != reason:
            self.block("result_invalid")
            raise B2BTerminalRefusal("result_invalid")
        dispatch = json.loads(marker["payload"])
        payload = json_utf8({
            "format": "dubsar.b2b-provider-result/1",
            "attempt_id": self.attempt_id, "binding_digest": self.binding_digest,
            "run_id": self.run_id, "request_digest": dispatch["request_digest"],
            "context_digest": receipt.digest, "text": text, "proposal": valid})
        if not self._store.b2b_commit_result(
            profile=self.profile, attempt_id=self.attempt_id,
                payload=payload):
            raise B2BTerminalRefusal("result_commit_failed")

    def assert_worker_response(self, response: Any) -> bool:
        text = _public_text(response)
        row = self._store.b2b_artifact(attempt_id=self.attempt_id, kind="provider_result")
        if row is None or text is None:
            return False
        stored = json.loads(row["payload"])
        parsed, _ = validate_proposal(
            text, self._proposal_refs(self.context_receipt.view)
            if self.context_receipt else ())
        return (stored.get("attempt_id") == self.attempt_id and stored.get("run_id") == self.run_id
                and stored.get("text") == text and parsed is not None
                and stored.get("proposal") == parsed)

    def put_context(self, receipt: Any) -> None:
        """Persist the published context (view + rendered bytes + digest) once."""
        from gateway.platforms.api_server_b2b_context import (
            assert_context_source_current)
        # The accepted receipt must BE the attached preparation's mission —
        # same cap, same configuration, same source basis, inside the OC window.
        preparation = self._context_preparation
        if preparation is not None:
            from agent.b2b_execution import current_execution
            preparation.assert_publication(current_execution(), receipt)
        proof = context_proof(receipt.view)
        if (proof["context_digest"] != receipt.digest or
                proof["source_basis_digest"] != receipt.source_basis_digest):
            raise B2BTerminalRefusal("context_proof_invalid")
        payload = json_utf8({
            "format": "dubsar.b2b-context-artifact/1", "attempt_id": self.attempt_id,
            "run_id": self.run_id, **proof,
            "rendered": receipt.rendered.decode("utf-8"), "turn_id": receipt.turn_id,
            "rendered_digest": receipt.rendered_digest})
        assert_context_source_current(preparation)
        if not self._store.b2b_commit_context(
                profile=self.profile, attempt_id=self.attempt_id, payload=payload):
            raise B2BTerminalRefusal("context_commit_failed")
        self.context_receipt = receipt

    async def resolve_before_seal(self) -> Optional[Dict[str, Any]]:
        resolved, reason = await _resolve_source_async(
            self.entry, self.keys, "before_seal", attempt_id=self.attempt_id,
            profile=self.profile, session_id=self.session_id)
        if resolved is None:
            self.block("source_before_seal_denied")
            return None
        # The policy/validator match is plugin-owned code — bounded on a
        # non-preparation worker, never inline on the API loop: a blocked
        # validator refuses ``context_unavailable`` on ``_SOURCE_DEADLINE_S``
        # instead of freezing the whole gateway.
        from gateway.platforms.api_server_b2b_context import (
            run_bounded_context_operation)
        matched = await run_bounded_context_operation(
            lambda: (self._matches_source(resolved) and
                     self._source_matches_context(resolved)),
            timeout=_SOURCE_DEADLINE_S)
        if not matched:
            self.block("source_before_seal_denied")
            return None
        return resolved

    def _prepare_seal(self, *, source_before_seal: Mapping[str, Any],
                      rechecked_view: Mapping[str, Any], created_at: str) -> Dict[str, Any]:
        """Plugin-validating seal PREPARATION: every check the attached
        preparation's validator must pass plus the proposal/artifact
        MATERIAL — never ``store.b2b_seal``. Runs ONLY inside a bounded
        worker; material a timed-out worker produced is simply discarded,
        so a straggler can never mint late durable proof."""
        receipt = self.context_receipt
        result = self._store.b2b_artifact(attempt_id=self.attempt_id, kind="provider_result")
        if (receipt is None or result is None or not self._matches_source(source_before_seal) or
                not self._source_matches_context(source_before_seal)):
            raise B2BTerminalRefusal("seal_unattested")
        now = time.time()
        if not all(env["issued_at"] <= now < env["expires_at"] for env in
                   (source_before_seal["_signed_request"], source_before_seal["_signed_response"])):
            raise B2BTerminalRefusal("source_window_closed")
        public = json.loads(result["payload"])
        parsed, _ = validate_proposal(public["text"], self._proposal_refs(receipt.view))
        if parsed is None or parsed != public.get("proposal"):
            raise B2BTerminalRefusal("result_invalid")
        # CLOSED dubsar.b2b-proposal/1 — exactly the 15 contract fields, nothing more.
        # Host/source/context/dispatch metadata stays in the artifacts and the OUTER DTO.
        proposal = {
            "proposal_id": "b2bprop_" + self.attempt_id[5:],
            "attempt_id": self.attempt_id, "binding_digest": self.binding_digest,
            "profile": self.profile, "session_id": self.session_id,
            "project_id": self.policy["project_id"], "mission_id": self.policy["mission_id"],
            "mission_revision": self.policy["mission_revision"],
            "context_digest": receipt.digest,
            "summary": parsed["summary"], "steps": parsed["steps"],
            "source_refs": parsed["source_refs"], "limitations": parsed["limitations"],
            "state": "prepared", "created_at": created_at}
        sealed_utf8 = json_utf8(proposal)
        if len(sealed_utf8) > 32768:
            raise B2BTerminalRefusal("proposal_invalid")
        # Compare source content, not capture metadata or public proposal fields.
        fresh = self._qualify_context(rechecked_view)
        assert_source_equivalent(receipt.view, fresh)
        marker = self._store.b2b_artifact(
            attempt_id=self.attempt_id, kind="provider_dispatch")
        if marker is None:
            raise B2BTerminalRefusal("context_proof_missing")
        dispatch = json.loads(marker["payload"])
        previous = verify_context_proof(dispatch.get("context_recheck"))
        assert_source_equivalent(previous["view"], fresh)
        proof = context_proof(fresh)
        return {
            "proposal": proposal,
            "source_window": {
                "request": {
                    "issued_at": source_before_seal["_signed_request"]["issued_at"],
                    "expires_at": source_before_seal["_signed_request"]["expires_at"]},
                "response": {
                    "issued_at": source_before_seal["_signed_response"]["issued_at"],
                    "expires_at": source_before_seal["_signed_response"]["expires_at"]}},
            "artifacts": {
                "source_before_seal": _source_record(source_before_seal),
                "context_recheck": json_utf8({
                    "format": "dubsar.b2b-context-recheck/2", "attempt_id": self.attempt_id,
                    "run_id": self.run_id, **proof}),
                "proposal": json_utf8(proposal)}}

    def _commit_seal(self, prepared: Mapping[str, Any]) -> Dict[str, Any]:
        """Host-only durable COMMIT — the sole ``store.b2b_seal`` caller.
        Invoked exclusively by the API thread after a TIMELY
        ``_prepare_seal`` return; a worker never owns this closure.

        The signed source window is re-verified HERE on host data — the
        async prepare→commit seam admits scheduling delay, so the window a
        timely preparation observed may have closed by commit. Pure
        timestamp arithmetic: no plugin callback, no revalidation."""
        from gateway.platforms.api_server_b2b_context import (
            assert_context_source_current)
        window = prepared["source_window"]
        now = time.time()
        if not all(env["issued_at"] <= now < env["expires_at"] for env in
                   (window["request"], window["response"])):
            raise B2BTerminalRefusal("source_window_closed")
        # The attached preparation's OC source deadline is rechecked on the
        # host in the same breath — the seam lets the observation cross its
        # own governed bound between the last validation and this commit.
        # Pure timestamp comparison: no plugin callback, no _assert_stamp.
        assert_context_source_current(self._context_preparation)
        stored = self._store.b2b_seal(
            profile=self.profile, attempt_id=self.attempt_id,
            artifacts=dict(prepared["artifacts"]))
        if stored is None:
            raise B2BTerminalRefusal("seal_commit_failed")
        return json.loads(stored)

    def seal(self, *, source_before_seal: Mapping[str, Any], rechecked_view: Mapping[str, Any],
             created_at: str) -> Dict[str, Any]:
        """Synchronous prepare+commit for direct callers/tests — the same
        two stages ``_b2b_finalize`` splits across the bounded boundary."""
        return self._commit_seal(self._prepare_seal(
            source_before_seal=source_before_seal,
            rechecked_view=rechecked_view, created_at=created_at))


def _b2b_lane_bootstrap(adapter: Any, *, profile: str,
                        project: Mapping[str, Any]) -> Tuple[Optional[str], Any, Any]:
    """Runs INSIDE the bounded NON-preparation worker, off the API
    loop and the default executor, on the ``_REQUEST_TTL_S`` budget:
    owning profile scope (secret hydration included), gateway config,
    plugin discovery, and the non-plugin/inputs gates. Discovery and
    hydration can legitimately take seconds; neither is plugin
    PREPARATION code, so neither may spend the source budget. The
    scoped context is captured ONCE and returned for the bounded
    task to inherit. Shared by the admission and prepare-only lanes —
    the gates ARE identical."""
    from gateway.run import _load_gateway_config
    from hermes_cli.plugins import discover_plugins, get_plugin_manager
    from gateway.platforms.api_server_b2b_execution import (
        b2b_execution_inputs_ready)
    try:
        with adapter._profile_scope(profile):
            config = _load_gateway_config()
            discover_plugins()
            if get_plugin_manager().has_non_plugin_hook_subscribers():
                return "non_plugin_hook_subscribers", None, None
            if not b2b_execution_inputs_ready(project, config):
                return "execution_inputs_unavailable", None, None
            return None, config, contextvars.copy_context()
    except Exception:
        return "execution_unavailable", None, None


def _b2b_prepare_once(*, cap: Any, sink: Any, project: Mapping[str, Any],
                      config: Any, resolved: Dict[str, Any]) -> Optional[str]:
    """Runs INSIDE the one bounded worker, under the scope the
    bootstrap captured: the bound execution, THEN the plugin-owned
    preparation (the native read) and readiness — the only code the
    source budget covers. The ContextVar is always reset. Shared by
    the admission and prepare-only lanes — identical body, identical
    refusal mapping."""
    from agent.b2b_execution import bind_execution, reset_execution
    from gateway.platforms.api_server_b2b_execution import (
        b2b_execution_unavailable_code)
    from gateway.platforms.api_server_b2b_context import (
        _prepare_b2b_context, assert_context_source_current)
    try:
        token = bind_execution(cap)
        try:
            sink._context_preparation = _prepare_b2b_context(
                cap, resolved=resolved)
            unavailable = b2b_execution_unavailable_code(
                project, config)
            assert_context_source_current(sink._context_preparation)
            return unavailable
        finally:
            reset_execution(token)
    except B2BTerminalRefusal as exc:
        return (str(exc) if str(exc) in {"context_oc_source_stale",
                                         "context_documents"}
                else "execution_unavailable")
    except Exception:
        return "execution_unavailable"


async def _b2b_run_bounded_preparation(adapter: Any, *, profile: str,
                                       project: Mapping[str, Any], cap: Any,
                                       sink: Any, resolved: Dict[str, Any]):
    """The shared preflight: bootstrap on the ``_REQUEST_TTL_S`` budget, then
    the ONE bounded preparation worker under the captured scope. The launch
    bootstrap is held off the API loop AND the default executor entirely: the
    bounded NON-preparation runner owns the wait on its own budget (never the
    ``_SOURCE_DEADLINE_S`` native-read budget). No capacity admission gates
    this request — a budget expiry fails THIS request closed, nothing else.
    Returns the deny response, or None when the preparation attached."""
    import asyncio as _a
    from gateway.platforms.api_server_b2b_context import (
        run_bounded_context_operation, run_bounded_context_preparation)
    try:
        bootstrap_error, config, scope_ctx = await run_bounded_context_operation(
            lambda: _b2b_lane_bootstrap(adapter, profile=profile, project=project),
            timeout=_REQUEST_TTL_S)
    except B2BTerminalRefusal:
        return _deny(503, "execution_unavailable")
    except Exception:
        return _deny(503, "execution_unavailable")
    if bootstrap_error == "non_plugin_hook_subscribers":
        return _deny(503, "non_plugin_hook_subscribers")
    if bootstrap_error is not None:
        return _deny(503, "execution_unavailable")
    try:
        # The task — and therefore the worker it spawns — runs under the
        # scope captured above: the owning profile's home, secrets and
        # terminal scope without a second hydration.
        preparation_task = scope_ctx.run(
            _a.create_task,
            run_bounded_context_preparation(
                lambda: _b2b_prepare_once(
                    cap=cap, sink=sink, project=project, config=config,
                    resolved=resolved)))
        preparation_error = await preparation_task
    except B2BTerminalRefusal:
        preparation_error = "execution_unavailable"
    if preparation_error is not None:
        return _deny(503, preparation_error)
    return None


async def _launch_b2b_run(adapter: Any, request: Any, *, profile: str, entry, keys,
                          session_id: str, binding_digest: str, attempt_id: str,
                          resolved: Dict[str, Any], store: Any, db: Any):
    """Keep the immutable empty origin, but accept worked sessions through their owned binding."""
    import asyncio as _a
    from hermes_constants import get_hermes_home
    home = get_hermes_home().resolve()
    if (not getattr(db, "db_path", None) or str(db.db_path) == ":memory:" or
            db.db_path.resolve().parent != home):
        return _deny(503, "store_unavailable")
    run_id = "run_" + uuid.uuid4().hex
    session = await _a.to_thread(db.get_session, session_id)
    if (not session or session.get("id") != session_id or session.get("source") != "api_server"
            or any(session.get(key) is not None for key in
                   ("parent_session_id", "ended_at", "end_reason"))):
        return _deny(409, "session_incompatible")
    try:
        tip = await _a.to_thread(db.resolve_resume_session_id, session_id)
    except Exception:
        return _deny(409, "genesis_resume")
    if tip != session_id:
        return _deny(409, "genesis_resume")
    existing = store.b2b_binding(session_id=session_id, profile=profile)
    if existing is None:
        if not _genesis_vs_native(session or {}, session_id, profile):
            # A concurrent winner may already have started the exact session.
            existing = store.b2b_binding(session_id=session_id, profile=profile)
            if existing is None:
                return _deny(409, "genesis_native")
    if existing is None:
        if not _valid_observation(resolved.get("observation_genesis"), profile, session_id):
            return _deny(403, "genesis_proof")
        obs = resolved["observation_genesis"]
        native_obs = {
            "id": session.get("id"), "source": session.get("source"),
            "title": session.get("title"), "model": session.get("model"),
            "parent_session_id": session.get("parent_session_id"),
            "has_system_prompt": session.get("system_prompt") is not None,
            "has_model_config": session.get("model_config") is not None,
            "ended_at": session.get("ended_at"), "end_reason": session.get("end_reason"),
            "message_count": int(session.get("message_count") or 0),
            "tool_call_count": int(session.get("tool_call_count") or 0),
            "api_call_count": int(session.get("api_call_count") or 0),
            "profile": profile}
        if native_obs != {k: obs[k] for k in _OBSERVATION_KEYS}:
            return _deny(409, "genesis_mismatch")
    project = entry["projects"].get(str(resolved.get("project_binding_id") or ""))
    if project is None or project["project_id"] != resolved["project_id"]:
        return _deny(404, "not_found")
    existing_attempt = store.b2b_attempt(profile=profile, attempt_id=attempt_id)
    native_binding = resolved.get("_native_binding")
    native_messages_digest = None
    if project.get("native_n2") is not None:
        if existing_attempt is not None:
            existing = existing or store.b2b_binding(session_id=session_id, profile=profile)
            try:
                native_messages_digest = json.loads(existing["policy_json"])[
                    "native_n2_messages_digest"]
            except (TypeError, KeyError, ValueError):
                return _deny(409, "conflict")
            if (not isinstance(native_messages_digest, str)
                    or _HEX64.fullmatch(native_messages_digest) is None):
                return _deny(409, "conflict")
        else:
            # Native run: the opted catalogue entry must carry run authorization
            # and the protected manifest must pin THIS exact binding plus this
            # exchange's digests. An absent stanza means prepare-only — refuse
            # before context preparation, admission or any receipt consumption.
            manifest = _native_auth._read_native_run_authorization(
                project["native_n2"].get("run_authorization"))
            if (native_binding is None or manifest is None
                    or canonical_json(manifest["binding"]) != canonical_json(native_binding)
                    or manifest["request_digest"] != resolved["request_digest"]
                    or manifest["mission_source_digest"] != resolved["mission_source_digest"]):
                return _deny(503, "execution_unavailable")
            native_messages_digest = manifest["messages_digest"]
    # P2 admission gate: NEW work proves its mission context BEFORE the single
    # durable attempt is consumed — the sink/cap are built in memory first,
    # then the bounded bootstrap enters the owning profile scope (secret
    # hydration included), loads the gateway config and discovers plugins,
    # and only THEN does the one bounded worker run the plugin-owned
    # preparation — the real native read (the profile's prepare_context
    # plugin callback, bound to THIS cap) AND its configuration validators —
    # inside the captured scope, attach the frozen preparation to the sink,
    # and consult readiness (the same single classifier /health/detailed
    # reports). Any source/producer error is 503 execution_unavailable with
    # NO binding/attempt/run/title/provider side effects — the in-memory
    # sink/cap are simply dropped. An already-durable attempt row is always
    # served by the idempotent replay below (b2b_admit -> _replayed_response),
    # so a lost-ACK retry never hears "execution_unavailable" for a committed
    # lane and never pays a context read.
    policy = {
        "profile": profile, "session_id": session_id, "binding_digest": binding_digest,
        "attempt_id": attempt_id, "profile_home": str(home),
        "schema_pins": R2_SCHEMA_PINS, "execution_policy": "h1/proposal-v1",
        "requester_id": resolved["requester_id"],
        "project_id": resolved["project_id"],
        "project_binding_id": resolved["project_binding_id"],
        "mission_id": resolved["mission_id"], "mission_revision": resolved["mission_revision"],
        "reservation_ref": resolved["reservation_ref"],
        "request_digest": resolved["request_digest"],
        "ticket_digest": resolved["ticket_digest"],
        "authority_basis_digest": resolved["authority_basis_digest"],
        "authority_digest": resolved["authority_digest"],
        "observation_genesis": resolved["observation_genesis"],
        "mission_request": resolved["mission_request"], "project": project,
        **({"native_n2_binding": native_binding,
            "native_n2_messages_digest": native_messages_digest}
           if native_binding is not None else {})}
    fingerprint = _policy_digest(profile, entry, project, policy)
    scope = _run_scope(profile, resolved["requester_id"], binding_digest)
    initial_status = {"status": "queued", "session_id": session_id, "created_at": time.time()}
    sink = None
    cap = None
    # Lost-ACK replay is allowed even while the original holds the final native worker slot.
    if existing_attempt is None:
        from gateway.platforms.api_server_b2b_context import (
            assert_context_source_current)
        from gateway.run import _profile_runtime_scope
        # The sink + cap exist ONLY in memory until b2b_admit commits the
        # attempt — a failed preparation drops them with zero durable trace.
        sink = _AttemptSink(adapter, store, profile=profile, entry=entry, keys=keys,
                            attempt_id=attempt_id, session_id=session_id,
                            binding_digest=binding_digest, run_id=run_id, policy=policy)
        cap = BoundExecution(
            profile=profile, session_id=session_id, binding_digest=binding_digest,
            attempt_id=attempt_id, run_id=run_id, policy=dict(policy),
            sink=sink, created_at=time.time())
        denied = await _b2b_run_bounded_preparation(
            adapter, profile=profile, project=project, cap=cap, sink=sink,
            resolved=resolved)
        if denied is not None:
            return denied
        if (native_binding is not None
                and native_recipe_messages_digest(
                    resolved["mission_request"], sink._context_preparation.rendered
                ) != native_messages_digest):
            return _deny(503, "execution_unavailable")
    if existing_attempt is None:
        # Inherited generic API admission, kept at
        # its original place — not a B2B capacity gate.
        limited = adapter._concurrency_limited_response()
        if limited is not None:
            return limited
    # Signed proof can expire while session/DB checks were awaited: re-verify the
    # freshness window on BOTH envelopes immediately before the durable commit —
    # same predicate the CAS/seal paths apply to their own source reads.
    now = int(time.time())
    if not all(env["issued_at"] <= now < env["expires_at"] for env in
               (resolved["_signed_request"], resolved["_signed_response"])):
        return _deny(403, "source_denied")
    if existing_attempt is None:
        # Non-hydrating scope entry — introspection only, never plugin
        # secret-source code on the loop.
        try:
            with _profile_runtime_scope(home, hydrate_secrets=False):
                from hermes_cli.plugins import get_plugin_manager

                has_non_plugin_hooks = (
                    get_plugin_manager().has_non_plugin_hook_subscribers())
        except Exception:
            return _deny(503, "execution_unavailable")
        if has_non_plugin_hooks:
            return _deny(503, "non_plugin_hook_subscribers")
    binding_row = {"profile": profile, "session_id": session_id,
                   "binding_digest": binding_digest,
                   "policy_json": json_utf8(policy).decode("utf-8")}
    attempt_row = {"attempt_id": attempt_id, "binding_digest": binding_digest,
                   "profile": profile, "session_id": session_id, "status": "admitted",
                   "run_id": run_id, "requester_id": resolved["requester_id"],
                   "source_bind": _source_record(resolved)}
    if cap is not None:
        try:
            assert_context_source_current(sink._context_preparation)
        except B2BTerminalRefusal as exc:
            return _deny(503, str(exc))
        if (native_binding is not None
                and not sink._native_run_current(resolved)):
            # Revocation during bounded preparation must not consume admission.
            return _deny(503, "execution_unavailable")
    outcome = store.b2b_admit(
        profile=profile, session_id=session_id, binding_digest=binding_digest,
        attempt_id=attempt_id, fingerprint=fingerprint,
        binding_row=binding_row,
        attempt_row=attempt_row,
        run_scope=scope, run_key=attempt_id, run_id=run_id,
        run_fingerprint=fingerprint, run_status=initial_status,
        owner_pid=getattr(adapter, "_run_owner_pid", 0),
        owner_started=getattr(adapter, "_run_owner_started", 0),
        replay_only=existing_attempt is not None)
    if outcome.get("status") == "conflict":
        return _deny(409, "conflict")
    stored_run_id = outcome.get("run_id") or (
        (outcome.get("attempt") or {}).get("run_id") if outcome.get("status") == "replayed" else run_id)
    if outcome.get("status") == "replayed":
        return _replayed_response(adapter, stored_run_id, attempt_id, binding_digest, profile, session_id)
    adapter._run_idempotency_ids.add(stored_run_id)
    try:
        await _a.to_thread(db.set_session_title, session_id, f"B2B {session_id}")
    except Exception:
        store.b2b_update_attempt(profile=profile, attempt_id=attempt_id, status="failed")
        return _deny(500, "title_commit_failed")
    # The admitted winner's run_id is the chosen one — the sink/cap built
    # pre-admission already carry it (a replayed outcome returned above).
    launched = await _spawn_run(adapter, request, cap=cap, resolved=resolved,
                                session_id=session_id, run_id=stored_run_id, profile=profile)
    if launched is None:
        sink.block("launch_failed")
        return _deny(503, "launch_failed")
    if project.get("native_n4") is not None:
        # Additive side artifact: the recipe run above is already admitted and
        # launched. The N4 admission never gates it; a refusal is explicit in
        # the log and leaves no file.
        from gateway.platforms.api_server_b2b_native_admission import (
            NativeAdmissionRefusal, emit_native_admission)
        try:
            emit_native_admission(
                home=home, stanza=project["native_n4"],
                native_binding=native_binding, resolved=resolved,
                preparation=sink._context_preparation,
                messages_digest=native_messages_digest,
                session_id=session_id, attempt_id=attempt_id,
                binding_digest=binding_digest, profile=profile,
                configured_tenant=project["native_n2"]["tenant_id"])
        except NativeAdmissionRefusal as exc:
            logger.warning("b2b native N4 admission refused: %s", exc.code)
        except OSError as exc:
            logger.warning("b2b native N4 admission unavailable: %s", exc)
    from aiohttp import web
    return web.json_response({
        "object": "b2b.proposal_attempt", "attempt_id": attempt_id,
        "binding_digest": binding_digest, "run_id": stored_run_id, "profile": profile,
        "session_id": session_id, "status": "admitted"})


async def _prepare_b2b_only(adapter: Any, request: Any, *, profile: str, entry, keys,
                            session_id: str, binding_digest: str, attempt_id: str,
                            request_id: str, resolved: Dict[str, Any],
                            store: Any, db: Any):
    """The prepare-only attestation (N3): verify the exact
    binding/session/attempt/source identities and run the SAME bounded
    bootstrap + plugin-owned context preparation as admission — then STOP:
    no b2b_admit, no title, no concurrency gate, no run, no provider, no
    durable write of any kind. The prepare-only attestation is signed by the
    owning Hermes profile; it binds the caller request_id and the signed
    source exchange. It does not create a Hermes record, authorize a run, or
    assert that a later admission has not occurred. The answer is a
    ``b2b.preparation`` attestation correlated to THIS signed exchange: the
    context proof digests, the source-basis contract, the rendered digest
    and the ordered piece tuple — ``run_id: null``,
    ``model_scheduled: false``. A replayed POST simply re-attests under a
    fresh signed exchange; an already durable binding/attempt refuses 409."""
    import asyncio as _a
    from aiohttp import web
    from datetime import datetime, timezone
    from gateway.platforms.api_server_b2b_context import (
        assert_context_source_current)
    from gateway.run import _profile_runtime_scope
    from hermes_constants import get_hermes_home
    home = get_hermes_home().resolve()
    if (not getattr(db, "db_path", None) or str(db.db_path) == ":memory:" or
            db.db_path.resolve().parent != home):
        return _deny(503, "store_unavailable")
    session = await _a.to_thread(db.get_session, session_id)
    if (not session or session.get("id") != session_id or session.get("source") != "api_server"
            or any(session.get(key) is not None for key in
                   ("parent_session_id", "ended_at", "end_reason"))):
        return _deny(409, "session_incompatible")
    try:
        tip = await _a.to_thread(db.resolve_resume_session_id, session_id)
    except Exception:
        return _deny(409, "genesis_resume")
    if tip != session_id:
        return _deny(409, "genesis_resume")
    # The single-use durable lane: a committed binding or attempt row means
    # the tuple was already consumed — refuse rather than attest beside it.
    if (store.b2b_binding(session_id=session_id, profile=profile) is not None
            or store.b2b_attempt(profile=profile, attempt_id=attempt_id) is not None):
        return _deny(409, "already_admitted")
    if not _genesis_vs_native(session, session_id, profile):
        return _deny(409, "genesis_native")
    if not _valid_observation(resolved.get("observation_genesis"), profile, session_id):
        return _deny(403, "genesis_proof")
    obs = resolved["observation_genesis"]
    native_obs = {
        "id": session.get("id"), "source": session.get("source"),
        "title": session.get("title"), "model": session.get("model"),
        "parent_session_id": session.get("parent_session_id"),
        "has_system_prompt": session.get("system_prompt") is not None,
        "has_model_config": session.get("model_config") is not None,
        "ended_at": session.get("ended_at"), "end_reason": session.get("end_reason"),
        "message_count": int(session.get("message_count") or 0),
        "tool_call_count": int(session.get("tool_call_count") or 0),
        "api_call_count": int(session.get("api_call_count") or 0),
        "profile": profile}
    if native_obs != {k: obs[k] for k in _OBSERVATION_KEYS}:
        return _deny(409, "genesis_mismatch")
    project = entry["projects"].get(str(resolved.get("project_binding_id") or ""))
    if project is None or project["project_id"] != resolved["project_id"]:
        return _deny(404, "not_found")
    policy = {
        "profile": profile, "session_id": session_id, "binding_digest": binding_digest,
        "attempt_id": attempt_id, "profile_home": str(home),
        "schema_pins": R2_SCHEMA_PINS, "execution_policy": "h1/proposal-v1",
        "requester_id": resolved["requester_id"],
        "project_id": resolved["project_id"],
        "project_binding_id": resolved["project_binding_id"],
        "mission_id": resolved["mission_id"], "mission_revision": resolved["mission_revision"],
        "reservation_ref": resolved["reservation_ref"],
        "request_digest": resolved["request_digest"],
        "ticket_digest": resolved["ticket_digest"],
        "authority_basis_digest": resolved["authority_basis_digest"],
        "authority_digest": resolved["authority_digest"],
        "observation_genesis": resolved["observation_genesis"],
        "mission_request": resolved["mission_request"], "project": project,
        **({"native_n2_binding": resolved.get("_native_binding")}
           if resolved.get("_native_binding") is not None else {})}
    # The sink + cap exist ONLY in memory — the run_id minted here is the
    # capability's identity, NEVER admitted, scheduled or returned: the
    # attestation's run_id is null. A failed preparation drops both with
    # zero durable trace.
    run_id = "run_" + uuid.uuid4().hex
    sink = _AttemptSink(adapter, store, profile=profile, entry=entry, keys=keys,
                        attempt_id=attempt_id, session_id=session_id,
                        binding_digest=binding_digest, run_id=run_id, policy=policy)
    cap = BoundExecution(
        profile=profile, session_id=session_id, binding_digest=binding_digest,
        attempt_id=attempt_id, run_id=run_id, policy=dict(policy),
        sink=sink, created_at=time.time())
    denied = await _b2b_run_bounded_preparation(
        adapter, profile=profile, project=project, cap=cap, sink=sink,
        resolved=resolved)
    if denied is not None:
        return denied
    # Non-hydrating scope entry — introspection only, never plugin
    # secret-source code on the loop.
    try:
        with _profile_runtime_scope(home, hydrate_secrets=False):
            from hermes_cli.plugins import get_plugin_manager
            has_non_plugin_hooks = (
                get_plugin_manager().has_non_plugin_hook_subscribers())
    except Exception:
        return _deny(503, "execution_unavailable")
    if has_non_plugin_hooks:
        return _deny(503, "non_plugin_hook_subscribers")
    preparation = sink._context_preparation
    proof = context_proof(preparation.view)
    documents = [
        {"native_ref": document["native_ref"], "revision": document["revision"],
         "digest": document["native_digest"]}
        for document in preparation.documents]
    # Last-mile race gate: a proposal admitted between the early durable
    # check above and this boundary consumed the same tuple — refuse rather
    # than mint a stale attestation beside an owned admission.
    if (store.b2b_binding(session_id=session_id, profile=profile) is not None
            or store.b2b_attempt(profile=profile, attempt_id=attempt_id) is not None):
        return _deny(409, "already_admitted")
    # Signed proof can expire while session/DB checks were awaited: re-verify
    # the freshness window on BOTH envelopes immediately before signing —
    # the same predicate the commit path applies to its own source reads.
    now = int(time.time())
    if not all(env["issued_at"] <= now < env["expires_at"] for env in
               (resolved["_signed_request"], resolved["_signed_response"])):
        return _deny(403, "source_denied")
    try:
        assert_context_source_current(preparation)
    except B2BTerminalRefusal as exc:
        return _deny(503, str(exc))
    body = {
        "object": "b2b.preparation",
        "attempt_id": attempt_id, "binding_digest": binding_digest,
        "profile": profile, "session_id": session_id,
        "requester_id": resolved["requester_id"],
        "project_id": resolved["project_id"],
        "project_binding_id": resolved["project_binding_id"],
        "mission_id": resolved["mission_id"],
        "mission_revision": resolved["mission_revision"],
        "status": "prepared", "run_id": None, "model_scheduled": False,
        "prepared_at": datetime.now(timezone.utc).isoformat(
            timespec="milliseconds").replace("+00:00", "Z"),
        "context_digest": proof["context_digest"],
        "view_digest": proof["view_digest"],
        "source_basis_contract": proof["source_basis_contract"],
        "source_basis_digest": proof["source_basis_digest"],
        "rendered_digest": hashlib.sha256(preparation.rendered).hexdigest(),
        "source_request_id": resolved["source_request_id"],
        "source_request_digest": resolved["source_request_digest"],
        "documents": documents}
    if resolved.get("_native_binding") is not None:
        body["messages_digest"] = native_recipe_messages_digest(
            resolved["mission_request"], preparation.rendered)
    envelope, _ = _signed_envelope(
        entry, keys, _PREPARED_OPERATION, body, request_id=request_id)
    return web.json_response(envelope)


def _replayed_response(adapter: Any, run_id: Any, attempt_id: str, binding_digest: str,
                       profile: str, session_id: str):
    from aiohttp import web
    return web.json_response({
        "object": "b2b.proposal_attempt", "attempt_id": attempt_id,
        "binding_digest": binding_digest, "run_id": run_id, "profile": profile,
        "session_id": session_id, "status": "replayed"})


async def _spawn_run(adapter: Any, request: Any, *, cap, resolved, session_id, run_id, profile):
    """Schedule the native run executor for the winning admission — the same queue,
    status, _RunLaunch and _execute_run path _handle_runs uses."""
    import asyncio as _a
    from gateway.platforms import api_server_runs as _runs
    import sys
    prompt = _mission_prompt(resolved.get("mission_request") or {})
    q = adapter._run_streams[run_id] = _a.Queue()
    created_at = adapter._run_streams_created[run_id] = time.time()
    adapter._run_approval_sessions[run_id] = run_id
    adapter._run_owners[run_id] = _run_scope(profile, resolved["requester_id"], cap.binding_digest)
    adapter._set_run_status(run_id, "queued", created_at=created_at,
                            session_id=session_id, model=None)
    launch = _runs._RunLaunch(
        adapter, run_id, q, session_id, None, False, prompt, [],
        False, dict(ephemeral_system_prompt=None, session_id=session_id,
                    gateway_session_key=None, route=None, room_dispatch=None,
                    room_execution_policy=None, requested_model=None,
                    requested_provider=None, model_options=None,
                    confirmed_runtime_lock=True),
        request_profile=profile if profile != "default" else None,
        browser_control_principal=None, browser_control_transport_family=None,
        turn_author=None, b2b_execution=cap)
    adapter._activate_admitted_request()
    task = adapter._active_run_tasks[run_id] = _a.create_task(
        _runs._execute_run(adapter, launch, _api_server=sys.modules["gateway.platforms.api_server"]))
    try:
        adapter._background_tasks.add(task)
        task.add_done_callback(adapter._background_tasks.discard)
    except Exception:
        pass
    return task


def _mission_prompt(mission_request: Mapping[str, Any]) -> str:
    return mission_prompt(mission_request)


async def _handle_b2b_proposal_post(adapter: Any, request: Any):
    """POST /p/<profile>/api/sessions/{id}/b2b-proposal — verify + admit + launch."""
    state = _state_for(adapter)
    if state is None or not state.config.enabled:
        return _deny(404, "not_found")
    profile = _request_profile(request)
    if not profile:
        return _deny(404, "not_found")
    entry = state.config.profile_entry(profile)
    keys = state.keys.get(profile)
    if entry is None or keys is None:
        return _deny(404, "not_found")
    session_id = str(request.match_info.get("session_id", "") or "")
    if not _SESSION_ID_RE.fullmatch(session_id):
        return _deny(400, "invalid_session_id")
    binding_digest = session_id[4:]
    parsed, err = await _read_bounded_json(request)
    if err is not None:
        return err
    if set(parsed.keys()) != {"attempt_id", "binding_digest"}:
        return _deny(400, "invalid_body")
    if parsed["binding_digest"] != binding_digest:
        return _deny(403, "binding_mismatch")
    attempt_id = parsed.get("attempt_id")
    if not _ATTEMPT_ID_RE.fullmatch(str(attempt_id or "")):
        return _deny(400, "invalid_attempt_id")
    if (request.headers.get("Idempotency-Key") or "").strip() != attempt_id:
        return _deny(400, "idempotency_key_mismatch")
    db = await adapter._ensure_session_db_async()
    if db is None:
        return _deny(503, "store_unavailable")
    store = adapter._run_idempotency_store
    if not _store_durable(store):
        return _deny(503, "store_unavailable")
    resolved, reason = await _resolve_source_async(
        entry, keys, "bind", attempt_id=attempt_id, profile=profile, session_id=session_id)
    if resolved is None:
        # Any signed-source invalidity collapses to one refusal shape — the
        # specific check is journal-side, never leaked to the caller.
        return _deny(503 if reason == "source_unavailable" else 403,
                     "source_unavailable" if reason == "source_unavailable" else "source_denied")
    return await _launch_b2b_run(
        adapter, request, profile=profile, entry=entry, keys=keys,
        session_id=session_id, binding_digest=binding_digest, attempt_id=attempt_id,
        resolved=resolved, store=store, db=db)


async def _handle_b2b_prepare_post(adapter: Any, request: Any):
    """POST /p/<profile>/api/sessions/{id}/b2b-prepare — verify + attest; never admit."""
    state = _state_for(adapter)
    if state is None or not state.config.enabled:
        return _deny(404, "not_found")
    profile = _request_profile(request)
    if not profile:
        return _deny(404, "not_found")
    entry = state.config.profile_entry(profile)
    keys = state.keys.get(profile)
    if entry is None or keys is None:
        return _deny(404, "not_found")
    session_id = str(request.match_info.get("session_id", "") or "")
    if not _SESSION_ID_RE.fullmatch(session_id):
        return _deny(400, "invalid_session_id")
    binding_digest = session_id[4:]
    parsed, err = await _read_bounded_json(request)
    if err is not None:
        return err
    if set(parsed.keys()) != {"attempt_id", "binding_digest", "request_id"}:
        return _deny(400, "invalid_body")
    if parsed["binding_digest"] != binding_digest:
        return _deny(403, "binding_mismatch")
    attempt_id = parsed.get("attempt_id")
    if not _ATTEMPT_ID_RE.fullmatch(str(attempt_id or "")):
        return _deny(400, "invalid_attempt_id")
    request_id = parsed["request_id"]
    if not isinstance(request_id, str) or not _PREPARE_REQUEST_ID_RE.fullmatch(request_id):
        return _deny(400, "invalid_request_id")
    if (request.headers.get("Idempotency-Key") or "").strip() != attempt_id:
        return _deny(400, "idempotency_key_mismatch")
    db = await adapter._ensure_session_db_async()
    if db is None:
        return _deny(503, "store_unavailable")
    store = adapter._run_idempotency_store
    if not _store_durable(store):
        return _deny(503, "store_unavailable")
    resolved, reason = await _resolve_source_async(
        entry, keys, "prepare", attempt_id=attempt_id, profile=profile, session_id=session_id)
    if resolved is None:
        # Any signed-source invalidity collapses to one refusal shape — the
        # specific check is journal-side, never leaked to the caller.
        return _deny(503 if reason == "source_unavailable" else 403,
                     "source_unavailable" if reason == "source_unavailable" else "source_denied")
    return await _prepare_b2b_only(
        adapter, request, profile=profile, entry=entry, keys=keys,
        session_id=session_id, binding_digest=binding_digest, attempt_id=attempt_id,
        request_id=request_id, resolved=resolved, store=store, db=db)


async def _b2b_get(adapter: Any, request: Any, *, want_context: bool):
    """GET read-proof-gated status/context — SELECT-only, no writes, no dispatch."""
    from aiohttp import web
    state = _state_for(adapter)
    if state is None or not state.config.enabled:
        return _deny(404, "not_found")
    profile = _request_profile(request)
    if not profile:
        return _deny(404, "not_found")
    entry = state.config.profile_entry(profile)
    keys = state.keys.get(profile)
    if entry is None or keys is None:
        return _deny(404, "not_found")
    session_id = str(request.match_info.get("session_id", "") or "")
    attempt_id = str(request.match_info.get("attempt_id", "") or "")
    if not _SESSION_ID_RE.fullmatch(session_id) or not _ATTEMPT_ID_RE.fullmatch(attempt_id):
        return _deny(404, "not_found")
    binding_digest = session_id[4:]
    proof, reason = verify_read_proof(
        request.headers.get("X-Dubsar-Read-Proof"), entry=entry, keys=keys)
    if proof is None:
        return _deny(403, "read_proof_required")
    if any(proof[key] != value for key, value in (
            ("attempt_id", attempt_id), ("binding_digest", binding_digest),
            ("profile", profile), ("session_id", session_id))):
        return _deny(404, "not_found")
    store = adapter._run_idempotency_store
    if not _store_durable(store):
        return _deny(503, "store_unavailable")
    try:
        snapshot = store.b2b_snapshot(profile=profile, attempt_id=attempt_id)
    except Exception:
        return _deny(503, "artifact_unavailable")
    row = snapshot["attempt"] if snapshot else None
    if (row is None or row["binding_digest"] != binding_digest or row["session_id"] != session_id
            or row["requester_id"] != proof["requester_id"]):
        return _deny(404, "not_found")
    artifacts = snapshot["artifacts"]
    manifests = [{"kind": kind, "sha256": artifact["digest"], "bytes": len(artifact["payload"])}
                 for kind, artifact in artifacts.items()]
    identity = {"attempt_id": attempt_id, "run_id": row["run_id"], "profile": profile,
                "session_id": session_id, "binding_digest": binding_digest}
    if want_context:
        artifact = artifacts.get("context")
        if artifact is None:
            return _deny(404, "not_found")
        context = json.loads(artifact["payload"])
        return web.json_response({
            "object": "b2b.context", **identity,
            **{key: context[key] for key in
               ("view", "rendered", "context_digest", "rendered_digest", "source_basis_digest")},
            **{key: context[key] for key in ("view_digest", "source_basis_contract")
               if key in context},
            "artifact": next(item for item in manifests if item["kind"] == "context")})
    from gateway.platforms.api_server_runs import _owner_alive
    native = json.loads(row["native_status_json"])
    dead = not _owner_alive(row["owner_pid"], row["owner_started"])
    native_status = native.get("status")
    if dead and native_status not in {"completed", "failed", "cancelled", "interrupted"}:
        native_status = "interrupted"
    phase = row["status"]
    status = phase
    if (dead or native_status in {"failed", "cancelled", "interrupted"}) and phase in {
            "admitted", "context_ready", "dispatch_committed", "result_received"}:
        status = "indeterminate" if phase == "dispatch_committed" else "interrupted"
    source = json.loads(artifacts["source_bind"]["payload"])["response"]["body"]
    # Read revalidation (no rebuild/network): every returned artifact must still
    # agree with the durable dispatch + ORIGINAL stored context. Anything
    # inconsistent or a missing prerequisite => artifact_unavailable, never a leak.
    context_artifact = artifacts.get("context")
    dispatch_artifact = artifacts.get("provider_dispatch")
    context_view = (json.loads(context_artifact["payload"]).get("view")
                    if context_artifact else None)
    public = json.loads(artifacts["provider_result"]["payload"]) if "provider_result" in artifacts else None
    if public is not None:
        from agent.b2b_execution import validate_proposal, extract_allowed_refs
        native_request = (
            source.get("mission_request")
            if source.get("mission_inputs") is not None and source.get("tenant_id") is not None
            else None
        )
        allowed = extract_allowed_refs(context_view, native_request=native_request) \
            if context_view else ()
        parsed, _ = validate_proposal(public.get("text"), allowed)
        dispatch = json.loads(dispatch_artifact["payload"]) if dispatch_artifact else None
        if (parsed is None or parsed != public.get("proposal") or dispatch is None or
                public.get("attempt_id") != attempt_id or
                public.get("run_id") != row["run_id"] or
                public.get("binding_digest") != binding_digest or
                public.get("context_digest") != dispatch.get("context_digest") or
                public.get("request_digest") != dispatch.get("request_digest")):
            return _deny(503, "artifact_unavailable")
    proposal = json.loads(artifacts["proposal"]["payload"]) if "proposal" in artifacts else None
    if proposal is not None:
        _CLOSED15 = {"proposal_id", "attempt_id", "binding_digest", "profile", "session_id",
                     "project_id", "mission_id", "mission_revision", "context_digest",
                     "summary", "steps", "source_refs", "limitations", "state", "created_at"}
        if (set(proposal) != _CLOSED15 or
                proposal.get("attempt_id") != attempt_id or
                proposal.get("binding_digest") != binding_digest or
                proposal.get("session_id") != session_id or
                proposal.get("profile") != profile or
                proposal.get("state") != "prepared" or
                not proposal.get("created_at") or
                context_artifact is None or
                proposal.get("context_digest") !=
                json.loads(context_artifact["payload"]).get("context_digest") or
                public is None or
                any(proposal.get(k) != public.get("proposal", {}).get(k)
                    for k in ("summary", "steps", "source_refs", "limitations")) or
                len(artifacts["proposal"]["payload"]) > 32768):
            return _deny(503, "artifact_unavailable")
    return web.json_response({
        "object": "b2b.proposal_attempt", **identity,
        **{key: source[key] for key in ("requester_id", "project_binding_id", "project_id",
                                       "mission_id", "mission_revision")},
        "phase": phase, "status": status, "native_status": native_status,
        "stored_native_status": native.get("status"), "recovered": dead or native_status == "interrupted",
        "current": False, "historical": True, "artifacts": manifests,
        "result": public["proposal"] if public else None, "proposal": proposal})


def b2b_http_routes(adapter: Any):
    from gateway.platforms.api_server import _admit_api_agent_request
    admitted_post = _admit_api_agent_request(_handle_b2b_proposal_post)
    admitted_prepare = _admit_api_agent_request(_handle_b2b_prepare_post)

    async def post(request):
        auth = adapter._check_auth(request)
        if auth is not None or not adapter._expected_api_key():
            return auth if auth is not None else _deny(401, "auth_required")
        return await admitted_post(adapter, request)

    async def prepare(request):
        auth = adapter._check_auth(request)
        if auth is not None or not adapter._expected_api_key():
            return auth if auth is not None else _deny(401, "auth_required")
        return await admitted_prepare(adapter, request)

    async def status(request):
        auth = adapter._check_auth(request)
        if auth is not None or not adapter._expected_api_key():
            return auth if auth is not None else _deny(401, "auth_required")
        return await _b2b_get(adapter, request, want_context=False)

    async def context(request):
        auth = adapter._check_auth(request)
        if auth is not None or not adapter._expected_api_key():
            return auth if auth is not None else _deny(401, "auth_required")
        return await _b2b_get(adapter, request, want_context=True)

    return [
        ("POST", "/api/sessions/{session_id}/b2b-proposal", post),
        ("POST", "/api/sessions/{session_id}/b2b-prepare", prepare),
        ("GET", "/api/sessions/{session_id}/b2b-proposal/{attempt_id}", status),
        ("GET", "/api/sessions/{session_id}/b2b-proposal/{attempt_id}/context", context)]


def guarded_session_id(adapter: Any, session_id: Any, *, allow_genesis_get: bool = False):
    """``(session_id, None)`` to proceed or ``(None, error)``. Reserved ``b2b_`` ids deny
    every generic surface — EXCEPT the documented pre-binding exception
    (``allow_genesis_get``): a GET on a demonstrably empty, unbound L2a genesis row.
    Bound/binding rows always deny. Non-reserved ids pass through."""
    sid = str(session_id or "")
    if not _SESSION_ID_RE.fullmatch(sid):
        return sid, None
    if allow_genesis_get:
        return sid, None
    return None, _deny(404, "not_found")
