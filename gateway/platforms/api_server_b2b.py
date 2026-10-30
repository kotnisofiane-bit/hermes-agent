"""B2B governed launch surface (KOT-263 H1): closed operator config, signed P1 source client,
typed routes and admission. Only the operator's ``config.extra["b2b"]`` enables it; every value
is validated at startup — nothing request-supplied is authority.

Routes (mirrored under ``/p/<profile>/``):
    POST /api/sessions/{id}/b2b-proposal
    GET  /api/sessions/{id}/b2b-proposal/{attempt_id}
    GET  /api/sessions/{id}/b2b-proposal/{attempt_id}/context
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import re
import time
import types
import uuid
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from agent.b2b_execution import (
    B2BTerminalRefusal, BoundExecution, R2_SCHEMA_PINS, _deep_freeze, _plain_json,
    _public_text, canonical_json, is_b2b_attempt_id, is_b2b_session_id, json_utf8,
    source_basis, mission_prompt, recheck_context, validate_proposal, extract_allowed_refs)

logger = logging.getLogger("gateway.platforms.api_server")

_DOMAIN = b"dubsar.b2b-source/1\x00"
_VERSION = "dubsar.b2b-source/1"
_OPERATION = "resolve"
_RESPONSE_OPERATION = "resolved"
_READ_OPERATION = "read"
_PURPOSES = frozenset({"bind", "before_provider", "before_seal"})
_BODY_MAX = 65536
_SOURCE_DEADLINE_S = 1.0
_REQUEST_TTL_S = 10
_MAX_WINDOW_S = 30
_SIG_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256_FIELD = re.compile(r"^(sha256:)?[0-9a-f]{64}$")
_SESSION_ID_RE = re.compile(r"^b2b_[0-9a-f]{64}$")
_ATTEMPT_ID_RE = re.compile(r"^b2bp_[0-9a-f]{64}$")
_OBJECT_ID = re.compile(r"^[0-9a-f]{24}$")
_PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_MISSION_ID = re.compile(r"^DUB-[0-9]{3}$")
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
_OBSERVATION_KEYS = frozenset({
    "id", "source", "title", "model", "parent_session_id", "has_system_prompt",
    "has_model_config", "ended_at", "end_reason", "message_count", "tool_call_count",
    "api_call_count", "profile"})
_TITLE_MAX, _OBJECTIVE_MAX = 160, 1000
_CRITERION_MAX, _CRITERIA_MAX = 300, 20
_SOURCE_REF_MAX, _SOURCE_REFS_MAX = 300, 20

_B2B_CONFIG_ROOT_KEYS = frozenset({"enabled", "profiles"})
_PROFILE_ENTRY_KEYS = frozenset({
    "source_url", "portal_issuer", "hermes_issuer",
    "portal_public_key_pem", "hermes_private_key_pem", "projects"})
_PROJECT_ENTRY_KEYS = frozenset({
    "project_id", "bot_id", "profile_id", "allowed_namespaces", "context_contract_root",
    "model", "provider", "base_url", "api_mode", "logical_mission", "project_context"})
_PROJECT_CONTEXT_KEYS = frozenset({"allocation_root", "project_id", "start"})
_API_MODES = frozenset({"chat_completions"})
_PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ECMA_WHITESPACE = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005" \
                   "\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"

_ATTEMPT_FORMAT = "dubsar.b2b-proposal-attempt/1"
_ATTEMPT_OPERATION = "proposal-v1"


class B2BConfigError(ValueError):
    pass


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
    """Only the explicit, natively resolved /p/<profile>/ typed surface is admitted."""
    from gateway.platforms.api_server import _api_request_profile
    declared = request.match_info.get("profile")
    if not isinstance(declared, str) or not _PROFILE_NAME.fullmatch(declared):
        return None
    active = _api_request_profile.get()
    if declared != (active or "default"):
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


def _validate_project_entry(entry: Any, binding_id: str) -> Dict[str, Any]:
    if not isinstance(entry, Mapping) or set(entry.keys()) != _PROJECT_ENTRY_KEYS:
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
    base_url = _req_str(entry.get("base_url"), "project.base_url", allow_none=False)
    try:
        url = urlsplit(base_url)
        if (url.scheme not in {"http", "https"} or not url.hostname or url.username is not None or
                url.password is not None or url.query or url.fragment or base_url != base_url.strip()):
            raise ValueError
        _ = url.port
    except ValueError:
        raise B2BConfigError(f"b2b config: project {binding_id}: explicit credential-free base_url required") from None
    if entry.get("api_mode") not in _API_MODES:
        raise B2BConfigError(f"b2b config: project {binding_id}: api_mode chat_completions only")
    logical_mission = entry.get("logical_mission")
    if logical_mission is not None:
        _req_str(logical_mission, "project.logical_mission", allow_none=False)
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
    return {
        "project_id": project_id,
        "bot_id": entry["bot_id"], "profile_id": entry["profile_id"],
        "allowed_namespaces": list(entry["allowed_namespaces"]),
        "context_contract_root": entry["context_contract_root"],
        "model": entry["model"], "provider": entry["provider"],
        "base_url": entry["base_url"], "api_mode": entry["api_mode"],
        "logical_mission": logical_mission,
        "project_context": dict(pc) if pc is not None else None}


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
                     body: Mapping, *, audience: Optional[str] = None) -> Tuple[Dict[str, Any], bytes]:
    """Mint a signed request envelope; returns (envelope, exact signed request bytes)."""
    now = int(time.time())
    env = {
        "version": _VERSION,
        "issuer": entry["hermes_issuer"],
        "audience": audience or entry["portal_issuer"],
        "operation": operation,
        "request_id": str(uuid.uuid4()),
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
                          session_id: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Closed 20-field resolved response; every P1 verifyResolvedSource check mirrored."""
    if not _exact_keys(body, _RESPONSE_BODY_KEYS) or not _scalar_ok(body):
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
    if not _valid_mission_request(body.get("mission_request")):
        return None, "body_mission_request"
    basis = {
        "format": "dubsar.b2b-agent-session-binding/1", "requester_id": body["requester_id"],
        "project_id": body["project_binding_id"], "mission_id": body["mission_id"],
        "mission_revision": body["mission_revision"]}
    if hashlib.sha256(canonical_json(basis)).hexdigest() != binding:
        return None, "body_binding_tuple"
    return dict(body), "ok"


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
    out, reason = _verify_resolved_body(
        verified.get("body"), request=env, profile=profile, session_id=session_id)
    if out is None:
        return None, reason
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
        return (project is not None and
                _policy_digest(self.profile, entry, project, self.policy) == self._fingerprint)

    def _matches_source(self, resolved: Mapping[str, Any]) -> bool:
        fields = (
            "attempt_id", "binding_digest", "requester_id", "project_id",
            "project_binding_id", "mission_id", "mission_revision", "profile", "session_id",
            "reservation_ref", "request_digest", "ticket_digest", "authority_basis_digest",
            "authority_digest", "observation_genesis", "mission_request")
        return (resolved.get("source_state") == "active" and self.assert_current_policy() and
                all(json_utf8(resolved.get(key)) == json_utf8(self.policy.get(key))
                    for key in fields))

    def _source_matches_context(self, resolved: Mapping[str, Any]) -> bool:
        receipt = self.context_receipt
        return (receipt is not None and
                resolved.get("mission_source_digest") ==
                receipt.view["my_work"]["mission"]["source_digest"])

    def block(self, reason: str) -> None:
        if reason == "context_unavailable":
            status = "context_unavailable"
        elif "context" in reason:
            status = "context_stale"
        elif "policy" in reason or "capability" in reason:
            status = "policy_changed"
        elif "source" in reason:
            status = "source_denied"
        elif reason in ("provider_result_unavailable", "result_unattested",
                        "middleware_response_unattested"):
            # NO-RECEIPT conditions: the dispatch may or may not have reached the
            # provider — committed marker + absent durable result => indeterminate,
            # never the known-invalid result_invalid.
            status = "failed"
        elif "result" in reason or "response" in reason:
            status = "result_invalid"
        else:
            status = "failed"
        row = self._store.b2b_attempt(profile=self.profile, attempt_id=self.attempt_id)
        if (row is not None and row["status"] == "dispatch_committed" and
                self._store.b2b_artifact(attempt_id=self.attempt_id, kind="provider_result") is None
                and status != "result_invalid"):
            status = "indeterminate"
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

    def cas_dispatch(self, *, request_digest: str, receipt: Any) -> bool:
        resolved = self._before_provider
        if (receipt is not self.context_receipt or resolved is None or
                not self._matches_source(resolved) or not self._source_matches_context(resolved)):
            return False
        now = time.time()
        if not all(env["issued_at"] <= now < env["expires_at"] for env in
                   (resolved["_signed_request"], resolved["_signed_response"])):
            self.block("source_window_closed")
            return False
        return self._store.b2b_cas_dispatch(
            profile=self.profile, attempt_id=self.attempt_id,
            source_record=_source_record(resolved),
            dispatch_record=json_utf8({
                "format": "dubsar.b2b-provider-dispatch/1",
                "attempt_id": self.attempt_id, "run_id": self.run_id,
                "binding_digest": self.binding_digest, "request_digest": request_digest,
                "context_digest": receipt.digest,
                "source_basis_digest": receipt.source_basis_digest,
                "rendered_digest": receipt.rendered_digest,
                "model": self.policy["project"]["model"],
                "provider": self.policy["project"]["provider"], "committed_at": now}))

    def commit_result(self, *, text: Any, parsed: Any, reason: str) -> None:
        receipt = self.context_receipt
        valid, checked = validate_proposal(
            text, extract_allowed_refs(receipt.view) if receipt else ())
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
            text, extract_allowed_refs(self.context_receipt.view) if self.context_receipt else ())
        return (stored.get("attempt_id") == self.attempt_id and stored.get("run_id") == self.run_id
                and stored.get("text") == text and parsed is not None
                and stored.get("proposal") == parsed)

    def put_context(self, receipt: Any) -> None:
        """Persist the published context (view + rendered bytes + digest) once."""
        payload = json_utf8({
            "format": "dubsar.b2b-context-artifact/1", "attempt_id": self.attempt_id,
            "run_id": self.run_id, "view": receipt.view,
            "rendered": receipt.rendered.decode("utf-8"), "turn_id": receipt.turn_id,
            "context_digest": receipt.digest, "rendered_digest": receipt.rendered_digest,
            "source_basis_digest": receipt.source_basis_digest})
        if not self._store.b2b_commit_context(
                profile=self.profile, attempt_id=self.attempt_id, payload=payload):
            raise B2BTerminalRefusal("context_commit_failed")
        self.context_receipt = receipt

    async def resolve_before_seal(self) -> Optional[Dict[str, Any]]:
        resolved, reason = await _resolve_source_async(
            self.entry, self.keys, "before_seal", attempt_id=self.attempt_id,
            profile=self.profile, session_id=self.session_id)
        if (resolved is None or not self._matches_source(resolved) or
                not self._source_matches_context(resolved)):
            self.block("source_before_seal_denied")
            return None
        return resolved

    def seal(self, *, source_before_seal: Mapping[str, Any], rechecked_view: Mapping[str, Any],
             created_at: str) -> Dict[str, Any]:
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
        parsed, _ = validate_proposal(public["text"], extract_allowed_refs(receipt.view))
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
        fresh_basis_bytes = json_utf8(source_basis(rechecked_view))
        if fresh_basis_bytes != receipt.source_basis_bytes:
            raise B2BTerminalRefusal("context_stale")
        stored = self._store.b2b_seal(
            profile=self.profile, attempt_id=self.attempt_id,
            artifacts={
                "source_before_seal": _source_record(source_before_seal),
                "context_recheck": json_utf8({
                    "format": "dubsar.b2b-context-recheck/1", "attempt_id": self.attempt_id,
                    "run_id": self.run_id, "view": rechecked_view,
                    "source_basis_digest": hashlib.sha256(fresh_basis_bytes).hexdigest()}),
                "proposal": json_utf8(proposal)})
        if stored is None:
            raise B2BTerminalRefusal("seal_commit_failed")
        return json.loads(stored)


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
        "mission_request": resolved["mission_request"], "project": project}
    fingerprint = _policy_digest(profile, entry, project, policy)
    scope = _run_scope(profile, resolved["requester_id"], binding_digest)
    initial_status = {"status": "queued", "session_id": session_id, "created_at": time.time()}
    # Lost-ACK replay is allowed even while the original holds the final native worker slot.
    if store.b2b_attempt(profile=profile, attempt_id=attempt_id) is None:
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
    outcome = store.b2b_admit(
        profile=profile, session_id=session_id, binding_digest=binding_digest,
        attempt_id=attempt_id, fingerprint=fingerprint,
        binding_row={"profile": profile, "session_id": session_id,
                     "binding_digest": binding_digest,
                     "policy_json": json_utf8(policy).decode("utf-8")},
        attempt_row={"attempt_id": attempt_id, "binding_digest": binding_digest,
                     "profile": profile, "session_id": session_id, "status": "admitted",
                     "run_id": run_id, "requester_id": resolved["requester_id"],
                     "source_bind": _source_record(resolved)},
        run_scope=scope, run_key=attempt_id, run_id=run_id,
        run_fingerprint=fingerprint, run_status=initial_status,
        owner_pid=getattr(adapter, "_run_owner_pid", 0),
        owner_started=getattr(adapter, "_run_owner_started", 0))
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
    sink = _AttemptSink(adapter, store, profile=profile, entry=entry, keys=keys,
                        attempt_id=attempt_id, session_id=session_id,
                        binding_digest=binding_digest, run_id=stored_run_id, policy=policy)
    cap = BoundExecution(
        profile=profile, session_id=session_id, binding_digest=binding_digest,
        attempt_id=attempt_id, run_id=stored_run_id, policy=dict(policy),
        sink=sink, created_at=time.time())
    launched = await _spawn_run(adapter, request, cap=cap, resolved=resolved,
                                session_id=session_id, run_id=stored_run_id, profile=profile)
    if launched is None:
        sink.block("launch_failed")
        return _deny(503, "launch_failed")
    from aiohttp import web
    return web.json_response({
        "object": "b2b.proposal_attempt", "attempt_id": attempt_id,
        "binding_digest": binding_digest, "run_id": stored_run_id, "profile": profile,
        "session_id": session_id, "status": "admitted"})


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
        allowed = extract_allowed_refs(context_view) if context_view else ()
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

    async def post(request):
        auth = adapter._check_auth(request)
        if auth is not None or not adapter._expected_api_key():
            return auth if auth is not None else _deny(401, "auth_required")
        return await admitted_post(adapter, request)

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


async def guard_generic_lineage(adapter: Any, db: Any, session_id: Any):
    """VALIDATE the raw id -> resume tip -> parent chain; every encountered id passes
    the namespace guard so a protected row can never be reached through lineage,
    aliasing or a second resolution. Returns ``(ORIGINAL session_id, None)`` — callers
    keep their ordinary selected id for reads — or ``(None, error)``. Missing ordinary
    ancestors stop the walk; cycles or >64 ancestors fail closed; a missing/None tip
    normalizes to the original id."""
    import asyncio as _a
    sid, err = guarded_session_id(adapter, session_id)
    if err is not None:
        return None, err
    tip = sid
    resolver = getattr(db, "resolve_resume_session_id", None)
    if callable(resolver):
        try:
            tip = await _a.to_thread(resolver, sid)
        except Exception:
            return None, _deny(404, "not_found")  # lookup failure — fail closed
        tip = str(tip) if tip else sid
        _, err = guarded_session_id(adapter, tip)
        if err is not None:
            return None, err
    seen = set()
    current = tip
    for _ in range(64):
        if current in seen:
            return None, _deny(404, "not_found")  # lineage cycle — fail closed
        seen.add(current)
        try:
            row = await _a.to_thread(db.get_session, current)
        except Exception:
            return None, _deny(404, "not_found")  # lookup failure — fail closed
        if not row:
            break  # missing ordinary ancestor — nothing more to protect
        parent = row.get("parent_session_id")
        if not parent:
            break
        parent, err = guarded_session_id(adapter, parent)
        if err is not None:
            return None, err
        current = parent
    else:
        return None, _deny(404, "not_found")  # >64 ancestors — fail closed
    return sid, None  # ORIGINAL selected id, not the tip — callers keep their read semantics
