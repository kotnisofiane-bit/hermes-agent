"""Closed B2B operator config and native body validation.

Extracted from ``api_server_b2b.py`` so the launch surface stays below the
repository's 2 000-line bound. This module owns the exact P1 scalar mirrors,
the frozen catalogue, and the native N2/N4 body binding checks.
"""

from __future__ import annotations

import dataclasses
import os
import re
import types
from typing import Any, Dict, Mapping, Optional

from agent.b2b_execution import B2B_MISSION_ID, _deep_freeze
from gateway.platforms import api_server_b2b_native_authorization as _native_auth
from hermes_cli.providers import custom_provider_aliases

_PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
# Lot-1 native N2 lane: the catalogue may opt a project in with an exact
# {tenant_id, run_authorization?} stanza; only a deploy-bound prj_32 lane may
# carry it and its resolved body is the strictly extended shape.
_NATIVE_PROJECT_ID = re.compile(r"^prj_[0-9a-f]{32}$")
_NATIVE_TENANT_ID = re.compile(
    r"^[^\x00-\x1f\s](?:[^\x00-\x1f]{0,62}[^\x00-\x1f\s])?$")
_SHA256_PREFIXED = re.compile(r"^sha256:[0-9a-f]{64}$")
_NATIVE_ROUTE_KEYS = frozenset({"provider_id", "model", "model_version"})
_NATIVE_N4_KEYS = frozenset({"dataset_id", "core_public_key", "endpoint"}) | _NATIVE_ROUTE_KEYS
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
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OBSERVATION_KEYS = frozenset({
    "id", "source", "title", "model", "parent_session_id", "has_system_prompt",
    "has_model_config", "ended_at", "end_reason", "message_count", "tool_call_count",
    "api_call_count", "profile"})
_TITLE_MAX, _OBJECTIVE_MAX = 160, 1000
_CRITERION_MAX, _CRITERIA_MAX = 300, 20
_SOURCE_REF_MAX, _SOURCE_REFS_MAX = 300, 20
_MAX_NATIVE_PIECES = 20
# The native G2 route is bound to this baseline model even when the operator
# configures no native project at all. A legacy project that names it (or any
# configured native model) must never reach the gateway without signed Core
# authorization, whatever provider/base_url alias it declares.
_NATIVE_BASELINE_MODEL = "mistralai/mistral-large-4-1t-a52b"

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


class B2BConfigError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Scalar / wire helpers (exact P1 mirrors)
# ---------------------------------------------------------------------------

def _plain_object(v: Any) -> bool:
    return isinstance(v, Mapping)


def _normalized_model_name(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower().rsplit("/", 1)[-1]


def _route_url(value: Any) -> str:
    return value.strip().rstrip("/") if isinstance(value, str) else ""


_G2_PROVIDER_KEY = "b2b-g2"
_G2_CANONICAL_ALIASES = custom_provider_aliases(_G2_PROVIDER_KEY, _G2_PROVIDER_KEY)


def _g2_route_identity(gateway_config: Any) -> tuple:
    """Aliases and URLs the served ``providers.b2b-g2`` entry exposes."""
    aliases = set(_G2_CANONICAL_ALIASES)
    urls = set()
    providers = (gateway_config.get("providers")
                 if isinstance(gateway_config, Mapping) else None)
    entry = (providers.get(_G2_PROVIDER_KEY)
             if isinstance(providers, Mapping) else None)
    if isinstance(entry, Mapping):
        aliases.update(custom_provider_aliases(
            entry.get("name") or _G2_PROVIDER_KEY, _G2_PROVIDER_KEY))
        for key in ("api", "url", "base_url"):
            url = entry.get(key)
            if isinstance(url, str) and url.strip():
                urls.add(_route_url(url))
                break
    return frozenset(aliases), frozenset(urls)


def _native_catalogue(profiles: Mapping[str, Any]) -> tuple:
    """Models and loopback URLs the native G2 lane is configured to serve."""
    models = {_normalized_model_name(_NATIVE_BASELINE_MODEL)}
    urls = set()
    for profile_entry in profiles.values():
        for project in profile_entry["projects"].values():
            if project.get("native_n2") is None:
                continue
            models.add(_normalized_model_name(project["model"]))
            urls.add(_route_url(project["base_url"]))
    return models, urls


def _legacy_targets_native_gateway(
        project: Mapping[str, Any], models, urls,
        provider_aliases=frozenset()) -> bool:
    """True when a non-native project aliases any native G2 route identity."""
    if project.get("native_n2") is not None:
        return False
    requested = str(project.get("provider") or "")
    aliases = _G2_CANONICAL_ALIASES | provider_aliases
    return (bool(custom_provider_aliases(requested) & aliases)
            or _route_url(project.get("base_url")) in urls
            or _normalized_model_name(project.get("model")) in models)


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


def _validate_route_endpoint(value: Any, name: str) -> str:
    if (not isinstance(value, str) or not value.startswith("https://")
            or len(value) > 2048 or re.search(r"[\s\x00-\x1f\x7f-\x9f]", value)):
        raise B2BConfigError(f"b2b config: {name} must be an https URL")
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
        stanza = entry["native_n4"]
        if (native_n2 is None or not isinstance(stanza, Mapping)
                or set(stanza) != _NATIVE_N4_KEYS
                or not isinstance(stanza["dataset_id"], str)
                or not _native_auth._DATASET_ID.fullmatch(stanza["dataset_id"])
                or not isinstance(stanza["core_public_key"], str)
                or not _HEX64.fullmatch(stanza["core_public_key"])):
            raise B2BConfigError(f"b2b config: project {binding_id}: invalid native_n4")
        _validate_route_endpoint(stanza["endpoint"], f"project {binding_id}: native_n4.endpoint")
        for key in _NATIVE_ROUTE_KEYS:
            value = stanza[key]
            if (not isinstance(value, str) or not value or len(value) > 256
                    or _CONTROL_CHARS.search(value)):
                raise B2BConfigError(
                    f"b2b config: project {binding_id}: native_n4.{key}")
        if stanza["model"] != entry["model"]:
            raise B2BConfigError(
                f"b2b config: project {binding_id}: native_n4.model must equal model")
        native_n4 = dict(stanza)
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
    g2_models: frozenset
    g2_base_urls: frozenset
    g2_provider_aliases: frozenset

    """Frozen, fully-validated ``config.extra["b2b"]``."""

    def __init__(self, raw: Any, gateway_config: Any = None):
        if raw is None:
            object.__setattr__(self, "enabled", False)
            object.__setattr__(self, "profiles", types.MappingProxyType({}))
            object.__setattr__(self, "g2_models", frozenset(
                {_normalized_model_name(_NATIVE_BASELINE_MODEL)}))
            object.__setattr__(self, "g2_base_urls", frozenset())
            object.__setattr__(self, "g2_provider_aliases", _G2_CANONICAL_ALIASES)
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
        provider_aliases, g2_urls = _g2_route_identity(gateway_config)
        models, urls = _native_catalogue(parsed)
        urls |= g2_urls
        for profile_entry in parsed.values():
            for binding_id, project in profile_entry["projects"].items():
                if _legacy_targets_native_gateway(
                        project, models, urls, provider_aliases):
                    raise B2BConfigError(
                        f"b2b config: project {binding_id}: "
                        "legacy lane may not target the native G2 catalogue")
        if enabled and not parsed:
            raise B2BConfigError("b2b config: enabled profiles must be explicit")
        object.__setattr__(self, "enabled", enabled)
        object.__setattr__(self, "profiles", _deep_freeze(parsed))
        object.__setattr__(self, "g2_models", frozenset(models))
        object.__setattr__(self, "g2_base_urls", frozenset(urls))
        object.__setattr__(
            self, "g2_provider_aliases",
            _G2_CANONICAL_ALIASES | provider_aliases)

    def profile_entry(self, profile: str) -> Optional[Dict[str, Any]]:
        return self.profiles.get(profile)


def validate_b2b_config(extra: Any, gateway_config: Any = None) -> B2BConfig:
    raw = (extra or {}).get("b2b") if isinstance(extra, Mapping) else None
    return B2BConfig(raw, gateway_config=gateway_config)


# ---------------------------------------------------------------------------
# Native resolved-body binding
# ---------------------------------------------------------------------------

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
