"""B2B governed execution capability (KOT-263 H1).

A ``BoundExecution`` is minted host-side only after a verified P1 source exchange; it is the
single frozen identity/policy object the terminal guard and artifact sinks consult. Nothing
request-supplied mints or mutates it — it is bound per ``(profile, session_id)`` through a
ContextVar at launch admission and reset in ``finally``.

The context seam is a placeholder contract for C1: ``publish_context`` validates and freezes a
caller-supplied view/rendered pair; ``register_context_recheck`` stores one per-capability
callable a trusted producer uses to re-qualify before seal. No HTTP publication and no
AgentContext builder invocation in H1.
"""

from __future__ import annotations

import contextvars
import dataclasses
import hashlib
import json
import math
import re
import threading
import time
import types
import weakref
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    Draft202012Validator = Registry = Resource = None

_B2B_ID_RE = re.compile(r"^b2b_[0-9a-f]{64}$")
_B2BP_ID_RE = re.compile(r"^b2bp_[0-9a-f]{64}$")
_REF_FIELD_NAMES = frozenset(
    {"references", "evidence_refs", "source_refs", "ref", "reference", "proof_ref", "receipt_ref"})

PROPOSAL_LIMITS = {
    "summary": (1, 2000), "steps": (1, 12), "step": (1, 500),
    "source_refs": (0, 50), "source_ref": (1, 512),
    "limitations": (0, 12), "limitation": (1, 500),
    "max_public_bytes": 32768}
CONTEXT_MAX_BYTES = 262_144
_PROPOSAL_KEYS = frozenset({"summary", "steps", "source_refs", "limitations"})
_SOURCE_BASIS_KEYS = (
    "format", "bot_id", "profile_id", "project_id", "mission_id", "mission_binding",
    "identity_source", "resolution", "namespaces_searched", "namespaces_refused",
    "coverage", "limits", "my_work", "memory", "operational_context", "accepted_context")
R2_SCHEMA_PINS = types.MappingProxyType({
    "agent-context-r2.schema.json":
        "8615f3b4730acbabc614cd7cc770730be244888b59cc69957f14d4f520dbd0e2",
    "mission-binding.schema.json":
        "919264ea23b6ef458a8fa5ac49769c2a11fc2dcf5bedbefac30ce56d0d2aab16",
    "my-work-mission-view.schema.json":
        "3a8c7eb91e88b3ce0f92335a6bf91731d96a925648351f3187fd30b71621d9fa",
    "my-work-mission-authority-view.schema.json":
        "e33b996a46fcc77ce71282140ecf8e9e166d5da2566da355c94a9fa026551933",
})


def b2b_session_id(binding_digest: str) -> str:
    return "b2b_" + binding_digest


def is_b2b_session_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_B2B_ID_RE.fullmatch(value))


def is_b2b_attempt_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_B2BP_ID_RE.fullmatch(value))


def _deep_freeze(value: Any) -> Any:
    """Recursive immutability PRESERVING dict/list distinction (maps stay map-shaped)."""
    if isinstance(value, Mapping):
        return types.MappingProxyType({str(k): _deep_freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(v) for v in value)
    return value


def _plain_json(value: Any, depth: int = 0) -> Any:
    """Copy JSON values without coercing keys, losing list order or accepting NaN."""
    if depth > 64:
        raise B2BTerminalRefusal("json_depth")
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise B2BTerminalRefusal("json_key")
            _reject_bad_unicode(key)
            result[key] = _plain_json(item, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_plain_json(item, depth + 1) for item in value]
    if isinstance(value, str):
        _reject_bad_unicode(value)
        return value
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise B2BTerminalRefusal("json_scalar")


def json_utf8(value: Any) -> bytes:
    """Artifact/context serialization, distinct from the integer-only P1 wire."""
    return json.dumps(_plain_json(value), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def strict_public_json(text: str) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def nonfinite(_):
        raise ValueError("nonfinite")

    return _plain_json(json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite))


def source_basis(view: Mapping[str, Any]) -> Dict[str, Any]:
    result = {key: _plain_json(view.get(key)) for key in _SOURCE_BASIS_KEYS}
    if "automation_results" in view:
        result["automation_results"] = _plain_json(view["automation_results"])
    return result


def native_context_digest(view: Mapping[str, Any]) -> str:
    basis = _plain_json(view)
    basis.pop("context_digest", None)
    bounds = basis.get("bounds")
    if isinstance(bounds, dict):
        bounds.pop("serialized_bytes", None)
        bounds.pop("render_chars", None)
    return hashlib.sha256(json_utf8(basis)).hexdigest()


def _deny_schema_fetch(uri: str):
    raise ValueError("unregistered schema reference")


def validate_context_schema(view: Mapping[str, Any], contract_root: Any) -> Dict[str, Any]:
    """Load only the four frozen Contracts blobs; no filesystem or network ref fallback."""
    if Draft202012Validator is None or not isinstance(contract_root, str) or not contract_root:
        raise B2BTerminalRefusal("context_contract_unavailable")
    root = Path(contract_root)
    if not root.is_absolute():
        raise B2BTerminalRefusal("context_contract_unavailable")
    schemas = {}
    try:
        for name, pin in R2_SCHEMA_PINS.items():
            with (root / name).open("rb") as stream:
                raw = stream.read(1_048_577)
            if len(raw) > 1_048_576 or hashlib.sha256(raw).hexdigest() != pin:
                raise ValueError("schema pin")
            schemas[name] = strict_public_json(raw.decode("utf-8"))
        registry = Registry(retrieve=_deny_schema_fetch).with_resources(
            (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values())
        plain = _plain_json(view)
        validator = Draft202012Validator(schemas["agent-context-r2.schema.json"],
                                        registry=registry)
        if next(validator.iter_errors(plain), None) is not None:
            raise B2BTerminalRefusal("context_schema_invalid")
    except B2BTerminalRefusal:
        raise
    except Exception:
        raise B2BTerminalRefusal("context_contract_unavailable") from None
    return plain


def _canonical_json(value: Any) -> bytes:
    """Session-wire canonical JSON: keys sorted by UTF-16-BE code units, no spaces,
    raw scalar Unicode, safe integers only."""
    if value is None or isinstance(value, bool):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, int):
        if not (-(2 ** 53) + 1 <= value <= 2 ** 53 - 1):
            raise ValueError("canonical json: unsafe integer")
        return str(value).encode("ascii")
    if isinstance(value, float):
        raise ValueError("canonical json: float not permitted")
    if isinstance(value, str):
        _reject_bad_unicode(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, Mapping):
        parts = []
        for key in sorted(value.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass")):
            if not isinstance(key, str):
                raise ValueError("canonical json: non-string key")
            _reject_bad_unicode(key)
            parts.append(b'"' + _escape_json_string(key) + b'":' + _canonical_json(value[key]))
        return b"{" + b",".join(parts) + b"}"
    if isinstance(value, (list, tuple)):
        return b"[" + b",".join(_canonical_json(v) for v in value) + b"]"
    raise ValueError(f"canonical json: unsupported {type(value).__name__}")


def _escape_json_string(s: str) -> bytes:
    return json.dumps(s, ensure_ascii=False, separators=(",", ":")).encode("utf-8")[1:-1]


def _reject_bad_unicode(s: str) -> None:
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise ValueError("lone surrogate not permitted")


def canonical_json(value: Any) -> bytes:
    return _canonical_json(value)


def _collect_reference_strings(value: Any, *, _in_ref: bool = False, _out=None) -> list:
    out = _out if _out is not None else []
    if isinstance(value, Mapping):
        for k, v in value.items():
            _collect_reference_strings(
                v, _in_ref=_in_ref or (isinstance(k, str) and k in _REF_FIELD_NAMES), _out=out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _collect_reference_strings(v, _in_ref=_in_ref, _out=out)
    elif isinstance(value, str) and _in_ref:
        out.append(value)
    return out


def extract_allowed_refs(view: Any) -> Tuple[str, ...]:
    """Reference whitelist from the ORIGINAL validated mapping — reference-designated
    field names only, never arbitrary strings."""
    if not isinstance(view, Mapping):
        return ()
    return tuple(_collect_reference_strings(view))


# ---------------------------------------------------------------------------
# Bound execution capability
# ---------------------------------------------------------------------------

class B2BTerminalRefusal(RuntimeError):
    """Raised when a B2B turn reaches the terminal without satisfying an invariant."""


@dataclasses.dataclass(frozen=True)
class ContextReceipt:
    """Frozen accepted-context artifact descriptor; ``view`` stays a recursively
    immutable mapping (dict/list shape preserved for reference extraction)."""

    view: Any
    rendered: bytes
    digest: str
    turn_id: str
    source_basis: Any
    accepted_at: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "view", _deep_freeze(dict(self.view)))
        object.__setattr__(self, "rendered", bytes(self.rendered))
        object.__setattr__(self, "source_basis", _deep_freeze(self.source_basis))

    @property
    def view_bytes(self) -> bytes:
        return json_utf8(self.view)

    @property
    def rendered_digest(self) -> str:
        return hashlib.sha256(self.rendered).hexdigest()

    @property
    def source_basis_bytes(self) -> bytes:
        return json_utf8(self.source_basis)

    @property
    def source_basis_digest(self) -> str:
        return hashlib.sha256(self.source_basis_bytes).hexdigest()


@dataclasses.dataclass(frozen=True)
class BoundExecution:
    """Frozen B2B capability: identity tuple, policy, sink. Minted host-side only.
    ``policy`` is a recursively immutable mapping; no request body can mint it."""

    profile: str
    session_id: str
    binding_digest: str
    attempt_id: str
    run_id: str
    policy: Any          # deep-frozen mapping
    sink: Any            # durable artifact sink owned by the adapter-side launcher
    created_at: float
    _recheck: Any = dataclasses.field(default=None, repr=False, compare=False)
    _receipt: Any = dataclasses.field(default=None, repr=False, compare=False)
    _agent_ref: Any = dataclasses.field(default=None, repr=False, compare=False)
    _context_lock: Any = dataclasses.field(default_factory=threading.RLock,
                                         repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy", _deep_freeze(dict(self.policy or {})))

    def policy_get(self, key: str, default: Any = None) -> Any:
        return self.policy.get(key, default) if isinstance(self.policy, Mapping) else default

    @property
    def tuple(self) -> Dict[str, str]:
        return {"profile": self.profile, "session_id": self.session_id,
                "binding_digest": self.binding_digest, "attempt_id": self.attempt_id,
                "run_id": self.run_id}

    @property
    def context_receipt(self) -> Optional[ContextReceipt]:
        return self._receipt

    @property
    def current_turn_id(self) -> Optional[str]:
        agent = self._agent_ref() if self._agent_ref is not None else None
        value = getattr(agent, "_current_turn_id", None)
        return value if isinstance(value, str) and value else None

    # -- C1-facing seams (host-minted only; no HTTP path mints these) --

    def register_context_recheck(self, callback: Callable) -> None:
        """One per-capability recheck callable; a second registration refuses."""
        with self._context_lock:
            if self._recheck is not None or not callable(callback):
                raise B2BTerminalRefusal("context_recheck_already_registered")
            object.__setattr__(self, "_recheck", callback)

    def context_recheck(self) -> Optional[Mapping[str, Any]]:
        cb = self._recheck
        return cb(self) if cb is not None else None

    def publish_context(self, view: Mapping[str, Any], rendered: Any, *,
                        turn_id: str) -> ContextReceipt:
        """Validate, freeze and persist one context publication through the sink."""
        with self._context_lock:
            receipt = publish_context(self, view, rendered, turn_id=turn_id)
            object.__setattr__(self, "_receipt", receipt)
            return receipt


_execution_var: contextvars.ContextVar[Optional[BoundExecution]] = contextvars.ContextVar(
    "hermes_b2b_execution", default=None)


def bind_execution(cap: BoundExecution) -> contextvars.Token:
    return _execution_var.set(cap)


def reset_execution(token: contextvars.Token) -> None:
    _execution_var.reset(token)


def current_execution(profile: str = "", session_id: str = "") -> Optional[BoundExecution]:
    """The bound capability when this context IS the admitted B2B lane, else ``None``."""
    cap = _execution_var.get()
    if cap is None:
        return None
    if session_id and cap.session_id != session_id:
        return None
    if profile and cap.profile != profile:
        return None
    return cap


def require_execution(agent: Any) -> Optional[BoundExecution]:
    """Terminal helper: this lane's bound cap. Refuses when a B2B session has no cap OR
    an ACTIVE cap exists that doesn't match this agent/session — never silently drops a
    B2B lane into the unguarded non-B2B branch."""
    session_id = str(getattr(agent, "session_id", "") or "")
    cap = _execution_var.get()
    tagged = vars(agent).get("_b2b_execution")
    if tagged is not None and (not isinstance(tagged, BoundExecution) or
                               tagged is not cap or tagged.session_id != session_id):
        raise B2BTerminalRefusal("b2b_capability_mismatch")
    if is_b2b_session_id(session_id):
        if cap is None or cap.session_id != session_id:
            raise B2BTerminalRefusal("b2b_capability_missing")
        if tagged is not cap:
            raise B2BTerminalRefusal("b2b_agent_binding_missing")
        if cap._agent_ref is None or cap._agent_ref() is not agent:
            raise B2BTerminalRefusal("b2b_agent_binding_mismatch")
        from hermes_constants import get_hermes_home
        if str(get_hermes_home().resolve()) != cap.policy_get("profile_home"):
            raise B2BTerminalRefusal("b2b_profile_mismatch")
        return cap
    if cap is not None:
        raise B2BTerminalRefusal("b2b_capability_mismatch")
    return None


def install_bounded_agent_policy(agent: Any, cap: BoundExecution) -> None:
    """Host-only attachment after construction under the exact native profile scope."""
    if (current_execution(cap.profile, cap.session_id) is not cap or
            agent.session_id != cap.session_id or cap._agent_ref is not None):
        raise B2BTerminalRefusal("b2b_agent_binding_mismatch")
    agent._b2b_execution = cap
    object.__setattr__(cap, "_agent_ref", weakref.ref(agent))
    agent._disable_streaming = True
    # The retry loop runs ``while retry_count < _api_max_retries``: 0 would skip
    # the guarded call entirely, so one attempt and zero retries means 1.
    agent._api_max_retries = 1
    agent._auto_recovery_cycles = 0
    agent.compression_enabled = False
    agent.codex_app_server_auto_compaction = False
    agent.codex_responses_native_compaction = False
    agent._fallback_chain = []
    if getattr(agent, "context_compressor", None) is not None:
        agent.context_compressor._micro_compact_enabled = False

    def refuse_alternate(*args, **kwargs):
        raise B2BTerminalRefusal("b2b_alternate_api_call")

    for name in ("_direct_api_call", "_interruptible_api_call",
                 "_interruptible_streaming_api_call", "_streaming_api_call",
                 "_compress_context"):
        if callable(getattr(agent, name, None)):
            setattr(agent, name, refuse_alternate)


# ---------------------------------------------------------------------------
# Context publication: pinned schema AND host-owned binding qualification.
# ---------------------------------------------------------------------------

def _qualify_memory_relation(relation, allowed_namespaces, binding) -> None:
    namespace = relation.get("namespace_id")
    if not isinstance(namespace, str) or namespace not in allowed_namespaces:
        raise B2BTerminalRefusal("context_memory_namespace")
    provenance = relation.get("provenance")
    if not isinstance(provenance, Mapping):
        raise B2BTerminalRefusal("context_memory_provenance")
    keys = ("mywork_mission_id", "mywork_mission_revision", "mywork_mission_authority_digest")
    actual = tuple(provenance.get(key) for key in keys)
    expected = (binding["mission_id"], binding["revision"], binding["authority_digest"])
    if actual != (None, None, None):
        if actual != expected or type(actual[1]) is not int:
            raise B2BTerminalRefusal("context_memory_mission")


def qualify_context_view(cap: BoundExecution, view: Mapping[str, Any]) -> Dict[str, Any]:
    project = cap.policy_get("project", {})
    plain = validate_context_schema(view, project.get("context_contract_root"))
    if plain["context_digest"] != native_context_digest(plain):
        raise B2BTerminalRefusal("context_digest_invalid")
    if (plain["resolution"] != "governed_bound" or
            plain["identity_source"] != "my_work_mission_authority"):
        raise B2BTerminalRefusal("context_identity_source")
    for key in ("project_id", "mission_id"):
        if plain[key] != cap.policy_get(key):
            raise B2BTerminalRefusal("context_identity_mismatch")
    for key in ("bot_id", "profile_id"):
        if plain[key] != project.get(key):
            raise B2BTerminalRefusal("context_catalogue_mismatch")
    expected = {
        "status": "governed", "project_id": cap.policy_get("project_id"),
        "mission_id": cap.policy_get("mission_id"),
        "revision": cap.policy_get("mission_revision"),
        "basis_digest": cap.policy_get("authority_basis_digest"),
        "authority_digest": cap.policy_get("authority_digest"),
        "scope": "personal-local", "issuer": "dubsar-my-work",
        "source": "my_work_mission_authority",
        "source_contract": "dubsar.my-work-mission-view/1",
    }
    binding = plain["mission_binding"]
    if any(binding.get(key) != value for key, value in expected.items()):
        raise B2BTerminalRefusal("context_authority_mismatch")
    if (plain["resolved_focus_key"] != "mission:" + expected["mission_id"] or
            plain["resolved_subject_key"] != "project:" + expected["project_id"]):
        raise B2BTerminalRefusal("context_selection_mismatch")
    allowed = set(project.get("allowed_namespaces") or ())
    searched = plain["namespaces_searched"]
    if (not searched or len(set(searched)) != len(searched) or
            not set(searched) <= allowed or set(searched) & set(plain["namespaces_refused"])):
        raise B2BTerminalRefusal("context_namespaces")
    memory, my_work, oc = (plain[key] for key in ("memory", "my_work", "operational_context"))
    if any(source["availability"] != "available" for source in (memory, my_work, oc)):
        raise B2BTerminalRefusal("context_source_unavailable")
    if any(source["freshness"] != "current" for source in (memory, oc)):
        raise B2BTerminalRefusal("context_source_stale")
    mission = my_work.get("mission")
    if (my_work["source"] != "get_mission_context" or not isinstance(mission, dict) or
            mission["availability"] != "available" or
            mission["project_id"] != expected["project_id"] or
            mission["mission_id"] != expected["mission_id"] or
            mission["ticket_id"] != expected["mission_id"] or
            mission["source_digest"] != binding["source_digest"]):
        raise B2BTerminalRefusal("context_my_work_mismatch")
    authority = mission["mission_authority"]
    if (authority["availability"] != "available" or
            any(authority[key] != expected[key] for key in
                ("mission_id", "revision", "basis_digest", "authority_digest", "scope", "issuer"))):
        raise B2BTerminalRefusal("context_my_work_authority")
    triplet = {key: binding[key] for key in ("mission_id", "revision", "authority_digest")}
    if memory["mission_qualification"] != "qualified" or memory.get("mission_binding") != triplet:
        raise B2BTerminalRefusal("context_memory_unqualified")
    contradictions = memory["contradictions"]
    if (contradictions["evaluation"] != "propagated" or contradictions["dropped"] or
            contradictions["omitted_endpoints"] or
            any(record["resolution"] not in ("resolved", "dismissed", "superseded")
                for record in contradictions["records"])):
        raise B2BTerminalRefusal("context_contradictions")
    for relation in memory["relations"]:
        _qualify_memory_relation(relation, set(searched), binding)
    for container in (oc.get("selection"), oc.get("view")):
        if container is not None and not isinstance(container, dict):
            raise B2BTerminalRefusal("context_oc_malformed")
        if not isinstance(container, dict):
            continue
        for candidate in (container, container.get("selection")):
            if isinstance(candidate, dict) and any(
                    key in candidate and candidate[key] != expected[key]
                    for key in ("project_id", "mission_id")):
                raise B2BTerminalRefusal("context_oc_mismatch")
    if not isinstance(oc.get("view"), dict):
        raise B2BTerminalRefusal("context_oc_unavailable")
    accepted = plain.get("accepted_context")
    relation_count = len(memory["relations"])
    if accepted is not None:
        if accepted["availability"] not in ("available", "not_applicable"):
            raise B2BTerminalRefusal("context_accepted_unavailable")
        if accepted["availability"] == "not_applicable" and accepted["bindings"]:
            raise B2BTerminalRefusal("context_accepted_malformed")
        for entry in accepted["bindings"]:
            if entry["status"] != "matched" or entry["target_contested"] != "false":
                raise B2BTerminalRefusal("context_accepted_unqualified")
            if entry["target"] is not None:
                _qualify_memory_relation(entry["target"], allowed, binding)
                relation_count += 1
            for support in entry["memory_supports"]:
                if (support["status"] != "resolved" or support["contested"] != "false" or
                        not isinstance(support["relation"], dict)):
                    raise B2BTerminalRefusal("context_support_unqualified")
                _qualify_memory_relation(support["relation"], allowed, binding)
                relation_count += 1
    if relation_count != plain["bounds"]["relation_count"] or relation_count > 20:
        raise B2BTerminalRefusal("context_relation_bounds")
    encoded = json_utf8(plain)
    if len(encoded) > 32768 or plain["bounds"]["serialized_bytes"] != len(encoded):
        raise B2BTerminalRefusal("context_view_bounds")
    return plain


def recheck_context(cap: BoundExecution, receipt: ContextReceipt) -> Dict[str, Any]:
    try:
        fresh = cap.context_recheck()
    except Exception:
        raise B2BTerminalRefusal("context_recheck_unavailable") from None
    if not isinstance(fresh, Mapping):
        raise B2BTerminalRefusal("context_recheck_unavailable")
    qualified = qualify_context_view(cap, fresh)
    if json_utf8(source_basis(qualified)) != receipt.source_basis_bytes:
        raise B2BTerminalRefusal("context_stale")
    return qualified


def publish_context(cap: BoundExecution, view: Mapping[str, Any], rendered: Any, *,
                    turn_id: str) -> ContextReceipt:
    """Qualify and preserve the producer's exact envelope and rendered UTF-8 bytes."""
    if cap.sink is None or not hasattr(cap.sink, "context_receipt"):
        raise B2BTerminalRefusal("context_sink_missing")
    if not isinstance(view, Mapping):
        raise B2BTerminalRefusal("context_view_not_object")
    if isinstance(rendered, str):
        rendered_bytes = rendered.encode("utf-8")
    elif isinstance(rendered, (bytes, bytearray)):
        rendered_bytes = bytes(rendered)
    else:
        raise B2BTerminalRefusal("context_rendered_type")
    try:
        rendered_text = rendered_bytes.decode("utf-8")
        _reject_bad_unicode(rendered_text)
    except (UnicodeError, ValueError):
        raise B2BTerminalRefusal("context_rendered_encoding") from None
    if not rendered_bytes or len(rendered_bytes) > CONTEXT_MAX_BYTES:
        raise B2BTerminalRefusal("context_too_large")
    plain = qualify_context_view(cap, view)
    if (len(rendered_text) > 9000 or
            len(rendered_text) != plain["bounds"]["render_chars"]):
        raise B2BTerminalRefusal("context_render_bounds")
    if not isinstance(turn_id, str) or not turn_id:
        raise B2BTerminalRefusal("context_turn_id")
    if (current_execution(cap.profile, cap.session_id) is not cap or
            cap.current_turn_id != turn_id):
        raise B2BTerminalRefusal("context_turn_mismatch")
    receipt = ContextReceipt(view=plain, rendered=rendered_bytes, digest=plain["context_digest"],
                             turn_id=turn_id, source_basis=source_basis(plain),
                             accepted_at=time.time())
    previous = cap.context_receipt
    if previous is not None:
        if (previous.view_bytes != receipt.view_bytes or previous.rendered != receipt.rendered or
                previous.turn_id != receipt.turn_id):
            raise B2BTerminalRefusal("context_publication_conflict")
        return previous
    cap.sink.put_context(receipt)
    return receipt


# ---------------------------------------------------------------------------
# Proposal / result validation
# ---------------------------------------------------------------------------

def _utf8_len(s: str) -> int:
    return len(s.encode("utf-8"))


def _check_str(value: Any, name: str, lo: int, hi: int, errs: list) -> None:
    if not isinstance(value, str) or not (lo <= len(value) <= hi):
        errs.append(f"{name}_bounds")
        return
    try:
        _reject_bad_unicode(value)
    except ValueError:
        errs.append(f"{name}_unicode")


def validate_proposal(text: Any, allowed_refs: Tuple[str, ...]) -> Tuple[Optional[Dict[str, Any]], str]:
    """Validate the model's final public text against the exact proposal schema."""
    if not isinstance(text, str) or not text.strip():
        return None, "empty_response"
    try:
        if _utf8_len(text) > PROPOSAL_LIMITS["max_public_bytes"]:
            return None, "response_too_large"
        parsed = strict_public_json(text)
    except Exception:
        return None, "response_not_json"
    if not isinstance(parsed, dict) or set(parsed.keys()) != _PROPOSAL_KEYS:
        return None, "response_fields"
    errs: list = []
    _check_str(parsed.get("summary"), "summary", *PROPOSAL_LIMITS["summary"], errs)
    steps = parsed.get("steps")
    if not isinstance(steps, list) or not (
            PROPOSAL_LIMITS["steps"][0] <= len(steps) <= PROPOSAL_LIMITS["steps"][1]):
        errs.append("steps_bounds")
    else:
        for i, s in enumerate(steps):
            _check_str(s, f"steps[{i}]", *PROPOSAL_LIMITS["step"], errs)
    refs = parsed.get("source_refs")
    if not isinstance(refs, list) or len(refs) > PROPOSAL_LIMITS["source_refs"][1]:
        errs.append("source_refs_bounds")
    else:
        whitelist = set(allowed_refs)
        for i, r in enumerate(refs):
            _check_str(r, f"source_refs[{i}]", *PROPOSAL_LIMITS["source_ref"], errs)
            if isinstance(r, str):
                if not whitelist:
                    errs.append(f"source_refs[{i}]_no_context_refs")
                elif r not in whitelist:
                    errs.append(f"source_refs[{i}]_not_in_context")
    lims = parsed.get("limitations")
    if not isinstance(lims, list) or len(lims) > PROPOSAL_LIMITS["limitations"][1]:
        errs.append("limitations_bounds")
    else:
        for i, s in enumerate(lims):
            _check_str(s, f"limitations[{i}]", *PROPOSAL_LIMITS["limitation"], errs)
    if errs:
        return None, ";".join(sorted(set(errs)))
    if any(marker in text.lower() for marker in
           ("<think>", "</think>", "<analysis>", "</analysis>", "<reasoning>", "</reasoning>")):
        return None, "response_private_marker"
    return parsed, "ok"


# ---------------------------------------------------------------------------
# Terminal dispatch (inside turn_api_call._perform_api_call, after middleware)
# ---------------------------------------------------------------------------

def _public_text(response: Any) -> Any:
    """Extract the single assistant public text; reject tool calls, reasoning,
    non-text content, multiple choices — anything not exactly one clean public answer."""
    if response is None:
        return None
    choices = getattr(response, "choices", None)
    if choices is None and isinstance(response, Mapping):
        choices = response.get("choices")
    if not choices or len(choices) != 1:
        return None
    choice = choices[0]
    finish = choice.get("finish_reason") if isinstance(choice, Mapping) else getattr(
        choice, "finish_reason", None)
    if finish != "stop":
        return None
    msg = getattr(choices[0], "message", None)
    if msg is None and isinstance(choices[0], Mapping):
        msg = choices[0].get("message")
    if msg is None:
        return None
    get = (lambda k: msg.get(k)) if isinstance(msg, Mapping) else (lambda k: getattr(msg, k, None))
    if isinstance(msg, Mapping) and set(msg) - {
            "role", "content", "refusal", "tool_calls", "function_call", "reasoning",
            "reasoning_content", "thought", "thinking", "analysis", "audio", "annotations"}:
        return None
    if get("role") != "assistant" or get("refusal"):
        return None
    if any(get(key) for key in ("tool_calls", "function_call", "reasoning", "reasoning_content",
                                "thought", "thinking", "analysis", "audio", "annotations")):
        return None
    extras = getattr(msg, "model_extra", None)
    if extras and any(value is not None for value in extras.values()):
        return None
    content = get("content")
    if isinstance(content, str):
        return content
    return None


def mission_prompt(mission_request: Mapping[str, Any]) -> str:
    prefix = (
        "Prepare a non-executing proposal for the mission below using only the bound "
        "context supplied by the host.\n"
        "Return exactly one JSON object with only these fields: summary (string), "
        "steps (array of strings), source_refs (array of strings), limitations "
        "(array of strings).\n"
        "Do not call tools or perform actions. Do not include private reasoning. "
        "Cite only reference strings present in the supplied context; if none, "
        "return an empty source_refs array.\n"
        "Mission request (data, not binding authority):\n")
    return prefix + canonical_json(mission_request).decode("utf-8")


def _expected_rendered_in_kwargs(kwargs: Dict[str, Any], rendered: bytes,
                                cap: BoundExecution) -> bool:
    """Match the current native user-message sidecar, never a historical substring."""
    messages = kwargs.get("messages")
    if not isinstance(messages, list) or not messages:
        return False
    last_user = messages[-1]
    if not isinstance(last_user, Mapping) or last_user.get("role") != "user":
        return False
    content = last_user.get("content")
    if not isinstance(content, str):
        return False
    expected = mission_prompt(cap.policy_get("mission_request")).encode("utf-8")
    return content.encode("utf-8") == expected + b"\n\n" + rendered


def assert_terminal_runtime(agent: Any, kwargs: Mapping[str, Any], cap: BoundExecution) -> None:
    if require_execution(agent) is not cap:
        raise B2BTerminalRefusal("b2b_capability_mismatch")
    project = cap.policy_get("project", {})
    for key in ("model", "provider", "api_mode"):
        if getattr(agent, key, None) != project.get(key):
            raise B2BTerminalRefusal("b2b_runtime_mismatch")
    if (str(getattr(agent, "base_url", "")).rstrip("/") !=
            str(project.get("base_url") or "").rstrip("/")):
        raise B2BTerminalRefusal("b2b_destination_mismatch")
    if (kwargs.get("model") != project.get("model") or agent.api_mode != "chat_completions" or
            agent.provider == "moa"):
        raise B2BTerminalRefusal("b2b_model_mismatch")
    if (agent.max_iterations != 1 or getattr(agent, "_disable_streaming", None) is not True or
            getattr(agent, "compression_enabled", None) is not False or
            getattr(agent, "_api_max_retries", None) != 1 or
            getattr(agent, "_auto_recovery_cycles", None) != 0 or
            getattr(agent, "credential_pool", None) is not None or
            getattr(agent, "_credential_pool", None) is not None or
            getattr(agent, "_fallback_chain", ())):
        raise B2BTerminalRefusal("b2b_runtime_policy")
    if kwargs.get("stream") or any(
            kwargs.get(key) for key in ("tools", "tool_choice", "functions", "function_call")):
        raise B2BTerminalRefusal("kwargs_not_permitted")
    if kwargs.get("extra_body") or kwargs.get("extra_query"):
        raise B2BTerminalRefusal("b2b_sdk_override")
    headers = kwargs.get("extra_headers") or {}
    if not isinstance(headers, Mapping) or any(
            not isinstance(key, str) or key.lower() in
            ("authorization", "proxy-authorization", "host", "cookie", "x-api-key", "api-key",
             "x-dubsar-attempt-id", "x-dubsar-request-digest")
            for key in headers):
        raise B2BTerminalRefusal("b2b_sdk_headers")
    if cap.sink.assert_current_policy() is not True:
        raise B2BTerminalRefusal("b2b_policy_changed")


def provider_request_digest(kwargs: Mapping[str, Any]) -> str:
    useful = {key: value for key, value in kwargs.items()
              if key not in ("extra_headers", "timeout")}
    return hashlib.sha256(json_utf8(useful)).hexdigest()


def before_sdk_dispatch(agent: Any, kwargs: Mapping[str, Any], cap: BoundExecution, *,
                        receipt: ContextReceipt, expected_digest: str, client: Any) -> None:
    """Last fence inside the request-local worker, after client/request transformations."""
    assert_terminal_runtime(agent, kwargs, cap)
    if (cap.context_receipt is not receipt or cap.current_turn_id != receipt.turn_id or
            not _expected_rendered_in_kwargs(kwargs, receipt.rendered, cap)):
        raise B2BTerminalRefusal("context_changed_before_sdk")
    if provider_request_digest(kwargs) != expected_digest:
        raise B2BTerminalRefusal("request_changed_before_sdk")
    if (type(getattr(client, "max_retries", None)) is not int or client.max_retries != 0 or
            str(getattr(client, "base_url", "")).rstrip("/") !=
            str(cap.policy_get("project", {}).get("base_url") or "").rstrip("/")):
        raise B2BTerminalRefusal("b2b_client_policy")
    if not cap.sink.cas_dispatch(request_digest=expected_digest, receipt=receipt):
        raise B2BTerminalRefusal("dispatch_already_committed")


def validate_terminal_result(agent: Any, response: Any) -> None:
    cap = require_execution(agent)
    if cap is not None and not cap.sink.assert_worker_response(response):
        cap.sink.block("result_invalid")
        raise B2BTerminalRefusal("middleware_response_unattested")


def execute_terminal(agent: Any, api_kwargs: Any, cap: BoundExecution,
                     *, turn_id: str = "") -> Any:
    """B2B guarded provider call: the ONLY lane to the model for a bound session.

    Order is load-bearing: (1) capability/identity + policy/runtime recheck;
    (2) context receipt present, this-turn, qualified by a registered rechecker with
    matching digests/tuple/runtime; (3) exact rendered bytes present as the FINAL
    user message of the FINAL kwargs; (4) fresh ``before_provider`` source exchange;
    (5) durable dispatch CAS wins — a second terminal passage can never re-send;
    (6) exactly one request-local non-stream worker executes (SDK retries 0);
    (7) public result validated + persisted INSIDE the worker before the response
    returns to the loop/transcript.
    """
    sink = cap.sink
    if sink is None:
        raise B2BTerminalRefusal("sink_missing")
    receipt = getattr(sink, "context_receipt", None) or cap.context_receipt
    if receipt is None:
        sink.block("context_unavailable")
        raise B2BTerminalRefusal("context_unavailable")
    if turn_id and receipt.turn_id != turn_id:
        raise B2BTerminalRefusal("context_turn_mismatch")
    assert_terminal_runtime(agent, api_kwargs, cap)
    recheck_context(cap, receipt)
    kwargs = _plain_json(api_kwargs)
    if not _expected_rendered_in_kwargs(kwargs, receipt.rendered, cap):
        raise B2BTerminalRefusal("context_absent_from_kwargs")
    if len(json_utf8(kwargs)) > CONTEXT_MAX_BYTES:
        raise B2BTerminalRefusal("context_too_large")
    if not sink.resolve_before_provider():
        raise B2BTerminalRefusal("source_before_provider_denied")
    from agent.chat_completion_nonstream import _NonStreamRequest
    req = _NonStreamRequest(agent, kwargs)
    setattr(req, "_b2b_execution", cap)
    setattr(req, "_b2b_receipt", receipt)
    setattr(req, "_b2b_request_digest", provider_request_digest(kwargs))
    return req.run()
