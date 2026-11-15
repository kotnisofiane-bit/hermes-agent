"""C1 context preparation for the B2B execution lane — the host-side adapter
to the INSTALLED ``dubsar-agent-context`` plugin's bound runtime.

P2 contract: an available plugin is not proof of producer readiness. A mission
is admitted only after THIS capability's own preparation — a real, current,
mission-scoped native read (My Work mission + native OC receipt + Memory Plane)
qualified by ``agent.b2b_execution`` — has been captured, stamped and bound to
this attempt's sink. Nothing here is a cache or a flag: the frozen preparation
lives on the owning ``_AttemptSink`` for exactly one capability, and every later
gate re-proves the live configuration against it (``assert_current`` before
admission, ``assert_publication`` at publication, ``assert_configuration_current``
from the sink's policy gate).

No new producer is added: ``build_agent_context_view_v2`` in the installed
plugin is the only builder, and the worker-side ``pre_llm_call`` publication
remains the only publisher. This module performs no preflight publish, reads no
provider credentials, and never touches ``sys.path`` — the scoped package is
imported under the already-loaded module's namespace.
"""

from __future__ import annotations

import contextvars
import importlib
import sys
import threading
import time
import types
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from agent.b2b_execution import (
    B2BTerminalRefusal, BoundExecution, CONTEXT_MAX_BYTES, _deep_freeze,
    _native_oc_read_metadata, _reject_bad_unicode, _utc_milliseconds,
    assert_source_equivalent, json_utf8, qualify_context_view, source_basis,
)
from gateway.platforms.api_server_b2b import _SOURCE_DEADLINE_S


_CONTEXT_PLUGIN_ID = "dubsar-agent-context"
_SOURCE_OBSERVED_MAX_AGE_MS = 900_000


def _context_plugin(*, discover: bool = False):
    """The already-loaded, enabled, error-free C1 plugin under the CURRENT
    home's plugin manager — or ``None``. Health/diagnostics pass
    ``discover=False``: plugin ``register()`` may do IO, so a status query
    must never trigger a load; only bounded preparation may discover."""
    from hermes_cli.plugins import discover_plugins, get_plugin_manager
    if discover:
        discover_plugins()
    manager = get_plugin_manager()
    for loaded in getattr(manager, "_plugins", {}).values():
        manifest = getattr(loaded, "manifest", None)
        if (getattr(manifest, "name", None) == _CONTEXT_PLUGIN_ID
                and getattr(loaded, "enabled", False)
                and not getattr(loaded, "error", None)
                and getattr(loaded, "module", None) is not None
                and "pre_llm_call" in (getattr(loaded, "hooks_registered", None) or [])):
            return manager, loaded
    return None


def producer_available() -> bool:
    """Registration introspection for diagnostics (health/health-detailed):
    is the C1 producer installed, enabled, error-free and hooked in THIS home?
    Says nothing about any mission's readiness — an available producer still
    admits nothing without a current per-capability preparation."""
    try:
        return _context_plugin(discover=False) is not None
    except Exception:
        return False


def _plugin_modules(loaded: Any) -> Tuple[Any, Any]:
    """Import ``runtime``/``assembly_v2`` under the LOADED module's own exact
    namespace — ``<loaded.module.__name__>.dubsar_agent_context.<mod>``.
    Scoped-package imports only; no parent-prefix fallback, no sys.path or
    raw paths."""
    prefix = loaded.module.__name__
    runtime = importlib.import_module(prefix + ".dubsar_agent_context.runtime")
    assembly = importlib.import_module(prefix + ".dubsar_agent_context.assembly_v2")
    return runtime, assembly


def _bound_runtime(cap: BoundExecution, *, discover: bool = True):
    """Fresh PluginContext -> RuntimeAdapter -> bound factory for THIS cap,
    built entirely through the installed plugin's own constructors. Returns
    ``(bound, loaded, assembly)``; any missing/mismatched/readonly/version/
    origin/port/pin failure surfaces as the typed refusal — fail closed."""
    found = _context_plugin(discover=discover)
    if found is None:
        raise B2BTerminalRefusal("context_unavailable")
    manager, loaded = found
    try:
        runtime, assembly = _plugin_modules(loaded)
    except Exception:
        raise B2BTerminalRefusal("context_unavailable") from None
    try:
        from hermes_cli.plugins import PluginContext
        ctx = PluginContext(loaded.manifest, manager)
        base = runtime.RuntimeAdapter.from_plugin_context(ctx)
        bound = runtime.RuntimeAdapter.for_bound_execution(
            base, cap, cap.policy_get("project"))
    except B2BTerminalRefusal:
        raise
    except Exception:
        raise B2BTerminalRefusal("context_unavailable") from None
    if getattr(bound, "_bound_stamp", None) is None:
        raise B2BTerminalRefusal("context_unavailable")
    return bound, loaded, assembly


def _native_build(bound: Any, assembly: Any):
    """One real native read through the plugin's OWN builder — the same call
    the worker's ``pre_llm_call`` makes. No second producer, no fixture."""
    return assembly.build_agent_context_view_v2(
        bound, preserve_native_oc_receipt=True,
        include_automation_results=bound._bound_include_automation_results)


def _bounded_native_read(cap: BoundExecution, deadline: float):
    """The preparation's native read, bounded off-loop by the signed source
    window and the standing source budget (pattern: ``recheck_context``). The
    build runs on a daemon thread under ``copy_context``; the caller Event-
    waits the remaining budget and is the ONLY attacher — a late completion
    can never admit anything."""
    budget = max(0.0, min(deadline - time.time(), _SOURCE_DEADLINE_S))
    if budget <= 0:
        raise B2BTerminalRefusal("context_unavailable")
    outcome: Dict[str, Any] = {}
    done = threading.Event()
    invoke_context = contextvars.copy_context()

    def _invoke() -> None:
        try:
            bound, loaded, assembly = _bound_runtime(cap)
            outcome["value"] = (_native_build(bound, assembly), bound, loaded)
        except BaseException as exc:  # noqa: BLE001 -- normalized below
            outcome["error"] = exc
        finally:
            done.set()

    threading.Thread(target=lambda: invoke_context.run(_invoke), daemon=True).start()
    if not done.wait(budget):
        raise B2BTerminalRefusal("context_unavailable")
    exc = outcome.get("error")
    if exc is not None:
        if isinstance(exc, B2BTerminalRefusal):
            raise exc
        raise B2BTerminalRefusal("context_unavailable") from None
    return outcome["value"]


def _source_observed_ms(plain: Mapping[str, Any]) -> Tuple[int, int]:
    """The SOURCE's own observation timestamp and bound, from a native /2
    receipt only: ``state_projection.candidate`` must be a measured
    observation carrying an explicit ``source_observed_at``. A /1 receipt —
    or any receipt that cannot prove its source timestamp — is refused
    narrowly (``context_oc_unqualified``); a capture instant is never a
    source observation. Returns ``(observed_ms, max_age_ms)`` where the
    maximum is ``min(_SOURCE_OBSERVED_MAX_AGE_MS, freshness_max_age_ms)``."""
    oc = plain.get("operational_context")
    receipt = oc.get("view") if isinstance(oc, Mapping) else None
    if not isinstance(receipt, Mapping):
        raise B2BTerminalRefusal("context_oc_unavailable")
    fmt = receipt.get("format")
    if not (isinstance(fmt, str) and fmt.endswith("/2")):
        raise B2BTerminalRefusal("context_oc_unqualified")
    projection = receipt.get("state_projection")
    candidate = projection.get("candidate") if isinstance(projection, Mapping) else None
    if not isinstance(candidate, Mapping) or candidate.get("result_kind") != "measured":
        raise B2BTerminalRefusal("context_oc_unqualified")
    observed_ms = _utc_milliseconds(candidate.get("source_observed_at"))
    if not isinstance(observed_ms, int) or isinstance(observed_ms, bool) or observed_ms <= 0:
        raise B2BTerminalRefusal("context_oc_unqualified")
    maximum = projection.get("freshness_max_age_ms")
    if type(maximum) is not int or maximum <= 0:
        raise B2BTerminalRefusal("context_oc_unqualified")
    return observed_ms, min(_SOURCE_OBSERVED_MAX_AGE_MS, maximum)


def _assert_source_window(plain: Mapping[str, Any]) -> Tuple[int, int]:
    """The source observation must bracket NOW: ``observed <= now <
    observed + maximum`` — no future source, nothing older than its own
    governed freshness bound. Returns ``(observed_ms, deadline_ms)``."""
    observed_ms, maximum = _source_observed_ms(plain)
    now_ms = int(time.time() * 1000)
    deadline_ms = observed_ms + maximum
    if observed_ms > now_ms or now_ms >= deadline_ms:
        raise B2BTerminalRefusal("context_oc_source_stale")
    return observed_ms, deadline_ms


@dataclass(frozen=True)
class _PreparedContext:
    """The frozen proof bound to ONE capability's sink: the qualified view,
    the bound-factory stamp, the loaded plugin objects and the signed-source
    deadline plus the source's own observation deadline. Immutable; scoped to
    ``cap`` by identity — never a global cache."""

    cap: BoundExecution
    view: Mapping[str, Any]
    stamp: Any
    module_name: str
    module: types.ModuleType
    manager: Any
    loaded: Any
    deadline: float
    source_deadline_ms: int
    project_utf8: bytes
    profile: str
    home: str
    policy_home: Any

    def _assert_frame(self, cap: Optional[BoundExecution]) -> None:
        if cap is not self.cap or cap.profile != self.profile:
            raise B2BTerminalRefusal("b2b_capability_mismatch")
        from hermes_constants import get_hermes_home
        if (str(get_hermes_home().resolve()) != self.home or
                cap.policy_get("profile_home") != self.policy_home or
                json_utf8(cap.policy_get("project")) != self.project_utf8):
            raise B2BTerminalRefusal("b2b_policy_changed")

    def _assert_stamp(self, cap: BoundExecution) -> None:
        """The configuration the preparation read under — plugin still the
        SAME loaded module object under the SAME manager, and a freshly
        rebuilt bound factory carries the SAME stamp."""
        if sys.modules.get(self.module_name) is not self.module:
            raise B2BTerminalRefusal("context_unavailable")
        from hermes_cli.plugins import get_plugin_manager
        if get_plugin_manager() is not self.manager:
            raise B2BTerminalRefusal("context_unavailable")
        bound, loaded, _assembly = _bound_runtime(cap, discover=False)
        if loaded is not self.loaded or bound._bound_stamp != self.stamp:
            raise B2BTerminalRefusal("b2b_policy_changed")

    def _assert_window(self, cap: BoundExecution) -> None:
        """The source's own observation deadline governs every gate; the
        signed-source deadline additionally governs while the lane is still
        pre-publication. Neither is extended by TTL or provider waiting."""
        if int(time.time() * 1000) >= self.source_deadline_ms:
            raise B2BTerminalRefusal("context_oc_source_stale")
        if cap.context_receipt is None and time.time() >= self.deadline:
            raise B2BTerminalRefusal("source_window_closed")

    def assert_current(self, cap: Optional[BoundExecution]) -> None:
        self._assert_frame(cap)
        self._assert_window(cap)
        self._assert_stamp(cap)

    def assert_configuration_current(self) -> bool:
        """Recheck for the sink's policy gates (which run under the owning
        profile's scope, possibly outside a bound execution ContextVar):
        same cap/home/project, source still inside its own observation
        deadline, same loaded plugin objects, same stamp."""
        try:
            self._assert_frame(self.cap)
            self._assert_window(self.cap)
            self._assert_stamp(self.cap)
            return True
        except Exception:
            return False

    def assert_publication(self, cap: Optional[BoundExecution], receipt: Any) -> None:
        """The published receipt must BE this preparation's mission: same
        cap, still inside both deadlines, same stamp — and a source-
        equivalent view with a still-current source observation. The
        publishing hook already performed its own fresh native read; no
        second read happens here."""
        self.assert_current(cap)
        if receipt is None or receipt.turn_id != cap.current_turn_id:
            raise B2BTerminalRefusal("context_turn_mismatch")
        assert_source_equivalent(self.view, receipt.view)
        _assert_source_window(receipt.view)
        if json_utf8(source_basis(receipt.view)) != json_utf8(receipt.source_basis):
            raise B2BTerminalRefusal("context_stale")


def prepare_b2b_context(cap: BoundExecution, *, resolved: Mapping[str, Any]) -> _PreparedContext:
    """Read + qualify the mission's context for THIS capability, before the
    signed source deadline. Returns the frozen preparation (the CALLER decides
    whether to attach it — a late result attaches nothing) or raises
    ``B2BTerminalRefusal`` — the caller maps it to ``execution_unavailable``.

    No durable write, no admission, no agent, no provider call, no
    ``publish_context``: this is source preparation only — actual publication
    stays in the real ``pre_llm_call`` hook on the admitted worker's turn.
    """
    if not isinstance(cap, BoundExecution) or getattr(cap, "sink", None) is None:
        raise B2BTerminalRefusal("context_unavailable")
    req, resp = resolved.get("_signed_request"), resolved.get("_signed_response")
    if not isinstance(req, Mapping) or not isinstance(resp, Mapping):
        raise B2BTerminalRefusal("context_unavailable")
    deadline = min(float(req["expires_at"]), float(resp["expires_at"]))
    if time.time() >= deadline:
        raise B2BTerminalRefusal("source_window_closed")

    built, bound, loaded = _bounded_native_read(cap, deadline)
    view, rendered = built
    plain = qualify_context_view(cap, view)

    # P2 proof bar: NATIVE OC metadata only — a legacy arbitrary view cannot
    # qualify, whatever the plugin returned.
    if _native_oc_read_metadata(plain) is None:
        raise B2BTerminalRefusal("context_oc_unqualified")
    if (plain["my_work"]["mission"]["source_digest"] !=
            resolved.get("mission_source_digest")):
        raise B2BTerminalRefusal("context_my_work_mismatch")

    # The rendered bytes the worker will publish are validated NOW under the
    # exact publish_context conditions — an unreadable or misbound render
    # must never reach admission.
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
    if (len(rendered_text) > 9000 or
            len(rendered_text) != plain["bounds"]["render_chars"]):
        raise B2BTerminalRefusal("context_render_bounds")

    _observed_ms, source_deadline_ms = _assert_source_window(plain)

    if time.time() >= deadline:
        raise B2BTerminalRefusal("source_window_closed")
    stamp = bound._bound_stamp
    bound2, loaded2, _assembly2 = _bound_runtime(cap)
    if loaded2 is not loaded or bound2._bound_stamp != stamp:
        raise B2BTerminalRefusal("b2b_policy_changed")

    from hermes_cli.plugins import get_plugin_manager
    from hermes_constants import get_hermes_home
    return _PreparedContext(
        cap=cap, view=_deep_freeze(plain), stamp=stamp,
        module_name=loaded.module.__name__,
        module=loaded.module, manager=get_plugin_manager(), loaded=loaded,
        deadline=deadline, source_deadline_ms=source_deadline_ms,
        project_utf8=json_utf8(cap.policy_get("project")),
        profile=cap.profile,
        home=str(get_hermes_home().resolve()),
        policy_home=cap.policy_get("profile_home"))


def prepared_context_ready(cap: Optional[BoundExecution], project: Any) -> bool:
    """THE readiness predicate: is a live, current, mission-scoped preparation
    attached to THIS capability's sink — under the same project policy, inside
    its signed window? No cap, no preparation, a stale stamp or a closed
    window all answer False — an installed plugin or complete config alone
    can never answer True."""
    if cap is None or getattr(cap, "sink", None) is None:
        return False
    preparation = getattr(cap.sink, "_context_preparation", None)
    if preparation is None or preparation.cap is not cap:
        return False
    if json_utf8(project) != preparation.project_utf8:
        return False
    try:
        preparation.assert_current(cap)
        return True
    except Exception:
        return False
