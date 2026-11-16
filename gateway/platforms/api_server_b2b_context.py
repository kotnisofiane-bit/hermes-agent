"""C1 context preparation for the B2B execution lane — the host-side adapter
to the generic ``prepare_context`` plugin hook.

P2 contract: an available plugin is not proof of producer readiness. A mission
is admitted only after THIS capability's own preparation — a real, current,
mission-scoped native read (My Work mission + native OC receipt + Memory Plane)
returned by the profile's single registered ``prepare_context`` callback and
qualified by ``agent.b2b_execution`` — has been captured, stamped and bound to
this attempt's sink. Nothing here is a cache or a flag: the frozen preparation
lives on the owning ``_AttemptSink`` for exactly one capability, and every later
gate re-proves the live configuration against it (``assert_current`` before
admission, ``assert_publication`` at publication, ``assert_configuration_current``
from the sink's policy gate).

No new producer is added: whatever plugin registered ``prepare_context`` under
the current profile's plugin manager is the only builder, and the worker-side
``pre_llm_call`` publication remains the only publisher. This module performs
no preflight publish and reads no provider credentials.
"""

from __future__ import annotations

import contextvars
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from agent.b2b_execution import (
    B2BTerminalRefusal, BoundExecution, CONTEXT_MAX_BYTES, _deep_freeze,
    _native_oc_read_metadata, _reject_bad_unicode, _utc_milliseconds,
    assert_source_equivalent, json_utf8, qualify_context_view, source_basis,
)
from gateway.platforms.api_server_b2b import _SOURCE_DEADLINE_S


_SOURCE_OBSERVED_MAX_AGE_MS = 900_000

# Fixed process-wide resource bound on in-flight native preparations: at most
# ONE discovery+read worker may run at a time, for every profile this process
# serves. A worker keeps its slot until it actually finishes — a caller
# deadline expiring releases nothing — so a wedged producer pins the bound and
# later launches (including other profiles') fail closed on saturation instead
# of stacking unbounded discovery/provider threads behind it.
_MAX_CONCURRENT_PREPARATIONS = 1
_preparation_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_PREPARATIONS)


def _context_provider(*, discover: bool = False):
    """The single plugin-owned ``prepare_context`` callback under the CURRENT
    home's plugin manager — ``(manager, callback)`` or ``None``. Only a
    callback registered through ``PluginContext.register_hook`` qualifies, and
    only when the SAME plugin also registered ``pre_llm_call`` (preparer and
    publisher share one owner). Exactly one owned callable must be registered:
    zero is "no producer", two or more is ambiguity — both fail closed, and a
    raw ``manager._hooks`` entry is neither owned nor counted. Health/
    diagnostics pass ``discover=False``: plugin ``register()`` may do IO, so a
    status query must never trigger a load; only bounded preparation may
    discover."""
    from hermes_cli.plugins import discover_plugins, get_plugin_manager
    if discover:
        discover_plugins()
    manager = get_plugin_manager()
    callbacks = manager.iter_plugin_hook_callbacks("prepare_context")
    if len(callbacks) != 1:
        return None
    owner, prepare = callbacks[0]
    if not any(plugin == owner for plugin, _ in
               manager.iter_plugin_hook_callbacks("pre_llm_call")):
        return None
    return manager, prepare


def producer_available() -> bool:
    """Registration introspection for diagnostics (health/health-detailed):
    is exactly one ``prepare_context`` callback registered in THIS home?
    Says nothing about any mission's readiness — an available producer still
    admits nothing without a current per-capability preparation."""
    try:
        return _context_provider(discover=False) is not None
    except Exception:
        return False


def _bounded_native_read(cap: BoundExecution):
    """The preparation's native read, bounded off-loop by the standing source
    budget (pattern: ``recheck_context``). The callback runs on a daemon
    thread under ``copy_context``; the caller Event-waits the budget and is
    the ONLY attacher — a late completion can never admit anything.

    The worker is admitted against the process-wide
    ``_MAX_CONCURRENT_PREPARATIONS`` bound BEFORE any discovery/provider work
    starts: a saturated bound refuses ``context_unavailable`` without spawning
    a thread. The slot is held until the worker completes (producer exceptions
    included) — never released by the caller's deadline expiring."""
    budget = _SOURCE_DEADLINE_S
    outcome: Dict[str, Any] = {}
    done = threading.Event()
    invoke_context = contextvars.copy_context()

    def _invoke() -> None:
        try:
            found = _context_provider(discover=True)
            if found is None:
                raise B2BTerminalRefusal("context_unavailable")
            manager, prepare = found
            result = prepare(execution=cap)
            if (not isinstance(result, Mapping)
                    or not callable(result.get("validate_configuration"))):
                raise B2BTerminalRefusal("context_unavailable")
            outcome["value"] = result, manager, prepare
        except BaseException as exc:  # noqa: BLE001 -- normalized below
            outcome["error"] = exc
        finally:
            done.set()
            _preparation_slots.release()

    if not _preparation_slots.acquire(blocking=False):
        raise B2BTerminalRefusal("context_unavailable")
    try:
        threading.Thread(
            target=lambda: invoke_context.run(_invoke), daemon=True).start()
    except BaseException:
        _preparation_slots.release()
        raise
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
    the registering manager/callback identities, the plugin-owned
    configuration validator and the source's own observation deadline.
    Immutable; scoped to ``cap`` by identity — never a global cache."""

    cap: BoundExecution
    view: Mapping[str, Any]
    manager: Any
    prepare: Any
    validate_configuration: Any
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

    def _assert_stamp(self) -> None:
        """The configuration the preparation read under — the SAME callback
        still registered under the SAME manager, and the plugin's own
        zero-argument validator re-proves its configuration. The validator
        performs no publication/native IO; any non-``True`` answer or error
        fails closed."""
        found = _context_provider(discover=False)
        if found is None or found[0] is not self.manager or found[1] is not self.prepare:
            raise B2BTerminalRefusal("context_unavailable")
        try:
            current = self.validate_configuration()
        except B2BTerminalRefusal:
            raise
        except Exception:
            raise B2BTerminalRefusal("context_unavailable") from None
        if current is not True:
            raise B2BTerminalRefusal("b2b_policy_changed")

    def _assert_window(self) -> None:
        """The source's own observation deadline governs every gate; it is
        never extended by TTL or provider waiting."""
        if int(time.time() * 1000) >= self.source_deadline_ms:
            raise B2BTerminalRefusal("context_oc_source_stale")

    def assert_current(self, cap: Optional[BoundExecution]) -> None:
        self._assert_frame(cap)
        self._assert_window()
        self._assert_stamp()

    def assert_configuration_current(self) -> bool:
        """Recheck for the sink's policy gates (which run under the owning
        profile's scope, possibly outside a bound execution ContextVar):
        same cap/home/project, source still inside its own observation
        deadline, same registered callback, validator still ``True``. Typed
        refusals propagate — the caller classifies them durably."""
        self._assert_frame(self.cap)
        self._assert_window()
        self._assert_stamp()
        return True

    def assert_publication(self, cap: Optional[BoundExecution], receipt: Any) -> None:
        """The published receipt must BE this preparation's mission: same
        cap, still inside the source deadline, same registration — and a
        source-equivalent view with a still-current source observation. The
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
    """Read + qualify the mission's context for THIS capability via the
    profile's ``prepare_context`` callback, inside the standing source
    budget. Returns the frozen preparation (the CALLER decides whether to
    attach it — a late result attaches nothing) or raises
    ``B2BTerminalRefusal`` — the caller maps it to ``execution_unavailable``.

    No durable write, no admission, no agent, no provider call, no
    ``publish_context``: this is source preparation only — actual publication
    stays in the real ``pre_llm_call`` hook on the admitted worker's turn.
    """
    if not isinstance(cap, BoundExecution) or getattr(cap, "sink", None) is None:
        raise B2BTerminalRefusal("context_unavailable")

    # The cap is bound to the home that minted it. A generic producer must not
    # decide that; the host refuses a foreign-home cap before any callback.
    from hermes_constants import get_hermes_home
    if str(get_hermes_home().resolve()) != cap.policy_get("profile_home"):
        raise B2BTerminalRefusal("b2b_policy_changed")

    result, manager, prepare = _bounded_native_read(cap)
    view, rendered = result.get("view"), result.get("rendered")
    if not isinstance(view, Mapping):
        raise B2BTerminalRefusal("context_unavailable")
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

    prepared = _PreparedContext(
        cap=cap, view=_deep_freeze(plain), manager=manager, prepare=prepare,
        validate_configuration=result["validate_configuration"],
        source_deadline_ms=source_deadline_ms,
        project_utf8=json_utf8(cap.policy_get("project")),
        profile=cap.profile,
        home=str(get_hermes_home().resolve()),
        policy_home=cap.policy_get("profile_home"))
    # The plugin's configuration must not have drifted during the read.
    prepared.assert_current(cap)
    return prepared


def assert_prepared_context_current(cap: Optional[BoundExecution], project: Any) -> None:
    """The TYPED readiness assertion: raise ``B2BTerminalRefusal`` with the
    preparation's exact durable cause whenever a live, current,
    mission-scoped preparation is not attached to THIS capability's sink."""
    if cap is None or getattr(cap, "sink", None) is None:
        raise B2BTerminalRefusal("context_unavailable")
    preparation = getattr(cap.sink, "_context_preparation", None)
    if preparation is None or preparation.cap is not cap:
        raise B2BTerminalRefusal("context_unavailable")
    if json_utf8(project) != preparation.project_utf8:
        raise B2BTerminalRefusal("b2b_policy_changed")
    preparation.assert_current(cap)


def prepared_context_ready(cap: Optional[BoundExecution], project: Any) -> bool:
    """THE readiness predicate: is a live, current, mission-scoped preparation
    attached to THIS capability's sink — under the same project policy, inside
    its source window? No cap, no preparation, a stale registration or a
    closed window all answer False — an installed plugin or complete config
    alone can never answer True."""
    try:
        assert_prepared_context_current(cap, project)
        return True
    except Exception:
        return False
