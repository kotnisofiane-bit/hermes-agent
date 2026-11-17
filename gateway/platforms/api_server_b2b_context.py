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

import asyncio
import contextvars
import threading
import time
from dataclasses import dataclass
from time import monotonic as _monotonic
from typing import Any, Dict, Mapping, Optional, Tuple

from agent.b2b_execution import (
    B2BTerminalRefusal, BoundExecution, CONTEXT_MAX_BYTES, _deep_freeze,
    _native_oc_read_metadata, _reject_bad_unicode, _utc_milliseconds,
    assert_source_equivalent, json_utf8, qualify_context_view, source_basis,
)
from gateway.platforms.api_server_b2b import _SOURCE_DEADLINE_S


_SOURCE_OBSERVED_MAX_AGE_MS = 900_000


def _context_provider():
    """The single plugin-owned ``prepare_context`` callback under the CURRENT
    home's plugin manager — ``(manager, callback)`` or ``None``. Only a
    callback registered through ``PluginContext.register_hook`` qualifies, and
    only when the SAME plugin also registered ``pre_llm_call`` (preparer and
    publisher share one owner). Exactly one owned callable must be registered:
    zero is "no producer", two or more is ambiguity — both fail closed, and a
    raw ``manager._hooks`` entry is neither owned nor counted. Pure
    introspection — plugin ``register()`` may do IO, so discovery is never
    triggered here: only the launch's bounded bootstrap discovers."""
    from hermes_cli.plugins import get_plugin_manager
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
        return _context_provider() is not None
    except Exception:
        return False


def _start_bounded_worker(callback):
    """Spawn THIS operation's ONE worker — a daemon thread running
    ``callback`` under ``copy_context`` — and hand back ``(done, outcome)``:

    * ``done`` is set only when the worker TRULY exits;
    * ``outcome`` carries ``{"value": ...}``, ``{"error": BaseException}``,
      and the worker's own ``finished_at`` monotonic instant — the value the
      deadline is judged against, never the polling loop's wake. A result
      produced past the deadline is simply discarded."""
    outcome: Dict[str, Any] = {}
    done = threading.Event()
    invoke_context = contextvars.copy_context()

    def _invoke() -> None:
        try:
            outcome["value"] = callback()
        except BaseException as exc:  # noqa: BLE001 -- normalized below
            outcome["error"] = exc
        finally:
            # The worker's OWN finish instant — the deadline is judged
            # against this, never against the polling loop's wake.
            outcome["finished_at"] = _monotonic()
            done.set()

    threading.Thread(target=lambda: invoke_context.run(_invoke), daemon=True).start()
    return done, outcome


def _preparation_result(outcome: Dict[str, Any]) -> Any:
    """The ONE normalization for the bounded runner: a typed refusal
    propagates as-is; every other BaseException collapses to
    ``context_unavailable``."""
    exc = outcome.get("error")
    if exc is not None:
        if isinstance(exc, B2BTerminalRefusal):
            raise exc
        raise B2BTerminalRefusal("context_unavailable") from None
    return outcome["value"]


async def _bounded_worker_result(done, outcome, deadline):
    """The shared bounded wait: poll the worker's ``done`` Event without an
    executor and without a nested worker — a monotonic deadline over a
    <=10 ms poll. A budget expiry refuses ``context_unavailable`` and the
    worker's late result is discarded; a task cancellation propagates — the
    daemon is never killed. The deadline is judged on the worker's OWN
    recorded finish instant, never on the polling loop's wake."""
    while not done.is_set():
        remaining = deadline - _monotonic()
        if remaining <= 0:
            raise B2BTerminalRefusal("context_unavailable")
        await asyncio.sleep(min(0.01, remaining))
    if outcome["finished_at"] >= deadline:
        # Fail closed: a result the worker finished past the budget
        # refuses — a finish inside it is never refused on wake time.
        raise B2BTerminalRefusal("context_unavailable")
    return _preparation_result(outcome)


async def run_bounded_context_preparation(callback):
    """THE bounded preparation: one native worker on the
    ``_SOURCE_DEADLINE_S`` budget. A budget expiry refuses
    ``context_unavailable`` — the request fails closed, nothing seals; a
    task cancellation propagates (the daemon is never killed — its late
    result is simply discarded)."""
    return await run_bounded_context_operation(
        callback, timeout=_SOURCE_DEADLINE_S)


async def run_bounded_context_operation(callback, *, timeout):
    """The bounded NON-preparation operation — the SAME
    daemon/``copy_context``/poll machinery and fail-closed
    ``context_unavailable`` expiry as native preparation, on the caller's
    own ``timeout``; the daemon is never killed and a late result is
    discarded. For work that must stay off the loop and off the executor
    but is NOT the native read: the launch bootstrap, seal-time
    source/policy validation, and the seal-time recheck."""
    deadline = _monotonic() + timeout
    done, outcome = _start_bounded_worker(callback)
    return await _bounded_worker_result(done, outcome, deadline)


def _invoke_producer(cap: BoundExecution):
    """The native read itself — the profile's single owned ``prepare_context``
    callback + the result-shape gate. May only run inside a bounded worker.
    Returns ``(result, manager, prepare)``."""
    found = _context_provider()
    if found is None:
        raise B2BTerminalRefusal("context_unavailable")
    manager, prepare = found
    result = prepare(execution=cap)
    if (not isinstance(result, Mapping)
            or not callable(result.get("validate_configuration"))):
        raise B2BTerminalRefusal("context_unavailable")
    return result, manager, prepare


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
        found = _context_provider()
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


def _prepare_b2b_context(cap: BoundExecution, *, resolved: Mapping[str, Any]) -> _PreparedContext:
    """The preparation BODY — unbounded: it may only run inside the worker
    ``run_bounded_context_preparation`` spawned, where the profile scope and
    the bound execution ContextVar are already installed. The native read AND
    every configuration validator execute on that one worker."""
    if not isinstance(cap, BoundExecution) or getattr(cap, "sink", None) is None:
        raise B2BTerminalRefusal("context_unavailable")

    # The cap is bound to the home that minted it. A generic producer must not
    # decide that; the host refuses a foreign-home cap before any callback.
    from hermes_constants import get_hermes_home
    if str(get_hermes_home().resolve()) != cap.policy_get("profile_home"):
        raise B2BTerminalRefusal("b2b_policy_changed")

    result, manager, prepare = _invoke_producer(cap)
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
