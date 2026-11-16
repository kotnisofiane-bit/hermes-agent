"""Asynchronous per-consumer plugin observers for streaming LLM output.

Each registered hook callback gets its own bounded queue + daemon worker thread
so plugin code never runs inline on the token path. Queues drop the oldest
pending event when full; dispatchers for callbacks that are no longer
registered are stopped lazily on the next lookup.
"""

from __future__ import annotations

import contextvars
import logging
import queue
import threading
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Callable

from hermes_cli.middleware import OBSERVER_SCHEMA_VERSION
from hermes_constants import hermes_home_key

logger = logging.getLogger(__name__)

_QUEUE_SIZE = 1024
_STOP = object()


@dataclass
class _ConsumerDispatcher:
    hook_name: str
    callback: Callable[..., Any]
    events: "queue.Queue[tuple[contextvars.Context, dict[str, Any], Any] | object]"
    thread: threading.Thread | None = None


_dispatcher_lock = threading.Lock()
# (owning profile's canonical home key, hook name, id(callback)) — one process
# serves many profiles; lazy stale-pruning must never reap another home's
# worker on the strength of ITS manager's callback list.
_dispatchers: dict[tuple[str, str, int], _ConsumerDispatcher] = {}


def _callback_name(callback: Callable[..., Any]) -> str:
    return getattr(callback, "__name__", repr(callback))


def _release_item_ref(item: Any) -> None:
    """Drop the launch-lease ref one queued event carried — idle dispatcher
    threads hold nothing; each EVENT does, until consumed, dropped or drained."""
    if isinstance(item, tuple) and len(item) == 3 and item[2] is not None:
        with suppress(Exception):
            item[2].release()


def _put_drop_oldest(events: "queue.Queue[Any]", item: Any) -> bool:
    """put_nowait; on a full queue evict the oldest pending event and retry once."""
    try:
        events.put_nowait(item)
        return True
    except queue.Full:
        try:
            evicted = events.get_nowait()
            _release_item_ref(evicted)
            events.task_done()
        except queue.Empty:
            pass
    try:
        events.put_nowait(item)
        return True
    except queue.Full:
        return False


def _worker(dispatcher: _ConsumerDispatcher) -> None:
    while True:
        item = dispatcher.events.get()
        try:
            if item is _STOP:
                # Anything enqueued behind the sentinel is unreachable once
                # this worker exits — free those refs before returning.
                while True:
                    try:
                        leftover = dispatcher.events.get_nowait()
                    except queue.Empty:
                        break
                    _release_item_ref(leftover)
                    dispatcher.events.task_done()
                return
            context, payload, ref = item
            payload = dict(payload)
            payload.setdefault("telemetry_schema_version", OBSERVER_SCHEMA_VERSION)
            try:
                # The worker outlives every turn and serves its owning profile; run the callback in the
                # enqueuing turn's contextvars so it sees that turn's profile scope (home override,
                # secrets), not an unbound context that fail-closed plugin bindings refuse (#118538).
                # ``copy()``: one snapshot fans out to N consumer threads and a Context can only be
                # entered by one thread at a time.
                def invoke_if_registered() -> None:
                    if any(callback is dispatcher.callback for callback in _dispatch_callbacks(dispatcher.hook_name)):
                        dispatcher.callback(**payload)

                context.copy().run(invoke_if_registered)
            except Exception as exc:
                # Fires once per streaming delta: a mis-declared callback fails identically every
                # time, so it goes through the manager's warn-once reporter (#111922) — through
                # the ENQUEUING profile's context so the report lands on the owning manager,
                # not the launch/default home's.
                from hermes_cli.plugins import get_plugin_manager

                context.copy().run(lambda: get_plugin_manager()._report_hook_failure(
                    dispatcher.hook_name, dispatcher.callback, payload, exc))
        finally:
            _release_item_ref(item)
            dispatcher.events.task_done()


def _registered_callbacks(hook_name: str) -> tuple[Callable[..., Any], ...]:
    try:
        from hermes_cli import plugins
        return tuple(plugins.get_plugin_manager()._hooks.get(hook_name, ()))
    except Exception:
        logger.debug("plugin stream hook callback lookup failed: %s", hook_name, exc_info=True)
        return ()


def _dispatch_callbacks(hook_name: str) -> tuple[Callable[..., Any], ...]:
    try:
        from hermes_cli import plugins
        return plugins.get_plugin_manager()._dispatch_hook_callbacks(hook_name)
    except Exception:
        logger.debug("plugin stream hook callback lookup failed: %s", hook_name, exc_info=True)
        return ()


def _stop_dispatcher(dispatcher: _ConsumerDispatcher, timeout: float = 1.0) -> None:
    # Free queued event refs BEFORE the sentinel: the drain must never remove
    # a live worker's _STOP (a callback still blocked at join timeout would
    # then park the worker on an empty queue forever).
    while True:
        try:
            leftover = dispatcher.events.get_nowait()
        except queue.Empty:
            break
        _release_item_ref(leftover)
        dispatcher.events.task_done()
    _put_drop_oldest(dispatcher.events, _STOP)
    if dispatcher.thread is not None:
        dispatcher.thread.join(timeout=timeout)
    if dispatcher.thread is None or not dispatcher.thread.is_alive():
        # Worker exited: events that raced in behind _STOP are unreachable.
        while True:
            try:
                leftover = dispatcher.events.get_nowait()
            except queue.Empty:
                break
            _release_item_ref(leftover)
            dispatcher.events.task_done()


def _start_dispatcher(hook_name: str, callback: Callable[..., Any]) -> _ConsumerDispatcher:
    dispatcher = _ConsumerDispatcher(hook_name=hook_name, callback=callback, events=queue.Queue(maxsize=_QUEUE_SIZE))
    dispatcher.thread = threading.Thread(
        target=_worker, args=(dispatcher,), daemon=True, name=f"plugin-stream-hook:{hook_name}"
    )
    dispatcher.thread.start()
    return dispatcher


def _dispatchers_for(hook_name: str) -> list[_ConsumerDispatcher]:
    """Live dispatcher per registered callback (restarting dead workers); stale
    ones for unregistered callbacks are stopped outside the lock. Registration
    and staleness are judged against the CURRENT profile home only — another
    home's dispatcher is a different key, never a stale one."""
    home = hermes_home_key()
    registered_callback_ids = {
        id(callback) for callback in _registered_callbacks(hook_name)
    }
    callbacks = _dispatch_callbacks(hook_name)
    ready: list[_ConsumerDispatcher] = []
    with _dispatcher_lock:
        stale = [
            _dispatchers.pop(key)
            for key in list(_dispatchers)
            if key[0] == home and key[1] == hook_name
            and key[2] not in registered_callback_ids
        ]
        for callback in callbacks:
            key = (home, hook_name, id(callback))
            dispatcher = _dispatchers.get(key)
            if dispatcher is None or dispatcher.thread is None or not dispatcher.thread.is_alive():
                dispatcher = _dispatchers[key] = _start_dispatcher(hook_name, callback)
            ready.append(dispatcher)

    for dispatcher in stale:
        _stop_dispatcher(dispatcher, timeout=0.2)
    return ready


def enqueue_plugin_stream_hook(hook_name: str, **payload: Any) -> bool:
    """Queue an observer hook for each consumer without running plugin code inline."""
    queued = False
    item_context = contextvars.copy_context()
    try:
        from agent.b2b_execution import current_launch_lease
        lease = current_launch_lease()
    except Exception:
        lease = None
    for dispatcher in _dispatchers_for(hook_name):
        # Each queued event retains the enqueuing launch's unit until the
        # callback actually completes, the event is drop-evicted, or the
        # dispatcher is drained — an outliving queued callback never frees
        # the launch's capacity early.
        ref = None
        if lease is not None:
            ref = lease.retain()
        if _put_drop_oldest(dispatcher.events, (item_context, dict(payload), ref)):
            queued = True
        else:
            if ref is not None:
                with suppress(Exception):
                    ref.release()
            logger.debug(
                "plugin stream hook queue full after drop-oldest: %s callback=%s",
                hook_name, _callback_name(dispatcher.callback),
            )
    return queued


def has_stream_observer_hooks() -> bool:
    return any(_dispatch_callbacks(name) for name in ("on_stream_start", "on_stream_delta", "on_stream_end"))


def has_reasoning_stream_observer_hooks() -> bool:
    return stream_reasoning_deltas_enabled() and bool(_dispatch_callbacks("on_stream_delta"))


def stream_reasoning_deltas_enabled() -> bool:
    """Return True only when the user opted plugins into reasoning deltas.

    Read-only scalar lookup: skips ``load_config()``'s deepcopy. Callers on the token path
    should still cache the result per stream (``_fire_reasoning_delta`` does)."""
    try:
        from hermes_cli import config as config_mod
        config = config_mod.load_config_readonly()
        return bool(config_mod.cfg_get(config, "plugins", "stream_reasoning_deltas", default=False))
    except Exception:
        logger.debug("failed to read plugins.stream_reasoning_deltas", exc_info=True)
        return False


def shutdown_plugin_stream_hook_dispatcher(timeout: float = 1.0) -> None:
    """Stop background stream hook dispatchers; used by tests and clean shutdown paths."""
    global _dispatchers
    with _dispatcher_lock:
        dispatchers = list(_dispatchers.values())
        _dispatchers = {}
    for dispatcher in dispatchers:
        _stop_dispatcher(dispatcher, timeout=timeout)
