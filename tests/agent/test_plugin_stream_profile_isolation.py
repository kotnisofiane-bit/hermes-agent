"""Stream-hook dispatchers are profile-scoped, never process-global.

Each ``(profile home, hook, callback)`` triple owns ONE worker. A lookup under
profile A must neither stop nor restart profile B's live dispatcher -- B's
callbacks stay serialized on B's single worker, callers under A are never
charged a stop/join against B's wedged consumer, and every callback runs in
the enqueuing profile's own scope.
"""

from __future__ import annotations

import threading
import time

import pytest


class _Probe:
    """Deterministic records for one profile's plugin callback."""

    def __init__(self, *, released: bool = False):
        self.entered = threading.Event()
        self.release = threading.Event()
        if released:
            self.release.set()
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.completions = []
        self.threads = []
        self.homes = []


_PROBES: dict = {}


def _record_delta(tag, kwargs):
    """Plugin callback body -- imported by the directory plugins below."""
    probe = _PROBES[tag]
    from hermes_constants import hermes_home_key
    with probe._lock:
        probe.threads.append(threading.current_thread())
        probe.homes.append(hermes_home_key())
        probe.active += 1
        probe.max_active = max(probe.max_active, probe.active)
    probe.entered.set()
    probe.release.wait(timeout=30.0)
    with probe._lock:
        probe.active -= 1
    probe.completions.append(kwargs.get("delta"))


def _plugin_init(tag: str) -> str:
    return (
        "def register(ctx):\n"
        "    def on_stream_delta(**kwargs):\n"
        "        from tests.agent.test_plugin_stream_profile_isolation import _record_delta\n"
        f"        _record_delta({tag!r}, kwargs)\n"
        "    ctx.register_hook(\"on_stream_delta\", on_stream_delta)\n"
    )


def _write_stream_plugin(home, name: str, *, tag: str) -> None:
    """A real directory plugin registering ``on_stream_delta`` through
    PluginContext -- loaded only by the real discovery/manifest path."""
    plug = home / "plugins" / name
    plug.mkdir(parents=True, exist_ok=True)
    (plug / "plugin.yaml").write_text(
        f"name: {name}\nversion: 1.0.0\ndescription: stream isolation probe\n")
    (plug / "__init__.py").write_text(_plugin_init(tag))
    (home / "config.yaml").write_text(
        f"plugins:\n  enabled:\n    - {name}\n")


def _wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate()


@pytest.mark.parametrize("a_has_hook", [True, False])
def test_stream_dispatchers_are_profile_scoped(
        tmp_path, monkeypatch, a_has_hook):
    """A->B->A interleaving with B's callback parked on a gate: profile-A
    lookups must leave B's dispatcher alive and identical, never attempt a
    lazy stop against it, and never overlap B's callbacks."""
    import agent.plugin_stream_hooks as psh
    import hermes_cli.plugins as plugins_mod
    from agent.secret_scope import is_multiplex_active, set_multiplex_active
    from hermes_constants import (
        hermes_home_key, reset_hermes_home_override, set_hermes_home_override)

    psh.shutdown_plugin_stream_hook_dispatcher()

    stop_attempts = []
    real_stop = psh._stop_dispatcher

    def _stop_spy(dispatcher, timeout=1.0):
        stop_attempts.append(dispatcher)
        return real_stop(dispatcher, timeout=timeout)

    monkeypatch.setattr(psh, "_stop_dispatcher", _stop_spy)

    empty_bundled = tmp_path / "no_bundled_plugins"
    empty_bundled.mkdir()
    monkeypatch.setattr(
        plugins_mod, "get_bundled_plugins_dir", lambda: empty_bundled)

    home_a = tmp_path / "home-a"
    home_b = tmp_path / "home-b"
    home_a.mkdir()
    home_b.mkdir()

    probes = {"a": _Probe(released=True), "b": _Probe()}
    _PROBES.clear()
    _PROBES.update(probes)

    if a_has_hook:
        _write_stream_plugin(home_a, "streamprobe-a", tag="a")
    _write_stream_plugin(home_b, "streamprobe-b", tag="b")

    def _scoped(home, fn, *args, **kwargs):
        token = set_hermes_home_override(home)
        try:
            return fn(*args, **kwargs)
        finally:
            reset_hermes_home_override(token)

    enqueued = {"a": [], "b": []}

    def _enqueue(home, tag, delta):
        enqueued[tag].append(
            _scoped(home, psh.enqueue_plugin_stream_hook,
                    "on_stream_delta", delta=delta))

    previous_multiplex = is_multiplex_active()
    set_multiplex_active(True)
    try:
        # Real per-home plugin managers via real discovery.
        for home in (home_a, home_b):
            _scoped(home, plugins_mod.discover_plugins)

        # A first delta (if A carries a hook), then B first -- which parks
        # inside the gated callback.
        _enqueue(home_a, "a", "a-1")
        _enqueue(home_b, "b", "b-1")
        assert probes["b"].entered.wait(timeout=10.0), (
            "B worker never entered its callback")
        # A second (or hook-free delta), B second, A third -- every A-side
        # lookup runs while B's worker is wedged inside the callback.
        _enqueue(home_a, "a", "a-2")
        _enqueue(home_b, "b", "b-2")
        _enqueue(home_a, "a", "a-3")

        # While B's gate is still closed, A-side work (or a hook-free lookup)
        # completed: neither the caller nor A's worker was stopped on B's
        # consumer.
        if a_has_hook:
            assert enqueued["a"] == [True, True, True]
            _wait_for(
                lambda: probes["a"].completions == ["a-1", "a-2", "a-3"])
        else:
            assert enqueued["a"] == [False, False, False]
        assert stop_attempts == [], (
            "cross-profile lazy stop attempted on %r" % (stop_attempts,))

        probes["b"].release.set()
        _wait_for(lambda: probes["b"].completions == ["b-1", "b-2"])
    finally:
        probes["b"].release.set()
        psh.shutdown_plugin_stream_hook_dispatcher()
        set_multiplex_active(previous_multiplex)
        _PROBES.clear()

    # B's two deltas completed in enqueue order on ONE worker -- the same
    # dispatcher/thread identity persisted across the whole interleave.
    assert probes["b"].completions == ["b-1", "b-2"]
    assert len(set(probes["b"].threads)) == 1, (
        "B deltas ran on %d distinct worker threads"
        % len(set(probes["b"].threads)))
    assert probes["b"].max_active == 1, (
        "B callbacks overlapped on %d workers" % probes["b"].max_active)
    # Each callback saw the profile scope of the turn that enqueued it.
    assert probes["b"].homes == [hermes_home_key(home_b)] * 2
    if a_has_hook:
        assert probes["a"].homes == [hermes_home_key(home_a)] * 3
        assert len(set(probes["a"].threads)) == 1
