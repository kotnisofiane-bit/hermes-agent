"""B2B governed-lane hook isolation.

During a turn bound to an admitted B2B execution (the ``agent.b2b_execution``
ContextVar set at launch admission), ``PluginManager.invoke_hook`` /
``ainvoke_hook`` must deliver ONLY to callbacks owned by an active
``PluginContext.register_hook`` registration. Every other subscriber of
``manager._hooks`` — configured outbound webhooks (``hooks.outbound``), shell
hooks (``hooks:``) and raw in-process subscribers (dashboard-style sentinels) —
must see NOTHING, for every name in ``VALID_HOOKS`` plus an unknown name and
through both the sync and async dispatch loops. ``prepare_context`` and
``transform_api_error_classification`` are refused by the config registrars, so
their raw subscribers are wired through the same ``_make_callback`` factories
deliberately — dispatch isolation must not depend on config guards. Outside a
bound execution the same subscribers keep receiving real deliveries, and no
payload profile/session kwarg may smuggle a bypass in either direction.
"""

from __future__ import annotations

import asyncio
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from agent import outbound_webhooks, plugin_stream_hooks, shell_hooks
from agent.b2b_execution import BoundExecution, bind_execution, reset_execution
import hermes_cli.plugins as plugins_mod
from hermes_cli.plugins import (
    PLUGIN_ONLY_HOOKS,
    SHELL_UNSUPPORTED_HOOKS,
    VALID_HOOKS,
    get_plugin_manager,
)

_UNKNOWN_HOOK = "b2b_probe_unknown_hook"
_PLUGIN_NAME = "b2b_hook_probe"
_MISSION_SENTINEL = "MISSION-SENTINEL-" + "9e4f" * 8


# ── real local HTTP capture server ────────────────────────────────────────


class _CapturingHandler(BaseHTTPRequestHandler):
    """Records every POST (path, headers, body) on the server instance."""

    def do_POST(self):  # noqa: N802 — http.server naming
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.captured.append(  # type: ignore[attr-defined]
            {"path": self.path, "headers": dict(self.headers), "body": body})
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002 — http.server naming
        pass


@pytest.fixture()
def http_server():
    server = HTTPServer(("127.0.0.1", 0), _CapturingHandler)
    server.captured = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _reset_hook_registrar_state():
    outbound_webhooks.reset_for_tests()
    shell_hooks.reset_for_tests()
    yield
    outbound_webhooks.reset_for_tests()
    shell_hooks.reset_for_tests()


# ── probe plugin, loaded through real directory discovery ─────────────────


def _write_probe_plugin(hermes_home: Path, log_path: Path) -> Path:
    """A directory plugin whose register() hooks one recording callback per event."""
    plugin_dir = hermes_home / "plugins" / _PLUGIN_NAME
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.yaml").write_text(yaml.dump(
        {"name": _PLUGIN_NAME, "version": "0.1.0",
         "description": "B2B hook-isolation probe"}), encoding="utf-8")
    (plugin_dir / "__init__.py").write_text(
        "def register(ctx):\n"
        "    def _record(event):\n"
        "        def _cb(**kwargs):\n"
        f"            with open({str(log_path)!r}, 'a', encoding='utf-8') as fh:\n"
        "                fh.write(event + '\\n')\n"
        "            return None\n"
        "        return _cb\n"
        f"    for _event in {sorted(VALID_HOOKS) + [_UNKNOWN_HOOK]!r}:\n"
        "        ctx.register_hook(_event, _record(_event))\n",
        encoding="utf-8")
    cfg_path = hermes_home / "config.yaml"
    cfg = {}
    if cfg_path.exists():
        cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    cfg.setdefault("plugins", {})["enabled"] = [_PLUGIN_NAME]
    cfg_path.write_text(yaml.dump(cfg), encoding="utf-8")
    return plugin_dir


@pytest.fixture()
def lane(tmp_path, monkeypatch):
    """Isolated per-test HERMES_HOME (conftest) + probe plugin on a fresh manager."""
    hermes_home = Path(os.environ["HERMES_HOME"])
    plugin_log = tmp_path / "plugin_calls.log"
    _write_probe_plugin(hermes_home, plugin_log)
    # Keep the sweep to just the probe plugin (bundled plugins stay unloaded).
    empty_bundled = tmp_path / "no_bundled_plugins"
    empty_bundled.mkdir()
    monkeypatch.setattr(
        plugins_mod, "get_bundled_plugins_dir", lambda: empty_bundled)
    manager = get_plugin_manager()
    manager.discover_and_load()
    return SimpleNamespace(
        home=hermes_home, manager=manager, plugin_log=plugin_log)


# ── raw subscribers (webhook / shell / sentinel) ──────────────────────────


def _wire_raw_subscribers(manager, event: str, url: str, command: str) -> None:
    """Subscribe one outbound webhook and one shell hook to *event*.

    Supported events go through the production config registrars; the two
    config-refused events use the same ``_make_callback`` factories appended
    straight onto ``_hooks`` — dispatch safety must not depend on config.
    """
    if event not in VALID_HOOKS or event in PLUGIN_ONLY_HOOKS:
        target = outbound_webhooks.WebhookTarget(url=url, events=[event], timeout=5)
        manager._hooks.setdefault(event, []).append(
            outbound_webhooks._make_callback(event, target))
    else:
        outbound_webhooks.register_from_config(
            {"hooks": {"outbound": [{"url": url, "events": [event], "timeout": 5}]}})
    if event not in VALID_HOOKS or event in SHELL_UNSUPPORTED_HOOKS:
        spec = shell_hooks.ShellHookSpec(event=event, command=command, timeout=5)
        manager._hooks.setdefault(event, []).append(
            shell_hooks._make_callback(spec))
    else:
        shell_hooks.register_from_config(
            {"hooks_auto_accept": True,
             "hooks": {event: [{"command": command, "timeout": 5}]}},
            accept_hooks=True)


def _cap(session_id: str) -> BoundExecution:
    """A real BoundExecution carrying the mission sentinel — minted host-side."""
    return BoundExecution(
        profile="hub", session_id=session_id,
        binding_digest="b" * 64, attempt_id="att_" + "c" * 8,
        run_id="run_x", sink=object(), created_at=0.0,
        policy={"project": {"project_id": "p"},
                "mission_request": {"objective": _MISSION_SENTINEL}})


def _dispatch(manager, event: str, payload: dict, mode: str):
    if mode == "sync":
        return manager.invoke_hook(event, **payload)
    return asyncio.run(manager.ainvoke_hook(event, **payload))


def _plugin_events(log_path: Path):
    if not log_path.exists():
        return []
    return log_path.read_text(encoding="utf-8").split()


# ── the inventory test ────────────────────────────────────────────────────


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("event", sorted(VALID_HOOKS) + [_UNKNOWN_HOOK])
def test_bound_b2b_dispatch_reaches_plugin_only(
        lane, http_server, tmp_path, event, mode):
    """For EVERY hook name: bound context → plugin only; unbound → all delivered."""
    manager = lane.manager
    url = f"http://127.0.0.1:{http_server.server_address[1]}/hook"
    capture_file = tmp_path / f"shell_capture_{event}.json"
    _wire_raw_subscribers(
        manager, event, url, f'/bin/sh -c "cat >> {capture_file}"')
    sentinel_calls = []
    manager._hooks.setdefault(event, []).append(
        lambda **kwargs: sentinel_calls.append(kwargs))

    payload = {
        "session_id": "b2b_" + "a" * 64,
        "user_message": _MISSION_SENTINEL,
        "conversation_history": [{"role": "user", "content": _MISSION_SENTINEL}],
        "tool_name": "terminal",
        "args": {"command": f"echo {_MISSION_SENTINEL}"},
    }

    # ---- bound B2B context: only the plugin-owned callback may run ----
    token = bind_execution(_cap(payload["session_id"]))
    try:
        _dispatch(manager, event, payload, mode)
        # Spoofed session/profile kwargs must not bypass the bound filter.
        _dispatch(manager, event,
                  {**payload, "session_id": "ordinary-session",
                   "profile": "attacker"}, mode)
    finally:
        reset_execution(token)

    outbound_webhooks.flush(timeout=5)
    assert _plugin_events(lane.plugin_log).count(event) == 2
    assert http_server.captured == []
    assert not capture_file.exists()
    assert sentinel_calls == []

    # ---- unbound: ordinary dispatch is preserved ----
    _dispatch(manager, event,
              {**payload, "session_id": "sess_unrelated"}, mode)
    # A B2B-looking session id in the payload must not trigger filtering either.
    _dispatch(manager, event, payload, mode)
    outbound_webhooks.flush(timeout=5)

    assert _plugin_events(lane.plugin_log).count(event) == 4
    assert len(http_server.captured) == 2
    assert all(_MISSION_SENTINEL.encode() in d["body"]
               for d in http_server.captured)
    capture_text = capture_file.read_text(encoding="utf-8")
    assert capture_text.count('"hook_event_name"') == 2
    assert _MISSION_SENTINEL in capture_text
    assert len(sentinel_calls) == 2


_QUEUED_B2B_HOOKS = (
    "on_stream_start",
    "on_stream_delta",
    "on_stream_end",
    "on_interim_message",
    "on_room_member_activity",
)


@pytest.fixture
def _queued_dispatcher_cleanup():
    yield
    with plugin_stream_hooks._dispatcher_lock:
        dispatchers = [
            plugin_stream_hooks._dispatchers.pop(key)
            for key in list(plugin_stream_hooks._dispatchers)
            if key[0] in _QUEUED_B2B_HOOKS
        ]
    for dispatcher in dispatchers:
        plugin_stream_hooks._stop_dispatcher(dispatcher, timeout=5)


def _drain_queued_hook(hook_name: str) -> None:
    with plugin_stream_hooks._dispatcher_lock:
        dispatchers = tuple(
            dispatcher
            for (name, _callback_id), dispatcher in plugin_stream_hooks._dispatchers.items()
            if name == hook_name
        )
    drained = threading.Event()

    def join_queues():
        for dispatcher in dispatchers:
            dispatcher.events.join()
        drained.set()

    threading.Thread(target=join_queues, daemon=True).start()
    assert drained.wait(5), f"observer workers did not drain {hook_name}"


def _emit_queued_hook(agent, event: str, payload: dict) -> None:
    if event == "on_interim_message":
        agent._emit_interim_assistant_message({
            "role": "assistant",
            "content": payload["user_message"],
        })
    else:
        plugin_stream_hooks.enqueue_plugin_stream_hook(event, **payload)


@pytest.mark.parametrize("event", _QUEUED_B2B_HOOKS)
def test_bound_b2b_queued_dispatch_reaches_plugin_only(
        lane, http_server, tmp_path, event, _queued_dispatcher_cleanup):
    """Queued observers select subscribers when the event is enqueued."""
    from run_agent import AIAgent

    manager = lane.manager
    url = f"http://127.0.0.1:{http_server.server_address[1]}/hook"
    capture_file = tmp_path / f"queued_shell_capture_{event}.json"
    _wire_raw_subscribers(
        manager, event, url, f'/bin/sh -c "cat >> {capture_file}"')
    sentinel_calls = []
    manager._hooks.setdefault(event, []).append(
        lambda **kwargs: sentinel_calls.append(kwargs))
    payload = {
        "session_id": "b2b_" + "a" * 64,
        "user_message": _MISSION_SENTINEL,
    }
    sequence = 0
    agent = AIAgent(
        api_key="test-key",
        base_url="https://openrouter.ai/api/v1",
        provider="openrouter",
        model="test/model",
        quiet_mode=True,
        skip_context_files=True,
        skip_memory=True,
    )

    def enqueue(session_id: str | None) -> None:
        nonlocal sequence
        event_payload = {
            **payload,
            "user_message": f"{_MISSION_SENTINEL}-{sequence}",
        }
        sequence += 1
        if session_id is None:
            _emit_queued_hook(agent, event, event_payload)
            return
        token = bind_execution(_cap(session_id))
        try:
            _emit_queued_hook(agent, event, event_payload)
        finally:
            reset_execution(token)

    enqueue("b2b_" + "a" * 64)
    _drain_queued_hook(event)
    outbound_webhooks.flush(timeout=5)
    assert _plugin_events(lane.plugin_log).count(event) == 1
    assert http_server.captured == []
    assert not capture_file.exists()
    assert sentinel_calls == []

    enqueue(None)
    _drain_queued_hook(event)
    outbound_webhooks.flush(timeout=5)
    assert _plugin_events(lane.plugin_log).count(event) == 2
    assert len(http_server.captured) == 1
    assert _MISSION_SENTINEL.encode() in http_server.captured[0]["body"]
    capture_text = capture_file.read_text(encoding="utf-8")
    assert _MISSION_SENTINEL in capture_text
    assert len(sentinel_calls) == 1

    for session_id in ("b2b_" + "a" * 64, "b2b_" + "d" * 64, "b2b_" + "a" * 64):
        enqueue(session_id)
    _drain_queued_hook(event)
    outbound_webhooks.flush(timeout=5)
    assert _plugin_events(lane.plugin_log).count(event) == 5
    assert len(http_server.captured) == 1
    assert len(sentinel_calls) == 1
    assert capture_file.read_text(encoding="utf-8") == capture_text


def test_execution_bind_reset_restores_ordinary_dispatch(
        lane, http_server, tmp_path):
    """A→B→A: each bound context filters; after every reset, delivery resumes."""
    manager = lane.manager
    event = "pre_llm_call"
    url = f"http://127.0.0.1:{http_server.server_address[1]}/hook"
    capture_file = tmp_path / "shell_capture_reset.json"
    _wire_raw_subscribers(
        manager, event, url, f'/bin/sh -c "cat >> {capture_file}"')
    sentinel_calls = []
    manager._hooks.setdefault(event, []).append(
        lambda **kwargs: sentinel_calls.append(kwargs))
    payload = {"user_message": _MISSION_SENTINEL, "session_id": "b2b_" + "a" * 64}

    for session_id in ("b2b_" + "a" * 64, "b2b_" + "d" * 64, "b2b_" + "a" * 64):
        token = bind_execution(_cap(session_id))
        try:
            manager.invoke_hook(event, **payload)
        finally:
            reset_execution(token)
        outbound_webhooks.flush(timeout=5)
        assert http_server.captured == []
        assert not capture_file.exists()
        assert sentinel_calls == []

    assert _plugin_events(lane.plugin_log).count(event) == 3

    manager.invoke_hook(event, **payload)
    outbound_webhooks.flush(timeout=5)
    assert len(http_server.captured) == 1
    assert _MISSION_SENTINEL.encode() in http_server.captured[0]["body"]
    assert capture_file.exists()
    assert len(sentinel_calls) == 1
