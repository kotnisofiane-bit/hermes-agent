"""B2B admission refuses raw hook subscribers before preparation or durable writes."""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

from agent import outbound_webhooks, shell_hooks
from hermes_state import SessionDB
from tests.gateway import test_api_server_b2b_admission as admission
from tests.gateway import test_api_server_b2b_execution_lane as execution_lane


@pytest.fixture
def opened():
    resources = []
    yield resources
    for resource in resources:
        try:
            resource.close()
        except Exception:
            pass


@pytest.fixture(autouse=True)
def _reset_hook_registrars():
    outbound_webhooks.reset_for_tests()
    shell_hooks.reset_for_tests()
    yield
    outbound_webhooks.flush(timeout=5)
    outbound_webhooks.reset_for_tests()
    shell_hooks.reset_for_tests()


class _CaptureHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.server.posts.append(self.path)
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture
def webhook_server():
    server = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    server.posts = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def _new_launch(tmp_path, monkeypatch, opened):
    profile_home = admission._profile_home(tmp_path, monkeypatch, "hub")
    execution_lane._write_serving_config(profile_home)
    import hermes_cli.plugins as plugins
    empty_bundled = tmp_path / "no_bundled_plugins"
    empty_bundled.mkdir()
    monkeypatch.setattr(plugins, "get_bundled_plugins_dir", lambda: empty_bundled)
    adapter = admission._adapter(tmp_path, monkeypatch, "hub")
    opened.append(adapter._session_db)
    adapter._session_db = SessionDB(profile_home / "state.db")
    opened.extend([adapter._session_db, adapter._run_idempotency_store])
    lane = execution_lane._ready_lane(tmp_path)
    opened.append(lane.store)
    entry = execution_lane._lane_entry(
        lane, portal_issuer="portal-hub", hermes_issuer="hermes-hub")
    session_id = "b2b_" + "b" * 64
    adapter._session_db.create_session(session_id, "api_server")
    resolved = execution_lane._launch_resolved(lane, session_id=session_id)
    observation = dict(resolved["observation_genesis"])
    observation["id"], observation["profile"] = session_id, "hub"
    resolved["observation_genesis"] = observation
    resolved["session_id"] = session_id
    resolved["binding_digest"] = session_id[4:]
    resolved["attempt_id"] = execution_lane.b2b._attempt_id_for(session_id[4:])
    return SimpleNamespace(
        profile_home=profile_home, adapter=adapter, lane=lane, entry=entry,
        session_id=session_id, resolved=resolved,
        store=adapter._run_idempotency_store)


def _forbidden(name):
    def _raise(*args, **kwargs):
        raise AssertionError(f"{name} must not run for a refused admission")
    return _raise


async def _launch(case):
    return await execution_lane.b2b._launch_b2b_run(
        case.adapter, None, profile="hub", entry=case.entry,
        keys=execution_lane.b2b._KeyRing(case.entry),
        session_id=case.session_id, binding_digest=case.session_id[4:],
        attempt_id=case.resolved["attempt_id"], resolved=case.resolved,
        store=case.store, db=case.adapter._session_db)


@pytest.mark.asyncio
@pytest.mark.parametrize("event", ["pre_llm_call", "on_stream_delta"])
async def test_launch_refuses_non_plugin_outbound_hook_before_preparation(
        tmp_path, monkeypatch, opened, webhook_server, event):
    case = _new_launch(tmp_path, monkeypatch, opened)
    url = f"http://127.0.0.1:{webhook_server.server_address[1]}/hook"
    with case.adapter._profile_scope("hub"):
        outbound_webhooks.register_from_config(
            {"hooks": {"outbound": [
                {"url": url, "events": [event], "timeout": 2},
            ]}})
    from gateway.platforms import api_server_b2b_context as b2b_context

    prepare_calls = []
    monkeypatch.setattr(b2b_context, "_prepare_b2b_context",
                        lambda *args, **kwargs: prepare_calls.append(args))
    monkeypatch.setattr(execution_lane.b2b, "_spawn_run", _forbidden("_spawn_run"))
    monkeypatch.setattr(case.adapter, "_create_agent", _forbidden("_create_agent"))
    before = admission._store_counts(case.store)

    response = await _launch(case)

    outbound_webhooks.flush(timeout=5)
    assert response.status == 503
    assert json.loads(response.body)["error"] == "non_plugin_hook_subscribers"
    assert prepare_calls == []
    assert webhook_server.posts == []
    assert admission._store_counts(case.store) == before
    assert case.adapter._session_db.get_session(case.session_id)["title"] is None


@pytest.mark.asyncio
async def test_launch_refuses_non_plugin_shell_hook_without_execution(
        tmp_path, monkeypatch, opened):
    case = _new_launch(tmp_path, monkeypatch, opened)
    marker = tmp_path / "shell-hook-ran"
    with case.adapter._profile_scope("hub"):
        shell_hooks.register_from_config(
            {"hooks_auto_accept": True,
             "hooks": {"pre_llm_call": [
                 {"command": f"/usr/bin/touch {marker}", "timeout": 2},
             ]}},
            accept_hooks=True)
    from gateway.platforms import api_server_b2b_context as b2b_context

    prepare_calls = []
    monkeypatch.setattr(b2b_context, "_prepare_b2b_context",
                        lambda *args, **kwargs: prepare_calls.append(args))
    monkeypatch.setattr(execution_lane.b2b, "_spawn_run", _forbidden("_spawn_run"))
    monkeypatch.setattr(case.adapter, "_create_agent", _forbidden("_create_agent"))
    before = admission._store_counts(case.store)

    response = await _launch(case)

    assert response.status == 503
    assert json.loads(response.body)["error"] == "non_plugin_hook_subscribers"
    assert prepare_calls == []
    assert not marker.exists()
    assert admission._store_counts(case.store) == before
    assert case.adapter._session_db.get_session(case.session_id)["title"] is None


@pytest.mark.asyncio
async def test_launch_refuses_raw_sentinel_on_unknown_hook(
        tmp_path, monkeypatch, opened):
    case = _new_launch(tmp_path, monkeypatch, opened)
    from gateway.platforms import api_server_b2b_context as b2b_context
    from hermes_cli.plugins import get_plugin_manager

    with case.adapter._profile_scope("hub"):
        manager = get_plugin_manager()
        manager._hooks.setdefault("unknown_admission_probe", []).append(
            lambda **kwargs: None)
    prepare_calls = []
    monkeypatch.setattr(b2b_context, "_prepare_b2b_context",
                        lambda *args, **kwargs: prepare_calls.append(args))
    monkeypatch.setattr(execution_lane.b2b, "_spawn_run", _forbidden("_spawn_run"))
    before = admission._store_counts(case.store)

    response = await _launch(case)

    assert response.status == 503
    assert json.loads(response.body)["error"] == "non_plugin_hook_subscribers"
    assert prepare_calls == []
    assert admission._store_counts(case.store) == before
    assert case.adapter._session_db.get_session(case.session_id)["title"] is None


@pytest.mark.asyncio
async def test_launch_allows_only_plugin_registered_hooks(
        tmp_path, monkeypatch, opened):
    case = _new_launch(tmp_path, monkeypatch, opened)
    execution_lane._write_fake_plugin(
        case.profile_home, init=execution_lane._FAKE_PLUGIN_INIT)
    execution_lane._plugin_config(case.profile_home)
    from gateway.platforms import api_server_b2b_context as b2b_context
    from hermes_cli.plugins import discover_plugins, get_plugin_manager

    with case.adapter._profile_scope("hub"):
        discover_plugins()

    preparations = []

    def _prepare(cap, *, resolved):
        preparation = execution_lane._UnitPreparation(cap)
        preparations.append(preparation)
        return preparation

    async def _spawn(adapter, request, *, cap, resolved, session_id, run_id,
                     profile):
        return SimpleNamespace()

    monkeypatch.setattr(b2b_context, "_prepare_b2b_context", _prepare)
    monkeypatch.setattr(execution_lane.b2b, "_spawn_run", _spawn)

    response = await _launch(case)

    assert response.status == 200, response.body
    assert len(preparations) == 1
    with case.adapter._profile_scope("hub"):
        manager = get_plugin_manager()
        assert manager._dispatch_hook_callbacks("prepare_context")
    attempt = case.store.b2b_attempt(
        profile="hub", attempt_id=case.resolved["attempt_id"])
    assert attempt["status"] == "admitted"
    assert case.adapter._session_db.get_session(case.session_id)["title"] == (
        "B2B " + case.session_id)


@pytest.mark.asyncio
async def test_launch_rechecks_raw_hooks_added_during_preparation(
        tmp_path, monkeypatch, opened):
    case = _new_launch(tmp_path, monkeypatch, opened)
    from gateway.platforms import api_server_b2b_context as b2b_context
    from hermes_cli.plugins import get_plugin_manager

    preparations = []

    def _prepare(cap, *, resolved):
        preparations.append(cap)
        get_plugin_manager()._hooks.setdefault(
            "late_raw_admission_probe", []).append(lambda **kwargs: None)
        return execution_lane._UnitPreparation(cap)

    monkeypatch.setattr(b2b_context, "_prepare_b2b_context", _prepare)
    monkeypatch.setattr(execution_lane.b2b, "_spawn_run", _forbidden("_spawn_run"))
    before = admission._store_counts(case.store)

    response = await _launch(case)

    assert response.status == 503
    assert json.loads(response.body)["error"] == "non_plugin_hook_subscribers"
    assert len(preparations) == 1
    assert admission._store_counts(case.store) == before
    assert case.adapter._session_db.get_session(case.session_id)["title"] is None


@pytest.mark.asyncio
async def test_launch_refuses_real_concurrency_saturation_before_native_reads(
        tmp_path, monkeypatch, opened):
    case = _new_launch(tmp_path, monkeypatch, opened)
    capacity_gate = asyncio.Event()
    capacity_task = asyncio.create_task(capacity_gate.wait())
    case.adapter._max_concurrent_runs = 1
    case.adapter._active_run_tasks["run_test_capacity"] = capacity_task
    from gateway.platforms import api_server_b2b_context as b2b_context

    prepare_calls = []
    native_read_calls = []

    def _forbidden_prepare(*args, **kwargs):
        prepare_calls.append((args, kwargs))
        raise AssertionError("native preparation must not run at capacity")

    def _forbidden_native_read(*args, **kwargs):
        native_read_calls.append((args, kwargs))
        raise AssertionError("native read must not run at capacity")

    monkeypatch.setattr(
        b2b_context, "_prepare_b2b_context", _forbidden_prepare)
    monkeypatch.setattr(
        b2b_context, "_bounded_native_read", _forbidden_native_read)
    before = admission._store_counts(case.store)

    try:
        response = await _launch(case)

        assert response.status == 429
        assert json.loads(response.body)["error"]["code"] == "rate_limit_exceeded"
        assert prepare_calls == []
        assert native_read_calls == []
        assert admission._store_counts(case.store) == before
        assert case.adapter._session_db.get_session(case.session_id)["title"] is None
    finally:
        capacity_gate.set()
        await capacity_task
        case.adapter._active_run_tasks.pop("run_test_capacity", None)
