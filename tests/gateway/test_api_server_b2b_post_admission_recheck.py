"""The post-admission native policy recheck never runs plugin code on the loop.

The Codex P1 defect: ``sink.assert_current_policy()`` after ``b2b_admit``
called the plugin-owned ``validate_configuration`` synchronously inside
``_launch_b2b_run``. A validator that blocks froze the API event loop before
the run spawned. This exercises the REAL launch path with a preparation whose
validator parks: the request must refuse after its bounded budget while a
concurrent loop task keeps running, and no run is spawned.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest
from aiohttp import web
from types import SimpleNamespace

from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from gateway.platforms import api_server_b2b as b2b
from gateway.platforms.api_server_b2b_native_validation import _NATIVE_BINDING_KEYS
from hermes_state import SessionDB
from tests.gateway import test_api_server_b2b_admission as admission
from tests.gateway import test_api_server_b2b_execution_lane as execution_lane
from tests.gateway import test_api_server_b2b_native_n2 as native
from tests.gateway.b2b_process_harness import build_unit_native_oc_view


class _BlockingPreparation:
    def __init__(self, view, rendered, entered, gate):
        self.view = view
        self.rendered = rendered
        self.documents = ()
        self.source_deadline_ms = int((time.time() + 60) * 1000)
        self._entered = entered
        self._gate = gate

    def assert_configuration_current(self):
        self._entered.set()
        self._gate.wait(timeout=30.0)
        return True


@pytest.mark.asyncio
async def test_post_admission_recheck_is_bounded_and_off_loop(
        tmp_path, monkeypatch):
    profile_home = admission._profile_home(tmp_path, monkeypatch, "deploy")
    execution_lane._write_serving_config(profile_home)
    session_id = "b2b_" + "d" * 64
    project = native._project_entry(
        native=True,
        run_ref={"path": str(tmp_path / "recipe.json"), "sha256": "0" * 64},
        project_context={"project_id": native.PROJECT,
                         "allocation_root": str(tmp_path / "alloc"),
                         "start": str(tmp_path / "start")},
        native_n4=native._native_n4("astra4-public-v1"))
    raw = native._raw_config(
        source_port=1, projects={native.PROJECT: project}, profile_name="deploy")
    extra = {"key": admission._API_KEY, "b2b": raw}
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra=extra))
    adapter.gateway_runner = SimpleNamespace(
        config=SimpleNamespace(multiplex_profiles=False))
    adapter._session_db = SessionDB(profile_home / "state.db")
    adapter._session_db.create_session(session_id, "api_server")
    store = adapter._run_idempotency_store
    try:
        lane = execution_lane._ready_lane(tmp_path)
        entry = raw["profiles"]["deploy"]
        resolved = execution_lane._launch_resolved(
            lane, profile="deploy", session_id=session_id)
        resolved["project_id"] = native.PROJECT
        resolved["project_binding_id"] = native.PROJECT
        resolved["profile"] = "deploy"
        resolved["session_id"] = session_id
        resolved["binding_digest"] = session_id[4:]
        resolved["attempt_id"] = b2b._attempt_id_for(session_id[4:])
        resolved["tenant_id"] = "tenant-alpha"
        resolved["mission_inputs"] = {}
        resolved["_native_verified"] = True
        observation = dict(resolved["observation_genesis"])
        observation["id"], observation["profile"] = session_id, "deploy"
        resolved["observation_genesis"] = observation
        native_binding = {key: resolved[key] for key in _NATIVE_BINDING_KEYS}
        resolved["_native_binding"] = native_binding

        messages_digest = "ab" * 32
        claim = {
            "n2": {
                "binding": native_binding,
                "request_digest": resolved["request_digest"],
                "mission_source_digest": resolved["mission_source_digest"],
                "messages_digest": messages_digest,
            },
            "result_public_key": "cd" * 32,
        }

        policy = {"project": project, "profile_home": str(profile_home)}
        view = build_unit_native_oc_view(
            {**policy, "mission_request": resolved["mission_request"]},
            {"mission_source_digest": resolved["mission_source_digest"]},
            ordered=True)
        entered, gate = threading.Event(), threading.Event()
        preparation = _BlockingPreparation(
            view, b"rendered", entered, gate)

        async def fake_preparation(adapter_, **kwargs):
            kwargs["sink"]._context_preparation = preparation
            return None

        async def fake_spawn(*args, **kwargs):
            raise AssertionError("_spawn_run must not be reached")

        monkeypatch.setattr(b2b, "_SOURCE_DEADLINE_S", 0.5)
        monkeypatch.setattr(b2b, "_b2b_run_bounded_preparation", fake_preparation)
        monkeypatch.setattr(b2b, "_spawn_run", fake_spawn)
        monkeypatch.setattr(
            b2b, "native_recipe_messages_digest",
            lambda *_args, **_kwargs: messages_digest)
        monkeypatch.setattr(
            b2b._native_auth, "read_approval",
            lambda *_args, **_kwargs: claim)
        monkeypatch.setattr(
            b2b._native_auth, "check_source", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(
            b2b._native_auth, "check_preparation",
            lambda *_args, **_kwargs: None)

        watchdog = threading.Timer(2.0, gate.set)
        watchdog.start()
        task = None
        try:
            task = asyncio.create_task(b2b._launch_b2b_run(
                adapter, None, profile="deploy", entry=entry,
                keys=b2b._KeyRing(entry), session_id=session_id,
                binding_digest=session_id[4:],
                attempt_id=resolved["attempt_id"], resolved=resolved,
                store=store, db=adapter._session_db))
            started = time.monotonic()
            for _ in range(100):
                if entered.is_set():
                    break
                await asyncio.sleep(0.05)
            assert time.monotonic() - started < 1.0, (
                "the event loop was blocked by the configuration validator")
            assert entered.is_set(), "the validator recheck never ran"
            response = await asyncio.wait_for(task, timeout=2.0)
            assert isinstance(response, web.Response)
            assert response.status == 503, response.body
            assert json.loads(response.body)["code"] == "context_unavailable"
            attempt = store.b2b_attempt(
                profile="deploy", attempt_id=resolved["attempt_id"])
            assert attempt is not None
            assert attempt["status"] == "context_unavailable"
        finally:
            gate.set()
            watchdog.cancel()
            if task is not None:
                try:
                    if not task.done():
                        await asyncio.wait_for(task, timeout=5.0)
                    task.result()
                except BaseException:
                    pass
    finally:
        adapter._session_db.close()
        store.close()
