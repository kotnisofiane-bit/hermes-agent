"""Legacy aliases of any native catalogue model are refused before admission.

The Codex P3 defect: the pre-admission guard compared against a frozen
``ROUTE["model"]`` constant, so a legacy project aliasing a native model with
any other route bypassed the authorization check. The guard must use the
operator-validated ``native_n4`` catalogue, not a hard-coded route.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from aiohttp import web

from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from gateway.platforms import api_server_b2b as b2b
from hermes_state import SessionDB
from tests.gateway import test_api_server_b2b_admission as admission
from tests.gateway import test_api_server_b2b_execution_lane as execution_lane
from tests.gateway import test_api_server_b2b_native_n2 as native

NATIVE_ALT_MODEL = "vendor/native-large-v2"


@pytest.mark.asyncio
async def test_legacy_alias_of_catalogue_native_model_is_refused(
        tmp_path, monkeypatch):
    profile_home = admission._profile_home(tmp_path, monkeypatch, "deploy")
    execution_lane._write_serving_config(profile_home)
    native_project = native._project_entry(
        native=True,
        run_ref={"path": str(tmp_path / "recipe.json"), "sha256": "0" * 64},
        model=NATIVE_ALT_MODEL,
        project_context={"project_id": native.PROJECT,
                         "allocation_root": str(tmp_path / "alloc"),
                         "start": str(tmp_path / "start")},
        native_n4=native._native_n4(
            "astra4-public-v1", model=NATIVE_ALT_MODEL))
    legacy_project = native._project_entry(
        native=False, project_id=native.LEGACY_PROJECT,
        model=NATIVE_ALT_MODEL)
    raw = native._raw_config(
        source_port=1,
        projects={native.PROJECT: native_project,
                  native.LEGACY_PROJECT: legacy_project},
        profile_name="deploy")
    extra = {"key": admission._API_KEY, "b2b": raw}
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra=extra))
    adapter.gateway_runner = SimpleNamespace(
        config=SimpleNamespace(multiplex_profiles=False))
    adapter._session_db = SessionDB(profile_home / "state.db")
    session_id = "b2b_" + "e" * 64
    adapter._session_db.create_session(session_id, "api_server")
    store = adapter._run_idempotency_store

    async def tripwire(*_args, **_kwargs):
        raise AssertionError("refused alias must not prepare a run")

    monkeypatch.setattr(b2b, "_b2b_run_bounded_preparation", tripwire)
    try:
        lane = execution_lane._ready_lane(tmp_path)
        resolved = execution_lane._launch_resolved(
            lane, profile="deploy", session_id=session_id)
        resolved["project_id"] = native.LEGACY_PROJECT
        resolved["project_binding_id"] = native.LEGACY_PROJECT
        resolved["profile"] = "deploy"
        resolved["session_id"] = session_id
        resolved["binding_digest"] = session_id[4:]
        resolved["attempt_id"] = b2b._attempt_id_for(session_id[4:])
        observation = dict(resolved["observation_genesis"])
        observation["id"], observation["profile"] = session_id, "deploy"
        resolved["observation_genesis"] = observation
        entry = raw["profiles"]["deploy"]
        response = await b2b._launch_b2b_run(
            adapter, None, profile="deploy", entry=entry,
            keys=b2b._KeyRing(entry), session_id=session_id,
            binding_digest=session_id[4:],
            attempt_id=resolved["attempt_id"], resolved=resolved,
            store=store, db=adapter._session_db)
        assert isinstance(response, web.Response)
        assert response.status == 403, response.body
        assert json.loads(response.body)["code"] == "model_authorization_missing"
        assert store.b2b_attempt(
            profile="deploy", attempt_id=resolved["attempt_id"]) is None
        assert store.b2b_binding(
            session_id=session_id, profile="deploy") is None
    finally:
        adapter._session_db.close()
        store.close()
