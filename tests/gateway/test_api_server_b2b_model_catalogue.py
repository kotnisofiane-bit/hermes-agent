"""Legacy aliases of any native catalogue model are refused before admission.

The Codex P3 defect: the pre-admission guard compared against a frozen
``ROUTE["model"]`` constant, so a legacy project aliasing a native model with
any other route bypassed the authorization check. The guard must use the
operator-validated native catalogue, not a hard-coded route, and it must also
work when no ``native_n4`` project is configured at all.
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
G2_SERVED_URL = "http://127.0.0.1:28921/v1"
G2_SERVED_CONFIG = {
    "providers": {
        "b2b-g2": {
            "name": "b2b-g2",
            "base_url": G2_SERVED_URL,
            "key_env": "B2B_G2_API_KEY",
            "api_mode": "chat_completions",
        }
    }
}


def _nat(config, gateway_config=None):
    with pytest.raises(native.m.B2BConfigError, match="native G2 catalogue"):
        if gateway_config is None:
            native.m.B2BConfig(config)
        else:
            native.m.B2BConfig(config, gateway_config=gateway_config)


def _write_g2_serving_config(home):
    """The served config names G2 at its own address, independently of any
    configured native project."""
    execution_lane._write_serving_config(home)
    with open(home / "config.yaml", "a") as fh:
        fh.write(
            "providers:\n  b2b-g2:\n"
            '    name: "b2b-g2"\n'
            f'    base_url: "{G2_SERVED_URL}"\n'
            '    key_env: "B2B_G2_API_KEY"\n'
            '    api_mode: "chat_completions"\n')


def test_legacy_alias_of_catalogue_native_model_is_refused():
    native_project = native._project_entry(
        native=True,
        model=NATIVE_ALT_MODEL,
        native_n4=native._native_n4(
            "astra4-public-v1", model=NATIVE_ALT_MODEL))
    legacy_project = native._project_entry(
        native=False, project_id=native.LEGACY_PROJECT,
        model=NATIVE_ALT_MODEL)
    _nat(native._raw_config(
        source_port=1,
        projects={native.PROJECT: native_project,
                  native.LEGACY_PROJECT: legacy_project},
        profile_name="deploy"))


@pytest.mark.parametrize("over", [
    {"model": native.MODEL},
    {"model": "MistralAI/Mistral-Large-4-1T-A52B"},
    {"model": "vendor/mistral-large-4-1t-a52b"},
    {"provider": "custom:b2b-g2"},
    {"provider": "b2b-g2"},
    {"provider": "B2B G2"},
], ids=["exact", "case", "provider-prefix", "g2-provider", "g2-bare-provider",
        "g2-spaced-provider"])
def test_legacy_g2_route_variants_are_refused_by_config(over):
    legacy_project = native._project_entry(
        native=False, project_id=native.LEGACY_PROJECT, **over)
    _nat(native._raw_config(
        source_port=1,
        projects={native.LEGACY_PROJECT: legacy_project},
        profile_name="deploy"))


def test_legacy_project_using_served_g2_display_alias_is_refused_by_config():
    legacy_project = native._project_entry(
        native=False, project_id=native.LEGACY_PROJECT,
        provider="g2-primary")
    _nat(native._raw_config(
        source_port=1,
        projects={native.LEGACY_PROJECT: legacy_project},
        profile_name="deploy"),
        gateway_config={"providers": {"b2b-g2": {
            "name": "G2 Primary", "base_url": G2_SERVED_URL}}})


def test_legacy_project_alone_on_served_g2_url_is_refused_by_config():
    legacy_project = native._project_entry(
        native=False, project_id=native.LEGACY_PROJECT,
        base_url=G2_SERVED_URL)
    _nat(native._raw_config(
        source_port=1,
        projects={native.LEGACY_PROJECT: legacy_project},
        profile_name="deploy"), gateway_config=G2_SERVED_CONFIG)


def test_legacy_project_sharing_native_g2_url_is_refused_by_config():
    native_project = native._project_entry()
    legacy_project = native._project_entry(
        native=False, project_id=native.LEGACY_PROJECT,
        base_url=native.BASE_URL)
    _nat(native._raw_config(
        source_port=1,
        projects={native.PROJECT: native_project,
                  native.LEGACY_PROJECT: legacy_project},
        profile_name="deploy"))


def test_legacy_off_g2_project_is_accepted_by_config():
    config = native.m.B2BConfig(native._raw_config(
        source_port=1,
        projects={native.LEGACY_PROJECT: native._project_entry(
            native=False, project_id=native.LEGACY_PROJECT)},
        profile_name="deploy"))
    project = config.profiles["deploy"]["projects"][native.LEGACY_PROJECT]
    assert project["model"] == "legacy-model"
    assert project["provider"] == "custom"


def test_legacy_off_g2_project_is_accepted_with_served_g2_entry():
    config = native.m.B2BConfig(native._raw_config(
        source_port=1,
        projects={native.LEGACY_PROJECT: native._project_entry(
            native=False, project_id=native.LEGACY_PROJECT)},
        profile_name="deploy"), gateway_config=G2_SERVED_CONFIG)
    project = config.profiles["deploy"]["projects"][native.LEGACY_PROJECT]
    assert project["model"] == "legacy-model"
    assert project["base_url"] == native._project_entry(
        native=False, project_id=native.LEGACY_PROJECT)["base_url"]


async def _assert_legacy_route_refused(tmp_path, monkeypatch, over, *,
                                       serve_g2):
    profile_home = admission._profile_home(tmp_path, monkeypatch, "deploy")
    if serve_g2:
        _write_g2_serving_config(profile_home)
    else:
        execution_lane._write_serving_config(profile_home)
    import gateway.run as gw_run
    monkeypatch.setattr(gw_run, "_hermes_home", profile_home, raising=False)
    legacy_project = native._project_entry(
        native=False, project_id=native.LEGACY_PROJECT)
    raw = native._raw_config(
        source_port=1,
        projects={native.LEGACY_PROJECT: legacy_project},
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
        raise AssertionError("refused legacy G2 project must not prepare a run")

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
        # The operator config stays a valid legacy project; only the raw entry
        # the route consumes claims the G2 provider/URL/model.
        entry["projects"][native.LEGACY_PROJECT].update(over)
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


@pytest.mark.asyncio
async def test_legacy_project_alone_on_g2_with_native_model_gets_403(
        tmp_path, monkeypatch):
    await _assert_legacy_route_refused(tmp_path, monkeypatch, {
        "model": native.MODEL,
        "provider": "custom:b2b-g2",
        "base_url": native.BASE_URL,
    }, serve_g2=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("over", [
    {"provider": "b2b-g2"},
    {"provider": "B2B G2"},
    {"base_url": G2_SERVED_URL},
], ids=["g2-bare-provider", "g2-spaced-provider", "served-g2-url"])
async def test_legacy_project_alone_on_served_g2_gets_403(
        tmp_path, monkeypatch, over):
    await _assert_legacy_route_refused(
        tmp_path, monkeypatch, over, serve_g2=True)
