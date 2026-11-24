"""Legacy aliases of any native catalogue model are refused before admission.

The Codex P3 defect: the pre-admission guard compared against a frozen
``ROUTE["model"]`` constant, so a legacy project aliasing a native model with
any other route bypassed the authorization check. The guard must use the
operator-validated native catalogue, not a hard-coded route, and it must also
work when no ``native_n4`` project is configured at all.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

import pytest
from aiohttp import web

from agent.b2b_execution import B2BTerminalRefusal, bind_execution, reset_execution
from gateway import run as gateway_run
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from gateway.platforms import api_server_b2b as b2b
from gateway.run import _profile_runtime_scope
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


@pytest.fixture
def provider_endpoint():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def parse_request(self):
            ok = super().parse_request()
            requests.append(self.command)
            return ok

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        assert server.server_port >= 20000
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}/v1"
        finally:
            server.shutdown()
            thread.join()
            assert requests == []


def _bind_legacy(base_url):
    project = native._project_entry(
        native=False, project_id=native.LEGACY_PROJECT,
        provider="custom:legacy-lane", base_url=base_url)
    adapter = SimpleNamespace(_extra={"b2b": native._raw_config(
        projects={native.LEGACY_PROJECT: project})})
    b2b.bind_b2b_state(adapter)
    return adapter._b2b_state.config.profiles["deploy"]["projects"][native.LEGACY_PROJECT]


@pytest.mark.parametrize("variant", ["base_url", "api", "localhost", "ipv6"])
def test_startup_refuses_served_g2_addresses(tmp_path, provider_endpoint, variant):
    other = "http://127.0.0.1:22001/v1"
    entry = {
        "base_url": {"api": other, "base_url": provider_endpoint},
        "api": {"api": provider_endpoint, "base_url": other},
        "localhost": {"url": provider_endpoint.replace("http://127.0.0.1", "HTTP://LOCALHOST") + "/"},
        "ipv6": {"url": provider_endpoint.replace("127.0.0.1", "[::1]")},
    }[variant]
    (tmp_path / "config.yaml").write_text(json.dumps({"providers": {"b2b-g2": entry}}))
    with _profile_runtime_scope(tmp_path, hydrate_secrets=False):
        with TestCase().assertRaisesRegex(b2b.B2BConfigError, "native G2 catalogue"):
            _bind_legacy(provider_endpoint)


@pytest.mark.parametrize("error", ["broken-yaml", "missing", "unreadable"])
def test_startup_refuses_unreadable_gateway_config(tmp_path, provider_endpoint, error):
    path = tmp_path / "config.yaml"
    path.write_text("model: {}\n")
    with _profile_runtime_scope(tmp_path, hydrate_secrets=False):
        _bind_legacy(provider_endpoint)
        if error == "broken-yaml":
            path.write_text("providers: [\n")
        else:
            path.unlink()
            if error == "unreadable":
                path.mkdir()
        with TestCase().assertRaisesRegex(b2b.B2BConfigError, "gateway config"):
            _bind_legacy(provider_endpoint)


def test_unreadable_managed_config_never_becomes_an_empty_catalogue(tmp_path, monkeypatch, provider_endpoint):
    managed = tmp_path / "managed"
    managed.mkdir()
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    (tmp_path / "config.yaml").write_text("model: {}\n")
    with _profile_runtime_scope(tmp_path, hydrate_secrets=False):
        (managed / "config.yaml").write_text("{}\n")
        _bind_legacy(provider_endpoint)
        (managed / "config.yaml").write_text("providers: [\n")
        with TestCase().assertRaisesRegex(b2b.B2BConfigError, "gateway config"):
            _bind_legacy(provider_endpoint)


@pytest.mark.parametrize("change", [
    "moved-url", "renamed", "resolved-url", "resolved-name", "during-resolution", "effective-url",
    "effective-name", "unreadable", "off-g2"])
def test_legacy_at_provider_resolution(tmp_path, monkeypatch, provider_endpoint, change):
    config = {
        "model": {"context_length": 256000}, "compression": {"enabled": False},
        "providers": {"legacy-lane": {"name": "Legacy Lane", "base_url": provider_endpoint,
                                      "api_key": "unit-legacy-only"},
                      "b2b-g2": {"name": "Original G2", "base_url": "http://127.0.0.1:22001/v1",
                                 "api_key": "unit-native-only"}},
    }
    pin = "http://127.0.0.1:22002/v1" if change in ("resolved-url", "effective-url") else provider_endpoint
    config["providers"]["legacy-lane"]["base_url"] = pin
    path = tmp_path / "config.yaml"
    path.write_text(json.dumps(config))
    with _profile_runtime_scope(tmp_path, hydrate_secrets=False):
        project = _bind_legacy(pin)
        lane = execution_lane._ready_lane(tmp_path)
        execution_lane._rebind_project(lane, **project)
        ctor = Mock(side_effect=execution_lane._LaneAgent)
        monkeypatch.setattr("run_agent.AIAgent", ctor)
        if change == "moved-url":
            config["providers"]["b2b-g2"]["base_url"] = provider_endpoint
            # If invoked, the generic resolver could probe this model-less default.
            config["model"].update(default="", base_url=provider_endpoint)
        elif change == "renamed":
            config["providers"]["b2b-g2"]["name"] = "Legacy Lane"
        elif change == "resolved-url":
            for entry in config["providers"].values():
                entry["base_url"] = provider_endpoint
        elif change == "resolved-name":
            for entry in config["providers"].values():
                entry["name"] = "New G2"
        elif change in ("during-resolution", "effective-url", "effective-name"):
            resolve = gateway_run._resolve_runtime_agent_kwargs_for_provider

            def move_while_resolving(*args, **kwargs):
                # The real credential ladder sees a later edit than the preflight.
                for entry in config["providers"].values():
                    if change == "effective-name":
                        entry["name"] = "Renamed During Resolution"
                    else:
                        entry["base_url"] = provider_endpoint
                path.write_text(json.dumps(config))
                return resolve(*args, **kwargs)

            monkeypatch.setattr(gateway_run, "_resolve_runtime_agent_kwargs_for_provider", move_while_resolving)
        path.write_text("providers: [\n" if change == "unreadable" else json.dumps(config))
        token = bind_execution(lane.cap)
        try:
            if change == "off-g2":
                agent = execution_lane._construct(lane)
                assert (agent.provider, agent.model, agent.base_url, agent.api_key) == (
                    project["provider"], "legacy-model", provider_endpoint, "unit-legacy-only")
                agent.session_db.close()
            else:
                with TestCase().assertRaisesRegex(B2BTerminalRefusal, "^model_authorization_missing$"):
                    execution_lane._construct(lane)
                ctor.assert_not_called()
                assert lane.store.b2b_attempt(profile=lane.profile, attempt_id=lane.attempt_id)["status"] == "policy_changed"
        finally:
            reset_execution(token)
            lane.store.close()
