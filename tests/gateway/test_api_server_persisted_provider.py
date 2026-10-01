"""Persisted API session models retain the configured custom-provider identity."""

from unittest.mock import patch

import pytest
import yaml

import gateway.run as gateway_run
import hermes_cli.runtime_provider as runtime_provider
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


@pytest.mark.parametrize("configured_provider", ["personal-router", "custom:personal-router"])
def test_persisted_session_model_keeps_named_runtime_provider(
    tmp_path, monkeypatch, configured_provider
):
    persisted_model = "openrouter/openai/gpt-5.6-luna"
    homes = []
    for label in ("a", "b"):
        home = tmp_path / label
        home.mkdir()
        endpoint = f"http://router-{label}.example.test:20128/v1"
        credential = f"synthetic-router-{label}-credential"
        (home / "config.yaml").write_text(
            yaml.safe_dump({
                "model": {"provider": configured_provider, "default": "router/default"},
                "providers": {
                    "personal-router": {"base_url": endpoint, "api_key": credential}
                },
            }),
            encoding="utf-8",
        )
        homes.append((home, endpoint, credential))

    # Real config imports and resolution across A -> B -> A; no provider resolver fake.
    for home, endpoint, credential in (homes[0], homes[1], homes[0]):
        monkeypatch.setenv("HERMES_HOME", str(home))
        adapter = APIServerAdapter(PlatformConfig(enabled=True))
        runtime = gateway_run._resolve_runtime_agent_kwargs()
        assert runtime["provider"] == "custom"
        assert runtime["requested_provider"] == configured_provider

        with patch.object(
            runtime_provider, "resolve_runtime_provider",
            wraps=runtime_provider.resolve_runtime_provider,
        ) as resolve:
            model, *_ = adapter._select_agent_runtime(
                runtime, "router/default",
                requested_model=None, requested_provider=None, route=None,
                session_model=adapter._stored_session_model({"model": persisted_model}),
                confirmed_runtime_lock=False,
                gateway_session_key="personal:hub", session_id="session-hub",
            )

        resolve.assert_called_once_with(
            requested=configured_provider, target_model=persisted_model
        )
        assert model == persisted_model
        assert runtime["provider"] == "custom"
        assert runtime["base_url"] == endpoint
        assert runtime["api_key"] == credential
        assert runtime["base_url"] != "https://openrouter.ai/api/v1"
