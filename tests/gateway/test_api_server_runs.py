"""Tests for /v1/runs endpoints: start, status, events, steer, and stop.

Covers:
- POST /v1/runs — start a run (202)
- GET /v1/runs/{run_id} — poll run status
- GET /v1/runs/{run_id}/events — SSE event stream
- POST /v1/runs/{run_id}/steer — inject guidance into a running agent
- POST /v1/runs/{run_id}/stop — interrupt a running agent
- Auth, error handling, and cleanup
"""

import asyncio
import copy
import hashlib
import json
import threading
import time
import weakref
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent.b2b_execution import (
    B2BTerminalRefusal, BoundExecution, bind_execution, extract_allowed_refs,
    json_utf8, native_context_digest, recheck_context, reset_execution, source_basis,
    validate_proposal,
)
from gateway.config import PlatformConfig
from gateway.platforms import api_server_b2b as b2b
from gateway.platforms.api_server import (
    APIServerAdapter,
    _api_request_profile,
    _approval_event_choices,
    cors_middleware,
    security_headers_middleware,
)
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from hermes_constants import get_hermes_home
from tests.gateway.b2b_process_harness import (
    UNIT_RENDERED, build_context_view, extract_contract_root, make_keypair,
)
from tools import approval as approval_mod
from tools import approval_gateway_wait


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("smart_denied", "allow_session", "allow_permanent", "expected"),
    [
        (False, True, True, ["once", "session", "always", "deny"]),
        (False, True, False, ["once", "session", "deny"]),
        (False, False, True, ["once", "deny"]),
        (False, False, False, ["once", "deny"]),
        (True, True, True, ["once", "deny"]),
        (True, False, False, ["once", "deny"]),
    ],
)
def test_approval_event_choices_follow_backend_capabilities(
    smart_denied, allow_session, allow_permanent, expected
):
    assert (
        _approval_event_choices(
            smart_denied=smart_denied,
            allow_session=allow_session,
            allow_permanent=allow_permanent,
        )
        == expected
    )


def _make_adapter(api_key: str = "") -> APIServerAdapter:
    """Create an adapter with optional API key."""
    extra = {}
    if api_key:
        extra["key"] = api_key
    config = PlatformConfig(enabled=True, extra=extra)
    adapter = APIServerAdapter(config)
    return adapter


def _claim_run(adapter: APIServerAdapter, run_id: str) -> None:
    """Stamp *run_id* as owned by the unprefixed (default) request scope."""
    request = MagicMock()
    request.headers = {}
    adapter._run_owners[run_id] = adapter._run_idempotency_scope(request)


def _create_runs_app(adapter: APIServerAdapter) -> web.Application:
    """Create an aiohttp app with /v1/runs routes registered."""
    mws = [mw for mw in (cors_middleware, security_headers_middleware) if mw is not None]
    app = web.Application(middlewares=mws)
    app["api_server_adapter"] = adapter
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_post(
        "/v1/room-members/invitations",
        adapter._handle_room_member_invitation,
    )
    app.router.add_get(
        "/v1/room-members/capabilities",
        adapter._handle_room_member_capabilities,
    )
    app.router.add_post(
        "/v1/room-members/grants/refresh",
        adapter._handle_room_member_grant_refresh,
    )
    app.router.add_post(
        "/v1/room-members/grants/revoke",
        adapter._handle_room_member_grant_revoke,
    )
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    app.router.add_get("/v1/runs/{run_id}/events", adapter._handle_run_events)
    app.router.add_post("/v1/runs/{run_id}/approval", adapter._handle_run_approval)
    app.router.add_post("/v1/runs/{run_id}/steer", adapter._handle_steer_run)
    app.router.add_post("/v1/runs/{run_id}/stop", adapter._handle_stop_run)
    return app


def _make_slow_agent(**kwargs):
    """Create a mock agent that blocks in run_conversation until interrupted.

    Returns (mock_agent, agent_ready_event, interrupt_event) where
    agent_ready_event is set once run_conversation starts, and
    interrupt_event is set when interrupt() is called.
    """
    ready = threading.Event()
    interrupted = threading.Event()

    mock_agent = MagicMock()

    def _do_interrupt(message=None):
        interrupted.set()

    mock_agent.interrupt = MagicMock(side_effect=_do_interrupt)

    def _slow_run(user_message=None, conversation_history=None, task_id=None):
        ready.set()
        # Block until interrupt() is called
        interrupted.wait(timeout=10)
        return {"final_response": "interrupted", "interrupted": True}

    mock_agent.run_conversation.side_effect = _slow_run
    mock_agent.session_prompt_tokens = 0
    mock_agent.session_completion_tokens = 0
    mock_agent.session_total_tokens = 0

    return mock_agent, ready, interrupted


@pytest.fixture
def adapter():
    return _make_adapter()


@pytest.fixture
def auth_adapter():
    return _make_adapter(api_key="sk-secret")


# ---------------------------------------------------------------------------
# POST /v1/runs — start a run
# ---------------------------------------------------------------------------


class TestStartRun:
    @pytest.mark.asyncio
    async def test_room_auth_is_validated_before_body_parse_or_work_reservation(
        self, auth_adapter
    ):
        from gateway.platforms import api_server_runs

        app = _create_runs_app(auth_adapter)
        handler = AsyncMock()
        with patch.object(api_server_runs, "_handle_runs", handler):
            async with TestClient(TestServer(app)) as cli:
                response = await cli.post(
                    "/v1/runs",
                    data="{this body must never be parsed",
                    headers={
                        "Authorization": "HermesRoom invalid-token",
                        "Content-Type": "application/json",
                    },
                )
                body = await response.json()

        assert response.status == 401
        assert body["error"]["code"] == "invalid_room_grant"
        assert auth_adapter._pending_agent_requests == 0
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_start_returns_202(self, adapter):
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.run_conversation.return_value = {"final_response": "done"}
                mock_agent.session_prompt_tokens = 10
                mock_agent.session_completion_tokens = 5
                mock_agent.session_total_tokens = 15
                mock_create.return_value = mock_agent

                resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert resp.status == 202
                data = await resp.json()
                assert data["status"] == "started"
                assert data["run_id"].startswith("run_")

                status_resp = await cli.get(f"/v1/runs/{data['run_id']}")
                assert status_resp.status == 200
                status = await status_resp.json()
                assert status["run_id"] == data["run_id"]
                assert status["status"] in {"queued", "running", "completed"}
                assert status["object"] == "hermes.run"

    @pytest.mark.asyncio
    async def test_start_binds_chat_id_for_delegation_wake_target(self, adapter):
        """/v1/runs must bind the raw session id as the api_server chat_id
        (like every other agent-entry route does via _run_agent): the async
        delegation dispatch reads HERMES_SESSION_CHAT_ID to pick its wake
        self-post target, and an empty binding forces background delegations
        on this route back to synchronous execution."""
        app = _create_runs_app(adapter)
        captured = {}

        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()

                def _capture_run(user_message=None, conversation_history=None, task_id=None):
                    from tools.async_delegation import _current_origin_session_id

                    captured["origin_session_id"] = _current_origin_session_id()
                    return {"final_response": "done"}

                mock_agent.run_conversation.side_effect = _capture_run
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                mock_create.return_value = mock_agent

                resp = await cli.post(
                    "/v1/runs",
                    json={"input": "hello", "session_id": "runs-raw-sid"},
                )
                assert resp.status == 202
                data = await resp.json()
                run_id = data["run_id"]

                for _ in range(40):
                    status_resp = await cli.get(f"/v1/runs/{run_id}")
                    status = await status_resp.json()
                    if status["status"] == "completed":
                        break
                    await asyncio.sleep(0.05)

        assert captured.get("origin_session_id") == "runs-raw-sid", (
            "runs route must bind chat_id so delegation dispatch sees a wake target"
        )

    @staticmethod
    async def _wait_completed(cli, run_id: str) -> None:
        for _ in range(40):
            status = await (await cli.get(f"/v1/runs/{run_id}")).json()
            if status["status"] == "completed":
                return
            await asyncio.sleep(0.05)
        raise AssertionError(f"run {run_id} did not complete")

    @staticmethod
    def _capturing_agent(captured):
        agent = MagicMock()
        agent.run_conversation.side_effect = lambda **kwargs: captured.update(kwargs) or {"final_response": "done"}
        agent.session_prompt_tokens = agent.session_completion_tokens = agent.session_total_tokens = 0
        return agent

    @pytest.mark.asyncio
    @pytest.mark.parametrize("body, expected", [
        ({"input": "hello", "author": {"id": "bot:dixie", "name": " dixie ", "is_bot": True, "role": "admin"}},
         {"id": "bot:dixie", "name": "dixie", "is_bot": True}),
        ({"input": "hello", "author": {"id": "bot:dixie", "name": "dixie", "is_bot": True, "origin": "cloud-1"}},
         {"id": "bot:cloud-1/dixie", "name": "dixie", "is_bot": True}),
        ({"input": "hello"}, "absent"),
    ], ids=["author", "author with origin", "no author"])
    async def test_start_passes_normalized_author_to_run_conversation(self, adapter, body, expected):
        """A body ``author`` reaches ``run_conversation`` normalized; it labels memory only. Without one the
        call keeps today's shape."""
        app = _create_runs_app(adapter)
        captured = {}

        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent", return_value=self._capturing_agent(captured)):
                resp = await cli.post("/v1/runs", json=body)
                assert resp.status == 202
                await self._wait_completed(cli, (await resp.json())["run_id"])

        assert captured["user_message"] == "hello"
        assert captured.get("turn_author", "absent") == expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize("author", ["dixie", ["dixie"], 7])
    async def test_start_rejects_non_object_author(self, adapter, author):
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                resp = await cli.post("/v1/runs", json={"input": "hello", "author": author})
                assert resp.status == 400
                body = await resp.json()
        assert body["error"]["code"] == "invalid_author"
        mock_create.assert_not_called()
        assert adapter._run_statuses == {}


    @pytest.mark.asyncio
    async def test_start_rejects_conflicting_route_and_request_provider(self):
        adapter = APIServerAdapter(
            PlatformConfig(
                enabled=True,
                extra={
                    "model_routes": {
                        "alias": {
                            "model": "route/model",
                            "provider": "openrouter",
                        }
                    }
                },
            )
        )
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                resp = await cli.post(
                    "/v1/runs",
                    json={
                        "input": "hello",
                        "model": "alias",
                        "provider": "minimax",
                    },
                )
                data = await resp.json()

        assert resp.status == 400
        assert "provider" in data["error"]["message"].lower()
        assert adapter._run_streams == {}
        assert adapter._run_statuses == {}
        mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_events_stream_forwards_interim_commentary(self, adapter):
        """Mid-turn assistant commentary (Codex ``phase="commentary"``) reaches /v1/runs clients
        as ``message.interim`` {text, already_streamed}; the final answer is unchanged (#67580)."""
        import json

        app = _create_runs_app(adapter)

        def create_agent(**kwargs):
            interim = kwargs["interim_assistant_callback"]
            agent = MagicMock()

            def run_conversation(**_kw):
                interim("Checking the docs first.", already_streamed=False)
                interim("Applying the fix.", already_streamed=True)
                return {"final_response": "Done."}

            agent.run_conversation.side_effect = run_conversation
            agent.session_prompt_tokens = agent.session_completion_tokens = agent.session_total_tokens = 0
            return agent

        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent", side_effect=create_agent):
                resp = await cli.post("/v1/runs", json={"input": "hello"})
                run_id = (await resp.json())["run_id"]
                body = await (await cli.get(f"/v1/runs/{run_id}/events")).text()

        events = [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]
        interim = [(e["text"], e["already_streamed"]) for e in events if e["event"] == "message.interim"]
        assert interim == [("Checking the docs first.", False), ("Applying the fix.", True)]
        completed = next(e for e in events if e["event"] == "run.completed")
        assert completed["output"] == "Done."

    @pytest.mark.asyncio
    async def test_start_passes_request_model_provider_options_to_create_agent(self, adapter):
        app = _create_runs_app(adapter)
        model_options = {"reasoning_effort": "medium", "service_tier": "priority"}
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.run_conversation.return_value = {"final_response": "done"}
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                mock_create.return_value = mock_agent

                resp = await cli.post(
                    "/v1/runs",
                    json={
                        "input": "hello",
                        "model": "MiniMax-M3",
                        "provider": "minimax",
                        "model_options": model_options,
                    },
                )
                assert resp.status == 202
                for _ in range(20):
                    if mock_create.call_args is not None:
                        break
                    await asyncio.sleep(0.05)

        kwargs = mock_create.call_args.kwargs
        assert kwargs["requested_model"] == "MiniMax-M3"
        assert kwargs["requested_provider"] == "minimax"
        assert kwargs["model_options"] == model_options


# ---------------------------------------------------------------------------
# GET /v1/runs/{run_id} — poll run status
# ---------------------------------------------------------------------------


class TestRunStatus:

    @pytest.mark.asyncio
    async def test_drain_boundary_is_visible_to_pollers_on_live_runs_only(self, adapter):
        """GET /v1/runs/{id} shows ``shutdown_requested_at`` as soon as the drain starts (#115133).

        A live run keeps ``status: running`` (it is still being served) but gains the marker,
        durably (the idempotency record carries it across a restart); a run whose status is set
        after the boundary inherits it; a terminal run is never touched.
        """
        status = adapter._set_run_status("run_live", "running")
        _claim_run(adapter, "run_live")
        scope = adapter._run_owners["run_live"]
        adapter._run_idempotency_store.reserve(
            scope, "shutdown-test-key", "shutdown-test-fingerprint", "run_live", status)
        adapter._run_idempotency_ids.add("run_live")
        adapter._run_statuses["run_done"] = {
            "object": "hermes.run", "run_id": "run_done", "status": "completed"}
        _claim_run(adapter, "run_done")

        async with TestClient(TestServer(_create_runs_app(adapter))) as client:
            before = await (await client.get("/v1/runs/run_live")).json()
            assert "shutdown_requested_at" not in before

            assert adapter.mark_shutdown_requested() == 1

            live = await (await client.get("/v1/runs/run_live")).json()
            assert live["status"] == "running"
            marker = live["shutdown_requested_at"]
            assert isinstance(marker, float)
            done = await (await client.get("/v1/runs/run_done")).json()
            assert "shutdown_requested_at" not in done

        durable = adapter._run_idempotency_store.status_for_run(scope, "run_live")
        assert durable["status"].get("shutdown_requested_at") == marker
        adapter._set_run_status("run_late", "queued")
        assert adapter._run_statuses["run_late"]["shutdown_requested_at"] == marker

    @pytest.mark.asyncio
    async def test_status_reflects_explicit_session_id(self, adapter):
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.run_conversation.return_value = {"final_response": "done"}
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                mock_create.return_value = mock_agent

                resp = await cli.post(
                    "/v1/runs",
                    json={"input": "hello", "session_id": "space-session"},
                )
                data = await resp.json()
                run_id = data["run_id"]

                for _ in range(20):
                    status_resp = await cli.get(f"/v1/runs/{run_id}")
                    status = await status_resp.json()
                    if status["status"] == "completed":
                        break
                    await asyncio.sleep(0.05)

                mock_agent.run_conversation.assert_called_once()
                assert mock_agent.run_conversation.call_args.kwargs["task_id"] == "space-session"
                assert status["session_id"] == "space-session"

    @pytest.mark.asyncio
    async def test_status_completed_run_reports_served_runtime_and_cache_tokens(self, adapter):
        """After a fallback_providers switch the run record carries the runtime that actually
        served the turn plus cache-read tokens, next to the requested ``model`` (#102101).

        ``agent.provider`` / ``agent.model`` still hold the fallback pair when
        ``run_conversation()`` returns: the primary is only restored at the start of the NEXT
        turn, so they are the served pair, while the top-level ``model`` echoes the request.
        """
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.run_conversation.return_value = {"final_response": "done"}
                mock_agent.provider = "openai-codex"
                mock_agent.model = "gpt-5.6-luna"
                mock_agent.session_prompt_tokens = 100
                mock_agent.session_completion_tokens = 5
                mock_agent.session_total_tokens = 105
                mock_agent.session_cache_read_tokens = 84
                mock_agent.session_cache_write_tokens = 11
                mock_create.return_value = mock_agent

                resp = await cli.post("/v1/runs", json={"input": "hello", "model": "deepseek-v4-pro"})
                run_id = (await resp.json())["run_id"]

                for _ in range(40):
                    status = await (await cli.get(f"/v1/runs/{run_id}")).json()
                    if status["status"] == "completed":
                        break
                    await asyncio.sleep(0.05)

                assert status["status"] == "completed"
                # Top-level model still echoes the request; the served pair is disclosed alongside.
                assert status["model"] == "deepseek-v4-pro"
                # Canonical api_server runtime shape (same as /v1/chat/completions), not a thinner twin.
                assert status["runtime"] == {
                    "provider": "openai-codex", "model": "gpt-5.6-luna", "route_source": "raw_request",
                    "requested": {"provider": "", "model": "deepseek-v4-pro"},
                }
                assert status["usage"] == {
                    "input_tokens": 100, "output_tokens": 5, "total_tokens": 105,
                    "cache_read_tokens": 84, "cache_write_tokens": 11,
                }


# ---------------------------------------------------------------------------
# GET /v1/runs/{run_id}/events — SSE event stream
# ---------------------------------------------------------------------------


class TestRunEvents:
    @pytest.mark.asyncio
    async def test_tool_completed_event_includes_redacted_bounded_result_preview(self, adapter):
        loop = asyncio.get_running_loop()
        adapter._run_streams["run_tool"] = asyncio.Queue()
        callback = adapter._make_run_event_callback("run_tool", loop)

        callback(
            "tool.completed", "terminal", duration=0.077, is_error=True,
            result={
                "exit_code": 2,
                "error": "BLOCKED: approval required",
                "token": "sk-abcdefghijklmnopqrstuvwxyz",
                "output": "x" * 600,
            },
        )
        event = await adapter._run_streams["run_tool"].get()

        assert event["error"] is True
        assert "BLOCKED: approval required" in event["preview"]
        assert "abcdefghijklmnopqrstuvwxyz" not in event["preview"]
        assert len(event["preview"]) <= 500
        assert event["preview"].endswith("...")

    @pytest.mark.asyncio
    async def test_events_stream_returns_completed(self, adapter):
        """Events stream should receive run.completed when agent finishes."""
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.run_conversation.return_value = {"final_response": "Hello!"}
                mock_agent.session_prompt_tokens = 10
                mock_agent.session_completion_tokens = 5
                mock_agent.session_total_tokens = 15
                mock_create.return_value = mock_agent

                # Start run
                resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert resp.status == 202
                data = await resp.json()
                run_id = data["run_id"]

                # Subscribe to events
                events_resp = await cli.get(f"/v1/runs/{run_id}/events")
                assert events_resp.status == 200
                body = await events_resp.text()

                # Should contain run.completed
                assert "run.completed" in body
                assert "Hello!" in body

    @pytest.mark.asyncio
    async def test_completed_event_carries_served_runtime_and_cache_tokens(self, adapter):
        """The run.completed SSE event discloses the same served runtime and cache tokens as the
        pollable status, so streaming clients get identical cost-attribution data (#102101)."""
        import json as _json

        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.run_conversation.return_value = {"final_response": "served"}
                mock_agent.provider = "openai-codex"
                mock_agent.model = "gpt-5.6-luna"
                mock_agent.session_prompt_tokens = 774050
                mock_agent.session_completion_tokens = 6286
                mock_agent.session_total_tokens = 780336
                mock_agent.session_cache_read_tokens = 650000
                mock_agent.session_cache_write_tokens = 42
                mock_create.return_value = mock_agent

                resp = await cli.post("/v1/runs", json={"input": "hello", "model": "deepseek-v4-pro"})
                run_id = (await resp.json())["run_id"]

                events_resp = await cli.get(f"/v1/runs/{run_id}/events")
                assert events_resp.status == 200
                body = await events_resp.text()

                completed = None
                for frame in body.split("\n"):
                    if frame.startswith("data: "):
                        try:
                            payload = _json.loads(frame[len("data: "):])
                        except ValueError:
                            continue
                        if payload.get("event") == "run.completed":
                            completed = payload
                            break
                assert completed is not None, "run.completed event missing from stream"
                assert completed["runtime"]["provider"] == "openai-codex"
                assert completed["runtime"]["model"] == "gpt-5.6-luna"
                assert completed["runtime"]["requested"]["model"] == "deepseek-v4-pro"
                assert completed["usage"]["cache_read_tokens"] == 650000
                assert completed["usage"]["cache_write_tokens"] == 42


    @pytest.mark.asyncio
    async def test_approval_resolve_all_is_scoped_to_target_run(self, auth_adapter):
        """Same client session_id must not let one run approve another run's queue."""
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(auth_adapter, "_create_agent") as mock_create:
                victim_agent, victim_ready, victim_interrupted = _make_slow_agent()
                attacker_agent, attacker_ready, attacker_interrupted = _make_slow_agent()
                mock_create.side_effect = [victim_agent, attacker_agent]

                victim_resp = await cli.post(
                    "/v1/runs",
                    json={"input": "victim", "session_id": "shared-project"},
                    headers={"Authorization": "Bearer sk-secret"},
                )
                attacker_resp = await cli.post(
                    "/v1/runs",
                    json={"input": "attacker", "session_id": "shared-project"},
                    headers={"Authorization": "Bearer sk-secret"},
                )
                assert victim_resp.status == 202
                assert attacker_resp.status == 202
                victim_run = (await victim_resp.json())["run_id"]
                attacker_run = (await attacker_resp.json())["run_id"]

                victim_ready.wait(timeout=3.0)
                attacker_ready.wait(timeout=3.0)
                assert auth_adapter._run_approval_sessions[victim_run] == victim_run
                assert auth_adapter._run_approval_sessions[attacker_run] == attacker_run
                assert auth_adapter._run_approval_sessions[victim_run] != auth_adapter._run_approval_sessions[attacker_run]

                victim_entry = approval_gateway_wait._ApprovalEntry({
                    "command": "bash -c victim-danger",
                    "description": "victim approval",
                    "pattern_keys": ["shell-c"],
                })
                attacker_entry = approval_gateway_wait._ApprovalEntry({
                    "command": "bash -c attacker-danger",
                    "description": "attacker approval",
                    "pattern_keys": ["shell-c"],
                })
                with approval_mod._lock:
                    approval_mod._gateway_queues[victim_run] = [victim_entry]
                    approval_mod._gateway_queues[attacker_run] = [attacker_entry]

                approval_resp = await cli.post(
                    f"/v1/runs/{attacker_run}/approval",
                    json={"choice": "always", "resolve_all": True},
                    headers={"Authorization": "Bearer sk-secret"},
                )
                approval_data = await approval_resp.json()

                assert approval_resp.status == 200
                assert approval_data["resolved"] == 1
                assert attacker_entry.result == "always"
                assert attacker_entry.event.is_set()
                assert victim_entry.result is None
                assert not victim_entry.event.is_set()
                with approval_mod._lock:
                    assert approval_mod._gateway_queues[victim_run] == [victim_entry]
                    assert victim_run in approval_mod._gateway_queues
                    assert attacker_run not in approval_mod._gateway_queues

                # Clean up the synthetic pending victim approval and unblock the
                # slow test agents so their background run tasks can finish.
                with approval_mod._lock:
                    approval_mod._gateway_queues.pop(victim_run, None)
                victim_interrupted.set()
                attacker_interrupted.set()


# ---------------------------------------------------------------------------
# POST /v1/runs/{run_id}/steer — steer a running agent
# ---------------------------------------------------------------------------


class TestSteerRun:
    @pytest.mark.asyncio
    async def test_steer_running_agent(self, adapter):
        app = _create_runs_app(adapter)
        agent = MagicMock()
        agent.steer.return_value = True
        queue = asyncio.Queue()
        adapter._active_run_agents["run_123"] = agent
        adapter._run_streams["run_123"] = queue
        adapter._set_run_status("run_123", "running")
        _claim_run(adapter, "run_123")

        async with TestClient(TestServer(app)) as cli:
            resp = await cli.post("/v1/runs/run_123/steer", json={"input": "tighten the ending"})
            payload = await resp.json()

        assert resp.status == 200
        assert payload == {
            "object": "hermes.run.steer",
            "run_id": "run_123",
            "accepted": True,
        }
        agent.steer.assert_called_once_with("tighten the ending")
        assert adapter._run_statuses["run_123"]["last_event"] == "run.steered"
        event = queue.get_nowait()
        assert event["event"] == "run.steered"
        assert event["run_id"] == "run_123"
        assert event["accepted"] is True

    @pytest.mark.asyncio
    async def test_steer_nonexistent_run_returns_404(self, adapter):
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            resp = await cli.post("/v1/runs/run_missing/steer", json={"input": "hello"})
            payload = await resp.json()

        assert resp.status == 404
        assert payload["error"]["code"] == "run_not_found"

    @pytest.mark.asyncio
    async def test_steer_inactive_run_returns_409(self, adapter):
        app = _create_runs_app(adapter)
        adapter._set_run_status("run_done", "completed")
        _claim_run(adapter, "run_done")

        async with TestClient(TestServer(app)) as cli:
            resp = await cli.post("/v1/runs/run_done/steer", json={"input": "hello"})
            payload = await resp.json()

        assert resp.status == 409
        assert payload["error"]["code"] == "run_not_accepting_steer"

    @pytest.mark.asyncio
    async def test_steer_missing_input_returns_400(self, adapter):
        app = _create_runs_app(adapter)
        agent = MagicMock()
        agent.steer.return_value = True
        adapter._active_run_agents["run_123"] = agent
        adapter._set_run_status("run_123", "running")
        _claim_run(adapter, "run_123")

        async with TestClient(TestServer(app)) as cli:
            resp = await cli.post("/v1/runs/run_123/steer", json={"input": ""})
            payload = await resp.json()

        assert resp.status == 400
        assert payload["error"]["code"] == "invalid_steer_input"
        agent.steer.assert_not_called()

    @pytest.mark.asyncio
    async def test_stop_then_steer_rejects_retained_agent_ref(self, adapter):
        """Steer must reject a stopping run even if the executor thread is still live."""
        app = _create_runs_app(adapter)
        run_can_finish = threading.Event()
        run_started = threading.Event()

        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                mock_agent.steer = MagicMock(return_value=True)

                def _interrupt(_message=None):
                    return None

                def _run_conversation(*_args, **_kwargs):
                    run_started.set()
                    run_can_finish.wait(timeout=5)
                    return {"final_response": "late result"}

                mock_agent.interrupt = MagicMock(side_effect=_interrupt)
                mock_agent.run_conversation.side_effect = _run_conversation
                mock_create.return_value = mock_agent

                start_resp = await cli.post("/v1/runs", json={"input": "hello"})
                run_id = (await start_resp.json())["run_id"]
                assert run_started.wait(timeout=3.0)

                stop_resp = await cli.post(f"/v1/runs/{run_id}/stop")
                assert stop_resp.status == 200
                assert run_id in adapter._active_run_agents

                steer_resp = await cli.post(
                    f"/v1/runs/{run_id}/steer",
                    json={"input": "tighten the ending"},
                )
                steer_data = await steer_resp.json()

                assert steer_resp.status == 409
                assert steer_data["error"]["code"] == "run_not_accepting_steer"
                mock_agent.steer.assert_not_called()

                run_can_finish.set()
                for _ in range(40):
                    if run_id not in adapter._active_run_tasks:
                        break
                    await asyncio.sleep(0.05)

    @pytest.mark.asyncio
    async def test_pending_steer_preserved_on_run_completed(self, adapter):
        """A steer drained by the turn finalizer (accepted after the final
        response) must surface as pending_steer on the terminal run status
        instead of being silently dropped."""
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                mock_agent.run_conversation.return_value = {
                    "final_response": "done",
                    "pending_steer": "tighten the ending",
                }
                mock_create.return_value = mock_agent

                start_resp = await cli.post("/v1/runs", json={"input": "hello"})
                run_id = (await start_resp.json())["run_id"]

                for _ in range(40):
                    status = adapter._run_statuses.get(run_id, {})
                    if status.get("status") == "completed":
                        break
                    await asyncio.sleep(0.05)

        assert adapter._run_statuses[run_id]["status"] == "completed"
        assert adapter._run_statuses[run_id]["pending_steer"] == "tighten the ending"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("result", "expected_status"),
        [
            ({"final_response": "Operation interrupted.", "interrupted": True, "completed": False}, "cancelled"),
            ({"final_response": "Budget exhausted summary.", "completed": False,
              "turn_exit_reason": "max_iterations_reached(2/2)"}, "failed"),
            ({"final_response": "done", "completed": True}, "completed"),
        ],
    )
    async def test_run_terminal_status_follows_result_flags(self, adapter, result, expected_status):
        """A turn that ended interrupted or unfinished must not be booked as ``completed``
        (#111770): the persisted status, the ``completed`` flag and the terminal event name
        agree, and a late steer survives on every terminal status."""
        result["pending_steer"] = "tighten the ending"
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                mock_agent.run_conversation.return_value = result
                mock_create.return_value = mock_agent

                start_resp = await cli.post("/v1/runs", json={"input": "hello"})
                run_id = (await start_resp.json())["run_id"]
                for _ in range(40):
                    if adapter._run_statuses.get(run_id, {}).get("status") == expected_status:
                        break
                    await asyncio.sleep(0.05)
                events = await (await cli.get(f"/v1/runs/{run_id}/events")).text()

        status = adapter._run_statuses[run_id]
        assert status["status"] == expected_status
        assert status["completed"] is (expected_status == "completed")
        assert status["pending_steer"] == "tighten the ending"
        assert f"run.{expected_status}" in events

    @pytest.mark.asyncio
    async def test_steer_requires_auth(self, auth_adapter):
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            resp = await cli.post("/v1/runs/run_any/steer", json={"input": "hello"})

        assert resp.status == 401


# ---------------------------------------------------------------------------
# Run lifecycle TTL sweeping
# ---------------------------------------------------------------------------


class TestRunLifecycleSweep:

    @pytest.mark.asyncio
    async def test_expired_live_run_drops_transport_but_keeps_control_state(self, adapter):
        """Stream TTL bounds buffering without detaching a live run."""
        app = _create_runs_app(adapter)
        adapter._max_concurrent_runs = 1

        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent, agent_ready, _ = _make_slow_agent()
                mock_create.return_value = mock_agent

                start_resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert start_resp.status == 202
                run_id = (await start_resp.json())["run_id"]
                assert agent_ready.wait(timeout=3.0)

                task = adapter._active_run_tasks[run_id]
                assert isinstance(task, asyncio.Task)
                assert not task.done()

                pending = approval_gateway_wait._ApprovalEntry({
                    "command": "bash -c long-running",
                    "description": "approval after stream TTL",
                    "pattern_keys": ["shell-c"],
                })
                with approval_mod._lock:
                    approval_mod._gateway_queues[run_id] = [pending]

                adapter._run_streams_created[run_id] -= adapter._RUN_STREAM_TTL + 1
                # Exercise one real sweeper iteration without waiting 60 seconds.
                with patch(
                    "gateway.platforms.api_server.asyncio.sleep",
                    side_effect=[None, asyncio.CancelledError()],
                ):
                    with pytest.raises(asyncio.CancelledError):
                        await adapter._sweep_orphaned_runs()

                assert adapter._active_run_tasks[run_id] is task
                assert adapter._active_run_agents[run_id] is mock_agent
                assert run_id not in adapter._run_streams
                assert run_id not in adapter._run_streams_created
                assert adapter._run_approval_sessions[run_id] == run_id

                limited = adapter._concurrency_limited_response()
                assert limited is not None
                assert limited.status == 429

                approval_resp = await cli.post(
                    f"/v1/runs/{run_id}/approval",
                    json={"choice": "once"},
                )
                assert approval_resp.status == 200
                assert pending.event.is_set()
                assert pending.result == "once"

                stop_resp = await cli.post(f"/v1/runs/{run_id}/stop")
                assert stop_resp.status == 200
                mock_agent.interrupt.assert_called_once_with("Stop requested via API")


# ---------------------------------------------------------------------------
# Run ownership across served profiles (#93689 / #90415)
# ---------------------------------------------------------------------------


class TestRunOwnershipAcrossProfiles:
    """Every served profile holds a valid key under multiplex; only the
    creating profile may see or control a run."""

    KEYS = {"victim": "sk-victim-profile-key-0001", "attacker": "sk-attacker-profile-key-01"}

    @classmethod
    def _profile_app(cls, adapter: APIServerAdapter) -> web.Application:
        """Runs routes behind a stand-in for the /p/<profile>/ middleware:
        the routed profile arrives in ``X-Test-Profile`` and each profile
        authenticates with its own key, as under gateway.multiplex_profiles."""

        @web.middleware
        async def stamp_profile(request, handler):
            token = _api_request_profile.set(request.headers.get("X-Test-Profile"))
            try:
                return await handler(request)
            finally:
                _api_request_profile.reset(token)

        adapter._expected_api_key = lambda: cls.KEYS.get(_api_request_profile.get(), "")
        app = _create_runs_app(adapter)
        app.middlewares.append(stamp_profile)
        app.router.add_post(
            "/api/sessions/{session_id}/chat/stream", adapter._handle_session_chat_stream
        )
        return app

    @pytest.mark.asyncio
    async def test_unstamped_run_state_fails_closed(self, adapter):
        """Run state with no owner stamp is nobody's — not everybody's."""
        app = _create_runs_app(adapter)
        adapter._active_run_agents["run_unstamped"] = MagicMock()
        adapter._set_run_status("run_unstamped", "running")

        async with TestClient(TestServer(app)) as cli:
            get_resp = await cli.get("/v1/runs/run_unstamped")
            stop_resp = await cli.post("/v1/runs/run_unstamped/stop")

        assert (get_resp.status, stop_resp.status) == (404, 404)

    @pytest.mark.asyncio
    async def test_session_chat_stream_run_is_owned_by_creating_profile(self, adapter):
        """The session-chat-stream run mint claims ownership like /v1/runs does."""
        app = self._profile_app(adapter)
        victim = {"X-Test-Profile": "victim", "Authorization": f"Bearer {self.KEYS['victim']}"}
        attacker = {"X-Test-Profile": "attacker", "Authorization": f"Bearer {self.KEYS['attacker']}"}
        gate = asyncio.Event()

        async def slow_run_agent(**kwargs):
            await gate.wait()
            return {"final_response": "ok"}, {}

        async with TestClient(TestServer(app)) as cli:
            with (
                patch.object(adapter, "_get_existing_session_or_404", new=AsyncMock(return_value=({"id": "s1"}, None))),
                patch.object(adapter, "_conversation_history_for_session", new=AsyncMock(return_value=[])),
                patch.object(adapter, "_run_agent", new=slow_run_agent),
            ):
                stream = await cli.post(
                    "/api/sessions/s1/chat/stream", json={"message": "hi"}, headers=victim
                )
                await stream.content.readline()
                (run_id,) = list(adapter._run_statuses)
                assert run_id in adapter._run_owners

                foreign_get = await cli.get(f"/v1/runs/{run_id}", headers=attacker)
                foreign_stop = await cli.post(f"/v1/runs/{run_id}/stop", headers=attacker)
                own_get = await cli.get(f"/v1/runs/{run_id}", headers=victim)
                assert (foreign_get.status, foreign_stop.status, own_get.status) == (404, 404, 200)

                gate.set()
                await stream.text()

        # The owner outlives the terminal status and goes with the last surface.
        assert run_id in adapter._run_owners
        adapter._run_statuses.pop(run_id)
        adapter._release_run_owner_if_forgotten(run_id)
        assert run_id not in adapter._run_owners


# ---------------------------------------------------------------------------
# POST /v1/runs/{run_id}/stop — interrupt a running agent
# ---------------------------------------------------------------------------


class TestStopRun:

    @pytest.mark.asyncio
    async def test_completion_wins_before_uncooperative_stop_is_acknowledged(
        self, adapter
    ):
        """A provisional Stop cannot discard a real completion."""
        app = _create_runs_app(adapter)
        run_can_finish = threading.Event()
        run_finished = threading.Event()

        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                started = threading.Event()

                def _run_conversation(*_args, **_kwargs):
                    started.set()
                    run_can_finish.wait(timeout=5)
                    run_finished.set()
                    return {"final_response": "late result"}

                mock_agent.run_conversation.side_effect = _run_conversation
                mock_create.return_value = mock_agent

                resp = await cli.post("/v1/runs", json={"input": "hello"})
                run_id = (await resp.json())["run_id"]
                assert started.wait(timeout=3)

                stop_resp = await cli.post(f"/v1/runs/{run_id}/stop")
                assert stop_resp.status == 200
                await asyncio.sleep(0.1)

                assert not run_finished.is_set()
                assert run_id in adapter._active_run_agents
                assert run_id in adapter._active_run_tasks
                assert adapter._run_statuses[run_id]["status"] == "stopping"

                run_can_finish.set()
                for _ in range(40):
                    if run_id not in adapter._active_run_tasks:
                        break
                    await asyncio.sleep(0.05)

                assert run_id not in adapter._active_run_agents
                assert run_id not in adapter._active_run_tasks
                assert adapter._run_statuses[run_id]["status"] == "completed"
                assert adapter._run_statuses[run_id]["output"] == "late result"

    @pytest.mark.asyncio
    async def test_stop_running_agent(self, adapter):
        """Stop should interrupt the agent and cancel the task."""
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent, agent_ready, _ = _make_slow_agent()
                mock_create.return_value = mock_agent

                # Start run
                resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert resp.status == 202
                data = await resp.json()
                run_id = data["run_id"]

                # Wait for agent to start running in the thread
                agent_ready.wait(timeout=3.0)
                await asyncio.sleep(0.1)

                # Verify agent ref is stored
                assert run_id in adapter._active_run_agents

                # Stop the run
                stop_resp = await cli.post(f"/v1/runs/{run_id}/stop")
                assert stop_resp.status == 200
                stop_data = await stop_resp.json()
                assert stop_data["run_id"] == run_id
                assert stop_data["status"] == "stopping"

                # Agent interrupt should have been called
                mock_agent.interrupt.assert_called_once_with("Stop requested via API")

                status_resp = await cli.get(f"/v1/runs/{run_id}")
                assert status_resp.status == 200
                status_data = await status_resp.json()
                assert status_data["status"] in {"stopping", "cancelled"}

                # Refs should be cleaned up
                await asyncio.sleep(0.2)
                assert run_id not in adapter._active_run_agents
                assert run_id not in adapter._active_run_tasks


    @pytest.mark.asyncio
    async def test_stop_sends_sentinel_to_events_stream(self, adapter):
        """After stop, the events stream should close."""
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent, agent_ready, _ = _make_slow_agent()
                mock_create.return_value = mock_agent

                # Start run
                resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert resp.status == 202
                data = await resp.json()
                run_id = data["run_id"]

                agent_ready.wait(timeout=3.0)
                await asyncio.sleep(0.1)

                # Subscribe to events in background
                events_task = asyncio.ensure_future(
                    cli.get(f"/v1/runs/{run_id}/events")
                )

                await asyncio.sleep(0.1)

                # Stop the run
                stop_resp = await cli.post(f"/v1/runs/{run_id}/stop")
                assert stop_resp.status == 200

                # Events stream should close
                events_resp = await asyncio.wait_for(events_task, timeout=5.0)
                assert events_resp.status == 200
                body = await events_resp.text()
                # Stream should have received run.failed and closed
                assert "run.failed" in body or "stream closed" in body


class TestRunsProviderAuthFailure:
    @pytest.mark.asyncio
    async def test_status_reports_provider_auth_failure_distinctly(self, adapter):
        """/v1/runs builds its own agent via _create_agent() and does not
        route through _run_agent(), so the controlled "Provider
        authentication failed" message added there does not cover this
        endpoint. _handle_runs()'s own _ProviderAuthResolutionError branch
        must give the same distinguished message instead of the generic
        except-Exception "run failed" text."""
        from gateway.platforms.api_server import _ProviderAuthResolutionError

        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_create.side_effect = _ProviderAuthResolutionError(
                    "No credentials found for provider 'nous'"
                )

                resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert resp.status == 202
                data = await resp.json()
                run_id = data["run_id"]

                for _ in range(40):
                    status_resp = await cli.get(f"/v1/runs/{run_id}")
                    status = await status_resp.json()
                    if status["status"] == "failed":
                        break
                    await asyncio.sleep(0.05)

                assert status["status"] == "failed"
                assert (
                    status["error"]
                    == "⚠️ Provider authentication failed: No credentials found for provider 'nous'"
                )
                assert status["last_event"] == "run.failed"


# ---------------------------------------------------------------------------
# POST /v1/runs idempotency
# ---------------------------------------------------------------------------


def _use_idempotency_db(adapter, path):
    from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore

    adapter._run_idempotency_store.close()
    adapter._run_idempotency_store = RunIdempotencyStore(str(path))


class TestRunIdempotency:
    @pytest.mark.asyncio
    async def test_invalid_body_does_not_consume_idempotency_key(
        self, adapter, tmp_path
    ):
        _use_idempotency_db(adapter, tmp_path / "idem.db")
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            headers = {"Idempotency-Key": "valid-after-rejection"}
            rejected = await cli.post(
                "/v1/runs", json={"input": ""}, headers=headers
            )
            with patch.object(adapter, "_create_agent") as create:
                agent = MagicMock()
                agent.run_conversation.return_value = {"final_response": "done"}
                agent.session_prompt_tokens = agent.session_completion_tokens = (
                    agent.session_total_tokens
                ) = 0
                create.return_value = agent
                accepted = await cli.post(
                    "/v1/runs", json={"input": "valid"}, headers=headers
                )
        assert rejected.status == 400
        assert accepted.status == 202

    @pytest.mark.asyncio
    async def test_capacity_rejection_does_not_reserve_key(
        self, adapter, tmp_path
    ):
        _use_idempotency_db(adapter, tmp_path / "idem.db")
        app = _create_runs_app(adapter)
        with patch.object(
            adapter,
            "_concurrency_limited_response",
            side_effect=[
                web.json_response({"error": "full"}, status=429),
                None,
            ],
        ):
            async with TestClient(TestServer(app)) as cli:
                headers = {"Idempotency-Key": "capacity-retry"}
                rejected = await cli.post(
                    "/v1/runs", json={"input": "valid"}, headers=headers
                )
                with patch.object(adapter, "_create_agent") as create:
                    agent = MagicMock()
                    agent.run_conversation.return_value = {"final_response": "done"}
                    agent.session_prompt_tokens = agent.session_completion_tokens = (
                        agent.session_total_tokens
                    ) = 0
                    create.return_value = agent
                    accepted = await cli.post(
                        "/v1/runs", json={"input": "valid"}, headers=headers
                    )
        assert rejected.status == 429
        assert accepted.status == 202

    @pytest.mark.asyncio
    async def test_sequential_duplicate_reuses_original(self, adapter, tmp_path):
        _use_idempotency_db(adapter, tmp_path / "idem.db")
        app = _create_runs_app(adapter)
        calls = 0
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as create:
                agent = MagicMock()

                def run(**kwargs):
                    nonlocal calls
                    calls += 1
                    return {"final_response": "done"}

                agent.run_conversation.side_effect = run
                agent.session_prompt_tokens = agent.session_completion_tokens = (
                    agent.session_total_tokens
                ) = 0
                create.return_value = agent
                headers = {"Idempotency-Key": "retry-1"}
                first = await cli.post(
                    "/v1/runs", json={"input": "hello"}, headers=headers
                )
                second = await cli.post(
                    "/v1/runs", json={"input": "hello"}, headers=headers
                )
                assert first.status == second.status == 202
                assert (await first.json())["run_id"] == (await second.json())["run_id"]
                assert second.headers["Idempotency-Replayed"] == "true"
                await asyncio.sleep(0.1)
        assert calls == 1

    @pytest.mark.asyncio
    async def test_changed_payload_conflicts(self, adapter, tmp_path):
        _use_idempotency_db(adapter, tmp_path / "idem.db")
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as create:
                agent = MagicMock()
                agent.run_conversation.return_value = {"final_response": "done"}
                agent.session_prompt_tokens = agent.session_completion_tokens = (
                    agent.session_total_tokens
                ) = 0
                create.return_value = agent
                headers = {"Idempotency-Key": "same-key"}
                assert (
                    await cli.post("/v1/runs", json={"input": "one"}, headers=headers)
                ).status == 202
                conflict = await cli.post(
                    "/v1/runs", json={"input": "two"}, headers=headers
                )
                assert conflict.status == 409
                assert (await conflict.json())["error"][
                    "code"
                ] == "idempotency_key_conflict"

    @pytest.mark.asyncio
    async def test_concurrent_duplicate_starts_once(self, adapter, tmp_path):
        _use_idempotency_db(adapter, tmp_path / "idem.db")
        app = _create_runs_app(adapter)
        calls = 0
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as create:
                agent = MagicMock()

                def run(**kwargs):
                    nonlocal calls
                    calls += 1
                    time.sleep(0.05)
                    return {"final_response": "done"}

                agent.run_conversation.side_effect = run
                agent.session_prompt_tokens = agent.session_completion_tokens = (
                    agent.session_total_tokens
                ) = 0
                create.return_value = agent

                async def post():
                    response = await cli.post(
                        "/v1/runs",
                        json={"input": "race"},
                        headers={"Idempotency-Key": "race-key"},
                    )
                    return response.status, await response.json()

                results = await asyncio.gather(*[post() for _ in range(8)])
                assert {status for status, _ in results} == {202}
                assert len({body["run_id"] for _, body in results}) == 1
                await asyncio.sleep(0.15)
        assert calls == 1

    def test_restart_durability_and_terminal_semantics(self, tmp_path):
        from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore

        path = tmp_path / "idem.db"
        for terminal in ("completed", "failed", "cancelled"):
            first = RunIdempotencyStore(str(path))
            run_id = f"run_{terminal}"
            assert (
                first.reserve(
                    "tenant",
                    terminal,
                    "fp",
                    run_id,
                    {"run_id": run_id, "status": terminal},
                )[0]
                == "created"
            )
            first.close()
            restarted = RunIdempotencyStore(str(path))
            outcome, record = restarted.reserve(
                "tenant", terminal, "fp", "run_new", {"status": "queued"}
            )
            assert outcome == "reused"
            assert record["run_id"] == run_id
            assert record["status"]["status"] == terminal
            restarted.close()

    def test_tenant_isolation_and_retention(self, tmp_path):
        from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore

        store = RunIdempotencyStore(str(tmp_path / "idem.db"))
        assert (
            store.reserve("tenant-a", "key", "fp-a", "run_a", {"status": "queued"})[0]
            == "created"
        )
        assert (
            store.reserve("tenant-b", "key", "fp-b", "run_b", {"status": "queued"})[0]
            == "created"
        )
        store.close()

    def test_retention_never_releases_an_active_idempotency_reservation(
        self, tmp_path
    ):
        from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore

        store = RunIdempotencyStore(str(tmp_path / "idem.db"))
        with patch("gateway.platforms.api_server.time.time", return_value=100):
            assert store.reserve(
                "tenant",
                "active-key",
                "active-fingerprint",
                "run-active",
                {"status": "running"},
            )[0] == "created"
            assert store.reserve(
                "tenant",
                "done-key",
                "done-fingerprint",
                "run-done",
                {"status": "completed"},
            )[0] == "created"

        after_retention = 100 + RunIdempotencyStore.RETENTION_SECONDS + 1
        with patch(
            "gateway.platforms.api_server.time.time", return_value=after_retention
        ):
            active, active_record = store.lookup(
                "tenant", "active-key", "active-fingerprint"
            )
            done, done_record = store.lookup(
                "tenant", "done-key", "done-fingerprint"
            )

        assert active == "reused"
        assert active_record["run_id"] == "run-active"
        assert done == "missing"
        assert done_record is None
        store.close()

    def test_room_terminal_receipt_survives_offline_home_until_grant_horizon(
        self, tmp_path, monkeypatch
    ):
        from gateway.platforms import api_server_run_idempotency as idempotency

        now = [100.0]
        monkeypatch.setattr(idempotency.time, "time", lambda: now[0])
        store = idempotency.RunIdempotencyStore(str(tmp_path / "idem.db"))
        horizon = now[0] + 30 * 24 * 60 * 60
        assert store.reserve(
            "room-scope",
            "room:task-1:1",
            "room-fingerprint",
            "run-room",
            {"run_id": "run-room", "status": "completed"},
            retention_until=horizon,
        )[0] == "created"

        now[0] += idempotency.RunIdempotencyStore.RETENTION_SECONDS + 1
        store.reserve(
            "other-scope",
            "other-key",
            "other-fingerprint",
            "run-other",
            {"run_id": "run-other", "status": "queued"},
        )
        outcome, record = store.lookup(
            "room-scope",
            "room:task-1:1",
            "room-fingerprint",
        )
        assert outcome == "reused"
        assert record["run_id"] == "run-room"

        now[0] = horizon + 1
        store.reserve(
            "third-scope",
            "third-key",
            "third-fingerprint",
            "run-third",
            {"run_id": "run-third", "status": "queued"},
        )
        assert store.lookup(
            "room-scope",
            "room:task-1:1",
            "room-fingerprint",
        ) == ("missing", None)
        store.close()

    @pytest.mark.asyncio
    async def test_missing_key_preserves_legacy_new_run_behavior(
        self, adapter, tmp_path
    ):
        _use_idempotency_db(adapter, tmp_path / "idem.db")
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as create:
                agent = MagicMock()
                agent.run_conversation.return_value = {"final_response": "done"}
                agent.session_prompt_tokens = agent.session_completion_tokens = (
                    agent.session_total_tokens
                ) = 0
                create.return_value = agent
                first = await cli.post("/v1/runs", json={"input": "hello"})
                second = await cli.post("/v1/runs", json={"input": "hello"})
                assert (await first.json())["run_id"] != (await second.json())["run_id"]

    @pytest.mark.asyncio
    async def test_memory_scope_participates_in_fingerprint(
        self, auth_adapter, tmp_path
    ):
        adapter = auth_adapter
        _use_idempotency_db(adapter, tmp_path / "idem.db")
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as create:
                agent = MagicMock()
                agent.run_conversation.return_value = {"final_response": "done"}
                agent.session_prompt_tokens = agent.session_completion_tokens = (
                    agent.session_total_tokens
                ) = 0
                create.return_value = agent
                first_headers = {
                    "Authorization": "Bearer sk-secret",
                    "Idempotency-Key": "memory-scope",
                    "X-Hermes-Session-Key": "memory-a",
                }
                second_headers = {
                    "Authorization": "Bearer sk-secret",
                    "Idempotency-Key": "memory-scope",
                    "X-Hermes-Session-Key": "memory-b",
                }
                first = await cli.post(
                    "/v1/runs", json={"input": "same"}, headers=first_headers
                )
                conflict = await cli.post(
                    "/v1/runs", json={"input": "same"}, headers=second_headers
                )
                assert first.status == 202
                assert conflict.status == 409

    @pytest.mark.asyncio
    async def test_replay_bypasses_concurrency_limit_and_preserves_session_header(
        self, auth_adapter, tmp_path
    ):
        adapter = auth_adapter
        _use_idempotency_db(adapter, tmp_path / "idem.db")
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as create:
                agent = MagicMock()
                agent.run_conversation.return_value = {"final_response": "done"}
                agent.session_prompt_tokens = agent.session_completion_tokens = (
                    agent.session_total_tokens
                ) = 0
                create.return_value = agent
                headers = {
                    "Authorization": "Bearer sk-secret",
                    "Idempotency-Key": "lost-acceptance",
                    "X-Hermes-Session-Key": "memory-a",
                }
                first = await cli.post(
                    "/v1/runs", json={"input": "same"}, headers=headers
                )
                first_body = await first.json()
                with patch.object(
                    adapter,
                    "_concurrency_limited_response",
                    return_value=web.json_response({"error": "full"}, status=429),
                ):
                    replay = await cli.post(
                        "/v1/runs", json={"input": "same"}, headers=headers
                    )
                replay_body = await replay.json()
                assert replay.status == 202
                assert replay_body["run_id"] == first_body["run_id"]
                assert replay_body["replayed"] is True
                assert replay.headers["X-Hermes-Session-Key"] == "memory-a"

    @pytest.mark.asyncio
    async def test_direct_status_hydrates_after_adapter_restart(
        self, tmp_path
    ):
        path = tmp_path / "idem.db"
        first_adapter = _make_adapter()
        _use_idempotency_db(first_adapter, path)
        first_app = _create_runs_app(first_adapter)
        async with TestClient(TestServer(first_app)) as cli:
            with patch.object(first_adapter, "_create_agent") as create:
                agent = MagicMock()
                agent.run_conversation.return_value = {"final_response": "done"}
                agent.session_prompt_tokens = agent.session_completion_tokens = (
                    agent.session_total_tokens
                ) = 0
                create.return_value = agent
                started = await cli.post(
                    "/v1/runs",
                    json={"input": "same"},
                    headers={"Idempotency-Key": "restart-status"},
                )
                run_id = (await started.json())["run_id"]
                for _ in range(40):
                    status = await cli.get(f"/v1/runs/{run_id}")
                    if (await status.json()).get("status") == "completed":
                        break
                    await asyncio.sleep(0.05)
        first_adapter._run_idempotency_store.close()

        restarted = _make_adapter()
        _use_idempotency_db(restarted, path)
        restarted_app = _create_runs_app(restarted)
        async with TestClient(TestServer(restarted_app)) as cli:
            status = await cli.get(f"/v1/runs/{run_id}")
            body = await status.json()
        assert status.status == 200
        assert body["status"] == "completed"
        assert body["output"] == "done"

    @pytest.mark.asyncio
    async def test_dead_owner_nonterminal_status_becomes_interrupted(
        self, tmp_path
    ):
        from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore

        path = tmp_path / "idem.db"
        scope = hashlib.sha256(
            "default\0unauthenticated-test-listener".encode()
        ).hexdigest()
        store = RunIdempotencyStore(str(path))
        store.reserve(
            scope,
            "stale-run",
            "fingerprint",
            "run_stale",
            {"run_id": "run_stale", "status": "running"},
            owner_pid=999_999_999,
            owner_started=1,
        )
        store.close()

        restarted = _make_adapter()
        _use_idempotency_db(restarted, path)
        app = _create_runs_app(restarted)
        async with TestClient(TestServer(app)) as cli:
            response = await cli.get("/v1/runs/run_stale")
            body = await response.json()
        assert response.status == 200
        assert body["status"] == "interrupted"
        assert body["last_event"] == "run.interrupted"


    def test_status_sweep_prunes_in_memory_ownership_mirrors(self, adapter):
        adapter._run_statuses["run_old"] = {
            "status": "completed",
            "updated_at": 1,
        }
        adapter._run_idempotency_ids.add("run_old")
        adapter._run_owners["run_old"] = "scope"

        adapter._sweep_orphaned_runs_once(adapter._RUN_STATUS_TTL + 2)

        assert "run_old" not in adapter._run_statuses
        assert "run_old" not in adapter._run_idempotency_ids
        assert "run_old" not in adapter._run_owners



class TestHostedRoomRuns:
    @pytest.mark.asyncio
    async def test_room_approval_requires_and_resolves_exact_request_id(
        self, auth_adapter
    ):
        run_id = "run-room-approval"
        current = approval_gateway_wait._ApprovalEntry({
            "request_id": "approval-B",
            "command": "rm -rf build-B",
        })
        auth_adapter._run_approval_sessions[run_id] = run_id
        auth_adapter._run_statuses[run_id] = {
            "run_id": run_id,
            "status": "waiting_for_approval",
            "approval": dict(current.data),
        }
        with approval_mod._lock:
            approval_mod._gateway_queues[run_id] = [current]
        app = _create_runs_app(auth_adapter)
        try:
            with (
                patch.object(auth_adapter, "_check_run_auth", return_value=None),
                patch.object(auth_adapter, "_request_owns_run", return_value=True),
                patch.object(
                    auth_adapter, "_room_grant_token", return_value="scoped-grant"
                ),
            ):
                async with TestClient(TestServer(app)) as cli:
                    missing = await cli.post(
                        f"/v1/runs/{run_id}/approval",
                        json={"choice": "once"},
                    )
                    stale = await cli.post(
                        f"/v1/runs/{run_id}/approval",
                        json={"choice": "once", "request_id": "approval-A"},
                    )
                    exact = await cli.post(
                        f"/v1/runs/{run_id}/approval",
                        json={"choice": "once", "request_id": "approval-B"},
                    )
                    missing_body = await missing.json()
                    stale_body = await stale.json()
                    exact_body = await exact.json()
        finally:
            approval_mod.unregister_gateway_notify(run_id)

        assert missing.status == 400
        assert missing_body["error"]["code"] == "approval_request_required"
        assert stale.status == 409
        assert stale_body["error"]["code"] == "approval_not_pending"
        assert exact.status == 200
        assert exact_body["request_id"] == "approval-B"
        assert current.result == "once"
        assert "approval" not in auth_adapter._run_statuses[run_id]

    @pytest.mark.asyncio
    async def test_room_grant_cannot_create_session_or_permanent_approval_policy(
        self, auth_adapter
    ):
        app = _create_runs_app(auth_adapter)
        with (
            patch.object(auth_adapter, "_check_run_auth", return_value=None),
            patch.object(auth_adapter, "_request_owns_run", return_value=True),
            patch.object(
                auth_adapter,
                "_durable_run_status",
                return_value={"status": "waiting_for_approval"},
            ),
            patch.object(
                auth_adapter, "_room_grant_token", return_value="scoped-grant"
            ),
        ):
            async with TestClient(TestServer(app)) as cli:
                permanent = await cli.post(
                    "/v1/runs/run-room/approval",
                    json={"choice": "always"},
                )
                resolve_all = await cli.post(
                    "/v1/runs/run-room/approval",
                    json={"choice": "once", "resolve_all": True},
                )
                permanent_body = await permanent.json()
                resolve_all_body = await resolve_all.json()

        assert permanent.status == 400
        assert permanent_body["error"]["code"] == "invalid_approval_choice"
        assert resolve_all.status == 400
        assert resolve_all_body["error"]["code"] == "invalid_approval_scope"

    @pytest.mark.asyncio
    async def test_invitation_uses_validated_app_managed_local_catalog(
        self, auth_adapter, monkeypatch
    ):
        monkeypatch.setenv("HERMES_DESKTOP", "1")
        monkeypatch.setenv(
            "HERMES_ROOM_LINK_URL", "https://peer.example.test/hermes"
        )
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            invitation = await cli.post(
                "/v1/room-members/invitations",
                json={
                    "room_id": "room-1",
                    "home_install_id": "install-home",
                    "authority_gateway_id": "gateway-home",
                    "authority_epoch": 1,
                    "member_id": "member-reviewer",
                },
                headers={"Authorization": "Bearer sk-secret"},
            )
            body = await invitation.json()
        assert invitation.status == 201
        assert body["catalog"]["persistent_process"] is False
        assert body["catalog"]["link_modes"] == ["direct"]
        assert body["catalog"]["endpoint"] == {
            "available": True,
            "url": "https://peer.example.test/hermes",
            "transport_security": "tls",
        }
        assert body["expires_at"] == body["status_expires_at"]

    @pytest.mark.asyncio
    async def test_invitation_returns_operator_selected_status_horizon(
        self, auth_adapter
    ):
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            invitation = await cli.post(
                "/v1/room-members/invitations",
                json={
                    "room_id": "room-horizon",
                    "home_install_id": "install-home",
                    "authority_gateway_id": "gateway-home",
                    "authority_epoch": 1,
                    "member_id": "member-reviewer",
                    "ttl_seconds": 600,
                    "status_ttl_seconds": 3600,
                },
                headers={"Authorization": "Bearer sk-secret"},
            )
            body = await invitation.json()

        assert invitation.status == 201
        assert body["status_expires_at"] - body["expires_at"] == 3000

    @pytest.mark.asyncio
    async def test_scoped_grant_refresh_requires_live_dispatch_authority(
        self, auth_adapter, monkeypatch
    ):
        from gateway import hosted_rooms
        from gateway.hosted_room_peer import decode_room_grant, issue_room_grant
        from gateway.hosted_rooms import local_authority_gateway_id

        old_grant = issue_room_grant(
            auth_adapter._room_grant_secret(),
            grant_id="grant-old",
            room_id="room-1",
            home_install_id="install-home",
            authority_gateway_id="install-home",
            authority_epoch=1,
            member_id="member-peer",
            target_install_id=local_authority_gateway_id(),
            target_profile="default",
            issued_at=100,
            ttl_seconds=300,
            status_expires_at=1000,
        )
        old_claims = decode_room_grant(
            auth_adapter._room_grant_secret(),
            old_grant,
            permission="status",
            now=100,
        )
        hosted_rooms.reserve_peer_room(
            hosted_rooms.default_db_path(),
            claims=old_claims,
            expires_at=1000,
            now=100,
        )
        monkeypatch.setattr("gateway.platforms.api_server.time.time", lambda: 200)
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            refreshed = await cli.post(
                "/v1/room-members/grants/refresh",
                json={"ttl_seconds": 300},
                headers={"Authorization": f"HermesRoom {old_grant}"},
            )
            body = await refreshed.json()
        assert refreshed.status == 200
        assert body["grant"] != old_grant
        claims = decode_room_grant(
            auth_adapter._room_grant_secret(),
            body["grant"],
            permission="dispatch",
            now=200,
        )
        assert claims["room_id"] == "room-1"
        assert claims["home_install_id"] == "install-home"
        assert claims["status_expires_at"] == 1000

        status_only = issue_room_grant(
            auth_adapter._room_grant_secret(),
            grant_id="grant-status-only",
            room_id="room-1",
            home_install_id="install-home",
            authority_gateway_id="install-home",
            authority_epoch=1,
            member_id="member-peer",
            target_install_id=local_authority_gateway_id(),
            target_profile="default",
            permissions=("status",),
            issued_at=100,
            ttl_seconds=300,
            status_expires_at=1000,
        )
        status_claims = decode_room_grant(
            auth_adapter._room_grant_secret(),
            status_only,
            permission="status",
            now=100,
        )
        hosted_rooms.reserve_peer_room(
            hosted_rooms.default_db_path(),
            claims=status_claims,
            expires_at=1000,
            now=100,
        )
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            status_refresh = await cli.post(
                "/v1/room-members/grants/refresh",
                json={"ttl_seconds": 300},
                headers={"Authorization": f"HermesRoom {status_only}"},
            )
            status_refresh_body = await status_refresh.json()
        assert status_refresh.status == 401
        assert status_refresh_body["error"]["code"] == "invalid_room_grant"

        fully_expired = issue_room_grant(
            auth_adapter._room_grant_secret(),
            grant_id="grant-expired",
            room_id="room-1",
            home_install_id="install-home",
            authority_gateway_id="install-home",
            authority_epoch=1,
            member_id="member-peer",
            target_install_id=local_authority_gateway_id(),
            target_profile="default",
            issued_at=100,
            ttl_seconds=10,
            status_expires_at=150,
        )
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            denied = await cli.post(
                "/v1/room-members/grants/refresh",
                json={},
                headers={"Authorization": f"HermesRoom {fully_expired}"},
            )
            denied_body = await denied.json()
        assert denied.status == 401
        assert denied_body["error"]["code"] == "invalid_room_grant"

    @pytest.mark.asyncio
    async def test_scoped_grant_refresh_refuses_execution_policy_drift(
        self, auth_adapter, monkeypatch
    ):
        """Renewal must pause for reauthorization when the target's execution
        policy changed since the grant was issued — never silently mint a
        grant against the drifted policy (blocker 2, #97681 review)."""
        from gateway import hosted_rooms
        from gateway.hosted_room_peer import issue_room_grant, decode_room_grant
        from gateway.hosted_rooms import local_authority_gateway_id

        stale_digest = "c" * 64
        drifted = issue_room_grant(
            auth_adapter._room_grant_secret(),
            grant_id="grant-drifted",
            room_id="room-1",
            home_install_id="install-home",
            authority_gateway_id="install-home",
            authority_epoch=1,
            member_id="member-peer",
            target_install_id=local_authority_gateway_id(),
            target_profile="default",
            execution_policy_digest=stale_digest,
            issued_at=100,
            ttl_seconds=300,
            status_expires_at=1000,
        )
        drifted_claims = decode_room_grant(
            auth_adapter._room_grant_secret(),
            drifted,
            permission="status",
            now=100,
        )
        hosted_rooms.reserve_peer_room(
            hosted_rooms.default_db_path(),
            claims=drifted_claims,
            expires_at=1000,
            now=100,
        )
        monkeypatch.setattr("gateway.platforms.api_server.time.time", lambda: 200)
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            refused = await cli.post(
                "/v1/room-members/grants/refresh",
                json={"ttl_seconds": 300},
                headers={"Authorization": f"HermesRoom {drifted}"},
            )
            refused_body = await refused.json()
        assert refused.status == 403
        assert refused_body["error"]["code"] == "room_reauthorization_required"

    @pytest.mark.asyncio
    async def test_scoped_grant_refresh_fails_after_secret_rotation(
        self, auth_adapter, monkeypatch
    ):
        from gateway.hosted_room_peer import issue_room_grant
        from gateway.hosted_rooms import local_authority_gateway_id

        monkeypatch.setattr("gateway.platforms.api_server.time.time", lambda: 200)
        revoked = issue_room_grant(
            b"x" * 32,
            grant_id="grant-revoked",
            room_id="room-1",
            home_install_id="install-home",
            authority_gateway_id="install-home",
            authority_epoch=1,
            member_id="member-peer",
            target_install_id=local_authority_gateway_id(),
            target_profile="default",
            issued_at=100,
            ttl_seconds=300,
            status_expires_at=1000,
        )
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            denied = await cli.post(
                "/v1/room-members/grants/refresh",
                json={},
                headers={"Authorization": f"HermesRoom {revoked}"},
            )
            denied_body = await denied.json()
        assert denied.status == 401
        assert denied_body["error"]["code"] == "invalid_room_grant"

    def test_grant_refresh_keeps_idempotency_scope_but_member_change_does_not(
        self, auth_adapter
    ):
        from types import SimpleNamespace

        from gateway import hosted_rooms
        from gateway.hosted_room_peer import decode_room_grant, issue_room_grant
        from gateway.hosted_rooms import local_authority_gateway_id

        common = {
            "room_id": "room-1",
            "home_install_id": "install-home",
            "authority_gateway_id": "gateway-home",
            "authority_epoch": 1,
            "member_id": "member-reviewer",
            "target_install_id": local_authority_gateway_id(),
            "target_profile": "default",
        }
        first = issue_room_grant(
            auth_adapter._room_grant_secret(),
            grant_id="grant-first",
            **common,
        )
        refreshed = issue_room_grant(
            auth_adapter._room_grant_secret(),
            grant_id="grant-refreshed",
            **common,
        )
        other_member = issue_room_grant(
            auth_adapter._room_grant_secret(),
            grant_id="grant-other-member",
            **{**common, "member_id": "member-other"},
        )
        for grant in (first, other_member):
            claims = decode_room_grant(
                auth_adapter._room_grant_secret(),
                grant,
                permission="status",
            )
            hosted_rooms.reserve_peer_room(
                hosted_rooms.default_db_path(),
                claims=claims,
                expires_at=float(claims["status_expires_at"]),
            )

        def request(token):
            return SimpleNamespace(
                headers={"Authorization": f"HermesRoom {token}"},
                method="POST",
                path="/v1/runs",
            )

        first_scope = auth_adapter._run_idempotency_scope(request(first))
        assert auth_adapter._run_idempotency_scope(request(refreshed)) == first_scope
        assert auth_adapter._run_idempotency_scope(request(other_member)) != first_scope

    @pytest.mark.asyncio
    async def test_scoped_grant_revoke_is_idempotent_and_fences_prior_lineage(
        self, auth_adapter, monkeypatch
    ):
        from gateway import hosted_rooms
        from gateway.hosted_room_peer import decode_room_grant, issue_room_grant
        from gateway.hosted_rooms import local_authority_gateway_id

        for target in (
            "gateway.platforms.api_server.time.time",
            "gateway.hosted_rooms_common.time.time",
        ):
            monkeypatch.setattr(target, lambda: 200)
        claims = {
            "room_id": "room-1",
            "home_install_id": "install-home",
            "authority_gateway_id": "install-home",
            "authority_epoch": 1,
            "member_id": "member-peer",
            "target_install_id": local_authority_gateway_id(),
            "target_profile": "default",
        }
        old_grant = issue_room_grant(
            auth_adapter._room_grant_secret(),
            grant_id="grant-old",
            **claims,
            issued_at=100,
            ttl_seconds=300,
            status_expires_at=1000,
        )
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            first = await cli.post(
                "/v1/room-members/grants/revoke",
                json={},
                headers={"Authorization": f"HermesRoom {old_grant}"},
            )
            repeated = await cli.post(
                "/v1/room-members/grants/revoke",
                json={},
                headers={"Authorization": f"HermesRoom {old_grant}"},
            )
            denied = await cli.get(
                "/v1/room-members/capabilities",
                headers={"Authorization": f"HermesRoom {old_grant}"},
            )
            denied_run = await cli.post(
                "/v1/runs",
                data="{never parsed",
                headers={
                    "Authorization": f"HermesRoom {old_grant}",
                    "Content-Type": "application/json",
                },
            )
            denied_body = await denied.json()
            denied_run_body = await denied_run.json()
            future_grant = issue_room_grant(
                auth_adapter._room_grant_secret(),
                grant_id="grant-repaired",
                **claims,
                issued_at=201,
                ttl_seconds=300,
                status_expires_at=1000,
            )
            future_claims = decode_room_grant(
                auth_adapter._room_grant_secret(),
                future_grant,
                permission="status",
                now=201,
            )
            hosted_rooms.reserve_peer_room(
                hosted_rooms.default_db_path(),
                claims=future_claims,
                expires_at=1000,
                now=201,
            )
            repaired = await cli.get(
                "/v1/room-members/capabilities",
                headers={"Authorization": f"HermesRoom {future_grant}"},
            )
        assert first.status == repeated.status == 200
        assert denied.status == 403
        assert denied_body["error"]["code"] == "room_reauthorization_required"
        assert denied_run.status == 403
        assert (
            denied_run_body["error"]["code"]
            == "room_reauthorization_required"
        )
        assert auth_adapter._pending_agent_requests == 0
        assert repaired.status == 200

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("method", "suffix"),
        [("GET", ""), ("POST", "/stop")],
    )
    async def test_room_grant_cannot_access_ownerless_compat_run(
        self, auth_adapter, tmp_path, method, suffix
    ):
        adapter = auth_adapter
        _use_idempotency_db(adapter, tmp_path / "idem.db")
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            invitation = await cli.post(
                "/v1/room-members/invitations",
                json={
                    "room_id": "room-1",
                    "home_install_id": "install-home",
                    "authority_gateway_id": "gateway-home",
                    "authority_epoch": 1,
                    "member_id": "member-reviewer",
                },
                headers={"Authorization": "Bearer sk-secret"},
            )
            grant = (await invitation.json())["grant"]
            adapter._run_statuses["run_ownerless"] = {
                "run_id": "run_ownerless",
                "status": "running",
            }
            response = await cli.request(
                method,
                f"/v1/runs/run_ownerless{suffix}",
                json={} if method == "POST" else None,
                headers={"Authorization": f"HermesRoom {grant}"},
            )
        assert response.status == 404

    @pytest.mark.asyncio
    async def test_scoped_grant_admits_group_session_run_without_peer_api_key(
        self, auth_adapter, tmp_path
    ):
        from gateway import hosted_rooms

        adapter = auth_adapter
        _use_idempotency_db(adapter, tmp_path / "idem.db")
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            invitation = await cli.post(
                "/v1/room-members/invitations",
                json={
                    "grant_id": "grant-room-1",
                    "room_id": "room-1",
                    "home_install_id": "install-home",
                    "authority_gateway_id": "gateway-home",
                    "authority_epoch": 1,
                    "member_id": "member-reviewer",
                    "ttl_seconds": 3600,
                },
                headers={"Authorization": "Bearer sk-secret"},
            )
            invitation_body = await invitation.json()
            assert invitation.status == 201
            grant = invitation_body["grant"]
            catalog = invitation_body["catalog"]
            probe = await cli.get(
                "/v1/room-members/capabilities",
                headers={"Authorization": f"HermesRoom {grant}"},
            )
            probe_body = await probe.json()
            assert probe.status == 200
            assert probe_body["catalog"] == catalog
            prompt = "Review this room message."
            dispatch = {
                "protocol_version": 2,
                "room_id": "room-1",
                "home_install_id": "install-home",
                "authority_gateway_id": "gateway-home",
                "authority_epoch": 1,
                "member_id": "member-reviewer",
                "target_install_id": catalog["installation_id"],
                "target_profile": "default",
                "task_id": "task-room-1",
                "execution_generation": 1,
                "source_event_seq": 1,
                "cancellation_scope_id": "cancel-room-1",
                "prompt": prompt,
                "prompt_digest": hashlib.sha256(prompt.encode()).hexdigest(),
                "capability_digest": catalog["catalog_digest"],
                "execution_policy_digest": catalog["execution_policy"][
                    "policy_digest"
                ],
                "trace_id": "trace-room-1",
            }
            with patch.object(adapter, "_create_agent") as create:
                agent = MagicMock()
                agent.run_conversation.return_value = {
                    "final_response": "Scoped room reply."
                }
                agent.session_prompt_tokens = agent.session_completion_tokens = (
                    agent.session_total_tokens
                ) = 0
                create.return_value = agent
                started = await cli.post(
                    "/v1/runs",
                    json={"input": prompt, "hosted_room_dispatch": dispatch},
                    headers={
                        "Authorization": f"HermesRoom {grant}",
                        "Idempotency-Key": "room:task-room-1:1",
                    },
                )
                started_body = await started.json()
                assert started.status == 202
                run_id = started_body["run_id"]
                for _ in range(40):
                    status = await cli.get(
                        f"/v1/runs/{run_id}",
                        headers={"Authorization": f"HermesRoom {grant}"},
                    )
                    status_body = await status.json()
                    if status_body.get("status") == "completed":
                        break
                    await asyncio.sleep(0.05)
            assert status.status == 200
            assert status_body["output"] == "Scoped room reply."
            session_id = status_body["session_id"]
            db = await adapter._ensure_session_db_async()
            row = db.get_session(session_id)
            assert row["source"] == "bot_room"
            assert row["title"] == "Group: room-1"
            assert catalog["installation_id"] == (
                hosted_rooms.local_authority_gateway_id()
            )

    @pytest.mark.asyncio
    async def test_scoped_grant_rejects_capability_and_target_tampering(
        self, auth_adapter, tmp_path
    ):
        adapter = auth_adapter
        _use_idempotency_db(adapter, tmp_path / "idem.db")
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            invitation = await cli.post(
                "/v1/room-members/invitations",
                json={
                    "room_id": "room-1",
                    "home_install_id": "install-home",
                    "authority_gateway_id": "gateway-home",
                    "authority_epoch": 1,
                    "member_id": "member-reviewer",
                },
                headers={"Authorization": "Bearer sk-secret"},
            )
            invitation_body = await invitation.json()
            prompt = "Review."
            dispatch = {
                "protocol_version": 2,
                "room_id": "room-1",
                "home_install_id": "install-home",
                "authority_gateway_id": "gateway-home",
                "authority_epoch": 1,
                "member_id": "member-reviewer",
                "target_install_id": invitation_body["catalog"]["installation_id"],
                "target_profile": "default",
                "task_id": "task-room-1",
                "execution_generation": 1,
                "source_event_seq": 1,
                "cancellation_scope_id": "cancel-room-1",
                "prompt": prompt,
                "prompt_digest": hashlib.sha256(prompt.encode()).hexdigest(),
                "capability_digest": "f" * 64,
                "execution_policy_digest": invitation_body["catalog"][
                    "execution_policy"
                ]["policy_digest"],
                "trace_id": "trace-room-1",
            }
            with patch.object(adapter, "_create_agent") as create:
                rejected = await cli.post(
                    "/v1/runs",
                    json={"input": prompt, "hosted_room_dispatch": dispatch},
                    headers={
                        "Authorization": f"HermesRoom {invitation_body['grant']}",
                        "Idempotency-Key": "room:task-room-1:1",
                    },
                )
            assert rejected.status == 403
            create.assert_not_called()


# ---------------------------------------------------------------------------
# B2B namespace guards — reserved session ids refuse every generic run surface
# before history load or agent construction.
# ---------------------------------------------------------------------------

def test_b2b_session_id_predicate():
    from agent.b2b_execution import is_b2b_session_id
    assert is_b2b_session_id("b2b_" + "a" * 64)
    assert not is_b2b_session_id("b2b_" + "a" * 63)
    assert not is_b2b_session_id("api_x")


@pytest.mark.asyncio
async def test_generic_runs_reject_b2b_session():
    """POST /v1/runs with a reserved b2b_ session_id -> 404 before any turn."""
    adapter = _make_adapter(api_key="k" * 16)
    app = _create_runs_app(adapter)
    async with TestClient(TestServer(app)) as client:
        resp = await client.post(
            "/v1/runs",
            json={"session_id": "b2b_" + "f" * 64, "input": "x"},
            headers={"Authorization": "Bearer " + "k" * 16})
        assert resp.status == 404, await resp.text()


# ---------------------------------------------------------------------------
# b2b seal reservation - real _AttemptSink + real disk RunIdempotencyStore.
# All context / source / provider data are UNIT CONTEXT/SOURCE/RESULT DOUBLES.
# ---------------------------------------------------------------------------

@pytest.fixture
def b2b_seal_lane(tmp_path):
    """UNIT CONTEXT/SOURCE/RESULT DOUBLES; real sink, schemas and disk transactions."""
    contract_root = extract_contract_root(tmp_path)
    profile = "hub"
    sid = "b2b_" + "a" * 64
    binding = sid[4:]
    attempt_id = b2b._attempt_id_for(binding)
    run_id = "run_" + "c" * 16
    now = time.time()
    _, _, portal_pub = make_keypair()
    _, hermes_priv, _ = make_keypair()
    entry = {"source_url": "http://127.0.0.1:1/internal/dubsar/b2b/source",
             "portal_issuer": "portal-h1", "hermes_issuer": "hermes-h1-hub",
             "portal_public_key_pem": portal_pub,
             "hermes_private_key_pem": hermes_priv,
             "projects": {"b2b-bench": {
                 "project_id": "b2b-bench", "bot_id": "bot", "profile_id": profile,
                 "allowed_namespaces": ["ns"], "context_contract_root": contract_root,
                 "model": "unit-double", "provider": "custom",
                 "base_url": "http://127.0.0.1:1/v1", "api_mode": "chat_completions",
                 "logical_mission": None, "project_context": None}}}
    config = b2b.B2BConfig({"enabled": True, "profiles": {profile: entry}})
    state = b2b._B2BState(config)
    adapter = SimpleNamespace(_b2b_state=state)
    policy = {
        "attempt_id": attempt_id, "binding_digest": binding,
        "requester_id": "1" * 24, "project_id": "b2b-bench",
        "project_binding_id": "b2b-bench", "mission_id": "DUB-001",
        "mission_revision": 1, "profile": profile, "session_id": sid,
        "profile_home": str(get_hermes_home().resolve()),
        "reservation_ref": {"collection": "dubsar_b2b_agent_sessions", "id": binding},
        "request_digest": "d" * 64, "ticket_digest": "e" * 64,
        "authority_basis_digest": "sha256:" + "b" * 64,
        "authority_digest": "sha256:" + "a" * 64,
        "observation_genesis": {
            "id": sid, "source": "api_server", "profile": profile,
            "title": None, "model": None, "parent_session_id": None,
            "has_system_prompt": False, "has_model_config": False,
            "ended_at": None, "end_reason": None, "message_count": 0,
            "tool_call_count": 0, "api_call_count": 0},
        "mission_request": {"title": "m", "objective": "o",
                             "criteria": [], "source_refs": []},
        "project": entry["projects"]["b2b-bench"]}
    view = build_context_view(policy, {"mission_source_digest": "c" * 64})
    store = RunIdempotencyStore(str(tmp_path / "runs.db"))
    keys = b2b._KeyRing(entry)
    sink = b2b._AttemptSink(adapter, store, profile=profile, entry=entry, keys=keys,
                          attempt_id=attempt_id, session_id=sid,
                          binding_digest=binding, run_id=run_id, policy=policy)
    binding_row = {"profile": profile, "session_id": sid,
                   "binding_digest": binding,
                   "policy_json": json_utf8(policy).decode("utf-8")}
    attempt_row = {"profile": profile, "session_id": sid, "binding_digest": binding,
                   "attempt_id": attempt_id, "run_id": run_id, "status": "admitted",
                   "requester_id": policy["requester_id"],
                   "source_bind": json_utf8({"unit_source_double": True})}
    admission = store.b2b_admit(profile=profile, session_id=sid, binding_digest=binding,
                    attempt_id=attempt_id, fingerprint=sink._fingerprint,
                    binding_row=binding_row, attempt_row=attempt_row,
                    run_scope="b2b:" + attempt_id, run_key=attempt_id,
                    run_id=run_id, run_fingerprint=sink._fingerprint,
                    run_status={"session_id": sid, "status": "running"})

    assert admission["status"] == "admitted"
    cap = BoundExecution(attempt_id=attempt_id, run_id=run_id, policy=policy,
                         profile=profile, session_id=sid, binding_digest=binding,
                         sink=sink, created_at=now)
    class UnitAgent:
        pass
    agent = UnitAgent()
    agent.session_id, agent._b2b_execution, agent._current_turn_id = sid, cap, "t0"
    object.__setattr__(cap, "_agent_ref", weakref.ref(agent))
    token = bind_execution(cap)
    try:
        receipt = cap.publish_context(view, UNIT_RENDERED, turn_id="t0")
    finally:
        reset_execution(token)
    assert sink.context_receipt is receipt

    resolved = {"source_state": "active", **{k: policy[k] for k in
        ("attempt_id", "binding_digest", "requester_id", "project_id",
         "project_binding_id", "mission_id", "mission_revision", "profile",
         "session_id", "reservation_ref", "request_digest", "ticket_digest",
         "authority_basis_digest", "authority_digest", "observation_genesis",
         "mission_request")},
        "mission_source_digest": view["my_work"]["mission"]["source_digest"],
        "_signed_request": {"issued_at": now - 1, "expires_at": now + 30},
        "_signed_response": {"issued_at": now - 1, "expires_at": now + 29},
        "_request_raw": b'{"unit_source_double":"request"}',
        "_response_raw": b'{"unit_source_double":"response"}'}
    sink._before_provider = resolved
    assert sink.cas_dispatch(request_digest=policy["request_digest"], receipt=receipt)
    public_json = json_utf8({
        "summary": "s", "steps": ["st"], "source_refs": [], "limitations": []})
    parsed, reason = validate_proposal(
        public_json.decode(), extract_allowed_refs(receipt.view))
    sink.commit_result(text=public_json.decode(), parsed=parsed, reason=reason)

    assert store.b2b_attempt(profile=profile, attempt_id=attempt_id)["status"] == "result_received"
    try:
        yield SimpleNamespace(
            store=store, sink=sink, cap=cap, receipt=receipt, resolved=resolved,
            view=view, db_path=tmp_path / "runs.db", agent=agent)
    finally:
        store.close()


def _seal_recheck_view(lane, *, divergent=False):
    view = copy.deepcopy(lane.view)
    view["captured_at"] = "2026-10-29T23:59:59.000Z"
    assert view["captured_at"] != lane.view["captured_at"]
    if divergent:
        view["operational_context"]["view"]["view_instant"] = "1970-01-01T00:00:00.000Z"
    view["context_digest"] = native_context_digest(view)
    for _ in range(8):
        size = len(json_utf8(view))
        if view["bounds"]["serialized_bytes"] == size:
            return view
        view["bounds"]["serialized_bytes"] = size
    raise AssertionError("serialized_bytes did not converge")


def _assert_seal_rollback(lane, before):
    lane.store.close()
    reopened = RunIdempotencyStore(str(lane.db_path))
    try:
        after = reopened.b2b_snapshot(profile=lane.sink.profile, attempt_id=lane.sink.attempt_id)
        assert after == before
        assert after["attempt"]["status"] == "result_received"
        assert not {"source_before_seal", "context_recheck", "proposal"} & after["artifacts"].keys()
    finally:
        reopened.close()


def test_b2b_seal_positive_exact15_and_persisted(b2b_seal_lane):
    lane = b2b_seal_lane
    sink, receipt = lane.sink, lane.receipt
    initial = lane.store.b2b_snapshot(profile=sink.profile, attempt_id=sink.attempt_id)
    fresh = _seal_recheck_view(lane)
    assert fresh["context_digest"] != receipt.digest
    assert json_utf8(source_basis(fresh)) == receipt.source_basis_bytes
    lane.cap.register_context_recheck(lambda cap: fresh)
    qualified = recheck_context(lane.cap, receipt)
    created = sink.seal(source_before_seal=lane.resolved, rechecked_view=qualified,
                        created_at="2026-10-29T23:59:59Z")
    assert set(created) == {
        "proposal_id", "attempt_id", "binding_digest", "profile", "session_id",
        "project_id", "mission_id", "mission_revision", "context_digest",
        "summary", "steps", "source_refs", "limitations", "state", "created_at"}
    assert "source_basis_digest" not in created
    lane.store.close()
    reopened = RunIdempotencyStore(str(lane.db_path))
    try:
        snap = reopened.b2b_snapshot(profile=sink.profile, attempt_id=sink.attempt_id)
        assert snap["attempt"]["status"] == "proposal_ready"
        assert snap["attempt"]["run_id"] == sink.run_id
        assert created["state"] == "prepared" and created["context_digest"] == receipt.digest
        assert (created["profile"], created["session_id"], created["binding_digest"],
                created["attempt_id"]) == (sink.profile, sink.session_id, sink.binding_digest,
                                          sink.attempt_id)
        artifacts = snap["artifacts"]
        for kind, original in initial["artifacts"].items():
            assert artifacts[kind] == original
        assert artifacts["proposal"]["payload"] == json_utf8(created)
        for artifact in artifacts.values():
            assert artifact["digest"] == hashlib.sha256(artifact["payload"]).hexdigest()
        rechecked = json.loads(artifacts["context_recheck"]["payload"])
        assert rechecked["view"] == fresh
        assert rechecked["source_basis_digest"] == receipt.source_basis_digest
        assert created["created_at"] == "2026-10-29T23:59:59Z"
        assert reopened.b2b_snapshot(profile=sink.profile, attempt_id=sink.attempt_id) == snap
        replay = reopened.b2b_seal(
            profile=sink.profile, attempt_id=sink.attempt_id,
            artifacts={kind: artifacts[kind]["payload"] for kind in
                       ("source_before_seal", "context_recheck", "proposal")})
        assert replay == json_utf8(created)
        assert reopened.b2b_snapshot(profile=sink.profile, attempt_id=sink.attempt_id) == snap
    finally:
        reopened.close()


def test_b2b_seal_rejects_stale_source_basis(b2b_seal_lane):
    lane = b2b_seal_lane
    before = lane.store.b2b_snapshot(profile=lane.sink.profile, attempt_id=lane.sink.attempt_id)
    fresh = _seal_recheck_view(lane, divergent=True)
    assert json_utf8(source_basis(fresh)) != lane.receipt.source_basis_bytes
    with pytest.raises(B2BTerminalRefusal, match="context_stale"):
        lane.sink.seal(source_before_seal=lane.resolved, rechecked_view=fresh,
                       created_at="2026-10-29T23:59:59Z")
    _assert_seal_rollback(lane, before)


@pytest.mark.parametrize("fault", ["forged_digest", "missing_digest", "wrong_digest",
                                  "missing_view", "nonmapping_view"])
def test_b2b_seal_store_rejects_invalid_context(b2b_seal_lane, fault):
    lane = b2b_seal_lane
    sink, receipt = lane.sink, lane.receipt
    before = lane.store.b2b_snapshot(profile=sink.profile, attempt_id=sink.attempt_id)
    recheck = {
        "format": "dubsar.b2b-context-recheck/1", "attempt_id": sink.attempt_id,
        "run_id": sink.run_id, "view": _seal_recheck_view(lane, divergent=fault == "forged_digest"),
        "source_basis_digest": receipt.source_basis_digest}
    if fault == "missing_digest":
        del recheck["source_basis_digest"]
    elif fault == "wrong_digest":
        recheck["source_basis_digest"] = "0" * 64
    elif fault == "missing_view":
        del recheck["view"]
    elif fault == "nonmapping_view":
        recheck["view"] = []
    proposal = json_utf8({"proposal_id": "b2bprop_" + sink.attempt_id[5:],
                    "attempt_id": sink.attempt_id, "binding_digest": sink.binding_digest,
                    "profile": sink.profile, "session_id": sink.session_id,
                    "project_id": sink.policy["project_id"],
                    "mission_id": sink.policy["mission_id"],
                    "mission_revision": sink.policy["mission_revision"],
                    "context_digest": receipt.digest,
                    "summary": "s", "steps": ["st"], "source_refs": [],
                    "limitations": [], "state": "prepared",
                    "created_at": "2026-10-29T23:59:59Z"})
    with pytest.raises(ValueError, match="b2b_seal_context"):
        lane.store.b2b_seal(
            profile=sink.profile, attempt_id=sink.attempt_id,
            artifacts={"source_before_seal": b2b._source_record(lane.resolved),
                       "context_recheck": json_utf8(recheck), "proposal": proposal})
    _assert_seal_rollback(lane, before)
