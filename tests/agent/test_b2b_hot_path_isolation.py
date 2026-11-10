"""The ordinary provider/compaction hot paths never touch the B2B lane.

Regression for the review finding that ``agent/chat_completion_nonstream.py``,
``agent/turn_api_call.py`` and ``agent/turn_context_compaction.py`` wired B2B
capability checks into code every ordinary request runs through. Ordinary
sessions must construct ``_NonStreamRequest``, run ``perform_api_call`` and
compact even when ``agent.b2b_execution`` cannot be imported at all, and a
reserved-looking session id must not short-circuit the generic compaction
helper either.
"""

from __future__ import annotations

import sys

import pytest


class _OrdinaryAgent:
    """Minimal stand-in carrying only what the ordinary paths read."""

    def __init__(self, session_id="api_ordinary"):
        self.session_id = session_id
        self.api_mode = "chat_completions"
        self.provider = "custom"
        self.model = "unit-model"
        self.base_url = "http://127.0.0.1:9/v1"
        self.platform = "api_server"
        self.client = None
        self._interrupt_requested = False
        self._disable_streaming = True
        self._pending_redirect_lock = None
        self._pending_redirect = None
        self.thinking_callback = None
        self.is_subagent = False
        self._fallback_index = 0
        self._model_request_active = None

    def _compute_non_stream_stale_timeout(self, api_payload):
        return float("inf")

    def _has_stream_consumers(self):
        return False

    def _has_pending_redirect(self):
        return False

    def _interruptible_api_call(self, kwargs):
        return {"marker": "ordinary-response", "kwargs": dict(kwargs)}

    def _touch_activity(self, *a, **k):
        pass


@pytest.fixture
def b2b_unimportable(monkeypatch):
    """Any ``import agent.b2b_execution`` during the call raises ImportError."""
    monkeypatch.delitem(sys.modules, "agent.b2b_execution", raising=False)
    monkeypatch.setitem(sys.modules, "agent.b2b_execution", None)


def test_nonstream_request_ordinary_path_never_imports_b2b(b2b_unimportable):
    from agent.chat_completion_nonstream import _NonStreamRequest
    req = _NonStreamRequest(_OrdinaryAgent(), {"model": "unit-model", "messages": []})
    assert req.result == {"response": None, "error": None}
    assert "agent.b2b_execution" not in sys.modules or \
        sys.modules["agent.b2b_execution"] is None


def test_perform_api_call_ordinary_path_never_imports_b2b(b2b_unimportable):
    from agent.turn_api_call import perform_api_call
    agent = _OrdinaryAgent()
    verdict = perform_api_call(
        agent, api_kwargs={"model": "unit-model", "messages": []},
        _original_api_kwargs=None, _llm_middleware_trace=[],
        _moa_prepared_request=None, _retry=None, thinking_spinner=None,
        retry_count=0, api_call_count=0, api_request_id="r1",
        effective_task_id=None, turn_id="t0", interrupted=False)
    assert verdict.action == "fallthrough"
    assert verdict.response == {
        "marker": "ordinary-response", "kwargs": {"model": "unit-model", "messages": []}}


def test_turn_start_compaction_never_short_circuits_reserved_session(
        monkeypatch, b2b_unimportable):
    """A b2b_-looking session id must not skip the generic compaction passes --
    the reserved namespace gets its protection at the admission surface, not by
    special-casing this shared helper."""
    from agent import turn_context_compaction as tcc

    calls = []
    monkeypatch.setattr(tcc, "_idle_compaction",
                        lambda *a, **k: calls.append("idle"))
    monkeypatch.setattr(tcc, "_preflight_compression",
                        lambda *a, **k: calls.append("preflight"))

    for sid in ("b2b_" + "a" * 64, "api_ordinary"):
        calls.clear()
        agent = _OrdinaryAgent(session_id=sid)
        out = tcc.run_turn_start_compaction(
            agent, messages=[], system_message=None, active_system_prompt=None,
            conversation_history=None, current_turn_user_idx=0,
            user_message=None, effective_task_id=None)
        assert calls == ["idle", "preflight"], sid
        assert out is not None


def test_b2b_terminal_worker_is_a_dedicated_class():
    """The B2B request worker exists only in its own module -- the ordinary
    ``_NonStreamRequest`` carries no B2B state and needs none."""
    from agent.b2b_nonstream import _B2BNonStreamRequest
    from agent.chat_completion_nonstream import _NonStreamRequest

    assert issubclass(_B2BNonStreamRequest, _NonStreamRequest)
    ordinary = _NonStreamRequest(_OrdinaryAgent(), {})
    assert not hasattr(ordinary, "_b2b_execution")
    assert not hasattr(ordinary, "_b2b_receipt")
    assert not hasattr(ordinary, "_b2b_request_digest")
