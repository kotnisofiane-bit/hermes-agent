"""B2B-only non-stream request worker (KOT-263 H1).

``_B2BNonStreamRequest`` reuses the ordinary ``_NonStreamRequest`` lifecycle --
thread spawn, watchdog poll loop, codex-token retirement and client cleanup --
but owns the governed-lane specifics the generic worker must never see: the
isolated zero-retry httpx client, the durable dispatch CAS + attestation
headers, and validate-then-commit of the public result INSIDE the worker before
the response is visible to the loop/transcript. Only ``execute_terminal``
constructs it.
"""

import httpx

from agent import chat_completion_helpers as h
from agent.b2b_execution import (
    B2BTerminalRefusal, _public_text, before_sdk_dispatch,
    extract_allowed_refs, validate_proposal)
from agent.chat_completion_nonstream import _NonStreamRequest


class _B2BNonStreamRequest(_NonStreamRequest):
    """One governed provider call on a worker thread, polled by the caller."""

    def __init__(self, agent, api_kwargs: dict, *, cap, receipt, request_digest: str):
        super().__init__(agent, api_kwargs)
        self._b2b_execution = cap
        self._b2b_receipt = receipt
        self._b2b_request_digest = request_digest
        # No stale watchdog before the send: C1/source deadlines and the
        # SQLite busy_timeout remain the local bounds. A finite stale window
        # could kill the poll while the worker still commits the CAS and
        # sends. The provider window arms only at the actual send (_call).
        self.wd.stale_timeout = float("inf")

    def _remaining_run_budget(self) -> float:
        """Seconds of run budget left on the worker clock; ``inf`` when the
        agent carries no numeric budget/start pair. A numeric zero budget or
        epoch-0 start is a real (exhausted) budget, never "no budget"."""
        budget = getattr(self.agent, "run_budget_seconds", None)
        started = getattr(self.agent, "_run_budget_started_at", None)
        if not (isinstance(budget, (int, float))
                and isinstance(started, (int, float))):
            return float("inf")
        return max(0.0, float(budget) - (h.time.time() - float(started)))

    def _check_dispatch_allowed(self) -> None:
        """The ONE budget/cancel rejection gate, invoked by
        ``before_sdk_dispatch`` AFTER the final C1 + source renewal and
        immediately BEFORE the durable dispatch CAS. Refusing here is still
        safe -- no committed marker exists. Once the CAS has committed there
        is no voluntary run-budget stop -- abandoning the send would leave a
        nonretryable, possibly-billed indeterminate. A cancel landing
        between this gate and the commit can still race the CAS (existing
        known race); there is deliberately no post-CAS abort."""
        if self.cancelled or self._remaining_run_budget() <= 0:
            # Persist BEFORE raising: _call swallows a cancelled worker's
            # exception -- without the durable block the attempt would stay
            # context_ready forever.
            self._b2b_execution.sink.block("provider_result_unavailable")
            raise B2BTerminalRefusal("provider_result_unavailable")

    def _arm_stale_window(self, requested_timeout: float) -> float:
        """Arm the stale deadline on the construction-origin clock and return
        the armed window: ``elapsed + requested_timeout``. ``call_start``
        never moves, so the raw ``wd.stale_timeout`` includes preparation
        elapsed; a poll holding a pre-arm elapsed can never falsely expire a
        freshly armed shorter window."""
        now = h.time.time()
        elapsed = max(0.0, now - self.call_start)
        self.wd.stale_timeout = elapsed + requested_timeout
        return requested_timeout

    def _make_client(self, reason: str, kind: str = "openai"):
        if self._b2b_receipt is None or not self._b2b_request_digest:
            raise B2BTerminalRefusal("terminal_guard_required")
        # Validate the policy BEFORE building the per-request client: a refusal
        # raised past construction would leak it -- it is not yet registered with
        # the abort machinery nor covered by the try/finally below.
        project_policy = self._b2b_execution.policy_get("project", {})
        raw_timeout = project_policy.get("request_timeout_seconds", 5)
        if (isinstance(raw_timeout, bool) or not isinstance(raw_timeout, int)
                or not 1 <= raw_timeout <= 900):
            raise B2BTerminalRefusal("b2b_timeout_policy")
        request_timeout = float(raw_timeout)
        # Per-request clients are registered with the abort machinery so the watchdogs
        # force-close the worker's connection, never the shared client (#67142).
        if kind == "anthropic_messages":
            client = self.agent._create_request_anthropic_client(reason=reason)
        else:
            client = self.agent._create_request_openai_client(reason=reason, api_kwargs=self.api_kwargs)
        # SDK options belong to this request, never to an agent/shared client.
        clone = getattr(client, "with_options", None)
        if not callable(clone):
            if client is not getattr(self.agent, "client", None):
                if kind == "anthropic_messages":
                    self.agent._close_request_anthropic_client(client, reason="b2b_isolated_transport")
                else:
                    self.agent._close_request_openai_client(client, reason="b2b_isolated_transport")
            raise B2BTerminalRefusal("b2b_retries_not_disabled")
        original = client
        transport = httpx.HTTPTransport(retries=0, trust_env=False)
        http_client = httpx.Client(
            transport=transport, trust_env=False, follow_redirects=False, timeout=request_timeout)
        try:
            client = clone(max_retries=0, http_client=http_client, timeout=request_timeout)
            if client is original:
                raise B2BTerminalRefusal("b2b_request_client_not_isolated")
        except Exception:
            http_client.close()
            raise
        finally:
            if original is not getattr(self.agent, "client", None):
                self.agent._close_request_openai_client(original, reason="b2b_isolated_transport")
        self.clients.set_client(client, kind=kind)
        cap = self._b2b_execution
        before_sdk_dispatch(
            self.agent, self.api_kwargs, cap, receipt=self._b2b_receipt,
            expected_digest=self._b2b_request_digest, client=client,
            dispatch_gate=self._check_dispatch_allowed)
        headers = dict(self.api_kwargs.get("extra_headers") or {})
        headers["X-Dubsar-Attempt-Id"] = cap.attempt_id
        headers["X-Dubsar-Request-Digest"] = self._b2b_request_digest
        self.api_kwargs["extra_headers"] = headers
        self.api_kwargs["timeout"] = request_timeout
        return self.clients.set_client(client, kind=kind)

    def _call(self):
        watchdog_state_var = watchdog_context_token = None
        try:
            self._install_codex_request_token()
            if self.codex_watchdog_state is not None:
                from agent.codex_runtime import _codex_watchdog_state_var

                watchdog_state_var = _codex_watchdog_state_var
                watchdog_context_token = watchdog_state_var.set(self.codex_watchdog_state)
            # The B2B chat-only lane has no virtual provider/last-moment payload
            # transform between the durable dispatch fence and this single SDK call.
            client = self._make_client("b2b_chat_completion_request")
            # Arm the full validated provider window AT the send (deadline =
            # elapsed + request_timeout, no run-budget clamp). The
            # budget/cancel gate already ran before the CAS; there is no
            # post-CAS voluntary stop. Explicit interrupts and network
            # failures retain their existing behavior.
            self._arm_stale_window(float(self.api_kwargs["timeout"]))
            try:
                response = client.chat.completions.create(**self.api_kwargs)
            finally:
                # The provider window ends on response or SDK error, before
                # local validation, SQLite persistence and client cleanup.
                self.wd.stale_timeout = float("inf")
            # Validate + persist the public result BEFORE the response is
            # visible to the loop/transcript -- a rejected shape never leaves the
            # worker as a "completed" response (tools/reasoning/private bytes ->
            # classified error).
            cap = self._b2b_execution
            receipt = getattr(cap.sink, "context_receipt", None) or cap.context_receipt
            text = _public_text(response)
            allowed = extract_allowed_refs(receipt.view) if receipt is not None else ()
            parsed, reason = validate_proposal(text, allowed)
            if parsed is None:
                cap.sink.block("result_invalid")
                raise B2BTerminalRefusal(f"result_invalid:{reason}")
            cap.sink.commit_result(text=text, parsed=parsed, reason=reason)
            self.result["response"] = response
        except Exception as e:
            # Our own force-close caused this error: swallow it, the main
            # thread raises InterruptedError (#6600). Retirement logs at info
            # (a watchdog discarded output the provider already sent -- what an
            # operator debugging a truncated reply needs); cancellation at debug.
            if self.codex_retired:
                h.logger.info("Codex worker caught %s after request retirement — "
                    "discarding the stale partial instead of surfacing it as a completed response. %s",
                    type(e).__name__, self.agent._client_log_context())
                return
            if self.cancelled:
                h.logger.debug("Non-streaming worker caught %s after request "
                    "cancellation — exiting without surfacing a network error.", type(e).__name__)
                return
            # A raw client/SDK/worker exception may carry provider response
            # bytes -- normalize it to a safe classified refusal BEFORE the native
            # loop or error log can echo it. Classified B2BTerminalRefusal passes
            # through untouched; the durable block lands with the same constant.
            if not isinstance(e, B2BTerminalRefusal):
                self.result["error"] = B2BTerminalRefusal("provider_result_unavailable")
                try:
                    self._b2b_execution.sink.block("provider_result_unavailable")
                except Exception:
                    pass  # DB unavailable -- the safe result is already set
                return
            self.result["error"] = e
        finally:
            if watchdog_state_var is not None:
                watchdog_state_var.reset(watchdog_context_token)
            # Retire first: close_once can raise, and a leaked token would let
            # a later worker mistake itself for the owning attempt.
            self._retire_codex_request_token()
            # Reuse reason only on a clean response; error or cancel-swallow
            # really closes so the next attempt builds a fresh pool.
            self.clients.close_once(
                "request_complete" if self.result["response"] is not None else "request_error_cleanup")
