"""The B2B context preparation's native read is bounded process-wide.

While one preparation worker is in flight -- including a producer wedged past
the caller's source deadline -- every further launch must refuse
``execution_unavailable`` WITHOUT starting another plugin discovery, provider
read or worker thread, and without durable writes. Releasing the blocked
producer frees the slot: the next launch prepares and admits normally.
"""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from tests.gateway import test_api_server_b2b_admission as admission
from tests.gateway import test_api_server_b2b_execution_lane as execution_lane
from tests.gateway.test_api_server_b2b_hook_admission import (
    _forbidden, _launch, _new_launch, opened)

# State shared with the fake producer plugin below (it imports this module):
# the gate the producer waits on and the actual worker Thread objects that
# entered its prepare_context callback.
PREP_GATE = threading.Event()
PREP_ENTERED = threading.Event()
PREP_WORKER_THREADS = []

_CAPACITY_PLUGIN_NAME = "capacity-producer"

# Same contract as execution_lane._FAKE_PLUGIN_INIT, but the callback parks
# on PREP_GATE so a launch can be held inside its native read.
_CAPACITY_PLUGIN_INIT = '''\
def register(ctx):
    def prepare_context(*, execution):
        import threading as _threading
        from agent.b2b_execution import B2BTerminalRefusal
        from tests.gateway import test_api_server_b2b_context_capacity as probe
        from tests.gateway.b2b_process_harness import (
            UNIT_RENDERED, build_unit_native_oc_view)
        probe.PREP_WORKER_THREADS.append(_threading.current_thread())
        probe.PREP_ENTERED.set()
        probe.PREP_GATE.wait()
        stamp = ctx.get_config("preparation_stamp")

        def validate_configuration():
            if ctx.get_config("preparation_stamp") != stamp:
                raise B2BTerminalRefusal("b2b_policy_changed")
            return True

        view = build_unit_native_oc_view(
            execution.policy, {"mission_source_digest": "c" * 64},
            ordered=True)
        return {"view": view, "rendered": UNIT_RENDERED,
                "validate_configuration": validate_configuration}
    ctx.register_hook("prepare_context", prepare_context)
    ctx.register_hook("pre_llm_call", lambda **kwargs: None)
'''


@pytest.mark.asyncio
async def test_preparation_is_bounded_process_wide(
        tmp_path, monkeypatch, opened):
    """Eight sequential launches while the producer is blocked: all explicit
    503 execution_unavailable, at most ONE native-read worker/discovery ever
    starts, nothing durable mutates -- then releasing the producer frees the
    slot and the next launch admits."""
    from gateway.platforms import api_server_b2b as b2b
    from gateway.platforms import api_server_b2b_context as b2b_ctx
    from hermes_cli.plugins import discover_plugins

    case = _new_launch(tmp_path, monkeypatch, opened)
    case.adapter._max_concurrent_runs = 1
    # The unit view's source_observed_at is a fixed instant; freeze the
    # source clock so a real preparation qualifies (refusals must come from
    # capacity, never a stale window).
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: 1793361605.0))
    execution_lane._write_fake_plugin(
        case.profile_home, name=_CAPACITY_PLUGIN_NAME,
        init=_CAPACITY_PLUGIN_INIT)
    execution_lane._plugin_config(
        case.profile_home, names=(_CAPACITY_PLUGIN_NAME,))
    with case.adapter._profile_scope("hub"):
        discover_plugins()

    PREP_GATE.clear()
    PREP_ENTERED.clear()
    del PREP_WORKER_THREADS[:]

    discovery_calls = []
    real_provider = b2b_ctx._context_provider

    def _counting_provider(*, discover=False):
        discovery_calls.append(discover)
        return real_provider(discover=discover)

    monkeypatch.setattr(b2b_ctx, "_context_provider", _counting_provider)
    monkeypatch.setattr(
        execution_lane.b2b, "_spawn_run", _forbidden("_spawn_run"))
    before = admission._store_counts(case.store)

    responses = []
    try:
        for _ in range(8):
            responses.append(await _launch(case))
        assert all(response.status == 503 for response in responses)
        assert all(
            json.loads(response.body)["error"] == "execution_unavailable"
            for response in responses)
        # Exactly ONE native-read worker ever entered the producer and exactly
        # ONE discovery was started -- the wedged worker's slot is not released
        # by the caller's deadline expiring, so the later launches refused
        # without spawning discovery/provider work.
        assert PREP_ENTERED.is_set(), "producer callback never ran"
        assert len(set(PREP_WORKER_THREADS)) == 1, (
            f"{len(set(PREP_WORKER_THREADS))} preparation workers started")
        assert discovery_calls.count(True) == 1, (
            f"{discovery_calls.count(True)} discovery passes started")
        assert admission._store_counts(case.store) == before
        assert case.adapter._session_db.get_session(
            case.session_id)["title"] is None
    finally:
        PREP_GATE.set()

    # Every worker that ever entered the producer finishes once the gate
    # opens; none is left holding a preparation slot.
    for thread in set(PREP_WORKER_THREADS):
        thread.join(timeout=10.0)
    assert not any(t.is_alive() for t in PREP_WORKER_THREADS)

    spawned = []

    async def _spawn(adapter, request, *, cap, resolved, session_id, run_id,
                     profile):
        spawned.append((run_id, session_id))
        return SimpleNamespace()

    monkeypatch.setattr(execution_lane.b2b, "_spawn_run", _spawn)

    response = await _launch(case)

    assert response.status == 200, response.body
    assert len(spawned) == 1
    attempt = case.store.b2b_attempt(
        profile="hub", attempt_id=case.resolved["attempt_id"])
    assert attempt["status"] == "admitted"
    assert case.adapter._session_db.get_session(case.session_id)["title"] == (
        "B2B " + case.session_id)
