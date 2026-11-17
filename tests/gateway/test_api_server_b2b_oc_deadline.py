"""OC source-deadline host rechecks — the last-line gates on every durable
commit that follows a plugin validation seam.

The attached ``_PreparedContext`` carries the source's own observation
deadline (``source_deadline_ms``). Every gate that commits durable proof —
the readiness/configuration assertions, context publication, the dispatch
CAS, the seal commit and launch admission — must re-prove that deadline on
HOST data after the last plugin callback, never trusting a validation that
observed an earlier instant. These tests cross the deadline at each seam
(final validator call, host serialization, host resume) and require the
exact ``context_oc_source_stale`` refusal with zero durable side effects.

Everything below is REAL except the explicitly labelled unit doubles: a
real ``_PreparedContext`` from a real registered producer (directory plugin
+ genuine discovery), the real ``_AttemptSink`` + disk
``RunIdempotencyStore``, and the real OpenAI SDK against the loopback
provider on the terminal seam. No test reads production source or calls a
production-only helper name — the refusal is exercised through the real
gates only.
"""

from __future__ import annotations

import asyncio
import dataclasses
import itertools
import json
import time
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.b2b_execution import (
    B2BTerminalRefusal, ContextReceipt, bind_execution, execute_terminal,
    json_utf8, reset_execution, source_basis)
from gateway.platforms import api_server_b2b as b2b
from gateway.platforms import api_server_b2b_context as b2b_ctx
from tests.gateway import b2b_unit_fixtures
from tests.gateway.b2b_unit_fixtures import _FakeClock
from tests.gateway.b2b_process_harness import (
    UNIT_RENDERED, build_unit_native_oc_view, renew_unit_oc_read)
from tests.gateway import test_api_server_b2b_admission as admission
from tests.gateway import test_api_server_b2b_context_capacity as probe
from tests.gateway.test_api_server_b2b_hook_admission import (
    _launch, _new_launch, opened)
from tests.gateway.test_api_server_b2b_terminal import (
    _api_kwargs, _terminal_lane)

# Inside the unit OC read's freshness window (source observed at the fixed
# instant 1793361600.000 with a 10 000 ms bound -> deadline 1793361610.000).
_OC_FROZEN_NOW_S = 1793361605.0


def _install_real_producer(tmp_path, monkeypatch, home):
    """Register the REAL gated-validator producer under *home*: a directory
    plugin loaded through the genuine discovery/manifest path, with the
    bundled catalog emptied so no shipped plugin can claim the hook."""
    import hermes_cli.plugins as plugins_mod
    probe._install_gated_validator(home)
    empty_bundled = tmp_path / "no_bundled_plugins"
    empty_bundled.mkdir(exist_ok=True)
    monkeypatch.setattr(
        plugins_mod, "get_bundled_plugins_dir", lambda: empty_bundled)
    from hermes_cli.plugins import discover_plugins
    discover_plugins()
    probe._reset_probe()


def _real_preparation(tmp_path, monkeypatch, lane):
    """A REAL ``_PreparedContext`` from the registered gated producer, built
    at the frozen unit instant inside the OC observation window."""
    _install_real_producer(
        tmp_path, monkeypatch, Path(lane.policy["profile_home"]))
    monkeypatch.setattr(
        b2b_ctx, "time", SimpleNamespace(time=lambda: _OC_FROZEN_NOW_S))
    return asyncio.run(b2b_ctx.run_bounded_context_preparation(
        lambda: b2b_ctx._prepare_b2b_context(
            lane.cap, resolved={"mission_source_digest": "c" * 64})))


def _deadline_clock(monkeypatch, prep):
    """Park BOTH module clocks 1 ms inside the preparation's OC deadline on
    one shared controllable clock — the same seam the existing seal recheck
    uses, so only the OC window can close."""
    deadline_s = prep.source_deadline_ms / 1000.0
    clock = _FakeClock(now=deadline_s - 0.001)
    monkeypatch.setattr(b2b_ctx, "time", clock)
    monkeypatch.setattr(b2b, "time", clock)
    return clock, deadline_s


def _expiring_preparation(prep, clock, deadline_s):
    """The same frozen preparation, but its configuration validator crosses
    the OC deadline AFTER running the plugin's own validator — the expiry
    lands inside the LAST stamp, never before it."""
    real_validate = prep.validate_configuration

    def _validate():
        result = real_validate()
        clock.now = deadline_s
        return result

    return dataclasses.replace(prep, validate_configuration=_validate)


def _fresh_receipt(prep, lane, *, read_id=2):
    """A still-current publication receipt: a NEWER unit read of the same
    source basis as the attached preparation — compatible by construction,
    so only the OC deadline can refuse it."""
    view = renew_unit_oc_read(
        json.loads(json_utf8(prep.view)), read_id=read_id)
    return ContextReceipt(
        view=view, rendered=UNIT_RENDERED.encode("utf-8"),
        digest=view["context_digest"], turn_id=lane.turn_id,
        source_basis=source_basis(view), accepted_at=time.time())


def _advance_on_commit_serialization(monkeypatch, clock, deadline_s):
    """Cross the OC deadline DURING host serialization of the commit
    payload — after the last plugin validation, before the durable write."""
    real_ju = b2b.json_utf8

    def _ju(value):
        result = real_ju(value)
        if isinstance(value, Mapping) and value.get("format") in (
                "dubsar.b2b-context-artifact/1",
                "dubsar.b2b-provider-dispatch/1"):
            clock.now = deadline_s
        return result

    monkeypatch.setattr(b2b, "json_utf8", _ju)


def _no_dispatch_or_result_artifacts(lane):
    for kind in ("provider_dispatch", "provider_result", "proposal"):
        assert lane.store.b2b_artifact(
            attempt_id=lane.attempt_id, kind=kind) is None


# ---------------------------------------------------------------------------
# The shared preparation assertions: frame -> window -> stamp must still
# re-prove the OC deadline AFTER the plugin's own validator — the stamp is
# the last call a gate makes before it trusts the configuration.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "method",
    ["assert_current", "assert_configuration_current", "assert_publication"])
def test_preparation_assertion_rechecks_oc_deadline_after_stamp(
        tmp_path, monkeypatch, method):
    """A REAL prepared context parked 1 ms inside its OC deadline: the
    plugin's validator crosses the deadline inside the LAST stamp, and the
    assertion must still refuse ``context_oc_source_stale`` — a pure host
    timestamp comparison after the validator, never a second plugin call.
    ``assert_publication`` is handed a fresh compatible receipt so the
    refusal can only come from the post-validator deadline, never a wrong
    receipt."""
    lane = b2b_unit_fixtures.build_b2b_dispatch_lane(tmp_path)
    try:
        prep = _real_preparation(tmp_path, monkeypatch, lane)
        clock, deadline_s = _deadline_clock(monkeypatch, prep)
        prep = _expiring_preparation(prep, clock, deadline_s)
        lane.sink._context_preparation = prep
        if method == "assert_publication":
            receipt = _fresh_receipt(prep, lane)
            call = lambda: prep.assert_publication(lane.cap, receipt)
        elif method == "assert_configuration_current":
            call = prep.assert_configuration_current
        else:
            call = lambda: prep.assert_current(lane.cap)
        with pytest.raises(B2BTerminalRefusal) as exc:
            call()
        assert str(exc.value) == "context_oc_source_stale"
        _no_dispatch_or_result_artifacts(lane)
    finally:
        lane.store.close()


# ---------------------------------------------------------------------------
# The sink's own commit gates: the context publication and the dispatch CAS
# must re-prove the OC deadline AFTER the last plugin validation and
# immediately before the durable write — whether the expiry lands inside
# the final validator call or during host serialization of the payload.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("gate", ["publication", "cas_dispatch"])
@pytest.mark.parametrize("seam", ["final_validator", "host_commit"])
def test_sink_commit_gate_rechecks_oc_deadline(
        tmp_path, monkeypatch, gate, seam):
    """REAL attached preparation, real disk store, spied commit/CAS calls
    (the spies call through if ever invoked). ``final_validator`` crosses
    the deadline inside the real plugin validator; ``host_commit`` crosses
    it during the host's own payload serialization — after validation
    succeeded. Either way the gate must refuse the exact
    ``context_oc_source_stale`` BEFORE the durable write: no context commit,
    no CAS marker, and the validator ran only once for the attempt (the
    host check never re-invokes the plugin)."""
    lane = b2b_unit_fixtures.build_b2b_dispatch_lane(tmp_path)
    try:
        prep = _real_preparation(tmp_path, monkeypatch, lane)
        clock, deadline_s = _deadline_clock(monkeypatch, prep)
        if seam == "final_validator":
            prep = _expiring_preparation(prep, clock, deadline_s)
        else:
            _advance_on_commit_serialization(
                monkeypatch, clock, deadline_s)
        lane.sink._context_preparation = prep
        commit_calls = []
        if gate == "publication":
            real_commit = lane.store.b2b_commit_context

            def _commit_spy(**kwargs):
                commit_calls.append(kwargs)
                return real_commit(**kwargs)

            monkeypatch.setattr(
                lane.store, "b2b_commit_context", _commit_spy)
            token = bind_execution(lane.cap)
            try:
                with pytest.raises(B2BTerminalRefusal) as exc:
                    lane.sink.put_context(_fresh_receipt(prep, lane))
            finally:
                reset_execution(token)
        else:
            # The signed envelopes bracket the fake clock on BOTH sides of
            # the deadline — ONLY the OC window closes, never the signed one.
            resolved = dict(lane.resolved)
            resolved["_signed_request"] = {
                "issued_at": clock.now - 1.0,
                "expires_at": deadline_s + 60.0}
            resolved["_signed_response"] = {
                "issued_at": clock.now - 1.0,
                "expires_at": deadline_s + 60.0}
            lane.sink._before_provider = resolved
            real_cas = lane.store.b2b_cas_dispatch

            def _cas_spy(**kwargs):
                commit_calls.append(kwargs)
                return real_cas(**kwargs)

            monkeypatch.setattr(lane.store, "b2b_cas_dispatch", _cas_spy)
            with pytest.raises(B2BTerminalRefusal) as exc:
                lane.sink.cas_dispatch(
                    request_digest=lane.policy["request_digest"],
                    receipt=lane.receipt,
                    rechecked_view=renew_unit_oc_read(lane.view))
        assert str(exc.value) == "context_oc_source_stale"
        assert commit_calls == []
        # One plugin validator call at preparation + exactly ONE for the
        # attempted gate — the host recheck is a timestamp comparison.
        assert len(probe.VAL_WORKER_THREADS) == 2
        _no_dispatch_or_result_artifacts(lane)
        if gate == "cas_dispatch":
            assert lane.store.b2b_attempt(
                profile=lane.profile, attempt_id=lane.attempt_id)[
                    "status"] == "context_stale"
    finally:
        lane.store.close()


# ---------------------------------------------------------------------------
# The real provider path: the LAST ``_matches_source`` inside the dispatch
# CAS is the final plugin validation before the paid send. The deadline is
# armed to cross only inside that call — every earlier policy validator is
# timely — so the expiry is provably caught by the CAS's own last line.
# ---------------------------------------------------------------------------

def test_terminal_cas_final_validator_oc_expiry_blocks_send(
        tmp_path, monkeypatch):
    """Real SDK loopback terminal path: arm the OC deadline to cross ONLY
    inside the ``_matches_source`` the dispatch CAS performs (the wrapped
    validator advances the shared clock only once ``cas_dispatch`` has been
    entered, after running the plugin's own validator). ``execute_terminal``
    must raise the exact ``context_oc_source_stale`` — the CAS never
    commits, the loopback provider is never contacted, and the attempt
    records the typed ``context_stale`` verdict."""
    read_ids = itertools.count(2)
    lane_ref = {}

    def _recheck(_cap):
        return renew_unit_oc_read(
            lane_ref["lane"].view, read_id=next(read_ids))

    lane, provider, agent = _terminal_lane(
        tmp_path, monkeypatch,
        view_factory=lambda policy, body: build_unit_native_oc_view(
            policy, body, ordered=True),
        recheck=_recheck)
    lane_ref["lane"] = lane
    try:
        prep = _real_preparation(tmp_path, monkeypatch, lane)
        clock, deadline_s = _deadline_clock(monkeypatch, prep)
        # Signed envelopes bracket the shared fake clock across the deadline
        # — ONLY the OC window closes.
        resolved = dict(lane.resolved)
        resolved["_signed_request"] = {
            "issued_at": _OC_FROZEN_NOW_S - 1.0,
            "expires_at": deadline_s + 60.0}
        resolved["_signed_response"] = {
            "issued_at": _OC_FROZEN_NOW_S - 1.0,
            "expires_at": deadline_s + 60.0}
        lane.resolved = resolved

        armed = {"flag": False}
        real_validate = prep.validate_configuration

        def _armed_validate():
            result = real_validate()
            if armed["flag"]:
                clock.now = deadline_s
            return result

        lane.sink._context_preparation = dataclasses.replace(
            prep, validate_configuration=_armed_validate)
        real_cas = lane.sink.cas_dispatch

        def _arming_cas(**kwargs):
            armed["flag"] = True
            return real_cas(**kwargs)

        monkeypatch.setattr(lane.sink, "cas_dispatch", _arming_cas)
        cas_calls = []
        real_store_cas = lane.store.b2b_cas_dispatch

        def _cas_spy(**kwargs):
            cas_calls.append(kwargs)
            return real_store_cas(**kwargs)

        monkeypatch.setattr(lane.store, "b2b_cas_dispatch", _cas_spy)

        token = bind_execution(lane.cap)
        try:
            with pytest.raises(B2BTerminalRefusal) as exc:
                execute_terminal(
                    agent, _api_kwargs(lane), lane.cap,
                    turn_id=lane.turn_id)
        finally:
            reset_execution(token)
        assert str(exc.value) == "context_oc_source_stale"
        assert provider.posts == []
        assert cas_calls == []
        _no_dispatch_or_result_artifacts(lane)
        assert lane.store.b2b_attempt(
            profile=lane.profile, attempt_id=lane.attempt_id)[
                "status"] == "context_stale"
    finally:
        agent.client.close()
        lane.store.close()
        provider.stop()


# ---------------------------------------------------------------------------
# Launch admission: the durable admit is the last commit of the launch —
# an OC deadline crossed inside the final readiness validation, or while
# the host resumes after a timely bounded preparation, refuses 503
# ``context_oc_source_stale`` BEFORE ``store.b2b_admit`` with zero durable
# side effects.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "seam", ["final_validator", "host_resume", "host_serialization"])
async def test_admission_rechecks_oc_deadline_before_admit(
        tmp_path, monkeypatch, opened, seam):
    """REAL launch (session DB, plugin discovery, bounded workers, disk
    store). ``final_validator`` returns a preparation whose validator
    crosses the OC deadline when the REAL readiness gate invokes it — the
    typed refusal must still surface even though boolean readiness
    flattens causes into ``c1_context_required``. ``host_resume`` lets
    preparation finish timely, then crosses the deadline while the host
    resumes — the re-check immediately before ``b2b_admit`` catches it.
    ``host_serialization`` lets everything pass timely, then crosses the
    deadline while the host serializes the admit's own source-bind row —
    serialization AFTER validation can never stand between the recheck
    and the durable write. Either way: 503 ``context_oc_source_stale``,
    no admit, no spawn, no durable writes."""
    case = _new_launch(tmp_path, monkeypatch, opened)
    probe._install_gated_validator(case.profile_home)
    clock = _FakeClock(now=_OC_FROZEN_NOW_S)
    monkeypatch.setattr(b2b_ctx, "time", clock)
    probe._reset_probe()
    if seam == "final_validator":
        real_prepare = b2b_ctx._prepare_b2b_context

        def _expiring_prepare(cap, *, resolved):
            prep = real_prepare(cap, resolved=resolved)
            deadline_s = prep.source_deadline_ms / 1000.0
            real_validate = prep.validate_configuration

            def _advancing_validate():
                result = real_validate()
                clock.now = deadline_s
                return result

            return dataclasses.replace(
                prep, validate_configuration=_advancing_validate)

        monkeypatch.setattr(
            b2b_ctx, "_prepare_b2b_context", _expiring_prepare)
    elif seam == "host_serialization":
        real_source_record = b2b._source_record

        def _serialize_then_advance(resolved):
            payload = real_source_record(resolved)
            clock.now = 1793361610.0
            return payload

        monkeypatch.setattr(b2b, "_source_record", _serialize_then_advance)
    else:
        prepared = {}
        real_prepare = b2b_ctx._prepare_b2b_context

        def _capturing_prepare(cap, *, resolved):
            prepared["prep"] = real_prepare(cap, resolved=resolved)
            return prepared["prep"]

        real_bounded = b2b_ctx.run_bounded_context_preparation

        async def _resume_then_advance(callback):
            result = await real_bounded(callback)
            clock.now = prepared["prep"].source_deadline_ms / 1000.0
            return result

        monkeypatch.setattr(
            b2b_ctx, "_prepare_b2b_context", _capturing_prepare)
        monkeypatch.setattr(
            b2b_ctx, "run_bounded_context_preparation",
            _resume_then_advance)

    admit_calls = []
    real_admit = case.store.b2b_admit

    def _admit_spy(**kwargs):
        admit_calls.append(kwargs)
        return real_admit(**kwargs)

    monkeypatch.setattr(case.store, "b2b_admit", _admit_spy)
    spawn_calls = []

    async def _spawn_spy(*a, **k):
        spawn_calls.append((a, k))
        return SimpleNamespace(done=lambda: True)

    monkeypatch.setattr(b2b, "_spawn_run", _spawn_spy)
    agent_calls = []
    monkeypatch.setattr(
        case.adapter, "_create_agent",
        lambda *a, **k: agent_calls.append((a, k)))
    before = admission._store_counts(case.store)

    response = await _launch(case)

    assert response.status == 503
    assert json.loads(response.body)["error"] == "context_oc_source_stale"
    assert admit_calls == []
    assert spawn_calls == []
    assert agent_calls == []
    # One plugin validator call at preparation + exactly ONE inside the
    # readiness gate itself — the host deadline recheck is a timestamp
    # comparison, never a second plugin invocation.
    assert len(probe.VAL_WORKER_THREADS) == 2
    assert admission._store_counts(case.store) == before
    assert case.adapter._session_db.get_session(
        case.session_id)["title"] is None
