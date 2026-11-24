"""``memory_mode`` -- the operator-catalogue context mode for the B2B lane:
project-entry validation (closed ``required``/``none`` vocabulary, absent key
keeps replay-identical bytes), policy-digest inclusion with mid-run
revocation, and the no-memory preparation contract: an explicit producer
opt-in checked BEFORE the callback may run, a returned memory block refused,
a policy/view mode mismatch refused, and opt-in removal revoking a stamped
preparation.

The producer below is a REAL directory plugin loaded through the genuine
discovery path; its returned view is an explicitly labelled UNIT DOUBLE built
on the pinned r2 blobs (``_no_memory_view`` in
``tests/agent/test_b2b_execution.py``) -- never a real AgentContext/C1 build
and never a real Memory service.
"""

from __future__ import annotations

import copy
import socket
import urllib.request

import pytest

from agent.b2b_execution import (
    B2BTerminalRefusal, context_proof, verify_context_proof)
from agent.memory_manager import MemoryManager
from gateway.platforms import api_server_b2b as b2b
from gateway.platforms import api_server_b2b_context as b2b_ctx
from gateway.platforms import api_server_b2b_native_validation as native_validation
from hermes_cli.plugins import discover_plugins
from tests.gateway import test_api_server_b2b_execution_lane as execution_lane
from tests.gateway import test_api_server_b2b_timeout as timeout
from tests.gateway.test_api_server_b2b_execution_lane import (
    _prepare_resolved, _ready_lane, _rebind_project, _write_fake_plugin)
from tools.memory_tool import MemoryStore


fake_plugin_home = execution_lane.fake_plugin_home


# ---------------------------------------------------------------------------
# memory_mode -- optional project catalogue key (same replay contract as
# request_timeout_seconds: absent adds no digest bytes, explicit fingerprints)
# ---------------------------------------------------------------------------

def test_memory_mode_operator_policy_and_revocation(tmp_path):
    for value in (None, True, False, "", "auto", "disabled", [], {}):
        with pytest.raises(native_validation.B2BConfigError, match="memory_mode"):
            native_validation._validate_project_entry(
                timeout._timeout_project_entry(memory_mode=value), "b")
    for value in ("required", "none"):
        normalized = native_validation._validate_project_entry(
            timeout._timeout_project_entry(memory_mode=value), "b")
        assert normalized["memory_mode"] == value
    normalized = native_validation._validate_project_entry(
        timeout._timeout_project_entry(), "b")
    assert "memory_mode" not in normalized

    entry, project, resolved = timeout._digest_inputs(timeout=None)
    default = b2b._policy_digest("hub", entry, project, resolved)
    fingerprints = {}
    for value in ("required", "none"):
        keyed = {**project, "memory_mode": value}
        fingerprints[value] = b2b._policy_digest("hub", entry, keyed, resolved)
        assert fingerprints[value] != default
    assert fingerprints["required"] != fingerprints["none"]

    lane = timeout._timeout_lane(tmp_path, None)
    try:
        assert lane.sink.assert_current_policy() is True
        # Operator selects the no-memory mode mid-run: the live basis diverges
        # from the admission fingerprint and the cap is revoked, never
        # silently re-pinned.
        changed = copy.deepcopy(lane.entry)
        changed["projects"]["b2b-bench"]["memory_mode"] = "none"
        lane.adapter._b2b_state = b2b._B2BState(b2b.validate_b2b_config(
            {"b2b": {"enabled": True, "profiles": {"hub": changed}}}))
        assert lane.sink.assert_current_policy() is False
    finally:
        lane.store.close()


# ---------------------------------------------------------------------------
# Explicit no-memory preparation -- the producer declares support BEFORE the
# host invokes it; every failure refuses with its typed reason.
# ---------------------------------------------------------------------------

_NO_MEMORY_PLUGIN_INIT = '''\
def register(ctx):
    def prepare_context(*, execution):
        from pathlib import Path
        from tests.agent.test_b2b_execution import _no_memory_view
        from tests.gateway.b2b_process_harness import (
            UNIT_RENDERED, reseal_unit_context_view)
        Path(__MARKER__).write_text("called")
        view = _no_memory_view(execution.policy)
        view["mission_binding"]["source_digest"] = "c" * 64
        view["my_work"]["mission"]["source_digest"] = "c" * 64
        __MEMORY_BLOCK__
        reseal_unit_context_view(view)
        return {"view": view, "rendered": UNIT_RENDERED,
                "validate_configuration": lambda: True}
    prepare_context.b2b_memory_modes = ("none",)
    ctx.register_hook("prepare_context", prepare_context)
    ctx.register_hook("pre_llm_call", lambda **kwargs: None)
'''

# A producer registered without the opt-in attribute: its callback body must
# never execute -- the marker and the raise make a pre-callback refusal
# observable instead of relying on the exception's provenance.
_LEGACY_PLUGIN_INIT = '''\
def register(ctx):
    def prepare_context(*, execution):
        from pathlib import Path
        Path(__MARKER__).write_text("called")
        raise AssertionError("legacy producer must not run")
    ctx.register_hook("prepare_context", prepare_context)
    ctx.register_hook("pre_llm_call", lambda **kwargs: None)
'''


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", [
    "supported", "legacy", "memory_block", "policy_mismatch", "support_revoked"])
async def test_no_memory_preparation_requires_explicit_producer_support(
        tmp_path, fake_plugin_home, monkeypatch, scenario):
    lane = _ready_lane(tmp_path)
    if scenario != "policy_mismatch":
        _rebind_project(lane, memory_mode="none")
    marker = fake_plugin_home.home / "producer-called"
    init = _NO_MEMORY_PLUGIN_INIT
    if scenario == "legacy":
        init = _LEGACY_PLUGIN_INIT
    init = init.replace("__MARKER__", repr(str(marker)))
    init = init.replace(
        "__MEMORY_BLOCK__", 'view["memory"] = {}'
        if scenario == "memory_block" else "pass")
    _write_fake_plugin(fake_plugin_home.home, init=init)
    discover_plugins()
    assert b2b_ctx.producer_available() is True
    # Zero-IO invariant of the Hermes no-memory path with this producer
    # double: neither prepare() nor validate_configuration() may touch a
    # Memory store or open a socket. Installed AFTER discovery so plugin
    # loading itself is unaffected; this is a path invariant, not a sandbox
    # claim about the external plugin.
    memory_io = []
    def forbid_memory_io(*args, **kwargs):
        memory_io.append(True)
        raise AssertionError(
            "no-memory preparation must not read Memory or open a socket")
    monkeypatch.setattr(MemoryStore, "load_from_disk", forbid_memory_io)
    monkeypatch.setattr(MemoryManager, "prefetch_all", forbid_memory_io)
    monkeypatch.setattr(urllib.request, "urlopen", forbid_memory_io)
    monkeypatch.setattr(socket.socket, "connect", forbid_memory_io)

    async def _prepare():
        return await b2b_ctx.run_bounded_context_preparation(
            lambda: b2b_ctx._prepare_b2b_context(
                lane.cap,
                resolved=_prepare_resolved(fake_plugin_home.now[0])))

    try:
        if scenario == "supported":
            prep = await _prepare()
            assert marker.exists()
            assert "memory" not in prep.view
            assert "accepted_context" not in prep.view
            assert prep.view["memory_mode"] == "none"
            checked = verify_context_proof(context_proof(prep.view))
            assert checked["view"]["memory_mode"] == "none"
            prep.assert_current(lane.cap)
            assert prep.assert_configuration_current() is True
        elif scenario == "support_revoked":
            prep = await _prepare()
            assert marker.exists()
            found = b2b_ctx._context_provider()
            del found[1].b2b_memory_modes
            with pytest.raises(B2BTerminalRefusal) as exc:
                prep.assert_current(lane.cap)
            assert str(exc.value) == "context_memory_mode"
        else:
            with pytest.raises(B2BTerminalRefusal) as exc:
                await _prepare()
            expected = {"legacy": "context_memory_mode",
                        "memory_block": "context_memory_unexpected",
                        "policy_mismatch": "context_memory_mode"}[scenario]
            assert str(exc.value) == expected
            if scenario == "legacy":
                # Refused BEFORE the callback: the marker the callback writes
                # first is proof it never ran.
                assert not marker.exists()
            else:
                assert marker.exists()
        assert memory_io == []
    finally:
        lane.store.close()
