"""Native-shaped UNIT metadata tests, not real-component/C1 evidence."""
import copy

import pytest

from agent.b2b_execution import B2BTerminalRefusal, _native_oc_read_metadata


def _ordered_read():
    instant = "2026-10-30T12:00:00.000Z"
    return {"operational_context": {
        "availability": "available", "freshness": "current", "truncated": False,
        "view": {
            "format": "dubsar.my-work-oc-context-view/2",
            "view_ref": "ocv_" + "a" * 32, "view_instant": instant,
            "bounds": {"truncated": False},
            "selection_receipt": "complete_in_authorized_selection",
            "qualification": {
                "status": "current", "freshness": "current",
                "admissibility": "limited", "agreement": "single",
                "comparability": "not_applicable",
                "limits": [{"code": "MAPPING_UNAVAILABLE"}],
            },
            "state_projection": {
                "contract": "dubsar.operational-context.state-projection/1",
                "instant": instant, "freshness": "current", "eligible": True,
                "head_complete": True, "history_truncated": False, "limits": [],
                "candidate": {"result_kind": "measured", "source_observed_at": instant},
                "age_ms": 0, "freshness_max_age_ms": 900000,
            },
        },
    }}


def test_ordered_legacy_limited_requires_current_governed_projection():
    view = _ordered_read()
    before = copy.deepcopy(view)
    assert _native_oc_read_metadata(view)[0] == "ocv_" + "a" * 32
    assert view == before


def test_legacy_limited_cannot_use_ordered_admissibility():
    view = _ordered_read()
    view["operational_context"]["view"]["format"] = "dubsar.my-work-oc-context-view/1"
    with pytest.raises(B2BTerminalRefusal, match="context_oc_unqualified"):
        _native_oc_read_metadata(view)


@pytest.mark.parametrize(("section", "key", "value"), [
    ("state_projection", "limits", [{"code": "STATE_BINDING_UNAVAILABLE"}]),
    ("state_projection", "eligible", False),
    ("state_projection", "freshness", "stale"),
    ("state_projection", "head_complete", False),
    ("state_projection", "history_truncated", True),
    ("qualification", "agreement", "conflict"),
    ("qualification", "freshness", "stale"),
    ("qualification", "admissibility", "forbidden"),
])
def test_ordered_limited_never_overrides_other_refusals(section, key, value):
    view = _ordered_read()
    view["operational_context"]["view"][section][key] = value
    with pytest.raises(B2BTerminalRefusal):
        _native_oc_read_metadata(view)


def test_ordered_candidate_must_be_a_measured_snapshot():
    view = _ordered_read()
    view["operational_context"]["view"]["state_projection"]["candidate"]["result_kind"] = "failed"
    with pytest.raises(B2BTerminalRefusal, match="context_oc_projection"):
        _native_oc_read_metadata(view)
