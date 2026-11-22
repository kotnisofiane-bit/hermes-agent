"""Tests for the ``all-checks-pass`` gate job in .github/workflows/ci.yaml.

The gate's decision logic lives inline in the workflow's ``run: |`` block:
keeping it under ``.github/`` means every change is classified
``ci_review`` by the change detector and the ``review-labels`` job asks for
a maintainer-applied ``ci-reviewed`` label on the PR. That label is still
produced by the PR-controlled workflow, so it is not independent proof of
review — the workflow does not claim otherwise. These tests
replay that exact step — the YAML is parsed, the step's ``run`` block is
executed by bash with a synthetic ``NEEDS`` payload shaped like
``${{ toJSON(needs) }}`` plus the ``LANE_*`` env values GitHub's
expression engine would emit — so what is verified here is what CI
actually runs, not a reimplementation of it.

Rule under test: the gate is green only when every job that ran reports
``success``. ``skipped`` is accepted solely when that job's own ``if:``
lane evaluated false for the event — the workflow re-evaluates each
lane-gated job's condition into ``LANE_<job>`` env vars, and this test
asserts those env expressions textually equal the jobs' ``if:``
conditions. ``failure`` and ``cancelled`` always fail the gate.
Regression coverage for run 44619994684, where cancelled required
suites still produced a green gate.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import yaml

_CI_YAML = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yaml"

_LANE_PREFIX = "LANE_"


def _jobs() -> dict:
    doc = yaml.safe_load(_CI_YAML.read_text(encoding="utf-8"))
    return doc["jobs"]


def _job_needs(name: str) -> list[str]:
    needs = _jobs()[name].get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def _gate_needs() -> list[str]:
    """Job ids the gate consumes — the ``needs:`` list of all-checks-pass."""
    return _job_needs("all-checks-pass")


def _downstream_of_gate() -> set[str]:
    """Jobs that (transitively) need the gate — e.g. ci-timings. They run
    after it and can never be part of its ``needs``."""
    jobs = _jobs()
    seen: set[str] = set()
    frontier = {"all-checks-pass"}
    while frontier:
        nxt = {
            name
            for name in jobs
            if name not in seen and set(_job_needs(name)) & frontier
        }
        seen |= nxt
        frontier = nxt
    return seen


def _gated_jobs() -> list[str]:
    """Needs entries gated by an ``if:`` — ``skipped`` is legitimate only
    when that lane evaluated false for the event."""
    jobs = _jobs()
    return [name for name in _gate_needs() if "if" in jobs[name]]


def _lane_key(job: str) -> str:
    """Job id → its ``LANE_<job>`` env var name."""
    return _LANE_PREFIX + job.upper().replace("-", "_")


def _lane_job(key: str) -> str:
    """``LANE_<job>`` env var → job id — the same decode the step's
    ``run`` block performs."""
    return key[len(_LANE_PREFIX):].lower().replace("_", "-")


def _expr_text(value) -> str:
    """Expression text of a YAML value: unwraps ``${{ ... }}`` and
    normalises YAML booleans to their GitHub expression spelling."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    text = str(value).strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    return text


def _needs(overrides: dict[str, str] | None = None) -> dict:
    """Build a ``toJSON(needs)``-shaped payload: ``{job: {result, outputs}}``."""
    overrides = overrides or {}
    return {
        name: {"result": overrides.get(name, "success"), "outputs": {}}
        for name in _gate_needs()
    }


@pytest.fixture(scope="module")
def evaluate_step() -> dict:
    """The gate's evaluate step, as parsed from ci.yaml."""
    return next(
        s for s in _jobs()["all-checks-pass"]["steps"] if s.get("id") == "evaluate"
    )


@pytest.fixture(scope="module")
def evaluate_run(evaluate_step) -> str:
    """The literal ``run`` script of the gate's evaluate step."""
    return evaluate_step["run"]


def _lanes(
    evaluate_step: dict,
    open_jobs: set[str] | frozenset[str] | None = None,
) -> dict[str, str]:
    """``LANE_*`` env values as GitHub's expression engine would emit
    them: ``'true'`` for the jobs in ``open_jobs``, ``'false'`` for the
    others. An empty ``open_jobs`` means every lane is closed."""
    open_jobs = open_jobs or set()
    return {
        key: ("true" if _lane_job(key) in open_jobs else "false")
        for key in evaluate_step["env"]
        if key.startswith(_LANE_PREFIX)
    }


def _run_gate(
    evaluate_run: str,
    needs: dict,
    tmp_path: Path,
    lanes: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess, str]:
    """Execute the step's ``run`` block exactly as Actions does: written to
    a script file, run under bash, NEEDS + LANE_* + GITHUB_OUTPUT in the
    env. Returns (process result, contents of the GITHUB_OUTPUT file)."""
    run_file = tmp_path / "step.sh"
    run_file.write_text(evaluate_run, encoding="utf-8")
    out_file = tmp_path / "github_output"
    env = {
        **os.environ,
        "NEEDS": json.dumps(needs),
        "GITHUB_OUTPUT": str(out_file),
        **(lanes or {}),
    }
    proc = subprocess.run(
        ["bash", str(run_file)], env=env, capture_output=True, text=True
    )
    gh_out = out_file.read_text(encoding="utf-8") if out_file.exists() else ""
    return proc, gh_out


@dataclass(frozen=True)
class GateCase:
    """One replayed gate payload: result overrides, lane state, expectation."""

    id: str
    overrides: dict[str, str] = field(default_factory=dict)
    open_lanes: frozenset[str] = frozenset()
    lane_values: dict[str, str] = field(default_factory=dict)
    ok: bool = True
    details: tuple[str, ...] = ()


def _acceptance_cases() -> list:
    """Full acceptance matrix: every job × bad result, every gated job's
    closed-lane skip, every open-lane skip, and the malformed lane values."""
    needs = _gate_needs()
    gated = _gated_jobs()
    cases = [
        GateCase("all-success-closed"),
        GateCase(
            "all-success-open",
            open_lanes=frozenset(n for n in needs if n != "e2e-desktop"),
        ),
        GateCase(
            "all-gated-skipped-closed",
            overrides={job: "skipped" for job in gated},
        ),
        GateCase(
            "multi-cancelled",
            overrides={
                "tests": "cancelled",
                "tests-os": "cancelled",
                "e2e-desktop-core": "cancelled",
            },
            ok=False,
            details=(
                "e2e-desktop-core=cancelled",
                "tests=cancelled",
                "tests-os=cancelled",
            ),
        ),
    ]
    for job in needs:
        for result in ("failure", "cancelled"):
            cases.append(
                GateCase(
                    f"{result}-{job}",
                    overrides={job: result},
                    ok=False,
                    details=(f"{job}={result}",),
                )
            )
    for job in gated:
        cases.append(GateCase(f"skip-closed-{job}", overrides={job: "skipped"}))
    for job in needs:
        if job == "e2e-desktop":
            continue
        cases.append(
            GateCase(
                f"skip-open-{job}",
                overrides={job: "skipped"},
                open_lanes=frozenset({job}),
                ok=False,
                details=(f"{job}=skipped (lane open)",),
            )
        )
    for label, value in (
        ("empty", ""),
        ("0", "0"),
        ("False", "False"),
        ("closed", "closed"),
    ):
        cases.append(
            GateCase(
                f"lane-value-{label}",
                overrides={"tests": "skipped"},
                lane_values={"LANE_TESTS": value},
                ok=False,
                details=("tests=skipped (lane open)",),
            )
        )
    return [pytest.param(case, id=case.id) for case in cases]


@pytest.mark.parametrize("case", _acceptance_cases())
def test_gate_acceptance_by_lane(evaluate_run, evaluate_step, tmp_path, case):
    """Green exactly for ``success`` and for ``skipped`` on a lane whose env
    value is the literal ``false``; ``failure`` and ``cancelled`` are red on
    every job. Each run emits ``needs-json`` and each rejected check is named
    on an ``::error::`` line."""
    lanes = _lanes(evaluate_step, case.open_lanes)
    lanes.update(case.lane_values)
    needs = _needs(case.overrides)
    proc, gh_out = _run_gate(evaluate_run, needs, tmp_path, lanes=lanes)
    if case.ok:
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert "All checks passed (skips only on closed lanes)" in proc.stdout
    else:
        assert proc.returncode != 0
        assert "::error::" in proc.stdout
        for detail in case.details:
            assert detail in proc.stdout, proc.stdout
    line = next(l for l in gh_out.splitlines() if l.startswith("needs-json="))
    assert json.loads(line.removeprefix("needs-json=")) == {
        name: info["result"] for name, info in needs.items()
    }


@pytest.mark.parametrize("job", [name for name in _jobs() if name != "all-checks-pass"])
def test_gate_wiring_matches_jobs(evaluate_step, job):
    """Every upstream job is in the gate's ``needs`` (unless it runs after
    the gate), each lane-gated job has a ``LANE_<job>`` Actions expression
    equal to its own ``if:``, and ungated jobs carry no lane."""
    jobs = _jobs()
    raw_lanes = {
        key: value
        for key, value in evaluate_step["env"].items()
        if key.startswith(_LANE_PREFIX)
    }
    assert set(_gate_needs()) == set(jobs) - {"all-checks-pass"} - _downstream_of_gate()
    assert {_lane_job(key) for key in raw_lanes} == set(_gated_jobs())
    key = _lane_key(job)
    if job in _downstream_of_gate():
        assert job not in _gate_needs()
        assert key not in raw_lanes
        return
    assert job in _gate_needs()
    if "if" not in jobs[job]:
        assert key not in raw_lanes
        return
    assert key in raw_lanes
    raw = raw_lanes[key]
    assert (
        isinstance(raw, str)
        and raw.strip().startswith("${{")
        and raw.strip().endswith("}}")
    ), (
        f"{key} must be an Actions expression (``${{{{ ... }}}}``), "
        f"got {raw!r} — a literal is not evaluated by Actions and the "
        "gate would read it as a closed lane"
    )
    job_if = _expr_text(jobs[job]["if"]).removeprefix("always() &&").strip()
    assert _expr_text(raw) == job_if, (
        f"{key} re-evaluates {_expr_text(raw)!r} but the job's ``if:`` is {job_if!r}"
    )
