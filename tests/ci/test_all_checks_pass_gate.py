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


def _required_jobs() -> list[str]:
    """Needs entries with no ``if:`` — they run on every event, so a
    ``skipped`` result can never be legitimate for them."""
    jobs = _jobs()
    return [name for name in _gate_needs() if "if" not in jobs[name]]


def _gated_jobs() -> list[str]:
    """Needs entries gated by an ``if:`` — ``skipped`` is legitimate only
    when that lane evaluated false for the event."""
    jobs = _jobs()
    return [name for name in _gate_needs() if "if" in jobs[name]]


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


def _lanes(evaluate_step: dict, open_jobs: set[str] | None = None) -> dict[str, str]:
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


# ---------------------------------------------------------------------------
# Structure contracts: the gate sees every job, and each lane condition is
# the job's own ``if:`` — not a parallel copy by name.
# ---------------------------------------------------------------------------


def test_workflow_does_not_claim_branch_protection_sufficiency():
    """The workflow file and its classifier are themselves PR-controlled, so
    a status produced by this workflow cannot prove an independent review.
    The YAML must not recommend requiring only this check."""
    text = _CI_YAML.read_text(encoding="utf-8").lower()
    assert "branch protection should require only this check" not in text
    assert "branch protection only needs to require a single check" not in text


def test_gate_needs_cover_every_upstream_job():
    """Every job in the file is either in the gate's ``needs``, the gate
    itself, or a job that (transitively) needs the gate (e.g. ci-timings)
    and therefore cannot be."""
    covered = set(_gate_needs())
    expected = set(_jobs()) - {"all-checks-pass"} - _downstream_of_gate()
    assert covered == expected, (
        f"gate needs mismatch — missing: {sorted(expected - covered)}, "
        f"unexpected: {sorted(covered - expected)}"
    )


def test_lane_env_mirrors_job_conditions(evaluate_step):
    """Each lane-gated needs entry has a ``LANE_<job>`` env on the step
    whose expression textually equals that job's ``if:`` — a leading
    ``always() &&`` is scheduling-only and is expected to be dropped.
    No ungated job may carry a LANE_ var."""
    jobs = _jobs()
    raw_lanes = {
        key: value
        for key, value in evaluate_step["env"].items()
        if key.startswith(_LANE_PREFIX)
    }
    for key, raw in raw_lanes.items():
        is_expression = (
            isinstance(raw, str)
            and raw.strip().startswith("${{")
            and raw.strip().endswith("}}")
        )
        assert is_expression, (
            f"{key} must be an Actions expression (``${{{{ ... }}}}``), "
            f"got {raw!r} — a literal is not evaluated by Actions and the "
            "gate would read it as a closed lane"
        )
    lanes = {key: _expr_text(value) for key, value in raw_lanes.items()}
    assert {_lane_job(key) for key in lanes} == set(_gated_jobs()), (
        "LANE_* env vars must exist exactly for the needs entries that "
        "carry an ``if:`` gate"
    )
    for key, expr in lanes.items():
        job_if = _expr_text(jobs[_lane_job(key)]["if"])
        job_if = job_if.removeprefix("always() &&").strip()
        assert expr == job_if, (
            f"{key} re-evaluates {expr!r} but the job's ``if:`` is {job_if!r}"
        )


# ---------------------------------------------------------------------------
# The five contract cases
# ---------------------------------------------------------------------------


def test_all_success_is_green(evaluate_run, evaluate_step, tmp_path):
    proc, _ = _run_gate(
        evaluate_run, _needs(), tmp_path, lanes=_lanes(evaluate_step)
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout


def test_failure_is_red(evaluate_run, evaluate_step, tmp_path):
    proc, _ = _run_gate(
        evaluate_run,
        _needs({"tests": "failure"}),
        tmp_path,
        lanes=_lanes(evaluate_step),
    )
    assert proc.returncode != 0
    assert "::error::" in proc.stdout
    assert "tests" in proc.stdout


def test_cancelled_is_red(evaluate_run, evaluate_step, tmp_path):
    """Regression: run 44619994684 — tests, tests-os and e2e-desktop-core
    were cancelled yet the gate reported green."""
    proc, _ = _run_gate(
        evaluate_run,
        _needs(
            {
                "tests": "cancelled",
                "tests-os": "cancelled",
                "e2e-desktop-core": "cancelled",
            }
        ),
        tmp_path,
        lanes=_lanes(evaluate_step),
    )
    assert proc.returncode != 0
    assert "::error::" in proc.stdout


def test_skip_on_closed_lanes_is_green(evaluate_run, evaluate_step, tmp_path):
    """Synthetic payload: every lane-gated job is skipped and every lane
    evaluates false. This is not a real event (``history-check`` is open on
    every PR); it isolates the gate's declared-skip branch."""
    proc, _ = _run_gate(
        evaluate_run,
        _needs({name: "skipped" for name in _gated_jobs()}),
        tmp_path,
        lanes=_lanes(evaluate_step),
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout


def test_history_check_skipped_on_pr_is_red(evaluate_run, evaluate_step, tmp_path):
    """On a pull_request, history-check's lane is open — a ``skipped``
    result there is illegitimate and must fail the gate."""
    proc, _ = _run_gate(
        evaluate_run,
        _needs({"history-check": "skipped"}),
        tmp_path,
        lanes=_lanes(evaluate_step, {"history-check"}),
    )
    assert proc.returncode != 0
    assert "::error::" in proc.stdout
    assert "history-check=skipped (lane open)" in proc.stdout


# ---------------------------------------------------------------------------
# Sweep: bad results always fail; a skip is green iff its lane was closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("job", _gate_needs())
@pytest.mark.parametrize("result", ["failure", "cancelled"])
def test_bad_result_always_red(evaluate_run, evaluate_step, tmp_path, job, result):
    proc, _ = _run_gate(
        evaluate_run,
        _needs({job: result}),
        tmp_path,
        lanes=_lanes(evaluate_step),
    )
    assert proc.returncode != 0, f"{job}={result} must fail the gate"
    assert "::error::" in proc.stdout
    assert f"{job}={result}" in proc.stdout


@pytest.mark.parametrize("job", _gated_jobs())
def test_skip_on_closed_lane_is_green(evaluate_run, evaluate_step, tmp_path, job):
    proc, _ = _run_gate(
        evaluate_run,
        _needs({job: "skipped"}),
        tmp_path,
        lanes=_lanes(evaluate_step),
    )
    assert proc.returncode == 0, f"{job} skipped on a closed lane must pass"


@pytest.mark.parametrize("job", [n for n in _gate_needs() if n != "e2e-desktop"])
def test_skip_on_open_lane_is_red(evaluate_run, evaluate_step, tmp_path, job):
    """A skip while the job's own ``if:`` lane was open can only mean an
    upstream failure or cancellation — never green. Jobs without a lane
    gate have no LANE_ entry and are treated as always-open. e2e-desktop
    is pinned ``if: false``: its lane can never open, so it is excluded."""
    proc, _ = _run_gate(
        evaluate_run,
        _needs({job: "skipped"}),
        tmp_path,
        lanes=_lanes(evaluate_step, {job}),
    )
    assert proc.returncode != 0, f"{job} skipped on an open lane must fail"
    assert "::error::" in proc.stdout
    assert f"{job}=skipped (lane open)" in proc.stdout, proc.stdout


@pytest.mark.parametrize("lane_value", ["", "0", "False", "closed"])
def test_skip_requires_explicit_false_lane(
    evaluate_run, evaluate_step, tmp_path, lane_value
):
    """The gate consumes GitHub's evaluated env string. Only the literal
    ``false`` may close a lane; empty, truthy-ish, or arbitrary values must
    not turn a skip green."""
    lanes = _lanes(evaluate_step)
    lanes["LANE_TESTS"] = lane_value
    proc, _ = _run_gate(
        evaluate_run,
        _needs({"tests": "skipped"}),
        tmp_path,
        lanes=lanes,
    )
    assert proc.returncode != 0, (
        f"LANE_TESTS={lane_value!r} must not authorise a skipped tests job"
    )
    assert "::error::" in proc.stdout
    assert "tests=skipped (lane open)" in proc.stdout


def test_needs_json_output_still_emitted(evaluate_run, evaluate_step, tmp_path):
    """The step still emits the compact ``{job: result}`` map as its
    ``needs-json`` output — this test proves emission, nothing more."""
    proc, gh_out = _run_gate(
        evaluate_run,
        _needs({"tests": "skipped"}),
        tmp_path,
        lanes=_lanes(evaluate_step),
    )
    assert proc.returncode == 0
    line = next(l for l in gh_out.splitlines() if l.startswith("needs-json="))
    compact = json.loads(line.removeprefix("needs-json="))
    assert compact["tests"] == "skipped"
    assert compact["detect"] == "success"
