"""Tests for the ``all-checks-pass`` gate job in .github/workflows/ci.yaml.

The gate's decision logic lives inline in the workflow's ``run: |`` block:
keeping it under ``.github/`` means every change is classified
``ci_review`` and blocks on the ``ci-reviewed`` label. These tests replay
that exact step — the YAML is parsed, the step's ``run`` block is executed
by bash with a synthetic ``NEEDS`` payload shaped like
``${{ toJSON(needs) }}`` — so what is verified here is what CI actually
runs, not a reimplementation of it.

Rule under test: the gate is green only when every required job reports
``success``. ``skipped`` is accepted solely for jobs whose lane gate
(their ``if:`` in ci.yaml) legitimately lets them not run; ``failure``
and ``cancelled`` always fail the gate. Regression coverage for run
44619994684, where cancelled required suites still produced a green gate.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

_CI_YAML = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yaml"


def _jobs() -> dict:
    doc = yaml.safe_load(_CI_YAML.read_text(encoding="utf-8"))
    return doc["jobs"]


def _gate_needs() -> list[str]:
    """Job ids the gate consumes — the ``needs:`` list of all-checks-pass."""
    return list(_jobs()["all-checks-pass"]["needs"])


def _required_jobs() -> list[str]:
    """Needs entries with no ``if:`` — they run on every event, so a
    ``skipped`` result can never be legitimate for them."""
    jobs = _jobs()
    return [name for name in _gate_needs() if "if" not in jobs[name]]


def _gated_jobs() -> list[str]:
    """Needs entries gated by an ``if:`` — ``skipped`` is the declared,
    legitimate outcome when their lane doesn't apply."""
    jobs = _jobs()
    return [name for name in _gate_needs() if "if" in jobs[name]]


def _needs(overrides: dict[str, str] | None = None) -> dict:
    """Build a ``toJSON(needs)``-shaped payload: ``{job: {result, outputs}}``."""
    overrides = overrides or {}
    return {
        name: {"result": overrides.get(name, "success"), "outputs": {}}
        for name in _gate_needs()
    }


@pytest.fixture(scope="module")
def evaluate_run() -> str:
    """The literal ``run`` script of the gate's evaluate step."""
    step = next(
        s for s in _jobs()["all-checks-pass"]["steps"] if s.get("id") == "evaluate"
    )
    return step["run"]


def _run_gate(
    evaluate_run: str, needs: dict, tmp_path: Path
) -> tuple[subprocess.CompletedProcess, str]:
    """Execute the step's ``run`` block exactly as Actions does: written to
    a script file, run under bash, NEEDS + GITHUB_OUTPUT in the env.
    Returns (process result, contents of the GITHUB_OUTPUT file)."""
    run_file = tmp_path / "step.sh"
    run_file.write_text(evaluate_run, encoding="utf-8")
    out_file = tmp_path / "github_output"
    env = {
        **os.environ,
        "NEEDS": json.dumps(needs),
        "GITHUB_OUTPUT": str(out_file),
    }
    proc = subprocess.run(
        ["bash", str(run_file)], env=env, capture_output=True, text=True
    )
    gh_out = out_file.read_text(encoding="utf-8") if out_file.exists() else ""
    return proc, gh_out


# ---------------------------------------------------------------------------
# The five contract cases
# ---------------------------------------------------------------------------


def test_all_success_is_green(evaluate_run, tmp_path):
    proc, _ = _run_gate(evaluate_run, _needs(), tmp_path)
    assert proc.returncode == 0, proc.stderr + proc.stdout


def test_failure_is_red(evaluate_run, tmp_path):
    proc, _ = _run_gate(evaluate_run, _needs({"tests": "failure"}), tmp_path)
    assert proc.returncode != 0
    assert "::error::" in proc.stdout
    assert "tests" in proc.stdout


def test_cancelled_is_red(evaluate_run, tmp_path):
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
    )
    assert proc.returncode != 0
    assert "::error::" in proc.stdout


def test_declared_skip_is_green(evaluate_run, tmp_path):
    """Every lane-gated job skipped (its declared ``if:`` didn't match) —
    e.g. a docs-only PR — must not block the gate."""
    proc, _ = _run_gate(
        evaluate_run, _needs({name: "skipped" for name in _gated_jobs()}), tmp_path
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout


@pytest.mark.parametrize("job", ["detect", "case-collision-check", "profile-artifact-check"])
def test_undeclared_skip_is_red(evaluate_run, tmp_path, job):
    """A job with no lane gate can only be skipped by an upstream
    cancellation/failure — that is never a green outcome."""
    assert job in _required_jobs(), f"{job} unexpectedly gained an `if:` gate"
    proc, _ = _run_gate(evaluate_run, _needs({job: "skipped"}), tmp_path)
    assert proc.returncode != 0
    assert "::error::" in proc.stdout


# ---------------------------------------------------------------------------
# Sweep: no non-success/non-declared-skip result may pass, on any job
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("job", _gate_needs())
@pytest.mark.parametrize("result", ["failure", "cancelled"])
def test_bad_result_always_red(evaluate_run, tmp_path, job, result):
    proc, _ = _run_gate(evaluate_run, _needs({job: result}), tmp_path)
    assert proc.returncode != 0, f"{job}={result} must fail the gate"


@pytest.mark.parametrize("job", _gate_needs())
def test_skip_policy_per_job(evaluate_run, tmp_path, job):
    """skipped passes iff the job has a declared lane gate in ci.yaml."""
    proc, _ = _run_gate(evaluate_run, _needs({job: "skipped"}), tmp_path)
    if job in _required_jobs():
        assert proc.returncode != 0, f"required job {job} skipped must fail"
    else:
        assert proc.returncode == 0, f"gated job {job} skipped must pass"


def test_needs_json_output_still_emitted(evaluate_run, tmp_path):
    """The compact needs-json GITHUB_OUTPUT feeds the live comment poller —
    the fix must not break that contract."""
    proc, gh_out = _run_gate(evaluate_run, _needs({"tests": "skipped"}), tmp_path)
    assert proc.returncode == 0
    line = next(l for l in gh_out.splitlines() if l.startswith("needs-json="))
    compact = json.loads(line.removeprefix("needs-json="))
    assert compact["tests"] == "skipped"
    assert compact["detect"] == "success"
