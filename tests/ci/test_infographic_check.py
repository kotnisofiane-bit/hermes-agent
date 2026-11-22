"""Tests for the committed-infographic check in
``.github/workflows/infographic-check.yml``.

The workflow is now a blocking ``needs`` entry of ``all-checks-pass``, so
its advertised ``docs/assets/`` and ``website/`` exclusions must actually be
applied before the infographic path filter. These tests extract the real
``run`` block, build a throwaway git index with the tracked files under
test, and execute that block under bash — nothing is reimplemented.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

_WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "workflows"
    / "infographic-check.yml"
)
_JOB = "check-no-committed-infographics"
_STEP_ID = "infographic-check"


def _run_script() -> str:
    doc = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    steps = doc["jobs"][_JOB]["steps"]
    return next(step for step in steps if step.get("id") == _STEP_ID)["run"]


def _tracked_repo(tmp_path: Path, paths: list[str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    for rel in paths:
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"\x89PNG\r\n\x1a\n")
        subprocess.run(["git", "add", "-f", "--", rel], cwd=repo, check=True)
    return repo


def _execute(tmp_path: Path, repo: Path) -> tuple[subprocess.CompletedProcess, str]:
    step_file = tmp_path / "step.sh"
    step_file.write_text(_run_script(), encoding="utf-8")
    output_file = tmp_path / "github_output"
    env = {**os.environ, "GITHUB_OUTPUT": str(output_file)}
    proc = subprocess.run(
        ["bash", str(step_file)],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )
    output = output_file.read_text(encoding="utf-8") if output_file.exists() else ""
    return proc, output


@pytest.mark.parametrize(
    "allowed",
    [
        "docs/assets/infographics/banner.png",
        "docs/assets/infograficos/banner.webp",
        "docs/assets/deep/infographics/banner.jpg",
        "website/infographics/banner.png",
        "website/static/infographics/banner.gif",
        "docs/assets/logo.png",
    ],
)
def test_docs_and_website_infographics_are_excluded(tmp_path, allowed):
    repo = _tracked_repo(tmp_path, [allowed])
    proc, output = _execute(tmp_path, repo)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "::notice::No committed PR-infographic images." in proc.stdout
    assert "review_status=[]" in output


@pytest.mark.parametrize(
    "offender",
    [
        "infographics/banner.png",
        "docs/infographics/banner.png",
        "docs/infograficos/banner.webp",
        "assets/infographics/banner.png",
        "docs/assets-other/infographics/banner.png",
        "website-preview/infographics/banner.png",
    ],
)
def test_infographics_outside_the_exclusions_are_rejected(tmp_path, offender):
    repo = _tracked_repo(tmp_path, [offender])
    proc, output = _execute(tmp_path, repo)
    assert proc.returncode != 0
    assert "::error::1 PR-infographic image(s) are tracked in git." in proc.stdout
    assert offender in proc.stdout
    assert "action_required" in output
