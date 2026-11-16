"""Unit coverage for native B2B profile guards and local patch materialization.

Tests use throwaway git repositories built in tmp_path, never a provisioned
profile checkout. The real pinned sources are covered by the integration lane.
"""
from __future__ import annotations

import hashlib
import subprocess

import pytest

from tests.gateway.native_b2b import profile_fixture


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _mini_repo(path):
    path.mkdir()
    subprocess.run(["git", "init", str(path)], check=True, capture_output=True)
    (path / "marker.txt").write_text("v1\n", encoding="utf-8")
    _git(path, "add", "marker.txt")
    _git(
        path,
        "-c", "user.email=fixture@test",
        "-c", "user.name=fixture",
        "commit", "-m", "init",
    )
    head = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True).stdout.strip()
    return head


def _marker_patch(old: str, new: str) -> bytes:
    return (
        "diff --git a/marker.txt b/marker.txt\n"
        "--- a/marker.txt\n"
        "+++ b/marker.txt\n"
        "@@ -1 +1 @@\n"
        f"-{old}\n"
        f"+{new}\n"
    ).encode("utf-8")


def _configure_local_patch(monkeypatch, head: str, patch_path, payload: bytes) -> None:
    patch_path.write_bytes(payload)
    monkeypatch.setattr(profile_fixture, "PROFILE_COMMIT", head)
    monkeypatch.setattr(profile_fixture, "PATCH_FILE", patch_path)
    monkeypatch.setattr(
        profile_fixture, "PATCH_SHA256", hashlib.sha256(payload).hexdigest())


def test_wrong_git_head_rejected(tmp_path):
    source = tmp_path / "source"
    _mini_repo(source)  # HEAD is a fresh local commit, never the pin
    with pytest.raises(RuntimeError, match="not pinned"):
        profile_fixture.materialize_test_profile(
            source, tmp_path / "out", patched=False)
    assert not (tmp_path / "out").exists()


def test_patch_checksum_tampering_raises_before_clone(tmp_path, monkeypatch):
    source = tmp_path / "source"
    head = _mini_repo(source)
    monkeypatch.setattr(profile_fixture, "PROFILE_COMMIT", head)
    monkeypatch.setattr(profile_fixture, "PATCH_SHA256", "0" * 64)
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        profile_fixture.materialize_test_profile(
            source, tmp_path / "out", patched=True)
    # Failure happened before any clone/apply side effect.
    assert not (tmp_path / "out").exists()


def test_unpatched_materialization_is_a_clean_detached_pin(tmp_path, monkeypatch):
    source = tmp_path / "source"
    head = _mini_repo(source)
    monkeypatch.setattr(profile_fixture, "PROFILE_COMMIT", head)
    out = profile_fixture.materialize_test_profile(
        source, tmp_path / "out", patched=False)
    head_out = subprocess.run(
        ["git", "-C", str(out), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True).stdout.strip()
    assert head_out == head
    status = subprocess.run(
        ["git", "-C", str(out), "status", "--porcelain"],
        check=True, capture_output=True, text=True).stdout
    assert status == ""
    assert (out / "marker.txt").read_text(encoding="utf-8") == "v1\n"


def test_dirty_tracked_tree_rejected(tmp_path, monkeypatch):
    source = tmp_path / "source"
    head = _mini_repo(source)
    monkeypatch.setattr(profile_fixture, "PROFILE_COMMIT", head)
    (source / "marker.txt").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="tracked modifications"):
        profile_fixture.materialize_test_profile(
            source, tmp_path / "out", patched=False)
    assert not (tmp_path / "out").exists()


def test_local_patch_applies_to_a_clean_pinned_clone(tmp_path, monkeypatch):
    source = tmp_path / "source"
    head = _mini_repo(source)
    patch = _marker_patch("v1", "v2")
    _configure_local_patch(monkeypatch, head, tmp_path / "local.patch", patch)

    out = profile_fixture.materialize_test_profile(
        source, tmp_path / "out", patched=True)

    assert (source / "marker.txt").read_text(encoding="utf-8") == "v1\n"
    assert subprocess.run(
        ["git", "-C", str(source), "status", "--porcelain"],
        check=True, capture_output=True, text=True,
    ).stdout == ""
    head_out = subprocess.run(
        ["git", "-C", str(out), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert head_out == head
    assert (out / "marker.txt").read_text(encoding="utf-8") == "v2\n"
    assert "marker.txt" in subprocess.run(
        ["git", "-C", str(out), "status", "--porcelain"],
        check=True, capture_output=True, text=True,
    ).stdout


def test_nonapplicable_local_patch_fails_check_without_partial_apply(
        tmp_path, monkeypatch):
    source = tmp_path / "source"
    head = _mini_repo(source)
    patch = _marker_patch("not-v1", "v2")
    _configure_local_patch(monkeypatch, head, tmp_path / "local.patch", patch)

    with pytest.raises(RuntimeError, match="git apply --check failed"):
        profile_fixture.materialize_test_profile(source, tmp_path / "out", patched=True)

    out = tmp_path / "out"
    assert (source / "marker.txt").read_text(encoding="utf-8") == "v1\n"
    assert (out / "marker.txt").read_text(encoding="utf-8") == "v1\n"
    assert subprocess.run(
        ["git", "-C", str(source), "status", "--porcelain"],
        check=True, capture_output=True, text=True,
    ).stdout == ""
    assert subprocess.run(
        ["git", "-C", str(out), "status", "--porcelain"],
        check=True, capture_output=True, text=True,
    ).stdout == ""
