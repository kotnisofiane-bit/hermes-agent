"""Unit coverage for the native B2B profile materializer.

These tests only exercise guard behaviour on throwaway git repos built in
tmp_path. They never read a provisioned profile checkout: the real pinned
sources are covered by the integration lane itself.
"""
from __future__ import annotations

import subprocess

import pytest

from tests.gateway.native_b2b import profile_fixture


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _mini_repo(path):
    path.mkdir()
    subprocess.run(["git", "init", str(path)], check=True, capture_output=True)
    _git(path, "config", "user.email", "fixture@test")
    _git(path, "config", "user.name", "fixture")
    (path / "marker.txt").write_text("v1\n", encoding="utf-8")
    _git(path, "add", "marker.txt")
    _git(path, "commit", "-m", "init")
    head = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True).stdout.strip()
    return head


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
