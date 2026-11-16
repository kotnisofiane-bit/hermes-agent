"""Versioned prepare_context patch materialization for the native B2B lane.

The producer profile is pinned at ``PROFILE_COMMIT``. The shipped pin does
NOT register ``prepare_context``; the native lane needs it, so a versioned
test-only patch (``dubsar-hermes-profile-prepare-context.patch``, SHA-256
pinned below) is verified byte-for-byte and applied to a local clone of the
pinned checkout — never to the provisioned source, which is only ever read.

The patch is a reconstruction authored for this harness. It does not claim
or certify equality with any historical patch produced outside this lot.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess

PROFILE_COMMIT = "05d7394c78f9761f1d4c6f2d4805e6e9a0042e18"
PATCH_FILE = Path(__file__).with_name("dubsar-hermes-profile-prepare-context.patch")
PATCH_SHA256 = "a5d90e16b0af9012a1db8bff21b6f80bc461f343f6db1ec4b2f43b063bec6fff"
_GIT_TIMEOUT_S = 60


def _git(*args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], input=input_bytes, capture_output=True, timeout=_GIT_TIMEOUT_S)


def _patch_bytes() -> bytes:
    payload = PATCH_FILE.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != PATCH_SHA256:
        raise RuntimeError(
            "prepare-context patch checksum mismatch: "
            f"{digest} != {PATCH_SHA256} (file tampered or re-generated?)")
    return payload


def _checked(proc: subprocess.CompletedProcess, what: str) -> str:
    if proc.returncode != 0:
        raise RuntimeError(f"{what} failed: {proc.stderr.decode('utf-8', 'replace').strip()}")
    return proc.stdout.decode("utf-8", "replace")


def materialize_test_profile(source, destination, *, patched: bool) -> Path:
    """Clone the pinned profile into ``destination``, optionally patched.

    ``source`` must be a git checkout whose HEAD is exactly ``PROFILE_COMMIT``
    with a clean tracked tree. The destination is a fresh local ``--shared``
    clone checked out detached at the pin; ``patched=True`` additionally
    verifies the patch SHA-256 and applies it with ``git apply``. The source
    is never written and a pre-patched source is never trusted.
    """
    source = Path(source)
    destination = Path(destination)
    head = _git("-C", str(source), "rev-parse", "HEAD")
    if head.returncode != 0 or _checked(head, "git rev-parse").strip() != PROFILE_COMMIT:
        raise RuntimeError(f"profile source {source} is not pinned at {PROFILE_COMMIT}")
    status = _git("-C", str(source), "status", "--porcelain", "--untracked-files=no")
    if status.returncode != 0 or _checked(status, "git status").strip():
        raise RuntimeError(f"profile source {source} has tracked modifications")
    payload = _patch_bytes() if patched else None
    _checked(_git("clone", "--shared", "--no-checkout", str(source), str(destination)),
             "git clone")
    _checked(_git("-C", str(destination), "checkout", "--detach", PROFILE_COMMIT),
             "git checkout")
    if payload is not None:
        _checked(_git("-C", str(destination), "apply", "--check", "-",
                      input_bytes=payload), "git apply --check")
        _checked(_git("-C", str(destination), "apply", "-", input_bytes=payload),
                 "git apply")
    return destination
