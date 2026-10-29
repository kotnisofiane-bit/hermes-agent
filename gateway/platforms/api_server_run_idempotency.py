"""Durable idempotency reservations for API server runs."""

import hashlib
import hmac
import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from agent.b2b_execution import json_utf8, source_basis
from hermes_cli.sqlite_util import add_column_if_missing


# Keep the extracted store's log records on the API server logger.
logger = logging.getLogger("gateway.platforms.api_server")

TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled", "interrupted"})
B2B_ARTIFACT_KINDS = frozenset({
    "source_bind", "source_before_provider", "context", "provider_dispatch",
    "provider_result", "source_before_seal", "context_recheck", "proposal"})

_SELECT_BY_KEY = (
    "SELECT fingerprint, run_id, status_json, owner_pid, owner_started, updated_at "
    "FROM run_idempotency WHERE scope=? AND idempotency_key=?")
_EXTEND_RETENTION_BY_KEY = (
    "UPDATE run_idempotency SET retention_until=MAX(retention_until, ?) "
    "WHERE scope=? AND idempotency_key=? AND fingerprint=?")
_EXTEND_RETENTION_BY_RUN = (
    "UPDATE run_idempotency SET retention_until=MAX(retention_until, ?) "
    "WHERE scope=? AND run_id=?")
# Columns added after the first schema shipped; applied when missing.
_MIGRATIONS = {
    "owner_pid": "INTEGER NOT NULL DEFAULT 0",
    "owner_started": "INTEGER NOT NULL DEFAULT 0",
    "retention_until": "REAL NOT NULL DEFAULT 0",
    "acknowledged_at": "REAL"}


def _encode_status(status: Dict[str, Any]) -> str:
    return json.dumps(status, sort_keys=True, separators=(",", ":"))


def _record(run_id, status_json, owner_pid, owner_started, updated_at) -> dict[str, Any]:
    return {
        "run_id": run_id, "status": json.loads(status_json), "owner_pid": int(owner_pid or 0),
        "owner_started": int(owner_started or 0), "updated_at": float(updated_at or 0)}


def _outcome(row, fingerprint):
    """Classify a stored ``(scope, key)`` row against the caller's fingerprint."""
    return ("reused" if hmac.compare_digest(row[0], fingerprint) else "conflict"), _record(*row[1:])


class RunIdempotencyStore:
    """Durable, tenant-scoped reservations for ``POST /v1/runs``: a unique ``(scope, key)`` row
    inserted inside ``BEGIN IMMEDIATE`` so separate workers cannot both admit one request. Only
    fingerprints and public run status are stored — never request bodies or credentials."""

    RETENTION_SECONDS = 24 * 60 * 60
    ACKNOWLEDGED_RETENTION_SECONDS = 24 * 60 * 60

    @property
    def durable(self) -> bool:
        """Whether reservations survive this process."""
        return self._db_path is not None
    def __init__(self, db_path: str = None):
        if db_path is None:
            try:
                from hermes_cli.config import get_hermes_home
                db_path = str(get_hermes_home() / "runs_idempotency.db")
            except Exception:
                db_path = ":memory:"
        self._db_path = None if db_path == ":memory:" else db_path
        try:
            self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        except Exception as exc:
            # Docker may create the container object before `docker run` fails to start it (e.g. exit code
            # 125 when the daemon isn't ready, or a timeout mid-pull). That orphan is left in "Created"
            # state — which the exited-only orphan reaper (reap_orphan_containers, status=exited) never
            # catches, so it leaks permanently. Remove it by its known name before re-raising. See #7439.
            logger.warning(
                "Run idempotency storage is unavailable; falling back to "
                "process memory, so replay will not survive a restart: %s", exc)
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._db_path = None
        from hermes_state_wal import apply_wal_with_fallback
        apply_wal_with_fallback(self._conn, db_label="runs_idempotency.db")
        # Row factory: positional indexes still work; b2b_* readers also need column names.
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS run_idempotency (
                scope TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                run_id TEXT NOT NULL,
                status_json TEXT NOT NULL,
                owner_pid INTEGER NOT NULL DEFAULT 0,
                owner_started INTEGER NOT NULL DEFAULT 0,
                retention_until REAL NOT NULL DEFAULT 0,
                acknowledged_at REAL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (scope, idempotency_key)
            )"""
        )
        columns = {str(row[1]) for row in self._conn.execute("PRAGMA table_info(run_idempotency)")}
        for column, ddl in _MIGRATIONS.items():
            if column not in columns:
                add_column_if_missing(self._conn, "run_idempotency", column, f"{column} {ddl}")
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS run_idempotency_run_id ON run_idempotency(run_id)")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS b2b_bindings (
                session_id TEXT NOT NULL,
                binding_digest TEXT NOT NULL,
                profile TEXT NOT NULL,
                policy_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (profile, session_id),
                UNIQUE (profile, binding_digest))""")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS b2b_attempts (
                attempt_id TEXT NOT NULL,
                profile TEXT NOT NULL,
                session_id TEXT NOT NULL,
                binding_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                run_id TEXT,
                source_bind TEXT,
                source_before_provider TEXT,
                source_before_seal TEXT,
                public_result TEXT,
                requester_id TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (profile, attempt_id))""")
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS b2b_attempts_session "
            "ON b2b_attempts(profile, session_id)")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS b2b_artifacts (
                attempt_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                digest TEXT NOT NULL,
                view TEXT,
                rendered TEXT,
                payload BLOB,
                created_at REAL NOT NULL,
                PRIMARY KEY (attempt_id, kind))""")
        add_column_if_missing(self._conn, "b2b_artifacts", "payload", "payload BLOB")
        self._conn.commit()
        self._lock = threading.Lock()
        self._tighten_permissions()

    def _tighten_permissions(self) -> None:
        for suffix in ("", "-wal", "-shm") if self._db_path else ():
            candidate = Path(self._db_path + suffix)
            try:
                if candidate.exists():
                    candidate.chmod(0o600)
            except OSError:
                logger.debug("Failed to restrict run idempotency store permissions", exc_info=True)

    @contextmanager
    def _immediate_txn(self):
        """Hold the lock inside ``BEGIN IMMEDIATE``; the body commits, errors roll back."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except Exception:
                self._conn.rollback()
                raise

    def reserve(self, scope: str, key: str, fingerprint: str, run_id: str, status: Dict[str, Any], *,
                owner_pid: int = 0, owner_started: int = 0, retention_until: float = 0):
        """Atomically reserve a key; return ``(outcome, stored_record)``."""
        now = time.time()
        with self._immediate_txn():
            self._prune_stale_terminal_locked(now)
            result = self._reserve_locked(
                scope, key, fingerprint, run_id, status, owner_pid=owner_pid,
                owner_started=owner_started, retention_until=retention_until, now=now)
            self._conn.commit()
            return result

    def _reserve_locked(self, scope: str, key: str, fingerprint: str, run_id: str,
                        status: Dict[str, Any], *, owner_pid: int = 0, owner_started: int = 0,
                        retention_until: float = 0, now: Optional[float] = None):
        """Same atomic reserve as ``reserve()`` but callable INSIDE a larger
        ``_immediate_txn`` so a B2B binding+attempt+run lands as one logical commit."""
        now = time.time() if now is None else now
        retention_until = max(0.0, float(retention_until or 0))
        row = self._conn.execute(_SELECT_BY_KEY, (scope, key)).fetchone()
        if row is not None:
            if retention_until:
                self._conn.execute(_EXTEND_RETENTION_BY_KEY, (retention_until, scope, key, fingerprint))
            return _outcome(row, fingerprint)
        encoded = _encode_status(status)
        self._conn.execute(
            "INSERT INTO run_idempotency("
            "scope,idempotency_key,fingerprint,run_id,status_json,"
            "owner_pid,owner_started,retention_until,created_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,?)",
            (scope, key, fingerprint, run_id, encoded, int(owner_pid or 0), int(owner_started or 0),
             retention_until, now, now))
        return "created", _record(run_id, encoded, owner_pid, owner_started, now) | {"status": status}

    def lookup(self, scope: str, key: str, fingerprint: str, *, retention_until: float = 0):
        """Return ``missing``, ``reused`` or ``conflict`` without reserving."""
        now = time.time()
        retention_until = max(0.0, float(retention_until or 0))
        with self._immediate_txn():
            if retention_until:
                self._conn.execute(_EXTEND_RETENTION_BY_KEY, (retention_until, scope, key, fingerprint))
            self._prune_stale_terminal_locked(now)
            row = self._conn.execute(_SELECT_BY_KEY, (scope, key)).fetchone()
            self._conn.commit()
        return ("missing", None) if row is None else _outcome(row, fingerprint)

    def _prune_stale_terminal_locked(self, now: float) -> None:
        """Prune aged replay records only once their stored run is terminal (caller holds the
        lock + transaction): a long or disconnected room turn may outlive the retention window."""
        stale = self._conn.execute(
            """SELECT scope, idempotency_key, status_json
                 FROM run_idempotency r
                WHERE (acknowledged_at <= ?
                   OR (retention_until > 0 AND retention_until <= ?)
                   OR (retention_until <= 0 AND updated_at < ?))
                  AND NOT EXISTS (
                        SELECT 1 FROM b2b_attempts a WHERE a.run_id = r.run_id)""",
            (now - self.ACKNOWLEDGED_RETENTION_SECONDS, now, now - self.RETENTION_SECONDS),
        ).fetchall()
        for stale_scope, stale_key, stale_status in stale:
            try:
                terminal = json.loads(stale_status).get("status") in TERMINAL_STATUSES
            except Exception:
                terminal = False
            if terminal:
                self._conn.execute(
                    "DELETE FROM run_idempotency WHERE scope=? AND idempotency_key=?", (stale_scope, stale_key))

    def status_for_run(self, scope: str, run_id: str, *, retention_until: float = 0) -> dict[str, Any] | None:
        """Load one durable run status inside its authenticated scope."""
        retention_until = max(0.0, float(retention_until or 0))
        with self._lock:
            if retention_until:
                self._conn.execute(_EXTEND_RETENTION_BY_RUN, (retention_until, scope, run_id))
                self._conn.commit()
            row = self._conn.execute(
                "SELECT status_json, owner_pid, owner_started, updated_at "
                "FROM run_idempotency WHERE scope=? AND run_id=?",
                (scope, run_id)).fetchone()
        if row is None:
            return None
        return {k: v for k, v in _record(None, *row).items() if k != "run_id"}

    def extend_retention(self, scope: str, run_id: str, until: float) -> bool:
        """Persist the latest verified recovery horizon for an active grant."""
        checked_until = max(0.0, float(until or 0))
        if not checked_until:
            return False
        with self._lock:
            changed = self._conn.execute(_EXTEND_RETENTION_BY_RUN, (checked_until, scope, run_id)).rowcount
            self._conn.commit()
        return changed == 1

    def owns_run(self, scope: str, run_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM run_idempotency WHERE scope=? AND run_id=?", (scope, run_id)).fetchone()
        return row is not None

    def update_status(self, run_id: str, status: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE run_idempotency SET status_json=?, updated_at=? WHERE run_id=?",
                (_encode_status(status), time.time(), run_id))
            self._conn.commit()

    # -- B2B governed lanes -------------------------------------------------

    def b2b_admit(self, *, profile: str, session_id: str, binding_digest: str,
                  attempt_id: str, fingerprint: str, binding_row: Dict[str, Any],
                  attempt_row: Dict[str, Any],
                  run_scope: str, run_key: str, run_id: str, run_fingerprint: str,
                  run_status: Dict[str, Any],
                  owner_pid: int = 0, owner_started: int = 0) -> Dict[str, Any]:
        """Atomic binding+attempt+run reservation in ONE BEGIN IMMEDIATE. Returns
        ``{"status": "admitted"|"replayed"|"conflict"}`` plus the stored rows; a replay
        returns the durable run identity so the POST surfaces the SAME run_id."""
        if (not self.durable or not run_scope.startswith("b2b:") or
                run_key != attempt_id or run_fingerprint != fingerprint or
                run_status.get("session_id") != session_id or not run_id or
                any(attempt_row.get(key) != value for key, value in
                    (("profile", profile), ("session_id", session_id),
                     ("binding_digest", binding_digest), ("attempt_id", attempt_id),
                     ("run_id", run_id), ("status", "admitted"))) or
                any(binding_row.get(key) != value for key, value in
                    (("profile", profile), ("session_id", session_id),
                     ("binding_digest", binding_digest)))):
            raise ValueError("b2b_admission_invalid")
        source_payload = attempt_row["source_bind"]
        if isinstance(source_payload, str):
            source_payload = source_payload.encode("utf-8")
        now = time.time()
        with self._immediate_txn():
            existing = self._conn.execute(
                "SELECT binding_digest, policy_json FROM b2b_bindings WHERE profile=? AND session_id=?",
                (profile, session_id)).fetchone()
            if existing is not None and (
                    existing["binding_digest"] != binding_digest or
                    existing["policy_json"] != binding_row["policy_json"]):
                self._conn.rollback()
                return {"status": "conflict"}
            row = self._conn.execute(
                "SELECT * FROM b2b_attempts WHERE profile=? AND attempt_id=?",
                (profile, attempt_id)).fetchone()
            if row is not None:
                if row["session_id"] != session_id or row["binding_digest"] != binding_digest or \
                        row["fingerprint"] != fingerprint:
                    self._conn.rollback()
                    return {"status": "conflict"}
                native = self._conn.execute(
                    _SELECT_BY_KEY, (run_scope, run_key)).fetchone()
                if (native is None or native["run_id"] != row["run_id"] or
                        native["fingerprint"] != fingerprint or existing is None):
                    self._conn.rollback()
                    return {"status": "conflict"}
                self._conn.commit()
                return {"status": "replayed", "attempt": dict(row), "run_id": row["run_id"]}
            out, rec = self._reserve_locked(
                run_scope, run_key, run_fingerprint, run_id, run_status,
                owner_pid=owner_pid, owner_started=owner_started, now=now)
            if out != "created" or rec["run_id"] != run_id:
                self._conn.rollback()
                return {"status": "conflict"}
            if existing is None:
                self._conn.execute(
                    "INSERT INTO b2b_bindings(session_id,binding_digest,profile,policy_json,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (session_id, binding_digest, profile, binding_row["policy_json"], now))
            self._conn.execute(
                "INSERT INTO b2b_attempts(attempt_id,profile,session_id,binding_digest,status,"
                "fingerprint,run_id,source_bind,requester_id,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (attempt_id, profile, session_id, binding_digest,
                 attempt_row["status"], fingerprint, run_id,
                 source_payload.decode("utf-8"), attempt_row["requester_id"], now, now))
            self._b2b_put_artifact_locked(attempt_id, "source_bind", source_payload, now)
            self._conn.commit()
        return {"status": "admitted", "run_id": run_id}

    def b2b_attempt(self, *, profile: str, attempt_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM b2b_attempts WHERE profile=? AND attempt_id=?",
                (profile, attempt_id)).fetchone()
        return dict(row) if row else None

    def b2b_binding(self, *, session_id: str,
                    profile: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with self._lock:
            if profile is None:
                row = self._conn.execute(
                    "SELECT * FROM b2b_bindings WHERE session_id=? LIMIT 1", (session_id,)).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT * FROM b2b_bindings WHERE profile=? AND session_id=?",
                    (profile, session_id)).fetchone()
        return dict(row) if row else None

    def b2b_artifact(self, *, attempt_id: str, kind: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._b2b_artifact_locked(attempt_id, kind)

    @staticmethod
    def _b2b_payload(payload: bytes) -> Dict[str, Any]:
        if not isinstance(payload, bytes) or not payload or len(payload) > 262144:
            raise ValueError("b2b_artifact_bounds")
        value = json.loads(payload.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("b2b_artifact_shape")
        return value

    def _b2b_artifact_locked(self, attempt_id: str, kind: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT attempt_id,kind,digest,payload,created_at FROM b2b_artifacts "
            "WHERE attempt_id=? AND kind=?", (attempt_id, kind)).fetchone()
        if row is None:
            return None
        result = dict(row)
        payload = result["payload"]
        if not isinstance(payload, bytes) or hashlib.sha256(payload).hexdigest() != result["digest"]:
            raise ValueError("b2b_artifact_integrity")
        return result

    def _b2b_put_artifact_locked(self, attempt_id: str, kind: str, payload: bytes, now: float):
        if kind not in B2B_ARTIFACT_KINDS:
            raise ValueError("b2b_artifact_kind")
        self._b2b_payload(payload)
        old = self._b2b_artifact_locked(attempt_id, kind)
        if old is not None:
            if old["payload"] != payload:
                raise ValueError("b2b_artifact_conflict")
            return False
        self._conn.execute(
            "INSERT INTO b2b_artifacts(attempt_id,kind,digest,payload,created_at) VALUES(?,?,?,?,?)",
            (attempt_id, kind, hashlib.sha256(payload).hexdigest(), sqlite3.Binary(payload), now))
        return True

    def _b2b_attempt_locked(self, profile: str, attempt_id: str):
        return self._conn.execute(
            "SELECT * FROM b2b_attempts WHERE profile=? AND attempt_id=?",
            (profile, attempt_id)).fetchone()

    def b2b_commit_context(self, *, profile: str, attempt_id: str, payload: bytes) -> bool:
        with self._immediate_txn():
            row = self._b2b_attempt_locked(profile, attempt_id)
            if row is None or row["status"] not in ("admitted", "context_ready"):
                self._conn.rollback()
                return False
            value = self._b2b_payload(payload)
            if value.get("attempt_id") != attempt_id or value.get("run_id") != row["run_id"]:
                raise ValueError("b2b_context_identity")
            changed = self._b2b_put_artifact_locked(attempt_id, "context", payload, time.time())
            if changed:
                self._conn.execute(
                    "UPDATE b2b_attempts SET status='context_ready',updated_at=? "
                    "WHERE profile=? AND attempt_id=?", (time.time(), profile, attempt_id))
            self._conn.commit()
            return True

    def b2b_cas_dispatch(self, *, profile: str, attempt_id: str,
                         source_record: bytes, dispatch_record: bytes) -> bool:
        """Commit source proof + dispatch marker before the only possible physical send."""
        with self._immediate_txn():
            row = self._b2b_attempt_locked(profile, attempt_id)
            if row is None or row["status"] not in ("admitted", "context_ready"):
                self._conn.rollback()
                return False
            context = self._b2b_artifact_locked(attempt_id, "context")
            dispatch = self._b2b_payload(dispatch_record)
            if (context is None or dispatch.get("attempt_id") != attempt_id or
                    dispatch.get("run_id") != row["run_id"] or
                    dispatch.get("binding_digest") != row["binding_digest"]):
                raise ValueError("b2b_dispatch_identity")
            captured = self._b2b_payload(context["payload"])
            if (dispatch.get("context_digest") != captured.get("context_digest") or
                    dispatch.get("source_basis_digest") != captured.get("source_basis_digest")):
                raise ValueError("b2b_dispatch_context")
            now = time.time()
            self._b2b_put_artifact_locked(attempt_id, "source_before_provider", source_record, now)
            self._b2b_put_artifact_locked(attempt_id, "provider_dispatch", dispatch_record, now)
            self._conn.execute(
                "UPDATE b2b_attempts SET status='dispatch_committed',source_before_provider=?,updated_at=? "
                "WHERE profile=? AND attempt_id=?",
                (source_record.decode("utf-8"), now, profile, attempt_id))
            self._conn.commit()
        return True

    def b2b_commit_result(self, *, profile: str, attempt_id: str, payload: bytes) -> bool:
        """Only the authorized worker may commit a result for its durable request marker."""
        with self._immediate_txn():
            row = self._b2b_attempt_locked(profile, attempt_id)
            if row is None:
                self._conn.rollback()
                return False
            value = self._b2b_payload(payload)
            marker = self._b2b_artifact_locked(attempt_id, "provider_dispatch")
            dispatch = self._b2b_payload(marker["payload"]) if marker else {}
            if (not marker or value.get("attempt_id") != attempt_id or
                    value.get("run_id") != row["run_id"] or
                    value.get("binding_digest") != row["binding_digest"] or
                    value.get("request_digest") != dispatch.get("request_digest") or
                    value.get("context_digest") != dispatch.get("context_digest")):
                raise ValueError("b2b_result_request_mismatch")
            old = self._b2b_artifact_locked(attempt_id, "provider_result")
            if old is not None:
                if old["payload"] != payload:
                    raise ValueError("b2b_artifact_conflict")
                self._conn.commit()
                return True
            if row["status"] != "dispatch_committed":
                self._conn.rollback()
                return False
            now = time.time()
            self._b2b_put_artifact_locked(attempt_id, "provider_result", payload, now)
            self._conn.execute(
                "UPDATE b2b_attempts SET status='result_received',public_result=?,updated_at=? "
                "WHERE profile=? AND attempt_id=?",
                (json.dumps(value["proposal"], ensure_ascii=False, sort_keys=True,
                            separators=(",", ":"), allow_nan=False), now, profile, attempt_id))
            self._conn.commit()
            return True

    def b2b_seal(self, *, profile: str, attempt_id: str,
                  artifacts: Dict[str, bytes]) -> Optional[bytes]:
        if set(artifacts) != {"source_before_seal", "context_recheck", "proposal"}:
            raise ValueError("b2b_seal_artifacts")
        with self._immediate_txn():
            row = self._b2b_attempt_locked(profile, attempt_id)
            if row is None:
                self._conn.rollback()
                return None
            if row["status"] == "proposal_ready":
                old = self._b2b_artifact_locked(attempt_id, "proposal")
                self._conn.commit()
                return old["payload"] if old else None
            if row["status"] != "result_received":
                self._conn.rollback()
                return None
            proposal = self._b2b_payload(artifacts["proposal"])
            result = self._b2b_artifact_locked(attempt_id, "provider_result")
            context = self._b2b_artifact_locked(attempt_id, "context")
            recheck = self._b2b_payload(artifacts["context_recheck"])
            if (result is None or context is None or
                    proposal.get("attempt_id") != attempt_id or
                    recheck.get("run_id") != row["run_id"] or
                    proposal.get("binding_digest") != row["binding_digest"]):
                raise ValueError("b2b_seal_identity")
            received = self._b2b_payload(result["payload"])
            original = self._b2b_payload(context["payload"])
            # Recompute from both durable views; a copied digest is not a recheck.
            orig_view, recheck_view = original.get("view"), recheck.get("view")
            if not isinstance(orig_view, dict) or not isinstance(recheck_view, dict):
                raise ValueError("b2b_seal_context")
            orig_basis = json_utf8(source_basis(orig_view))
            recheck_basis = json_utf8(source_basis(recheck_view))
            if (orig_basis != recheck_basis or
                    hashlib.sha256(orig_basis).hexdigest() != original.get("source_basis_digest") or
                    hashlib.sha256(recheck_basis).hexdigest() != recheck.get("source_basis_digest")):
                raise ValueError("b2b_seal_context")
            if (proposal.get("context_digest") != original.get("context_digest") or
                    any(proposal.get(key) != received["proposal"].get(key) for key in
                        ("summary", "steps", "source_refs", "limitations"))):
                raise ValueError("b2b_seal_result")
            now = time.time()
            for kind, payload in artifacts.items():
                self._b2b_put_artifact_locked(attempt_id, kind, payload, now)
            self._conn.execute(
                "UPDATE b2b_attempts SET status='proposal_ready',source_before_seal=?,updated_at=? "
                "WHERE profile=? AND attempt_id=?",
                (artifacts["source_before_seal"].decode("utf-8"), now, profile, attempt_id))
            self._conn.commit()
            return artifacts["proposal"]

    def b2b_is_run(self, run_id: str) -> bool:
        with self._lock:
            return self._conn.execute(
                "SELECT 1 FROM b2b_attempts WHERE run_id=?", (run_id,)).fetchone() is not None

    def b2b_snapshot(self, *, profile: str, attempt_id: str) -> Optional[Dict[str, Any]]:
        """A consistent, read-only projection; no native hydration, pruning or lease renewal."""
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                row = self._conn.execute(
                    "SELECT a.*,r.status_json AS native_status_json,r.owner_pid,r.owner_started "
                    "FROM b2b_attempts a JOIN run_idempotency r ON r.run_id=a.run_id "
                    "WHERE a.profile=? AND a.attempt_id=?", (profile, attempt_id)).fetchone()
                if row is None:
                    self._conn.commit()
                    return None
                kinds = self._conn.execute(
                    "SELECT kind FROM b2b_artifacts WHERE attempt_id=? ORDER BY kind",
                    (attempt_id,)).fetchall()
                artifacts = {item["kind"]: self._b2b_artifact_locked(attempt_id, item["kind"])
                             for item in kinds}
                self._conn.commit()
                return {"attempt": dict(row), "artifacts": artifacts}
            except Exception:
                self._conn.rollback()
                raise

    def b2b_update_attempt(self, *, profile: str, attempt_id: str, **fields: Any) -> None:
        if not fields:
            return
        status = fields.get("status")
        allowed = {"context_unavailable", "context_stale", "source_denied", "policy_changed",
                   "result_invalid", "failed", "interrupted", "indeterminate"}
        if set(fields) != {"status"} or status not in allowed:
            raise ValueError("b2b_status_transition")
        with self._immediate_txn():
            row = self._b2b_attempt_locked(profile, attempt_id)
            if row is None or row["status"] not in (
                    "admitted", "context_ready", "dispatch_committed", "result_received"):
                self._conn.commit()
                return
            self._conn.execute(
                "UPDATE b2b_attempts SET status=?,updated_at=? WHERE profile=? AND attempt_id=?",
                (status, time.time(), profile, attempt_id))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
