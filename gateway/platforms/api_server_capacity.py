"""Profile-keyed capacity accounting for the API server — ONE shared ledger
behind the run limiter (``_concurrency_limited_response`` /
``max_concurrent_runs``) and every B2B launch's work unit.

The count that the limiter and shutdown drain read is, per canonical
``hermes_home_key``: pending request admissions + in-flight ``_run_agent``
turns + live ``/v1/runs`` tasks + live B2B :class:`LaunchWorkLease` objects.
A B2B launch occupies exactly ONE unit — its lease — from before its first
native read until its last host-created worker actually exits; tasks and
workers the lease already covers are never double-counted. Atomic
check-and-reserve (``acquire``) and every count read happen under the same
lock, so a saturated home returns the limiter's exact 429 refusal while a
sibling profile's home is judged independently.
"""

from __future__ import annotations

import asyncio
import contextvars
import threading
import weakref
from contextlib import suppress
from typing import Any, Dict, Optional, Set, Tuple


class _LeaseRef:
    """One held reference of a launch lease — release() is idempotent."""

    __slots__ = ("_lease", "_released")

    def __init__(self, lease: "LaunchWorkLease") -> None:
        self._lease = lease
        self._released = False

    def release(self) -> None:
        with self._lease._ledger.lock:
            if self._released:
                return
            self._released = True
            self._lease._drop_locked()


class LaunchWorkLease:
    """ONE capacity unit owned by ONE new B2B launch on its own home.

    ``_refs`` counts the launch handler's root hold plus every outstanding
    child reference (preparation worker, db/title ``to_thread`` workers, the
    scheduled run task, construction/recheck/hook/loader/stream workers).
    The unit is counted while ``live`` — i.e. until the LAST real worker
    finally runs, never at a caller's timeout or cancellation."""

    __slots__ = ("_ledger", "home_key", "_refs", "_live", "_root_released")

    def __init__(self, ledger: "_CapacityLedger", home_key: str) -> None:
        self._ledger = ledger
        self.home_key = home_key
        self._refs = 1  # the root hold, released by the launch handler
        self._live = True
        self._root_released = False

    @property
    def live(self) -> bool:
        return self._live

    def retain(self) -> _LeaseRef:
        """One child reference — fails only when the unit is already gone,
        which no host-created child should ever see (a parent ref outlives it)."""
        with self._ledger.lock:
            if not self._live:
                raise RuntimeError("retaining a released B2B launch lease")
            self._refs += 1
        return _LeaseRef(self)

    def release(self) -> None:
        """Release the ROOT hold (the launch handler's own). Idempotent."""
        with self._ledger.lock:
            if self._root_released:
                return
            self._root_released = True
            self._drop_locked()

    def _drop_locked(self) -> None:
        self._refs -= 1
        if self._refs <= 0:
            self._live = False
            bucket = self._ledger.leases.get(self.home_key)
            if bucket is not None:
                bucket.discard(self)
                if not bucket:
                    self._ledger.leases.pop(self.home_key, None)


class _CapacityLedger:
    """Per-adapter registry keyed by canonical ``hermes_home_key``.

    ``pending_by_home``/``inflight_by_home`` carry the provenance of legacy
    counts at creation; manually injected untracked counts fall back to the
    adapter's launch home. ``task_provenance`` maps run_id ->
    (home_key, covered-by-lease). ``leases`` holds live launch leases; a
    lease-covered task is represented by its lease, never counted twice."""

    def __init__(self, adapter: Any, launch_home_key: str) -> None:
        self.lock = threading.Lock()
        self._adapter_ref = weakref.ref(adapter)
        self.launch_home_key = launch_home_key
        self.pending_by_home: Dict[str, int] = {}
        self.inflight_by_home: Dict[str, int] = {}
        self.task_provenance: Dict[str, Tuple[str, bool]] = {}
        self.leases: Dict[str, Set[LaunchWorkLease]] = {}

    def _adapter(self) -> Any:
        return self._adapter_ref()

    # -- legacy work provenance (recorded at creation) ----------------------

    def note_pending(self, delta: int, home_key: Optional[str] = None) -> None:
        with self.lock:
            key = home_key or self.launch_home_key
            self.pending_by_home[key] = self.pending_by_home.get(key, 0) + delta

    def note_inflight(self, delta: int, home_key: Optional[str] = None) -> None:
        with self.lock:
            key = home_key or self.launch_home_key
            self.inflight_by_home[key] = self.inflight_by_home.get(key, 0) + delta

    def note_task(self, run_id: str, home_key: Optional[str], *,
                  covered: bool = False) -> None:
        with self.lock:
            self.task_provenance[run_id] = (home_key or self.launch_home_key, covered)

    def drop_task(self, run_id: str) -> None:
        with self.lock:
            self.task_provenance.pop(run_id, None)

    # -- the shared count ----------------------------------------------------

    def work_count(self, home_key: Optional[str] = None) -> int:
        with self.lock:
            return self._count_locked(home_key)

    def _count_locked(self, home_key: Optional[str]) -> int:
        adapter = self._adapter()
        pending_total = int(getattr(adapter, "_pending_agent_requests", 0) or 0)
        inflight_total = int(getattr(adapter, "_inflight_agent_runs", 0) or 0)
        tasks = getattr(adapter, "_active_run_tasks", {}) or {}
        if home_key is None:
            uncovered = sum(
                1 for run_id, task in tasks.items()
                if _live_task(task) and not self.task_provenance.get(run_id, (None, False))[1])
            return (max(0, pending_total) + max(0, inflight_total) + uncovered
                    + sum(len(bucket) for bucket in self.leases.values()))
        pending = self.pending_by_home.get(home_key, 0)
        inflight = self.inflight_by_home.get(home_key, 0)
        if home_key == self.launch_home_key:
            pending += max(0, pending_total - sum(self.pending_by_home.values()))
            inflight += max(0, inflight_total - sum(self.inflight_by_home.values()))
        tasks_here = 0
        for run_id, task in tasks.items():
            if not _live_task(task):
                continue
            provenance = self.task_provenance.get(run_id)
            task_home, covered = provenance if provenance is not None else (
                self.launch_home_key, False)
            if covered:
                continue
            if task_home == home_key:
                tasks_here += 1
        return pending + inflight + tasks_here + len(self.leases.get(home_key, ()))

    def has_lease(self, lease: Optional[LaunchWorkLease]) -> bool:
        return (lease is not None and lease.live
                and lease in self.leases.get(lease.home_key, ()))

    def saturated(self, home_key: str, *, own_lease: Optional[LaunchWorkLease],
                  limit: int) -> bool:
        """READ-ONLY saturation probe — never reserves. The caller's own live
        lease is excluded so a launch under preparation never classifies its
        own home as full — but only ON that home: a crossed bound context
        must never discount another home's count."""
        with self.lock:
            count = self._count_locked(home_key)
            if (own_lease is not None and own_lease.home_key == home_key
                    and self.has_lease(own_lease)):
                count -= 1
            return count >= limit

    def acquire(self, home_key: str):
        """Atomically check-and-reserve ONE unit on *home_key*.

        Under the same lock the shared count is read and — when it admits —
        the request's pending decorator reservation is transferred into the
        lease (no double count) and the lease is registered. Returns
        ``(lease, None)`` or ``(None, refusal_response)`` with the limiter's
        exact 429 output."""
        adapter = self._adapter()
        with self.lock:
            reservation = _own_pending_reservation()
            own_pending = 0
            if reservation is not None and reservation.get("active"):
                if (reservation.get("home_key") or self.launch_home_key) == home_key:
                    own_pending = 1
            limit = int(getattr(adapter, "_max_concurrent_runs", 0) or 0)
            if limit > 0 and (self._count_locked(home_key) - own_pending) >= limit:
                return None, adapter._concurrency_limit_response(limit)
            if reservation is not None and reservation.get("active"):
                reservation["active"] = False
                adapter._pending_agent_requests = max(
                    0, int(adapter._pending_agent_requests) - 1)
                res_home = reservation.get("home_key") or self.launch_home_key
                self.pending_by_home[res_home] = (
                    self.pending_by_home.get(res_home, 0) - 1)
            lease = LaunchWorkLease(self, home_key)
            self.leases.setdefault(home_key, set()).add(lease)
            return lease, None


def _live_task(task: Any) -> bool:
    try:
        return not task.done()
    except Exception:
        return True


def _own_pending_reservation() -> Any:
    try:
        from gateway.platforms.api_server import _api_agent_request_reservation
        return _api_agent_request_reservation.get()
    except Exception:
        return None


def capacity_home_key() -> str:
    """The ledger key for the CURRENT request scope: the ``/p/<profile>/``
    prefix's canonical home when set, else the ambient home."""
    try:
        from gateway.platforms.api_server import _api_request_profile
        profile = _api_request_profile.get()
        if profile:
            from hermes_cli.profiles import get_profile_dir
            return hermes_home_key(get_profile_dir(profile))
    except Exception:
        pass
    return hermes_home_key()


def hermes_home_key(path: Any = None) -> str:
    from hermes_constants import hermes_home_key as _key
    return _key(path)


_CAPACITY_ADAPTERS: "weakref.WeakSet[Any]" = weakref.WeakSet()
_CAPACITY_REGISTRY_LOCK = threading.Lock()


def register_adapter(adapter: Any) -> None:
    """Make an adapter's ledger visible to unscoped ``capacity_saturated``
    probes (health called without the adapter under a profile scope)."""
    with suppress(Exception):
        with _CAPACITY_REGISTRY_LOCK:
            _CAPACITY_ADAPTERS.add(adapter)


def _own_launch_lease() -> Optional[LaunchWorkLease]:
    """The calling context's own bound launch lease, when one rides this
    execution — excluded from saturation probes so a launch never diagnoses
    itself as full."""
    try:
        from agent.b2b_execution import current_launch_lease
        lease = current_launch_lease()
    except Exception:
        return None
    return lease if isinstance(lease, LaunchWorkLease) else None


def capacity_saturated(adapter: Any = None, home_key: Optional[str] = None) -> bool:
    """READ-ONLY: is the shared work ledger full for this home? No reservation,
    no discovery — the caller's own live lease is not counted against it.
    Diagnostics fail CLOSED: a probe that cannot be evaluated reports
    unavailable, never a green light it could not prove."""
    try:
        key = home_key or hermes_home_key()
    except Exception:
        return True
    own = _own_launch_lease()
    if adapter is not None:
        # An explicit adapter is probed against ITS ledger only — the same
        # accounting its own limiter reads.
        candidates = [adapter]
    else:
        with _CAPACITY_REGISTRY_LOCK:
            candidates = list(_CAPACITY_ADAPTERS)
    for candidate in candidates:
        try:
            ledger = getattr(candidate, "_capacity", None)
            if ledger is None:
                continue
            limit = int(getattr(candidate, "_max_concurrent_runs", 0) or 0)
            if limit <= 0:
                continue
            if ledger.saturated(key, own_lease=own, limit=limit):
                return True
        except Exception:
            return True
    return False


def acquire_launch_lease(adapter: Any, home_key: str):
    """Reserve ONE unit on *home_key* or return the limiter's exact refusal."""
    ledger = getattr(adapter, "_capacity", None)
    if ledger is None:
        ledger = _CapacityLedger(adapter, home_key)
        adapter._capacity = ledger
    return ledger.acquire(home_key)


class _WorkerSubmission:
    """Atomic PENDING/RUNNING/CANCELLED lifecycle for ONE executor submission
    holding counted resources (a lease ref, a worker-lifetime count).

    The submitter creates it PENDING. The worker calls :meth:`begin` as its
    first act: PENDING -> RUNNING, or False when the submission was cancelled
    while still queued — the worker MUST skip its payload because the
    canceller already released the resources (a queued-cancelled job never
    runs uncounted and never double-releases). :meth:`cancel` — awaiter
    cancellation or a failed submit — releases ONLY while PENDING; a RUNNING
    worker's resources are released exclusively by :meth:`finish` in the
    worker's real ``finally``. Exactly one release ever happens, decided by
    the lock — never by sampling an Event."""

    __slots__ = ("_lock", "_state", "_release")

    _PENDING = "pending"
    _RUNNING = "running"
    _CANCELLED = "cancelled"
    _FINISHED = "finished"

    def __init__(self, release: Any) -> None:
        self._lock = threading.Lock()
        self._state = self._PENDING
        self._release = release

    def begin(self) -> bool:
        """Worker entry: claim the submission or learn it was cancelled
        while queued (payload must be skipped — resources already freed)."""
        with self._lock:
            if self._state != self._PENDING:
                return False
            self._state = self._RUNNING
            return True

    def cancel(self) -> None:
        """Awaiter/submit-side cancellation: free the resources here only
        while the job is still queued; a started worker owns its release."""
        with self._lock:
            if self._state != self._PENDING:
                return
            self._state = self._CANCELLED
        self._release()

    def finish(self) -> None:
        """Worker real finally: only the RUNNING worker releases."""
        with self._lock:
            if self._state != self._RUNNING:
                return
            self._state = self._FINISHED
        self._release()


async def lease_to_thread(fn: Any, /, *args: Any, work_lease: Any = None, **kwargs: Any) -> Any:
    """``asyncio.to_thread`` holding a lease ref for the worker's real
    lifetime — released in the worker's own ``finally`` (cancellation of the
    awaiter cannot drop it), refunded when the submission dies before the
    worker starts. The hand-off is atomic: a cancellation that lands while
    the job is still queued frees the ref AND the queued worker skips its
    payload, so cancelled work never runs uncounted."""
    if work_lease is None:
        return await asyncio.to_thread(fn, *args, **kwargs)
    ref = work_lease.retain()
    submission = _WorkerSubmission(ref.release)

    def _wrapped() -> Any:
        if not submission.begin():
            return None
        try:
            return fn(*args, **kwargs)
        finally:
            submission.finish()

    try:
        return await asyncio.to_thread(_wrapped)
    except BaseException:
        submission.cancel()
        raise


async def run_bounded_lease_worker(work_lease: Any, fn: Any, *, deadline: float) -> Any:
    """Run ``fn`` on ONE dedicated daemon worker under the caller's copied
    context, awaited asynchronously up to *deadline* seconds.

    The worker's lease ref is released in its real ``finally`` BEFORE the
    completion is signalled, so a caller's timeout/cancellation never frees
    the unit while the worker still runs — ``asyncio.TimeoutError`` marks
    the wait, the abandoned worker keeps the unit until it exits. A thread
    start failure refunds the ref to the caller."""
    loop = asyncio.get_running_loop()
    future: "asyncio.Future[Any]" = loop.create_future()
    ref = work_lease.retain() if work_lease is not None else None
    worker_context = contextvars.copy_context()

    def _worker() -> None:
        result: Any = None
        error: Optional[BaseException] = None
        try:
            result = fn()
        except BaseException as exc:  # noqa: BLE001 -- re-raised on the awaiter
            error = exc
        finally:
            if ref is not None:
                with suppress(Exception):
                    ref.release()

        def _settle() -> None:
            if future.done():
                return  # timed out / cancelled — a late result admits nothing
            if error is None:
                future.set_result(result)
            else:
                future.set_exception(error)
        try:
            loop.call_soon_threadsafe(_settle)
        except RuntimeError:
            pass  # the loop is gone — the abandoned worker exits quietly

    try:
        threading.Thread(target=lambda: worker_context.run(_worker), daemon=True).start()
    except BaseException:
        if ref is not None:
            with suppress(Exception):
                ref.release()
        raise
    return await asyncio.wait_for(future, deadline)
