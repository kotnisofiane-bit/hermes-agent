"""B2B-protected session resolution + listing filter for generic surfaces.

``resolve_generic_session_id`` is the single validation seam every generic
session-addressing route funnels through. ``list_b2b_filtered_sessions``
back-fills ``GET /api/sessions`` rows on the enabled lane; both share the one
``_protected_lineage`` ancestor walk. ``get_reserved_genesis_session`` owns the
single reserved-id GET exception — an empty, unbound L2a genesis row.
"""

import asyncio
from typing import Any

from agent.b2b_execution import is_b2b_session_id
from gateway.platforms.api_server_b2b import (
    _deny, _state_for, guarded_session_id)

_CHUNK = 200


def _protected_lineage(db: Any, session_id: Any, ancestor_cache: dict) -> bool:
    """True when sid is itself reserved OR any ancestor is. Only ever invoked
    on the enabled lane, so cycles and lookup errors fail closed; a missing
    ordinary ancestor stops the walk (ordinary) and a finite ordinary chain of
    any depth is admitted. The whole-chain verdict is cached per call."""
    sid = str(session_id or "")
    verdict = ancestor_cache.get(sid)
    if verdict is not None:
        return verdict
    if is_b2b_session_id(sid):
        ancestor_cache[sid] = True
        return True
    current, seen = sid, set()
    while True:
        if current in seen:
            verdict = True  # cycle in lineage — fail closed
            break
        seen.add(current)
        cached = ancestor_cache.get(current)
        if cached is not None:
            verdict = cached
            break
        try:
            row = db.get_session(current)
        except Exception:
            verdict = True  # lookup error — fail closed
            break
        if not row:
            verdict = False  # missing ordinary ancestor
            break
        parent = row.get("parent_session_id")
        if not parent:
            verdict = False
            break
        if is_b2b_session_id(parent):
            verdict = True
            break
        current = str(parent)
    for cached_id in seen:
        ancestor_cache[cached_id] = verdict
    ancestor_cache[sid] = verdict
    return verdict


async def resolve_generic_session_id(adapter: Any, session_id: Any, *,
                                     db: Any = None, resolve_tip: bool = False,
                                     fail_open: bool = True):
    """Central generic-session validation seam.

    Returns ``(selected_id, None)`` to proceed or ``(None, error_response)``.
    The cheap ``guarded_session_id`` prefix check runs in every mode and
    retains reserved-ID denials even when the lane is off.

    Disabled or absent: ``resolve_tip=False`` returns the raw id with zero
    ancestry/resolver work. ``resolve_tip=True`` runs only the native
    ``resolve_resume_session_id`` that lane already needed; ``fail_open``
    controls only this native resolver-error handling (True = the
    preexisting fail-open-to-original contract, False = let the resolver
    exception propagate like a raw native call). No ancestry check ever runs
    on this lane.

    Enabled: obtain the session DB when not supplied; missing DB or
    lookup/resolver errors fail closed 404. Both the requested id's AND the
    resolved tip's ancestry are walked, so neither direction can be aliased
    by the resolver. ``resolve_tip=False`` returns the original id (native
    selection semantics); ``resolve_tip=True`` returns the already-checked
    tip so no second unguarded resolution runs after the seam.
    """
    sid, err = guarded_session_id(adapter, session_id)
    if err is not None:
        return None, err
    state = _state_for(adapter)
    if state is None or not getattr(state.config, "enabled", False):
        if not resolve_tip:
            return sid, None
        if db is None:
            db = await adapter._ensure_session_db_async()
        resolver = getattr(db, "resolve_resume_session_id", None) if db is not None else None
        tip = sid
        if callable(resolver):
            try:
                resolved = await asyncio.to_thread(resolver, sid)
                tip = str(resolved) if resolved else sid
            except Exception:
                if not fail_open:
                    raise  # native strict contract (e.g. /messages)
                tip = sid
        tip, err = guarded_session_id(adapter, tip)
        if err is not None:
            return None, err
        return tip, None
    if db is None:
        db = await adapter._ensure_session_db_async()
    if db is None:
        return None, _deny(404, "not_found")  # enabled but no store — fail closed
    resolver = getattr(db, "resolve_resume_session_id", None)

    def _resolve_and_check() -> tuple:
        # Tip resolution + both ancestor chains as ONE worker-thread unit.
        tip = sid
        if callable(resolver):
            resolved = resolver(sid)  # raises -> outer except -> fail closed
            tip = str(resolved) if resolved else sid
        cache: dict = {}
        if _protected_lineage(db, sid, cache):
            return tip, True
        if tip != sid and _protected_lineage(db, tip, cache):
            return tip, True
        return tip, False

    try:
        tip, protected = await asyncio.to_thread(_resolve_and_check)
    except Exception:
        return None, _deny(404, "not_found")  # lookup/resolver error — fail closed
    if protected:
        return None, _deny(404, "not_found")
    return (tip if resolve_tip else sid), None


def list_b2b_filtered_sessions(db: Any, *, source, limit: int, offset: int,
                               include_children: bool, title_filter,
                               include_hidden: bool) -> list:
    """``/api/sessions`` rows with every protected row removed BEFORE the
    visible offset/limit is counted -- a post-limit filter would produce
    missing/duplicated ordinary pages.

    Bounded scan: raw chunks (``project_compression_tips=False`` so the cursor
    counts RAW rows, not the projected window), native projection applied per
    chunk, then protected ids filtered; stops once ``offset + limit`` visible
    rows are collected or raw rows are exhausted. Pins ride the same native
    back-fill, protected pins dropped, native pin order preserved. ``limit=0``
    keeps native pin-only behavior -- no scan at all.
    """
    ancestor_cache: dict = {}

    def _is_protected_id(sid: Any) -> bool:
        """True when sid itself is reserved OR any ancestor chain reaches a
        reserved row (a grandparent can be protected, not just the immediate
        parent). Whole-chain verdicts cached per id; missing rows are
        ordinary; errors fail closed."""
        return _protected_lineage(db, sid, ancestor_cache)

    def _row_protected(row: dict) -> bool:
        if _is_protected_id(row.get("id")):
            return True
        lineage = row.get("_lineage_ids") or ()
        return any(_is_protected_id(x) for x in lineage)

    visible: list = []
    if limit > 0:
        cursor = 0
        while len(visible) < offset + limit:
            chunk = db.list_sessions_rich(
                source=source, limit=_CHUNK, offset=cursor,
                include_children=include_children, order_by_last_active=True,
                include_pinned=False, search_query=title_filter,
                include_hidden=include_hidden,
                project_compression_tips=False)
            if not chunk:
                break
            cursor += len(chunk)  # RAW row count -- never the projected window
            projected = (db._project_compression_tips(chunk, False)
                         if not include_children else chunk)
            visible.extend(s for s in projected if not _row_protected(s))
            if len(chunk) < _CHUNK:
                break
    # Pin backfill rides its own native call (include_pinned=True); protected
    # pins are dropped, native pin order preserved.
    pins = db.list_sessions_rich(
        source=source, limit=0, offset=0, include_children=include_children,
        order_by_last_active=True, include_pinned=True,
        search_query=title_filter, include_hidden=include_hidden)
    pins = [p for p in pins if p.get("pinned") and not _row_protected(p)]
    page = visible[offset:offset + limit] if limit else []
    seen = {s.get("id") for s in page}
    return page + [p for p in pins if p.get("id") not in seen]


async def list_generic_sessions(adapter: Any, db: Any, *, source, limit: int,
                                offset: int, include_children: bool, title_filter,
                                include_hidden: bool) -> list:
    """``GET /api/sessions`` row source of truth. Absent/disabled lane: the
    ONE native ``list_sessions_rich`` call this surface always made — the
    caller's own offset/limit, pins back-filled, zero ancestry work. Enabled:
    the protected-lineage filtered scan in ``list_b2b_filtered_sessions``.
    Exact-title filtering stays the caller's job."""
    state = _state_for(adapter)
    if state is None or not getattr(state.config, "enabled", False):
        # include_pinned back-fills pins past the recency window; search_query pushes the
        # title needle into SQL (substring) so a hidden/old row is found, exact match above.
        return await asyncio.to_thread(
            db.list_sessions_rich, source=source, limit=limit, offset=offset,
            include_children=include_children, order_by_last_active=True, include_pinned=True,
            search_query=title_filter, include_hidden=include_hidden)
    # Reserved-namespace rows must be excluded BEFORE the visible offset/limit
    # is counted — a post-limit filter produces missing/duplicated ordinary pages.
    return await asyncio.to_thread(
        list_b2b_filtered_sessions, db, source=source, limit=limit,
        offset=offset, include_children=include_children,
        title_filter=title_filter, include_hidden=include_hidden)


def validate_genesis_creation(adapter: Any, body: Any, raw_id: Any, session_id: str):
    """``POST /api/sessions`` reserved-namespace gate -> ``(session_id, error)``.

    Non-reserved ids return unchanged with zero work — the cheap namespace
    contract holds on EVERY lane, disabled included. The ONLY generic create on
    the reserved namespace is EXACTLY ``{"id": <b2b_…>, "source": "api_server"}``
    — the literal id string, mandatory source, no alias and no other key (even
    null) — under a real configured API key.
    """
    from agent.b2b_execution import is_b2b_session_id
    if not (is_b2b_session_id(session_id) or is_b2b_session_id(raw_id)):
        return session_id, None
    exact = (set(body.keys()) == {"id", "source"}
             and body.get("source") == "api_server"
             and is_b2b_session_id(body.get("id"))
             and adapter._expected_api_key())
    if not exact:
        from gateway.platforms.api_server import _error_response
        return None, _error_response(
            "B2B namespace sessions accept closed genesis creation only",
            400, code="invalid_session_id")
    return str(body["id"]), None  # exact, no strip/alias/normalize


def guard_fork_destination(adapter: Any, fork_id: Any):
    """``POST /api/sessions/{id}/fork`` destination gate -> error or ``None``.
    A reserved ``b2b_`` fork id is a not-found on every lane — cheap namespace
    contract, no state/store work."""
    from agent.b2b_execution import is_b2b_session_id
    if is_b2b_session_id(fork_id):
        from gateway.platforms.api_server import _error_response
        return _error_response(
            f"Session not found: {fork_id}", 404, code="session_not_found")
    return None


async def resolve_internal_wake_session(adapter: Any, session_id: Any):
    """In-process ``gateway.wake`` session resolution -> the selected tip id,
    or the same native ``RuntimeError`` the generic site raised on a protected
    refusal. The seam keeps tip resolution + lineage on both directions."""
    resolved, guard_err = await resolve_generic_session_id(
        adapter, session_id, resolve_tip=True)
    if guard_err is not None:
        raise RuntimeError("internal wake refused for a protected B2B session")
    return resolved


async def resolve_history_session(adapter: Any, session_id: Any, db: Any = None):
    """History-path session resolution -> the validated id, or raises the
    native ``RuntimeError`` the facade's history loader always raised on a
    guarded refusal. The seam keeps its own gating semantics."""
    resolved, guard_err = await resolve_generic_session_id(
        adapter, session_id, db=db)
    if guard_err is not None:
        raise RuntimeError("protected B2B session history request refused")
    return resolved


async def get_generic_session(adapter: Any, session_id: Any):
    """``GET /api/sessions/{id}`` orchestration: ordinary ids take the native
    ``_get_existing_session_or_404`` + exact response; a reserved id's only
    generic exception (empty unbound L2a genesis) lives in
    ``get_reserved_genesis_session`` — disabled lanes included."""
    _sid, guard_err = guarded_session_id(adapter, session_id)
    if guard_err is None:
        session, err = await adapter._get_existing_session_or_404(session_id)
        if err:
            return err
        from aiohttp import web
        return web.json_response(
            {"object": "hermes.session", "session": adapter._session_response(session)})
    return await get_reserved_genesis_session(adapter, session_id, guard_err)


async def get_reserved_genesis_session(adapter: Any, session_id: Any, guard_err: Any):
    """Reserved ``b2b_`` id: the ONE generic exception is an exact GET of a
    demonstrably EMPTY, UNBOUND L2a genesis row (pre-binding only) under a REAL
    native key and a durable store. Anything else — auth-disabled,
    missing/durable-less store, bound row under ANY profile, non-empty session —
    is the caller's plain 404 ``guard_err``. No writes. Called only after
    ``guarded_session_id`` already denied the id."""
    from aiohttp import web
    from gateway.platforms.api_server import _api_request_profile
    from gateway.platforms.api_server_b2b import _genesis_vs_native, _store_durable
    if not adapter._expected_api_key():
        return guard_err
    db = await adapter._ensure_session_db_async()
    if db is None:
        return adapter._session_db_unavailable()
    store = getattr(adapter, "_run_idempotency_store", None)
    if not _store_durable(store):
        return guard_err
    session = await asyncio.to_thread(db.get_session, session_id)
    if not _genesis_vs_native(session or {}, session_id,
                              _api_request_profile.get() or "default"):
        return guard_err
    try:
        if store.b2b_binding(session_id=session_id) is not None:
            return guard_err
    except Exception:
        return guard_err  # fail closed on lookup error
    return web.json_response(
        {"object": "hermes.session", "session": adapter._session_response(session)})
