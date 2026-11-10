"""B2B-protected session resolution + listing filter for generic surfaces.

``resolve_generic_session_id`` is the single validation seam every generic
session-addressing route funnels through. ``list_b2b_filtered_sessions``
back-fills ``GET /api/sessions`` rows on the enabled lane; both share the one
``_protected_lineage`` ancestor walk.
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
