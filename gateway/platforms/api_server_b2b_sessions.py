"""B2B-protected session filtering for ``GET /api/sessions`` (KOT-263 H1).

Owns the reserved-namespace filter the generic listing applies ONLY when the
B2B lane is enabled: with ``b2b.enabled`` off the handler issues the plain
native ``list_sessions_rich`` call and this module is never touched.
"""

from typing import Any

from agent.b2b_execution import is_b2b_session_id

_CHUNK = 200


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
        sid = str(sid or "")
        verdict = ancestor_cache.get(sid)
        if verdict is not None:
            return verdict
        if is_b2b_session_id(sid):
            ancestor_cache[sid] = True
            return True
        current, seen = sid, set()
        for _ in range(64):
            if current in seen:
                verdict = True  # cycle in lineage -- fail closed
                break
            seen.add(current)
            cached = ancestor_cache.get(current)
            if cached is not None:
                verdict = cached
                break
            try:
                row = db.get_session(current)
            except Exception:
                verdict = True  # lookup error -- fail closed
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
        else:
            verdict = True  # >64 ancestors -- fail closed
        for cached_id in seen:
            ancestor_cache[cached_id] = verdict
        ancestor_cache[sid] = verdict
        return verdict

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
