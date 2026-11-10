"""``GET /api/sessions`` + the B2B reserved-namespace listing filter.

Two contracts, one file:

* B2B disabled (no state, or ``b2b.enabled: false``): the generic listing is the
  BASELINE -- one native ``list_sessions_rich`` call carrying the caller's actual
  ``offset``/``limit``, zero per-row ``get_session`` ancestry probes, and no
  extra filtering at all (a reserved ``b2b_`` row pages through like any other).
* B2B enabled: protection moves into a dedicated sibling helper,
  ``gateway.platforms.api_server_b2b_sessions.list_b2b_filtered_sessions`` --
  reserved ids AND any row whose ancestry/compression lineage reaches one are
  dropped BEFORE the visible offset/limit is counted, pins back-fill filtered.

Real disk ``SessionDB`` + real ``APIServerAdapter``/aiohttp app; SQL call spies,
never source inspection.
"""

from __future__ import annotations

import time

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from hermes_state import SessionDB


@pytest.fixture
def opened():
    """Close every SessionDB the test registered."""
    resources = []
    yield resources
    for resource in resources:
        try:
            resource.close()
        except Exception:
            pass


def _seed(db: SessionDB, session_id: str, *, started_at: float, source: str = "api_server",
          parent: str = None, title: str = None, pinned: bool = False) -> str:
    db.create_session(session_id, source, parent_session_id=parent)
    db._write_sql(
        "UPDATE sessions SET started_at = ?, last_activity_at = ? WHERE id = ?",
        (started_at, started_at, session_id))
    if title is not None:
        db.set_session_title(session_id, title)
    if pinned:
        db.set_session_pinned(session_id, True)
    return session_id


def _app_for(adapter: APIServerAdapter) -> web.Application:
    app = web.Application()
    app.router.add_get("/api/sessions", adapter._handle_list_sessions)
    return app


async def _list(client: TestClient, **query) -> dict:
    resp = await client.get("/api/sessions", params={k: str(v) for k, v in query.items()})
    assert resp.status == 200, await resp.text()
    return await resp.json()


# ---------------------------------------------------------------------------
# Disabled = baseline
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("b2b_state", ["absent", "disabled"])
@pytest.mark.parametrize(
    ("row_count", "limit", "offset"),
    [(6, 3, 0), (215, 5, 210), (4, 0, 0)],
    ids=["small", "offset_beyond_200", "limit_zero"])
async def test_list_sessions_b2b_disabled_is_native_baseline(
        tmp_path, b2b_state, row_count, limit, offset, opened):
    """When the B2B lane is absent/disabled the handler issues exactly ONE
    ``list_sessions_rich`` with the caller's own offset/limit (no 200-row chunk
    scan), never opens per-row ``get_session`` ancestry probes, and filters
    nothing -- a reserved ``b2b_`` row is just another row."""
    db = SessionDB(tmp_path / "state.db")
    opened.append(db)
    t0 = time.time() - 100_000
    reserved = "b2b_" + "e" * 64
    for i in range(row_count):
        _seed(db, f"ord_{i:04d}", started_at=t0 + i)
    _seed(db, reserved, started_at=t0 + row_count + 1)
    _seed(db, "ord_pinned", started_at=t0 - 1, pinned=True)

    extra = {"b2b": {"enabled": False, "profiles": {}}} if b2b_state == "disabled" else {}
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra=extra))
    if b2b_state == "absent":
        adapter._b2b_state = None
    adapter._session_db = db

    rich_calls, get_session_calls = [], []
    orig_rich = db.list_sessions_rich
    orig_get = db.get_session

    def _spy_rich(*args, **kwargs):
        rich_calls.append({"args": args, "kwargs": kwargs})
        return orig_rich(*args, **kwargs)

    def _spy_get(*args, **kwargs):
        get_session_calls.append(args)
        return orig_get(*args, **kwargs)

    db.list_sessions_rich = _spy_rich
    db.get_session = _spy_get
    try:
        async with TestClient(TestServer(_app_for(adapter))) as client:
            payload = await _list(client, limit=limit, offset=offset)
        handler_get_calls = list(get_session_calls)
        get_session_calls.clear()
        baseline = orig_rich(
            source=None, limit=limit, offset=offset, include_children=False,
            order_by_last_active=True, include_pinned=True, search_query=None,
            include_hidden=False)
        baseline_get_calls = list(get_session_calls)
    finally:
        db.list_sessions_rich = orig_rich
        db.get_session = orig_get

    expected = [APIServerAdapter._session_response(s) for s in baseline]

    # One native call, carrying the caller's ACTUAL window -- never chunked from 0.
    assert len(rich_calls) == 1, rich_calls
    call = rich_calls[0]
    assert call["args"] == ()
    assert call["kwargs"]["limit"] == limit and call["kwargs"]["offset"] == offset
    assert call["kwargs"]["include_pinned"] is True
    # No per-row ancestry walk beyond what the NATIVE call itself performs --
    # identical get_session traffic as plain list_sessions_rich.
    assert handler_get_calls == baseline_get_calls
    # Identical to the raw native result -- no extra filtering (the reserved
    # row pages through whenever it falls inside the window).
    assert payload["data"] == expected
    windowed = sum(1 for s in baseline if not s.get("pinned"))
    assert payload["has_more"] == (windowed >= limit)


# ---------------------------------------------------------------------------
# Enabled: the dedicated helper owns protection
# ---------------------------------------------------------------------------

def _b2b_enabled_adapter() -> APIServerAdapter:
    from tests.gateway.b2b_process_harness import make_keypair
    _, _, portal_pub = make_keypair()
    _, hermes_priv, _ = make_keypair()
    entry = {
        "source_url": "http://127.0.0.1:1/internal/dubsar/b2b/source",
        "portal_issuer": "portal-h1", "hermes_issuer": "hermes-h1-hub",
        "portal_public_key_pem": portal_pub, "hermes_private_key_pem": hermes_priv,
        "projects": {"b2b-bench": {
            "project_id": "b2b-bench", "bot_id": "bot", "profile_id": "hub",
            "allowed_namespaces": ["ns"], "context_contract_root": None,
            "model": "unit-double", "provider": "custom",
            "base_url": "http://127.0.0.1:9/v1", "api_mode": "chat_completions",
            "logical_mission": None, "project_context": None}}}
    return APIServerAdapter(PlatformConfig(
        enabled=True, extra={"b2b": {"enabled": True, "profiles": {"hub": entry}}}))


@pytest.mark.asyncio
async def test_list_sessions_b2b_enabled_filters_reserved_and_lineage(
        tmp_path, opened):
    """Enabled lane: reserved rows and descendants/compression tips whose chain
    reaches one are removed BEFORE offset/limit -- pages stay dense, protected
    pins never back-fill, ordinary rows are untouched."""
    from gateway.platforms.api_server_b2b_sessions import (
        list_b2b_filtered_sessions)  # structural seam: dedicated sibling

    db = SessionDB(tmp_path / "state.db")
    opened.append(db)
    t0 = time.time() - 100_000
    reserved = "b2b_" + "e" * 64
    # Ordinary rows sandwiching the protected family so a post-limit filter
    # would leave a hole the dense page must not show.
    _seed(db, "ord_0", started_at=t0 + 0)
    _seed(db, "ord_1", started_at=t0 + 1)
    _seed(db, reserved, started_at=t0 + 2)
    _seed(db, "b2b_child", started_at=t0 + 3, parent=reserved)
    _seed(db, "b2b_grandchild", started_at=t0 + 4, parent="b2b_child")
    _seed(db, "ord_2", started_at=t0 + 5)
    _seed(db, "ord_3", started_at=t0 + 6)
    # Compression chain rooted on an ordinary row whose live tip is reserved:
    # the projected row carries _lineage_ids into the namespace.
    _seed(db, "comp_root", started_at=t0 + 7)
    db.end_session("comp_root", "compression")
    _seed(db, "b2b_" + "f" * 64, started_at=t0 + 8, parent="comp_root")
    _seed(db, "ord_pinned", started_at=t0 - 1, pinned=True)
    _seed(db, "b2b_pinned_child", started_at=t0 - 2, parent=reserved, pinned=True)

    rows = list_b2b_filtered_sessions(
        db, source=None, limit=50, offset=0, include_children=True,
        title_filter=None, include_hidden=False)
    ids = [r["id"] for r in rows]
    # Descendants of a reserved row are protected by the whole ancestor walk.
    assert "ord_0" in ids and "ord_1" in ids and "ord_2" in ids and "ord_3" in ids
    assert "ord_pinned" in ids  # ordinary pin still back-fills
    for protected in (reserved, "b2b_child", "b2b_grandchild",
                      "b2b_" + "f" * 64, "b2b_pinned_child"):
        assert protected not in ids, protected
    # The ordinary compression ROOT stays visible under include_children -- its
    # own row is not inside the namespace (protection walks ancestors, never
    # descendants); only its projected-tips form is filtered (next block).
    assert "comp_root" in ids

    # With children collapsed, comp_root projects to its live tip -- which IS
    # the reserved id -- so the projected row is filtered via _lineage_ids.
    collapsed = list_b2b_filtered_sessions(
        db, source=None, limit=50, offset=0, include_children=False,
        title_filter=None, include_hidden=False)
    collapsed_ids = [r["id"] for r in collapsed]
    assert "b2b_" + "f" * 64 not in collapsed_ids
    assert "comp_root" not in collapsed_ids

    # Filtering precedes the visible window: limit=2 over the same set returns
    # the two newest SURVIVING rows (comp_root's chain-effective activity is the
    # tip's), not a hole where the protected family sat.
    page = list_b2b_filtered_sessions(
        db, source=None, limit=2, offset=0, include_children=True,
        title_filter=None, include_hidden=False)
    page_ids = [r["id"] for r in page if not r.get("pinned")]
    assert page_ids == ["comp_root", "ord_3"]
    # The same page through the real handler matches (dense window + pin backfill).
    adapter = _b2b_enabled_adapter()
    adapter._session_db = db
    async with TestClient(TestServer(_app_for(adapter))) as client:
        payload = await _list(client, limit=2, offset=0, include_children=True)
    handler_ids = [s["id"] for s in payload["data"]]
    assert handler_ids == ["comp_root", "ord_3", "ord_pinned"]
    assert payload["has_more"] is True


@pytest.mark.asyncio
async def test_list_sessions_b2b_enabled_limit_zero_pins_only(tmp_path, opened):
    """``limit=0`` keeps native pin-only behaviour on the enabled lane too --
    no scan at all, protected pins still dropped."""
    from gateway.platforms.api_server_b2b_sessions import list_b2b_filtered_sessions

    db = SessionDB(tmp_path / "state.db")
    opened.append(db)
    t0 = time.time() - 100_000
    _seed(db, "ord_a", started_at=t0)
    _seed(db, "ord_pin", started_at=t0 + 1, pinned=True)
    _seed(db, "b2b_" + "d" * 64, started_at=t0 + 2, pinned=True)

    rows = list_b2b_filtered_sessions(
        db, source=None, limit=0, offset=0, include_children=False,
        title_filter=None, include_hidden=False)
    ids = [r["id"] for r in rows]
    assert "ord_pin" in ids
    assert "ord_a" not in ids  # no scan: unpinned rows never surface at limit=0
    assert "b2b_" + "d" * 64 not in ids
