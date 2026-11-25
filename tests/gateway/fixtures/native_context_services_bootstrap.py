"""Local mission draft and session setup. Neither port is installation evidence."""
import json
import os
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
import sys
from uuid import uuid4


def draft(c):
    from scribe.core_mission_boundary import core_mission_boundary as core

    store = Path(c["dir"]) / "draft-store"
    core._MissionStore(str(store)).write_index({
        "by_project_ref": {"fixture-project": c["project_id"]}, "by_idempotency": {}})
    return core.create_mission_draft({
        "schema": core.REQUEST_SCHEMA, "contract_version": "0.1",
        "request_id": "native-draft", "project_ref": "fixture-project",
        "workspace_ref": "fixture-workspace", "objective": c["objective"],
        "session_ref": "fixture-session", "correlation_id": "fixture-context",
        "idempotency_key": "native-draft", "workspace_summary": {
            "manifest_digest": "0" * 64, "manifest_entry_count": 0, "markers": []}},
        store_dir=str(store), now=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        new_id=lambda prefix: c["mission_id"] if prefix == "mis" else f"{prefix}_{uuid4().hex}")


def session(c):
    from gateway.platforms.api_server import APIServerAdapter
    from hermes_state import SessionDB

    db = SessionDB(db_path=Path(c["dir"]) / "genesis.db")
    try:
        if c["create"]:
            db.create_session(c["id"], "api_server")
        row = db.get_session(c["id"])
        if row is None:
            return {"status": "missing"}
        return {"status": "created" if c["create"] else "found",
                "session": APIServerAdapter._session_response(row)}
    finally:
        db.close()


if __name__ == "__main__":
    if os.geteuid() == 0:
        raise SystemExit("non-root only")
    job, module_root = sys.argv[1:]
    sys.path.insert(0, str(Path(module_root).resolve(strict=True)))
    with redirect_stdout(sys.stderr):
        result = {"draft": draft, "session": session}[job](json.load(sys.stdin))
    print(json.dumps(result))
