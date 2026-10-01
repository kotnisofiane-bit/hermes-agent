"""R0: real stdio Gateway, native approval queue and ephemeral plugin.

Only the existing synthetic agent seam replaces the unused LLM. No approval,
session, dispatch or persistence implementation is mocked; there is no business action.
"""

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

import pytest


ROOT = Path(__file__).resolve().parents[2]
PLUGIN = '''
import asyncio
import json
from gateway.session_context import get_session_env
from hermes_state import SessionDB
from tools.approval import request_tool_approval
from tools.approval_context import get_current_session_key

def inspect_context():
    return {
        "approval_key": get_current_session_key(),
        "session_key": get_session_env("HERMES_SESSION_KEY", ""),
        "stored_session_id": get_session_env("HERMES_SESSION_ID", ""),
        "runtime_session_id": get_session_env("HERMES_UI_SESSION_ID", ""),
        "source": get_session_env("HERMES_SESSION_SOURCE", ""),
    }

def probe(raw):
    action = json.loads(raw)
    before = inspect_context()
    # Seed only the isolated test DB through Hermes's real persistence API.
    # A repeated invocation or cold resume must find exactly the same row.
    db = SessionDB()
    try:
        if db.get_session(before["session_key"]) is None:
            db.create_session(before["session_key"], "tui")
            db.append_message(before["session_key"], "user", json.dumps(action["context"]))
    finally:
        db.close()
    decision = request_tool_approval("symbolic-noop", raw, rule_key=action["nonce"])
    return json.dumps({"action": action, "before": before, "after": inspect_context(),
                       "approved": decision["approved"], "business_actions": 0})

async def async_probe(raw):
    await asyncio.sleep(0)
    return probe(raw)

def register(ctx):
    ctx.register_command("kot228-sync", probe)
    ctx.register_command("kot228-async", async_probe)
    ctx.register_command("kot228-context", lambda _raw: json.dumps(inspect_context()))
'''


class Gateway:
    def __init__(self, home):
        env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "TZ") if key in os.environ}
        env.update(HERMES_HOME=str(home), HERMES_ISO_CERTIFY_SYNTH_TURN="1",
                   PYTHONUNBUFFERED="1", PYTHONHASHSEED="0")
        self.frames, self.condition, self.serial = [], threading.Condition(), 0
        self.stderr = (home / "gateway-stderr.log").open("a")
        self.process = subprocess.Popen(
            [sys.executable, "-c", "from hermes_cli.plugins import discover_plugins; "
             "discover_plugins(); from tui_gateway.entry import main; main()"],
            cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, text=True, bufsize=1,
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.wait(lambda frame: frame.get("params", {}).get("type") == "gateway.ready")

    def _read(self):
        for line in self.process.stdout:
            try:
                frame = json.loads(line)
            except json.JSONDecodeError:
                continue
            with self.condition:
                self.frames.append(frame)
                self.condition.notify_all()

    def wait(self, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                for frame in self.frames:
                    if predicate(frame):
                        return frame
                remaining = deadline - time.monotonic()
                assert remaining > 0, f"Gateway response missing; exit={self.process.poll()}, frames={self.frames[-5:]}"
                self.condition.wait(remaining)

    def send(self, method, **params):
        self.serial += 1
        rid = f"r0-{self.serial}"
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                            "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        return rid

    def result(self, rid):
        response = self.wait(lambda frame: frame.get("id") == rid)
        assert "error" not in response, response
        return response["result"]

    def call(self, method, **params):
        return self.result(self.send(method, **params))

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.process.stdout.close()
        self.stderr.close()


@pytest.mark.parametrize("method,kinds", [
    ("command.dispatch", ("sync", "async")),
    ("slash.exec", ("async", "sync")),
])
def test_r0_native_approve_deny_and_resume_keep_session_ticket_context(tmp_path, method, kinds):
    home = tmp_path / "hermes"
    plugin = home / "plugins" / "kot228-r0"
    plugin.mkdir(parents=True)
    (plugin / "plugin.yaml").write_text("name: kot228-r0\nversion: 0.1.0\ndescription: Symbolic R0 probe\n")
    (plugin / "__init__.py").write_text(PLUGIN)
    (home / "config.yaml").write_text("plugins:\n  enabled: [kot228-r0]\napprovals:\n  mode: manual\n")
    gateway = Gateway(home)
    transcript = []
    try:
        sessions = [gateway.call("session.create", source="tui", cwd=str(tmp_path)) for _ in kinds]
        for session in sessions:
            # session.create is deliberately lazy. The native session.info event
            # confirms the agent and its approval notification route are wired.
            gateway.wait(lambda frame: frame.get("params", {}).get("type") == "session.info"
                         and frame["params"]["session_id"] == session["session_id"])
        actions, requests, events = [], [], []
        for label, session, kind in zip(("A", "B"), sessions, kinds):
            action = {"nonce": f"r0-{method}-{label}", "operation": "symbolic-noop",
                      "context": {"ticket": "DUB-027" if label == "A" else "R0-control-B",
                                  "issue": "KOT-228", "lane": label,
                                  "workspace": str(tmp_path / label)}}
            actions.append(action)
            params = {"session_id": session["session_id"]}
            if method == "command.dispatch":
                params.update(name=f"kot228-{kind}", arg=json.dumps(action))
            else:
                params["command"] = f"kot228-{kind} {json.dumps(action)}"
            requests.append(gateway.send(method, **params))
        for session, action in zip(sessions, actions):
            event = gateway.wait(lambda frame: frame.get("params", {}).get("type") == "approval.request"
                                 and frame["params"]["session_id"] == session["session_id"])
            assert json.loads(event["params"]["payload"]["description"]) == action
            events.append(event)
        # Reattach while both native approvals are pending: neither a new session
        # nor a different queued request may replace the original one.
        for session, event in zip(sessions, events):
            resumed = gateway.call("session.resume", session_id=session["stored_session_id"])
            assert resumed["session_id"] == session["session_id"]
            assert resumed["session_key"] == session["stored_session_id"]
            pending = gateway.call("approval.pending", session_id=resumed["session_id"])
            assert [p["request_id"] for p in pending["approvals"]] == [event["params"]["payload"]["request_id"]]
        # A valid but different session cannot consume B's request.
        assert gateway.call("approval.respond", session_id=sessions[0]["session_id"],
                            request_id=events[1]["params"]["payload"]["request_id"], choice="once")["resolved"] == 0
        for session, event, choice in zip(sessions, events, ("once", "deny")):
            assert gateway.call("approval.respond", session_id=session["session_id"],
                                request_id=event["params"]["payload"]["request_id"], choice=choice)["resolved"] == 1
        for index, (session, action, rid) in enumerate(zip(sessions, actions, requests)):
            output = json.loads(gateway.result(rid)["output"])
            assert output["approved"] is (index == 0)
            assert output["action"] == action and output["business_actions"] == 0
            assert output["before"] == output["after"] == {
                "approval_key": session["stored_session_id"], "session_key": session["stored_session_id"],
                "stored_session_id": session["stored_session_id"], "runtime_session_id": session["session_id"],
                "source": "tui",
            }
            assert gateway.call("approval.pending", session_id=session["session_id"])["approvals"] == []
        transcript.extend(gateway.frames)
    finally:
        gateway.close()
    # Cold restart uses the same real SessionDB. Runtime attachment IDs may change;
    # the durable Hermes session and ticket/context must remain unchanged.
    gateway = Gateway(home)
    try:
        for session, action in zip(sessions, actions):
            resumed = gateway.call("session.resume", session_id=session["stored_session_id"])
            assert resumed["session_key"] == session["stored_session_id"]
            assert any(json.loads(m["text"]) == action["context"] for m in resumed["messages"]
                       if m.get("role") == "user")
            context = json.loads(gateway.call("command.dispatch", session_id=resumed["session_id"],
                                              name="kot228-context")["output"])
            assert context["approval_key"] == context["session_key"] == context["stored_session_id"] == session["stored_session_id"]
            assert context["runtime_session_id"] == resumed["session_id"]
        transcript.extend(gateway.frames)
    finally:
        gateway.close()
    with sqlite3.connect(home / "state.db") as db:
        rows = db.execute("SELECT id, parent_session_id FROM sessions").fetchall()
    assert {row[0] for row in rows} == {session["stored_session_id"] for session in sessions}
    assert all(row[1] is None for row in rows)
    (tmp_path / "r0-transcript.json").write_text(json.dumps(transcript, indent=2))
