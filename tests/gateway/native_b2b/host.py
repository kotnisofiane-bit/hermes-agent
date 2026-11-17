"""Subprocess host for the real API adapter. No production method is patched."""
import asyncio
import json
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace


async def main():
    cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    os.environ["HERMES_HOME"] = cfg["home"]
    os.environ["HERMES_DISABLE_LAZY_INSTALLS"] = "1"
    os.environ["TIRITH_ENABLED"] = "false"
    # Test-only egress fence, inherited by all Python worker threads.
    # Unix reader sockets and declared loopback doubles are the only peers.
    def fence(event, args):
        if event == "socket.connect":
            sock, peer = args
            if sock.family == socket.AF_UNIX:
                return
            if (isinstance(peer, tuple) and peer[0] in ("127.0.0.1", "::1")
                    and peer[1] in cfg["allowed_ports"]):
                return
            raise OSError("P2 test refused undeclared network destination")
        if event == "socket.getaddrinfo":
            if args[0] not in ("127.0.0.1", "::1", "localhost", None):
                raise OSError("P2 test refused external DNS")
    sys.addaudithook(fence)
    from agent.secret_scope import set_multiplex_active
    from gateway.config import PlatformConfig
    from gateway.platforms.api_server import APIServerAdapter
    from gateway.run import _discover_gateway_mcp_tools
    set_multiplex_active(True)
    runner_cfg = SimpleNamespace(multiplex_profiles=True)
    runner = SimpleNamespace(multiplex_profiles=True)
    await _discover_gateway_mcp_tools(runner)
    adapter = APIServerAdapter(PlatformConfig(
        enabled=True, extra={"b2b": cfg["b2b"], "multiplex_profiles": True}))
    adapter._port = cfg["port"]
    adapter.gateway_runner = SimpleNamespace(config=runner_cfg)
    assert await adapter.connect()
    Path(cfg["ready"]).write_text(json.dumps({"ready": True}), encoding="utf-8")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
