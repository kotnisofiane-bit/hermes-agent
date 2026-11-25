// node native_context_services.mjs ABS_CONFIG
// {root,project_id,mission_id,tenant_id,requester_id,pieces:[text,text]}
// root: existing test-owned private directory. Writable run state is always new.
// Optional core_snapshot: the caller's real Builder draft. Otherwise the Builder
// setup port creates one. Only this local fixture's single-UID topology is proved.
// Default mode "native" REQUIRES installation_record:{path,sha256} supplied
// by the operator. Portal checks publisher, bytes, boot and tenant/project.
// "bench-data" is an explicit, separate data-only mode. No record, no native
// source URL, no Portal signing key and no model authorization are returned.
//
// Required: DUBSAR_MY_WORK_ROOT (materialized packages), DUBSAR_OC_ROOT,
// DUBSAR_PORTAL_ROOT (Mongo driver), DUBSAR_TEST_POSTGRES_URL (CREATEDB),
// DUBSAR_TEST_MONGO_URL. TOOL_ROOT may default to the Portal checkout's sibling.
// DUBSAR_SCRIBE_BUILDER defaults to Hermes's sibling.
// DUBSAR_CORE_PYTHON / DUBSAR_HERMES_PYTHON select the provisioned interpreters.
// Stop with SIGTERM. The fixture neither drops databases nor contacts a provider.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath } from "node:fs/promises";
import { randomInt } from "node:crypto";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { startObservation } from "./native_context_services_oc.mjs";
import { requireInstallationScope, startPortal } from "./native_context_services_portal.mjs";

const abs = value => {
  assert.ok(typeof value === "string" && path.isAbsolute(value), "absolute fixture/checkout path required");
  return value;
};
const checkout = (key, fallback) => abs(process.env[key] ?? fallback);
const hermes = fileURLToPath(new URL("../../../", import.meta.url));
const sibling = name => path.resolve(hermes, "..", name);
const nodeEnv = process.env.NODE_ENV;
assert.ok(!nodeEnv || nodeEnv === "test", "non-test NODE_ENV refused");
process.env.NODE_ENV = "test";
assert.ok(process.getuid() > 0, "non-root only");
process.umask(0o077);
const config = JSON.parse(await readFile(abs(process.argv[2]), "utf8"));
const { project_id, mission_id, tenant_id, requester_id, pieces, mode = "native", installation_record } = config;
assert.ok(mode === "native" || mode === "bench-data", 'mode must be "native" or "bench-data"');
if (mode === "native") {
  assert.ok(installation_record,
    "B2B_AGENT_INPUTS_MODEL_GATEWAY_REQUIRED: supply an external protected installation_record {path, sha256}");
} else {
  assert.ok(!Object.hasOwn(config, "installation_record"), "bench-data cannot consume installation evidence");
}
const portalRoot = checkout("DUBSAR_PORTAL_ROOT");
if (mode === "native") requireInstallationScope(portalRoot, installation_record, config);
assert.match(project_id, /^prj_[a-f0-9]{32}$/);
assert.match(mission_id, /^mis_[a-f0-9]{32}$/);
assert.match(requester_id, /^[a-f0-9]{24}$/);
assert.ok(Array.isArray(pieces) && pieces.length === 2 && pieces.every(v => typeof v === "string" && v.length));
const root = abs(config.root);
const parent = await lstat(root);
assert.ok(parent.isDirectory() && parent.uid === process.getuid() && !(parent.mode & 0o022));
const mw = checkout("DUBSAR_MY_WORK_ROOT"), ocRoot = checkout("DUBSAR_OC_ROOT");
const tool = checkout("DUBSAR_TOOL_ROOT", path.resolve(portalRoot, "../dubsar-tool-layer"));
const pg = new URL(process.env.DUBSAR_TEST_POSTGRES_URL);
// pg accepts both encoded-directory DSNs and ?host=/private/directory.
// Do not allow connection-string options to redirect to an arbitrary host.
const unixPath = !pg.search && path.isAbsolute(decodeURIComponent(pg.hostname))
  ? decodeURIComponent(pg.hostname)
  : pg.hostname === "localhost" && [...pg.searchParams.keys()].join() === "host"
    ? pg.searchParams.get("host") : null;
if (unixPath !== null) {
  const folder = await lstat(abs(unixPath));
  assert.ok(folder.isDirectory() && folder.uid === process.getuid() && !(folder.mode & 0o077));
}
assert.ok(["postgresql:", "postgres:"].includes(pg.protocol) && Number(pg.port) >= 20000 && !pg.hash &&
  (unixPath || (pg.hostname === "127.0.0.1" && !pg.search)), "private high-port local Postgres DSN required");
const mongoUrl = process.env.DUBSAR_TEST_MONGO_URL;
assert.ok(/^mongodb:\/\/127\.0\.0\.1:[1-9][0-9]{4}$/.test(mongoUrl) &&
  Number(new URL(mongoUrl).port) >= 20000, "private high-port loopback Mongo URL required");
const dir = await mkdtemp(path.join(root, "context-"));
// AF_UNIX paths are limited to 107 bytes; pytest's tmp_path may be much longer.
const socketBase = process.env.DUBSAR_TEST_SOCKET_ROOT ?? (Buffer.byteLength(dir) < 85 ? dir : os.homedir());
const socketDir = await mkdtemp(path.join(abs(socketBase), ".ctx-"));
assert.ok(Buffer.byteLength(socketDir) + 8 < 108, "use a shorter DUBSAR_TEST_SOCKET_ROOT");
const start = path.join(dir, "start"), allocationRoot = path.join(dir, "allocation");
await mkdir(path.join(start, ".dubsar"), { recursive: true });
await mkdir(allocationRoot);
const context = { tenant_id, project_id, mission: { namespace: "scribe-backend", id: mission_id } };
const profile = { tenantId: tenant_id, projectIds: [project_id], hostId: "native-context",
  environmentId: "env:native-context", sourceInstanceId: "instance:native-context" };
const readSha = () => execFileSync("git", ["-C", mw, "rev-parse", "--verify", "HEAD"], { encoding: "utf8" }).trim();
const python = process.env.DUBSAR_HERMES_PYTHON ?? process.env.DUBSAR_CORE_PYTHON ?? "python3";
const bootstrap = (job, args) => {
  const [bin, source] = job === "session" ? [python, hermes]
    : [process.env.DUBSAR_CORE_PYTHON ?? python, checkout("DUBSAR_SCRIBE_BUILDER", sibling("Scribe-Builder"))];
  const result = execFileSync(bin, ["-IB", fileURLToPath(new URL("./native_context_services_bootstrap.py", import.meta.url)),
    job, source], { encoding: "utf8", timeout: 25000,
    env: { PATH: process.env.PATH, HOME: dir, HERMES_HOME: path.join(dir, "hermes"), LANG: "C.UTF-8" },
    input: JSON.stringify({ dir, project_id, mission_id, ...args }) });
  return JSON.parse(result);
};
const port = Number(process.env.DUBSAR_TEST_SOURCE_PORT ?? randomInt(20000, 65000));
assert.ok(Number.isInteger(port) && port >= 20000 && port <= 65535);
const cleanup = [];
const contract = "dubsar.asm.mw-preflight-reader/1";
try {
  const oc = await startObservation({ mw, ocRoot, dir, socketDir, context, profile, postgres: pg, readSha, cleanup });
  const portal = await startPortal({ portalRoot, mw, context, requester: requester_id, pieces,
    start, allocationRoot, dir, port, mongoUrl, readSha, bootstrap, cleanup,
    coreSnapshot: config.core_snapshot, mode, installation: installation_record });
  const mcp = `${mw}/packages/dubsar-my-work-mcp/src`;
  const { createMissionPreflightReader, missionContextReaderFromEnv } = await import(`${mcp}/mission-context-profile.mjs`);
  const read = createMissionPreflightReader({ start, tenantId: tenant_id, projectIds: [project_id],
    portal: portal.readerConfig, readObservation: oc.readObservation });
  let id = 0;
  const readForMission = async name => {
    const request = { jsonrpc: "2.0", id: ++id, method: "tools/call",
      params: { name, arguments: { binding: portal.readerBinding } } };
    const response = await read({ contract, payload: request });
    return JSON.parse(response.result.content[0].text);
  };
  const { serveUnixSocket } = await import(`${tool}/src/core-write-delivery.mjs`);
  const { createPeerCredentials } = await import(`${tool}/src/peer-credentials.mjs`);
  const readerSocket = path.join(socketDir, "reader");
  const pyPath = execFileSync(python, ["-I", "-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).trim();
  const server = await serveUnixSocket({ path: readerSocket, peer: createPeerCredentials({ pythonExecutable: pyPath }),
    socketMode: 0o660, routes: { [contract]: { uid: process.getuid(), handler: read } } });
  cleanup.push(() => server.close());

  // Native N2 uses only the late prepare reader. Bench uses the ordinary
  // bound-profile bind reader; each MCP call makes its own live inputs read.
  process.env.DUBSAR_MY_WORK_MISSION_ID = mission_id;
  process.env.DUBSAR_MYWORK_RELEASE_HELPER_SOCKET = oc.helperSocket;
  const { listenHermesMcpSocket } = await import(`${mcp}/hermes-transport.mjs`);
  const { setMcpProfile } = await import(`${mcp}/server.mjs`);
  setMcpProfile("hermes");
  const mcpSocket = path.join(socketDir, "mcp");
  const mcpServer = await listenHermesMcpSocket(mcpSocket, process, {
    projectContext: { project_id, start, allocation_root: allocationRoot }, trustedOcBinding: oc.binding,
    missionContextReader: mode === "bench-data" ? missionContextReaderFromEnv(portal.benchReaderEnv) : async (_, identity) => {
      assert.equal(identity.projectId, project_id);
      assert.equal(identity.missionId, mission_id);
      return readForMission("get_mission_context");
    },
  });
  await chmod(mcpSocket, 0o600);
  cleanup.push(() => new Promise(resolve => mcpServer.close(resolve)));
  const myWork = await readForMission("get_mission_context");
  const operationalContext = await readForMission("get_oc_context_view");
  assert.deepEqual(myWork.documents.map(p => p.text), pieces);
  assert.equal(operationalContext.availability, "available");
  const { title, objective, criteria, references: source_refs } = myWork;
  process.stdout.write(JSON.stringify({ ready: true, ...portal.metadata, start, allocation_root: allocationRoot,
    socket_path: readerSocket, reader_binding: portal.readerBinding, mcp_socket_path: mcpSocket,
    mcp_proxy: await realpath(`${mw}/tools/hermes-mywork-proxy.py`),
    mcp_config: { command: pyPath, args: [`${mw}/tools/hermes-mywork-proxy.py`],
      env: { DUBSAR_MY_WORK_HERMES_SOCKET: mcpSocket } },
    my_work: myWork, operational_context: operationalContext,
    mission_request: { title, objective, criteria, source_refs } }) + "\n");
  await new Promise(resolve => {
    process.prependOnceListener("SIGTERM", resolve);
    process.prependOnceListener("SIGINT", resolve);
  });
} finally {
  for (const close of cleanup.reverse()) await close();
}
