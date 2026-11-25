import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { writeFile } from "node:fs/promises";
import path from "node:path";

const requirePortal = root => createRequire(`${root}/api/server/services/dubsar/b2b-agent-source.js`);

// Early scope check, before provisioning either database. Portal's composer and
// its live native reads repeat the product checks; never override their reader,
// trusted publisher uid, boot id or filesystem trust root.
export function requireInstallationScope(portalRoot, ref, { tenant_id, project_id }) {
  const { readNativeInstallation } = requirePortal(portalRoot)("./b2b-agent-native-n2.js");
  const { tenantId, projectId } = readNativeInstallation(ref);
  assert.ok(tenantId === tenant_id && projectId === project_id,
    "B2B_AGENT_INPUTS_MODEL_GATEWAY_REQUIRED: external record does not cover the configured tenant/project");
}

async function key(file = null) {
  const pair = generateKeyPairSync("ed25519");
  const pem = pair.privateKey.export({ format: "pem", type: "pkcs8" });
  if (file) await writeFile(file, pem, { flag: "wx", mode: 0o400 });
  return { file, pem, public: pair.publicKey.export({ format: "pem", type: "spki" }) };
}

export async function startPortal({ portalRoot, mw, context, requester, pieces, start,
  allocationRoot, dir, port, mongoUrl, readSha, bootstrap, cleanup, coreSnapshot, mode, installation }) {
  const require = requirePortal(portalRoot);
  const native = mode === "native";
  const portalMode = mode === "bench-data" ? "bench" : mode;
  const { MongoClient } = require("mongodb");
  const { B2BMissions } = require("./b2b-missions.js");
  const { B2BAgentSessions } = require("./b2b-agent-sessions.js");
  const { composeB2BMissionInputs } = require("./b2b-mission-inputs.js");
  const { composeB2BAgentProposals } = require("./b2b-agent-proposals.js");
  const { composeB2BAgentSource } = require("./b2b-agent-source.js");
  const { SOURCE_PATH, INPUTS_PATH } = require("../../routes/dubsar/b2b-agent-source.js");
  const mongo = new MongoClient(mongoUrl, { serverSelectionTimeoutMS: 5000 });
  await mongo.connect();
  cleanup.push(() => mongo.close());
  const db = mongo.db(`native_${randomUUID().replaceAll("-", "")}`);
  const { project_id: projectId, tenant_id: tenantId, mission: { id: missionId } } = context;
  const missionRequest = { title: "Public beacon cards", objective: "Compare the public cards.",
    criteria: ["Cite both cards without performing an action."], source_refs: [] };
  const snapshot = coreSnapshot ?? bootstrap("draft", { objective: missionRequest.objective });
  const { createB2BMissionPorts } = await import(
    `${mw}/packages/dubsar-workbench-launcher/src/b2b-mission-ports.mjs`);
  const binding = { start, allocationRoot, projectId, tenantId };
  const preflightCoreMission = ({ tenantId: t, projectId: p }) => {
    assert.equal(t, tenantId);
    assert.equal(p, snapshot.project_id);
    assert.equal(missionId, snapshot.mission_id);
  };
  const ports = createB2BMissionPorts({ bindings: [binding], createCoreMission: request => {
    preflightCoreMission(request);
    return { snapshot, context };
  } });
  const portalSession = { _id: randomUUID().replaceAll("-", "").slice(0, 24), user: requester,
    expiration: new Date(Date.now() + 3600_000) };
  const sessionsColl = db.collection("sessions");
  await sessionsColl.insertOne(portalSession);
  const findSession = ({ userId, sessionId }) => sessionsColl.findOne({ _id: sessionId, user: userId });
  // Data harness boundary: a pre-authenticated local test session, not a browser
  // login/P7 claim. Mission creation, ticket reopens and source resolution below
  // are the real product implementations against their own stores.
  const req = { user: requester, sessionId: portalSession._id };
  const missions = new B2BMissions({ origin: "http://127.0.0.1", collection: db.collection("dubsar_b2b_missions"),
    bindings: [{ ...binding, userId: requester, agentProfile: "deploy", label: "Native composition",
      repositoryUrl: "https://github.com/kotnisofiane-bit/dubsar-my-work", startingSha: readSha() }],
    ...ports, preflightCoreMission, findSession, authenticated: async r => ({
      user: r.user, session: await findSession({ userId: r.user, sessionId: r.sessionId }) }) });
  const created = await missions.create(req, projectId, { ...missionRequest, client_request_id: randomUUID() });
  assert.equal(created.body.mission.mission_id, missionId);
  const agentSessions = new B2BAgentSessions({ collection: db.collection("dubsar_b2b_agent_sessions"), missions,
    bridge: { inspectExactSession: (_, id) => bootstrap("session", { id, create: false }),
      createExactSession: (_, id) => bootstrap("session", { id, create: true }) } });
  const genesis = await agentSessions.create(req, projectId, missionId);
  assert.equal(genesis.status, 201, JSON.stringify(genesis));
  const inputs = await composeB2BMissionInputs({ config: { enabled: true }, mode: portalMode,
    // Bench MissionInputs requires a configured user id excluded from recipient
    // selection. No approval, recipient selection or ticket workflow is run.
    ticketApproverId: native ? null : randomUUID().replaceAll("-", "").slice(0, 24),
    collection: db.collection("dubsar_b2b_mission_inputs"), missions, agentInputsEnabled: true });
  cleanup.push(() => inputs.close());
  for (const text of pieces) {
    const answer = await inputs.runtime.addPiece(req, projectId, missionId, { client_piece_id: randomUUID(), text });
    assert.equal(answer.status, 201);
  }
  const proposals = await composeB2BAgentProposals({ collection: db.collection("dubsar_b2b_agent_proposals"),
    agentSessions, missions, missionInputs: inputs.runtime });
  cleanup.push(() => proposals.close());
  const prepared = await proposals.runtime.prepare(req, projectId, missionId);
  const attempt = await proposals.runtime.readAttemptForSource(prepared.body.agent_proposal.attempt_id);
  assert.ok(attempt?.mission_inputs);
  const readerBinding = { tenant_id: tenantId, attempt_id: attempt._id,
    ...Object.fromEntries(["project_id", "mission_id", "requester_id", "mission_revision", "binding_digest",
      "session_id", "profile", "mission_inputs"].map(k => [k, attempt[k]])) };

  const portal = await key(), hermes = await key(path.join(dir, "hermes.pem"));
  const portalIssuer = native ? "portal-lot1-n2" : "portal-bench-data";
  const hermesIssuer = native ? "hermes/deploy" : "bench-data/deploy";
  const reader = native ? await key(path.join(dir, "reader.pem")) : hermes;
  const readerIssuer = native ? "mw/preflight-reader" : hermesIssuer;
  const config = { enabled: true, missionInputs: true, port, portalIssuer, privateKeyPem: portal.pem,
    profiles: [{ profile: "deploy", hermesIssuer, hermesPublicKeyPem: hermes.public }],
    ...(native ? { nativeN2: { readerIssuer, readerPublicKeyPem: reader.public, g2Installation: installation } } : {}) };
  const source = await composeB2BAgentSource({ config, mode: portalMode, missions, agentSessions,
    proposals: proposals.runtime, missionInputs: inputs.runtime });
  cleanup.push(() => source.close());
  assert.equal(source.port, port);
  const origin = `http://127.0.0.1:${port}`;
  const readerConfig = { url: origin + INPUTS_PATH, publicKeyPem: portal.public,
    clientKeyFile: reader.file, portalIssuer, readerIssuer };
  const metadata = { mode, native_source: native, ...readerBinding, request_digest: attempt.request_digest,
    mission_source_digest: attempt.mission_source_digest, core_snapshot: snapshot };
  if (native) {
    return { readerBinding, readerConfig, metadata: { ...metadata, source_url: origin + SOURCE_PATH,
      source_port: port, portal_issuer: portalIssuer, hermes_issuer: hermesIssuer, portal_public_key_pem: portal.public,
      hermes_private_key_file: hermes.file, installation_record: installation } };
  }
  // The independent MCP reader uses My Work's existing signed inputs/bind
  // port. Bench signs as the profile, not as a dedicated native N2 reader.
  const { tenant_id: _, ...publicBinding } = readerBinding;
  const bindingFile = path.join(dir, "bench-inputs.json");
  await writeFile(bindingFile, JSON.stringify({ ...publicBinding, portal_issuer: portalIssuer,
    hermes_issuer: hermesIssuer }), { flag: "wx", mode: 0o400 });
  return { readerBinding, readerConfig, benchReaderEnv: {
    DUBSAR_MY_WORK_START: start, DUBSAR_MY_WORK_ALLOCATION_ROOT: allocationRoot,
    DUBSAR_MY_WORK_MISSION_PROFILE: "b2b-production", DUBSAR_MY_WORK_TENANT_ID: tenantId,
    DUBSAR_MY_WORK_PROJECT_ID: projectId, DUBSAR_MY_WORK_MISSION_ID: missionId,
    DUBSAR_MY_WORK_PORTAL_INPUTS_URL: readerConfig.url, DUBSAR_MY_WORK_PORTAL_PUBLIC_KEY_PEM: portal.public,
    DUBSAR_MY_WORK_PORTAL_CLIENT_PRIVATE_KEY_FILE: hermes.file, DUBSAR_MY_WORK_PORTAL_INPUTS_BINDING_FILE: bindingFile,
  }, metadata: { ...metadata, bench_inputs_url: readerConfig.url } };
}
