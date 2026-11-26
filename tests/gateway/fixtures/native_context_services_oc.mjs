// The disposable DB is provisioned with an initial ordered-state policy.
// No proof/observation rows are seeded: the MW producer, OC bridge/kernel and
// MW receipt mapper generate them. Each subsequent read calls the kernel.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";

async function initialPolicy(oc, kernel, root, scope, generation) {
  // Owner data setup, not an exercise of the root-owned OC admin service.
  // Use the Contracts store to provision *policy only* in a brand new DB.
  const { appendStatePolicy, lockStatePolicy } = await import(
    `${root}/src/operational-context/state-policy-store.mjs`);
  const { tenant_id, environment_id, resource_local_ref, property, producer_id } = scope;
  const at = new Date().toISOString();
  const trust = oc.validateTrust({ contract: "dubsar.operational-context.trust/1",
    tenant_id, environment_id, principal_id: "principal:fixture-owner", principal_kind: "admin" });
  const mapping = oc.validateMapping({ contract: "dubsar.operational-context.mapping/2",
    mapping_ref: "mapping:mywork-release-state/1", version: 1, property, producer_id,
    source_instance_id: generation.sourceInstanceId, value_type: "string", temporal_mode: "ordered_snapshot" });
  const rule = oc.validateRule({ contract: "dubsar.operational-context.rule/1",
    rule_ref: "rule:mywork-release-state-freshness/1", version: 1, freshness_max_age_ms: 900000 });
  const binding = oc.validateStateBinding({ contract: "dubsar.operational-context.state-binding/1",
    binding_ref: "binding:native-context", version: 1, tenant_id, environment_id, resource_local_ref,
    property, producer_id, source_instance_id: generation.sourceInstanceId, producer_epoch: generation.epoch,
    mapping_ref: mapping.mapping_ref, mapping_version: mapping.version,
    rule_ref: rule.rule_ref, rule_version: rule.version, effective_at: at,
    legacy_observation_refs: [], supersedes: { absence: "initial" } });
  await kernel.store.withTransaction(async client => {
    await lockStatePolicy(client, trust);
    await kernel.store.upsertMapping(client, trust, mapping, "admitted");
    await kernel.store.upsertRule(client, trust, rule, "admitted");
    for (const [kind, value] of Object.entries({ mapping, rule, binding })) {
      await appendStatePolicy(client, trust, kind, value, "admitted", at);
    }
  });
}

export async function startObservation({ mw, ocRoot, dir, socketDir, context, profile, postgres,
  readSha, cleanup }) {
  const contracts = await realpath(`${mw}/packages/dubsar-contracts`);
  const launcher = `${mw}/packages/dubsar-workbench-launcher/src`;
  const mcp = `${mw}/packages/dubsar-my-work-mcp/src`;
  const { loadProductionMwOModules } = await import(`${launcher}/mw-o-production.mjs`);
  const modules = await loadProductionMwOModules({ contractsRoot: contracts, profile });
  const { loadContractsModule } = await import(`${ocRoot}/src/contracts-loader.mjs`);
  const { loadContractsPin } = await import(`${ocRoot}/src/config.mjs`);
  const { oc } = await loadContractsModule(contracts, loadContractsPin());
  const pg = createRequire(path.join(launcher, "mw-o-store.mjs"))("pg");
  const dbName = `native_${randomUUID().replaceAll("-", "")}`;
  const owner = new pg.Client({ connectionString: postgres.href });
  await owner.connect();
  try {
    await owner.query(`CREATE DATABASE ${dbName}`);
  } finally {
    await owner.end();
  }
  const url = new URL(postgres.href);
  url.pathname = "/" + dbName;
  const pool = new pg.Pool({ connectionString: url.href });
  cleanup.push(() => pool.end());
  await oc.applyOperationalContextMigration(pool);
  const scope = { tenant_id: profile.tenantId, environment_id: profile.environmentId,
    resource_local_ref: modules.profile.selection.resource_ref,
    property: modules.profile.selection.property, producer_id: "producer:mywork-release" };
  const policy = { contract: "dubsar.oc-host.authority-policy/1", grants: [] };
  const trust = role => oc.validateTrust({ contract: "dubsar.operational-context.trust/1",
    tenant_id: scope.tenant_id, environment_id: scope.environment_id,
    principal_id: `principal:mywork-${role}`, principal_kind: "workload" });
  const grant = (role, action, fields) => {
    const { contract: _, ...identity } = trust(role);
    policy.grants.push({ ...identity, action, resource_local_ref: scope.resource_local_ref, ...fields });
  };
  const fields = { property: scope.property, producer_id: scope.producer_id };
  grant("producer", "observe", fields);
  for (const r of [{}, { property: scope.property }, fields]) grant("reader", "read", r);
  const policyFile = path.join(dir, "oc-authority.json");
  await writeFile(policyFile, JSON.stringify(policy), { flag: "wx", mode: 0o400 });
  process.env.OC_HOST_AUTHORITY_POLICY_FILE = policyFile;
  const { createAuthority } = await import(`${ocRoot}/src/authority/policy-authority.mjs`);
  const kernel = oc.createOperationalContextKernel({ pool, authority: await createAuthority() });
  const epoch = "epoch:native-context";
  const journalDirectory = path.join(dir, "journal");
  const anchorFile = path.join(dir, "anchor", "counter.json");
  const { initializeStateJournal } = await import(`${mcp}/oc-state-journal.mjs`);
  await initializeStateJournal(journalDirectory, epoch, anchorFile);
  await initialPolicy(oc, kernel, contracts, scope, { sourceInstanceId: profile.sourceInstanceId, epoch });
  // The deployment transports the bridge envelope; here the two pinned
  // principals are local composition ports, never selected by a caller.
  const { buildObserveRequest, buildGetContextViewRequest } = await import(`${mcp}/oc-bridge-client.mjs`);
  const exchange = (role, makeRequest) => {
    const bridge = oc.createOperationalContextBridge({ kernel, resolveTrust: async () => trust(role) });
    return (payload, { requestId }) => bridge.handle(JSON.stringify(makeRequest(payload, requestId)));
  };
  const store = modules.createMwOStore({ pool });
  await store.initialize();
  const producer = modules.createMwOProducer({ store, journalDirectory, anchorFile, readCurrentSha: readSha,
    now: () => new Date().toISOString(),
    observe: exchange("producer", buildObserveRequest) });
  const reader = modules.createMwOReader({ store, getContextView: exchange("reader", buildGetContextViewRequest) });
  const sequencer = modules.createMwOSequencer({ store, reader, producer,
    clock: () => ({ now_ms: Date.now(), synchronized: true }) });
  const binding = { format: "dubsar.my-work-oc-binding/1", project_id: context.project_id,
    mission_id: context.mission.id, selection_id: modules.profile.selection.selection_id };
  const started = await sequencer.start({ context, binding });
  assert.equal(started.phase, "ready", `native OC startup: ${started.phase} ${started.last_error ?? ""}`);
  const mwO = modules.createMwOHelperInterface({ store, reader, role: "reader", boundContext: context });
  const { createHelperRuntime, listenReleaseHelper } = await import(`${mw}/scripts/release-host-helper.mjs`);
  const helperSocket = path.join(socketDir, "helper");
  const helper = await listenReleaseHelper(createHelperRuntime({ mwO, role: "reader" }), { socketPath: helperSocket });
  cleanup.push(() => new Promise(resolve => helper.close(resolve)));
  return { binding, helperSocket, readObservation: sequencer.readPreflightObservation };
}
