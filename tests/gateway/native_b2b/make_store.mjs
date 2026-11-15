#!/usr/bin/env node
// Synthetic B2B production ticket store, minted through the REAL identity
// helpers: sealB2BMissionAuthority computes the domain-separated basis and
// authority digests the registry validator recomputes, so the fixture carries
// real digests — never fabricated hashes. Usage:
//   node make_store.mjs <mywork-repo> <start-dir> <tenant> <project> <mission-id> [objective]
import fs from 'node:fs';
import path from 'node:path';

const [repo, start, tenantId, projectId, missionId, objective] = process.argv.slice(2);
const { sealB2BMissionAuthority, assertB2BContext, B2B_MISSION_NAMESPACE } =
  await import(`${repo}/packages/dubsar-workbench-launcher/src/b2b-mission-identity.mjs`);

const context = assertB2BContext({
  tenant_id: tenantId,
  project_id: projectId,
  mission: { namespace: B2B_MISSION_NAMESPACE, id: missionId },
});
const missionObjective = objective ?? 'P2 native qualification mission: bound context read end-to-end.';
const ticket = {
  id: missionId,
  work_id: null,
  project_id: projectId,
  project: projectId,
  title: 'P2 native lane mission',
  objective: missionObjective,
  criteria: ['Bound context must be read natively', 'No production bypass'],
  state: 'Backlog',
  duplicate_of: null,
  agent: null,
  branch: null,
  pr: null,
  blocker: null,
  references: [],
  intent_fingerprint: `sha256:${'ab'.repeat(32)}`,
  repository_url: 'https://github.com/kotnisofiane-bit/dubsar-my-work',
  starting_sha: '1'.repeat(40),
  workspace_root: null,
  cursor_launch: null,
  cursor_run: null,
  codex_launch: null,
  codex_run: null,
  codex_stop: null,
  identity_profile: 'b2b-production',
  core_context: context,
  activity: [],
};
ticket.mission_authority = sealB2BMissionAuthority(ticket);

const dir = path.join(start, '.dubsar');
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(
  path.join(dir, 'tickets.json'),
  JSON.stringify({ format: 'dubsar.tickets/1', tickets: [ticket] }, null, 2),
  { mode: 0o600 },
);
const { createB2BMissionPorts } = await import(
  `${repo}/packages/dubsar-workbench-launcher/src/b2b-mission-ports.mjs`);
const ports = createB2BMissionPorts({
  bindings: [{ start, allocationRoot: start, projectId, tenantId }],
  createCoreMission: async () => { throw new Error('test read-only composition'); },
});
console.log(JSON.stringify(ports.buildMissionContextView(
  { format: 'dubsar.tickets/1', tickets: [ticket] }, { projectId, missionId })));
