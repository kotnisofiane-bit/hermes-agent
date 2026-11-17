// Test composition of the EXISTING PostgreSQL OC fixture and release helper.
// SimulatedAuthority is the explicit trust double; views, observations,
// state policy, migrations, journal, IPC and source timestamps are native.
import fs from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline';
import { pathToFileURL } from 'node:url';

const cfg = JSON.parse(await fs.readFile(process.argv[2], 'utf8'));
const load = file => import(pathToFileURL(path.join(cfg.mywork, file)).href);
process.env.OC_CONTRACTS_CHECKOUT = cfg.contracts;
const { startOcKernelFixture } = await load('tests/fixtures/mw-o-oc-kernel.mjs');
const { initializeStateJournal, reserveRefreshSnapshot } =
  await load('packages/dubsar-my-work-mcp/src/oc-state-journal.mjs');
const { buildActivateObservation, emitPreparedObservation } =
  await load('packages/dubsar-my-work-mcp/src/oc-producer.mjs');
const helper = await load('scripts/release-host-helper.mjs');
const cleanups = [];
const t = { after(fn) { cleanups.push(fn); } };
const journalDir = path.join(cfg.root, 'journal');
const anchorFile = path.join(cfg.root, 'anchor/counter.json');
const socketPath = path.join(cfg.root, 'oc.sock');
await initializeStateJournal(journalDir, 'epoch-p2', anchorFile);
const oc = await startOcKernelFixture(t, {
  socketPath, dbUrl: cfg.postgres_url, journalDir,
});
async function observe(sha40 = 'a'.repeat(40)) {
  const record = await reserveRefreshSnapshot({
    directory: journalDir, anchorFile,
    buildObservation: fields => buildActivateObservation({ sha40, ...fields }),
  });
  await emitPreparedObservation(record.observation, {
    socketPath, requestId: 'p2-' + Date.now(),
  });
}
await observe();
const runtime = helper.createHelperRuntime({
  gitSource: cfg.mywork, optRoot: path.join(cfg.root, 'unused-release'),
  refreshCanonicalSource: false, ocHostSocketPath: socketPath,
  env: { DUBSAR_OC_STATE_PROJECTION: 'ordered_snapshot' },
});
const helperSocket = path.join(cfg.root, 'helper.sock');
const server = await helper.listenReleaseHelper(runtime, { socketPath: helperSocket });
console.log(JSON.stringify({ ready: true, helperSocket }));
readline.createInterface({ input: process.stdin }).on('line', async line => {
  const request = JSON.parse(line);
  if (request.action === 'observe') await observe('b'.repeat(40));
  else if (request.action === 'unavailable') oc.viewMode = 'unavailable';
  else if (request.action === 'hold') oc.viewMode = 'hold';
  else if (request.action === 'release') { oc.viewMode = 'normal'; oc.releaseViews(); }
  console.log(JSON.stringify({
    ok: true, views: oc.viewCount, observations: await oc.pgObservationCount(),
  }));
});
process.once('SIGTERM', async () => {
  await new Promise(resolve => server.close(resolve));
  for (const cleanup of cleanups.reverse()) await cleanup();
  process.exit(0);
});
