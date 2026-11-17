#!/usr/bin/env node
// Embedding host for the B2B production read path: the piece the MW-O bound
// child plays in production. Newline JSON-RPC on stdio, real modules only:
//   tools/list            -> real HERMES_ONLY + mission-context tool defs
//   tools/call get_mission_context
//                         -> createB2BMissionPorts().buildMissionContextView
//                            (the production composition seam; the plain
//                            runMissionContextTool rightly refuses mis_ ids)
//   tools/call get_oc_context_view
//                         -> real handleMessage() with the host-supplied
//                            trustedOcBinding (socket-unservable by design)
// Scope values are host-bound (env), never caller-supplied.
import path from 'node:path';
import readline from 'node:readline';

const repo = process.env.MW_REPO;
const projectContext = {
  start: process.env.MW_START,
  allocation_root: process.env.MW_ALLOCATION_ROOT,
  project_id: process.env.MW_PROJECT_ID,
};
const missionId = process.env.MW_MISSION_ID;
const tenantId = process.env.MW_TENANT_ID;
// trustedMissionIdFromEnv() reads DUBSAR_MY_WORK_MISSION_ID at call time; the
// embedding host (MW-O bound child launcher) owns it, never the caller.
process.env.DUBSAR_MY_WORK_MISSION_ID = missionId;

const { bindHermesProject } = await import(`${repo}/packages/dubsar-my-work-mcp/src/canonical.mjs`);
const { handleMessage, setMcpProfile } = await import(`${repo}/packages/dubsar-my-work-mcp/src/server.mjs`);
const { declareHistoricalLabOcScope } = await import(`${repo}/packages/dubsar-my-work-mcp/src/oc-production-scope.mjs`);
setMcpProfile('hermes');
// Same declaration the real service's --oc-lab performs: the task-owned
// kernel fixture serves the historical lab resource/selection.
declareHistoricalLabOcScope();
const { MISSION_CONTEXT_TOOL_DEFINITIONS } = await import(`${repo}/packages/dubsar-my-work-mcp/src/mission-context-tools.mjs`);
const { OC_CONTEXT_VIEW_TOOL_DEFINITIONS } = await import(`${repo}/packages/dubsar-my-work-mcp/src/oc-context-view-tools.mjs`);
const { createB2BMissionPorts } = await import(`${repo}/packages/dubsar-workbench-launcher/src/b2b-mission-ports.mjs`);
const { readTickets } = await import(`${repo}/packages/dubsar-workbench-launcher/src/registry-store.mjs`);
const { validateTrustedOcBinding } = await import(`${repo}/packages/dubsar-my-work-mcp/src/oc-context-selection.mjs`);

const trustedOcBinding = validateTrustedOcBinding({
  format: 'dubsar.my-work-oc-binding/1',
  project_id: projectContext.project_id,
  mission_id: missionId,
  selection_id: 'mywork.release.current_sha',
});

const ports = createB2BMissionPorts({
  bindings: [{
    start: projectContext.start,
    allocationRoot: projectContext.allocation_root,
    projectId: projectContext.project_id,
    tenantId,
  }],
  createCoreMission: async () => { throw new Error('B2B_MISSION_PORT_REQUIRED'); },
});

const TOOLS = [...MISSION_CONTEXT_TOOL_DEFINITIONS, ...OC_CONTEXT_VIEW_TOOL_DEFINITIONS];

function toolResult(result) {
  return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: false };
}
function toolError(error) {
  const code = error?.code ?? 'MY_WORK_OPERATION_FAILED';
  return { content: [{ type: 'text', text: JSON.stringify({ format: 'dubsar.my-work-mcp-error/1', code }) }], structuredContent: { format: 'dubsar.my-work-mcp-error/1', code }, isError: true };
}

async function dispatch(message) {
  if (message?.method?.startsWith('notifications/')) return null;
  if (message?.method === 'initialize') {
    return { protocolVersion: '2024-11-05', capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'dubsar-my-work', version: '0.1.0-dev', profile: 'hermes' } };
  }
  if (message?.method === 'ping') return {};
  if (message?.method === 'tools/list') return { tools: TOOLS };
  if (message?.method === 'tools/call') {
    const name = message.params?.name;
    if (name === 'get_mission_context') {
      try {
        const bound = bindHermesProject(message, projectContext);
        const args = bound.params?.arguments ?? {};
        const store = await readTickets({ start: args.start });
        return toolResult(ports.buildMissionContextView(store, { projectId: args.project_id, missionId }));
      } catch (error) { return toolError(error); }
    }
    try {
      const bound = bindHermesProject(message, projectContext);
      // handleMessage returns a full JSON-RPC frame; keep only the result.
      const frame = await handleMessage(bound, { trustedOcBinding });
      if (frame?.error) return { isError: true, content: [{ type: 'text', text: JSON.stringify(frame.error) }] };
      return frame?.result ?? { isError: true, content: [{ type: 'text', text: JSON.stringify({ code: 'MY_WORK_OPERATION_FAILED' }) }] };
    } catch (error) {
      return { isError: true, content: [{ type: 'text', text: JSON.stringify({ code: error?.code }) }] };
    }
  }
  return null;
}

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', async (line) => {
  if (!line.trim()) return;
  let message;
  try { message = JSON.parse(line); } catch { return; }
  const result = await dispatch(message);
  if (result !== null && message.id !== undefined) {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }) + '\n');
  }
});
