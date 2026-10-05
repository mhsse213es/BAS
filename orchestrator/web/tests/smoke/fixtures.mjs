// Fixture responses for the smoke harness. Keys are "METHOD /path" with the
// query string removed; a value may be a function of the request URL. PAYLOAD
// strings must never execute: smoke.spec.mjs fails if window.__xss is set.
export const PAYLOAD = '"><img src=x onerror="window.__xss=1"><svg onload="window.__xss=1">';

const NOW = '2026-10-01T10:00:00Z';

const agent = {
  id: 'agent-smoke-1', agentId: 'agent-smoke-1', hostname: `host ${PAYLOAD}`, os: 'windows', platform: 'windows',
  ip: '10.0.0.5', state: 'active', status: 'online', online: true, version: '1.0.0', lastSeen: NOW, lastHeartbeat: NOW,
  groupId: null, tags: [], capabilities: [],
};

const run = {
  id: 'run-smoke-1', name: `Run ${PAYLOAD}`, scenarioId: 'sc-smoke-1', scenarioName: `Scenario ${PAYLOAD}`,
  status: 'completed', mode: 'standard', agentId: 'agent-smoke-1', hostname: `host ${PAYLOAD}`,
  startedAt: NOW, finishedAt: NOW, createdAt: NOW, score: 80, passed: 4, failed: 1, total: 5,
  progress: { stepsTotal: 5, stepsDone: 5 },
};

const finding = {
  id: 'finding-smoke-1', techniqueId: 'T1082', techniqueName: `System Info ${PAYLOAD}`, title: `Finding ${PAYLOAD}`,
  severity: 'high', status: 'open', runId: 'run-smoke-1', agentId: 'agent-smoke-1', hostname: `host ${PAYLOAD}`,
  createdAt: NOW, updatedAt: NOW, firstSeen: NOW, lastSeen: NOW, enrichment: {},
};

const campaign = {
  id: 'campaign-smoke-1', name: `Campaign ${PAYLOAD}`, description: PAYLOAD, status: 'draft',
  createdAt: NOW, updatedAt: NOW, scenarioIds: [], steps: [], targets: [],
};

export const FIXTURES = {
  'GET /ready': { version: '0.0.0-smoke' },
  'GET /api/license/status': { state: 'valid' },
  'GET /api/auth/me': { username: 'smoke', role: 'admin' },
  // Paged when called with ?limit (Agents tab), a plain list otherwise.
  'GET /api/agents': (u) => (u.searchParams.has('limit')
    ? { items: [agent], next_cursor: '', has_more: false, totals: { online: 1, degraded: 0, offline: 0, retired: 0 } }
    : [agent]),
  'GET /api/agents/legacy-migration-status': { blockingAgents: [], unattributedRequests: null },
  'GET /api/agent-groups': [{ id: 1, name: `Group ${PAYLOAD}`, totalAgentCount: 1, agentCount: 1, children: [] }],
  'GET /api/scenarios/runs': [run],
  'GET /api/findings': [finding],
  'GET /api/campaigns': [campaign],
  // Variants tab polls this every 3s; a non-list makes it toast forever.
  'GET /api/vex/sweeps': [],
  // Loaded at boot by loadScenarios(); the {} default made .map throw, and the
  // resulting toast landed on whichever tab was open (flaky in CI).
  'GET /api/scenarios': [],
};

// Text each tab must show once its fixture renders (payloads appear as
// literal text, which also proves they were escaped, not parsed).
export const RENDER_MARKERS = {
  agents: 'host "><img',
  runs: 'Run "><img',
  findings: '"><img src=x',
  campaigns: 'Campaign "><img',
};

export function fixtureFor(method, url) {
  const key = `${method} ${url.pathname}`;
  if (!Object.prototype.hasOwnProperty.call(FIXTURES, key)) return {};
  const v = FIXTURES[key];
  return typeof v === 'function' ? v(url) : v;
}
