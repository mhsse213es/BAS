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

// Ransomware Readiness panel (ransomware.js loadRansomwareReadiness, fired
// from evidence.js's dashboard load on Agents > Operational view): needs a
// run with this exact scenarioId and a non-empty `results` array to resolve
// rrRun truthy. Mixed pass/fail across categories so the score gauge and
// at least one category bar render their g1-v color/width rules.
const rrRun = {
  id: 'run-rr-smoke-1', name: `RR Run ${PAYLOAD}`, scenarioId: 'ransomware-drill',
  status: 'completed', startedAt: NOW, completedAt: NOW,
  results: [
    { phase: 'prevention-posture', result: 'pass' },
    { phase: 'prevention-posture', result: 'pass' },
    { phase: 'prevention-posture', result: 'fail' },
    { phase: 'backup-resilience', result: 'pass' },
    { phase: 'backup-resilience', result: 'pass' },
    { phase: 'backup-resilience', result: 'pass' },
    { phase: 'recovery-posture', result: 'fail' },
    { phase: 'recovery-posture', result: 'fail' },
  ],
};

// Compliance dashboard tile (compliance.js complianceTile, fired from
// evidence.js's dashboard load): hasData=true (testedControls>0) so the
// kpi-card border-left/score-value colors and the coverage bar both
// render; failingControls>0 and coveragePct<50 also exercise the
// gating/low-coverage notes.
const complianceScore = {
  frameworkId: 'nist-800-53', agentId: 'agent-smoke-1', frameworkName: `NIST 800-53 ${PAYLOAD}`,
  shortName: 'NIST 800-53', regulator: 'NIST',
  compliancePct: 72, coveragePct: 40, testedControls: 20, passingControls: 14,
  failingControls: 6, untestedControls: 10, testableControls: 30, totalControls: 50,
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

// Scheduled Assessments rows (jobs.Schedule, PascalCase, no JSON tags
// server-side -- see scheduled.js's own comment). Three rows exercise every
// modeColor/statusColor either-or branch the G1e codemod produced:
// telemetry+enabled (warning/success), posture+disabled (muted/muted), and
// a completed one-time run (muted mode/accent status).
const schedule1 = {
  ID: 'sched-smoke-1', Mode: 'telemetry', Enabled: true, RecurrenceType: 'weekly',
  DayOfWeek: 1, TimeOfDay: '02:00', Timezone: 'UTC', GroupIDs: [], AgentIDs: ['agent-smoke-1'],
  Payload: { scenarioId: 'sc-smoke-1' }, LastOccurrenceAt: null,
};
const schedule2 = {
  ID: 'sched-smoke-2', Mode: 'posture', Enabled: false, RecurrenceType: 'weekly',
  DayOfWeek: 3, TimeOfDay: '04:00', Timezone: 'UTC', GroupIDs: [], AgentIDs: [],
  Payload: { scenarioId: 'sc-smoke-1' }, LastOccurrenceAt: null,
};
const schedule3 = {
  ID: 'sched-smoke-3', Mode: 'posture', Enabled: true, RecurrenceType: 'once',
  RunAt: NOW, Timezone: 'UTC', GroupIDs: [], AgentIDs: [],
  Payload: { scenarioId: 'sc-smoke-1' }, LastOccurrenceAt: NOW,
};

// Agent Risk & Remediation table (shell.js renderAgentRiskSummary): one
// measurable row so the healthScore cell's g1-v color rule renders.
const riskAgent = {
  agentId: 'agent-smoke-1', hostname: `host ${PAYLOAD}`, measurable: true,
  healthScore: 82, criticalityRisk: 2, trend: 'Improving', topDeficitCategory: 'Patch', openFindingsCount: 1,
};

// Initiative Layer (initiatives.js): one active initiative so the list row
// and its drawer (progress bar's g1-v width rule) both render.
const initiative1 = {
  ID: 'init-smoke-1', Name: `Initiative ${PAYLOAD}`, State: 'active',
  CreatedBy: 'smoke', CreatedAt: NOW, Description: `Desc ${PAYLOAD}`,
};

// Live Run replay: ART steps carry a techniqueId, which drives the ART
// catalog lookup (G1c final review C1 broke exactly this path).
const runEvents = [
  { type: 'run_started', taskId: '', payload: { stepsTotal: 2 } },
  { type: 'queued', taskId: 'task-1', techniqueId: 'T1059', stepName: `Step ${PAYLOAD}` },
  { type: 'started', taskId: 'task-1', techniqueId: 'T1059' },
  { type: 'completed', taskId: 'task-1', techniqueId: 'T1059', payload: { verdict: 'pass', durationMs: 1200 } },
];

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
  'GET /api/scenarios/runs': [run, rrRun],
  'GET /api/compliance/scores': [complianceScore],
  'GET /api/findings': [finding],
  'GET /api/campaigns': [campaign],
  // Variants tab polls this every 3s; a non-list makes it toast forever.
  'GET /api/vex/sweeps': [],
  // Loaded at boot by loadScenarios(); the {} default made .map throw, and the
  // resulting toast landed on whichever tab was open (flaky in CI).
  'GET /api/scenarios': [],
  'GET /api/scheduled-assessments': { schedules: [schedule1, schedule2, schedule3] },
  'GET /api/agents/risk-summary': { agents: [riskAgent] },
  'GET /api/initiatives': { initiatives: [initiative1] },
  'GET /api/initiatives/init-smoke-1': { initiative: initiative1, progress: { PercentComplete: 45 }, jobs: [] },
  // Drawers (smoke.spec.mjs "drawers"): detail endpoints for the list fixtures.
  'GET /api/scenarios/runs/run-smoke-1/events': runEvents,
  'GET /api/findings/finding-smoke-1': finding,
  'GET /api/campaigns/campaign-smoke-1': campaign,
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
