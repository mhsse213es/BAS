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

// Per-run indicators (iocs.js renderRunIOCToolbar/renderRunIOCList, fired
// from reports.js's viewRunResults "run results" drawer): one entry so the
// tier badge and row header render.
const runIOC = { type: 'ip', value: `5.6.7.8 ${PAYLOAD}`, source: 'ART', tier: 'suspicious', pulseCount: 2 };

// Cross-run IOC registry + analytics tiles (iocs.js loadIOCRegistry, fired
// automatically on the 'iocs' tab): suppressed:true so the suppressed badge
// renders too (ROLE is 'admin' per the auth fixture, so the suppress button
// always renders regardless).
const iocRegistryRow = {
  id: 'ioc-smoke-1', type: 'ip', value: `1.2.3.4 ${PAYLOAD}`, source: 'ART', origin: 'run',
  status: 'active', sightingCount: 3, firstSeen: NOW, lastSeen: NOW,
  suppressed: true, suppressionReason: 'known-good',
};
const iocAnalytics = {
  mostDetected: [{ value: `evil.exe ${PAYLOAD}`, sightingCount: 7 }],
  highestBypassRate: [], frequentlyReused: [], longestSurviving: [],
};

// ATT&CK Coverage tab (coverage.js loadCoverageAnalytics/loadUnifiedTechniques/
// loadCoverage, all fired on 'coverage' tab visit): 3 tiers (success/warning/
// danger rateColor branches) with mixed missed=0/missed>0 rows, a gapTechs
// row spanning 2 tiers (exercises the tier-badge border+color pair), and a
// byTactic/byTechnique pair exercising both zebra-stripe and verdict-color
// branches.
const coverageAnalytics = {
  runsAnalyzed: 3,
  summary: { attempted: 20, prevented: 14, detectedOnly: 4, missed: 2, preventionRate: 70, detectionCoverage: 90 },
  byTactic: [
    { tactic: 'Execution', prevented: 5, detectedOnly: 1, missed: 0 },
    { tactic: 'Persistence', prevented: 3, detectedOnly: 0, missed: 1 },
  ],
  byTechnique: [
    { techniqueId: 'T1059', name: `Command Scripting ${PAYLOAD}`, runCount: 4, bestVerdict: 'missed' },
    { techniqueId: 'T1547', name: `Boot Persist ${PAYLOAD}`, runCount: 2, bestVerdict: 'detectedOnly' },
  ],
  privilegeCoverage: {
    byTier: [
      { tier: 'user', attempted: 10, prevented: 9, preventionRate: 90, missed: 0 },
      { tier: 'admin', attempted: 6, prevented: 3, preventionRate: 50, missed: 2 },
      { tier: 'system', attempted: 4, prevented: 1, preventionRate: 25, missed: 1 },
    ],
    gapTechs: [
      { techniqueId: 'T1068', name: `Privilege Escalation ${PAYLOAD}`, tiers: ['admin', 'system'] },
    ],
  },
};

// Unified Technique Library (coverage.js loadUnifiedTechniques).
const unifiedTechnique = {
  techniqueId: 'T1082', name: `System Info ${PAYLOAD}`, tactic: 'Discovery',
  basCount: 2, artCount: 1, emuCount: 0, atomicCount: 3, totalVariants: 6,
};

// ATT&CK coverage matrix (coverage.js loadCoverage).
const attackMatrix = {
  tactics: [
    { name: 'Discovery', techniques: [{ id: 'T1082', name: `System Info ${PAYLOAD}` }] },
  ],
};

// License panel (audit-logs.js loadLicenseInfo, Settings > License):
// status 'grace' exercises the daysRemaining/lockoutAt extra row and the
// warning statusColor branch (distinct from the backups fixture below's
// success/danger branches).
const license = {
  status: 'grace', customer: `Acme Corp ${PAYLOAD}`, customerId: 'cust-smoke-1',
  issuedAt: '2026-01-01', expiresAt: '2026-12-31', daysRemaining: 14,
  lockoutAt: '2027-01-14', features: ['ransomware', 'purple-team'],
};

// Backup jobs (audit-logs.js loadBackups, Settings > Backup): two jobs
// exercise success (protected, canRestore) and danger (remote_failed,
// with errorMessage) status-color branches.
const backupJob1 = {
  id: 'backup-smoke-1', status: 'protected', archiveSizeBytes: 5242880,
  requestedAt: NOW, trigger: 'manual', localPath: '/backups/1.tar.gz', remotePath: 's3://bucket/1.tar.gz',
};
const backupJob2 = {
  id: 'backup-smoke-2', status: 'remote_failed', archiveSizeBytes: 3145728,
  requestedAt: NOW, trigger: 'scheduled', localPath: '/backups/2.tar.gz', remotePath: null,
  errorMessage: `Upload failed ${PAYLOAD}`,
};

// Audit log entries (audit-logs.js loadAuditLogs, Settings > Audit Log):
// one 'ok' and one failing outcome exercise both outcome-badge classes.
const auditEntry1 = {
  ts: NOW, actorName: `admin ${PAYLOAD}`, action: 'user.login', outcome: 'ok',
  ip: '10.0.0.9', detail: JSON.stringify({ username: 'admin' }),
};
const auditEntry2 = {
  ts: NOW, actorName: `admin ${PAYLOAD}`, action: 'user.login', outcome: 'denied',
  ip: '10.0.0.9', detail: JSON.stringify({ username: 'admin', reason: 'bad password' }),
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
  'GET /api/coverage/analytics': coverageAnalytics,
  'GET /api/techniques/unified': [unifiedTechnique],
  'GET /api/attack/matrix': attackMatrix,
  'GET /api/license': license,
  'GET /api/backups': [backupJob1, backupJob2],
  'GET /api/audit-logs': { entries: [auditEntry1, auditEntry2] },
  'GET /api/scenarios/runs/run-smoke-1/iocs': [runIOC],
  'GET /api/iocs': [iocRegistryRow],
  'GET /api/analytics/iocs': iocAnalytics,
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
