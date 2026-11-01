// Dummy-data overrides, page group 4: { 'GET /api/path': value | (url) => value }
// Adds the drill-down payloads (exposure drawer, OpenAEV scenario, execution drawer, collection history)
// that the list fixtures in demo-a/demo-b do not cover. Shapes match the real API responses.
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();

const HOSTS = ['ws-fin-0142', 'ws-fin-0143', 'dc-pri-01', 'dc-sec-02', 'fs-leg-01', 'lnx-web-07', 'lnx-web-08', 'lnx-db-02', 'mac-des-221', 'ca-iss-01', '10.20.2.60', '10.20.8.14'];

const exposureDetail = (i) => ({
  scores: {
    exposureScore: 38 + ((i * 7) % 40), exposureMeasurable: true, attackPathScore: 33 + ((i * 5) % 45), attackPathMeasurable: true,
    detectionCoverageScore: 58 + ((i * 3) % 30), detectionMeasurable: i !== 11, vulnerabilityScore: 45 + ((i * 9) % 40), vulnerabilityMeasurable: i % 5 !== 4,
  },
  recommendations: [
    { edge: { from: 'WS-FIN-0143', to: 'FS-LEG-01', kind: 'smb' }, priority: 'High', reason: 'Finance workstation can reach the legal file server over SMB.' },
    { edge: { from: 'FS-LEG-01', to: 'svc-backup', kind: 'has-session' }, priority: 'Critical', reason: 'Backup service account session with no credential-theft detection.' },
  ],
  vulnerabilities: [
    { cveId: 'CVE-2025-33053', cvss: 8.8, kev: true, epssScore: 0.71, techniqueId: 'T1204' },
    { cveId: 'CVE-2025-21298', cvss: 9.8, kev: false, epssScore: 0.34, techniqueId: 'T1203' },
  ],
  findings: { collected: i !== 10, findings: [{ techniqueName: 'Credential Dumping via LSASS', techniqueId: 'T1003', severity: 'critical', exposureState: 'open' }, { techniqueName: 'Persistence via Run Key', techniqueId: 'T1547', severity: 'medium', exposureState: 'open' }] },
  threatIntel: [{ groupName: 'APT29' }, { groupName: 'FIN7' }],
});

const execDetail = (id, name, status, score) => ({
  execution: { id, name, status, score },
  steps: [
    { step_id: 'step-1-phish', step_type: 'send_email', status: 'completed', result: { sent: 24, delivered: 24 } },
    { step_id: 'step-2-approve', step_type: 'approval', status: status === 'paused' ? 'waiting' : 'completed' },
    { step_id: 'step-3-wait', step_type: 'wait', status: 'completed' },
    { step_id: 'step-4-agent', step_type: 'agent_task', status: status === 'running' ? 'running' : 'completed', error: status === 'aborted' ? 'aborted by operator' : undefined },
  ],
});

export const DEMO = {
  'GET /api/attackpath/history': [
    { collectedAt: iso(5 * 60), hostname: 'DC-PRI-01', nodeCount: 71, edgeCount: 127, durationMs: 94000, sharpHound: false, status: 'completed' },
    { collectedAt: iso(29 * 60), hostname: 'DC-PRI-01', nodeCount: 69, edgeCount: 121, durationMs: 88000, sharpHound: false, status: 'completed' },
    { collectedAt: iso(53 * 60), hostname: 'FS-LEG-01', nodeCount: 12, edgeCount: 9, durationMs: 21000, sharpHound: false, status: 'failed', errorMsg: 'target unreachable' },
  ],
  'GET /api/openaev/scenarios/oaev-sc-101': {
    scenario: { Name: 'Ransomware precursor: credential theft to file encryption' },
    detail: { description: 'Simulates credential theft, lateral movement over SMB and mass file encryption on a finance file server.', injects: [{ title: 'Dump LSASS memory', techniqueIds: ['T1003'] }, { title: 'Move laterally over SMB', techniqueIds: ['T1021'] }, { title: 'Encrypt shared documents', techniqueIds: ['T1486'] }] },
  },
  'GET /api/exercises/executions/exec-310': execDetail('exec-310', 'Domain controller attack path rehearsal', 'running', null),
  'GET /api/exercises/executions/exec-308': execDetail('exec-308', 'BEC response walkthrough', 'completed', { measurable: true, overall: 72, human: { sent: 24, clicked: 5, click_rate: 0.21 }, technical: { edr_detected: true }, management: { sla_met: true } }),
  ...Object.fromEntries(HOSTS.map((h, i) => [`GET /api/exposure/assets/${h}`, exposureDetail(i)])),
};
