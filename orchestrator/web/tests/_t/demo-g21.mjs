// Dummy-data overrides, page group 21: Reports (history log, compliance framework scores, SLA report).
// Response shapes follow GET /api/reports, /api/compliance/frameworks, /api/compliance/scores, /api/sla/report.
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (hAgo) => new Date(NOW - hAgo * 3_600_000).toISOString();

const reports = () => [
  { id: 'a41c09e7d2b34f10', reportType: 'posture', format: 'html', scopeLabel: 'FIN-WS-02', source: 'reports_hub', status: 'generated', generatedBy: 'admin', generatedAt: iso(2), downloadPath: '/api/report/full/html?agentId=FIN-WS-02' },
  { id: '7be2f15a90c84d33', reportType: 'compliance', format: 'html', scopeLabel: 'PCI-DSS v4.0 · FIN-WS-02', source: 'reports_hub', status: 'generated', generatedBy: 'compliance', generatedAt: iso(30), downloadPath: '/api/compliance/report?framework=pci&agentId=FIN-WS-02&format=html' },
  { id: '3d90b6c1e8a74b52', reportType: 'audit', format: '', scopeLabel: 'ENG-LNX-02', source: 'reports_hub', status: 'generated', generatedBy: 'analyst.r', generatedAt: iso(74), downloadPath: '/api/report/audit-pack?agentId=ENG-LNX-02' },
  { id: '58f1a2d7c3e94a08', reportType: 'posture', format: 'csv', scopeLabel: 'HR-MAC-01', source: 'reports_hub', status: 'failed', generatedBy: 'admin', generatedAt: iso(120), downloadPath: '/api/report/full/csv?agentId=HR-MAC-01' },
  { id: 'c20e7b94a1d64f77', reportType: 'compliance', format: 'csv', scopeLabel: 'ISO 27001 · ENG-LNX-01', source: 'reports_hub', status: 'generated', generatedBy: 'compliance', generatedAt: iso(240), downloadPath: '/api/compliance/report?framework=iso&agentId=ENG-LNX-01&format=csv' },
];

const frameworks = () => [
  { id: 'pci', name: 'PCI-DSS v4.0', regulator: 'PCI SSC' },
  { id: 'iso', name: 'ISO 27001:2022', regulator: 'ISO' },
  { id: 'nist', name: 'NIST CSF 2.0', regulator: 'NIST' },
  { id: 'rbi', name: 'RBI Cyber Security Framework', regulator: 'RBI' },
];

const score = (id, name, short, reg, tested, pass, fail, testable, total) => ({
  frameworkId: id, frameworkName: name, shortName: short, regulator: reg,
  testedControls: tested, passingControls: pass, failingControls: fail, testableControls: testable, totalControls: total,
  compliancePct: tested ? Math.round(pass / tested * 100) : 0, coveragePct: testable ? Math.round(tested / testable * 100) : 0, untestedControls: Math.max(0, testable - tested),
});
const scores = () => [
  score('pci', 'PCI-DSS v4.0', 'pci', 'PCI SSC', 14, 12, 2, 20, 64),
  score('iso', 'ISO 27001:2022', 'iso', 'ISO', 19, 15, 4, 30, 93),
  score('nist', 'NIST CSF 2.0', 'nist', 'NIST', 12, 6, 6, 22, 106),
  score('rbi', 'RBI Cyber Security Framework', 'rbi', 'RBI', 0, 0, 0, 18, 40),
  score('sebi', 'SEBI CSCRF', 'sebi', 'SEBI', 6, 4, 2, 12, 39),
  score('certin', 'CERT-In Directions', 'cert-in', 'CERT-In', 5, 3, 2, 10, 28),
  score('irdai', 'IRDAI Cyber Security', 'irdai', 'IRDAI', 4, 3, 1, 9, 24),
];

const slaReport = () => ({
  overall: { totalEpisodes: 36, onTime: 22, late: 4, currentlyOpen: 10, complianceRate: 84.6 },
  bySeverity: [
    { severity: 'High', onTime: 8, late: 3, currentlyOpen: 5, complianceRate: 72.7 },
    { severity: 'Critical', onTime: 5, late: 0, currentlyOpen: 2, complianceRate: 100 },
    { severity: 'Medium', onTime: 7, late: 1, currentlyOpen: 3, complianceRate: 87.5 },
    { severity: 'Low', onTime: 2, late: 0, currentlyOpen: 0, complianceRate: 100 },
  ],
  monthlyTrend: [
    { month: '2026-07', resolved: 5, onTime: 4, complianceRate: 80 },
    { month: '2026-08', resolved: 6, onTime: 5, complianceRate: 83.3 },
    { month: '2026-09', resolved: 8, onTime: 7, complianceRate: 87.5 },
    { month: '2026-10', resolved: 7, onTime: 6, complianceRate: 85.7 },
  ],
  recentlyResolved: [
    { agentId: 'FIN-WS-02', checkId: 'edr-runkey-persistence', severity: 'High', startedAt: iso(24 * 12), resolvedAt: iso(24 * 3), deadlineAt: iso(24 * 2), onTime: true },
    { agentId: 'ENG-LNX-02', checkId: 'av-eicar-detect', severity: 'Critical', startedAt: iso(24 * 9), resolvedAt: iso(24 * 5), deadlineAt: iso(24 * 2), onTime: true },
    { agentId: 'HR-MAC-01', checkId: 'dns-tunnel-block', severity: 'Medium', startedAt: iso(24 * 40), resolvedAt: iso(24 * 6), deadlineAt: iso(24 * 10), onTime: false },
    { agentId: 'ENG-LNX-01', checkId: 'sudo-cache-timeout', severity: 'Low', startedAt: iso(24 * 20), resolvedAt: iso(24 * 8), deadlineAt: iso(24 * 3), onTime: true },
  ],
});

export const DEMO = {
  'GET /api/reports': reports,
  'GET /api/compliance/frameworks': frameworks,
  'GET /api/compliance/scores': scores,
  'GET /api/sla/report': slaReport,
};
