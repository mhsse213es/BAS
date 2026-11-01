// Dummy-data overrides for the redesigned Dashboard: real response shapes, sample values.
//   GET /api/notifications                       -> { notifications: [notifications.Event ...] } (Go struct, PascalCase)
//   GET /api/analytics/threat-intel-summary      -> topActors carry techniqueCount / coverageGapCount / trend
//   GET /api/ti/readiness/history                -> trends carry a `history` array (newest first)
//   GET /api/compliance/scores                   -> the seventh framework (PCI DSS)
//   GET /api/tamper-events                       -> none (an unacknowledged tamper event shows a red banner that hides the logo)
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();
const DAY = 1440;

const fw = (frameworkId, frameworkName, shortName, regulator, totalControls, testableControls, testedControls, passingControls) => ({
  frameworkId, frameworkName, shortName, regulator, enrolledAgentCount: 12, totalControls, testableControls, testedControls, passingControls,
  failingControls: testedControls - passingControls, untestedControls: testableControls - testedControls,
  compliancePct: Math.round((passingControls / testedControls) * 1000) / 10, coveragePct: Math.round((testedControls / testableControls) * 1000) / 10,
});
const COMPLIANCE = [
  fw('sebi-cscrf', 'SEBI Cybersecurity and Cyber Resilience Framework', 'SEBI CSCRF', 'SEBI', 96, 58, 46, 34),
  fw('rbi-csf', 'RBI Cyber Security Framework for Banks', 'RBI CSF', 'RBI', 118, 72, 61, 49),
  fw('irdai-iscg', 'IRDAI Information and Cyber Security Guidelines', 'IRDAI', 'IRDAI', 84, 50, 36, 22),
  fw('cert-in', 'CERT-In Directions (28 April 2022)', 'CERT-In', 'CERT-In', 24, 14, 12, 10),
  fw('iso-27001', 'ISO/IEC 27001:2022 Annex A', 'ISO 27001', 'ISO', 93, 61, 52, 41),
  fw('nist-csf', 'NIST Cybersecurity Framework 2.0', 'NIST CSF', 'NIST', 106, 68, 57, 43),
  fw('pci-dss-4', 'PCI DSS v4.0', 'PCI DSS V4', 'PCI SSC', 64, 40, 35, 29),
];

const TI = {
  topActors: [
    { actorName: 'FIN7', score: 91, tier: 'Critical', techniqueCount: 38, coverageGapCount: 11, trend: 'rising', trendDelta: 6, canonicalGroupId: 'G0046' },
    { actorName: 'APT29', score: 84, tier: 'High', techniqueCount: 54, coverageGapCount: 7, trend: 'stable', canonicalGroupId: 'G0016' },
    { actorName: 'Scattered Spider', score: 79, tier: 'High', techniqueCount: 31, coverageGapCount: 9, trend: 'rising', trendDelta: 4, canonicalGroupId: 'G1015' },
    { actorName: 'LockBit 3.0', score: 63, tier: 'Medium', techniqueCount: 47, coverageGapCount: 6, trend: 'falling', trendDelta: 3 },
    { actorName: 'APT41', score: 58, tier: 'Medium', techniqueCount: 44, coverageGapCount: 5, trend: 'stable', canonicalGroupId: 'G0096' },
  ],
  kevExposedTechniques: 27, totalKevCves: 143,
};

const hist = (actor, values) => values.map((v, i) => ({
  runId: `rr-${actor}-${i}`, actorName: actor, prevention: v, detection: Math.min(100, v + 8), tested: 12, total: 14, confidence: 'medium',
  recordedAt: iso((values.length - 1 - i) * 2 * DAY + 60),
})).reverse();
const trend = (actor, values) => {
  const h = hist(actor, values);
  const latest = values[values.length - 1], delta = Math.round((latest - values[0]) * 10) / 10;
  return { actorName: actor, latestPrevention: latest, latestDetection: Math.min(100, latest + 8), preventionDelta: delta, detectionDelta: delta,
    direction: delta > 1 ? 'up' : delta < -1 ? 'down' : 'stable', dataPoints: values.length, history: h };
};
const READINESS = {
  agentId: 'a-1', total: 6,
  trends: [
    trend('FIN7', [64, 61, 58]), trend('Scattered Spider', [52, 51, 49]), trend('APT29', [64, 69, 72, 78]),
    trend('LockBit 3.0', [77, 79, 81]), trend('Lazarus Group', [64, 66]), trend('APT41', [69, 69, 69]),
  ],
};

const EV = (n, Type, Severity, Message, minAgo) => ({ ID: `ev-${n}`, Type, JobID: `job-${n}`, TargetID: '', AgentID: '', Severity, Message, Metadata: {}, Timestamp: iso(minAgo) });
const NOTIFICATIONS = { notifications: [
  EV(1, 'job_failed', 'error', 'Weekly posture scan failed on 2 of 12 agents', 95),
  EV(2, 'target_offline', 'warning', 'lnx-web-08 went offline during a scheduled assessment', 190),
  EV(3, 'job_completed', 'info', 'Full Security Posture Scan completed', 420),
  EV(4, 'job_partial', 'warning', 'Credential access sweep finished with 1 skipped agent', 1500),
  EV(5, 'job_completed', 'info', 'Nightly ransomware canary completed', 2600),
] };

// rwscore.Score for the Akira run (run-3): the dashboard's Ransomware readiness card reads this.
const dim = (dimension, pass, fail, error = 0, unknown = 0) => ({ dimension, pass, fail, error, unknown, notApplicable: 0, notTested: 0, passRate: pass + fail + error + unknown ? pass / (pass + fail + error + unknown) : 0 });
const RW_SCORE = { overall: 72, rating: 'at_risk', gateTriggered: false, criticalFailures: [], dimensions: [
  dim('prevention', 9, 1), dim('detection', 7, 2), dim('containment', 3, 3), dim('recovery', 4, 0), dim('data_protection', 5, 1) ] };

export const DEMO = {
  'GET /api/scenarios/runs/run-3/rw-score': RW_SCORE,
  'GET /api/tamper-events': [],
  'GET /api/compliance/scores': COMPLIANCE,
  'GET /api/analytics/threat-intel-summary': TI,
  'GET /api/ti/readiness/history': READINESS,
  'GET /api/notifications': NOTIFICATIONS,
};
