// Dummy-data overrides, page group 17: Email (real response shapes of /api/emailgw/coverage, /metrics, -runs, -campaigns).
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();

const coverage = () => ({
  summary: '6 of 7 email security areas are exercised by the scenarios.',
  areas: [
    { areaId: 'A', areaName: 'Sender Identity / Spoofing / Trust', status: 'covered' },
    { areaId: 'B', areaName: 'Phishing / Social Engineering', status: 'covered' },
    { areaId: 'C', areaName: 'Attachments / Content Inspection', status: 'covered' },
    { areaId: 'D', areaName: 'URL / Browser / Post-Delivery Protection', status: 'covered' },
    { areaId: 'E', areaName: 'Outbound Security / DLP', status: 'covered' },
    { areaId: 'F', areaName: 'Mailbox / Identity / Tenant Security', status: 'not-covered' },
    { areaId: 'G', areaName: 'Detection / IR / Resilience', status: 'excluded', exclusionReason: 'Needs a SIEM connector' },
  ],
});
const dim = (s, f, i, t) => ({ outcomes: { confirmedSuccess: s, confirmedFailure: f, inconclusive: i, notTested: t, notApplicable: 0 } });
const lat = (mean, n) => ({ sufficient: true, meanSeconds: mean, medianSeconds: mean, sampleCount: n, minimumSampleSize: 5 });
const metrics = () => ({
  lab: { runsConsidered: 14, prevention: dim(10, 3, 1, 0), detection: { ...dim(8, 4, 2, 0), latency: lat(252, 8) }, response: { ...dim(6, 5, 1, 2), latency: lat(660, 6) } },
  customer: { runsConsidered: 9, prevention: dim(5, 3, 1, 0), detection: { ...dim(4, 3, 1, 1), latency: { sufficient: false, sampleCount: 2, minimumSampleSize: 5 } }, response: { ...dim(2, 2, 1, 4), latency: { unavailable: true } } },
});
const run = (id, scenarioId, status, env, minAgo, error) => ({ id, scenarioId, status, environment: env, startedAt: iso(minAgo), error,
  result: status === 'completed' ? { prevention: { verdict: 'confirmed-success' }, detectionVerdict: { verdict: 'confirmed-failure' }, responseVerdict: { verdict: 'inconclusive' } } : null });
const runs = () => [
  run('r1', 'EG-001.spf.known-bad', 'completed', 'lab', 40),
  run('r2', 'EG-004.known-bad', 'completed', 'customer', 180),
  run('r3', 'EG-011.qr-code-lure.known-bad', 'running', 'lab', 5),
  run('r4', 'EG-002.known-bad', 'failed', 'customer', 1500, 'Mailbox probe timed out waiting for delivery'),
  run('r5', 'EG-003.url-rewrite.known-good', 'completed', 'lab', 3000),
];
const campaigns = () => [
  { id: 'camp-0007', templateId: 'bec-supplier-fraud', status: 'completed', createdAt: iso(2900), completedAt: iso(2880) },
  { id: 'camp-0008', templateId: 'credential-phishing-url-chain', status: 'running', createdAt: iso(25), completedAt: null },
  { id: 'camp-0009', templateId: 'bec-supplier-fraud', status: 'failed', createdAt: iso(5000), completedAt: iso(4990) },
];

export const DEMO = {
  'GET /api/emailgw/coverage': coverage,
  'GET /api/emailgw/metrics': metrics,
  'GET /api/emailgw-runs': runs,
  'GET /api/emailgw-campaigns': campaigns,
};
