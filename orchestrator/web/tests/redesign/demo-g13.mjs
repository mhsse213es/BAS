// Dummy-data overrides, page group 13: Factory Health (real response shape of GET /api/analytics/factory-health).
import { DEMO as G2 } from './demo-g2.mjs';

const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();
const day = (n) => new Date(NOW - n * 86_400_000).toISOString().slice(0, 10);

const factory = () => {
  const f = G2['GET /api/analytics/factory-health']();
  f.pipeline.ingestion.sources = [
    { sourceInstanceId: 'src-mitre', displayName: 'MITRE ATT&CK', lastSuccessAt: iso(360), failuresInWindow: 0, lastDiagnostic: '' },
    { sourceInstanceId: 'src-kev', displayName: 'CISA KEV', lastSuccessAt: iso(95), failuresInWindow: 0, lastDiagnostic: '' },
    { sourceInstanceId: 'src-otx', displayName: 'AlienVault OTX', lastSuccessAt: iso(3000), failuresInWindow: 3, lastDiagnostic: 'HTTP 429 rate limited by upstream' },
    { sourceInstanceId: 'src-misp', displayName: 'MISP (internal)', lastSuccessAt: iso(40), failuresInWindow: 0, lastDiagnostic: '' },
    { sourceInstanceId: 'src-octi', displayName: 'OpenCTI', lastSuccessAt: null, failuresInWindow: 1, lastDiagnostic: 'connector not configured' },
  ];
  f.trends.threatsProcessedByDay = [38, 44, 41, 52, 47, 63, 58, 49, 71, 66, 60, 74, 69, 82].map((value, i, a) => ({ day: day(a.length - i), value }));
  return f;
};

export const DEMO = { 'GET /api/analytics/factory-health': factory };
