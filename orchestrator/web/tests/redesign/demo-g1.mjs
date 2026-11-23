// Dummy-data overrides, page group 1 (Dashboard, Scenarios, Live Runs, Campaigns).
// Runs get the real result/score shape (technique results, weighted score object, detected map) so the
// dashboard charts, the Live Runs strip and the campaign result mix have something to compute from.
import { richRuns } from './fixtures-rich.mjs';

const TECHS = [
  ['T1003', 'OS Credential Dumping', 'credential-access'], ['T1547', 'Boot or Logon Autostart', 'persistence'],
  ['T1021', 'Remote Services', 'lateral-movement'], ['T1059', 'Command and Scripting Interpreter', 'execution'],
  ['T1490', 'Inhibit System Recovery', 'impact'], ['T1486', 'Data Encrypted for Impact', 'impact'],
  ['T1558', 'Steal or Forge Kerberos Tickets', 'credential-access'], ['T1562', 'Impair Defenses', 'defense-evasion'],
  ['T1083', 'File and Directory Discovery', 'discovery'], ['T1566', 'Phishing', 'initial-access'],
];
const NOW = new Date('2026-10-26T09:30:00Z').getTime();

function richRunsG1() {
  return richRuns().map((r, n) => {
    const running = r.status === 'running';
    const results = running ? [] : [0, 1, 2, 3, 4, 5].map((k) => {
      const t = TECHS[(n + k * 3) % TECHS.length];
      const v = (n * 7 + k * 5) % 10;
      return { name: t[1], result: v < 5 ? 'pass' : v < 8 ? 'fail' : v < 9 ? 'blocked' : 'error', technique: { id: t[0], name: t[1], tactic: t[2] } };
    });
    const passed = results.filter((c) => c.result === 'pass' || c.result === 'blocked').length;
    const failed = results.filter((c) => c.result === 'fail').length;
    const detectedTechs = {};
    results.forEach((c, i) => { if (c.result === 'fail' && i % 2 === 0) detectedTechs[c.technique.id] = true; });
    const pct = passed + failed ? Math.round(passed / (passed + failed) * 100) : 0;
    return {
      ...r, scenarioId: n === 2 ? 'akira-kill-chain' : r.scenarioId, score: results.length ? { preventionScore: pct, exposureScore: 100 - pct, classification: pct >= 70 ? 'Protected' : pct >= 40 ? 'Medium Risk' : 'High Risk', trend: n % 3 === 0 ? 'Improving' : n % 3 === 1 ? 'Degrading' : 'Stable', passedTechniques: passed, failedTechniques: failed } : undefined,
      results, detectedTechs, completedAt: running ? undefined : r.finishedAt, initiatedBy: ['asha.nair', 'scheduler', 'rohan.k'][n % 3],
      progress: running ? { stepsTotal: 7, stepsDone: 4, stepsPassed: 3, stepsFailed: 1 } : r.progress,
      startedAt: new Date(NOW - (30 + n * 700) * 60000).toISOString(),
    };
  });
}

const day = (i) => new Date(NOW - i * 86400000).toISOString().slice(0, 10);
const TREND = (u) => {
  const n = Math.min(Number(u.searchParams.get('days')) || 30, 45);
  return Array.from({ length: n }, (_, i) => ({ date: day(n - 1 - i), avgRiskScore: 60 + Math.round(Math.sin(i / 3) * 4 + i / 6), exposureScore: 80 - Math.round(i / 6), detectionCoverage: 66 + Math.round(i / 4), assetCount: 400 + i }));
};
const HIST = Array.from({ length: 30 }, (_, i) => ({ dayIndex: i, score: 60 + Math.round(Math.sin(i / 3) * 4 + i / 6) }));
const PROJ = Array.from({ length: 10 }, (_, i) => ({ dayIndex: 30 + i, score: 66 + Math.round(i * 0.6), high: 68 + i, low: 64 + Math.round(i * 0.2) }));

export const DEMO = {
  'GET /api/scenarios/runs': () => richRunsG1(),
  'GET /api/dashboard/current': { avgRiskScore: 66, exposureScore: 74, detectionCoverage: 76, assetCount: 428, hasAttackPathData: true },
  'GET /api/dashboard/trends': TREND,
  'GET /api/predict/risk': {
    forecast: { hasForecast: true, direction: 'worsening', confidence: 'medium', history: HIST, projected: PROJ, note: '' },
    exposure: { hasData: true, openCount: 12, worstDaysOpen: 41, medianDaysOpen: 11, overThreshold: 4, thresholdDays: 30, worst: [
      { techniqueId: 'T1558', techniqueName: 'Steal or Forge Kerberos Tickets', severity: 'Critical', daysOpen: 41, firstSeen: day(41), reopenedCount: 1 },
      { techniqueId: 'T1547', techniqueName: 'Boot or Logon Autostart', severity: 'High', daysOpen: 27, firstSeen: day(27), reopenedCount: 0 },
      { techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery', severity: 'High', daysOpen: 11, firstSeen: day(11), reopenedCount: 0 }] },
  },
};
