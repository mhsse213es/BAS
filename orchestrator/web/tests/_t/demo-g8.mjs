// Dummy-data overrides, page group 8 (Live Runs page redesign). Real response shapes, sample values.
//   GET /api/scenarios/runs -> the g7 runs, with the states the page lays out: one queued (pending) run, one run that
//                              failed before any step (failReason set, no results), one partial run (progress only, no results)
//                              and one paused run. Finished runs also carry what the results drawer reads: timed steps
//                              (startedAt/durationMs), severity, detection verdicts, score.tacticBreakdown and reverted[].
import { DEMO as demoG7 } from './demo-g7.mjs';

const base = demoG7['GET /api/scenarios/runs'];
const VERDICT = { pass: 'prevented', blocked: 'prevented', fail: 'undetected', error: '' };
const SEV = ['critical', 'high', 'medium', 'low'];
const REVERTED = ['Registry key HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater removed', 'File C:\\Users\\Public\\svchost32.exe deleted', 'Scheduled task "SyncUpdate" removed', 'Service "wsvc" stopped and deleted'];

function enrich(r, n) {
  const t0 = new Date(r.startedAt).getTime();
  const results = (r.results || []).map((c, k) => ({
    ...c, startedAt: new Date(t0 + k * 41000).toISOString(), executedAt: new Date(t0 + k * 41000 + 3000).toISOString(), durationMs: 1200 + ((n * 3 + k * 7) % 9) * 650,
    severity: SEV[(n + k) % 4], framework: k % 3 === 2 ? 'caldera' : 'art', stepName: c.name,
    detectionVerdict: c.result === 'fail' && k % 2 === 0 ? 'detected' : VERDICT[c.result] || '',
  }));
  const tb = {};
  results.forEach((c) => {
    const t = c.technique.tactic;
    tb[t] = tb[t] || { passed: 0, failed: 0, passPct: 0 };
    if (c.result === 'fail') tb[t].failed++; else if (c.result !== 'error') tb[t].passed++;
  });
  Object.values(tb).forEach((e) => { e.passPct = Math.round(e.passed / Math.max(1, e.passed + e.failed) * 100); });
  const sc = r.score && {
    ...r.score, totalTechniques: results.length, tacticBreakdown: tb, killChainCoverage: Math.round(Object.keys(tb).length / 14 * 100), killChainAmplifier: 1,
    previousPreventionScore: r.score.trend === 'Baseline' ? undefined : Math.max(0, r.score.preventionScore - 6), confidence: 100,
  };
  return { ...r, results, score: sc, reverted: REVERTED };
}

export const DEMO = {
  'GET /api/scenarios/runs': (u) => base(u).map((r, n) => {
    if (r.id === 'run-8') return { ...r, status: 'pending', results: [], score: undefined, completedAt: undefined, finishedAt: undefined, progress: { stepsTotal: 7, stepsDone: 0, stepsPassed: 0, stepsFailed: 0 } };
    if (r.id === 'run-10') return { ...r, status: 'failed', results: [], score: undefined, detectedTechs: {}, progress: undefined, failReason: 'Agent is offline — could not deliver the run' };
    if (r.id === 'run-12') return { ...r, status: 'partial', results: [], score: undefined, detectedTechs: {}, progress: { stepsTotal: 8, stepsDone: 5, stepsPassed: 3, stepsFailed: 2 } };
    if (r.id === 'run-6') return { ...r, paused: true };
    return r.status === 'completed' ? enrich(r, n) : r;
  }),
};
