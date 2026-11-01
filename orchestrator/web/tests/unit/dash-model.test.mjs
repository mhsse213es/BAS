import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const M = await import('../../src/features/dash-model.js');
const R = await import('../../src/features/dash-rich.js');

const res = (id, tactic, result) => ({ result, technique: { id, name: 'N ' + id, tactic } });
const run = (results, extra) => Object.assign({ id: 'r' + Math.random(), results, startedAt: '2026-10-25T10:00:00Z' }, extra);

test('verdict: prevented, detected-only, missed and other', () => {
  assert.equal(M.verdict({ result: 'blocked' }, {}), 'prevented');
  assert.equal(M.verdict(res('T1', 'x', 'fail'), { T1: true }), 'detected');
  assert.equal(M.verdict(res('T1', 'x', 'fail'), {}), 'missed');
  assert.equal(M.verdict({ result: 'error' }, {}), 'other');
});

test('effectiveness tallies every result and ignores missing runs', () => {
  const e = M.effectiveness([run([res('T1', 'a', 'pass'), res('T2', 'a', 'fail'), res('T3', 'b', 'skipped')], { detectedTechs: { T2: true } })]);
  assert.deepEqual([e.prevented, e.detected, e.missed, e.other, e.total], [1, 1, 0, 1, 3]);
  assert.equal(M.effectiveness(null).total, 0);
});

test('postureWindow is the unweighted mean of the backend per-run preventionScore and the backend trend', () => {
  // Technique counts differ on purpose: the window figure must NOT re-weight by them.
  const sc = (p, pass, fail, trend) => ({ score: { preventionScore: p, passedTechniques: pass, failedTechniques: fail, trend } });
  const runs = [sc(90, 1, 0, 'Improving'), sc(80, 20, 0, 'Stable'), sc(40, 4, 6, 'Degrading'), sc(30, 3, 7, 'Stable'), sc(0, 0, 0)];
  const w = M.postureWindow(runs, 8);
  assert.equal(w.count, 4, 'the run with no scoreable results is not scored');
  assert.equal(w.pct, Math.round((90 + 80 + 40 + 30) / 4), 'mean of the four run scores, unweighted');
  assert.equal(w.trend, 'Improving', 'backend trend of the newest scored run');
  assert.deepEqual(w.series, [30, 40, 80, 90]);
  assert.equal(M.postureWindow([], 8), null);
});

test('coverage reports its numerator and denominator', () => {
  const runs = [run([res('T1', 'a', 'pass'), res('T2', 'a', 'fail')]), run([res('T2', 'a', 'pass'), res('T3', 'a', 'fail')])];
  const c = M.coverage(runs);
  assert.equal(c.tested, 3);
  assert.equal(c.prevented, 2, 'T1 and T2 were prevented in at least one run');
  assert.equal(c.pct, 67);
});

test('topFailing and coverageGaps rank by failures and by prevention rate', () => {
  const runs = [run([res('T1', 'a', 'fail'), res('T1', 'a', 'pass'), res('T2', 'a', 'fail'), res('T3', 'a', 'pass')]), run([res('T1', 'a', 'fail'), res('T2', 'a', 'fail')])];
  const f = M.topFailing(runs, 5);
  assert.deepEqual(f.map((t) => [t.id, t.fail, t.pct]), [['T1', 2, 33], ['T2', 2, 0]]);
  assert.deepEqual(M.coverageGaps(runs, 5).map((t) => t.id), ['T2', 'T1']);
});

test('tacticRows and flowByTactic come out in kill-chain order', () => {
  const runs = [run([res('T1', 'impact', 'pass'), res('T2', 'execution', 'fail'), res('T3', 'execution', 'pass')], { detectedTechs: { T2: true } })];
  assert.deepEqual(M.tacticRows(runs).map((r) => [r.tactic, r.pct]), [['execution', 50], ['impact', 100]]);
  assert.deepEqual(M.flowByTactic(runs).map((r) => [r.tactic, r.prevented, r.detected, r.missed]), [['execution', 1, 1, 0], ['impact', 1, 0, 0]]);
});

test('dailySeries buckets by day, leaves empty days at zero and null rate', () => {
  const now = new Date('2026-10-26T12:00:00').getTime();
  const runs = [run([res('T1', 'a', 'pass'), res('T2', 'a', 'fail')], { startedAt: '2026-10-25T10:00:00' }), run([res('T1', 'a', 'pass')], { startedAt: '2026-08-01T10:00:00' })];
  const d = M.dailySeries(runs, 3, now);
  assert.equal(d.length, 3);
  assert.deepEqual(d.map((s) => s.total), [0, 2, 0]);
  assert.equal(d[1].rate, 50);
  assert.equal(d[0].rate, null);
});

test('groupHealth counts online share per group and skips retired agents', () => {
  const g = M.groupHealth([{ groupName: 'A', status: 'online' }, { groupName: 'A', status: 'offline' }, { groupName: 'B', status: 'online' }, { groupName: 'B', status: 'online', state: 'retired' }, { status: 'online' }]);
  assert.deepEqual(g.map((x) => [x.name, x.online, x.total, x.pct]), [['A', 1, 2, 50], ['B', 1, 1, 100], ['Ungrouped', 1, 1, 100]]);
});

test('activityFeed merges runs and open findings newest first', () => {
  const runs = [run([], { id: 'r1', name: 'Run one', status: 'completed', completedAt: '2026-10-25T10:00:00Z' })];
  const findings = [{ id: 'f1', status: 'open', techniqueName: 'Tech', firstSeen: '2026-10-25T12:00:00Z', severity: 'High' }, { id: 'f2', status: 'closed', firstSeen: '2026-10-26T00:00:00Z' }];
  const a = M.activityFeed(runs, findings, 6);
  assert.deepEqual(a.map((i) => i.arg), ['f1', 'r1']);
});

test('preventionSeries averages per day, oldest first; actorHistory sorts oldest first', () => {
  const t = [{ history: [{ recordedAt: '2026-10-25T10:00:00', prevention: 60 }, { recordedAt: '2026-10-24T10:00:00', prevention: 40 }] }, { history: [{ recordedAt: '2026-10-25T11:00:00', prevention: 80 }] }];
  const s = M.preventionSeries(t);
  assert.deepEqual(s.data, [40, 70]);
  assert.deepEqual(M.actorHistory(t[0]), [40, 60]);
});

test('execInsights states only numbers present in its inputs', () => {
  const trends = [{ detectionCoverage: 60, avgRiskScore: 70, assetCount: 10 }, { detectionCoverage: 66, avgRiskScore: 64, assetCount: 12 }];
  const out = M.execInsights(trends, { detectionMeasurable: true }, { hasData: true, overThreshold: 1, thresholdDays: 30, openCount: 4, worstDaysOpen: 41, medianDaysOpen: 9 });
  const text = out.map((i) => i.title).join('|');
  assert.doesNotMatch(text, /Detection coverage/, 'detection history is untrusted legacy data and is never narrated');
  assert.match(text, /Risk score fell 6 points/);
  assert.match(text, /1 open weakness older than 30 days/);
  assert.match(text, /grew from 10 to 12/);
  assert.equal(M.execInsights([], {}, null).length, 0);
  assert.equal(M.execInsights(trends, { hasAttackPathData: true, detectionMeasurable: true }, null).some((i) => /Detection coverage/.test(i.title)), false);
  assert.equal(M.execInsights(trends, { hasAttackPathData: false }, null).some((i) => /Detection coverage/.test(i.title)), false);
});

test('trendDelta colour follows the metric direction', () => {
  // risk: a rise is bad
  assert.equal(M.trendDelta([50, 60], true).tone, 'bad');
  assert.equal(M.trendDelta([60, 50], true).tone, 'ok');
  // exposure score (higher is better): a rise is GOOD (regression guard for the inverted colour)
  assert.equal(M.trendDelta([50, 60], false).tone, 'ok');
  assert.equal(M.trendDelta([60, 50], false).tone, 'bad');
  assert.equal(M.trendDelta([50], false).tone, 'muted');
  assert.equal(M.trendDelta([50, 50], false).text, 'flat over the last week');
});

test('exposureKpi: unmeasurable is never a number; measured shows its denominator and no legacy trend', () => {
  const none = M.exposureKpi({ exposureScore: 100, exposureMeasurable: false, assetCount: 3, exposureMeasuredAssets: 0 });
  assert.equal(none.value, '—');
  assert.equal(none.measurable, false);
  assert.equal(none.spark, null);
  assert.equal(M.exposureKpi({ exposureScore: 100, assetCount: 3 }).value, '—', 'a server that does not report measurability must not show 100');
  const ok = M.exposureKpi({ exposureScore: 72, exposureMeasurable: true, assetCount: 5, exposureMeasuredAssets: 3 });
  assert.equal(ok.value, 72);
  assert.match(ok.sub, /from 3 of 5 assets/);
  assert.match(ok.sub, /Historical trend unavailable due to legacy measurement data/);
  assert.equal(ok.spark, null, 'stored exposure history is legacy data and is not plotted');
  assert.equal(ok.label, 'Exposure score (higher is better)');
});

test('detectionKpi: a placeholder 100 is never coverage, and history is never plotted', () => {
  const none = M.detectionKpi({ detectionCoverage: 100, detectionMeasurable: false });
  assert.equal(none.value, '—');
  assert.equal(none.spark, null);
  assert.equal(M.detectionKpi({ detectionCoverage: 100 }).value, '—');
  const ok = M.detectionKpi({ detectionCoverage: 64, detectionMeasurable: true });
  assert.equal(ok.value, '64%');
  assert.equal(ok.spark, null, 'measurable today does not make earlier stored points trustworthy');
  assert.equal(ok.sub, M.LEGACY_TREND_NOTE);
});

test('heroValues: unmeasurable exposure and detection are dashes, never 100', () => {
  assert.deepEqual(M.heroValues({ exposureScore: 100, exposureMeasurable: false, detectionCoverage: 100, detectionMeasurable: false, hasAttackPathData: true }),
    { exposure: '—', detection: '—' });
  assert.deepEqual(M.heroValues({ exposureScore: 61, exposureMeasurable: true, detectionCoverage: 48, detectionMeasurable: true }),
    { exposure: 61, detection: '48%' });
  assert.deepEqual(M.heroValues(null), { exposure: '—', detection: '—' });
});

test('riskBand and topRisks', () => {
  assert.equal(M.riskBand(20).tone, 'ok'); assert.equal(M.riskBand(55).label, 'Moderate'); assert.equal(M.riskBand(90).tone, 'bad');
  const r = M.topRisks([{ id: 1, status: 'open', severity: 'High' }, { id: 2, status: 'open', severity: 'Critical' }, { id: 3, status: 'open', severity: 'Low' }, { id: 4, status: 'closed', severity: 'Critical' }], 4);
  assert.deepEqual(r.map((f) => f.id), [2, 1]);
});

test('compliance card escapes hostile framework fields and keeps them out of attributes', () => {
  const p = '"><img src=x onerror=alert(1)>';
  const div = document.createElement('div');
  div.innerHTML = R.complianceCard({ frameworkId: p, agentId: p, frameworkName: p, shortName: p, regulator: p, testedControls: 2, passingControls: 1, failingControls: 1, compliancePct: 50, coveragePct: 40, totalControls: 9 });
  assert.equal(div.querySelector('img'), null);
  assert.equal(div.querySelectorAll('[onerror]').length, 0);
});

test('scheduleWhen words recurring and one-off schedules', () => {
  const now = Date.parse('2026-10-26T00:00:00Z');
  assert.equal(R.scheduleWhen({ RecurrenceType: 'daily', TimeOfDay: '23:00' }, now), 'Daily · 23:00');
  assert.equal(R.scheduleWhen({ RecurrenceType: 'weekly', DayOfWeek: 1, TimeOfDay: '02:00' }, now), 'Weekly · Mon · 02:00');
  assert.equal(R.scheduleWhen({ RecurrenceType: 'once', RunAt: '2026-10-27T01:00:00Z' }, now), 'in 1 d 1 h');
});

// ── weekly trend series for the KPI tiles ───────────────────────────────────
const NOW = Date.parse('2026-10-27T12:00:00Z');
const dayAgo = (d) => new Date(NOW - d * 86400000).toISOString();

test('openFindingsSeries: open count at each weekly boundary, last point is the current open count', () => {
  const f = [
    { status: 'open', firstSeen: dayAgo(40) },
    { status: 'open', firstSeen: dayAgo(10) },
    { status: 'remediated', firstSeen: dayAgo(30), resolvedAt: dayAgo(12) },
    { status: 'open', firstSeen: dayAgo(2) },
  ];
  const s = M.openFindingsSeries(f, NOW, 8);
  assert.equal(s.length, 8);
  assert.equal(s[s.length - 1], 3);
  assert.equal(s[0], 0);
  assert.equal(s[2], 1);
  assert.equal(s[3], 2);
});

test('openFindingsSeries: empty or all-zero history gives no series', () => {
  assert.equal(M.openFindingsSeries([], NOW, 8), null);
  assert.equal(M.openFindingsSeries(null, NOW, 8), null);
});

test('oldestOpenAgeSeries: age in days of the oldest open finding at each boundary', () => {
  const f = [{ status: 'open', firstSeen: dayAgo(40) }, { status: 'open', firstSeen: dayAgo(3) }];
  const s = M.oldestOpenAgeSeries(f, NOW, 8);
  assert.equal(s[s.length - 1], 40);
  assert.equal(s[0], 0);
  assert.ok(s[s.length - 1] > s[s.length - 2]);
});

test('startedPerWeek: campaigns started in each weekly bucket, oldest first', () => {
  const c = [{ startedAt: dayAgo(1) }, { startedAt: dayAgo(2) }, { startedAt: dayAgo(10) }];
  const s = M.startedPerWeek(c, NOW, 8);
  assert.equal(s.length, 8);
  assert.equal(s[s.length - 1], 2);
  assert.equal(s[s.length - 2], 1);
  assert.equal(M.startedPerWeek([], NOW, 8), null);
});

test('orgReadinessTrends maps organisation readiness to the card shape and counts agents, not runs', () => {
  const org = { scope: 'organisation', agentCount: 3, actors: [
    { actorName: 'APT29', agentCount: 2, latestPrevention: 75, preventionDelta: 10, direction: 'up', testedTechniques: 20, preventedTechniques: 15,
      history: [{ date: '2026-10-01', prevention: 65, tested: 20 }, { date: '2026-10-02', prevention: 75, tested: 20 }] },
  ] };
  const t = M.orgReadinessTrends(org);
  assert.equal(t.scope, 'organisation');
  assert.equal(t.total, 1);
  assert.equal(t.agentCount, 3);
  assert.equal(t.trends[0].dataPoints, 2, 'dataPoints is the agent count behind the figure');
  assert.deepEqual(t.trends[0].history[1], { recordedAt: '2026-10-02', prevention: 75, tested: 20 });
  assert.deepEqual(M.orgReadinessTrends(null).trends, [], 'no response gives no actors, never a made-up figure');
});

test('zero denominators stay empty: no coverage, no scored runs, no compliance coverage', () => {
  assert.equal(M.coverage([]).tested, 0, 'no tested techniques means no percentage');
  assert.equal(M.coverage([run([{ result: 'error', technique: { id: 'T9' } }])]).tested, 0, 'an error result is not a tested technique');
  assert.equal(M.postureWindow([{ score: { preventionScore: 0, passedTechniques: 0, failedTechniques: 0 } }], 8), null, 'a run with nothing scoreable has no score');
});
