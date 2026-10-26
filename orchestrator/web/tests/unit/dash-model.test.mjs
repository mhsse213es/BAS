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

test('postureWindow weights by technique count and reports the trend', () => {
  const sc = (p, pass, fail) => ({ score: { preventionScore: p, passedTechniques: pass, failedTechniques: fail } });
  const runs = [sc(90, 9, 1), sc(80, 8, 2), sc(40, 4, 6), sc(30, 3, 7), sc(0, 0, 0)];
  const w = M.postureWindow(runs, 8);
  assert.equal(w.count, 4);
  assert.equal(w.pct, Math.round((90 * 10 + 80 * 10 + 40 * 10 + 30 * 10) / 40));
  assert.equal(w.trend, 'Improving');
  assert.deepEqual(w.series, [30, 40, 80, 90]);
  assert.equal(M.postureWindow([], 8), null);
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
  const out = M.execInsights(trends, { hasAttackPathData: true }, { hasData: true, overThreshold: 1, thresholdDays: 30, openCount: 4, worstDaysOpen: 41, medianDaysOpen: 9 });
  const text = out.map((i) => i.title).join('|');
  assert.match(text, /rose 6 points/);
  assert.match(text, /Risk score fell 6 points/);
  assert.match(text, /1 open weakness older than 30 days/);
  assert.match(text, /grew from 10 to 12/);
  assert.equal(M.execInsights([], {}, null).length, 0);
  assert.equal(M.execInsights(trends, { hasAttackPathData: false }, null).some((i) => /Detection coverage/.test(i.title)), false);
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
