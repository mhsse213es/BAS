import test from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/runs-res-model.js';

const C = (result, tactic, o) => ({ result, technique: { id: 'T1', name: 'N', tactic }, ...o });
const RUN = { id: 'r3', scenarioId: 's', startedAt: '2026-10-26T10:00:00Z', completedAt: '2026-10-26T10:10:00Z', results: [C('pass', 'execution', { durationMs: 1500, severity: 'High' }), C('fail', 'impact', { durationMs: 4000, severity: 'critical' }), C('error', 'impact'), C('blocked', 'impact')] };

test('stepsOf maps verdicts to ok / bad / na and tolerates missing fields', () => {
  const s = M.stepsOf(RUN);
  assert.deepEqual(s.map((r) => r.state), ['ok', 'bad', 'na', 'ok']);
  assert.equal(s[1].sev, 'critical'); assert.equal(s[2].ms, null);
  assert.deepEqual(M.stepsOf({}), []); assert.deepEqual(M.stepsOf(null), []);
  assert.deepEqual(M.counts(s), { total: 4, ok: 2, bad: 1, na: 1 });
});

test('tacticRows follow kill-chain order and leave unmeasured steps out of the percentage', () => {
  const rows = M.tacticRows(M.stepsOf(RUN));
  assert.deepEqual(rows.map((r) => r.key), ['execution', 'impact']);
  assert.equal(rows[1].pass, 1); assert.equal(rows[1].fail, 1); assert.equal(rows[1].na, 1); assert.equal(rows[1].pct, 50);
  assert.equal(M.tacticLabel('command-and-control'), 'Command And Control');
  assert.equal(M.tacticLabel('weird_tactic'), 'Weird Tactic'); assert.equal(M.tacticLabel(''), 'Other');
});

test('heatCells covers all 12 tactics and classifies them', () => {
  const cells = M.heatCells(M.stepsOf(RUN));
  assert.equal(cells.length, 12);
  assert.equal(cells.find((c) => c.key === 'execution').cls, 'ok');
  assert.equal(cells.find((c) => c.key === 'impact').cls, 'mid');
  assert.equal(cells.find((c) => c.key === 'discovery').cls, 'na');
  assert.equal(M.heatCells([C('fail', 'impact')].map((c, i) => M.stepsOf({ results: [c] })[0]))[11].cls, 'bad');
});

test('severityCounts only counts failing steps', () => {
  assert.deepEqual(M.severityCounts(M.stepsOf(RUN)), { critical: 1, high: 0, medium: 0, low: 0 });
});

test('durationStats uses the run stamps for wall clock and the timed steps for active time', () => {
  const d = M.durationStats(M.stepsOf(RUN), RUN);
  assert.equal(d.wallMs, 600000); assert.equal(d.activeMs, 5500); assert.equal(d.slowest.ms, 4000); assert.equal(d.timed, 2);
  const none = M.durationStats(M.stepsOf({ results: [C('pass', 'x')] }), {});
  assert.equal(none.wallMs, null); assert.equal(none.activeMs, null); assert.equal(none.slowest, null);
  assert.equal(M.fmtMs(450), '450 ms'); assert.equal(M.fmtMs(6400), '6.4 s'); assert.equal(M.fmtMs(600000), '10 m 00 s'); assert.equal(M.fmtMs(null), '—');
});

test('cumulative and furthestStage track the breakthrough', () => {
  const steps = M.stepsOf(RUN);
  assert.deepEqual(M.cumulative(steps), [0, 1, 1, 1]);
  assert.equal(M.furthestStage(M.tacticRows(steps)).key, 'impact');
  assert.equal(M.furthestStage(M.tacticRows(M.stepsOf({ results: [C('pass', 'execution')] }))), null);
});

test('scoreHistory takes scored runs of the same scenario up to the open one', () => {
  const mk = (id, day, p, sc = 's') => ({ id, scenarioId: sc, startedAt: `2026-10-${day}T10:00:00Z`, score: p == null ? undefined : { preventionScore: p } });
  const h = M.scoreHistory([mk('r1', 20, 40), mk('r2', 22, 55), mk('r3', 26, 70), mk('r4', 27, 90), mk('x', 21, 10, 'other'), mk('u', 23, null)], RUN, 7);
  assert.deepEqual(h.values, [40, 55, 70]); assert.deepEqual(h.labels, ['20 Oct', '22 Oct', '26 Oct']);
  assert.deepEqual(M.scoreHistory([], RUN).values, []);
  assert.deepEqual(M.scoreHistory([mk('r1', 20, 40), mk('r2', 22, 55), mk('r3', 26, 70)], RUN, 2).values, [55, 70]);
});

test('donutOf drops empty slices', () => {
  assert.deepEqual(M.donutOf([{ label: 'a', value: 0 }, { label: 'b', value: 2 }]).map((p) => p.label), ['b']);
});

test('drawer blocks escape step names and stay empty without data', async () => {
  const { setupDom } = await import('./dom.mjs');
  setupDom();
  const D = await import('../../src/features/runs-drawer.js');
  const evil = { results: [{ result: 'fail', technique: { id: 'T1', name: '<img src=x onerror=1>', tactic: 'impact' } }] };
  const html = D.overviewExtra(M.stepsOf(evil)) + D.findingsExtra(M.stepsOf(evil));
  assert.ok(!html.includes('<img'), html);
  assert.equal(D.overviewExtra([]), ''); assert.equal(D.findingsExtra([]), ''); assert.equal(D.timelineExtra([], {}), ''); assert.equal(D.endpointExtra({}), ''); assert.equal(D.reportsExtra({}), '');
  assert.match(D.reportsExtra({ id: 'r1' }), /data-on-click="exportRunJSON"/);
  assert.match(D.historyHtml({ values: [1], labels: ['a'] }), /Not enough scored runs/);
});
