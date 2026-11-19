import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const runs = await import('../../src/features/runs-rich.js');
const camps = await import('../../src/features/campaigns-rich.js');

test('runBucket groups unknown, odd and missing statuses as needs-attention', () => {
  assert.equal(runs.runBucket({ status: 'running' }), 'running');
  assert.equal(runs.runBucket({ status: 'COMPLETED' }), 'completed');
  assert.equal(runs.runBucket({ status: 'partial' }), 'attention');
  assert.equal(runs.runBucket({}), 'attention');
  assert.equal(runs.runBucket(null), 'attention');
});

test('runStats ignores runs without scoreable results', () => {
  const s = runs.runStats([
    { status: 'completed', score: { preventionScore: 80, passedTechniques: 4, failedTechniques: 1 } },
    { status: 'completed', score: { preventionScore: 0, passedTechniques: 0, failedTechniques: 0 } },
    { status: 'running' },
  ]);
  assert.equal(s.total, 3); assert.equal(s.scored, 1); assert.equal(s.avgPrevention, 80); assert.equal(s.running, 1);
  assert.equal(runs.runStats(undefined).avgPrevention, null);
});

test('runsPerDay buckets by start day and tolerates bad dates', () => {
  const d = runs.runsPerDay([{ startedAt: '2026-10-26T01:00:00Z' }, { startedAt: '2026-10-26T20:00:00Z' }, { startedAt: 'nope' }, {}], 3);
  assert.equal(d.data.length, 3);
  assert.ok(d.data[2] >= 1);
  assert.deepEqual(runs.runsPerDay([], 7), { labels: [], data: [] });
});

test('charts html escapes status names and is empty without runs', () => {
  assert.equal(runs.chartsHtml([]), '');
  const h = runs.chartsHtml([{ status: '<img src=x onerror=1>', startedAt: '2026-10-26T01:00:00Z' }]);
  assert.ok(!h.includes('<img'), h);
  assert.match(runs.runsStatusAttr({ id: 'r1', status: 'failed' }), /data-run-status="failed"/);
});

test('campaignStats counts paused separately and survives missing summaries', () => {
  const s = camps.campaignStats([
    { summary: { status: 'running', paused: true, targets: 4, dispatched: 2, prevented: 3, missed: 1 } },
    { summary: { status: 'running', targets: 2 } },
    {}, null,
  ]);
  assert.equal(s.total, 4); assert.equal(s.paused, 1); assert.equal(s.running, 1);
  assert.equal(s.targets, 6); assert.equal(s.preventedPct, 75);
  assert.equal(camps.campaignStats([]).preventedPct, null);
});

test('campaign summary html escapes and omits itself when there are none', () => {
  assert.equal(camps.campaignSummaryHTML([]), '');
  const h = camps.campaignSummaryHTML([{ summary: { status: '<b>x</b>' } }]);
  assert.ok(!h.includes('<b>x'), h);
});
