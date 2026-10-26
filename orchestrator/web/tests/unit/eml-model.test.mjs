import { test } from 'node:test';
import assert from 'node:assert/strict';
import { heroStats, coverageSummary, fmtSeconds, latencyTile, metricTiles, outcomeShare, catalogCards, latestByScenario, campaignName, filterCampaigns, templateUse } from '../../src/features/eml-model.js';

test('heroStats counts only loaded lists', () => {
  assert.deepEqual(heroStats(null, []), { runs: null, completed: null, failed: null, campaigns: null });
  assert.deepEqual(heroStats([{ status: 'completed' }, { status: 'failed' }, { status: 'running' }], [{}]), { runs: 3, completed: 1, failed: 1, campaigns: 1 });
});

test('coverageSummary ignores excluded areas in the percentage', () => {
  const s = coverageSummary([{ areaId: 'A', areaName: 'Spoof', status: 'covered' }, { areaId: 'B', areaName: 'DLP', status: 'not-covered' }, { areaId: 'C', areaName: 'X', status: 'excluded', exclusionReason: 'n/a' }]);
  assert.equal(s.pct, 50);
  assert.deepEqual(s.rows.map((r) => r.status), ['covered', 'missing', 'excluded']);
  assert.equal(s.rows[0].label, 'A — Spoof');
  assert.equal(coverageSummary(null).pct, 0);
});

test('latency formatting and honest empty tiles', () => {
  assert.equal(fmtSeconds(42), '42s');
  assert.equal(fmtSeconds(150), '2.5 min');
  assert.equal(fmtSeconds(7200), '2 h');
  assert.equal(latencyTile('MTTD', null).note, 'no eligible samples');
  assert.equal(latencyTile('MTTD', { sufficient: false, sampleCount: 1, minimumSampleSize: 5 }).note, '1/5 samples');
  const t = latencyTile('MTTD', { sufficient: true, meanSeconds: 90, sampleCount: 7 });
  assert.equal(t.value, '1.5 min'); assert.equal(t.note, 'n=7');
});

test('metricTiles only for environments present', () => {
  assert.equal(metricTiles({}).length, 0);
  assert.equal(metricTiles({ lab: {}, customer: {} }).length, 4);
});

test('outcomeShare', () => {
  assert.equal(outcomeShare({ outcomes: {} }), null);
  assert.deepEqual(outcomeShare({ outcomes: { confirmedSuccess: 1, confirmedFailure: 3 } }), { pct: 25, succ: 1, total: 4 });
});

test('catalogCards derives tags from expectation ids', () => {
  const c = catalogCards([{ id: 'EG-001', name: 'A', expectations: [{ id: 'EG-001.spf.known-good' }, { id: 'EG-001.spf.known-bad' }, { id: 'EG-001.dkim.known-good' }] }, { id: 'EG-010', name: 'B', expectations: [{ id: 'EG-010.detection' }, { id: 'EG-010.response' }] }]);
  assert.deepEqual(c[0].kinds, ['known-good', 'known-bad']); assert.equal(c[0].count, 3);
  assert.deepEqual(c[1].kinds, ['detection', 'response']);
});

test('latestByScenario keeps the newest run', () => {
  const m = latestByScenario([{ scenarioId: 'a', startedAt: '2026-10-01', id: 1 }, { scenarioId: 'a', startedAt: '2026-10-03', id: 2 }]);
  assert.equal(m.a.id, 2);
});

test('campaign name, filter and template use', () => {
  const T = [{ id: 't1', name: 'BEC' }];
  const L = [{ id: 'c1', templateId: 't1', status: 'running' }, { id: 'c2', templateId: 'zz', status: 'completed' }];
  assert.equal(campaignName(L[0], T), 'BEC'); assert.equal(campaignName(L[1], T), 'zz');
  assert.equal(filterCampaigns(L, T, 'running', '').length, 1);
  assert.equal(filterCampaigns(L, T, 'all', 'bec').length, 1);
  assert.equal(filterCampaigns(L, T, 'all', '').length, 2);
  assert.equal(templateUse(L, 't1'), 1);
});
