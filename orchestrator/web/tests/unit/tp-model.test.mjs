import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/tp-model.js';

const a = (actorName, tier, score, trend, trendDelta, gap, total) => ({ actorName, tier, score, trend, trendDelta, coverageGapCount: gap, techniqueCount: total });
const LIST = [
  a('LockBit', 'High', 43, 'down', -23, 1, 12),
  a('Akira', 'Medium', 37, 'down', -1, 5, 11),
  a('APT29', 'Medium', 35, 'up', 4, 65, 121),
  a('Scattered Spider', 'Low', 16, 'stable', 0, 24, 30),
  a('Newcomer', 'Low', 9, 'new', 0, 2, 2),
];

test('heroStats counts only what the rows carry', () => {
  assert.deepEqual(M.heroStats(LIST), { actors: 5, high: 1, techniques: 176, gaps: 97 });
  assert.deepEqual(M.heroStats(null), { actors: 0, high: 0, techniques: 0, gaps: 0 });
});

test('tierTiles names the top actors and hides an empty Critical tile', () => {
  const t = M.tierTiles(LIST);
  assert.deepEqual(t.map((x) => x.label), ['High tier', 'Medium tier', 'Low tier']);
  assert.equal(t[0].caption, 'LockBit');
  assert.equal(t[1].caption, 'Akira · APT29');
  assert.equal(M.tierTiles(LIST.concat([a('X', 'Critical', 99, 'up', 1, 0, 1), a('Y', 'Medium', 5, 'new', 0, 0, 0)]))[0].label, 'Critical tier');
  assert.equal(M.tierTiles(LIST.concat([a('Y', 'Medium', 5, 'new', 0, 0, 0)]))[1].caption, 'Akira · APT29 +1');
  assert.equal(M.tierTiles([])[1].caption, 'no actors');
});

test('trendInfo and tones', () => {
  assert.deepEqual(M.trendInfo(LIST[0]), { cls: 'down', text: '▼ -23' });
  assert.deepEqual(M.trendInfo(LIST[2]), { cls: 'up', text: '▲ +4' });
  assert.equal(M.trendInfo(LIST[3]).text, '—');
  assert.equal(M.trendInfo(LIST[4]).text, 'New');
  assert.equal(M.tierTone('High'), 'bad');
  assert.equal(M.tierTone('Medium'), 'warn');
  assert.equal(M.tierTone('Low'), 'muted');
  assert.equal(M.initials('Scattered Spider'), 'SS');
  assert.equal(M.initials('LockBit'), 'L');
});

test('filterRows searches every column; filterTier narrows by tier', () => {
  assert.equal(M.filterRows(LIST, 'lockbit').length, 1);
  assert.equal(M.filterRows(LIST, 'medium').length, 2);
  assert.equal(M.filterRows(LIST, '  ').length, 5);
  assert.equal(M.filterRows(LIST, 'zzz').length, 0);
  assert.equal(M.filterTier(LIST, 'Low').length, 2);
  assert.equal(M.filterTier(LIST, 'all').length, 5);
});

test('sortRows is stable, ranks tiers and keeps no-history actors last on Trend', () => {
  assert.deepEqual(M.sortRows(LIST, 2, -1).map((r) => r.actorName)[0], 'LockBit');
  assert.deepEqual(M.sortRows(LIST, 1, 1).map((r) => r.actorName).slice(0, 3), ['LockBit', 'Akira', 'APT29']);
  assert.equal(M.sortRows(LIST, 3, 1).pop().actorName, 'Newcomer');
  assert.equal(M.sortRows(LIST, 3, -1).pop().actorName, 'Newcomer');
  assert.equal(M.sortRows(LIST, 4, -1)[0].actorName, 'APT29');
  assert.equal(M.sortRows(LIST, -1, 1)[0].actorName, 'LockBit');
});

test('numericCols right-aligns Trend only when every actor has a figure', () => {
  assert.deepEqual(M.numericCols(LIST), { 2: true });
  assert.deepEqual(M.numericCols(LIST.slice(0, 3)), { 2: true, 3: true });
});

test('csv header and rows follow the visible columns', () => {
  assert.deepEqual(M.csvHeader([0, 4]), ['Actor', 'Coverage gap']);
  assert.deepEqual(M.csvRows([LIST[0]], [0, 4]), [['LockBit', '1 of 12 techniques']]);
  assert.equal(M.rangeCounts(2, 5), '2 of 5 rows');
  assert.equal(M.useLight(7), true);
  assert.equal(M.useLight(8), false);
});

test('drawer pieces use only the fields the detail carries', () => {
  const d = { actorName: 'APT29', tier: 'High', score: 77, canonicalGroupId: 'G0016', techniqueSource: 'mitre', techniqueCount: 6, coverageGapCount: 5, trend: 'up', trendDelta: 3 };
  assert.equal(M.drawerSub(d), 'Threat actor · relevance 77 · MITRE G0016');
  assert.equal(M.drawerSub({ score: 5 }), 'Threat actor · relevance 5');
  assert.deepEqual(M.chipRows(d), [['High', 'bad'], ['Techniques: MITRE-authoritative', 'info']]);
  assert.deepEqual(M.chipRows({ tier: 'Low', techniqueSource: 'connector' })[1], ['Techniques: connector-derived', 'warn']);
  assert.deepEqual(M.factRows(d).map((r) => r[0]), ['Score', 'Techniques', 'Coverage gap', 'Trend']);
  assert.equal(M.related().length, 3);
});
