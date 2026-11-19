import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rateTone, heroStats, weakestTactics, shortTitle, threatRows, gapRows, sourceCount, libSummary, libFilter, verdictInfo } from '../../src/features/cov-model.js';

test('rateTone thresholds', () => {
  assert.equal(rateTone(75), 'ok'); assert.equal(rateTone(40), 'warn'); assert.equal(rateTone(39), 'bad'); assert.equal(rateTone(undefined), 'bad');
});

test('heroStats: covered of total, detected share of tested, null without data', () => {
  assert.deepEqual(heroStats({ cov: 5, part: 2, gap: 3, none: 34, total: 44 }), { covered: '5 / 44', detected: '70%', missed: 3, untested: 34 });
  assert.deepEqual(heroStats({ cov: 0, part: 0, gap: 0, none: 0, total: 0 }), { covered: null, detected: null, missed: null, untested: null });
  assert.deepEqual(heroStats(null), { covered: null, detected: null, missed: null, untested: null });
  assert.equal(heroStats({ cov: 0, part: 0, gap: 0, none: 4 }).detected, null);
});

test('weakestTactics sorts by prevention rate and skips untried tactics', () => {
  const r = weakestTactics([
    { tactic: 'A', prevented: 3, detectedOnly: 0, missed: 1 },
    { tactic: 'B', prevented: 1, detectedOnly: 1, missed: 2 },
    { tactic: 'C', prevented: 0, detectedOnly: 0, missed: 0 },
  ], 5);
  assert.deepEqual(r.map((x) => [x.name, x.pct, x.tone]), [['B', 25, 'bad'], ['A', 75, 'ok']]);
  assert.deepEqual(weakestTactics(null), []);
});

test('shortTitle cuts at a word boundary', () => {
  assert.equal(shortTitle('Short one'), 'Short one');
  assert.equal(shortTitle('FIN7 phishing-to-ransomware chain targeting finance staff', 24), 'FIN7 phishing-to-ransomw…');
  assert.equal(shortTitle('Scattered Spider help-desk social engineering', 24), 'Scattered Spider…');
  assert.equal(shortTitle(null), '');
});

test('threatRows counts executable content', () => {
  const r = threatRows([{ title: 'apt29 wave', lastSeenAt: 'x', techniques: [{ hasExecutableContent: true }, {}] }, { title: '' }]);
  assert.deepEqual([r[0].initial, r[0].techCount, r[0].withContent, r[0].pct], ['A', 2, 1, 50]);
  assert.equal(r[1].techCount, 0); assert.equal(r[1].pct, 0);
  assert.deepEqual(threatRows(null), []);
});

test('gapRows: missed before detected-only, lowest coverage first', () => {
  const r = gapRows([
    { techniqueId: 'T1', bestVerdict: 'prevented', runCount: 2, prevented: 2 },
    { techniqueId: 'T2', bestVerdict: 'detectedOnly', runCount: 4, prevented: 1, tactic: 'Impact' },
    { techniqueId: 'T3', bestVerdict: 'missed', runCount: 2, prevented: 1 },
    { techniqueId: 'T4', bestVerdict: 'missed', runCount: 3, prevented: 0 },
  ], 5);
  assert.deepEqual(r.map((x) => x.id), ['T4', 'T3', 'T2']);
  assert.deepEqual([r[2].pct, r[2].label, r[2].tone, r[2].tactic], [25, 'Detected only', 'warn', 'Impact']);
  assert.equal(gapRows([{ techniqueId: 'T9', bestVerdict: 'missed' }])[0].pct, 0);
});

test('library helpers', () => {
  const data = [
    { techniqueId: 'T1', name: 'Alpha', tactic: 'Execution', basCount: 2, artCount: 1 },
    { techniqueId: 'T2', name: 'Beta', tactic: 'Impact', basCount: 1 },
  ];
  assert.equal(sourceCount(data[0]), 2);
  assert.deepEqual(libSummary(data), { total: 2, bas: 2, art: 1, emu: 0, atomic: 0 });
  assert.equal(libFilter(data, { src: 'multi' }).length, 1);
  assert.equal(libFilter(data, { src: 'art' })[0].techniqueId, 'T1');
  assert.equal(libFilter(data, { q: 'beta' })[0].techniqueId, 'T2');
  assert.equal(libFilter(data, { tactic: 'Impact' }).length, 1);
  assert.equal(libFilter(null, {}).length, 0);
});

test('verdictInfo', () => {
  assert.deepEqual(verdictInfo('gap'), { label: 'Missed', tone: 'bad' });
  assert.deepEqual(verdictInfo('zzz'), { label: 'Untested', tone: 'muted' });
});
