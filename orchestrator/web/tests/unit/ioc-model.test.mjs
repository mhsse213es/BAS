import { test } from 'node:test';
import assert from 'node:assert/strict';
import { heroStats, statusTone, tally, donutSegments, typeCounts, sightingCountsByType, sourceRows, typeChips, sightingPct, analyticsTiles, parseEntry, drawerFacts, typeLabel, sourceLabel } from '../../src/features/ioc-model.js';

const rows = [
  { type: 'ip', value: 'a', source: 'scenario', status: 'detected', sightingCount: 6 },
  { type: 'ip', value: 'b', source: 'scenario', status: 'missed', sightingCount: 2 },
  { type: 'file_hash', value: 'c', source: 'detection_alert', status: 'observed', sightingCount: 4 },
  { type: 'domain', value: 'd', source: '', status: 'draft', sightingCount: 0 },
];

test('heroStats counts only loaded rows', () => {
  assert.deepEqual(heroStats(null), { total: null, detected: null, missed: null, observed: null });
  assert.deepEqual(heroStats(rows), { total: 4, detected: 1, missed: 1, observed: 1 });
});

test('labels and tones fall back sensibly', () => {
  assert.equal(typeLabel('file_hash'), 'File hash');
  assert.equal(typeLabel('weird'), 'weird');
  assert.equal(sourceLabel('detection_alert'), 'Detection alert');
  assert.equal(statusTone('missed'), 'bad');
  assert.equal(statusTone('zzz'), 'muted');
});

test('tally sorts by count then label and weights', () => {
  assert.deepEqual(typeCounts(rows), [['IP', 2], ['Domain', 1], ['File hash', 1]]);
  assert.deepEqual(sightingCountsByType(rows), [['IP', 8], ['File hash', 4], ['Domain', 0]]);
  assert.deepEqual(tally([{ k: '' }], (r) => r.k), [['Unknown', 1]]);
});

test('donutSegments folds the remainder into Other and drops zeros', () => {
  const segs = donutSegments([['a', 5], ['b', 3], ['c', 2], ['z', 0]], ['#1', '#2'], 2, '#m');
  assert.deepEqual(segs.map((s) => [s.label, s.value, s.color]), [['a', 5, '#1'], ['b', 3, '#2'], ['Other', 2, '#m']]);
  assert.deepEqual(donutSegments([], ['#1'], 7, '#m'), []);
});

test('sourceRows scales to the largest source', () => {
  const r = sourceRows(rows, 6);
  assert.deepEqual(r[0], ['Scenario', 100, 'info', ' · 2']);
  assert.equal(r.length, 3);
  assert.deepEqual(sourceRows([], 6), []);
});

test('typeChips lists every type and marks the active one', () => {
  const c = typeChips(rows, 'ip');
  assert.equal(c[0].label, 'All types');
  assert.equal(c[0].on, false);
  assert.equal(c.length, 15);
  assert.deepEqual(c.filter((k) => k.on).map((k) => k.id), ['ip']);
  assert.equal(c.find((k) => k.id === 'ip').count, 2);
  assert.equal(typeChips(rows, '')[0].on, true);
});

test('sightingPct is relative to the busiest row', () => {
  assert.equal(sightingPct(rows[0], rows), 100);
  assert.equal(sightingPct(rows[2], rows), 67);
  assert.equal(sightingPct(rows[0], []), 0);
});

test('analyticsTiles never invents a number', () => {
  const t = analyticsTiles({ mostDetected: [{ value: '1.2.3.4', sightingCount: 1 }], frequentlyReused: [{ value: 'x', sightingCount: 6 }] });
  assert.equal(t.length, 4);
  assert.deepEqual([t[0].value, t[0].sub, t[0].tone], ['1.2.3.4', '1 detection', 'bad']);
  assert.deepEqual([t[1].value, t[1].sub, t[1].tone], ['No data yet', 'needs detection results', 'muted']);
  assert.equal(t[2].sub, '6 sightings');
  assert.equal(t[3].value, 'No data yet');
  assert.equal(analyticsTiles(null)[0].value, 'No data yet');
});

test('parseEntry validates the add form', () => {
  assert.equal(parseEntry('ip', '  ').error, 'Enter an indicator value.');
  assert.equal(parseEntry('bogus', 'x').error, 'Choose an indicator type.');
  assert.deepEqual(parseEntry('ip', ' 203.0.113.9 ').entry, { type: 'ip', value: '203.0.113.9' });
});

test('drawerFacts formats dates and shows suppression', () => {
  const f = drawerFacts({ source: 'scenario', origin: 'run', status: 'detected', firstSeen: 't', sightingCount: 3, suppressed: true, suppressionReason: 'lab' }, (t) => 'D:' + t);
  assert.deepEqual(f.find((r) => r[0] === 'First seen'), ['First seen', 'D:t']);
  assert.deepEqual(f.find((r) => r[0] === 'Last seen'), ['Last seen', '—']);
  assert.deepEqual(f[f.length - 1], ['Suppressed', 'lab']);
});
