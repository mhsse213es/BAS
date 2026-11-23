import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/tcv-model.js';

const r = (id, s, d, p, c, pb) => ({ techniqueId: id, simulationExists: s, detectionProfileExists: d, purpleExerciseExists: p, complianceMappingExists: c, responsePlaybookExists: pb });
const L = [
  r('T1003', true, true, true, true, true),
  r('T1021', true, false, false, true, null),
  r('T1486', false, false, false, false, false),
];

test('rowCov counts applicable dimensions only', () => {
  assert.deepEqual(M.rowCov(L[0]), { have: 5, applicable: 5, pct: 100 });
  assert.deepEqual(M.rowCov(L[1]), { have: 2, applicable: 4, pct: 50 });
  assert.deepEqual(M.rowCov({ techniqueId: 'X' }), { have: 0, applicable: 0, pct: 0 });
});

test('heroStats totals, average, covered and gaps', () => {
  assert.deepEqual(M.heroStats(L), { total: 3, avg: 50, covered: 1, gaps: 2 });
  assert.deepEqual(M.heroStats(null), { total: 0, avg: null, covered: 0, gaps: 0 });
});

test('actorNote and chipActors', () => {
  assert.equal(M.actorNote('', L), '3 techniques across all known groups · 1 fully covered · 2 with gaps');
  assert.match(M.actorNote('APT29', L), /^Showing only techniques attributed to APT29 · 3 techniques/);
  const many = Array.from({ length: 30 }, (_, i) => 'A' + i);
  assert.equal(M.chipActors(many, '').length, M.MAX_CHIPS - 1);
  assert.ok(M.chipActors(many, 'A29').includes('A29'));
  assert.deepEqual(M.chipActors(['A', 'B'], 'ZZ'), ['A', 'B']);
});

test('filterRows by search and result', () => {
  assert.equal(M.filterRows(L, {}).length, 3);
  assert.deepEqual(M.filterRows(L, { q: 't100' }).map((t) => t.techniqueId), ['T1003']);
  assert.deepEqual(M.filterRows(L, { result: 'gaps' }).map((t) => t.techniqueId), ['T1021', 'T1486']);
  assert.deepEqual(M.filterRows(L, { result: 'covered' }).map((t) => t.techniqueId), ['T1003']);
});

test('cellText, tableFilter and csvRow', () => {
  assert.equal(M.cellText(L[1], 7), 'N/A');
  assert.equal(M.cellText(L[1], 3), 'Yes');
  assert.equal(M.cellText(L[1], 4), 'No');
  assert.equal(M.cellText(L[1], 2), '50%');
  assert.equal(M.cellText({ techniqueId: 'T1', name: 'Phishing' }, 1), 'Phishing');
  assert.deepEqual(M.tableFilter(L, 'n/a').map((t) => t.techniqueId), ['T1021']);
  assert.deepEqual(M.csvRow(L[0], [0, 2]), ['T1003', '100%']);
});

test('sortRows: coverage, direction, N/A last, stable', () => {
  assert.deepEqual(M.sortRows(L, 2, 1).map((t) => t.techniqueId), ['T1486', 'T1021', 'T1003']);
  assert.deepEqual(M.sortRows(L, 2, -1).map((t) => t.techniqueId), ['T1003', 'T1021', 'T1486']);
  assert.deepEqual(M.sortRows(L, 7, 1).map((t) => t.techniqueId), ['T1486', 'T1003', 'T1021']);
  assert.deepEqual(M.sortRows(L, -1, 1), L);
});

test('withNames adds name and tactic from the library and leaves unknown rows alone', () => {
  const out = M.withNames(L, { T1003: { name: 'OS Credential Dumping', tactic: 'credential-access' } });
  assert.equal(out[0].name, 'OS Credential Dumping');
  assert.equal(out[1].name, undefined);
  assert.deepEqual(M.withNames(null, {}), []);
  assert.equal(L[0].name, undefined); // the input is not modified
});

test('search matches id, name and tactic', () => {
  const rows = M.withNames(L, { T1003: { name: 'OS Credential Dumping', tactic: 'credential-access' } });
  assert.deepEqual(M.filterRows(rows, { q: 'credential' }).map((x) => x.techniqueId), ['T1003']);
  assert.deepEqual(M.filterRows(rows, { q: 'T1021' }).map((x) => x.techniqueId), ['T1021']);
});

test('bands count techniques by share of applicable dimensions; none-applicable are skipped', () => {
  assert.deepEqual(M.bands(L).map((b) => b.value), [1, 0, 1, 1]);
  assert.deepEqual(M.bands([{ techniqueId: 'X' }]).map((b) => b.value), [0, 0, 0, 0]);
});

test('dimRows explains what is missing and only for No', () => {
  const d = M.dimRows(L[1]);
  assert.deepEqual(d.map((x) => x.state), ['yes', 'no', 'no', 'yes', 'na']);
  assert.ok(d[1].todo.length > 0);
  assert.equal(d[0].todo, '');
  assert.equal(d[4].todo, '');
});

test('prettyTactic', () => { assert.equal(M.prettyTactic('credential-access'), 'Credential Access'); });
