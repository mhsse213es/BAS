import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/ex-model.js';

const S = [
  { Name: 'Cloud Credential Theft', Category: 'Credential Access', Severity: 'high', TechniqueIDs: ['T1', 'T2'], InjectsCount: 9, SourceUpdatedAt: '2026-10-15T17:30:00Z' },
  { Name: 'Ransomware Precursors', Category: 'Impact', Severity: 'critical', TechniqueIDs: [], InjectsCount: 5, SourceUpdatedAt: '' },
  { Name: 'No inject count', Category: '', Severity: '', TechniqueIDs: ['T9'] },
];
const E = [
  { id: 'a', name: 'Drill #1', status: 'running', steps_done: 1, steps_total: 2, started_at: '2026-10-25T10:00:00Z' },
  { id: 'b', plan_id: 'p', status: 'completed', steps_done: 2, steps_total: 2, created_at: '2026-10-12 10:00:00' },
  { id: 'c', name: 'Empty', status: 'failed', steps_total: 0 },
];

test('heroStats counts only loaded lists', () => {
  assert.deepEqual(M.heroStats({ scen: S, plans: [1], execs: E }), { scen: 3, plans: 1, execs: 3, done: 1 });
  assert.deepEqual(M.heroStats({}), { scen: null, plans: null, execs: null, done: null });
  assert.deepEqual(M.heroStats(null), { scen: null, plans: null, execs: null, done: null });
});

test('table mode switches at 8 rows', () => {
  assert.equal(M.isFull(7), false);
  assert.equal(M.isFull(8), true);
});

test('tones follow the demo', () => {
  assert.equal(M.sevTone('Critical'), 'bad');
  assert.equal(M.sevTone('high'), 'warn');
  assert.equal(M.sevTone('medium'), 'info');
  assert.equal(M.sevTone('low'), 'info');
  assert.equal(M.statusTone('completed'), 'ok');
  assert.equal(M.statusTone('running'), 'info');
  assert.equal(M.statusTone('aborted'), 'bad');
  assert.equal(M.statusTone('x'), 'muted');
});

test('stamp, dayOf and planSub format dates and counts', () => {
  assert.equal(M.stamp('2026-10-15T17:30:00Z'), '2026-10-15 17:30');
  assert.equal(M.stamp('2026-10-12 10:00:00'), '2026-10-12 10:00');
  assert.equal(M.stamp('soon'), 'soon');
  assert.equal(M.stamp(null), '');
  assert.equal(M.dayOf('2026-09-25T09:00:00Z'), '2026-09-25');
  assert.equal(M.planSub({ steps: [1, 2], created_at: '2026-09-25T09:00:00Z' }), '2 steps · created 2026-09-25');
  assert.equal(M.planSub({ steps: [1] }), '1 step');
  assert.equal(M.planSub({}), '0 steps');
});

test('cellText covers scenario and execution columns', () => {
  assert.equal(M.cellText('scen', S[0], 3), '2');
  assert.equal(M.cellText('scen', S[2], 4), '');
  assert.equal(M.cellText('scen', S[0], 5), '2026-10-15 17:30');
  assert.equal(M.cellText('execs', E[0], 1), 'running · live');
  assert.equal(M.cellText('execs', E[0], 2), '1 / 2 steps');
  assert.equal(M.cellText('execs', E[2], 2), '');
  assert.equal(M.cellText('execs', E[1], 0), 'p');
  assert.equal(M.cellText('execs', E[1], 3), '2026-10-12 10:00');
  assert.equal(M.progressPct(E[0]), 50);
  assert.equal(M.progressPct(E[2]), null);
});

test('filterRows searches every column', () => {
  assert.equal(M.filterRows('scen', S, 'impact').length, 1);
  assert.equal(M.filterRows('scen', S, 'CRITICAL').length, 1);
  assert.equal(M.filterRows('scen', S, '  ').length, 3);
  assert.equal(M.filterRows('execs', E, 'live').length, 1);
  assert.equal(M.filterRows('execs', E, 'zzz').length, 0);
});

test('sortRows is numeric for counts and progress, stable, empties last', () => {
  assert.deepEqual(M.sortRows('scen', S, 3, 1).map((r) => r.Name), ['Ransomware Precursors', 'No inject count', 'Cloud Credential Theft']);
  assert.deepEqual(M.sortRows('scen', S, 4, -1).map((r) => r.Name), ['Cloud Credential Theft', 'Ransomware Precursors', 'No inject count']);
  assert.deepEqual(M.sortRows('scen', S, 1, 1).map((r) => r.Name), ['Cloud Credential Theft', 'Ransomware Precursors', 'No inject count']);
  assert.deepEqual(M.sortRows('execs', E, 2, -1).map((r) => r.id), ['b', 'a', 'c']);
  assert.deepEqual(M.sortRows('scen', S, -1, 1), S);
});

test('csvRow follows the visible columns', () => {
  assert.deepEqual(M.csvRow('scen', S[0], [0, 3]), ['Cloud Credential Theft', '2']);
  assert.equal(M.rangeCounts(2, 6), '2 of 6 rows');
  assert.equal(M.csvText(['A'], [['=x']]).includes("'=x"), true);
});
