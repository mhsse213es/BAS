import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/rec-model.js';

const L = [
  { techniqueId: 'T1021.002', name: 'SMB/Windows Admin Shares', tactic: 'lateral-movement', score: 36, tier: 'High', coverageState: 'never-tested', kev: true, epssPercentile: 91.4, threatActors: 15, environmentRisk: 100, reasons: ['On a path', 'Previously failed'] },
  { techniqueId: 'T1053.005', name: 'Scheduled Task', tactic: 'persistence', score: 21, tier: 'Medium', coverageState: 'stale', threatActors: 1, environmentRisk: 0, reasons: [] },
  { techniqueId: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'exfiltration', score: 50, tier: 'Critical', coverageState: 'recent' },
];

test('normLimit only accepts the three Top-N sizes', () => {
  assert.equal(M.normLimit('10'), 10);
  assert.equal(M.normLimit(50), 50);
  assert.equal(M.normLimit('7'), M.DEFAULT_LIMIT);
  assert.equal(M.limitLabel(20), 'Top 20');
});

test('heroStats counts ranked, Critical/High, never tested and on-a-path', () => {
  assert.deepEqual(M.heroStats(L), { ranked: 3, top: 2, never: 1, path: 1 });
  assert.deepEqual(M.heroStats(null), { ranked: 0, top: 0, never: 0, path: 0 });
});

test('threatBits and labels', () => {
  assert.deepEqual(M.threatBits(L[0]).map((b) => b.text), ['KEV', 'EPSS 91', '15 groups']);
  assert.deepEqual(M.threatBits(L[1]).map((b) => b.text), ['1 group']);
  assert.deepEqual(M.threatBits(L[2]), []);
  assert.equal(M.coverageLabel('never-tested'), 'Never tested');
  assert.equal(M.coverageTone('stale'), 'warn');
  assert.equal(M.tierTone('Critical'), 'bad');
});

test('filterRows searches every column text', () => {
  assert.equal(M.filterRows(L, '').length, 3);
  assert.deepEqual(M.filterRows(L, 'smb').map((t) => t.techniqueId), ['T1021.002']);
  assert.deepEqual(M.filterRows(L, 'stale').map((t) => t.techniqueId), ['T1053.005']);
  assert.deepEqual(M.filterRows(L, 'previously failed').length, 1);
});

test('sortRows: numeric, direction, empty last, stable', () => {
  assert.deepEqual(M.sortRows(L, 2, 1).map((t) => t.score), [21, 36, 50]);
  assert.deepEqual(M.sortRows(L, 2, -1).map((t) => t.score), [50, 36, 21]);
  assert.deepEqual(M.sortRows(L, 6, -1).map((t) => t.techniqueId), ['T1021.002', 'T1053.005', 'T1041']);
  assert.deepEqual(M.sortRows(L, -1, 1), L);
});

test('csvRow carries the visible columns plus the technique id', () => {
  assert.deepEqual(M.csvRow(L[0], [0, 2]), ['SMB/Windows Admin Shares', '36', 'T1021.002']);
  assert.equal(M.cellText(L[1], 5), '');
});

test('scenarioSub pluralises', () => {
  assert.match(M.scenarioSub(['T1']), /^1 technique ·/);
  assert.match(M.scenarioSub(['T1', 'T2']), /^2 techniques ·/);
});
