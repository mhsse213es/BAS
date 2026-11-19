import { test } from 'node:test';
import assert from 'node:assert/strict';
import { heroStats, tileData, sevCounts, filterRems, showingText, cardView, drawerView } from '../../src/features/rem-model.js';

const L = [
  { severity: 'Critical', techniqueId: 'T1486', techniqueName: 'Data Encrypted for Impact', findingCount: 6, agentCount: 1, controlClasses: ['AV', 'EDR'], missed: 6, detectedOnly: 0, mitigations: [{ name: 'Data Backup', description: 'Keep offline copies' }, { description: 'nameless' }], detection: 'Watch for mass file writes', recommendedTargets: ['ws-1'] },
  { severity: 'high', techniqueId: 'T1055', techniqueName: 'Process Injection', findingCount: 1, agentCount: 2, controlClasses: ['EDR'], missed: 1, detectedOnly: 1 },
  { severity: 'Medium', techniqueId: 'T1005', techniqueName: 'Data from Local System', findingCount: 2, agentCount: 2, controlClasses: [] },
];

test('heroStats / tileData count open, critical and affected findings', () => {
  assert.deepEqual(heroStats(L), { open: 3, critical: 1 });
  assert.deepEqual(tileData(L), { open: 3, findings: 9, critical: 1 });
  assert.deepEqual(heroStats(null), { open: 0, critical: 0 });
  assert.deepEqual(tileData(undefined), { open: 0, findings: 0, critical: 0 });
});

test('sevCounts is case-insensitive', () => {
  assert.deepEqual(sevCounts(L), { all: 3, Critical: 1, High: 1, Medium: 1, Low: 0 });
});

test('filterRems keeps original indexes; matches id, name and control class', () => {
  assert.deepEqual(filterRems(L, 'all', ''), [0, 1, 2]);
  assert.deepEqual(filterRems(L, 'High', ''), [1]);
  assert.deepEqual(filterRems(L, 'all', 'inject'), [1]);
  assert.deepEqual(filterRems(L, 'all', 'av'), [0]);
  assert.deepEqual(filterRems(L, 'Low', ''), []);
  assert.deepEqual(filterRems(null, 'all', ''), []);
});

test('showingText', () => { assert.equal(showingText(3, 31), 'Showing 3 of 31'); });

test('cardView pluralises and normalises', () => {
  var c = cardView(L[0]);
  assert.equal(c.closes, '6 findings'); assert.equal(c.agents, '1 agent'); assert.equal(c.controls, 'AV, EDR');
  assert.equal(c.sev, 'Critical'); assert.equal(c.sevKey, 'critical'); assert.equal(c.tone, 'bad'); assert.equal(c.missed, 6);
  var d = cardView(L[1]);
  assert.equal(d.sev, 'High'); assert.equal(d.closes, '1 finding'); assert.equal(d.detectedOnly, 1);
  assert.equal(cardView(L[2]).controls, '');
});

test('drawerView lists only named mitigations, never invents steps', () => {
  var d = drawerView(L[0]);
  assert.equal(d.subtitle, 'T1486 · MITRE ATT&CK mitigation');
  assert.deepEqual(d.steps, [{ name: 'Data Backup', description: 'Keep offline copies' }]);
  assert.equal(d.summary, 'Closes 6 findings on 1 agent · Missed 6 · Detected only 0');
  assert.deepEqual(d.targets, ['ws-1']);
  assert.deepEqual(drawerView(L[1]).steps, []);
  assert.equal(drawerView(L[1]).detection, '');
});
