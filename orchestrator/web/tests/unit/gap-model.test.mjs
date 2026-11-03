import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as G from '../../src/features/gap-model.js';

test('summary tiles come in a fixed order, always all five, with zero counts shown', () => {
  const t = G.summaryTiles({ 'Detection gap': 2, Detected: 5 });
  assert.deepEqual(t.map((x) => x.status), ['Detection gap', 'Unknown', 'Execution error', 'Skipped', 'Detected']);
  assert.deepEqual(t.map((x) => x.count), [2, 0, 0, 0, 5]);
  assert.equal(G.summaryTiles(null).every((x) => x.count === 0), true);
});

test('only a detection gap is danger; Unknown is never shown as good or as a gap', () => {
  assert.equal(G.statusTone('Detection gap'), 'bad');
  assert.equal(G.statusTone('Detected'), 'ok');
  assert.equal(G.statusTone('Unknown'), 'warn');
  assert.equal(G.statusTone('Execution error'), 'muted');
  assert.equal(G.statusTone('whatever'), 'muted');
});

test('rule availability tone never reads as success for a missing rule or translation', () => {
  assert.equal(G.availabilityTone('Rule available'), 'info');
  assert.equal(G.availabilityTone('No rule available'), 'warn');
  assert.equal(G.availabilityTone('Backend translation unavailable'), 'warn');
});

test('a mapped query names the data source it needs; a generic one says it must be adapted', () => {
  const mapped = G.backendNote({ backend: 'splunk', mapping: 'pipeline', dataSource: 'Sysmon event 1' });
  assert.match(mapped, /Sysmon event 1/);
  assert.match(mapped, /only matches if/i);
  const generic = G.backendNote({ backend: 'splunk', mapping: 'generic', dataSource: '' });
  assert.match(generic, /adapt/i);
  assert.doesNotMatch(generic, /only matches if/i);
});

test('backend names and the export link', () => {
  assert.equal(G.backendLabel('microsoft_sentinel'), 'Microsoft Sentinel');
  assert.equal(G.backendLabel('crowdstrike'), 'CrowdStrike LogScale');
  assert.equal(G.backendLabel('nope'), 'nope');
  assert.equal(G.exportZipUrl('run 1', ''), '/api/scenarios/runs/run%201/detection-gaps/export');
  assert.equal(G.exportZipUrl('r', 'splunk'), '/api/scenarios/runs/r/detection-gaps/export?backend=splunk');
  assert.equal(G.gapsUrl('r', 'elastic'), '/api/scenarios/runs/r/detection-gaps?backend=elastic');
});

test('export is offered only when the run has a detection gap', () => {
  assert.equal(G.canExport({ 'Detection gap': 1 }), true);
  assert.equal(G.canExport({ Detected: 4, Unknown: 2 }), false);
  assert.equal(G.canExport(null), false);
});

test('a parent-technique rule is labelled as broader', () => {
  assert.match(G.matchNote('parent'), /parent technique/i);
  assert.equal(G.matchNote('exact'), '');
});

test('severity tone', () => {
  assert.equal(G.severityTone('critical'), 'bad');
  assert.equal(G.severityTone('High'), 'bad');
  assert.equal(G.severityTone('medium'), 'warn');
  assert.equal(G.severityTone('low'), 'muted');
  assert.equal(G.severityTone(''), 'muted');
});

test('the explanatory line states what a gap is and what it is not', () => {
  assert.match(G.HELP, /reviewed/i);
  assert.match(G.HELP, /not validated|not been tested|not tested/i);
});

test('IBM QRadar is a selectable SIEM, in the same order the connectors use', () => {
  assert.equal(G.backendLabel('qradar'), 'IBM QRadar');
  assert.deepEqual(G.BACKENDS, ['microsoft_sentinel', 'microsoft_defender', 'splunk', 'qradar', 'elastic', 'crowdstrike']);
});

test('a QRadar query is generic: it says to adapt it and never names a data source', () => {
  const note = G.backendNote({ backend: 'qradar', mapping: 'generic', dataSource: '' });
  assert.match(note, /adapt/i);
  assert.doesNotMatch(note, /only matches if/i);
});
