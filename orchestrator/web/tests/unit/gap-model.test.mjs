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

test('deployment URLs are under the run and encode ids', () => {
  assert.equal(G.deploymentsUrl('r 1'), '/api/scenarios/runs/r%201/detection-gaps/deployments');
  assert.equal(G.retestLinkUrl('r1', 'd/2'), '/api/scenarios/runs/r1/detection-gaps/deployments/d%2F2/retest');
});

test('only a re-test that proves a detection reads as closed; the rest never look like success', () => {
  assert.equal(G.deploymentTone('Closed on re-test'), 'ok');
  assert.equal(G.deploymentTone('Still a gap'), 'bad');
  assert.equal(G.deploymentTone('Deployed'), 'info');
  assert.equal(G.deploymentTone('Re-test running'), 'info');
  assert.equal(G.deploymentTone('Re-test awaiting verification'), 'warn');
  assert.equal(G.deploymentTone('Technique not re-tested'), 'warn');
  assert.equal(G.deploymentTone('anything else'), 'muted');
});

test('a re-test is offered only where another run could change the answer', () => {
  for (const s of ['Deployed', 'Still a gap', 'Technique not re-tested']) assert.equal(G.canRetest(s), true, s);
  for (const s of ['Re-test running', 'Re-test awaiting verification', 'Closed on re-test']) assert.equal(G.canRetest(s), false, s);
});

test('the re-test plan reuses the original run mode and asks for the same confirmations as starting a run', () => {
  const posture = G.retestPlan({ scenarioId: 's1', agentId: 'a1', mode: '' });
  assert.deepEqual(posture.body, { agentId: 'a1', mode: 'posture', confirmLive: false, confirmLab: false, reason: posture.body.reason });
  assert.deepEqual(posture.confirms, []);
  assert.match(posture.body.reason, /re-test/i);

  const tel = G.retestPlan({ scenarioId: 's1', agentId: 'a1', mode: 'telemetry' });
  assert.equal(tel.body.confirmLive, true);
  assert.equal(tel.body.confirmLab, false);
  assert.equal(tel.confirms.length, 1);
  assert.match(tel.confirms[0], /alerts/i);

  const lab = G.retestPlan({ scenarioId: 's1', agentId: 'a1', mode: 'lab' });
  assert.equal(lab.body.confirmLab, true);
  assert.equal(lab.confirms.length, 2);
  assert.match(lab.confirms[1], /isolated/i);

  assert.equal(G.retestPlan({ scenarioId: '', agentId: 'a1' }), null);
  assert.equal(G.retestPlan(null), null);
});

test('deployments are grouped by technique', () => {
  const deps = [{ id: '1', techniqueId: 'T1' }, { id: '2', techniqueId: 'T2' }, { id: '3', techniqueId: 'T1' }];
  assert.deepEqual(G.deploymentsFor(deps, 'T1').map((d) => d.id), ['1', '3']);
  assert.deepEqual(G.deploymentsFor(null, 'T1'), []);
});

test('a mapped query says how far it can be trusted, and never claims more than the evidence', () => {
  const note = (v) => G.backendNote({ backend: 'splunk', mapping: 'pipeline', dataSource: 'X', verification: v });
  assert.match(note('documented'), /not yet been run against real events/);
  assert.match(note('assumed'), /our assumption/);
  assert.match(note('validated'), /matched a sample event/);
  assert.doesNotMatch(note('validated'), /not yet been run/);
  assert.match(note(undefined), /not yet been run against real events/, 'a missing value is the weakest claim, never "validated"');
});
