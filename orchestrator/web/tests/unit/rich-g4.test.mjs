import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const g = await import('../../src/features/rich-g4.js');

const EVIL = '<img src=x onerror=alert(1)>';

test('attack-path body escapes graph data and tolerates a sparse summary', () => {
  const h = g.apRichBody({ collected: true, summary: { attackPathScore: 40, band: EVIL, maxBlastEntry: EVIL, shortestDomainAdminPath: [{ from: EVIL, to: 'DA', kind: EVIL }], domainCompromise: true, chokePoints: [{ label: EVIL, onPaths: 2, coverage: 0.5 }] }, coverage: {} }, { gaps: [{ priority: EVIL, edge: { from: EVIL, to: 'b', kind: 'smb' }, reason: EVIL, remediation: EVIL }] });
  assert.ok(!h.includes('<img'), h);
  assert.match(h, /Attack path score/);
  assert.doesNotThrow(() => g.apRichBody({ collected: true }, null));
});

test('attack-path empty state keeps the Run Collection action', () => {
  assert.match(g.apRichBody(null, null), /data-on-click="openAPCollect"/);
});

test('exposure filters and rows', () => {
  const a = [
    { asset: { hostKey: 'a', label: 'Alpha', managed: true, crownJewel: 'ERP' }, exposureScore: 30, kevExposed: true },
    { asset: { hostKey: EVIL, label: EVIL, managed: false }, exposureScore: 90 },
  ];
  assert.equal(g.expFilterAssets(a, 'managed', '').length, 1);
  assert.equal(g.expFilterAssets(a, 'kev', '').length, 1);
  assert.equal(g.expFilterAssets(a, 'all', 'alp').length, 1);
  assert.equal(g.expFilterAssets(a, 'crown', 'zzz').length, 0);
  assert.ok(!g.expRowsHtml(a).includes('<img'));
  assert.equal(g.expSummary([]), '');
  assert.match(g.expSummary(a), /KEV-exposed hosts/);
});

test('coverage stats treat null as N/A and detect gaps', () => {
  const rows = [
    { techniqueId: 'T1', simulationExists: true, detectionProfileExists: false, purpleExerciseExists: null, complianceMappingExists: true, responsePlaybookExists: true },
    { techniqueId: EVIL, simulationExists: true, detectionProfileExists: true, purpleExerciseExists: true, complianceMappingExists: true, responsePlaybookExists: true },
  ];
  const st = g.covStats(rows);
  assert.equal(st.gaps, 1);
  assert.equal(st.dims[2].applicable, 1);
  assert.equal(g.covFilterRows(rows, 'gaps').length, 1);
  assert.ok(!g.covRowsHtml(rows).includes('<img'));
  assert.equal(g.covSummary([]), '');
});

test('threat priority builders handle odd data', () => {
  const actors = [{ actorName: EVIL, tier: 'Critical', score: 90, trend: 'up', trendDelta: 3, coverageGapCount: 2, techniqueCount: 0 }, { actorName: 'x' }];
  assert.ok(!g.tpRowsHtml(actors).includes('<img'));
  assert.equal(g.tpFilterActors(actors, 'Low').length, 1);
  assert.match(g.tpSummary(actors), /Actors tracked/);
  assert.match(g.tpFactorsHtml([{ name: EVIL, explanation: EVIL, available: false }]), /Not yet validated/);
  assert.ok(!g.tpFactorsHtml([{ name: EVIL, explanation: EVIL, available: true, rawScore: 50 }]).includes('<img'));
  assert.match(g.tpHistoryHtml([]), /No history/);
  assert.doesNotThrow(() => g.tpHistoryHtml([{ recordedAt: 'bad', score: 3 }, { recordedAt: '2026-10-01', score: 5 }]));
});

test('recommendation and exercise summaries', () => {
  const list = [{ techniqueId: 'T1', name: EVIL, tactic: EVIL, score: 80, tier: 'High', coverageState: 'never-tested', kev: true, environmentRisk: EVIL, reasons: [EVIL] }];
  assert.ok(!g.recRowsHtml(list).includes('<img'));
  assert.ok(!g.recSummary(list, { artTechniques: [EVIL] }).includes('<img'));
  assert.equal(g.recSummary([], null), '');
  assert.equal(g.exSummary({}), '');
  assert.ok(!g.exSummary({ scen: [{ Severity: EVIL, Category: EVIL }], exs: [], plans: [], execs: [{ status: EVIL }] }).includes('<img'));
});
