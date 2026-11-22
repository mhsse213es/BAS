import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sourceState, sourceRows, sourceCounts, heroStats, funnelStages, qualityLines } from '../../src/features/fh-model.js';

const S = [
  { sourceInstanceId: 'a', displayName: 'MITRE', lastSuccessAt: '2026-10-01T00:00:00Z', failuresInWindow: 0 },
  { sourceInstanceId: 'b', displayName: 'OTX', lastSuccessAt: '2026-10-01T00:00:00Z', failuresInWindow: 3, lastDiagnostic: 'HTTP 429' },
  { sourceInstanceId: 'c', displayName: 'OpenCTI', lastSuccessAt: null, failuresInWindow: 1 },
];

test('sourceState: never synced beats failing beats healthy', () => {
  assert.equal(sourceState(S[0]).key, 'healthy');
  assert.equal(sourceState(S[1]).key, 'failing');
  assert.equal(sourceState(S[2]).key, 'never');
  assert.equal(sourceState(null).key, 'never');
});

test('sourceRows and sourceCounts', () => {
  const rows = sourceRows(S);
  assert.equal(rows[1].diagnostic, 'HTTP 429');
  assert.equal(rows[2].lastSuccessAt, null);
  assert.deepEqual(sourceCounts(S), { total: 3, healthy: 1, failing: 1, never: 1 });
  assert.equal(sourceRows(null).length, 0);
});

test('heroStats uses only returned numbers and null for no data', () => {
  const h = heroStats({ threatsProcessed: { state: 'measured', value: 10 }, publishedContent: { state: 'no_data' }, pipeline: { ingestion: { sources: S, unresolvedCandidates: 7 } } });
  assert.deepEqual(h, { threats: 10, published: null, sources: '1 / 3', unresolved: 7 });
  assert.deepEqual(heroStats({}), { threats: null, published: null, sources: null, unresolved: null });
});

test('funnelStages and qualityLines', () => {
  assert.deepEqual(funnelStages({ candidate: 5, published: 2 }).map((s) => s.value), [5, 0, 2, 0]);
  const q = qualityLines({ staleSources: ['OTX'], staleValidations: 2 });
  assert.deepEqual(q.map((l) => l.tone), ['warn', 'warn']);
  assert.equal(q[0].text, 'Stale sources: OTX');
  assert.deepEqual(qualityLines({}).map((l) => l.text), ['No stale sources', '0 stuck in validation']);
});

test('qualityLines reports scenarios the validation lab stopped retrying, and stays quiet otherwise', () => {
  assert.equal(qualityLines({ staleSources: [], staleValidations: 0, stalledValidations: [] }).length, 2);
  const one = qualityLines({ stalledValidations: [{ contentId: 'intel-1', version: 1, attempts: 3 }] });
  assert.equal(one.length, 3);
  assert.equal(one[2].tone, 'warn');
  assert.equal(one[2].text, '1 scenario stopped after 3 failed validation attempts and needs editing: intel-1 v1');
  const many = qualityLines({ stalledValidations: Array.from({ length: 7 }, (_, i) => ({ contentId: 'c' + i, version: 1, attempts: 3 })) });
  assert.match(many[2].text, /^7 scenarios stopped/);
  assert.match(many[2].text, /and 2 more$/);
});

// ── KPI tiles and per-source reliability ─────────────────────────────────────
import { kpiTiles, freshnessText, rateText, COLUMNS, cellText, sourceRows as rows2 } from '../../src/features/fh-model.js';

const mm = (v) => ({ state: 'measured', value: v });
const nd = (reason) => ({ state: 'no_data', reason });

test('rateText shows a percentage for a measured rate and an em dash for no data', () => {
  assert.equal(rateText(mm(0.5)), '50%');
  assert.equal(rateText(mm(0)), '0%');
  assert.equal(rateText(nd('x')), '—');
  assert.equal(rateText(undefined), '—');
});

test('freshnessText summarises the age buckets, and says so when nothing is published', () => {
  assert.equal(freshnessText({ total: 0 }), 'Nothing published yet');
  assert.equal(freshnessText({ total: 10, under30Days: 6, days31To90: 2, days91To365: 1, over365Days: 1 }),
    '6 under 30d · 2 at 31–90d · 1 at 91–365d · 1 over a year');
  assert.equal(freshnessText({ total: 4, under30Days: 4, days31To90: 0, days91To365: 0, over365Days: 0 }), '4 under 30d');
  assert.equal(freshnessText(undefined), 'Nothing published yet');
});

test('kpiTiles keeps measured zero distinct from no data, and never invents a value', () => {
  const tiles = kpiTiles({
    threatsIngestedPerDay: mm(0), publishedPerDay: nd('window'), candidatesGeneratedPerDay: mm(2.5),
    candidatesValidated: mm(3), candidatesRejected: mm(1), threatsMapped: mm(4),
    executionValidationPassRate: mm(0.75), executionValidationErrors: mm(2),
    handsOffRate: mm(0.4), stageAutomationRate: nd('none'), reuseRate: mm(0.667),
    contentFreshness: { total: 2, under30Days: 2 },
  });
  const by = Object.fromEntries(tiles.map(t => [t.key, t]));
  assert.equal(by.ingested.value, '0.0 / day');      // measured zero
  assert.equal(by.published.value, null);            // no data: the page shows NO DATA
  assert.equal(by.generated.value, '2.5 / day');
  assert.equal(by.validated.value, '3');
  assert.equal(by.rejected.value, '1');
  assert.equal(by.mapped.value, '4');
  assert.equal(by.execpass.value, '75%');
  assert.match(by.execpass.caption, /2 errors/);     // ERROR reported, kept out of the rate
  assert.equal(by.handsoff.value, '40%');
  assert.equal(by.stageauto.value, null);
  assert.equal(by.reuse.value, '67%');
  assert.equal(by.freshness.value, '2');
});

test('a report from an older server (no new fields) yields no-data tiles, not a crash', () => {
  const tiles = kpiTiles({});
  assert.ok(tiles.length >= 10);
  tiles.filter(t => t.key !== 'freshness').forEach(t => assert.equal(t.value, null, t.key));
});

test('source rows carry reliability rates and the table columns include them', () => {
  const r = rows2([{ sourceInstanceId: 's', displayName: 'S', lastSuccessAt: '2026-01-01T00:00:00Z', failuresInWindow: 0,
    reliability: { syncSuccessRate: mm(0.5), resolutionRate: mm(1), usefulnessRate: nd('none') } }])[0];
  assert.deepEqual(COLUMNS.slice(4, 7), ['Sync success', 'Resolution', 'Usefulness']);
  assert.equal(cellText(r, 4), '50%');
  assert.equal(cellText(r, 5), '100%');
  assert.equal(cellText(r, 6), '—');
  assert.equal(cellText(r, 7), '');                  // last diagnostic stays last
  // an older server with no reliability block must not break the row
  assert.equal(cellText(rows2([{ sourceInstanceId: 'o' }])[0], 4), '—');
});
