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
