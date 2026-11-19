import { test } from 'node:test';
import assert from 'node:assert/strict';
import { stateGroup, k8sRunCounts, heroStats, clusterCards, filterRuns, planSteps, paramRows } from '../../src/features/k8s-model.js';

const R = (id, cluster, namespace, state, extra) => Object.assign({ id, cluster, namespace, state, action: 'sa-token-probe', requester: 'alice' }, extra);
const runs = [R('1', 'a', 'x', 'PLANNED'), R('2', 'a', 'y', 'CLEANED'), R('3', 'b', 'x', 'FAILED'), R('4', 'a', 'x', 'APPROVED')];

test('states map to outcome groups', () => {
  assert.equal(stateGroup('DRY_RUN_PLANNED'), 'pending');
  assert.equal(stateGroup('APPROVED'), 'ready');
  assert.equal(stateGroup('CLEANED'), 'clean');
  assert.equal(stateGroup('CLEANUP_FAILED'), 'problem');
  assert.equal(stateGroup('DISCARDED_NOT_REVOKED'), 'problem');
});

test('counts and hero numbers come from the rows', () => {
  assert.deepEqual(k8sRunCounts(runs), { total: 4, pending: 1, ready: 1, clean: 1, problem: 1 });
  assert.deepEqual(heroStats(runs), { clusters: 2, runs: 4, pending: 2, problem: 1 });
  assert.deepEqual(heroStats([]), { clusters: 0, runs: 0, pending: 0, problem: 0 });
});

test('cluster cards are busiest first with a tone and clean share', () => {
  const c = clusterCards(runs);
  assert.deepEqual(c.map((e) => e.id), ['a', 'b']);
  assert.equal(c[0].runs, 3);
  assert.equal(c[0].nsCount, 2);
  assert.equal(c[0].cleanPct, 33);
  assert.equal(c[0].tone, 'warn');
  assert.equal(c[1].tone, 'bad');
  assert.equal(clusterCards([R('9', 'z', 'n', 'CLEANED')])[0].label, 'All clean');
});

test('filter by cluster, state group and search text', () => {
  assert.equal(filterRuns(runs, { cluster: 'a' }).length, 3);
  assert.equal(filterRuns(runs, { group: 'problem' }).length, 1);
  assert.equal(filterRuns(runs, { q: 'FAILED' }).length, 0);
  assert.equal(filterRuns(runs, { q: 'probe token' }, () => 'Mint and discard a probe token').length, 4);
  assert.equal(filterRuns(runs, { q: 'ALICE', cluster: 'b' }).length, 1);
});

test('plan lines and parameters', () => {
  assert.deepEqual(planSteps('a\n\n b \n'), ['a', 'b']);
  assert.deepEqual(planSteps(undefined), []);
  assert.deepEqual(paramRows({ value: 'on', name: 'p' }), [['name', 'p'], ['value', 'on']]);
  assert.deepEqual(paramRows(null), []);
});
