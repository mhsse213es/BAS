import { test } from 'node:test';
import assert from 'node:assert/strict';
import { planRunBody, labClusterOptions } from '../../src/features/k8s-model.js';

test('a plan request carries the registry ID and never a cluster name', () => {
  const body = planRunBody('k8sc-lab', 'bas-sandbox', 'configmap-patch-labelled', { name: 'x' });
  assert.equal(body.clusterId, 'k8sc-lab');
  assert.equal('cluster' in body, false);
  assert.equal(body.namespace, 'bas-sandbox');
  assert.deepEqual(body.params, { name: 'x' });
});

test('the picker offers lab-class clusters only, keyed by registry ID', () => {
  const opts = labClusterOptions([
    { id: 'k8sc-lab', displayName: 'kind-bas-lab', class: 'lab' },
    { id: 'k8sc-prod', displayName: 'prod-east', class: 'production' },
    { id: 'k8sc-nonprod', displayName: 'stage', class: 'non-production' },
  ]);
  assert.deepEqual(opts, [{ id: 'k8sc-lab', label: 'kind-bas-lab' }]);
});

test('the picker is empty when no list is returned', () => {
  assert.deepEqual(labClusterOptions(null), []);
  assert.deepEqual(labClusterOptions({ error: 'nope' }), []);
});
