import { test } from 'node:test';
import assert from 'node:assert/strict';

const M = await import('../../src/features/rec-model.js');

test('re-validate applies to a plain ATT&CK technique ID', () => {
  assert.equal(M.canRevalidate({ techniqueId: 'T1003' }), true);
  assert.equal(M.canRevalidate({ techniqueId: 'T1003.002' }), true);
  assert.equal(M.canRevalidate({ techniqueId: 't1059.001' }), true);
});

test('re-validate is not offered for a row without a usable technique ID', () => {
  assert.equal(M.canRevalidate({ techniqueId: '' }), false);
  assert.equal(M.canRevalidate({ techniqueId: 'custom-step-7' }), false);
  assert.equal(M.canRevalidate({}), false);
  assert.equal(M.canRevalidate(undefined), false);
});
