import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildPhishingRunRequest, withExecutionLink } from '../../src/features/scenario-library-route.js';

const entry = {
  type: 'phishing',
  id: 'PH-ID-001',
  status: 'available',
  parameters: [{ name: 'executionId', kind: 'text', required: true }],
};

test('an execution ID is added to the request parameters', () => {
  const built = buildPhishingRunRequest(entry, { executionId: 'exec-1' });
  const linked = withExecutionLink(built, 'exec-1');
  assert.deepEqual(linked, { ok: true, body: { scenarioId: 'PH-ID-001', parameters: { executionId: 'exec-1' } } });
});

test('an empty execution link leaves the request exactly as built', () => {
  const built = buildPhishingRunRequest({ ...entry, parameters: [] }, {});
  assert.deepEqual(withExecutionLink(built, ''), built);
  assert.deepEqual(withExecutionLink(built, '   '), built);
  assert.deepEqual(withExecutionLink(built, undefined), built);
});

test('the execution ID is trimmed before it is sent', () => {
  const built = { ok: true, body: { scenarioId: 'PH-BEC-001', parameters: {} } };
  assert.equal(withExecutionLink(built, '  exec-9 ').body.parameters.executionId, 'exec-9');
});

test('a refused request stays refused and gains no link', () => {
  const refused = { ok: false, errors: ['executionId'] };
  assert.deepEqual(withExecutionLink(refused, 'exec-1'), refused);
});
