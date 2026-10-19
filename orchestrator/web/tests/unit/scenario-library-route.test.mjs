import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildPhishingRunRequest, libraryEntryRoute } from '../../src/features/scenario-library-route.js';

test('an executable agent entry routes to the agent path only', () => {
  assert.deepEqual(libraryEntryRoute({ type: 'agent', id: 'sc-1', status: 'executable' }), { kind: 'agent', id: 'sc-1' });
});

test('an executable phishing entry routes to the phishing path only', () => {
  assert.deepEqual(libraryEntryRoute({ type: 'phishing', id: 'PH-DET-002', status: 'executable' }), { kind: 'phishing', id: 'PH-DET-002' });
});

test('an experimental phishing entry is runnable and routes to phishing', () => {
  assert.deepEqual(libraryEntryRoute({ type: 'phishing', id: 'PH-ID-004', status: 'experimental' }), { kind: 'phishing', id: 'PH-ID-004' });
});

test('an available (catalog-only) phishing entry has no execution path', () => {
  assert.deepEqual(libraryEntryRoute({ type: 'phishing', id: 'PH-CHN-001', status: 'available' }), { kind: 'none' });
});

test('a phishing-looking ID with no type is not inferred as phishing', () => {
  assert.deepEqual(libraryEntryRoute({ id: 'PH-DET-002', status: 'executable' }), { kind: 'none' });
});

test('a missing, unknown, or differently-cased type has no execution path', () => {
  for (const type of [undefined, null, '', 'Phishing', 'AGENT', 'agent ', 'email', 'phish']) {
    assert.deepEqual(libraryEntryRoute({ type, id: 'x', status: 'executable' }), { kind: 'none' }, `type=${JSON.stringify(type)}`);
  }
});

test('a non-object or empty entry has no execution path', () => {
  for (const entry of [null, undefined, 'PH-DET-002', 42, {}]) {
    assert.deepEqual(libraryEntryRoute(entry), { kind: 'none' });
  }
});

test('an unknown status never routes, whatever the type', () => {
  for (const status of [undefined, 'available', 'pending', 'EXECUTABLE']) {
    assert.deepEqual(libraryEntryRoute({ type: 'phishing', id: 'PH-DET-002', status }), { kind: 'none' });
    assert.deepEqual(libraryEntryRoute({ type: 'agent', id: 'sc-1', status }), { kind: 'none' });
  }
});

test('agent and phishing paths are mutually exclusive for every input', () => {
  const types = ['agent', 'phishing', '', undefined, 'other'];
  const statuses = ['executable', 'experimental', 'available', undefined];
  for (const type of types) {
    for (const status of statuses) {
      const r = libraryEntryRoute({ type, id: 'id', status });
      if (r.kind === 'agent') assert.equal(type, 'agent');
      if (r.kind === 'phishing') assert.equal(type, 'phishing');
      assert.ok(['agent', 'phishing', 'none'].includes(r.kind));
    }
  }
});


const detEntry = {
  type: 'phishing', id: 'PH-DET-002', status: 'executable',
  parameters: [
    { name: 'executionId', label: 'Execution ID', kind: 'text', required: true },
    { name: 'targetId', label: 'Target ID', kind: 'text', required: true },
  ],
};

test('a complete phishing form builds the request body with its parameters', () => {
  const r = buildPhishingRunRequest(detEntry, { executionId: ' exec-1 ', targetId: 'tgt-2' });
  assert.deepEqual(r, { ok: true, body: { scenarioId: 'PH-DET-002', parameters: { executionId: 'exec-1', targetId: 'tgt-2' } } });
});

test('a missing required field is reported and no body is built', () => {
  const r = buildPhishingRunRequest(detEntry, { executionId: 'exec-1', targetId: '   ' });
  assert.equal(r.ok, false);
  assert.deepEqual(r.errors, ['targetId']);
  assert.equal(r.body, undefined);
});

test('a number field must be a positive integer and is sent as a number', () => {
  const entry = { type: 'phishing', id: 'PH-ID-004', status: 'experimental', parameters: [
    { name: 'userId', kind: 'text', required: true },
    { name: 'threshold', kind: 'number', required: true },
  ] };
  assert.equal(buildPhishingRunRequest(entry, { userId: 'u', threshold: '5' }).body.parameters.threshold, 5);
  for (const bad of ['0', '-3', '2.5', 'abc']) {
    assert.equal(buildPhishingRunRequest(entry, { userId: 'u', threshold: bad }).ok, false, `threshold=${bad}`);
  }
});

test('an email field needs an address shape', () => {
  const entry = { type: 'phishing', id: 'PH-CHN-004', status: 'executable', parameters: [
    { name: 'attendeeEmail', kind: 'email', required: true },
  ] };
  assert.equal(buildPhishingRunRequest(entry, { attendeeEmail: 'not-an-address' }).ok, false);
  assert.equal(buildPhishingRunRequest(entry, { attendeeEmail: 'lab@example-lab.test' }).ok, true);
});

test('only schema fields are sent; extra values from the form are dropped', () => {
  const r = buildPhishingRunRequest(detEntry, { executionId: 'e', targetId: 't', scenarioId: 'PH-OTHER', evil: 'x' });
  assert.deepEqual(r.body.parameters, { executionId: 'e', targetId: 't' });
  assert.equal(r.body.scenarioId, 'PH-DET-002');
});

test('a scenario with no schema builds a body with empty parameters', () => {
  const r = buildPhishingRunRequest({ type: 'phishing', id: 'PH-ID-003', status: 'executable' }, {});
  assert.deepEqual(r, { ok: true, body: { scenarioId: 'PH-ID-003', parameters: {} } });
});

test('a non-runnable or non-phishing entry never builds a phishing request', () => {
  assert.equal(buildPhishingRunRequest({ type: 'phishing', id: 'PH-CHN-001', status: 'available', parameters: [] }, {}).ok, false);
  assert.equal(buildPhishingRunRequest({ type: 'agent', id: 'sc-1', status: 'executable', parameters: [] }, {}).ok, false);
  assert.equal(buildPhishingRunRequest(null, {}).ok, false);
});
