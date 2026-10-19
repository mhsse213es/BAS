import { test } from 'node:test';
import assert from 'node:assert/strict';
import { libraryEntryRoute } from '../../src/features/scenario-library-route.js';

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
