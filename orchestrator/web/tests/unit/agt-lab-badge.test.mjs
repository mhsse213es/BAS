import { test } from 'node:test';
import assert from 'node:assert/strict';

// agt-view.js reads the DOM only inside handlers, but give it a minimal document in case an import touches one.
globalThis.document ??= { addEventListener() {}, getElementById() { return null; }, querySelector() { return null; } };
const { statusCellHtml } = await import('../../src/features/agt-view.js');

test('status cell: the Threat Factory lab agent shows the lab tag', () => {
  const h = statusCellHtml({ agentId: 'lab', factoryLab: true, status: 'idle', state: 'active', wsConnected: true, transport: 'mtls' }, null);
  assert.match(h, /agt-flag-lab/);
  assert.match(h, /Threat Factory lab/);
  assert.doesNotMatch(h, /not connected/);
});

test('status cell: an offline lab agent is marked and says it is not connected', () => {
  const h = statusCellHtml({ agentId: 'lab', factoryLab: true, status: 'offline', state: 'active', wsConnected: false, transport: 'mtls' }, null);
  assert.match(h, /agt-flag-lab-down/);
  assert.match(h, /\(not connected\)/);
});

test('status cell: an ordinary agent has no lab tag', () => {
  const h = statusCellHtml({ agentId: 'a1', factoryLab: false, status: 'idle', state: 'active', wsConnected: true, transport: 'mtls' }, null);
  assert.doesNotMatch(h, /Threat Factory lab/);
  assert.doesNotMatch(h, /agt-flag-lab/);
});
