import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { setupDom, load } from './dom.mjs';

setupDom();
const fns = await load([
  'openRevokeAgentModal', 'submitRevokeAgent', 'openReinstateAgentModal', 'submitReinstateAgent', 'agentRevokeMenuItems',
]);

function stubNetwork({ response = { ok: true }, confirmAnswer = true } = {}) {
  const calls = [];
  globalThis.fetch = (path, init) => { calls.push({ path, init }); return Promise.resolve({ status: 200, json: () => Promise.resolve(response) }); };
  globalThis.confirm = () => confirmAnswer;
  return calls;
}
const flush = () => new Promise((r) => setTimeout(r, 0));

test('the revoke and reinstate modals exist in the dashboard', () => {
  for (const p of ['revoke-agent', 'reinstate-agent']) {
    for (const suffix of ['overlay', 'target-sub', 'reason', 'submit-btn']) {
      assert.ok(document.getElementById(`${p}-${suffix}`), `missing #${p}-${suffix}`);
    }
  }
});

test('every action the new buttons name is registered in globals.js', () => {
  const globals = readFileSync(new URL('../../src/globals.js', import.meta.url), 'utf8');
  for (const name of ['submitRevokeAgent', 'closeRevokeAgentModal', 'submitReinstateAgent', 'closeReinstateAgentModal', 'rowMenuRevokeAgent', 'rowMenuReinstateAgent']) {
    assert.ok(globals.includes(name), `${name} is not registered`);
  }
});

test('revoking needs a reason and sends nothing without one', async () => {
  const calls = stubNetwork();
  fns.openRevokeAgentModal('abc123deadbeef01', 'host-1');
  fns.submitRevokeAgent();
  await flush();
  assert.equal(calls.length, 0);
});

test('revoking asks for confirmation and sends nothing if declined', async () => {
  const calls = stubNetwork({ confirmAnswer: false });
  fns.openRevokeAgentModal('abc123deadbeef01', 'host-1');
  document.getElementById('revoke-agent-reason').value = 'laptop stolen';
  fns.submitRevokeAgent();
  await flush();
  assert.equal(calls.length, 0);
});

test('revoking posts the reason to the revoke endpoint and closes the dialog', async () => {
  const calls = stubNetwork();
  fns.openRevokeAgentModal('abc123deadbeef01', 'host-1');
  document.getElementById('revoke-agent-reason').value = 'laptop stolen';
  fns.submitRevokeAgent();
  await flush();
  const revoke = calls.find((c) => c.path === '/api/agents/abc123deadbeef01/revoke');
  assert.ok(revoke, 'no call to the revoke endpoint');
  assert.equal(revoke.init.method, 'POST');
  assert.deepEqual(JSON.parse(revoke.init.body), { reason: 'laptop stolen' });
  assert.ok(!document.getElementById('revoke-agent-overlay').classList.contains('open'));
});

test('a server error keeps the revoke dialog open', async () => {
  stubNetwork({ response: { error: 'agent not found' } });
  fns.openRevokeAgentModal('abc123deadbeef01', 'host-1');
  document.getElementById('revoke-agent-reason').value = 'x';
  fns.submitRevokeAgent();
  await flush();
  assert.ok(document.getElementById('revoke-agent-overlay').classList.contains('open'));
});

test('reinstating posts the reason to the reinstate endpoint', async () => {
  const calls = stubNetwork();
  fns.openReinstateAgentModal('abc123deadbeef01', 'host-1');
  document.getElementById('reinstate-agent-reason').value = 're-imaged';
  fns.submitReinstateAgent();
  await flush();
  const c = calls.find((x) => x.path === '/api/agents/abc123deadbeef01/reinstate');
  assert.ok(c, 'no call to the reinstate endpoint');
  assert.deepEqual(JSON.parse(c.init.body), { reason: 're-imaged' });
});

test('menu items: admins see Revoke for a live agent and Reinstate for a revoked one, others see nothing', () => {
  const live = { agentId: 'a1', hostname: 'h', state: 'active' };
  const revoked = { agentId: 'a1', hostname: 'h', state: 'revoked' };
  assert.match(fns.agentRevokeMenuItems(live, true), /rowMenuRevokeAgent/);
  assert.doesNotMatch(fns.agentRevokeMenuItems(live, true), /rowMenuReinstateAgent/);
  assert.match(fns.agentRevokeMenuItems(revoked, true), /rowMenuReinstateAgent/);
  assert.doesNotMatch(fns.agentRevokeMenuItems(revoked, true), /rowMenuRevokeAgent/);
  assert.equal(fns.agentRevokeMenuItems(live, false), '');
  for (const state of ['retired', 'uninstalled']) {
    assert.equal(fns.agentRevokeMenuItems({ agentId: 'a1', state }, true), '', `${state} agents have nothing to revoke`);
  }
});
