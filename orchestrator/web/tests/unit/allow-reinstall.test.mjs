import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { setupDom, load } from './dom.mjs';

setupDom();
const fns = await load(['openAllowReinstallModal', 'submitAllowReinstall', 'agentRevokeMenuItems']);

function stubNetwork({ response = { ok: true }, confirmAnswer = true } = {}) {
  const calls = [];
  globalThis.fetch = (path, init) => { calls.push({ path, init }); return Promise.resolve({ status: 200, json: () => Promise.resolve(response) }); };
  globalThis.confirm = () => confirmAnswer;
  return calls;
}
const flush = () => new Promise((r) => setTimeout(r, 0));

test('the allow-reinstall modal exists in the dashboard', () => {
  for (const suffix of ['overlay', 'target-sub', 'reason', 'submit-btn']) {
    assert.ok(document.getElementById(`allow-reinstall-agent-${suffix}`), `missing #allow-reinstall-agent-${suffix}`);
  }
});

test('every action the allow-reinstall button names is registered in globals.js', () => {
  const globals = readFileSync(new URL('../../src/globals.js', import.meta.url), 'utf8');
  for (const name of ['submitAllowReinstall', 'closeAllowReinstallModal', 'rowMenuAllowReinstall']) {
    assert.ok(globals.includes(name), `${name} is not registered`);
  }
});

test('approving a reinstall needs a reason and sends nothing without one', async () => {
  const calls = stubNetwork();
  fns.openAllowReinstallModal('abc123deadbeef01', 'host-1');
  fns.submitAllowReinstall();
  await flush();
  assert.equal(calls.length, 0);
});

test('approving a reinstall posts the reason to the allow-reinstall endpoint and closes the dialog', async () => {
  const calls = stubNetwork();
  fns.openAllowReinstallModal('abc123deadbeef01', 'host-1');
  document.getElementById('allow-reinstall-agent-reason').value = 'disk reimaged';
  fns.submitAllowReinstall();
  await flush();
  const c = calls.find((x) => x.path === '/api/agents/abc123deadbeef01/allow-reinstall');
  assert.ok(c, 'no call to the allow-reinstall endpoint');
  assert.equal(c.init.method, 'POST');
  assert.deepEqual(JSON.parse(c.init.body), { reason: 'disk reimaged' });
  assert.equal(document.getElementById('allow-reinstall-agent-overlay').classList.contains('open'), false);
});

test('the row menu offers Allow reinstall to admins for a live host only', () => {
  const live = { agentId: 'a1', hostname: 'h', state: 'active' };
  assert.match(fns.agentRevokeMenuItems(live, true), /rowMenuAllowReinstall/);
  assert.doesNotMatch(fns.agentRevokeMenuItems(live, false), /rowMenuAllowReinstall/);
  assert.doesNotMatch(fns.agentRevokeMenuItems({ agentId: 'a1', state: 'revoked' }, true), /rowMenuAllowReinstall/);
  assert.doesNotMatch(fns.agentRevokeMenuItems({ agentId: 'a1', state: 'uninstalled' }, true), /rowMenuAllowReinstall/);
});
