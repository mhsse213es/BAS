import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

// Drives the real console actions for revoking, un-revoking and the minimum agent version: what is asked, what is sent.

const HASH = 'a'.repeat(64);

// ask: type into the in-page version prompt and confirm it.
function ask(value) { document.getElementById('ask-input').value = value; }
async function ready(answers) {
  setupDom();
  const calls = [];
  globalThis.fetch = async (url, opts) => {
    calls.push({ url, method: (opts && opts.method) || 'GET', body: opts && opts.body });
    const body = String(url).includes('min-agent')
      ? { version: '1.9.9.3', source: 'previous-release', default: '1.9.9.3' }
      : { sha256: HASH, agentsStillQuarantined: 2, items: [] };
    return { status: 200, ok: true, json: async () => body, text: async () => JSON.stringify(body) };
  };
  const fns = await load(['runConfirmDiffModal', 'unrevokeAgentBinary', 'revokeAgentBinary', 'toggleMinAgentVersion', 'minAgentVersionLabel']);
  const { state } = await import('../../src/core/state.js');
  return { fns, calls, state };
}
const tick = () => new Promise((r) => setTimeout(r, 20));
const writes = (calls) => calls.filter((c) => c.method !== 'GET');

test('un-revoke asks first, then sends a DELETE for that hash only', async () => {
  const { fns, calls } = await ready({ confirm: false });
  fns.unrevokeAgentBinary(HASH);
  await tick();
  assert.equal(writes(calls).length, 0, 'until the dialog is confirmed nothing is sent');

  const r2 = await ready({ confirm: true });
  r2.fns.unrevokeAgentBinary(HASH);
  r2.fns.runConfirmDiffModal();
  await tick();
  const w = writes(r2.calls);
  assert.equal(w.length, 1);
  assert.equal(w[0].method, 'DELETE');
  assert.equal(w[0].url, '/api/agent-binaries/revocations/' + HASH);
});

test('the revoke confirmation no longer says the console cannot undo it', async () => {
  setupDom();
  globalThis.fetch = async () => ({ status: 200, ok: true, json: async () => ({}), text: async () => '{}' });
  const { revokeAgentBinary } = await load(['revokeAgentBinary']);
  revokeAgentBinary(HASH);
  const asked = document.getElementById('confirm-diff-body').textContent;
  assert.ok(asked.length > 20, 'the dialog explains the effect');
  assert.doesNotMatch(asked, /cannot undo/i);
});

test('the minimum label says when it is the previous release', async () => {
  const { fns } = await ready({});
  assert.equal(fns.minAgentVersionLabel('1.9.9.3', 'previous-release'), 'Min agent 1.9.9.3 (previous release)');
  assert.equal(fns.minAgentVersionLabel('1.9.0', 'setting'), 'Min agent 1.9.0');
  assert.equal(fns.minAgentVersionLabel('', 'none'), 'Min agent: none');
});

test('typing "default" removes the setting; a version sets it; "default" with nothing to go back to sends nothing', async () => {
  let r = await ready({ prompt: 'default' });
  r.state.minAgentVersionDefault = '1.9.9.3';
  r.fns.toggleMinAgentVersion();
  ask('default'); r.fns.runConfirmDiffModal();
  await tick();
  let w = writes(r.calls);
  assert.deepEqual(w.map((c) => c.method + ' ' + c.url), ['DELETE /api/fleet/min-agent-version']);
  assert.equal(r.state.minAgentVersionSource, 'previous-release');

  r = await ready({ prompt: ' 1.9.0 ' });
  r.fns.toggleMinAgentVersion();
  ask(' 1.9.0 '); r.fns.runConfirmDiffModal();
  await tick();
  w = writes(r.calls);
  assert.equal(w[0].method, 'PUT');
  assert.equal(JSON.parse(w[0].body).version, '1.9.0');

  r = await ready({ prompt: 'default' });
  r.state.minAgentVersionDefault = '';
  r.fns.toggleMinAgentVersion();
  ask('default'); r.fns.runConfirmDiffModal();
  await tick();
  assert.equal(writes(r.calls).length, 0);
});
