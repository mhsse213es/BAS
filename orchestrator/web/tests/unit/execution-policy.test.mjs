import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

// ROLE is read from localStorage when shell.js first loads, so the role must be
// set before load() imports the modules.
setupDom();
globalThis.localStorage.setItem('bas_role', 'admin');
const { loadExecutionPolicyDefault, saveExecutionPolicyDefault } = await load(['loadExecutionPolicyDefault', 'saveExecutionPolicyDefault']);

const realFetch = globalThis.fetch;

function mockFetch(handler) {
  const calls = [];
  globalThis.fetch = async (url, opts = {}) => {
    calls.push({ url, method: opts.method || 'GET', body: opts.body });
    const body = handler(url, opts);
    return { status: 200, json: async () => body };
  };
  return calls;
}

function flush() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function freshDom() {
  setupDom();
  globalThis.localStorage.setItem('bas_role', 'admin');
}

test.after(() => { globalThis.fetch = realFetch; });

test('loading shows the installation default as the selected option', async () => {
  freshDom();
  mockFetch(() => ({ inProcessPolicy: 'restricted' }));
  loadExecutionPolicyDefault();
  await flush(); await flush();
  const sel = document.getElementById('execution-policy-select');
  assert.ok(sel, 'the policy select must render');
  assert.equal(sel.value, 'restricted');
});

test('an unset default is shown as not stated, never as a chosen policy', async () => {
  freshDom();
  mockFetch(() => ({ inProcessPolicy: '' }));
  loadExecutionPolicyDefault();
  await flush(); await flush();
  const sel = document.getElementById('execution-policy-select');
  assert.equal(sel.value, '');
  assert.ok(sel.options[sel.selectedIndex].textContent.includes('Not stated'));
});

test('saving sends exactly the chosen value and reports it saved', async () => {
  freshDom();
  const calls = mockFetch((url, opts) => (opts.method === 'PUT' ? { inProcessPolicy: 'unrestricted' } : { inProcessPolicy: '' }));
  loadExecutionPolicyDefault();
  await flush(); await flush();
  document.getElementById('execution-policy-select').value = 'unrestricted';
  saveExecutionPolicyDefault();
  await flush(); await flush();
  const put = calls.find((c) => c.method === 'PUT');
  assert.ok(put, 'a PUT must be sent');
  assert.equal(put.url, '/api/execution-policy/default');
  assert.equal(put.body, JSON.stringify({ inProcessPolicy: 'unrestricted' }));
  assert.ok(document.getElementById('execution-policy-result').textContent.startsWith('Saved:'));
});

test('a rejected save is reported as not saved, not as success', async () => {
  freshDom();
  mockFetch((url, opts) => (opts.method === 'PUT'
    ? { error: 'inProcessPolicy must be restricted, unrestricted, or empty (not stated)' }
    : { inProcessPolicy: '' }));
  loadExecutionPolicyDefault();
  await flush(); await flush();
  saveExecutionPolicyDefault();
  await flush(); await flush();
  const text = document.getElementById('execution-policy-result').textContent;
  assert.ok(text.startsWith('Not saved:'), `expected a not-saved message, got "${text}"`);
});
