import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

// The feature module touches document at import time, so give it a document first.
const dom = new JSDOM('<!DOCTYPE html><body><div id="k8s-runs"></div></body>', { url: 'http://127.0.0.1/' });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
globalThis.localStorage = dom.window.localStorage;
globalThis.sessionStorage = dom.window.sessionStorage;
globalThis.location = dom.window.location;
const { renderK8sRuns } = await import('../../src/features/k8s-scenarios.js');

function run(over) {
  return Object.assign({
    id: 'k8sr-1', requester: 'alice', cluster: 'kind-bas-lab', namespace: 'bas-sandbox',
    action: 'pod-create-unprivileged', params: { name: 'bas-sbx-1' }, state: 'PLANNED', detail: '', approvalId: ''
  }, over);
}

test('a planned run offers Approve, and never Execute', () => {
  renderK8sRuns([run({ state: 'PLANNED' })]);
  const html = document.getElementById('k8s-runs').innerHTML;
  assert.match(html, /data-k8s-approve="k8sr-1"/);
  assert.doesNotMatch(html, /data-k8s-execute/);
});

test('an approved run offers Execute, and never Approve', () => {
  renderK8sRuns([run({ state: 'APPROVED' })]);
  const html = document.getElementById('k8s-runs').innerHTML;
  assert.match(html, /data-k8s-execute="k8sr-1"/);
  assert.doesNotMatch(html, /data-k8s-approve/);
});

test('a finished run offers no action button', () => {
  renderK8sRuns([run({ state: 'CLEANED' })]);
  const html = document.getElementById('k8s-runs').innerHTML;
  assert.doesNotMatch(html, /data-k8s-(approve|execute)/);
});

test('a failed cleanup is labelled as failed, not as cleaned', () => {
  renderK8sRuns([run({ state: 'CLEANUP_FAILED' })]);
  const html = document.getElementById('k8s-runs').innerHTML;
  assert.match(html, /Cleanup FAILED/);
  assert.doesNotMatch(html, /Ran, verified, cleaned up/);
});

test('server-supplied text is escaped, not rendered as markup', () => {
  renderK8sRuns([run({ requester: '<img src=x onerror=alert(1)>', detail: '<script>bad()</script>' })]);
  const host = document.getElementById('k8s-runs');
  assert.equal(host.querySelector('img'), null);
  assert.equal(host.querySelector('script'), null);
  assert.match(host.innerHTML, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('an empty list says nothing has been written', () => {
  renderK8sRuns([]);
  assert.match(document.getElementById('k8s-runs').textContent, /Planning writes nothing|No runs yet/);
});

test('a discarded token is labelled as not revoked, never as cleaned', () => {
  renderK8sRuns([run({ state: 'DISCARDED_NOT_REVOKED', detail: 'valid until 2026-10-23T06:31:38Z' })]);
  const html = document.getElementById('k8s-runs').innerHTML;
  assert.match(html, /NOT revoked/);
  assert.doesNotMatch(html, /cleaned up/);
  assert.doesNotMatch(html, /data-k8s-(approve|execute)/);
});
