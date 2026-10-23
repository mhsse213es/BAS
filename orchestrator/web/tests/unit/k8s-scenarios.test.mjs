import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

// The feature module touches document at import time, so give it a document first.
const dom = new JSDOM('<!DOCTYPE html><body><div id="k8s-runs"></div>' +
  '<span id="k8s-an-meta"></span><input type="checkbox" id="k8s-an-system"><div id="k8s-an-kpis"></div><div id="k8s-an-body"></div>' +
  '</body>', { url: 'http://127.0.0.1/' });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
globalThis.localStorage = dom.window.localStorage;
globalThis.sessionStorage = dom.window.sessionStorage;
globalThis.location = dom.window.location;
const { renderK8sRuns, renderK8sAnalysisReport } = await import('../../src/features/k8s-scenarios.js');

// Sets the signed-in user the panel reads from local storage.
function asUser(role, userId) {
  localStorage.setItem('bas_role', role);
  localStorage.setItem('bas_user_id', userId);
}

function run(over) {
  return Object.assign({
    id: 'k8sr-1', requester: 'alice', cluster: 'kind-bas-lab', namespace: 'bas-sandbox',
    action: 'pod-create-unprivileged', params: { name: 'bas-sbx-1' }, state: 'PLANNED', detail: '', approvalId: ''
  }, over);
}

test('a planned run offers Approve to an admin who did not plan it, and never Execute', () => {
  asUser('admin', 'admin-1');
  renderK8sRuns([run({ state: 'PLANNED' })]);
  const html = document.getElementById('k8s-runs').innerHTML;
  assert.match(html, /data-k8s-approve="k8sr-1"/);
  assert.doesNotMatch(html, /data-k8s-execute/);
});

test('an approved run offers Execute only to its requester, and never Approve', () => {
  asUser('analyst', 'alice');
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
  assert.match(html, /Cleanup failed/);
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
  assert.match(html, /not revoked/);
  assert.doesNotMatch(html, /cleaned up/);
  assert.doesNotMatch(html, /data-k8s-(approve|execute)/);
});

test('the planner cannot approve their own run', () => {
  asUser('admin', 'alice');
  renderK8sRuns([run({ state: 'PLANNED' })]);
  assert.doesNotMatch(document.getElementById('k8s-runs').innerHTML, /data-k8s-approve/);
  assert.match(document.getElementById('k8s-runs').innerHTML, /Waiting for a different admin/);
});

test("an analyst never sees Approve, even on another user's run", () => {
  asUser('analyst', 'analyst-1');
  renderK8sRuns([run({ state: 'PLANNED' })]);
  assert.doesNotMatch(document.getElementById('k8s-runs').innerHTML, /data-k8s-approve/);
});

test('someone other than the requester sees no Execute', () => {
  asUser('admin', 'admin-1');
  renderK8sRuns([run({ state: 'APPROVED' })]);
  const html = document.getElementById('k8s-runs').innerHTML;
  assert.doesNotMatch(html, /data-k8s-execute/);
  assert.match(html, /Only the requester can execute/);
});

// ── Read-only analysis ────────────────────────────────────────────────────────

function analysisReport(over) {
  return Object.assign({
    cluster: 'kind-bas-lab', observedAt: '2026-10-23T08:00:00Z', complete: true, gaps: [],
    wildcards: [
      { Role: 'k8s://kind-bas-lab/_cluster/clusterrole/system:controller:gc', RoleKind: 'ClusterRole', Rule: 0,
        Verbs: ['*'], Resources: ['*'], Subjects: [] },
      { Role: 'k8s://kind-bas-lab/default/role/wild', RoleKind: 'Role', Rule: 0,
        Verbs: ['*'], Resources: ['pods'], Subjects: ['k8s://kind-bas-lab/default/serviceaccount/app'] },
    ],
    breadth: [], crossNamespace: [], workloadCreation: [], escalation: [], attackPaths: [], podConfig: [], tokenExposure: [],
  }, over || {});
}

test('built-in system roles are hidden by default, with a count of what is hidden', () => {
  renderK8sAnalysisReport(analysisReport());
  const body = document.getElementById('k8s-an-body').innerHTML;
  assert.doesNotMatch(body, /system:controller/);
  assert.match(body, /default\/wild/);
  assert.match(document.getElementById('k8s-an-meta').textContent, /1 built-in hidden/);
});

test('ticking the toggle shows the built-in roles', () => {
  document.getElementById('k8s-an-system').checked = true;
  renderK8sAnalysisReport(analysisReport());
  assert.match(document.getElementById('k8s-an-body').innerHTML, /system:controller/);
  document.getElementById('k8s-an-system').checked = false;
});

test('an incomplete discovery is labelled as incomplete, with its gap count', () => {
  renderK8sAnalysisReport(analysisReport({ complete: false, gaps: ['pods: forbidden'] }));
  assert.match(document.getElementById('k8s-an-meta').textContent, /INCOMPLETE: 1 gap/);
});

test('server text in the analysis is escaped, not rendered as markup', () => {
  renderK8sAnalysisReport(analysisReport({ wildcards: [
    { Role: 'k8s://kind-bas-lab/default/role/<img src=x onerror=bad()>', RoleKind: 'Role', Rule: 0,
      Verbs: ['*'], Resources: ['pods'], Subjects: [] }] }));
  const body = document.getElementById('k8s-an-body');
  assert.equal(body.querySelector('img'), null);
});
