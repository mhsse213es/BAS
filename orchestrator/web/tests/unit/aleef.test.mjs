import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load, PAYLOADS } from './dom.mjs';

setupDom();
const { renderFindings, renderRunCard, renderClassTable } = await load(['renderFindings', 'renderRunCard', 'renderClassTable']);
const model = await import('../../src/features/aleef-model.js');

const RUN = { view: true, run: true, authorize: false };
const VIEWER = { view: true, run: false, authorize: false };

function f(id, over) {
  return Object.assign({ id, run_id: 'r1', test_id: 't-' + id, property_id: 'OWN-1', title: 'Title ' + id, state: 'candidate',
    prior_knowledge: 'not_checked', novelty_label: 'prior reports not checked', evidence_hash: 'h' + id, created_at: '2026-10-23T00:00:00Z' }, over || {});
}
function render(body, perms) {
  const host = document.createElement('div');
  renderFindings(host, body, perms || RUN);
  return host;
}
const titles = (n) => [...n.querySelectorAll('tbody tr td:first-child')].map((c) => c.textContent);

test('candidates and verified render in separate tables and never merge', () => {
  const host = render({ candidates: [f('c1')], verified: [f('v1', { state: 'verified', regression_id: 'reg1' })], pending_regression: [], unconfirmed: [], rejected: [] });
  assert.deepEqual(titles(host.querySelector('#aleef-candidates')), ['Title c1']);
  assert.deepEqual(titles(host.querySelector('#aleef-verified')), ['Title v1']);
  assert.match(host.querySelector('#aleef-candidates h3').textContent, /Candidates \(unverified\)/);
  assert.match(host.querySelector('#aleef-verified h3').textContent, /Verified \(reproduced 3×, owner \+ negative control, regression saved\)/);
});

test('verified table is fed only from verified, pending_regression never appears in it', () => {
  const host = render({ candidates: [], verified: [f('v1')], pending_regression: [f('p1', { state: 'verified_without_regression' })], unconfirmed: [f('u1')], rejected: [f('x1')] });
  assert.deepEqual(titles(host.querySelector('#aleef-verified')), ['Title v1']);
  assert.deepEqual(titles(host.querySelector('#aleef-pending')), ['Title p1']);
  assert.equal(host.querySelector('#aleef-verified').textContent.includes('Title p1'), false);
  assert.equal(host.querySelector('#aleef-verified').textContent.includes('Title u1'), false);
  assert.equal(host.querySelector('#aleef-pending [data-aleef-action="download-regression"]'), null, 'pending rows have no download');
});

test('a verified-looking state in candidates stays in candidates', () => {
  const host = render({ candidates: [f('c1', { state: 'verified' })], verified: [] });
  assert.equal(host.querySelectorAll('#aleef-verified tbody tr').length, 0);
  assert.equal(host.querySelectorAll('#aleef-candidates tbody tr').length, 1);
});

test('unconfirmed and rejected are collapsed details, pending is hidden when empty', () => {
  const host = render({ candidates: [], verified: [], pending_regression: [], unconfirmed: [f('u1')], rejected: [f('x1')] });
  assert.equal(host.querySelector('#aleef-unconfirmed').tagName, 'DETAILS');
  assert.equal(host.querySelector('#aleef-unconfirmed').open, false);
  assert.equal(host.querySelector('#aleef-rejected').tagName, 'DETAILS');
  assert.equal(host.querySelector('#aleef-pending'), null);
});

test('each verified row has Download regression and a prior-knowledge select with the API values', () => {
  const host = render({ verified: [f('v1', { prior_knowledge: 'known_public' })] });
  assert.ok(host.querySelector('[data-aleef-action="download-regression"][data-finding="v1"]'));
  const sel = host.querySelector('select[data-aleef-pk="v1"]');
  assert.deepEqual([...sel.options].map((o) => o.value), ['not_checked', 'checked_none_found', 'known_public', 'known_vendor']);
  assert.equal(sel.value, 'known_public');
  assert.equal(sel.disabled, false);
});

test('a user without aleef:run cannot change prior knowledge', () => {
  const host = render({ verified: [f('v1')] }, VIEWER);
  assert.equal(host.querySelector('select[data-aleef-pk]').disabled, true);
});

test('XSS payloads in a finding title and hash render as text', () => {
  for (const p of PAYLOADS) {
    const host = render({ candidates: [f('c1', { title: p, evidence_hash: p })], verified: [f('v1', { title: p, regression_id: p })] });
    assert.equal(host.querySelector('img,svg,script,iframe'), null);
    assert.equal(titles(host.querySelector('#aleef-candidates'))[0], p);
    assert.equal(titles(host.querySelector('#aleef-verified'))[0], p);
    assert.equal(globalThis.__xss, undefined);
  }
});

test('run card: STOP for run users, confirmation is in-page, none for viewers or finished runs', () => {
  const host = document.createElement('div');
  const run = { run_id: 'r1', status: 'running' };
  renderRunCard(host, run, RUN, false);
  assert.ok(host.querySelector('[data-aleef-action="stop"]'));
  renderRunCard(host, run, RUN, true);
  assert.ok(host.querySelector('[data-aleef-action="stop-confirm"]'));
  assert.equal(host.querySelector('[data-aleef-action="stop"]'), null);
  renderRunCard(host, run, VIEWER, false);
  assert.equal(host.querySelector('[data-aleef-action]'), null);
  renderRunCard(host, { run_id: 'r1', status: 'completed' }, RUN, false);
  assert.equal(host.querySelector('[data-aleef-action]'), null);
});

test('run card shows coverage, halted reason and an orphans warning, as text', () => {
  const host = document.createElement('div');
  renderRunCard(host, {
    run_id: 'r1', status: 'halted', halted_reason: PAYLOADS[0],
    orphans: [{ Operation: 'post_items', ID: PAYLOADS[1], Owner: 'alice' }],
    report: { Total: 4, Executed: 3, NotExecuted: 1, PerOperation: { get_items: { Class: 'read', Generated: 4, Executed: 3, NotExecuted: 1, Findings: 1, Verified: 0, Skipped: '' } } }
  }, RUN, false);
  assert.equal(host.querySelector('img,svg,script'), null);
  assert.match(host.textContent, /Halted: <img/);
  assert.match(host.textContent, /Orphaned objects: 1/);
  assert.match(host.textContent, /get_items/);
  assert.match(host.textContent, /4 generated, 3 executed, 1 not executed/);
});

test('class table defaults every operation to unknown and offers the five classes', () => {
  const host = document.createElement('div');
  renderClassTable(host, ['a', 'b'], null);
  const sels = host.querySelectorAll('select');
  assert.equal(sels.length, 2);
  assert.equal(sels[0].value, 'unknown');
  assert.deepEqual([...sels[0].options].map((o) => o.value), ['unknown', 'read', 'setup_safe', 'reversible', 'money', 'notifying']);
});

// ── pure model ───────────────────────────────────────────────────────────────
test('permissions: viewer none, analyst view+run, admin all', () => {
  assert.deepEqual(model.aleefPerms('viewer'), { view: false, run: false, authorize: false });
  assert.deepEqual(model.aleefPerms('analyst'), { view: true, run: true, authorize: false });
  assert.deepEqual(model.aleefPerms('admin'), { view: true, run: true, authorize: true });
});

test('add-on detection reads specialAddons only', () => {
  assert.equal(model.hasAleefAddon({ specialAddons: [{ name: 'aleef', category: 'special' }] }), true);
  assert.equal(model.hasAleefAddon({ specialAddons: [] }), false);
  assert.equal(model.hasAleefAddon({ features: ['addon:aleef'] }), false);
  assert.equal(model.hasAleefAddon(null), false);
});

test('run request carries secret references only and rejects a token-looking value', () => {
  const base = { engagementId: 'e1', baseUrl: 'https://uat.example', openapi: '{"paths":{}}', accounts: [{ name: 'a', customerId: 'c', role: 'user', tokenRef: 'bank/alice' }], classes: { a: 'read', b: 'unknown' } };
  const ok = model.buildRunRequest(base);
  assert.deepEqual(ok.body.accounts, [{ name: 'a', customer_id: 'c', token_ref: 'bank/alice', role: 'user' }]);
  assert.deepEqual(ok.body.classes, { a: 'read' });
  const bad = model.buildRunRequest(Object.assign({}, base, { accounts: [{ name: 'a', customerId: 'c', role: 'user', tokenRef: 'Bearer eyJhbGciOi.abc def' }] }));
  assert.match(bad.error, /secret reference/);
  assert.equal(JSON.stringify(bad).includes('eyJ'), false);
});

test('engagement request refuses production and builds the API field names', () => {
  const form = { customer: 'Bank', environment: 'lab', notBefore: '2026-10-23T10:00', notAfter: '2026-10-24T10:00', hosts: 'https://uat.example:8443\nhttps://b.example', maxRequests: '100', maxConcurrent: '2', rps: '5' };
  const ok = model.buildEngagementRequest(form);
  assert.deepEqual(Object.keys(ok.body).sort(), ['customer', 'environment', 'hosts', 'maxConcurrent', 'maxRequests', 'notAfter', 'notBefore', 'rps']);
  assert.equal(ok.body.hosts.length, 2);
  assert.equal('approver' in ok.body, false);
  assert.match(model.buildEngagementRequest(Object.assign({}, form, { environment: 'production' })).error, /lab or uat/);
});

test('derived operation ids mirror the server', () => {
  assert.equal(model.derivedOpId('get', '/items/{id}'), 'get_items_by_id');
  assert.equal(model.derivedOpId('get', '/'), 'get_root');
  assert.deepEqual(model.operationIdsFromOpenAPI(JSON.stringify({ paths: { '/a': { get: { operationId: 'listA' }, post: {} } } })).ops, ['listA', 'post_a']);
});

test('error messages: 403 not licensed, 401 session, server text otherwise', () => {
  assert.match(model.apiErrorMessage(403, { error: 'product_not_licensed' }), /not licensed/);
  assert.match(model.apiErrorMessage(401, {}), /session/);
  assert.equal(model.apiErrorMessage(400, { error: 'bad window' }), 'bad window');
});

// ── polling ──────────────────────────────────────────────────────────────────
function fakeTimers() {
  const t = { pending: null, cleared: 0 };
  t.setTimer = (fn) => { t.pending = () => { t.pending = null; fn(); }; return 1; };
  t.clearTimer = () => { t.pending = null; t.cleared++; };
  return t;
}
const flush = () => new Promise((r) => setTimeout(r, 0));

test('polling continues while running and stops itself when the run finishes', async () => {
  const t = fakeTimers();
  const seq = ['running', 'running', 'completed'];
  let calls = 0; const seen = []; let finished = 0;
  const p = model.createPoller({ setTimer: t.setTimer, clearTimer: t.clearTimer, fetchFn: async () => ({ status: seq[calls++] }), onUpdate: (r) => seen.push(r.status), onFinished: () => finished++ });
  p.start(); await flush();
  assert.ok(t.pending, 'next poll scheduled while running');
  t.pending(); await flush();
  assert.ok(t.pending);
  t.pending(); await flush();
  assert.equal(t.pending, null, 'no timer after the run finished');
  assert.equal(p.isActive(), false);
  assert.equal(finished, 1);
  assert.deepEqual(seen, ['running', 'running', 'completed']);
  assert.equal(calls, 3);
});

test('stop() clears the timer and ignores an in-flight response', async () => {
  const t = fakeTimers();
  let resolve; let updates = 0;
  const p = model.createPoller({ setTimer: t.setTimer, clearTimer: t.clearTimer, fetchFn: () => new Promise((r) => { resolve = r; }), onUpdate: () => updates++ });
  p.start(); await flush();
  p.stop();
  resolve({ status: 'running' }); await flush();
  assert.equal(updates, 0);
  assert.equal(t.pending, null);
  assert.equal(p.isActive(), false);
  p.stop(); // idempotent
});

test('a transient error keeps polling and reports the error', async () => {
  const t = fakeTimers(); const errs = [];
  const p = model.createPoller({ setTimer: t.setTimer, clearTimer: t.clearTimer, fetchFn: async () => { throw new Error('net'); }, onUpdate: () => {}, onError: (e) => errs.push(e.message) });
  p.start(); await flush();
  assert.deepEqual(errs, ['net']);
  assert.ok(t.pending);
  p.stop();
});

test('finished statuses', () => {
  for (const s of ['completed', 'halted', 'failed', 'interrupted']) assert.equal(model.isRunFinished(s), true, s);
  for (const s of ['running', 'stopping', '']) assert.equal(model.isRunFinished(s), false, s);
});
