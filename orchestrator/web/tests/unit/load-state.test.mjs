import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { failureOf, listOf, failureHtml } from '../../src/core/load-state.js';

// api.js imports the shell for doLogout; stub the browser pieces it needs instead of loading the app.
async function apiWith(status, body) {
  const dom = new JSDOM('<!DOCTYPE html><body></body>', { url: 'http://127.0.0.1/' });
  globalThis.window = dom.window; globalThis.document = dom.window.document; globalThis.localStorage = dom.window.localStorage;
  globalThis.fetch = async () => ({ status, json: async () => body });
  const { apicall } = await import('../../src/core/api.js');
  return apicall('/api/x');
}

test('apicall tags 4xx/5xx object bodies with a non-enumerable httpStatus', async () => {
  const r = await apiWith(500, { error: 'internal error' });
  assert.equal(r.httpStatus, 500);
  assert.deepEqual(Object.keys(r), ['error']);
  assert.equal(JSON.stringify(r), '{"error":"internal error"}');
});

test('apicall leaves successful bodies and arrays untouched', async () => {
  assert.equal((await apiWith(200, { a: 1 })).httpStatus, undefined);
  const arr = await apiWith(200, [1, 2]);
  assert.equal(arr.httpStatus, undefined);
  assert.deepEqual(arr, [1, 2]);
  assert.equal(await apiWith(200, null), null);
});

test('failureOf separates forbidden from error and ignores good responses', () => {
  const mk = (s) => Object.defineProperty({ error: 'x' }, 'httpStatus', { value: s });
  assert.deepEqual(failureOf(mk(403)), { kind: 'forbidden', status: 403 });
  assert.deepEqual(failureOf(mk(500)), { kind: 'error', status: 500 });
  assert.equal(failureOf(mk(200)), null);
  assert.equal(failureOf({ error: 'no tag' }), null);
  assert.equal(failureOf([]), null);
  assert.equal(failureOf(null), null);
});

test('listOf accepts arrays and {items} only', () => {
  assert.deepEqual(listOf([1]), [1]);
  assert.deepEqual(listOf({ items: [2] }), [2]);
  assert.equal(listOf({ error: 'x' }), null);
  assert.equal(listOf(null), null);
});

test('failureHtml says failed vs forbidden, escapes input and offers Retry only when given an action', () => {
  const err = failureHtml('findings', { kind: 'error', status: 500 }, 'loadFindings');
  assert.match(err, /Could not load findings/);
  assert.match(err, /HTTP 500/);
  assert.match(err, /data-on-click="loadFindings"/);
  assert.match(err, /role="alert"/);
  const forb = failureHtml('findings', { kind: 'forbidden', status: 403 });
  assert.match(forb, /do not have permission to view findings/);
  assert.doesNotMatch(forb, /Retry/);
  assert.doesNotMatch(failureHtml('<img src=x onerror=1>', { kind: 'error' }), /<img/);
});
