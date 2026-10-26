import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { setupDom, load } from './dom.mjs';

setupDom();
const fns = await load([
  'parseEnrollHostnames', 'enrollTokensToCsv', 'generateEnrollmentTokens', 'clearEnrollmentTokens', 'downloadEnrollmentTokensCsv', 'copyEnrollmentToken',
]);

const flush = () => new Promise((r) => setTimeout(r, 0));
function stubNetwork(response) {
  const calls = [];
  globalThis.fetch = (path, init) => { calls.push({ path, init }); return Promise.resolve({ status: 200, json: () => Promise.resolve(response) }); };
  return calls;
}

test('the Deploy Agent page has the token generator controls', () => {
  for (const id of ['enroll-tok-hosts', 'enroll-tok-ttl', 'enroll-tok-note', 'enroll-tok-generate', 'enroll-tok-results', 'enroll-tok-warning']) {
    assert.ok(document.getElementById(id), `missing #${id}`);
  }
});

test('every action the token generator names is registered in globals.js', () => {
  const globals = readFileSync(new URL('../../src/globals.js', import.meta.url), 'utf8');
  for (const name of ['generateEnrollmentTokens', 'clearEnrollmentTokens', 'downloadEnrollmentTokensCsv', 'copyEnrollmentToken']) {
    assert.ok(globals.includes(name), `${name} is not registered`);
  }
});

test('hostnames are split on lines and commas, trimmed, and blanks dropped', () => {
  assert.deepEqual(fns.parseEnrollHostnames(' FIN-01 \n\nFIN-02, HR-9\r\n  '), ['FIN-01', 'FIN-02', 'HR-9']);
  assert.deepEqual(fns.parseEnrollHostnames('   \n '), []);
});

test('nothing is sent without a hostname', async () => {
  const calls = stubNetwork({});
  document.getElementById('enroll-tok-hosts').value = '  \n ';
  fns.generateEnrollmentTokens();
  await flush();
  assert.equal(calls.length, 0);
});

test('generating posts the hostnames, lifetime and note to the bulk endpoint', async () => {
  const calls = stubNetwork({ tokens: [], duplicates: [] });
  document.getElementById('enroll-tok-hosts').value = 'FIN-01\nFIN-02';
  document.getElementById('enroll-tok-ttl').value = '24';
  document.getElementById('enroll-tok-note').value = 'Q4 rollout';
  fns.generateEnrollmentTokens();
  await flush();
  const c = calls.find((x) => x.path === '/api/enrollment-tokens/bulk');
  assert.ok(c, 'no call to the bulk endpoint');
  assert.equal(c.init.method, 'POST');
  assert.deepEqual(JSON.parse(c.init.body), { hostnames: ['FIN-01', 'FIN-02'], ttlHours: 24, note: 'Q4 rollout' });
});

const RESPONSE = {
  tokens: [
    { hostname: 'FIN-01', agentId: 'aaaaaaaaaaaaaaaa', token: 'bas_enr_one', expiresAt: '2030-01-01T00:00:00Z' },
    { hostname: '<img src=x onerror="globalThis.__xss=1">', agentId: 'bbbbbbbbbbbbbbbb', token: 'bas_enr_two', expiresAt: '2030-01-01T00:00:00Z' },
  ],
  duplicates: ['FIN-01'],
};

test('results are shown as text, never interpreted as markup', async () => {
  stubNetwork(RESPONSE);
  document.getElementById('enroll-tok-hosts').value = 'FIN-01';
  fns.generateEnrollmentTokens();
  await flush();
  const box = document.getElementById('enroll-tok-results');
  assert.ok(box.textContent.includes('bas_enr_one'));
  assert.equal(box.querySelector('img'), null, 'a hostname must not become an element');
  assert.equal(globalThis.__xss, undefined);
});

test('the warning says tokens are shown once and are per host and single use', async () => {
  stubNetwork(RESPONSE);
  document.getElementById('enroll-tok-hosts').value = 'FIN-01';
  fns.generateEnrollmentTokens();
  await flush();
  const w = document.getElementById('enroll-tok-warning').textContent.toLowerCase();
  assert.ok(w.includes('once') && w.includes('single') && w.includes('script'), w);
});

test('clearing removes every token from the page', async () => {
  stubNetwork(RESPONSE);
  document.getElementById('enroll-tok-hosts').value = 'FIN-01';
  fns.generateEnrollmentTokens();
  await flush();
  fns.clearEnrollmentTokens();
  assert.ok(!document.getElementById('enroll-tok-results').textContent.includes('bas_enr_'));
  assert.equal(document.getElementById('enroll-tok-hosts').value, '');
});

test('the CSV has a header, one line per token, and neutralises spreadsheet formulas', () => {
  const csv = fns.enrollTokensToCsv([
    { hostname: 'FIN-01', agentId: 'a', token: 'bas_enr_x', expiresAt: 'e' },
    { hostname: '=HYPERLINK("http://evil")', agentId: 'b', token: 'bas_enr_y', expiresAt: 'e' },
    { hostname: 'has,comma', agentId: 'c', token: 'bas_enr_z', expiresAt: 'e' },
  ]);
  const lines = csv.trim().split('\n');
  assert.equal(lines[0], 'hostname,agentId,token,expiresAt');
  assert.equal(lines.length, 4);
  assert.ok(lines[2].startsWith("\"'=HYPERLINK") || lines[2].startsWith("'=HYPERLINK"), lines[2]);
  assert.ok(lines[3].startsWith('"has,comma"'), lines[3]);
});
