import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  classLabel, authTone, authLabel, envTone, classOptions, filterOps, parseObserved, parseBindingSpec,
  exampleBindingSpec, changeLines, errorText, MAX_OBSERVED,
  jobTone, resultTone, isFinalStatus, resultText, newJobKey, storedNote, exampleWriteBindingSpec, countsText, worstTone,
} from '../../src/features/api-inventory-model.js';

const OPS = [
  { method: 'GET', path: '/v2/orders/{orderId}', auth: 'required', path_params: ['orderId'], classes: ['object_level_authorization', 'sensitive_data_exposure'] },
  { method: 'GET', path: '/v2/catalog', auth: 'none', classes: ['unauthenticated_access'] },
  { method: 'PATCH', path: '/v2/orders/{orderId}', auth: 'required', path_params: ['orderId'], classes: ['object_level_authorization'] },
];

test('labels and tones: a public operation is flagged, an unknown value falls back', () => {
  assert.equal(authTone('none'), 'bad');
  assert.equal(authTone('required'), 'ok');
  assert.equal(authTone('whatever'), 'muted');
  assert.equal(authLabel('none'), 'Public');
  assert.equal(envTone('production'), 'bad');
  assert.equal(envTone('lab'), 'info');
  assert.equal(classLabel('lifecycle'), 'Deprecated or older version');
  assert.equal(classLabel('not_a_class'), 'not_a_class');
});

test('classOptions lists All plus only the classes present, with counts', () => {
  const o = classOptions(OPS, { object_level_authorization: 2, unauthenticated_access: 1, file_upload: 0 });
  assert.deepEqual(o.map((x) => x.id), ['all', 'object_level_authorization', 'unauthenticated_access']);
  assert.equal(o[0].count, 3);
});

test('filterOps keeps operations carrying the class; all and empty keep everything', () => {
  assert.equal(filterOps(OPS, 'object_level_authorization').length, 2);
  assert.equal(filterOps(OPS, 'unauthenticated_access').length, 1);
  assert.equal(filterOps(OPS, 'all').length, 3);
  assert.equal(filterOps(OPS, '').length, 3);
  assert.equal(filterOps([{ method: 'GET', path: '/x' }], 'lifecycle').length, 0);
});

test('parseObserved accepts METHOD /path lines and skips blanks and comments', () => {
  const r = parseObserved('# sample\nGET /v2/orders\n\nPOST   /v2/files\r\n');
  assert.equal(r.error, '');
  assert.deepEqual(r.routes, [{ method: 'GET', path: '/v2/orders' }, { method: 'POST', path: '/v2/files' }]);
});

test('parseObserved names the bad line the way the server would reject it', () => {
  for (const bad of ['get /a', 'GET a', 'GET', 'GET /a extra', 'G /a', 'TOOLONGMETHOD /a']) {
    const r = parseObserved('GET /ok\n' + bad);
    assert.match(r.error, /^Line 2:/, bad);
    assert.deepEqual(r.routes, []);
  }
  assert.match(parseObserved('').error, /at least one/i);
  assert.match(parseObserved('# only a comment').error, /at least one/i);
});

test('parseObserved enforces the route limit and the path length', () => {
  assert.match(parseObserved('GET /' + 'a'.repeat(2049)).error, /^Line 1:/);
  const many = Array.from({ length: MAX_OBSERVED + 1 }, (_, i) => 'GET /r' + i).join('\n');
  assert.match(parseObserved(many).error, /At most/);
});

test('parseBindingSpec checks the outline and reports JSON errors without throwing', () => {
  assert.match(parseBindingSpec('').error, /Enter the test data/);
  assert.match(parseBindingSpec('{not json').error, /not valid JSON/);
  assert.match(parseBindingSpec('[]').error, /identities/);
  assert.match(parseBindingSpec('{"identities":[]}').error, /objects/);
  const ok = parseBindingSpec('{"identities":[],"objects":[]}');
  assert.equal(ok.error, '');
  assert.deepEqual(ok.spec, { identities: [], objects: [] });
  assert.match(parseBindingSpec('x'.repeat((1 << 20) + 1)).error, /too large/);
});

test('exampleBindingSpec starts from the first authenticated GET with a path parameter and holds only placeholders', () => {
  const s = exampleBindingSpec(OPS);
  assert.equal(s.objects[0].operation, 'GET /v2/orders/{orderId}');
  assert.deepEqual(Object.keys(s.objects[0].params), ['orderId']);
  assert.notEqual(s.objects[0].params.orderId, s.objects[1].params.orderId);
  assert.ok(s.identities.every((i) => i.credential_ref.startsWith('REPLACE/')), 'a credential reference must be a placeholder');
  // With nothing suitable it still returns a usable outline.
  assert.equal(exampleBindingSpec([{ method: 'GET', path: '/x', auth: 'none', path_params: ['id'] }]).objects.length, 2);
  assert.equal(exampleBindingSpec(null).identities.length, 2);
});

test('changeLines summarises the import changes and shortens long lists', () => {
  assert.deepEqual(changeLines(null), []);
  assert.deepEqual(changeLines({ added_total: 0, removed_total: 0, auth_changed_total: 0 }), []);
  const lines = changeLines({
    added_total: 7, added: ['GET /a', 'GET /b', 'GET /c', 'GET /d', 'GET /e', 'GET /f'],
    removed_total: 1, removed: ['GET /z'],
    auth_changed_total: 1, auth_changed: [{ key: 'GET /b', from: 'required', to: 'none' }],
  });
  assert.equal(lines.length, 3);
  assert.match(lines[0], /^7 added: GET \/a, GET \/b, GET \/c, GET \/d, GET \/e, …$/);
  assert.match(lines[2], /GET \/b \(required → none\)/);
});

test('errorText reads an API error body and says nothing for a normal one', () => {
  assert.equal(errorText({ error: 'target not found' }), 'target not found');
  assert.equal(errorText({ version: 1 }), '');
  assert.equal(errorText(null), 'No response from the server');
});

test('job and result tones, and which statuses are final', () => {
  assert.equal(jobTone('completed'), 'ok');
  assert.equal(jobTone('failed'), 'bad');
  assert.equal(jobTone('running'), 'info');
  assert.equal(jobTone('?'), 'muted');
  assert.equal(resultTone('FAIL'), 'bad');
  assert.equal(resultTone('PASS'), 'ok');
  assert.equal(resultTone('ERROR'), 'warn');
  assert.equal(resultTone('SKIPPED'), 'muted');
  for (const s of ['completed', 'failed', 'cancelled']) assert.equal(isFinalStatus(s), true, s);
  for (const s of ['queued', 'running', '', undefined]) assert.equal(isFinalStatus(s), false, String(s));
});

test('resultText never reads an error or a skip as a pass', () => {
  assert.match(resultText({ result: 'FAIL' }), /control failed/);
  assert.match(resultText({ result: 'PASS' }), /refused/);
  for (const r of ['ERROR', 'SKIPPED']) {
    const t = resultText({ result: r, reason: 'EVIDENCE_INCONCLUSIVE' });
    assert.match(t, /not a pass/i, r);
    assert.match(t, /EVIDENCE_INCONCLUSIVE/, r);
  }
  assert.equal(resultText(null), '');
  assert.equal(resultText({ result: 'weird' }), '');
});

test('newJobKey is prefixed, hex, 20 characters of entropy and differs between calls', () => {
  const a = newJobKey();
  const b = newJobKey();
  assert.match(a, /^ui-[0-9a-f]{20}$/);
  assert.notEqual(a, b);
  let n = 0;
  assert.equal(newJobKey(() => (n++ % 16) / 16), 'ui-0123456789abcdef0123');
});

test('storedNote says when the stored data is stale and what to do', () => {
  assert.equal(storedNote(null), '');
  const fresh = storedNote({ updated_by: 'admin1', updated_at: '2026-11-10', validated_inventory: 2, newest_inventory: 2, stale: false });
  assert.match(fresh, /checked against the newest inventory \(v2\)/);
  const stale = storedNote({ updated_by: 'admin1', validated_inventory: 1, newest_inventory: 3, stale: true });
  assert.match(stale, /v1/);
  assert.match(stale, /v3/);
  assert.match(stale, /Save it again before running/);
});

test('exampleWriteBindingSpec allows writes, uses a PUT or PATCH and holds only placeholders', () => {
  const ops = [
    { method: 'GET', path: '/v2/orders/{orderId}', auth: 'required', path_params: ['orderId'] },
    { method: 'PATCH', path: '/v2/orders/{orderId}', auth: 'required', path_params: ['orderId'] },
  ];
  const s = exampleWriteBindingSpec(ops);
  assert.equal(s.allow_writes, true);
  assert.equal(s.objects[0].operation, 'PATCH /v2/orders/{orderId}');
  assert.deepEqual(Object.keys(s.objects[0].params), ['orderId']);
  assert.equal(s.objects[0].write.read_operation, undefined, 'a GET on the same path is the default read-back');
  assert.ok(s.identities.every((i) => i.credential_ref.startsWith('REPLACE/')));
  assert.notEqual(s.objects[0].write.attack_body, s.objects[0].write.restore_body);
  // With no GET on the same path the example asks for a read operation.
  const noGet = exampleWriteBindingSpec([ops[1]]);
  assert.match(noGet.objects[0].write.read_operation, /^GET /);
  assert.equal(exampleWriteBindingSpec(null).objects.length, 2);
});

test('countsText lists only the non-zero grades, worst first', () => {
  assert.equal(countsText({ pass: 2, fail: 1, error: 0, skipped: 3 }), '1 fail · 2 pass · 3 skipped');
  assert.equal(countsText({ pass: 0, fail: 0, error: 1, skipped: 0 }), '1 error');
  assert.equal(countsText({ pass: 0, fail: 0, error: 0, skipped: 0 }), 'no results');
  assert.equal(countsText(null), 'no results');
  assert.equal(countsText({ pass: 'x' }), 'no results');
});

test('worstTone: a failure outranks an error, which outranks a skip, which outranks a pass', () => {
  assert.equal(worstTone({ pass: 5, fail: 1, error: 1, skipped: 1 }), 'bad');
  assert.equal(worstTone({ pass: 5, fail: 0, error: 1, skipped: 1 }), 'warn');
  assert.equal(worstTone({ pass: 5, fail: 0, error: 0, skipped: 1 }), 'muted', 'a skip must not read as green');
  assert.equal(worstTone({ pass: 5, fail: 0, error: 0, skipped: 0 }), 'ok');
  assert.equal(worstTone({ pass: 0, fail: 0, error: 0, skipped: 0 }), 'muted');
  assert.equal(worstTone(null), 'muted');
});
