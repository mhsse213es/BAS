import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  classLabel, authTone, authLabel, envTone, classOptions, filterOps, parseObserved, parseBindingSpec,
  exampleBindingSpec, changeLines, errorText, MAX_OBSERVED,
  jobTone, resultTone, isFinalStatus, resultText, newJobKey, storedNote, exampleWriteBindingSpec, countsText, worstTone,
  opKey, writeOperations, readChoices, defaultReadOperation, buildWriteObject, mergeWriteObject, writeObjectsOf, removeObjectAt, identityNames, MAX_WRITE_BODY,
  parseEveryHours, everyLabel, scheduleState, scheduleTone, scheduleNote,
  boundKindLabel, boundWho, exampleChecksSpec, validJobStatus, JOB_STATUSES, graphQLExampleOp, opFullKey, exampleGraphQLSpec,
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

const WOPS = [
  { method: 'GET', path: '/v2/orders/{orderId}', auth: 'required', path_params: ['orderId'] },
  { method: 'PATCH', path: '/v2/orders/{orderId}', auth: 'required', path_params: ['orderId'] },
  { method: 'PUT', path: '/v2/profiles/{pid}', auth: 'required', path_params: ['pid'] },
  { method: 'GET', path: '/v2/profile-view/{pid}', auth: 'required', path_params: ['pid'] },
  { method: 'GET', path: '/v2/public/{pid}', auth: 'none', path_params: ['pid'] },
  { method: 'DELETE', path: '/v2/orders/{orderId}', auth: 'required', path_params: ['orderId'] },
  { method: 'PATCH', path: '/v2/open/{id}', auth: 'none', path_params: ['id'] },
  { method: 'PATCH', path: '/v2/noparam', auth: 'required', path_params: [] },
];

const FORM = () => ({ operation: 'PATCH /v2/orders/{orderId}', params: { orderId: 'ORD-A1' }, owner: 'alice', attack_body: '{"status":"hacked"}', restore_body: '{"status":"open"}', read_operation: '', ignore_fields: 'updated_at, etag' });

test('writeOperations keeps authenticated PUT or PATCH with a path parameter only', () => {
  assert.deepEqual(writeOperations(WOPS).map(opKey), ['PATCH /v2/orders/{orderId}', 'PUT /v2/profiles/{pid}']);
  assert.deepEqual(writeOperations(null), []);
});

test('readChoices lists authenticated GETs with the same path parameters; the default is the same path', () => {
  const patch = WOPS[1];
  assert.deepEqual(readChoices(WOPS, patch), ['GET /v2/orders/{orderId}']);
  assert.equal(defaultReadOperation(WOPS, patch), 'GET /v2/orders/{orderId}');
  const put = WOPS[2];
  assert.deepEqual(readChoices(WOPS, put), ['GET /v2/profile-view/{pid}'], 'a public GET is not an owner view');
  assert.equal(defaultReadOperation(WOPS, put), '', 'no GET on the same path');
  assert.deepEqual(readChoices(WOPS, null), []);
});

test('buildWriteObject builds the object the server expects, trimming and omitting defaults', () => {
  const r = buildWriteObject(FORM(), WOPS);
  assert.equal(r.error, '');
  assert.deepEqual(r.object, { operation: 'PATCH /v2/orders/{orderId}', params: { orderId: 'ORD-A1' }, owner: 'alice',
    write: { attack_body: '{"status":"hacked"}', restore_body: '{"status":"open"}', ignore_fields: ['updated_at', 'etag'] } });
  // Naming the default read-back explicitly changes nothing; a different one is kept.
  assert.equal(buildWriteObject({ ...FORM(), read_operation: 'GET /v2/orders/{orderId}' }, WOPS).object.write.read_operation, undefined);
  const put = buildWriteObject({ ...FORM(), operation: 'PUT /v2/profiles/{pid}', params: { pid: 'P1' }, read_operation: 'GET /v2/profile-view/{pid}' }, WOPS);
  assert.equal(put.error, '');
  assert.equal(put.object.write.read_operation, 'GET /v2/profile-view/{pid}');
});

test('buildWriteObject refuses what the server would, naming the problem', () => {
  const bad = {
    'no operation': { operation: '' },
    'a GET': { operation: 'GET /v2/orders/{orderId}' },
    'a DELETE': { operation: 'DELETE /v2/orders/{orderId}' },
    'public operation': { operation: 'PATCH /v2/open/{id}', params: { id: 'x1' } },
    'empty param': { params: { orderId: '  ' } },
    'traversal param': { params: { orderId: '../admin' } },
    'slash param': { params: { orderId: 'a/b' } },
    'no owner': { owner: ' ' },
    'attack not JSON': { attack_body: 'status=hacked' },
    'attack an array': { attack_body: '[1]' },
    'attack empty': { attack_body: '' },
    'restore missing': { restore_body: '' },
    'bodies identical': { restore_body: '{"status":"hacked"}' },
    'bodies equal as JSON': { restore_body: '{ "status" : "hacked" }' },
    'body too large': { attack_body: '{"a":"' + 'x'.repeat(MAX_WRITE_BODY) + '"}' },
    'read op not offered': { read_operation: 'GET /v2/profile-view/{pid}' },
    'bad ignore field': { ignore_fields: 'ok, a b' },
    'too many ignore fields': { ignore_fields: Array.from({ length: 21 }, (_, i) => 'f' + i).join(',') },
  };
  for (const [name, patch] of Object.entries(bad)) {
    const r = buildWriteObject({ ...FORM(), ...patch }, WOPS);
    assert.notEqual(r.error, '', name + ' was accepted');
    assert.equal(r.object, null, name);
  }
  // A PUT with no GET on its own path needs a read-back chosen.
  const noRead = buildWriteObject({ ...FORM(), operation: 'PUT /v2/profiles/{pid}', params: { pid: 'P1' } }, WOPS);
  assert.match(noRead.error, /choose how to read it back/);
});

test('mergeWriteObject adds, replaces by operation and values, sets allow_writes and never mutates its input', () => {
  const spec = { identities: [{ name: 'alice', credential_ref: 'a/x' }, { name: 'bob', credential_ref: 'b/x' }], objects: [{ operation: 'GET /v2/orders/{orderId}', params: { orderId: 'ORD-A1' }, owner: 'alice' }] };
  const frozen = JSON.stringify(spec);
  const obj = buildWriteObject(FORM(), WOPS).object;
  const m = mergeWriteObject(spec, obj);
  assert.equal(m.error, '');
  assert.equal(m.replaced, false);
  assert.equal(m.spec.allow_writes, true);
  assert.equal(m.spec.objects.length, 2);
  assert.equal(JSON.stringify(spec), frozen, 'the input spec must not change');
  const again = mergeWriteObject(m.spec, { ...obj, write: { ...obj.write, restore_body: '{"status":"new"}' } });
  assert.equal(again.replaced, true);
  assert.equal(again.spec.objects.length, 2, 'same operation and values replace');
  assert.equal(again.spec.objects[1].write.restore_body, '{"status":"new"}');
  const other = mergeWriteObject(m.spec, { ...obj, params: { orderId: 'ORD-B1' }, owner: 'bob' });
  assert.equal(other.spec.objects.length, 3, 'different values add');
});

test('mergeWriteObject refuses an owner who is not an identity, and a spec with no identities', () => {
  const obj = buildWriteObject(FORM(), WOPS).object;
  assert.match(mergeWriteObject({ identities: [{ name: 'bob' }], objects: [] }, obj).error, /not one of the identities/);
  assert.match(mergeWriteObject({}, obj).error, /Add the identities first/);
  assert.match(mergeWriteObject(null, obj).error, /Add the identities first/);
});

test('writeObjectsOf, removeObjectAt and identityNames read and edit a spec without mutating it', () => {
  const spec = { identities: [{ name: 'alice' }, { name: 'bob' }, null], objects: [
    { operation: 'GET /a/{id}', params: { id: '1' }, owner: 'alice' },
    { operation: 'PATCH /v2/orders/{orderId}', params: { orderId: 'O1' }, owner: 'alice', write: { attack_body: '{"a":1}', restore_body: '{"a":2}' } },
  ] };
  assert.deepEqual(identityNames(spec), ['alice', 'bob']);
  assert.deepEqual(identityNames(null), []);
  const w = writeObjectsOf(spec);
  assert.equal(w.length, 1);
  assert.equal(w[0].index, 1);
  assert.deepEqual(writeObjectsOf(null), []);
  const frozen = JSON.stringify(spec);
  const r = removeObjectAt(spec, 1);
  assert.equal(r.objects.length, 1);
  assert.equal(JSON.stringify(spec), frozen);
  assert.equal(removeObjectAt(spec, 9).objects.length, 2, 'an out-of-range index removes nothing');
});

test('parseEveryHours accepts whole hours from 1 to 720 only', () => {
  assert.deepEqual(parseEveryHours(' 24 '), { hours: 24, error: '' });
  assert.equal(parseEveryHours('1').hours, 1);
  assert.equal(parseEveryHours('720').hours, 720);
  for (const bad of ['', '0', '721', '9999', '1.5', '-1', 'abc', '1e2', '0x10', null, undefined, '12345']) {
    const r = parseEveryHours(bad);
    assert.equal(r.hours, 0, String(bad));
    assert.notEqual(r.error, '', String(bad));
  }
});

test('everyLabel reads the common intervals naturally', () => {
  assert.equal(everyLabel(1), 'every hour');
  assert.equal(everyLabel(6), 'every 6 hours');
  assert.equal(everyLabel(24), 'every day');
  assert.equal(everyLabel(48), 'every 2 days');
  assert.equal(everyLabel(168), 'every week');
  assert.equal(everyLabel(336), 'every 336 hours');
});

test('scheduleState and scheduleTone: a paused schedule is a problem, an off one is quiet', () => {
  assert.equal(scheduleState(null), 'none');
  assert.equal(scheduleState({ enabled: true }), 'on');
  assert.equal(scheduleState({ enabled: false }), 'off');
  assert.equal(scheduleState({ enabled: false, paused_for_failures: true }), 'paused');
  assert.equal(scheduleTone({ enabled: true }), 'ok');
  assert.equal(scheduleTone({ enabled: false }), 'muted');
  assert.equal(scheduleTone({ enabled: false, paused_for_failures: true }), 'bad');
});

test('scheduleNote says what runs, whether writes are included, and the last attempt', () => {
  assert.match(scheduleNote(null), /No schedule/);
  const on = scheduleNote({ enabled: true, every_hours: 6, include_writes: true, next_run_at: '2026-11-11T02:00:00Z', last_result: 'queued', last_run_at: '2026-11-10T20:00:00Z' });
  assert.match(on, /every 6 hours, including write scenarios/);
  assert.match(on, /Next run 2026-11-11 02:00 UTC/);
  assert.match(on, /Last attempt 2026-11-10 20:00 UTC: queued/);
  assert.match(scheduleNote({ enabled: false, every_hours: 6 }), /schedule is off/);
  assert.match(scheduleNote({ enabled: true, every_hours: 1, next_run_at: 'garbage' }), /unknown time/);
});

test('parseBindingSpec accepts function and property checks without an objects list', () => {
  assert.equal(parseBindingSpec('{"identities":[],"functions":[]}').error, '');
  assert.equal(parseBindingSpec('{"identities":[],"properties":[]}').error, '');
  assert.match(parseBindingSpec('{"identities":[]}').error, /objects/);
  assert.match(parseBindingSpec('{"identities":[],"functions":{}}').error, /objects/);
});

test('boundKindLabel and boundWho describe each kind of check in its own words', () => {
  assert.equal(boundKindLabel({}), 'read');
  assert.equal(boundKindLabel({ kind: 'function' }), 'function');
  assert.equal(boundKindLabel({ kind: 'property' }), 'property');
  assert.equal(boundKindLabel(null), 'read');
  assert.equal(boundWho({ attacker: 'alice', victim: 'bob' }), 'alice → bob');
  assert.match(boundWho({ kind: 'function', attacker: 'alice', victim: 'admin' }), /alice \(ordinary\).*admin \(privileged\)/);
  assert.equal(boundWho({ kind: 'property', attacker: 'alice', victim: 'alice' }), 'alice reads their own object');
  assert.equal(boundWho(null), '');
});

test('exampleChecksSpec picks a privileged-looking GET for the function and holds only placeholders', () => {
  const ops = [
    { method: 'GET', path: '/v2/orders/{orderId}', auth: 'required', path_params: ['orderId'], classes: ['object_level_authorization'] },
    { method: 'GET', path: '/v2/admin/reports/{reportId}', auth: 'required', path_params: ['reportId'], classes: ['function_level_authorization'] },
    { method: 'GET', path: '/v2/catalog', auth: 'none' },
    { method: 'PATCH', path: '/v2/orders/{orderId}', auth: 'required', path_params: ['orderId'] },
  ];
  const s = exampleChecksSpec(ops);
  assert.equal(s.functions[0].operation, 'GET /v2/admin/reports/{reportId}');
  assert.deepEqual(s.functions[0].params, { reportId: 'REPLACE-F' });
  assert.equal(s.properties[0].operation, 'GET /v2/orders/{orderId}');
  assert.deepEqual(s.properties[0].params, { orderId: 'REPLACE-P' });
  assert.deepEqual(s.objects, []);
  assert.notEqual(s.functions[0].privileged, s.functions[0].ordinary);
  assert.ok(s.identities.every((i) => i.credential_ref.startsWith('REPLACE/')));
  // With no usable operation it still gives a fillable skeleton.
  const empty = exampleChecksSpec([]);
  assert.match(empty.functions[0].operation, /^GET /);
  assert.match(empty.properties[0].operation, /^GET /);
});

test('validJobStatus accepts the filter choices only', () => {
  for (const ok of ['', 'queued', 'running', 'completed', 'failed', 'cancelled']) assert.equal(validJobStatus(ok), true, ok);
  for (const bad of ['bogus', 'COMPLETED', "failed'--", null, undefined, 'all']) assert.equal(validJobStatus(bad), false, String(bad));
  assert.equal(JOB_STATUSES[0][0], '');
});

const GQL_OPS = [
  { method: 'QUERY', path: '/graphql', field: 'orders', returns: 'Order', returns_composite: true, args: [{ name: 'limit', type: 'Int', kind: 'SCALAR' }], auth: 'unspecified' },
  { method: 'QUERY', path: '/graphql', field: 'anything', returns: 'U', returns_composite: true, returns_union: true, args: [], auth: 'unspecified' },
  { method: 'QUERY', path: '/graphql', field: 'byIds', returns: 'Order', returns_composite: true, args: [{ name: 'ids', type: 'ID', kind: 'SCALAR', list: true, required: true }], auth: 'unspecified' },
  { method: 'QUERY', path: '/graphql', field: 'order', returns: 'Order', returns_composite: true, args: [{ name: 'id', type: 'ID', kind: 'SCALAR', required: true }], auth: 'unspecified' },
  { method: 'QUERY', path: '/graphql', field: 'note', returns: 'String', args: [{ name: 'id', type: 'ID', kind: 'SCALAR', required: true }, { name: 'n', type: 'Int', kind: 'SCALAR', required: true }], auth: 'unspecified' },
  { method: 'MUTATION', path: '/graphql', field: 'setStatus', returns: 'Order', returns_composite: true, args: [{ name: 'id', type: 'ID', kind: 'SCALAR', required: true }] },
];

test('graphQLExampleOp prefers a usable query with a required argument, and skips unions, lists and mutations', () => {
  assert.equal(graphQLExampleOp(GQL_OPS).field, 'order');
  assert.equal(graphQLExampleOp([GQL_OPS[1], GQL_OPS[2], GQL_OPS[5]]), null);
  assert.equal(graphQLExampleOp([GQL_OPS[0]]).field, 'orders');
  assert.equal(graphQLExampleOp([]), null);
  assert.equal(graphQLExampleOp(null), null);
  const inputArg = { method: 'QUERY', path: '/graphql', field: 'f', returns: 'O', args: [{ name: 'x', type: 'F', kind: 'INPUT_OBJECT', required: true }] };
  assert.equal(graphQLExampleOp([inputArg]), null);
});

test('opFullKey names a GraphQL field with # and a REST operation without', () => {
  assert.equal(opFullKey(GQL_OPS[3]), 'QUERY /graphql#order');
  assert.equal(opFullKey({ method: 'GET', path: '/v2/a/{id}' }), 'GET /v2/a/{id}');
});

test('exampleBindingSpec builds GraphQL test data when the inventory has no REST read, with a selection and typed placeholders', () => {
  const s = exampleBindingSpec(GQL_OPS);
  assert.equal(s.objects.length, 2);
  assert.equal(s.objects[0].operation, 'QUERY /graphql#order');
  assert.deepEqual(s.objects[0].params, { id: 'REPLACE-A' });
  assert.equal(s.objects[0].selection, 'id');
  assert.deepEqual(s.objects[1].params, { id: 'REPLACE-B' });
  assert.ok(s.objects.every((o) => o.protected_values.length === 1));
  assert.ok(s.identities.every((i) => i.credential_ref.startsWith('REPLACE/')));
  // A scalar return needs no selection, and Int arguments get a number.
  const only = exampleGraphQLSpec(GQL_OPS[4]);
  assert.equal(only.objects[0].selection, undefined);
  assert.deepEqual(only.objects[0].params, { id: 'REPLACE-A', n: '1' });
  // A REST read still wins when there is one.
  const rest = exampleBindingSpec([{ method: 'GET', path: '/v2/o/{id}', auth: 'required', path_params: ['id'] }].concat(GQL_OPS));
  assert.equal(rest.objects[0].operation, 'GET /v2/o/{id}');
});
