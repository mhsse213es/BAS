import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const EVIL = '</textarea><img src=x onerror=alert(1)><script>boom()</script>';

function inventory() {
  return {
    version: 1, title: 'Shop', api_version: '1', openapi_version: '3.0.0', imported_at: '2026-11-10T00:00:00Z', imported_by: 'admin1',
    source_sha256: 'a'.repeat(64), operations: 2, classes: { object_level_authorization: 1 }, suggested_scope: ['/v2'], warnings: [],
    listed_operations: [
      { method: 'GET', path: '/v2/orders/{orderId}', auth: 'required', path_params: ['orderId'], classes: ['object_level_authorization'] },
      { method: 'PATCH', path: '/v2/orders/{orderId}', auth: 'required', path_params: ['orderId'], classes: ['object_level_authorization'] },
    ],
  };
}

function storedBinding(stale) {
  return {
    spec: { identities: [{ name: 'alice', credential_ref: 'shop/alice' }, { name: 'bob', credential_ref: 'shop/bob' }], objects: [{ operation: 'GET /v2/orders/{orderId}', params: { orderId: 'ORD-A1' }, owner: 'alice', protected_values: [EVIL] }] },
    updated_by: 'admin1', updated_at: '2026-11-10T00:00:00Z', validated_inventory: 1, newest_inventory: stale ? 2 : 1, stale: !!stale,
  };
}

async function setup({ stale = false, jobReason = 'EVIDENCE_INCONCLUSIVE', jobs = null, jobStatus = 'completed', schedule = null, environment = 'lab', scheduleRefusal = '', planBound = null, jobsNext = '', jobsPage2 = null, jobsFiltered = null, allJobs = null, allNext = '', allPage2 = null, allFail = false } = {}) {
  const dom = new JSDOM('<!doctype html><body><div id="toast"></div><div id="api-inv-targets"></div><div id="api-inv-detail"></div></body>');
  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  const store = {};
  globalThis.localStorage = { getItem: (k) => store[k] ?? null, setItem: (k, v) => { store[k] = String(v); }, removeItem: (k) => { delete store[k]; } };
  const calls = [];
  globalThis.fetch = async (path, opts) => {
    const method = (opts && opts.method) || 'GET';
    calls.push({ path, method, body: opts && opts.body });
    const ok = (b, status = 200) => ({ status, json: async () => b });
    if (path === '/api/apibas/targets') return ok({ targets: [{ id: 'shop-1', name: EVIL, base_url: 'http://x', environment: environment, enabled: true, inventory: { version: 1, operations: 2, imported_at: '2026-11-10T00:00:00Z' } }] });
    if (path.endsWith('/shop-1/schedule')) {
      if (method === 'GET') return schedule ? ok(schedule) : ok({ error: 'no schedule for this target' }, 404);
      if (method === 'DELETE') return ok({ removed: true });
      if (scheduleRefusal) return ok({ error: scheduleRefusal }, 400);
      const b = JSON.parse(opts.body);
      return ok({ target_id: 'shop-1', every_hours: b.every_hours, at: b.at, timezone: b.timezone, days: b.days, include_writes: b.include_writes, enabled: b.enabled, next_run_at: '2026-11-11T02:00:00Z', created_by: 'admin1', consecutive_failures: 0 });
    }
    if (path.endsWith('/binding/plan') && planBound) return ok({ inventory_version: 1, scenarios: planBound.length, bound: planBound, skipped: [], limits: [] });
    if (path.endsWith('/inventory/versions')) return ok({ versions: [{ version: 1, operations: 2, imported_at: '2026-11-10T00:00:00Z', imported_by: 'admin1' }] });
    if (path.endsWith('/inventory')) return ok(inventory());
    if (path.endsWith('/binding/jobs')) return ok({ id: 'job-1', status: 'queued', created: true }, 202);
    if (path.endsWith('/binding') && method === 'GET') return ok(storedBinding(stale));
    if (path.endsWith('/binding') && method === 'PUT') return ok({ inventory_version: 1, scenarios: 0, bound: [], skipped: [], limits: [] });
    if (path.includes('/shop-1/jobs')) {
      if (path.includes('before=') && jobsPage2) return ok({ jobs: jobsPage2 });
      if (path.includes('status=') && jobsFiltered) return ok({ jobs: jobsFiltered });
      if (jobsNext && jobs) return ok({ jobs, next: jobsNext });
      return ok({ jobs: jobs || [
        { id: 'job-1', requested_by: EVIL, environment: 'lab', status: 'completed', failure_reason: '', bound: true, scenarios: 3, created_at: '2026-11-10T01:00:00Z',
          results: { pass: 1, fail: 1, error: 0, skipped: 1 } },
        { id: 'job-0', requested_by: 'a1', environment: 'lab', status: 'failed', failure_reason: 'execution timed out', bound: false, scenarios: 1, created_at: '2026-11-09T01:00:00Z',
          results: { pass: 0, fail: 0, error: 0, skipped: 0 } }] });
    }
    if (path === '/api/apibas/jobs' || path.startsWith('/api/apibas/jobs?')) {
      if (allFail) return ok({ error: 'could not list jobs' }, 500);
      if (path.includes('before=') && allPage2) return ok({ jobs: allPage2 });
      const base = allJobs || [
        { id: 'aj-2', target_id: 'shop-1', requested_by: 'schedule:' + EVIL, scheduled: true, environment: 'lab', status: 'completed', failure_reason: '', bound: true, scenarios: 2, created_at: '2026-11-10T03:00:00Z', results: { pass: 2, fail: 0, error: 0, skipped: 0 } },
        { id: 'aj-1', target_id: 'gone-9', requested_by: 'a1', scheduled: false, environment: 'staging', status: 'failed', failure_reason: 'x', bound: false, scenarios: 1, created_at: '2026-11-09T03:00:00Z', results: { pass: 0, fail: 1, error: 0, skipped: 0 } }];
      return ok(allNext ? { jobs: base, next: allNext } : { jobs: base });
    }
    if (path === '/api/apibas/jobs/job-1') {
      return ok({ id: 'job-1', status: jobStatus, environment: 'lab', failure_reason: '', started_at: null, finished_at: null,
        reports: [{ scenario_id: 'API-BAS-AUTHZ-901', result: 'SKIPPED', exploitability: 'inconclusive', control: 'inconclusive', reason: jobReason }] });
    }
    return ok({ error: 'unexpected ' + method + ' ' + path }, 404);
  };
  const m = await import('../../src/features/api-inventory.js');
  await m.loadApiInventory();
  m.apiInvSelect('shop-1');
  await new Promise((r) => setTimeout(r, 40));
  return { dom, m, calls };
}

const settle = () => new Promise((r) => setTimeout(r, 40));

test('hostile target names and stored values reach the page as text, and the textarea cannot be broken out of', async () => {
  const { dom } = await setup();
  const doc = dom.window.document;
  assert.equal(doc.querySelectorAll('img,script').length, 0, 'no element may be created from stored or target text');
  const ta = doc.getElementById('api-inv-binding');
  assert.ok(ta, 'the binding box is shown');
  assert.ok(ta.value.includes(EVIL), 'the stored spec is shown literally in the box');
  assert.ok(doc.getElementById('api-inv-targets').textContent.includes(EVIL));
  assert.match(doc.getElementById('api-inv-stored-note').textContent, /checked against the newest inventory/);
});

test('running stored data queues a job with a fresh key and shows an inconclusive result as not a pass', async () => {
  const { dom, m, calls } = await setup();
  m.apiInvRunBound();
  await settle();
  const post = calls.find((c) => c.path.endsWith('/binding/jobs'));
  assert.ok(post, 'a job was queued');
  assert.match(JSON.parse(post.body).key, /^ui-[0-9a-f]{20}$/);
  const out = dom.window.document.getElementById('api-inv-job');
  assert.match(out.textContent, /API-BAS-AUTHZ-901/);
  assert.match(out.textContent, /Not conclusive/);
  assert.match(out.textContent, /not a pass/i);
  assert.equal(out.querySelectorAll('img,script').length, 0);
});

test('stale stored data is not run, and says why', async () => {
  const { dom, m, calls } = await setup({ stale: true });
  m.apiInvRunBound();
  await settle();
  assert.equal(calls.some((c) => c.path.endsWith('/binding/jobs')), false, 'no job may be queued for stale data');
  assert.match(dom.window.document.getElementById('api-inv-job').textContent, /Save it again/);
});

test('a reason from the server is shown as text', async () => {
  const { dom, m } = await setup({ jobReason: '<img src=x onerror=alert(2)>' });
  m.apiInvRunBound();
  await settle();
  const out = dom.window.document.getElementById('api-inv-job');
  assert.equal(out.querySelectorAll('img').length, 0);
  assert.ok(out.textContent.includes('<img src=x onerror=alert(2)>'));
});

test('saving sends the typed JSON by PUT, and invalid JSON sends nothing', async () => {
  const { dom, m, calls } = await setup();
  const ta = dom.window.document.getElementById('api-inv-binding');
  ta.value = '{not json';
  m.apiInvSaveBinding();
  await settle();
  assert.equal(calls.filter((c) => c.method === 'PUT').length, 0);
  assert.match(dom.window.document.getElementById('api-inv-binding-result').textContent, /not valid JSON/);

  ta.value = JSON.stringify({ identities: [], objects: [] });
  m.apiInvSaveBinding();
  await settle();
  const put = calls.find((c) => c.method === 'PUT');
  assert.ok(put && put.path.endsWith('/binding'));
  assert.deepEqual(JSON.parse(put.body), { identities: [], objects: [] });
});

test('previewing with an empty box uses the stored data (empty body)', async () => {
  const { dom, m, calls } = await setup();
  dom.window.document.getElementById('api-inv-binding').value = '';
  m.apiInvPlanBinding();
  await settle();
  const post = calls.find((c) => c.path.includes('/binding/plan'));
  assert.ok(post, 'a preview was requested');
  assert.equal(post.body, '');
});

test('the recent jobs list shows kind, status and grade counts, with hostile text as text', async () => {
  const { dom } = await setup();
  const doc = dom.window.document;
  const list = doc.getElementById('api-inv-jobs-list');
  assert.ok(list, 'the list is shown');
  assert.equal(list.querySelectorAll('tbody tr').length, 2);
  const text = list.textContent;
  assert.match(text, /bound/);
  assert.match(text, /catalogue/);
  assert.match(text, /1 fail · 1 pass · 1 skipped/);
  assert.match(text, /no results/);
  assert.ok(text.includes(EVIL), 'a requester name is shown literally');
  assert.equal(doc.querySelectorAll('img,script').length, 0);
  const view = list.querySelector('[data-on-click="apiInvJob"]');
  assert.equal(view.getAttribute('data-args'), '["job-1"]');
});

test('an empty list says so', async () => {
  const { dom } = await setup({ jobs: [] });
  assert.match(dom.window.document.getElementById('api-inv-jobs-list').textContent, /No jobs yet/);
});

test('viewing a job from the list shows its grades in its own panel and leaves the run panel alone', async () => {
  const { dom, m } = await setup();
  const doc = dom.window.document;
  doc.getElementById('api-inv-job').innerHTML = 'untouched';
  m.apiInvJob('job-1');
  await settle();
  const view = doc.getElementById('api-inv-jobview');
  assert.match(view.textContent, /API-BAS-AUTHZ-901/);
  assert.match(view.textContent, /not a pass/i);
  assert.equal(doc.getElementById('api-inv-job').innerHTML, 'untouched');
});

test('a job that has ended refreshes the list; one still running keeps being followed', async () => {
  const { dom, m, calls } = await setup({ jobStatus: 'running' });
  const before = calls.filter((c) => c.path.endsWith('/shop-1/jobs')).length;
  m.apiInvJob('job-1');
  await settle();
  assert.match(dom.window.document.getElementById('api-inv-jobview').textContent, /Running/);
  assert.equal(calls.filter((c) => c.path.endsWith('/shop-1/jobs')).length, before, 'no refresh while the job is still running');
  // Selecting the target again stops the earlier follow (no further requests for the old job).
  m.apiInvSelect('shop-1');
  await settle();
  const n = calls.filter((c) => c.path === '/api/apibas/jobs/job-1').length;
  await new Promise((r) => setTimeout(r, 3300));
  assert.equal(calls.filter((c) => c.path === '/api/apibas/jobs/job-1').length, n, 'a stopped follow must not keep polling');
});

test('Refresh reloads the list', async () => {
  const { m, calls } = await setup();
  const before = calls.filter((c) => c.path.endsWith('/shop-1/jobs')).length;
  m.apiInvJobsRefresh();
  await settle();
  assert.equal(calls.filter((c) => c.path.endsWith('/shop-1/jobs')).length, before + 1);
});

function fillForm(doc, v) {
  const set = (id, val) => { doc.getElementById(id).value = val; };
  const p = doc.querySelector('#api-inv-w-params [data-param="orderId"]');
  p.value = v.orderId;
  set('api-inv-w-owner', v.owner);
  set('api-inv-w-attack', v.attack);
  set('api-inv-w-restore', v.restore);
  set('api-inv-w-ignore', v.ignore || '');
}

const GOOD = { orderId: 'ORD-A1', owner: 'alice', attack: '{"status":"hacked"}', restore: '{"status":"open"}', ignore: 'updated_at, etag' };

test('the write form offers the inventory PUT or PATCH operations, path inputs, identities and the default read-back', async () => {
  const { dom } = await setup();
  const doc = dom.window.document;
  assert.deepEqual([...doc.getElementById('api-inv-w-op').options].map((o) => o.value), ['PATCH /v2/orders/{orderId}']);
  assert.ok(doc.querySelector('#api-inv-w-params [data-param="orderId"]'));
  assert.deepEqual([...doc.getElementById('api-inv-w-owner').options].map((o) => o.value), ['alice', 'bob']);
  assert.match(doc.getElementById('api-inv-w-read').options[0].textContent, /Same path \(GET \/v2\/orders\/\{orderId\}\)/);
  assert.match(doc.getElementById('api-inv-wlist').textContent, /No write objects/);
  assert.match(doc.querySelector('.ai-warn').textContent, /really tries to change/);
});

test('adding from the form puts the object in the test-data box with allow_writes, and lists it', async () => {
  const { dom, m } = await setup();
  const doc = dom.window.document;
  fillForm(doc, GOOD);
  m.apiInvWriteApply();
  const spec = JSON.parse(doc.getElementById('api-inv-binding').value);
  assert.equal(spec.allow_writes, true);
  const w = spec.objects.find((o) => o.write);
  assert.deepEqual(w, { operation: 'PATCH /v2/orders/{orderId}', params: { orderId: 'ORD-A1' }, owner: 'alice',
    write: { attack_body: '{"status":"hacked"}', restore_body: '{"status":"open"}', ignore_fields: ['updated_at', 'etag'] } });
  assert.equal(spec.identities.length, 2, 'the identities are kept');
  assert.match(doc.getElementById('api-inv-w-result').textContent, /Added to the test data.*not saved yet/s);
  assert.match(doc.getElementById('api-inv-wlist').textContent, /ORD-A1/);
});

test('an invalid form changes nothing and says why', async () => {
  const { dom, m } = await setup();
  const doc = dom.window.document;
  const before = doc.getElementById('api-inv-binding').value;
  fillForm(doc, { ...GOOD, attack: 'status=hacked' });
  m.apiInvWriteApply();
  assert.equal(doc.getElementById('api-inv-binding').value, before);
  assert.match(doc.getElementById('api-inv-w-result').textContent, /attack body is not valid JSON/i);
  fillForm(doc, { ...GOOD, restore: GOOD.attack });
  m.apiInvWriteApply();
  assert.match(doc.getElementById('api-inv-w-result').textContent, /same/);
  assert.equal(doc.getElementById('api-inv-binding').value, before);
});

test('the form will not edit a box that is not valid JSON', async () => {
  const { dom, m } = await setup();
  const doc = dom.window.document;
  const box = doc.getElementById('api-inv-binding');
  box.value = '{broken';
  fillForm(doc, GOOD);
  m.apiInvWriteApply();
  assert.equal(box.value, '{broken');
  assert.match(doc.getElementById('api-inv-w-result').textContent, /not valid JSON/);
  m.apiInvWriteSync();
  assert.match(doc.getElementById('api-inv-wlist').textContent, /not valid JSON/);
});

test('with no identities in the box there is no owner to choose, and nothing is added', async () => {
  const { dom, m } = await setup();
  const doc = dom.window.document;
  const box = doc.getElementById('api-inv-binding');
  box.value = '';
  m.apiInvWriteSync();
  assert.match(doc.getElementById('api-inv-w-owner').textContent, /add identities/i);
  fillForm(doc, { ...GOOD, owner: '' });
  m.apiInvWriteApply();
  assert.equal(box.value, '');
  assert.match(doc.getElementById('api-inv-w-result').textContent, /Choose the identity/);
});

test('Edit loads an object into the form and adding it again replaces it', async () => {
  const { dom, m } = await setup();
  const doc = dom.window.document;
  fillForm(doc, GOOD);
  m.apiInvWriteApply();
  const read = () => JSON.parse(doc.getElementById('api-inv-binding').value);
  const n = read().objects.length;
  const idx = read().objects.findIndex((o) => o.write);
  doc.getElementById('api-inv-w-attack').value = '';
  m.apiInvWriteEdit(idx);
  assert.equal(doc.getElementById('api-inv-w-attack').value, '{"status":"hacked"}');
  assert.equal(doc.querySelector('#api-inv-w-params [data-param="orderId"]').value, 'ORD-A1');
  assert.equal(doc.getElementById('api-inv-w-ignore').value, 'updated_at, etag');
  doc.getElementById('api-inv-w-restore').value = '{"status":"reopened"}';
  m.apiInvWriteApply();
  assert.equal(read().objects.length, n, 'the same operation and values replace rather than add');
  assert.equal(read().objects[idx].write.restore_body, '{"status":"reopened"}');
  assert.match(doc.getElementById('api-inv-w-result').textContent, /Replaced/);
});

test('Remove takes a write object out of the box', async () => {
  const { dom, m } = await setup();
  const doc = dom.window.document;
  fillForm(doc, GOOD);
  m.apiInvWriteApply();
  const idx = JSON.parse(doc.getElementById('api-inv-binding').value).objects.findIndex((o) => o.write);
  m.apiInvWriteRemove(idx);
  assert.equal(JSON.parse(doc.getElementById('api-inv-binding').value).objects.some((o) => o.write), false);
  assert.match(doc.getElementById('api-inv-wlist').textContent, /No write objects/);
});

test('a hostile identity name or object value reaches the form as text only', async () => {
  const { dom, m } = await setup();
  const doc = dom.window.document;
  const evil = '<img src=x onerror=alert(3)>';
  doc.getElementById('api-inv-binding').value = JSON.stringify({ identities: [{ name: evil, credential_ref: 'a/b' }, { name: 'bob', credential_ref: 'c/d' }], objects: [
    { operation: 'PATCH /v2/orders/{orderId}', params: { orderId: evil }, owner: evil, write: { attack_body: '{"a":1}', restore_body: '{"a":2}', read_operation: evil } }] });
  m.apiInvWriteSync();
  assert.equal(doc.querySelectorAll('img,script').length, 0);
  assert.ok(doc.getElementById('api-inv-wlist').textContent.includes(evil));
  assert.ok([...doc.getElementById('api-inv-w-owner').options].some((o) => o.textContent === evil));
});

const SCHED = (over = {}) => ({ target_id: 'shop-1', every_hours: 24, include_writes: false, enabled: true, next_run_at: '2026-11-11T02:00:00Z', created_by: 'admin1',
  last_run_at: '2026-11-10T02:00:00Z', last_job_id: 'job-9', last_result: 'queued', consecutive_failures: 0, ...over });

test('the schedule card says there is none, and creating one sends the typed interval by PUT', async () => {
  const { dom, m, calls } = await setup();
  const doc = dom.window.document;
  assert.match(doc.getElementById('api-inv-sched-note').textContent, /No schedule/);
  assert.equal(doc.getElementById('api-inv-sched-writes').checked, false, 'writes are off by default');
  doc.getElementById('api-inv-sched-hours').value = '12';
  m.apiInvSaveSchedule();
  await settle();
  const put = calls.find((c) => c.path.endsWith('/shop-1/schedule') && c.method === 'PUT');
  assert.ok(put, 'the schedule was sent');
  assert.deepEqual(JSON.parse(put.body), { every_hours: 12, include_writes: false, enabled: true });
  assert.match(doc.getElementById('api-inv-sched-note').textContent, /every 12 hours/);
});

test('an invalid interval sends nothing and says why', async () => {
  const { dom, m, calls } = await setup();
  const doc = dom.window.document;
  for (const bad of ['', '0', '721', 'abc', '1.5', '-3']) {
    doc.getElementById('api-inv-sched-hours').value = bad;
    m.apiInvSaveSchedule();
    assert.match(doc.getElementById('api-inv-sched-result').textContent, /hours/, bad);
  }
  assert.equal(calls.some((c) => c.path.endsWith('/schedule') && c.method === 'PUT'), false);
});

test('including writes is sent only when ticked', async () => {
  const { dom, m, calls } = await setup();
  const doc = dom.window.document;
  doc.getElementById('api-inv-sched-writes').checked = true;
  doc.getElementById('api-inv-sched-enabled').checked = false;
  m.apiInvSaveSchedule();
  await settle();
  const put = calls.find((c) => c.method === 'PUT' && c.path.endsWith('/schedule'));
  assert.deepEqual(JSON.parse(put.body), { every_hours: 24, include_writes: true, enabled: false });
});

test('an existing schedule is shown with its next run and last result, and can be removed', async () => {
  const { dom, m, calls } = await setup({ schedule: SCHED() });
  const doc = dom.window.document;
  const note = doc.getElementById('api-inv-sched-note').textContent;
  assert.match(note, /every day/);
  assert.match(note, /read scenarios only/);
  assert.match(note, /2026-11-11 02:00 UTC/);
  assert.match(note, /Last attempt.*queued/);
  assert.equal(doc.getElementById('api-inv-sched-hours').value, '24');
  m.apiInvRemoveSchedule();
  await settle();
  assert.ok(calls.some((c) => c.method === 'DELETE' && c.path.endsWith('/shop-1/schedule')));
  assert.match(doc.getElementById('api-inv-sched-note').textContent, /No schedule/);
});

test('a paused schedule says it is paused and how to resume it', async () => {
  const { dom } = await setup({ schedule: SCHED({ enabled: false, paused_for_failures: true, consecutive_failures: 5, last_result: 'not run: the test data was checked against an older inventory; save it again first' }) });
  const note = dom.window.document.getElementById('api-inv-sched-note');
  assert.match(note.textContent, /Paused after 5 runs/);
  assert.match(note.textContent, /save the schedule again to resume/i);
  assert.match(note.textContent, /older inventory/);
  assert.equal(note.className, 'ai-warn');
});

test('text from a schedule result reaches the page as text only', async () => {
  const { dom } = await setup({ schedule: SCHED({ last_result: '<img src=x onerror=alert(5)>' }) });
  const doc = dom.window.document;
  assert.equal(doc.querySelectorAll('img').length, 0);
  assert.ok(doc.getElementById('api-inv-sched-note').textContent.includes('<img src=x onerror=alert(5)>'));
});

test('a production target is not offered a schedule', async () => {
  const { dom } = await setup({ environment: 'production' });
  const doc = dom.window.document;
  assert.equal(doc.getElementById('api-inv-sched-hours'), null);
  assert.match(doc.getElementById('api-inv-detail').textContent, /production target cannot be scheduled/);
});

test('a server refusal is shown and the card keeps its state', async () => {
  const { dom, m } = await setup({ scheduleRefusal: 'including writes needs the target to register allowed paths' });
  const doc = dom.window.document;
  doc.getElementById('api-inv-sched-writes').checked = true;
  m.apiInvSaveSchedule();
  await settle();
  assert.match(doc.getElementById('api-inv-sched-result').textContent, /register allowed paths/);
});

test('the function and property example fills the box with both checks, and the preview shows their kinds', async () => {
  const { dom, m, calls } = await setup({ planBound: [
    { scenario_id: 'API-BAS-AUTHZ-901', operation: 'GET /v2/admin/reports/{reportId}', attacker: 'alice', victim: 'admin', path: '/v2/admin/reports/R-1', kind: 'function' },
    { scenario_id: 'API-BAS-AUTHZ-902', operation: 'GET /v2/orders/{orderId}', attacker: 'alice', victim: 'alice', path: '/v2/orders/O-1', kind: 'property' },
    { scenario_id: 'API-BAS-AUTHZ-903', operation: 'GET /v2/orders/{orderId}', attacker: 'bob', victim: 'alice', path: '/v2/orders/O-2' },
  ] });
  const doc = dom.window.document;
  m.apiInvExampleChecks();
  const spec = JSON.parse(doc.getElementById('api-inv-binding').value);
  assert.equal(spec.functions.length, 1);
  assert.equal(spec.properties.length, 1);
  assert.deepEqual(spec.objects, []);
  m.apiInvPlanBinding();
  await settle();
  const post = calls.find((c) => c.path.includes('/binding/plan'));
  assert.ok(post, 'the plan was requested');
  assert.equal(JSON.parse(post.body).functions[0].privileged, 'admin');
  const out = doc.getElementById('api-inv-binding-result').textContent;
  assert.match(out, /alice \(ordinary\) calls a function of admin \(privileged\)/);
  assert.match(out, /alice reads their own object/);
  assert.match(out, /bob → alice/);
  assert.match(out, /function/);
  assert.match(out, /property/);
});

function jobRow(id, status) {
  return { id, requested_by: 'a1', environment: 'lab', status, failure_reason: '', bound: true, scenarios: 1, created_at: '2026-11-09T01:00:00Z', results: { pass: 1, fail: 0, error: 0, skipped: 0 } };
}

test('Load more adds the next page below the jobs shown, with the cursor passed back unchanged', async () => {
  const { dom, m, calls } = await setup({ jobs: [jobRow('job-a', 'completed'), jobRow('job-b', 'completed')], jobsNext: '2026-11-09T01:00:00Z_aaaaaaaa-0000-0000-0000-000000000001', jobsPage2: [jobRow('job-c', 'failed')] });
  const doc = dom.window.document;
  assert.ok(doc.querySelector('[data-a="apiInvJobsMore"]') || /Load more/.test(doc.getElementById('api-inv-jobs-list').textContent), 'a Load more button is shown while a cursor exists');
  m.apiInvJobsMore();
  await settle();
  const more = calls.find((c) => c.path.includes('/shop-1/jobs') && c.path.includes('before='));
  assert.ok(more, 'the next page was requested');
  assert.match(decodeURIComponent(more.path), /before=2026-11-09T01:00:00Z_aaaaaaaa-0000-0000-0000-000000000001/);
  const list = doc.getElementById('api-inv-jobs-list');
  assert.equal(list.querySelectorAll('tbody tr').length, 3);
  assert.ok(!/Load more/.test(list.textContent), 'no button once the last page is shown');
});

test('choosing a status asks the server for that status and starts again from the newest job', async () => {
  const { dom, m, calls } = await setup({ jobs: [jobRow('job-a', 'completed')], jobsFiltered: [jobRow('job-f', 'failed')] });
  const doc = dom.window.document;
  doc.getElementById('api-inv-jobs-status').value = 'failed';
  m.apiInvJobsFilter();
  await settle();
  const f = calls.find((c) => c.path.includes('/shop-1/jobs') && c.path.includes('status=failed'));
  assert.ok(f, 'the filtered list was requested');
  assert.ok(!f.path.includes('before='), 'a filter starts from the first page');
  assert.equal(doc.getElementById('api-inv-jobs-list').querySelectorAll('tbody tr').length, 1);
  assert.match(doc.getElementById('api-inv-jobs-list').textContent, /failed/);
});

test('an empty filtered list says which status has none', async () => {
  const { dom, m } = await setup({ jobs: [jobRow('job-a', 'completed')], jobsFiltered: [] });
  const doc = dom.window.document;
  doc.getElementById('api-inv-jobs-status').value = 'cancelled';
  m.apiInvJobsFilter();
  await settle();
  assert.match(doc.getElementById('api-inv-jobs-list').textContent, /No cancelled jobs/);
});

test('a status that is not in the list is treated as All', async () => {
  const { dom, m, calls } = await setup({ jobs: [jobRow('job-a', 'completed')] });
  const sel = dom.window.document.getElementById('api-inv-jobs-status');
  const opt = dom.window.document.createElement('option');
  opt.value = "failed'; DROP TABLE x;--";
  sel.appendChild(opt);
  sel.value = opt.value;
  m.apiInvJobsFilter();
  await settle();
  assert.equal(calls.some((c) => c.path.includes('DROP')), false);
});

test('choosing a time of day shows its fields, sends at, timezone and days, and names the schedule by its clock', async () => {
  const { dom, m, calls } = await setup();
  const doc = dom.window.document;
  assert.equal(doc.getElementById('api-inv-sched-clock').hidden, true);
  doc.getElementById('api-inv-sched-mode').value = 'clock';
  m.apiInvSchedMode();
  assert.equal(doc.getElementById('api-inv-sched-clock').hidden, false);
  assert.equal(doc.getElementById('api-inv-sched-interval').hidden, true);
  doc.getElementById('api-inv-sched-at').value = '02:30';
  doc.getElementById('api-inv-sched-tz').value = 'Asia/Kolkata';
  doc.getElementById('api-inv-sched-days').value = 'Fri, mon';
  m.apiInvSaveSchedule();
  await settle();
  const put = calls.find((c) => c.method === 'PUT' && c.path.endsWith('/schedule'));
  assert.deepEqual(JSON.parse(put.body), { at: '02:30', timezone: 'Asia/Kolkata', days: ['mon', 'fri'], include_writes: false, enabled: true });
  assert.match(doc.getElementById('api-inv-sched-note').textContent, /Mon, Fri at 02:30 Asia\/Kolkata/);
});

test('a bad time, timezone or day sends nothing and says why', async () => {
  const { dom, m, calls } = await setup();
  const doc = dom.window.document;
  doc.getElementById('api-inv-sched-mode').value = 'clock';
  m.apiInvSchedMode();
  for (const [at, tz, days, want] of [['2:30', 'UTC', '', /HH:MM/], ['25:00', 'UTC', '', /HH:MM/], ['02:30', 'a b', '', /timezone/], ['02:30', 'UTC', 'monday', /Days/]]) {
    doc.getElementById('api-inv-sched-at').value = at;
    doc.getElementById('api-inv-sched-tz').value = tz;
    doc.getElementById('api-inv-sched-days').value = days;
    m.apiInvSaveSchedule();
    assert.match(doc.getElementById('api-inv-sched-result').textContent, want, at + tz + days);
  }
  assert.equal(calls.some((c) => c.path.endsWith('/schedule') && c.method === 'PUT'), false);
});

test('an existing time-of-day schedule opens in time-of-day mode with its values', async () => {
  const { dom } = await setup({ schedule: SCHED({ every_hours: undefined, at: '03:15', timezone: 'UTC', days: ['sat'] }) });
  const doc = dom.window.document;
  assert.equal(doc.getElementById('api-inv-sched-mode').value, 'clock');
  assert.equal(doc.getElementById('api-inv-sched-at').value, '03:15');
  assert.equal(doc.getElementById('api-inv-sched-days').value, 'sat');
  assert.equal(doc.getElementById('api-inv-sched-interval').hidden, true);
  assert.match(doc.getElementById('api-inv-sched-note').textContent, /Sat at 03:15 UTC/);
});

const allCalls = (calls) => calls.filter((c) => c.path === '/api/apibas/jobs' || c.path.startsWith('/api/apibas/jobs?'));

test('the all-targets list loads on page load and shows target, environment, source and results as text', async () => {
  const { dom, calls } = await setup();
  const doc = dom.window.document;
  assert.ok(allCalls(calls).length >= 1, 'the list was requested');
  const list = doc.getElementById('api-inv-all-list');
  assert.match(list.textContent, /scheduled/);
  assert.ok(list.textContent.includes(EVIL), 'the hostile target name is shown literally');
  assert.ok(list.textContent.includes('gone-9'), 'a job of a target that is no longer listed still shows its id');
  assert.match(list.textContent, /manual/);
  assert.equal(doc.querySelectorAll('#api-inv-all-list img, #api-inv-all-list script').length, 0);
});

test('changing a filter asks the server with only known choices and the target list offers the registered targets', async () => {
  const { dom, m, calls } = await setup();
  const doc = dom.window.document;
  assert.ok([...doc.getElementById('api-inv-all-target').options].some((o) => o.value === 'shop-1'));
  doc.getElementById('api-inv-all-env').value = 'staging';
  doc.getElementById('api-inv-all-source').value = 'scheduled';
  doc.getElementById('api-inv-all-status').value = 'failed';
  doc.getElementById('api-inv-all-target').value = 'shop-1';
  m.apiInvAllJobsFilter();
  await settle();
  const last = allCalls(calls).pop();
  assert.equal(last.path, '/api/apibas/jobs?status=failed&environment=staging&source=scheduled&target_id=shop-1');
  // The chosen values stay selected after the list is redrawn.
  assert.equal(doc.getElementById('api-inv-all-env').value, 'staging');
});

test('load more adds the next page without repeating a job, using the server cursor unchanged', async () => {
  const { dom, m, calls } = await setup({ allNext: 'CURSOR_1', allPage2: [
    { id: 'aj-1', target_id: 'gone-9', requested_by: 'a1', scheduled: false, environment: 'staging', status: 'failed', bound: false, scenarios: 1, created_at: '2026-11-09T03:00:00Z', results: { pass: 0, fail: 1, error: 0, skipped: 0 } },
    { id: 'aj-0', target_id: 'shop-1', requested_by: 'a1', scheduled: false, environment: 'lab', status: 'completed', bound: false, scenarios: 1, created_at: '2026-11-08T03:00:00Z', results: { pass: 1, fail: 0, error: 0, skipped: 0 } }] });
  const doc = dom.window.document;
  m.apiInvAllJobsMore();
  await settle();
  assert.ok(allCalls(calls).some((c) => c.path.includes('before=CURSOR_1')));
  const rows = doc.querySelectorAll('#api-inv-all-list tbody tr');
  assert.equal(rows.length, 3, 'aj-1 is not listed twice');
});

test('a failed all-targets list says so in the card and the rest of the page still works', async () => {
  const { dom } = await setup({ allFail: true });
  const doc = dom.window.document;
  assert.match(doc.getElementById('api-inv-all-list').textContent, /could not list jobs/);
  assert.ok(doc.getElementById('api-inv-binding'), 'the selected target is still shown');
});
