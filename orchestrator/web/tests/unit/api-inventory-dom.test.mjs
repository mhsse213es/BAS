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

async function setup({ stale = false, jobReason = 'EVIDENCE_INCONCLUSIVE' } = {}) {
  const dom = new JSDOM('<!doctype html><body><div id="api-inv-targets"></div><div id="api-inv-detail"></div></body>');
  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  const store = {};
  globalThis.localStorage = { getItem: (k) => store[k] ?? null, setItem: (k, v) => { store[k] = String(v); }, removeItem: (k) => { delete store[k]; } };
  const calls = [];
  globalThis.fetch = async (path, opts) => {
    const method = (opts && opts.method) || 'GET';
    calls.push({ path, method, body: opts && opts.body });
    const ok = (b, status = 200) => ({ status, json: async () => b });
    if (path === '/api/apibas/targets') return ok({ targets: [{ id: 'shop-1', name: EVIL, base_url: 'http://x', environment: 'lab', enabled: true, inventory: { version: 1, operations: 2, imported_at: '2026-11-10T00:00:00Z' } }] });
    if (path.endsWith('/inventory/versions')) return ok({ versions: [{ version: 1, operations: 2, imported_at: '2026-11-10T00:00:00Z', imported_by: 'admin1' }] });
    if (path.endsWith('/inventory')) return ok(inventory());
    if (path.endsWith('/binding/jobs')) return ok({ id: 'job-1', status: 'queued', created: true }, 202);
    if (path.endsWith('/binding') && method === 'GET') return ok(storedBinding(stale));
    if (path.endsWith('/binding') && method === 'PUT') return ok({ inventory_version: 1, scenarios: 0, bound: [], skipped: [], limits: [] });
    if (path === '/api/apibas/jobs/job-1') {
      return ok({ id: 'job-1', status: 'completed', environment: 'lab', failure_reason: '', started_at: null, finished_at: null,
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
