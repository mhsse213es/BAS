import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises'; import { mkdirSync } from 'node:fs';
import { fixtureSet } from './fixtures-rich.mjs';
const out = resolve(process.argv[2]); mkdirSync(out, { recursive: true }); const MODE = process.argv[3] || 'full';
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich');
const OPS = [
  { method: 'GET', path: '/v2/orders', auth: 'required', classes: ['read'] },
  { method: 'GET', path: '/v2/orders/{id}', auth: 'required', classes: ['read'] },
  { method: 'POST', path: '/v2/orders', auth: 'required', classes: ['write'] },
  { method: 'PATCH', path: '/v2/orders/{id}', auth: 'required', classes: ['write', 'state'] },
  { method: 'DELETE', path: '/v2/orders/{id}', auth: 'required', classes: ['write'], deprecated: true },
  { method: 'GET', path: '/v2/health', auth: 'none', classes: ['public'] },
  { method: 'GET', path: '/v2/customers/{id}/statement', auth: 'optional', classes: ['read'] } ];
const TARGET = { id: 'orders-api', name: 'Orders API', environment: 'staging', base_url: 'https://orders.staging.example.com', enabled: true, inventory: { version: 3, operations: OPS.length, imported_at: '2026-11-20T08:12:00Z' } };
const withParams = OPS.map((o) => ({ ...o, path_params: (o.path.match(/{[^}]+}/g) || []).map((m) => m.slice(1, -1)) }));
const INV = { version: 3, title: 'Orders API', api_version: '2.4.0', openapi_version: '3.0.3', imported_at: '2026-11-20T08:12:00Z', imported_by: 'admin', source_sha256: 'a1f3c9e8b2d7460f5c1e9a0b7d3f2e8c4a6b9d1e0f7c3a2b5d8e9f4a1c6b0d2e', operations: OPS.length,
  listed_operations: withParams, classes: { read: 3, write: 3, state: 1, public: 1 }, suggested_scope: ['/v2/orders', '/v2/customers'], warnings: ['Operation DELETE /v2/orders/{id} is deprecated'] };
const VERS = { versions: [ { version: 3, operations: 7, imported_at: '2026-11-20T08:12:00Z', imported_by: 'admin' }, { version: 2, operations: 6, imported_at: '2026-11-10T09:00:00Z', imported_by: 'admin' }, { version: 1, operations: 5, imported_at: '2026-10-28T16:40:00Z', imported_by: 'analyst' } ] };
const JOBS = { jobs: [
  { id: 'job-0007', created_at: '2026-11-20T10:15:00Z', requested_by: 'admin', bound: true, status: 'completed', results: { pass: 9, fail: 1, error: 0, skipped: 2 }, scenarios: 12, environment: 'staging', scheduled: false, target_id: 'orders-api' },
  { id: 'job-0006', created_at: '2026-11-19T02:00:00Z', requested_by: 'scheduler', bound: false, status: 'completed', results: { pass: 14, fail: 0, error: 0, skipped: 0 }, scenarios: 14, environment: 'staging', scheduled: true, target_id: 'orders-api' },
  { id: 'job-0005', created_at: '2026-11-18T13:30:00Z', requested_by: 'analyst', bound: true, status: 'failed', results: { pass: 2, fail: 0, error: 3, skipped: 1 }, scenarios: 6, environment: 'staging', scheduled: false, target_id: 'orders-api' } ], next: '' };
const BINDING = { target_id: 'orders-api', updated_at: '2026-11-18T13:20:00Z', updated_by: 'admin', stale: false, validated_inventory: 3, newest_inventory: 3, spec: { identities: [{ name: 'alice', credential: 'orders-alice-token' }], objects: [{ id: 'ord-1001', owner: 'alice', kind: 'order' }] } };
const SCHED = { target_id: 'orders-api', enabled: true, mode: 'interval', every_hours: 24, next_run_at: '2026-11-21T02:00:00Z' };
const PLAN = { inventory_version: 3, scenarios: 1, bound: [{ scenario_id: 'read-own-order', operation: 'GET /v2/orders/{id}', kind: 'read', attacker: 'bob', owner: 'alice', path: '/v2/orders/ord-1001', write: false }], skipped: [{ operation: 'POST /v2/orders', reason: 'no test object of type order' }], limits: ['Results show what the target returned, not whether the control is sound.'] };
const JOB8 = { id: 'job-0008', status: 'completed', environment: 'staging', started_at: '2026-11-21T09:40:00Z', finished_at: '2026-11-21T09:40:12Z', reports: [{ scenario_id: 'read-own-order', result: 'pass', exploitability: 'low', control: 'ownership check', meaning: 'Bob was refused the order alice owns.' }] };
const browser = await chromium.launch();
const posts = [];
async function fresh() {
  const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 140))); page.on('dialog', (d) => { errs.push('native dialog: ' + d.message().slice(0, 80)); d.dismiss(); });
  page.on('request', (q) => { if (q.method() !== 'GET') posts.push(q.method() + ' ' + q.url().replace(origin, '')); });
  await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
  await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url()); const p = u.pathname;
    const json = (b, st) => r.fulfill({ status: st || 200, contentType: 'application/json', body: JSON.stringify(b) });
    if (p === '/api/apibas/targets') return json({ targets: [TARGET] });
    if (p === '/api/apibas/jobs') return json(JOBS);
    if (p === '/api/apibas/targets/orders-api/inventory') return json(INV);
    if (p === '/api/apibas/targets/orders-api/inventory/versions') return json(VERS);
    if (p === '/api/apibas/targets/orders-api/binding') return req.method() === 'GET' ? json(BINDING) : req.method() === 'PUT' ? json(PLAN) : r.fulfill({ status: 204, body: '' });
    if (p === '/api/apibas/targets/orders-api/jobs') return json(JOBS);
    if (p === '/api/apibas/targets/orders-api/schedule') return json(SCHED);
    if (p === '/api/apibas/targets/orders-api/binding' && req.method() === 'DELETE') return r.fulfill({ status: 204, body: '' });
  if (p === '/api/apibas/targets/orders-api/binding/plan') return json(PLAN);
  if (p === '/api/apibas/targets/orders-api/binding/jobs') return json({ id: 'job-0008', status: 'queued', environment: 'staging' });
  if (p === '/api/apibas/jobs/job-0008') return json(JOB8);
  if (p === '/ready' || p.startsWith('/api/')) return json(fx(req.method(), u));
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
  await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'api-inventory'); el && el.click(); }); await page.waitForTimeout(1000);
  await page.evaluate(() => [...document.querySelectorAll('#api-inv-targets button')].find((b) => b.textContent.trim() === 'Open').click()); await page.waitForTimeout(1200);
  return { page, errs };
}
const LIST = 'document.querySelectorAll("#tab-api-inventory button")';
const names = await (await fresh()).page.evaluate(() => [...document.querySelectorAll('#tab-api-inventory button')].filter((b) => b.offsetParent && !b.disabled).map((b, i) => (b.textContent.trim() || b.getAttribute('aria-label') || b.title || '(icon)').slice(0, 40) + '|' + (b.closest('[id]') ? b.closest('[id]').id : '')));
console.log('buttons:', names.length, JSON.stringify(names));
for (let i = 0; i < names.length; i++) {
  const { page, errs } = await fresh();
  const before = await page.evaluate(() => document.getElementById('tab-api-inventory').innerText);
  const pc = posts.length;
  const r = await page.evaluate((i) => { const b = [...document.querySelectorAll('#tab-api-inventory button')].filter((x) => x.offsetParent && !x.disabled)[i]; if (!b) return 'missing'; b.click(); return 'clicked'; }, i);
  await page.waitForTimeout(800);
  const after = await page.evaluate(() => document.getElementById('tab-api-inventory').innerText);
  const seen = new Set(before.split(String.fromCharCode(10)));
  const added = after.split(String.fromCharCode(10)).filter((l) => l.trim() && !seen.has(l)).slice(0, 3).map((l) => l.trim().slice(0, 90));
  const toast = await page.evaluate(() => { const t = document.getElementById('toast'); return t && t.className.includes('show') ? t.textContent.trim().slice(0, 90) : ''; });
  console.log(JSON.stringify({ i, button: names[i].split('|')[0], r, toast, added, posts: posts.slice(pc), errors: errs.slice(0, 2) }));
}
await browser.close(); server.close();
