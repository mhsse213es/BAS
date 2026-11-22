import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises'; import { mkdirSync } from 'node:fs';
import { fixtureSet } from './fixtures-rich.mjs';
import { DEMO } from './demo-g13.mjs';
const out = resolve(process.argv[2]); mkdirSync(out, { recursive: true });
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich');
const D = 86400;
const SEG = (k) => [
  { source: 'MITRE ATT&CK', content_type: 'emulates', cohort: 'validated', n: 18, p50_seconds: Math.round(0.4 * D * k), p95_seconds: Math.round(1.1 * D * k) },
  { source: 'CISA KEV', content_type: 'generated_for', cohort: 'validated', n: 11, p50_seconds: Math.round(0.3 * D * k), p95_seconds: Math.round(0.8 * D * k) },
  { source: 'MISP (internal)', content_type: 'emulates', cohort: 'validated', n: 6, p50_seconds: Math.round(0.6 * D * k), p95_seconds: Math.round(1.9 * D * k) },
  { source: 'AlienVault OTX', content_type: 'generated_for', cohort: 'failed', n: 3, p50_seconds: null, p95_seconds: null },
  { source: 'MITRE ATT&CK', content_type: 'emulates', cohort: 'open', n: 5, p50_seconds: null, p95_seconds: null } ];
const SLA = { queue: 0.3, generation: 1.2, validation: 0.5, end_to_end: 2.0 };
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url());
  if (u.pathname === '/api/analytics/factory-health') return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(DEMO['GET /api/analytics/factory-health']()) });
  if (u.pathname === '/api/intel/factory/sla') { const k = SLA[u.searchParams.get('stage')] || 1; return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ segments: SEG(k), open_count: 5, oldest_open_seconds: 6 * D, bottleneck: 'generation', incomplete_window: true }) }); }
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
  if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'factory-health'); el && el.click(); }); await page.waitForTimeout(1600);

const posts = []; const gets = [];
async function fresh() {
  const pg = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  const errs = []; pg.on('pageerror', (e) => errs.push(e.message.slice(0, 140))); pg.on('dialog', (d) => { errs.push('native dialog: ' + d.message().slice(0, 80)); d.dismiss(); });
  pg.on('request', (q) => { if (q.method() !== 'GET') posts.push(q.method() + ' ' + q.url().replace(origin, '')); else if (q.url().includes('/api/intel/')) gets.push(q.url().replace(origin, '').slice(0, 90)); });
  await pg.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
  await pg.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url());
    if (u.pathname === '/api/analytics/factory-health') return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(DEMO['GET /api/analytics/factory-health']()) });
    if (u.pathname === '/api/intel/factory/sla') { const k = SLA[u.searchParams.get('stage')] || 1; return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ segments: SEG(k), open_count: 5, oldest_open_seconds: 6 * D, bottleneck: 'generation', incomplete_window: true }) }); }
    if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
  await pg.routeWebSocket(/ws/, () => {});
  await pg.goto(origin + '/index.html'); await pg.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await pg.waitForTimeout(700);
  await pg.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'factory-health'); el && el.click(); }); await pg.waitForTimeout(1400);
  return { page: pg, errs };
}
const CTRL = '#tab-factory-health button, #tab-factory-health input, #tab-factory-health select, #tab-factory-health th[data-on-click], #tab-factory-health [data-on-click]';

{
  const { page, errs } = await fresh();
  const row = await page.evaluate(() => { const r = document.querySelector('#tab-factory-health tr.fh-row'); if (!r) return 'no row'; r.click(); return 'clicked row'; });
  await page.waitForTimeout(900);
  const st = await page.evaluate(() => ({ open: [...document.querySelectorAll('.overlay.open, .drawer-overlay.open, .sc-drawer.open')].map((e) => e.id), title: [...document.querySelectorAll('.sc-drawer-hd h3, .sc-drawer-title, #fh-drawer-title, [id$=drawer-title]')].map((e) => e.textContent.trim().slice(0, 60)).slice(0, 3), buttons: [...document.querySelectorAll('.drawer-overlay.open button, .sc-drawer button, #fh-drawer-overlay button')].filter((b) => b.offsetParent).map((b) => b.textContent.trim().slice(0, 30)).slice(0, 12) }));
  console.log(JSON.stringify({ row, ...st, errors: errs.slice(0, 2) }));
  await page.locator('#fh-drawer-overlay.open').first().screenshot({ path: resolve(process.argv[2], 'fh-drawer.png') }).catch((e) => console.log('shot', e.message.slice(0, 60)));
}
await browser.close(); server.close();
