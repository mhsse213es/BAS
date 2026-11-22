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
const info = await page.evaluate(() => ({ visible: !document.getElementById('tab-factory-health').classList.contains('is-hidden'), tiles: document.querySelectorAll('.fh-tile').length, buttons: [...document.querySelectorAll('#tab-factory-health button')].filter((b) => b.offsetParent).map((b) => b.textContent.trim().slice(0, 30)), overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth }));
console.log(JSON.stringify({ ...info, errors: errs }));
await page.screenshot({ path: join(out, 'fh-full.png'), fullPage: true });
await page.locator('#factory-health-velocity').first().screenshot({ path: join(out, 'fh-vel.png') }).catch((e) => console.log('vel shot', e.message.slice(0, 80)));
await browser.close(); server.close();
