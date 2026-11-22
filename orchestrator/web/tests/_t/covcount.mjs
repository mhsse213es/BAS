import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises'; import { mkdirSync } from 'node:fs';
import { fixtureSet } from './fixtures-rich.mjs';
import { DEMO as G14 } from './demo-g14.mjs';
import { DEMO as A } from './demo-a.mjs';
const out = resolve(process.argv[2]); mkdirSync(out, { recursive: true });
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich'); const DATA = { ...A, ...G14 };
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url()); const key = req.method() + ' ' + u.pathname;
  if (DATA[key] !== undefined) { const v = typeof DATA[key] === 'function' ? DATA[key](u) : DATA[key]; return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(v) }); }
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
  if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'coverage'); el && el.click(); }); await page.waitForTimeout(2000);
const rows = () => page.evaluate(() => document.querySelectorAll('#utl-body tr').length + '|' + (document.getElementById('utl-foot').textContent || '').trim().slice(0, 60));
const cells = () => page.evaluate(() => { const m = document.getElementById('cov-matrix'); return { cells: m.querySelectorAll('.mx-cell').length, dim: m.querySelectorAll('.mx-cell.g1-s-c1f75ce4').length, foot: (document.getElementById('cov-foot').textContent||'').trim().slice(0,70), toolbar: [...document.querySelectorAll('#cov-toolbar button')].map((b) => b.textContent.trim() + (b.className.includes('active')||b.className.includes('on') ? '*' : '')).join(',') }; });
const log = {};
log.utl_initial = await rows();
for (const v of ['bas', 'art', 'atomic', 'multi', 'all']) { await page.click(`.cov-chip[data-val="${v}"]`); await page.waitForTimeout(300); log['utl_' + v] = await rows(); }
await page.click('.cov-chip[data-val="all"]'); await page.waitForTimeout(200);
await page.fill('#utl-search', 'T1566'); await page.waitForTimeout(300); log.search_T1566 = await rows();
await page.fill('#utl-search', '');
await page.fill('#utl-search', 'zzzz'); await page.waitForTimeout(300); log.search_zzzz = await rows();
await page.fill('#utl-search', '');
log.heat_initial = await cells();
for (const b of ['Prevented', 'Detected only', 'Missed', 'Untested']) { await page.locator('#cov-toolbar button', { hasText: b }).first().click(); await page.waitForTimeout(300); log['heat_' + b] = await cells(); }
console.log(JSON.stringify(log, null, 1));
await page.locator('#cov-matrix').screenshot({ path: join(out, 'heatmap.png') });
await browser.close(); server.close();
