import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises'; import { mkdirSync } from 'node:fs';
import { fixtureSet } from './fixtures-rich.mjs';
import * as DC from './demo-c.mjs'; import * as DG15 from './demo-g15.mjs'; import * as DG16 from './demo-g16.mjs'; import * as DG17 from './demo-g17.mjs';
const OUT = resolve(process.argv[2]); mkdirSync(OUT, { recursive: true });
const DATA = { ...DC.DEMO, ...DG15.DEMO, ...(DG16.DEMO || {}), ...(DG17.DEMO || {}) };
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich');
const browser = await chromium.launch(); const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 140)));
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url()); const key = req.method() + ' ' + u.pathname;
  if (DATA[key] !== undefined) { const v = typeof DATA[key] === 'function' ? DATA[key](u) : DATA[key]; return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(v) }); }
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
  if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'email'); el && el.click(); }); await page.waitForTimeout(2200);
const runRows = () => page.evaluate(() => { const t = [...document.querySelectorAll('#tab-email section')].find((s) => s.querySelector('.rk-hd h2') && s.querySelector('.rk-hd h2').textContent.trim() === 'Runs'); return t ? t.querySelectorAll('tbody tr').length : -1; });
const campRows = () => page.evaluate(() => { const t = [...document.querySelectorAll('#tab-email table')].find((x) => [...x.querySelectorAll('th')].some((h) => h.textContent.trim().toUpperCase() === 'CAMPAIGN')); return t ? t.querySelectorAll('tbody tr').length : -1; });
const log = {};
log.runs0 = await runRows();
for (const b of ['Running 1', 'Completed 3', 'Failed 1', 'All 5']) { await page.locator('#tab-email button', { hasText: b }).first().click(); await page.waitForTimeout(300); log['runs_' + b] = await runRows(); }
await page.locator('#tab-email button', { hasText: 'Campaigns 3' }).first().click(); await page.waitForTimeout(300); log.camp0 = await campRows();
for (const b of ['Running 1', 'Completed 1', 'Failed 1', 'All 3']) { await page.locator('#tab-email button', { hasText: b }).first().click(); await page.waitForTimeout(300); log['camp_' + b] = await campRows(); }
console.log(JSON.stringify(log));
console.log(JSON.stringify({ errors: errs.slice(0, 3) }));
await browser.close(); server.close();
