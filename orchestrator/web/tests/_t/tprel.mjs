import { chromium } from 'playwright-core'; import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs'; import * as DC from './demo-c.mjs'; import * as DG15 from './demo-g15.mjs'; import * as DG16 from './demo-g16.mjs'; import * as DG17 from './demo-g17.mjs'; import * as DG3 from './demo-g3.mjs'; import * as DG12 from './demo-g12.mjs'; import * as DG18 from './demo-g18.mjs';
const DATA = { ...DC.DEMO, ...DG15.DEMO, ...(DG16.DEMO || {}), ...(DG17.DEMO || {}), ...(DG3.DEMO || {}), ...(DG12.DEMO || {}), ...(DG18.DEMO || {}) };
const dist = resolve('dist'); const strip = new RegExp('^[/]+'); const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich'); const browser = await chromium.launch(); const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url()); const key = req.method() + ' ' + u.pathname;
  if (DATA[key] !== undefined) { const v = typeof DATA[key] === 'function' ? DATA[key](u) : DATA[key]; return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(v) }); }
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
  if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
const P = '#tab-threat-priority '; const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 100)));
const tabNow = () => page.evaluate(() => [...document.querySelectorAll('[id^="tab-"]')].filter((e) => !e.classList.contains('is-hidden') && getComputedStyle(e).display !== 'none').map((e) => e.id).join(','));
const go = () => page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'threat-priority'); el && el.click(); });
await go(); await page.waitForTimeout(2200);
await page.locator(P + 'button:has-text("Columns")').click(); await page.waitForTimeout(300);
const before = (await page.locator(P + 'thead th').allInnerTexts()).map((s) => s.trim()).filter(Boolean).join('/');
await page.locator('#tp-cols input.dt-colchk').nth(1).uncheck(); await page.waitForTimeout(400);
const after = (await page.locator(P + 'thead th').allInnerTexts()).map((s) => s.trim()).filter(Boolean).join('/');
console.log('columns before:', before, '\ncolumns after hiding Tier:', after);
await page.locator('#tp-cols input.dt-colchk').nth(1).check();
for (const label of ['Per-technique content and outcomes', 'What to simulate next', 'Run a simulation for these techniques']) {
  await go(); await page.waitForTimeout(1500);
  await page.locator(P + 'tbody tr').first().click(); await page.waitForTimeout(800);
  await page.locator('#tp-detail-overlay :text("' + label + '")').first().click({ timeout: 3000 }).catch(() => console.log(label, 'click failed'));
  await page.waitForTimeout(1200);
  console.log('related', label.padEnd(20), '-> tab:', (await tabNow()).slice(0, 40), '| drawer still open:', await page.evaluate(() => document.getElementById('tp-detail-overlay').classList.contains('open')));
}
console.log('errors:', JSON.stringify(errs));
await browser.close(); server.close();
