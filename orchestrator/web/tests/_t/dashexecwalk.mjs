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
const reqs = []; const dialogs = []; const errs = [];
page.on('request', (r) => { if (r.url().includes('/api/')) reqs.push(r.method() + ' ' + new URL(r.url()).pathname + new URL(r.url()).search); });
page.on('dialog', async (d) => { dialogs.push(d.message().slice(0, 60)); await d.dismiss(); }); page.on('pageerror', (e) => errs.push(e.message.slice(0, 100)));
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'dashboard'); el && el.click(); }); await page.waitForTimeout(2000);
await page.locator('#tab-dashboard button:has-text("Executive")').first().click(); await page.waitForTimeout(2000);
const ov = () => page.evaluate(() => ['results-overlay','report-overlay','run-overlay','tp-detail-overlay','cmp-drawer-overlay'].filter((id) => { const e = document.getElementById(id); return e && e.classList.contains('open'); }).join(','));
const tabNow = () => page.evaluate(() => [...document.querySelectorAll('[id^="tab-"]')].filter((e) => !e.classList.contains('is-hidden') && getComputedStyle(e).display !== 'none').map((e) => e.id).join(','));
const steps = [['30 days'], ['1 year'], ['90 days'], ['Refresh'], ['Generate report']];
for (const [label] of steps) {
  reqs.length = 0; await page.locator('#tab-dashboard button:has-text("' + label + '")').first().click().catch((e) => console.log(label, 'click-fail')); await page.waitForTimeout(1200);
  console.log(label.padEnd(16), '| overlay:', await ov(), '| reqs:', reqs.filter((r) => !r.startsWith('GET /ready')).slice(0, 4).join(' ; ').slice(0, 150));
  await page.evaluate(() => document.querySelectorAll('.overlay.open, .drawer-overlay.open').forEach((e) => e.classList.remove('open')));
}
const X = '#dash-view-executive ';
await page.locator(X + 'button:has-text("Generate report"), #hero-dash-exec button:has-text("Generate report")').first().click({ timeout: 3000 }).catch(() => console.log('generate-report: not found in exec view'));
await page.waitForTimeout(800); console.log('Generate report  | overlay:', await ov(), '| tab:', (await tabNow()).slice(0, 40));
await page.evaluate(() => document.querySelectorAll('.overlay.open, .drawer-overlay.open').forEach((e) => e.classList.remove('open')));
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'dashboard'); el && el.click(); }); await page.waitForTimeout(900);
await page.locator('#tab-dashboard button:has-text("Executive")').first().click().catch(() => {}); await page.waitForTimeout(1200);
const rows = page.locator(X + '[data-on-click]:visible');
const n = await rows.count(); console.log('visible clickables in executive view:', n);
for (let i = 0; i < Math.min(n, 14); i++) {
  const el = page.locator(X + '[data-on-click]:visible').nth(i); const act = await el.getAttribute('data-on-click'); const txt = ((await el.innerText().catch(() => '')) || '').replace(/s+/g, ' ').slice(0, 38);
  await el.click({ timeout: 2000 }).catch(() => {}); await page.waitForTimeout(700);
  console.log(' ', i, act, '|', txt, '| overlay:', await ov(), '| tab:', (await tabNow()).slice(0, 34));
  await page.evaluate(() => document.querySelectorAll('.overlay.open, .drawer-overlay.open').forEach((e) => e.classList.remove('open')));
  await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'dashboard'); el && el.click(); }); await page.waitForTimeout(700);
  await page.locator('#tab-dashboard button:has-text("Executive")').first().click().catch(() => {}); await page.waitForTimeout(900);
}
console.log('dialogs:', JSON.stringify(dialogs), '| errors:', JSON.stringify(errs));
await browser.close(); server.close();
