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
const T = 'C:/Users/Administrator/AppData/Local/Temp/';
const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 100)));
const dl = []; page.on('download', (d) => dl.push(d.suggestedFilename()));
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'threat-priority'); el && el.click(); }); await page.waitForTimeout(2200);
const P = '#tab-threat-priority ';
// Columns menu
await page.locator(P + 'button:has-text("Columns")').click(); await page.waitForTimeout(500);
await page.screenshot({ path: T + 'tp-s1-columns.png', clip: { x: 700, y: 480, width: 740, height: 320 } });
const boxes = await page.locator(P + '.dt-colmenu input[type=checkbox], ' + P + '[class*=colmenu] input').count(); console.log('column menu checkboxes:', boxes);
if (boxes) { await page.locator(P + '[class*=colmenu] input').nth(1).click(); await page.waitForTimeout(400); console.log('headers after hiding 2nd col:', (await page.locator(P + 'thead th').allInnerTexts()).join(' / ').replace(/\s+/g, ' ')); await page.locator(P + '[class*=colmenu] input').nth(1).click(); }
await page.keyboard.press('Escape'); await page.locator(P + 'h2, .rk-hd').first().click({ position: { x: 5, y: 5 } }).catch(() => {});
// bulk selection
await page.locator(P + 'tbody input[type=checkbox]').nth(0).check(); await page.locator(P + 'tbody input[type=checkbox]').nth(2).check(); await page.waitForTimeout(400);
await page.locator(P + '.rk-card').nth(0).screenshot({ path: T + 'tp-s2-selected.png' }).catch(() => {});
console.log('selection toolbar text:', (await page.locator(P + '[class*=sel], ' + P + '.dt-bulk').allInnerTexts()).join(' | ').replace(/\s+/g, ' ').slice(0, 120));
await page.locator(P + 'button:has-text("Export selected")').click().catch(() => console.log('no Export selected button')); await page.waitForTimeout(600);
console.log('downloads after export selected:', JSON.stringify(dl));
// empty tier
await page.locator(P + 'button:has-text("Critical")').first().click(); await page.waitForTimeout(500);
await page.locator(P + '.rk-card').nth(0).screenshot({ path: T + 'tp-s3-empty.png' }).catch(() => {});
// drawer lower part
await page.locator(P + 'button:has-text("All")').first().click(); await page.waitForTimeout(400);
await page.locator(P + 'tbody tr').first().click(); await page.waitForTimeout(800);
await page.evaluate(() => { const b = document.querySelector('#tp-detail-overlay [class*=body], #tp-detail-overlay .drawer-body, #tp-detail-overlay'); [...document.querySelectorAll('#tp-detail-overlay *')].forEach((e) => { if (e.scrollHeight > e.clientHeight + 20 && getComputedStyle(e).overflowY !== 'visible') e.scrollTop = e.scrollHeight; }); });
await page.waitForTimeout(400); await page.screenshot({ path: T + 'tp-s4-drawer-bottom.png' });
await page.locator('#tp-detail-overlay button:has-text("Close")').first().click(); await page.waitForTimeout(400);
console.log('drawer closed:', !(await page.evaluate(() => document.getElementById('tp-detail-overlay').classList.contains('open'))), '| errors:', JSON.stringify(errs));
await browser.close(); server.close();
