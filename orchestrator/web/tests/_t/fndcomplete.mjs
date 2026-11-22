import { chromium } from 'playwright-core'; import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs'; import * as DC from './demo-c.mjs'; import * as DG15 from './demo-g15.mjs'; import * as DG16 from './demo-g16.mjs'; import * as DG17 from './demo-g17.mjs'; import * as DG3 from './demo-g3.mjs'; import * as DG12 from './demo-g12.mjs'; import * as DG18 from './demo-g18.mjs';
const DATA = { ...DC.DEMO, ...DG15.DEMO, ...(DG16.DEMO || {}), ...(DG17.DEMO || {}), ...(DG3.DEMO || {}), ...(DG12.DEMO || {}), ...(DG18.DEMO || {}) };
const dist = resolve('dist'); const strip = new RegExp('^[/]+'); const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich'); const browser = await chromium.launch(); const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
const shots = [];
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url()); const key = req.method() + ' ' + u.pathname;
  if (DATA[key] !== undefined) { const v = typeof DATA[key] === 'function' ? DATA[key](u) : DATA[key]; return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(v) }); }
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
  if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'findings'); el && el.click(); }); await page.waitForTimeout(1500);

// 1. Page overview
shots.push({ name: 'fnd-01-page-full', desc: 'Full Findings page' }); await page.screenshot({ path: 'C:/Users/Administrator/AppData/Local/Temp/fnd-01-page-full.png', fullPage: false });

// 2. Click a finding to open the drawer
await page.locator('#tab-findings tbody tr').first().click(); await page.waitForTimeout(600);
shots.push({ name: 'fnd-02-drawer-open', desc: 'Finding row clicked, overlay drawer opened' }); await page.screenshot({ path: 'C:/Users/Administrator/AppData/Local/Temp/fnd-02-drawer-open.png', fullPage: false });

// 3. Close drawer, then try risk accept
await page.keyboard.press('Escape'); await page.waitForTimeout(300);
await page.locator('#tab-findings tbody tr').nth(1).locator('select.triage-sel').selectOption('risk_accepted'); await page.waitForTimeout(500);
shots.push({ name: 'fnd-03-risk-modal', desc: 'Risk accept confirmation modal' }); await page.screenshot({ path: 'C:/Users/Administrator/AppData/Local/Temp/fnd-03-risk-modal.png', fullPage: false });

// 4. Close modal via Cancel
await page.locator('#confirm-diff-overlay button:has-text("Cancel")').click(); await page.waitForTimeout(300);

// 5. Try export
await page.locator('button:has-text("Export")').first().click(); await page.waitForTimeout(400);
shots.push({ name: 'fnd-04-export-toast', desc: 'Export button clicked (check for toast)' }); await page.screenshot({ path: 'C:/Users/Administrator/AppData/Local/Temp/fnd-04-export-toast.png', fullPage: false });

// 6. Try a status filter to show the filtered list
await page.locator('#tab-findings button:has-text("Critical")').click(); await page.waitForTimeout(400);
shots.push({ name: 'fnd-05-severity-filter', desc: 'Critical severity filter applied' }); await page.screenshot({ path: 'C:/Users/Administrator/AppData/Local/Temp/fnd-05-severity-filter.png', fullPage: false });

console.log('Shots captured:'); shots.forEach((s) => console.log(`  ${s.name}: ${s.desc}`));
await browser.close(); server.close();
