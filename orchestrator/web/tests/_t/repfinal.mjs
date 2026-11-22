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
const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 120)));
const opened = []; await page.context().on('page', (p) => opened.push(p.url()));
// a-1 gets six runs of three scenarios, so the "+ N more" line has something to count
await page.route('**/api/scenarios/runs', (r) => { const mk = (i, name, st, d) => ({ id: 'run-x' + i, agentId: 'a-1', name, status: st, completedAt: new Date(Date.now() - d * 3600e3).toISOString(),
  score: { totalTechniques: 6, passedTechniques: st === 'failed' ? 0 : 5, failedTechniques: st === 'failed' ? 0 : 1, erroredTechniques: st === 'failed' ? 6 : 0, skippedTechniques: 0 } });
  r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([mk(1, 'PowerShell Execution', 'completed', 1), mk(2, 'Credential Access', 'completed', 5), mk(3, 'Persistence', 'partial', 9), mk(4, 'PowerShell Execution', 'completed', 20), mk(5, 'Credential Access', 'failed', 30), mk(6, 'Persistence', 'completed', 40)]) }); });
const go = async (t) => { await page.evaluate((t) => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t); el && el.click(); }, t); await page.waitForTimeout(1500); };
await go('reports');
await page.locator('.rpt-agent').first().screenshot({ path: T + 'rep-06-more.png' });
console.log('first card text:', (await page.locator('.rpt-agent').first().innerText()).replace(/\n+/g, ' | ').slice(0, 330));
await go('compliance');
await page.locator('#cmp-agent-sel').selectOption({ index: 1 });
await page.locator('#cmp-fw-sel').selectOption({ index: 0 });
await page.locator('#tab-compliance button[data-on-click="loadComplianceReport"]').first().click(); await page.waitForTimeout(1800);
console.log('report shown:', await page.locator('#cmp-report').isVisible(), '| exports:', await page.evaluate(() => ['html','pdf','json','csv'].map((k) => getComputedStyle(document.getElementById('cmp-export-' + k)).display)));
await page.screenshot({ path: T + 'rep-07-cmp-report.png', fullPage: true });
const tabs = await page.locator('.cmp-ftab').allInnerTexts(); console.log('filter tabs:', tabs.join(' / '));
for (let i = 0; i < Math.min(tabs.length, 3); i++) { await page.locator('.cmp-ftab').nth(i).click(); await page.waitForTimeout(250); console.log(' tab', tabs[i].replace(/\s+/g, ' '), '-> rows', await page.locator('#cmp-controls-body tr').count()); }
await page.locator('.cmp-ftab').first().click(); await page.waitForTimeout(250);
console.log('toggle labels:', (await page.locator('.cmp-expand-btn').allInnerTexts()).slice(0,4).join(' | '));
await page.locator('.cmp-expand-btn').first().click(); await page.waitForTimeout(300);
console.log('after click:', (await page.locator('.cmp-expand-btn').first().innerText()), '| evidence visible:', await page.locator('.cmp-evidence.open').count());
await page.locator('.cmp-evidence.open').first().screenshot({ path: T + 'rep-08-evidence.png' }).catch(() => {});
console.log('errors:', JSON.stringify(errs));
await browser.close(); server.close();
