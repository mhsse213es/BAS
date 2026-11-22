import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises'; import { mkdirSync } from 'node:fs';
import { fixtureSet } from './fixtures-rich.mjs';
import * as DC from './demo-c.mjs';
import * as DG15 from './demo-g15.mjs';
const OUT = resolve(process.argv[2]); mkdirSync(OUT, { recursive: true });
const DATA = { ...DC.DEMO, ...DG15.DEMO };
const RESULTS = [
  { taskId: 't1', encoding: 'base64', execContext: 'user', evasion: 'none', riskLevel: 'high', verdict: 'ALLOWED' },
  { taskId: 't2', encoding: 'base64', execContext: 'admin', evasion: 'amsi', riskLevel: 'high', verdict: 'PREVENTED' },
  { taskId: 't3', encoding: 'xor', execContext: 'user', evasion: 'none', riskLevel: 'medium', verdict: 'PREVENTED' },
  { taskId: 't4', encoding: 'xor', execContext: 'system', evasion: 'amsi', riskLevel: 'low', verdict: 'ERROR' },
];
const DETAIL = { run: { status: 'completed', techniqueId: 'T1003.001', scenarioRunId: 'sr-1', cleanupStatus: 'ok' }, results: RESULTS, summary: { total: 4, prevented: 2, allowed: 1, pending: 0, firstBypass: 'LSASS Memory: base64 / user / none', firstBypassRisk: 'high' }, stepsDone: 4 };
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich');
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url()); const key = req.method() + ' ' + u.pathname;
  if (key === 'POST /api/variants/run') return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ scenarioRunId: 'sr-1', variantRunId: 'vr-1', totalVariants: 56 }) });
  if (u.pathname === '/api/variants/run/vr-1') return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(DETAIL) });
  if (DATA[key] !== undefined) { const v = typeof DATA[key] === 'function' ? DATA[key](u) : DATA[key]; return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(v) }); }
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
  if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'variants'); el && el.click(); }); await page.waitForTimeout(2000);
const agents = await page.evaluate(() => [...document.querySelectorAll('#vex-agent option')].map((o) => o.value).filter(Boolean));
await page.selectOption('#vex-agent', agents[0]); await page.waitForTimeout(200);
await page.locator('#vex-tech-list input[type=checkbox], input[type=checkbox][id^="vex-tech"]').first().check().catch(async () => { await page.locator('label:has-text("T1003.001") input').first().check(); });
await page.locator('#vex-run-btn').click();
await page.waitForTimeout(4500);
await page.locator('#vex-result-panel').first().screenshot({ path: join(OUT, 'result-panel.png') }).catch((e) => console.log('panel shot', e.message.slice(0, 80)));
const txt = await page.evaluate(() => (document.getElementById('vex-result-panel') || {}).innerText || '');
console.log(JSON.stringify({ agent: agents[0], panel: txt.slice(0, 300).replace(/\n+/g, ' | '), errors: errs.slice(0, 3) }));
await browser.close(); server.close();
