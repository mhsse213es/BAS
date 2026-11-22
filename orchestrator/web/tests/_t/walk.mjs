import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises'; import { mkdirSync, writeFileSync } from 'node:fs';
import { fixtureSet } from './fixtures-rich.mjs';
const TAB = process.argv[2]; const out = resolve(process.argv[3]); mkdirSync(out, { recursive: true });
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich');
const CAT = { scenarios: [ { id: 'aws-bucket', name: 'Bucket walk', provider: 'aws', description: 'Reads buckets', steps: [{}] }, { id: 'az-vault', name: 'Vault read', provider: 'azure', description: 'Reads vaults', steps: [{}, {}] } ] };
const browser = await chromium.launch();
async function fresh() {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } }); const page = await ctx.newPage();
  const errs = []; page.on('dialog', (d) => { errs.push('native dialog: ' + d.message().slice(0, 80)); d.dismiss(); }); page.on('pageerror', (e) => errs.push(e.message.slice(0, 120)));
  await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
  await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url());
    if (u.pathname === '/api/cloud-scenarios') return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(CAT) });
    if (u.pathname === '/api/cloud-runs' && req.method() === 'GET') return r.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
    if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
  await page.evaluate((t) => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t); el && el.click(); }, TAB); await page.waitForTimeout(1100);
  return { ctx, page, errs };
}
const LIST = () => { const root = document.getElementById('tab-' + window.__T); const vis = (e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0; }; return [...root.querySelectorAll('button')].filter((b) => vis(b) && !b.disabled).map((b, i) => (b.textContent.trim() || b.getAttribute('aria-label') || b.title || '(icon)').slice(0, 40)); };
const OPEN = process.argv[4] || ''; const SCOPE = process.argv[5] || '';
const { ctx: c0, page: p0 } = await fresh(); await p0.evaluate((t) => { window.__T = t; }, TAB);
const names = OPEN ? await (async () => { await p0.evaluate((sel) => { const e = document.querySelector(sel); e && e.click(); }, OPEN); await p0.waitForTimeout(700); return p0.evaluate((scope) => [...document.querySelectorAll(scope + ' button')].filter((b) => b.offsetParent && !b.disabled).map((b) => (b.textContent.trim() || b.getAttribute('aria-label') || b.title || '(icon)').slice(0, 40)), SCOPE); })() : await p0.evaluate((t) => { window.__T = t; const root = document.getElementById('tab-' + t); const vis = (e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0; }; return [...root.querySelectorAll('button')].filter((b) => vis(b) && !b.disabled).map((b) => (b.textContent.trim() || b.getAttribute('aria-label') || b.title || '(icon)').slice(0, 40)); }, TAB);
await c0.close();
const results = [];
for (let i = 0; i < names.length; i++) {
  const { ctx, page, errs } = await fresh();
  if (OPEN) await page.evaluate((sel) => { const e = document.querySelector(sel); e && e.click(); }, OPEN).then(() => page.waitForTimeout(700));
  const before = await page.evaluate((scope) => (document.querySelector(scope || '#tab-' + window.__T) || document.body).innerText, SCOPE || TAB);
  const r = await page.evaluate(([t, i, scope]) => { const root = scope ? document.querySelector(scope) : document.getElementById('tab-' + t); const vis = (e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0; }; const list = [...root.querySelectorAll('button')].filter((b) => vis(b) && !b.disabled); const b = list[i]; if (!b) return 'missing'; b.click(); return 'clicked'; }, [TAB, i, SCOPE]);
  await page.waitForTimeout(900);
  const state = await page.evaluate(() => {
    const open = [...document.querySelectorAll('.overlay.open, .drawer-overlay.open, .ph-scrim, #page-help')].map((e) => e.id || e.className.toString().slice(0, 30));
    const t = document.getElementById('toast'); const toast = t && t.className.includes('show') ? t.textContent.trim() : '';
    const alerts = [...document.querySelectorAll('[role="alert"], .u-danger, .init-dr-err, .init-confirm, [id$="-error"]')].filter((e) => e.offsetParent && e.textContent.trim()).map((e) => e.textContent.trim().slice(0, 90));
    return { open, toast, alerts: alerts.slice(0, 3) };
  });
  const after = await page.evaluate((scope) => (document.querySelector(scope || '#tab-' + window.__T) || document.body).innerText, SCOPE || TAB);
  const seen = new Set(before.split(String.fromCharCode(10))); const added = after.split(String.fromCharCode(10)).filter((l) => l.trim() && !seen.has(l)).slice(0, 4).map((l) => l.trim().slice(0, 100));
  const rec = { i, button: names[i], result: r, ...state, added, errors: errs.slice(0, 3) };
  results.push(rec); console.log(JSON.stringify(rec).slice(0, 380));
  await page.screenshot({ path: join(out, String(i).padStart(2, '0') + '.png') }).catch(() => {});
  await ctx.close();
}
writeFileSync(join(out, 'walk.json'), JSON.stringify(results, null, 1));
await browser.close(); server.close();
