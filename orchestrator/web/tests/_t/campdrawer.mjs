import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises'; import { mkdirSync } from 'node:fs';
import { fixtureSet } from './fixtures-rich.mjs';
const out = resolve(process.argv[2]); mkdirSync(out, { recursive: true });
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich'); const browser = await chromium.launch();
async function fresh() {
  const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 140))); page.on('dialog', (d) => { errs.push('native dialog: ' + d.message().slice(0, 80)); d.dismiss(); });
  await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
  await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url());
    if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
  await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'campaigns'); el && el.click(); }); await page.waitForTimeout(1000);
  await page.evaluate(() => [...document.querySelectorAll('#tab-campaigns button')].find((b) => b.textContent.includes('View per-agent breakdown')).click());
  await page.waitForTimeout(900);
  return { page, errs };
}
const list = async () => (await fresh()).page.evaluate(() => [...document.querySelectorAll('#cmp-drawer-overlay button')].filter((b) => b.offsetParent && !b.disabled).map((b) => (b.textContent.trim() || b.getAttribute('aria-label') || b.title || '(icon)').slice(0, 40)));
const posts = [];
async function flow(label, fn) {
  const { page, errs } = await fresh();
  page.on('request', (q) => { if (q.method() === 'POST') posts.push(q.url().replace(origin, '')); });
  await fn(page);
  await page.waitForTimeout(700);
  const st = await page.evaluate(() => ({ bar: !!document.getElementById('cmp-stop-confirm'), barText: (document.getElementById('cmp-stop-confirm') || {}).innerText || '', open: [...document.querySelectorAll('.overlay.open, .drawer-overlay.open')].map((e) => e.id), toast: (document.getElementById('toast') || {}).textContent || '' }));
  console.log(JSON.stringify({ label, ...st, posts: posts.splice(0), errors: errs.slice(0, 2) }));
  return page;
}
const clickIn = (sel, text) => (page) => page.evaluate(([sel, text]) => { const b = [...document.querySelectorAll(sel)].find((x) => x.offsetParent && x.textContent.trim() === text); if (!b) throw new Error('no ' + text); b.click(); }, [sel, text]);
await flow('stop: open confirm', clickIn('#cmp-drawer-foot button, #cmp-drawer-overlay button', 'Stop campaign'));
await flow('stop: keep running', async (p) => { await clickIn('#cmp-drawer-foot button, #cmp-drawer-overlay button', 'Stop campaign')(p); await p.waitForTimeout(300); await clickIn('#cmp-stop-confirm button, #cmp-drawer-overlay button', 'Keep running')(p); });
await flow('stop: confirm', async (p) => { await clickIn('#cmp-drawer-foot button, #cmp-drawer-overlay button', 'Stop campaign')(p); await p.waitForTimeout(300); await clickIn('#cmp-stop-confirm button, #cmp-drawer-overlay button', 'Stop campaign')(p); });
await flow('results: first run', async (p) => { await clickIn('#cmp-drawer-overlay button', 'Results →')(p); });
const names = await list();
console.log('drawer buttons:', JSON.stringify(names));
for (let i = 0; i < names.length; i++) {
  const { page, errs } = await fresh();
  const before = await page.evaluate(() => document.getElementById('cmp-drawer-overlay').innerText);
  const r = await page.evaluate((i) => { const b = [...document.querySelectorAll('#cmp-drawer-overlay button')].filter((x) => x.offsetParent && !x.disabled)[i]; if (!b) return 'missing'; b.click(); return 'clicked'; }, i);
  await page.waitForTimeout(900);
  const after = await page.evaluate(() => document.getElementById('cmp-drawer-overlay').innerText);
  const seen = new Set(before.split(String.fromCharCode(10)));
  const added = after.split(String.fromCharCode(10)).filter((l) => l.trim() && !seen.has(l)).slice(0, 4).map((l) => l.trim().slice(0, 100));
  const toast = await page.evaluate(() => { const t = document.getElementById('toast'); return t && t.className.includes('show') ? t.textContent.trim() : ''; });
  console.log(JSON.stringify({ i, button: names[i], r, toast, added, errors: errs.slice(0, 2) }));
  await page.locator('#cmp-drawer-overlay').screenshot({ path: join(out, String(i).padStart(2, '0') + '.png') }).catch(() => {});
}
await browser.close(); server.close();
