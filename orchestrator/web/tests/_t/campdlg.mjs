import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich'); const browser = await chromium.launch();
const posts = [];
async function fresh() {
  const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 140))); page.on('dialog', (d) => { errs.push('native dialog: ' + d.message().slice(0, 80)); d.dismiss(); });
  page.on('request', (q) => { if (q.method() === 'POST') posts.push(q.url().replace(origin, '')); });
  await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
  await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url());
    if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
  await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'campaigns'); el && el.click(); }); await page.waitForTimeout(1000);
  await page.evaluate(() => [...document.querySelectorAll('#tab-campaigns button')].find((b) => b.textContent.trim() === 'New campaign').click());
  await page.waitForTimeout(900);
  return { page, errs };
}
const dlgButtons = (p) => p.evaluate(() => [...document.querySelectorAll('#campaign-overlay button')].filter((b) => b.offsetParent && !b.disabled).map((b) => (b.textContent.trim() || b.getAttribute('aria-label') || b.title || '(icon)').slice(0, 40)));
const { page: p0 } = await fresh();
const names = await dlgButtons(p0);
console.log('dialog buttons:', JSON.stringify(names));
for (let i = 0; i < names.length; i++) {
  const { page, errs } = await fresh();
  const before = posts.length;
  const r = await page.evaluate((i) => { const b = [...document.querySelectorAll('#campaign-overlay button')].filter((x) => x.offsetParent && !x.disabled)[i]; if (!b) return 'missing'; b.click(); return 'clicked'; }, i);
  await page.waitForTimeout(800);
  const st = await page.evaluate(() => ({ open: [...document.querySelectorAll('.overlay.open,.drawer-overlay.open')].map((e) => e.id), toast: (document.getElementById('toast') || {}).textContent || '', alerts: [...document.querySelectorAll('#campaign-overlay [role=alert], #campaign-overlay .init-confirm, #campaign-overlay .aleef-error, #campaign-overlay .cmp-err, #campaign-overlay [class*=err]')].filter((e) => e.offsetParent && e.textContent.trim()).map((e) => e.textContent.trim().slice(0, 90)).slice(0, 2) }));
  console.log(JSON.stringify({ i, button: names[i], r, ...st, posts: posts.slice(before), errors: errs.slice(0, 2) }));
}
await browser.close(); server.close();
