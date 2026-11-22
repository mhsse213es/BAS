import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises'; import { mkdirSync } from 'node:fs';
import { fixtureSet } from './fixtures-rich.mjs';
import { DEMO as G14 } from './demo-g14.mjs';
import { DEMO as A } from './demo-a.mjs';
const out = resolve(process.argv[2]); mkdirSync(out, { recursive: true });
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich'); const DATA = { ...A, ...G14 };
const browser = await chromium.launch();
const posts = []; let nonGet = [];
async function fresh() {
  const pg = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  const errs = []; pg.on('pageerror', (e) => errs.push(e.message.slice(0, 140))); pg.on('dialog', (d) => { errs.push('dialog:' + d.message().slice(0, 60)); d.dismiss(); });
  pg.on('request', (q) => { if (q.method() !== 'GET') posts.push(q.method() + ' ' + q.url().replace(origin, '')); });
  await pg.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
  await pg.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url()); const key = req.method() + ' ' + u.pathname;
    if (DATA[key] !== undefined) { const v = typeof DATA[key] === 'function' ? DATA[key](u) : DATA[key]; return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(v) }); }
    if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
  await pg.routeWebSocket(/ws/, () => {});
  await pg.goto(origin + '/index.html'); await pg.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await pg.waitForTimeout(700);
  await pg.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'coverage'); el && el.click(); }); await pg.waitForTimeout(2000);
  return { page: pg, errs };
}
const SEL = '#tab-coverage button, #tab-coverage input, #tab-coverage select, #tab-coverage [data-on-click]:not(button)';
const names = await (await fresh()).page.evaluate((sel) => [...document.querySelectorAll(sel)].filter((b) => b.offsetParent && !b.disabled).map((b) => (b.tagName === 'INPUT' ? 'input:' + (b.placeholder || b.id) : b.tagName === 'SELECT' ? 'select:' + b.id : (b.textContent.trim() || b.getAttribute('aria-label') || b.title || '(icon)')).replace(/\s+/g, ' ').slice(0, 36)), SEL);
console.log('controls:', names.length, JSON.stringify(names));
for (let i = 0; i < names.length; i++) {
  const { page, errs } = await fresh(); const pc = posts.length;
  const before = await page.evaluate(() => document.getElementById('tab-coverage').innerText);
  const r = await page.evaluate(([sel, i]) => { const b = [...document.querySelectorAll(sel)].filter((x) => x.offsetParent && !x.disabled)[i]; if (!b) return 'missing';
    if (b.tagName === 'INPUT' && b.type === 'text') { b.focus(); b.value = 'T1'; b.dispatchEvent(new Event('input', { bubbles: true })); return 'typed'; }
    if (b.tagName === 'SELECT') { b.focus(); const o = b.options[b.options.length > 1 ? 1 : 0]; b.value = o.value; b.dispatchEvent(new Event('change', { bubbles: true })); return 'changed'; }
    b.click(); return 'clicked'; }, [SEL, i]);
  await page.waitForTimeout(900);
  const after = await page.evaluate(() => document.getElementById('tab-coverage').innerText);
  const overlays = await page.evaluate(() => [...document.querySelectorAll('.modal.open, .modal-backdrop.open, .drawer-overlay.open, .cov-drawer.open, [class*=drawer].open, [class*=overlay].open')].map((e) => e.id || e.className).slice(0, 3));
  const seen = new Set(before.split('\n')); const added = after.split('\n').filter((l) => l.trim() && !seen.has(l)).slice(0, 2).map((l) => l.trim().slice(0, 70));
  const toast = await page.evaluate(() => { const t = document.getElementById('toast'); return t && t.className.includes('show') ? t.textContent.trim().slice(0, 70) : ''; });
  console.log(JSON.stringify({ i, c: names[i], r, toast, overlays, added, posts: posts.slice(pc), errors: errs.slice(0, 2) }));
  await page.context().close();
}
await browser.close(); server.close();
