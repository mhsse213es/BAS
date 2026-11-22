import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';
import * as DG16 from './demo-g16.mjs';
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich');
const browser = await chromium.launch(); const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url()); const key = req.method() + ' ' + u.pathname;
  if (DG16.DEMO[key] !== undefined) { const v = typeof DG16.DEMO[key] === 'function' ? DG16.DEMO[key](u) : DG16.DEMO[key]; return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(v) }); }
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
  if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'ad-coverage'); el && el.click(); }); await page.waitForTimeout(2000);
console.log(JSON.stringify(await page.evaluate(() => {
  const s = document.querySelector('.adc-cap > summary'); const h = document.querySelector('.adc-head'); const d = document.querySelector('.adc-cap'); const dl = Math.round(d.getBoundingClientRect().left); const hl = Math.round(h.getBoundingClientRect().left); const sl = Math.round(s.getBoundingClientRect().left); const sp = getComputedStyle(s).paddingLeft; const hp = getComputedStyle(h).paddingLeft;
  const cs = (e) => e ? { display: getComputedStyle(e).display, cols: getComputedStyle(e).gridTemplateColumns } : null;
  const bf = getComputedStyle(s, '::before'); const mk = getComputedStyle(s, '::marker'); return { sm: getComputedStyle(s).marginLeft, dpad: getComputedStyle(d).paddingLeft, dmar: getComputedStyle(d).marginLeft, dbord: getComputedStyle(d).borderLeftWidth, before: [bf.content, bf.display, bf.width, bf.marginRight], marker: mk.content, dl, sl, hl, sp, hp, summary: cs(s), head: cs(h), summaryKids: s ? [...s.children].map((c) => Math.round(c.getBoundingClientRect().left)) : null, headKids: h ? [...h.children].map((c) => Math.round(c.getBoundingClientRect().left)) : null };
})));
await browser.close(); server.close();
