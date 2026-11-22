import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich'); const browser = await chromium.launch(); const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url()); if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) }); if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(800);
const tabs = process.argv.slice(2);
for (const t of tabs) {
  if (t === 'profile') { await page.evaluate(() => { document.querySelector('#user-menu-btn, .user-avatar, [data-on-click="toggleUserMenu"]') && document.querySelector('#user-menu-btn, .user-avatar, [data-on-click="toggleUserMenu"]').click(); }); await page.waitForTimeout(300); await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find((x) => /Go to Profile/.test(x.textContent)); b && b.click(); }); await page.waitForTimeout(900); }
  const found = t === 'profile' ? true : await page.evaluate((t) => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t); if (!el) return false; el.click(); return true; }, t);
  await page.waitForTimeout(900);
  const cur = await page.evaluate(() => { const el = document.querySelector('main > [id^="tab-"]:not(.is-hidden)'); return el ? el.id : '(none)'; });
  if (t === 'initiatives') console.log(JSON.stringify(await page.evaluate(() => [...document.querySelectorAll('[id^="tab-"]')].filter((e) => !e.classList.contains('is-hidden')).map((e) => e.id + '@' + e.parentElement.tagName + '.' + e.parentElement.id))));
  await page.click('#page-help-btn'); await page.waitForTimeout(300);
  const info = await page.evaluate(() => ({ title: (document.getElementById('ph-title') || {}).textContent, about: ((document.querySelector('.ph-about p') || {}).textContent || '').slice(0, 70) }));
  console.log(found, t.padEnd(18), 'current=' + cur.padEnd(24), 'title=' + info.title, '|', info.about);
  await page.evaluate(() => document.querySelector('.ph-close') && document.querySelector('.ph-close').click()); await page.waitForTimeout(150);
}
await browser.close(); server.close();
