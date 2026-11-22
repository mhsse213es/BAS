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
const fx = fixtureSet('rich'); const DATA = { ...A, ...G14, 'GET /api/attack/technique/T1566': { id: 'T1566', name: 'Phishing', tactics: ['initial-access'], platforms: ['Windows', 'Linux', 'macOS'], groups: ['APT29', 'FIN7', 'Lazarus Group'], dataSources: ['Application Log: Application Log Content', 'Network Traffic: Network Traffic Content', 'Email Gateway'], description: 'Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering.', url: 'https://attack.mitre.org/techniques/T1566/' } };
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 140)));
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url()); const key = req.method() + ' ' + u.pathname;
  if (DATA[key] !== undefined) { const v = typeof DATA[key] === 'function' ? DATA[key](u) : DATA[key]; return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(v) }); }
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
  if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'coverage'); el && el.click(); }); await page.waitForTimeout(2000);
// 1. technique drawer
await page.locator('#utl-body tr.cov-row').first().click(); await page.waitForTimeout(1200);
await page.locator('#cov-drawer-overlay .drawer').first().screenshot({ path: join(out, 'drawer.png') }).catch((e) => console.log('drawer shot', e.message.slice(0, 80)));
const drawerInfo = await page.evaluate(() => { const d = document.querySelector('#cov-drawer-overlay .drawer'); return d ? { hasStyle: getComputedStyle(d).backgroundColor, kv: !!d.querySelector('.rk-kv, .kv, dl'), text: d.innerText.slice(0, 160).replace(/\n+/g, ' | ') } : null; });
console.log('drawer', JSON.stringify(drawerInfo));
await page.evaluate(() => closeCovDrawerSafe()).catch(() => {});
await page.keyboard.press('Escape'); await page.waitForTimeout(300);
await page.evaluate(() => { const o = document.getElementById('cov-drawer-overlay'); o && o.classList.remove('open'); });
// 2. run dialog from Test coverage gaps
await page.locator('button', { hasText: 'Test coverage gaps' }).first().click(); await page.waitForTimeout(1200);
const run = await page.evaluate(() => { const o = document.getElementById('run-overlay'); if (!o) return null; const r = o.getBoundingClientRect(); return { open: o.classList.contains('open'), w: r.width, h: r.height, text: o.innerText.slice(0, 200).replace(/\n+/g, ' | ') }; });
console.log('run', JSON.stringify(run));
await page.locator('#run-overlay .modal, #run-overlay .drawer, #run-overlay > div').first().screenshot({ path: join(out, 'run-overlay.png') }).catch((e) => console.log('run shot', e.message.slice(0, 80)));
console.log(JSON.stringify({ errors: errs.slice(0, 3) }));
await browser.close(); server.close();
