// Generic tab walker: node tests/_t/tabwalk.mjs <tab> <outDir> [walk|shot]
// Loads the real build, opens <tab> with the demo data, and clicks every visible control in turn.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises'; import { mkdirSync } from 'node:fs';
import { fixtureSet } from './fixtures-rich.mjs';
import * as DC from './demo-c.mjs';
import * as DG16 from './demo-g16.mjs';
import * as DG17 from './demo-g17.mjs';
import * as DG3 from './demo-g3.mjs';
import * as DG12 from './demo-g12.mjs';
import * as DG18 from './demo-g18.mjs';
import * as DG15 from './demo-g15.mjs';
const TAB = process.argv[2], OUT = resolve(process.argv[3]); mkdirSync(OUT, { recursive: true });
const DATA = { ...DC.DEMO, ...DG15.DEMO, ...(DG16.DEMO || {}), ...(DG17.DEMO || {}), ...(DG3.DEMO || {}), ...(DG12.DEMO || {}), ...(DG18.DEMO || {}) };
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich');
const browser = await chromium.launch();
const posts = [];
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
  await pg.evaluate((t) => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t); el && el.click(); }, TAB); await pg.waitForTimeout(2200);
  return { page: pg, errs };
}
const SEL = `#tab-${TAB} button, #tab-${TAB} input, #tab-${TAB} select, #tab-${TAB} [data-on-click]:not(button):not(input):not(select)`;
const label = (b) => (b.tagName === 'INPUT' ? 'input:' + (b.type || '') + ':' + (b.placeholder || b.id || b.value || '') : b.tagName === 'SELECT' ? 'select:' + b.id : (b.textContent.trim() || b.getAttribute('aria-label') || b.title || '(icon)')).replace(/\s+/g, ' ').slice(0, 40);
const { page: p0, errs: e0 } = await fresh();
const names = await p0.evaluate(([sel]) => [...document.querySelectorAll(sel)].filter((b) => b.offsetParent && !b.disabled).map((b) => b.tagName + '|' + (b.tagName === 'INPUT' ? 'input:' + (b.type||'') + ':' + (b.placeholder || b.id || b.value || '') : b.tagName === 'SELECT' ? 'select:' + b.id : (b.textContent.trim() || b.getAttribute('aria-label') || b.title || '(icon)')).replace(/\s+/g, ' ').slice(0, 40)), [SEL]);
if (process.env.SHOT) { await p0.screenshot({ path: join(OUT, TAB + '-full.png'), fullPage: true }); }
await p0.context().close();
console.log('controls:', names.length);
console.log(JSON.stringify(names));
const max = Number(process.env.MAX || names.length);
for (let i = 0; i < Math.min(names.length, max); i++) {
  const { page, errs } = await fresh(); const pc = posts.length;
  const before = await page.evaluate((t) => document.getElementById('tab-' + t).innerText, TAB);
  const r = await page.evaluate(([sel, i]) => { const b = [...document.querySelectorAll(sel)].filter((x) => x.offsetParent && !x.disabled)[i]; if (!b) return 'missing';
    if (b.tagName === 'INPUT' && (b.type === 'text' || b.type === 'search' || !b.type)) { b.focus(); b.value = 'a'; b.dispatchEvent(new Event('input', { bubbles: true })); return 'typed'; }
    if (b.tagName === 'INPUT' && b.type === 'checkbox') { b.click(); return 'toggled'; }
    if (b.tagName === 'INPUT' && b.type === 'radio') { b.click(); return 'selected'; }
    if (b.tagName === 'SELECT') { b.focus(); const o = b.options[b.options.length > 1 ? 1 : 0]; if (o) b.value = o.value; b.dispatchEvent(new Event('change', { bubbles: true })); return 'changed'; }
    b.click(); return 'clicked'; }, [SEL, i]);
  await page.waitForTimeout(900);
  const after = await page.evaluate((t) => document.getElementById('tab-' + t).innerText, TAB);
  const overlays = await page.evaluate(() => [...document.querySelectorAll('.modal.open, .drawer-overlay.open, [id$="-overlay"].open, [id$="-modal"]:not(.is-hidden), .modal-backdrop.open')].filter((e) => e.offsetParent !== null || getComputedStyle(e).display !== 'none').map((e) => e.id || e.className).slice(0, 3));
  const seen = new Set(before.split('\n')); const added = after.split('\n').filter((l) => l.trim() && !seen.has(l)).slice(0, 2).map((l) => l.trim().slice(0, 70));
  const toast = await page.evaluate(() => { const t = document.getElementById('toast'); return t && t.className.includes('show') ? t.textContent.trim().slice(0, 70) : ''; });
  console.log(JSON.stringify({ i, c: names[i].split('|').slice(1).join('|'), r, toast, overlays, added, posts: posts.slice(pc), errors: errs.slice(0, 2) }));
  await page.context().close();
}
await browser.close(); server.close();
