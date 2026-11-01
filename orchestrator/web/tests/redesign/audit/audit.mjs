// Visual-audit driver (read-only): renders every tab of dist/ against a fixture set and records DOM metrics + screenshots.
//   node tests/redesign/audit.mjs --set rich|empty|error --theme dark|light|cyberpunk|slate --width 1440 --out dir [--full 1] [--tabs a,b]
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { mkdirSync } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';
import { fixtureSet } from '../fixtures-rich.mjs';

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d; };
const out = resolve(arg('out', 'audit-out')); const set = arg('set', 'rich'); const theme = arg('theme', 'dark');
const width = Number(arg('width', 1440)); const height = Number(arg('height', width < 500 ? 844 : 900));
const only = arg('tabs', '') ? arg('tabs').split(',') : null; const full = arg('full', '0') === '1'; const dist = resolve('dist');
mkdirSync(out, { recursive: true });
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (req, res) => {
  const p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const file = join(dist, normalize(p === '/' ? '/index.html' : p).replace(/^([/\\])+/, ''));
  if (!file.startsWith(dist)) { res.writeHead(403).end(); return; }
  try { res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream' }).end(await readFile(file)); } catch { res.writeHead(404).end(); }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;
// errauth = signed-in session (boot endpoints succeed) where every DATA endpoint returns 500 -> true per-page error states.
const AUTH_OK = new Set(['/ready', '/api/license/status', '/api/me', '/api/me/permissions', '/api/agents']);
const fixtures = fixtureSet(set === 'errauth' ? 'rich' : set);
const forceFail = (u) => set === 'errauth' && !AUTH_OK.has(u.pathname);
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width, height } })).newPage();
const errors = []; const failed = [];
page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
page.on('console', (m) => { if (m.type() === 'error') errors.push(`console: ${m.text().slice(0, 160)}`); });
await page.addInitScript((t) => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', t); }, theme);
await page.route('**/*', (route) => {
  const u = new URL(route.request().url());
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) {
    if (!fixtures || forceFail(u)) { failed.push(u.pathname); const fs = Number(arg('failstatus', 500)); return route.fulfill({ status: fs, contentType: 'application/json', body: fs === 403 ? '{"error":"forbidden"}' : '{"error":"internal error"}' }); }
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fixtures(route.request().method(), u)) });
  }
  if (u.hostname !== '127.0.0.1') return route.fulfill({ status: 204, body: '' });
  return route.continue();
});
await page.routeWebSocket(/\/ws\//, () => {});
await page.goto(`${origin}/index.html`);
await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none', null, { timeout: 15_000 }).catch(() => {});
await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => {});

const navTabs = await page.$$eval('[data-on-click="showTab"]', (els) => [...new Set(els.map((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0]))].filter(Boolean).sort());
const tabs = [...navTabs, 'profile'];
const metricsFn = (tab) => {
  const vis = (e) => { const r = e.getBoundingClientRect(); const cs = getComputedStyle(e); return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
  const pane = document.getElementById('tab-' + tab) || document.querySelector('main') || document.body;
  const parse = (s) => (s.match(/[\d.]+/g) || []).map(Number);
  const bgOf = (el) => { while (el) { const c = parse(getComputedStyle(el).backgroundColor); if (c.length >= 3 && (c[3] === undefined || c[3] > 0.85)) return c; el = el.parentElement; } return [8, 13, 24]; };
  const L = (c) => { const [r, g, b] = c.slice(0, 3).map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
  let low = 0, lowEx = ''; const walk = document.createTreeWalker(pane, NodeFilter.SHOW_TEXT); let n, texts = 0;
  while ((n = walk.nextNode())) {
    const t = n.textContent.trim(); if (!t) continue; const el = n.parentElement; if (!el || !vis(el)) continue; texts++;
    const cs = getComputedStyle(el); const pc = parse(cs.color); if ((pc[3] !== undefined && pc[3] < 0.5) || /transparent|rgba\(0, 0, 0, 0\)/.test(cs.webkitTextFillColor || '')) continue; const a = L(pc); const b = L(bgOf(el)); const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    const big = parseFloat(cs.fontSize) >= 18.66 || (parseFloat(cs.fontSize) >= 14 && +cs.fontWeight >= 700);
    if (ratio < (big ? 3 : 4.5)) { low++; if (!lowEx) lowEx = `${t.slice(0, 22)} ${ratio.toFixed(2)}`; }
  }
  const interactive = [...pane.querySelectorAll('button, a[href], [role=button], input, select, textarea, [data-on-click]')].filter(vis);
  const noName = interactive.filter((e) => !(e.textContent || '').trim() && !e.getAttribute('aria-label') && !e.getAttribute('title') && !e.getAttribute('aria-labelledby') && !(e.labels && e.labels.length) && !e.getAttribute('placeholder') && e.type !== 'hidden');
  const small = interactive.filter((e) => { const r = e.getBoundingClientRect(); return r.height < 24 || r.width < 24; });
  const maxRight = Math.max(0, ...[...pane.querySelectorAll('*')].filter(vis).map((e) => e.getBoundingClientRect().right));
  const titleEls = [...document.querySelectorAll('.header-page-title, #page-title, h1')].filter(vis).map((e) => e.textContent.trim());
  const crumb = (document.querySelector('.breadcrumb, #breadcrumb, nav[aria-label=Breadcrumb]') || {}).textContent;
  const empties = [...pane.querySelectorAll('*')].filter((e) => vis(e) && e.children.length === 0 && /^(No |Nothing |Loading|Failed|Error|Unable|Could not)/i.test((e.textContent || '').trim())).map((e) => e.textContent.trim().slice(0, 60));
  return {
    tab, overflowDoc: document.documentElement.scrollWidth > innerWidth + 1, overflowPx: Math.round(Math.max(0, document.documentElement.scrollWidth - innerWidth)), maxRight: Math.round(maxRight), vw: innerWidth,
    titles: titleEls.slice(0, 4), crumb: (crumb || '').replace(/\s+/g, ' ').trim().slice(0, 60),
    selects: [...pane.querySelectorAll('select')].filter(vis).length, searches: [...pane.querySelectorAll('input[type=search], input[placeholder*="earch"], input[placeholder*="ilter"]')].filter(vis).length,
    tables: [...pane.querySelectorAll('table')].filter(vis).length, noName: noName.length, small: small.length, interactive: interactive.length,
    lowContrast: low, lowEx, texts, empties: [...new Set(empties)].slice(0, 4),
    loginVisible: !!document.getElementById('login-screen') && vis(document.getElementById('login-screen')), sidebarVisible: !!document.querySelector('.sidebar, #sidebar') && vis(document.querySelector('.sidebar, #sidebar')),
    paneVisible: vis(pane), badText: (pane.innerText.match(/undefined|NaN|\[object|null/g) || []).length, badCtx: ((pane.innerText.match(/.{0,25}(undefined|NaN|\[object).{0,15}/) || [''])[0]).replace(/\s+/g,' ')
  };
};
const rows = [];
for (const tab of tabs) {
  if (only && !only.includes(tab)) continue;
  errors.length = 0; failed.length = 0;
  if (tab === 'profile') { await page.evaluate(() => { const a = document.querySelector('#user-avatar, .user-avatar, [data-on-click="toggleUserMenu"]'); if (a) a.click(); }); }
  await page.evaluate((t) => { const el = t === 'profile' ? document.querySelector('[data-on-click="goToProfileFromMenu"]') : [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t); if (el) el.click(); }, tab);
  await page.waitForTimeout(500); await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
  await page.screenshot({ path: join(out, `${tab}.png`), fullPage: full });
  const m = await page.evaluate(metricsFn, tab); m.errors = [...new Set(errors)].slice(0, 3); m.failedApi = [...new Set(failed)].length;
  rows.push(m);
}
await writeFile(join(out, '_metrics.json'), JSON.stringify({ set, theme, width, tabs: rows }, null, 1));
await browser.close(); server.close();
console.log(`${set}/${theme}/${width}: ${rows.length} tabs, overflow ${rows.filter((r) => r.overflowDoc).length}, errors ${rows.filter((r) => r.errors.length).length}, lowContrast ${rows.filter((r) => r.lowContrast).length}`);
