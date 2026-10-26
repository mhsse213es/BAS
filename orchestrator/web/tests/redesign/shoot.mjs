// Renders the built console (dist/) against a fixture set and writes one screenshot per tab.
//
//   node tests/redesign/shoot.mjs --out <dir> [--set rich|empty|error|smoke] [--theme dark|light|cyberpunk|slate]
//                                 [--width 1440] [--height 900] [--tabs a,b,c] [--full 1] [--dist dist]
//
// Prints one line per tab and exits non-zero if any page raised an error (apart from the HTTP 500s
// the `error` set injects on purpose). Run `node tools/build.mjs` first.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { mkdirSync } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';
import { fixtureSet } from './fixtures-rich.mjs';

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d; };
const out = resolve(arg('out', 'redesign-shots'));
const set = arg('set', 'rich');
const theme = arg('theme', 'dark');
const width = Number(arg('width', 1440));
const height = Number(arg('height', 900));
const only = arg('tabs', '') ? arg('tabs').split(',') : null;
const full = arg('full', '1') === '1';
const dist = resolve(arg('dist', 'dist'));
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

const fixtures = fixtureSet(set);
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width, height } })).newPage();
const errors = [];
const expect500 = set === 'error';
page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
page.on('console', (m) => { if (m.type() === 'error' && !(expect500 && /500/.test(m.text()))) errors.push(`console: ${m.text()}`); });
await page.addInitScript((t) => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', t); }, theme);
await page.route('**/*', (route) => {
  const u = new URL(route.request().url());
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) {
    if (!fixtures) return route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"internal error"}' });
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fixtures(route.request().method(), u)) });
  }
  if (u.hostname !== '127.0.0.1') return route.fulfill({ status: 204, body: '' });
  return route.continue();
});
await page.routeWebSocket(/\/ws\//, () => {});
await page.goto(`${origin}/index.html`);
await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none', null, { timeout: 15_000 });
await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => {});

const tabs = await page.$$eval('[data-on-click="showTab"]', (els) => [...new Set(els.map((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0]))].filter(Boolean).sort());
let bad = 0;
for (const tab of tabs) {
  if (only && !only.includes(tab)) continue;
  errors.length = 0;
  await page.evaluate((t) => {
    const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t);
    el.click();
  }, tab);
  await page.waitForTimeout(600);
  await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
  await page.screenshot({ path: join(out, `${tab}.png`), fullPage: full });
  if (errors.length) bad++;
  console.log(`${tab.padEnd(24)} ${errors.length ? 'ERRORS: ' + [...new Set(errors)].join(' | ').slice(0, 200) : 'ok'}`);
}
await browser.close();
server.close();
console.log(`${set}/${theme}/${width}px -> ${out}  (${bad} tab(s) with errors)`);
process.exit(bad ? 1 : 0);
