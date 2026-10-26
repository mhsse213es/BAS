// Lists, per tab, the API endpoints the page calls and what the rich fixtures answer, so gaps in the
// demo data are visible: UNMATCHED = fell through to {}, HOSTILE = smoke XSS placeholder text.
//   node tests/redesign/probe-endpoints.mjs [--set rich]
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import { fixtureSet } from './fixtures-rich.mjs';
import { FIXTURES } from '../smoke/fixtures.mjs';

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d; };
const dist = resolve('dist');
const fixtures = fixtureSet(arg('set', 'rich'));
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (req, res) => {
  const p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const file = join(dist, normalize(p === '/' ? '/index.html' : p).replace(/^([/\\])+/, ''));
  try { res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream' }).end(await readFile(file)); } catch { res.writeHead(404).end(); }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); });
let current = 'boot';
const seen = {};
await page.route('**/*', (route) => {
  const u = new URL(route.request().url());
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) {
    const key = `${route.request().method()} ${u.pathname}`;
    const body = fixtures(route.request().method(), u);
    const json = JSON.stringify(body);
    const known = Object.prototype.hasOwnProperty.call(FIXTURES, key);
    const status = json === '{}' ? 'UNMATCHED' : json.includes('img src=x') ? 'HOSTILE' : 'ok';
    ((seen[current] ||= {})[key] = status === 'ok' && known && !arg('quiet', '') ? 'ok' : status);
    return route.fulfill({ status: 200, contentType: 'application/json', body: json });
  }
  if (u.hostname !== '127.0.0.1') return route.fulfill({ status: 204, body: '' });
  return route.continue();
});
await page.routeWebSocket(/\/ws\//, () => {});
await page.goto(`${origin}/index.html`);
await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none', null, { timeout: 15_000 });
await page.waitForLoadState('networkidle').catch(() => {});
const tabs = await page.$$eval('[data-on-click="showTab"]', (els) => [...new Set(els.map((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0]))].filter(Boolean).sort());
for (const t of tabs) {
  current = t;
  await page.evaluate((n) => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === n); if (el) el.click(); }, t);
  await page.waitForTimeout(500);
}
for (const [tab, eps] of Object.entries(seen)) {
  const bad = Object.entries(eps).filter(([, s]) => s !== 'ok');
  if (bad.length) console.log(`${tab}\n${bad.map(([k, s]) => `   ${s.padEnd(9)} ${k}`).join('\n')}`);
}
await browser.close();
server.close();
