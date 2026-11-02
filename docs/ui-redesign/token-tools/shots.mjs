// Deterministic screenshots of every tab for before/after comparison.
//   node tests/_t/shots.mjs --out dir --theme dark --width 1440
const RealDate = Date; const FIXED = RealDate.parse('2026-11-01T12:00:00Z');
globalThis.Date = class extends RealDate { constructor(...a) { if (a.length === 0) super(FIXED); else super(...a); } static now() { return FIXED; } };
const { chromium } = await import('playwright-core');
const { createServer } = await import('node:http'); const { readFile } = await import('node:fs/promises'); const { mkdirSync } = await import('node:fs');
const { extname, join, normalize, resolve } = await import('node:path'); const { fixtureSet } = await import('./fixtures-rich.mjs');
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const out = resolve(arg('out', 'shots')); const theme = arg('theme', 'dark'); const width = Number(arg('width', 1440)); const height = width < 500 ? 844 : 900; const dist = resolve('dist');
mkdirSync(out, { recursive: true });
const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich');
const browser = await chromium.launch(); const ctx = await browser.newContext({ viewport: { width, height }, reducedMotion: 'reduce' }); const page = await ctx.newPage();
await page.clock.install({ time: FIXED }); await page.clock.setFixedTime(FIXED);
await page.addInitScript((t) => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', t); }, theme);
await page.route('**/*', (r) => { const u = new URL(r.request().url()); if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(r.request().method(), u)) }); if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(1200);
const tabs = (await page.$$eval('[data-on-click="showTab"]', (els) => [...new Set(els.map((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0]))].filter(Boolean).sort()));
for (const t of tabs) {
  await page.evaluate((x) => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === x); el && el.click(); }, t);
  await page.waitForTimeout(700); await page.waitForLoadState('networkidle', { timeout: 4000 }).catch(() => {});
  await page.screenshot({ path: join(out, t + '.png'), fullPage: true, animations: 'disabled' });
}
console.log(theme + '/' + width + ': ' + tabs.length + ' tabs -> ' + out);
await browser.close(); server.close();
