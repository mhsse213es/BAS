// Read-only: real-flow overlay checks (open via the UI, then test keyboard, focus trap, ESC, fit in viewport).
//   node tests/redesign/overlays-flow.mjs --width 1440 --out dir
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { mkdirSync } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';
import { fixtureSet } from '../fixtures-rich.mjs';

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d; };
const out = resolve(arg('out', 'ov-out')); const width = Number(arg('width', 1440)); const height = width < 500 ? 844 : 900; const dist = resolve('dist');
mkdirSync(out, { recursive: true });
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const strip = new RegExp('^([/\\\\])+');
const server = createServer(async (req, res) => {
  const p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const file = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, ''));
  try { res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream' }).end(await readFile(file)); } catch { res.writeHead(404).end(); }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;
const fixtures = fixtureSet('rich');
const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width, height } })).newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(e.message));
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (route) => {
  const u = new URL(route.request().url());
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fixtures(route.request().method(), u)) });
  if (u.hostname !== '127.0.0.1') return route.fulfill({ status: 204, body: '' });
  return route.continue();
});
await page.routeWebSocket(/\/ws\//, () => {});
await page.goto(`${origin}/index.html`);
await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none', null, { timeout: 15000 }).catch(() => {});
await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});

const goTab = async (t) => { await page.evaluate((x) => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === x); if (el) el.click(); }, t); await page.waitForTimeout(700); };
const flows = [
  { name: 'agent-drawer', tab: 'agents', open: async () => page.locator('#tab-agents table tbody tr').first().click() },
  { name: 'deploy-agent', tab: 'agents', open: async () => page.getByRole('button', { name: /Deploy Agent/i }).first().click() },
  { name: 'finding-drawer', tab: 'findings', open: async () => page.locator('#tab-findings table tbody tr').first().click() },
  { name: 'run-scenario', tab: 'scenarios', open: async () => page.locator('#tab-scenarios button', { hasText: /^\s*Run\s*$/ }).first().click() },
  { name: 'generate-report', tab: 'reports', open: async () => page.getByRole('button', { name: /Generate report/i }).first().click() },
  { name: 'new-simulation', tab: 'dashboard', open: async () => page.getByRole('button', { name: /New simulation/i }).first().click() },
  { name: 'command-palette', tab: 'dashboard', open: async () => page.keyboard.press('Control+k') }
];
const results = [];
for (const f of flows) {
  const r = { flow: f.name, width }; errors.length = 0;
  try {
    await goTab(f.tab);
    await f.open(); await page.waitForTimeout(700);
    const info = await page.evaluate(() => {
      const vis = (e) => { const s = getComputedStyle(e); const b = e.getBoundingClientRect(); return s.display !== 'none' && s.visibility !== 'hidden' && b.width > 0 && b.height > 0; };
      const cands = [...document.querySelectorAll('.overlay.open .modal, .drawer-overlay.open .drawer, .drawer.open, .modal-overlay.open .modal, [role=dialog]')].filter(vis);
      const d = cands[cands.length - 1];
      if (!d) return { found: false };
      d.setAttribute('data-audit-dlg', '1');
      const b = d.getBoundingClientRect(); const focusables = d.querySelectorAll('button, a[href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
      return { found: true, cls: d.className.slice(0, 40), role: d.getAttribute('role'), modal: d.getAttribute('aria-modal'), label: d.getAttribute('aria-label') || (d.querySelector('h1,h2,h3') || {}).textContent || '', box: [Math.round(b.left), Math.round(b.top), Math.round(b.right), Math.round(b.bottom)], vw: innerWidth, vh: innerHeight, fitsX: b.left >= -1 && b.right <= innerWidth + 1, fitsY: b.top >= -1 && b.bottom <= innerHeight + 1, scrolls: d.scrollHeight > d.clientHeight + 2, focusables: focusables.length, activeInside: d.contains(document.activeElement), closeBtn: !!d.querySelector('[aria-label*=lose i], .modal-x, .drawer-close, button[data-on-click*=lose i]') };
    });
    Object.assign(r, info);
    if (!info.found) await page.screenshot({ path: join(out, `${f.name}-notfound.png`) });
    if (info.found) {
      await page.screenshot({ path: join(out, `${f.name}.png`) });
      // focus trap: tab many times, is focus ever outside the dialog?
      let escaped = 0;
      for (let i = 0; i < 30; i++) { await page.keyboard.press('Tab'); const inside = await page.evaluate(() => { const d = document.querySelector('[data-audit-dlg]'); return d ? d.contains(document.activeElement) : null; }); if (inside === false) escaped++; }
      r.tabEscapes = escaped;
      await page.keyboard.press('Escape'); await page.waitForTimeout(400);
      r.escCloses = await page.evaluate(() => { const d = document.querySelector('[data-audit-dlg]'); if (!d) return null; const b = d.getBoundingClientRect(); const cs = getComputedStyle(d); return b.width === 0 || cs.display === 'none' || cs.visibility === 'hidden'; });
    }
  } catch (e) { r.error = String(e.message).split('\n')[0].slice(0, 120); }
  r.pageErrors = [...new Set(errors)].slice(0, 2);
  results.push(r);
  // close anything left open so the next flow starts clean
  await page.evaluate(() => { document.querySelectorAll('[data-audit-dlg]').forEach((e) => e.removeAttribute('data-audit-dlg')); document.querySelectorAll('.overlay.open, .drawer-overlay.open').forEach((e) => e.classList.remove('open')); });
}
await writeFile(join(out, '_flows.json'), JSON.stringify(results, null, 1));
for (const r of results) console.log(JSON.stringify({ f: r.flow, found: r.found, fitsX: r.fitsX, fitsY: r.fitsY, scrolls: r.scrolls, role: r.role, modal: r.modal, label: (r.label || '').trim().slice(0, 24), tabEscapes: r.tabEscapes, escCloses: r.escCloses, activeInside: r.activeInside, err: r.error }));
await browser.close(); server.close();
