// Dummy backend for the Recommendations page.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';
const TACTICS = ['Credential Access', 'Persistence', 'Defense Evasion', 'Lateral Movement', 'Impact', 'Execution'];
const NAMES = ['OS Credential Dumping', 'Scheduled Task/Job', 'Impair Defenses', 'Remote Services', 'Data Encrypted for Impact', 'PowerShell'];
const mk = (i) => ({ techniqueId: i === 7 ? 'CUSTOM-7' : 'T' + (1003 + i * 13), name: NAMES[i % 6] + (i > 5 ? ' (' + i + ')' : ''), tactic: TACTICS[i % 6], score: Math.max(8, 98 - i * 3), tier: i < 4 ? 'Critical' : i < 9 ? 'High' : i < 15 ? 'Medium' : 'Low', coverageState: ['never-tested', 'stale', 'recent'][i % 3], kev: i % 4 === 0, epssPercentile: i % 3 === 0 ? 90 - i : 0, threatActors: i % 5, environmentRisk: i % 4 === 1 ? 40 + i : 0, reasons: ['Used by ' + (i % 5) + ' tracked groups', 'Not tested in 90 days'].slice(0, 1 + (i % 2)) });
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
export async function boot(opts = {}) {
  const dist = resolve('dist'), strip = new RegExp('^[/]+');
  const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': TYPES[extname(f)] || 'application/octet-stream' }).end(d); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const fx = fixtureSet('rich');
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: opts.viewport || { width: 1440, height: 900 }, acceptDownloads: true, permissions: opts.noclip ? [] : ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  const state = { fail: {}, status: {}, reqs: [], total: opts.n == null ? 50 : opts.n };
  const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
  await page.addInitScript((r) => { localStorage.setItem('bas_role', r); localStorage.setItem('audspect_theme', 'dark'); }, opts.role || 'admin');
  const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/*', async (r) => {
    const req = r.request(), u = new URL(req.url()), path = u.pathname;
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' });
    if (!path.startsWith('/api/recommend') && !path.startsWith('/api/attack/technique')) { if (path === '/ready' || path.startsWith('/api/')) return json(r, fx(req.method(), u)); return r.continue(); }
    state.reqs.push(path + u.search);
    const fk = Object.keys(state.fail).find((k) => path.includes(k));
    if (fk) return json(r, { error: state.fail[fk] }, state.status[fk] || 500);
    if (path.startsWith('/api/attack/technique')) return json(r, { name: 'Technique detail', tactics: ['credential-access'], platforms: ['Windows'], groups: ['APT29'], description: 'Adversaries may attempt something.', url: 'https://attack.mitre.org/techniques/T1003/' });
    const lim = Number(u.searchParams.get('limit')) || 20; const n = Math.min(lim, state.total);
    const t = Array.from({ length: n }, (_, i) => mk(i));
    return json(r, { techniques: t, suggestedScenario: { artTechniques: t.filter((x) => /^T\d/.test(x.techniqueId)).slice(0, 8).map((x) => x.techniqueId) } });
  });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none');
  await page.waitForTimeout(700);
  const go = async () => { await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'recommendations'); el && el.click(); }); await page.waitForTimeout(1600); };
  const toast = () => page.evaluate(() => { const e = document.getElementById('toast'); return e ? (e.className + ': ' + e.textContent).slice(0, 200) : ''; });
  const close = async () => { await browser.close(); server.close(); };
  return { page, state, errs, go, toast, close, T: 'C:/Users/Administrator/AppData/Local/Temp/' };
}
