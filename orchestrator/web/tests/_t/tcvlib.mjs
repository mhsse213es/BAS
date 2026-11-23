// Dummy backend for the Technique Coverage page: actors, the coverage matrix (per actor), technique names, ATT&CK detail.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';

const NAMES = ['Data Encrypted for Impact', 'OS Credential Dumping', 'Phishing', 'Exploit Public-Facing Application', 'Command and Scripting Interpreter', 'Scheduled Task/Job', 'Valid Accounts', 'Remote Services', 'Process Injection', 'Impair Defenses', 'Inhibit System Recovery', 'Ingress Tool Transfer', 'Exfiltration Over C2 Channel', 'Account Discovery', 'Obfuscated Files or Information', 'Boot or Logon Autostart Execution', 'Create Account', 'Masquerading', 'System Information Discovery', 'Data from Local System'];
const TACTICS = ['impact', 'credential-access', 'initial-access', 'execution', 'persistence', 'lateral-movement', 'defense-evasion', 'discovery', 'collection', 'exfiltration'];
const mkIds = (n) => Array.from({ length: n }, (_, i) => 'T' + String(1001 + i * 3).padStart(4, '0') + (i % 5 === 0 ? '.00' + (i % 4 + 1) : ''));
const IDS = mkIds(180);
const dims = (i) => ({ simulationExists: i % 3 !== 0, detectionProfileExists: i % 4 !== 0, purpleExerciseExists: i % 5 === 0 ? true : i % 7 === 0 ? false : (i % 2 === 0), complianceMappingExists: i % 6 !== 0, responsePlaybookExists: i % 9 === 0 ? null : i % 4 === 1 });
const matrixFor = (ids) => ids.map((id) => ({ techniqueId: id, ...dims(IDS.indexOf(id)) }));
const ACTORS = { APT29: IDS.slice(0, 14), 'Lazarus Group': IDS.slice(10, 40), FIN7: IDS.slice(30, 52), 'Sandworm Team': IDS.slice(60, 66), 'Empty Actor': [] };
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };

export async function boot(opts = {}) {
  const dist = resolve('dist'), strip = new RegExp('^[/]+');
  const server = createServer(async (q, s) => {
    const p = decodeURIComponent(new URL(q.url, 'http://x').pathname);
    const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, ''));
    let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; }
    s.writeHead(200, { 'Content-Type': TYPES[extname(f)] || 'application/octet-stream' }).end(d);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const fx = fixtureSet('rich');
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: opts.viewport || { width: 1440, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  const state = { fail: {}, reqs: [], all: opts.few ? IDS.slice(0, 6) : IDS };
  const errs = [], dialogs = [];
  page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
  page.on('dialog', async (d) => { dialogs.push(d.message().slice(0, 80)); await d.dismiss(); });
  await page.addInitScript((r) => { localStorage.setItem('bas_role', r); localStorage.setItem('audspect_theme', 'dark'); }, opts.role || 'admin');
  const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/*', async (r) => {
    const req = r.request(), u = new URL(req.url()), path = u.pathname;
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' });
    const mine = path.startsWith('/api/coverage/matrix') || path === '/api/coverage/actors' || path === '/api/techniques/unified' || path.startsWith('/api/attack/technique/');
    if (!mine) { if (path === '/ready' || path.startsWith('/api/')) return json(r, fx(req.method(), u)); return r.continue(); }
    state.reqs.push(path + u.search);
    const fk = Object.keys(state.fail).find((k) => path.includes(k));
    if (fk) return json(r, { error: state.fail[fk] }, 500);
    if (path === '/api/coverage/actors') return json(r, { actors: Object.keys(ACTORS) });
    if (path === '/api/coverage/matrix') { const a = u.searchParams.get('actor'); return json(r, opts.empty ? [] : matrixFor(a ? (ACTORS[a] || []) : state.all)); }
    if (path === '/api/techniques/unified') return json(r, IDS.map((id, i) => ({ techniqueId: id, name: NAMES[i % NAMES.length] + (i >= NAMES.length ? ' (' + id + ')' : ''), tactic: TACTICS[i % TACTICS.length], basCount: 1, artCount: 0, emuCount: 0, atomicCount: 0, totalVariants: 1 })));
    const id = decodeURIComponent(path.split('/').pop()); const i = IDS.indexOf(id);
    if (i < 0) return json(r, { error: 'technique not found' }, 404);
    return json(r, { id, name: NAMES[i % NAMES.length], tactics: [TACTICS[i % TACTICS.length]], platforms: ['windows', 'linux'], groups: ['APT29', 'FIN7'], dataSources: ['Process: Process Creation'], description: 'Adversaries may ' + NAMES[i % NAMES.length].toLowerCase() + ' to achieve their goals.', url: 'https://attack.mitre.org/techniques/' + id });
  });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none');
  await page.waitForTimeout(700);
  const go = async () => { await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'attack-coverage'); el && el.click(); }); await page.waitForTimeout(1600); };
  const toast = () => page.evaluate(() => { const e = document.getElementById('toast'); return e ? (e.className + ': ' + e.textContent).slice(0, 170) : ''; });
  const vis = (sel) => page.evaluate((s) => { const e = document.querySelector(s); return !!e && getComputedStyle(e).display !== 'none' && e.offsetParent !== null; }, sel);
  const close = async () => { await browser.close(); server.close(); };
  return { page, state, errs, dialogs, go, toast, vis, close, T: 'C:/Users/Administrator/AppData/Local/Temp/' };
}
