// Dummy backend for the Exposure Explorer page: asset index + per-asset profiles.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';

const mk = (i) => {
  const managed = i % 3 !== 2, cj = i % 7 === 0 ? ['Domain controller', 'Payments DB', 'Backup server'][i % 3] : '';
  const measurable = i % 11 !== 10;
  const exp = measurable ? Math.max(5, 100 - ((i * 37) % 95)) : null;
  return { asset: { hostKey: 'host-' + i, label: (managed ? 'WS-FIN-' : 'unmanaged-') + String(100 + i), managed, internetFacing: i % 5 === 0, crownJewel: cj, os: managed ? 'Windows 11' : 'Linux', ip: '10.0.' + (i % 8) + '.' + (10 + i), agentId: managed ? 'agt-' + i : '', segment: i % 2 ? 'corp' : 'dmz', criticalityTier: cj ? 'Tier 0' : i % 4 === 0 ? 'Tier 1' : '', production: i % 2 === 0, identityExposed: i % 9 === 0, complianceScope: i % 4 === 0 ? ['PCI', 'SOX'] : [] },
    exposureScore: exp, attackPathScore: measurable ? Math.min(100, exp + 8) : null, detectionCoverageScore: measurable ? Math.max(0, exp - 12) : null, openFindingsCount: measurable ? (i * 3) % 17 : 0, kevExposed: i % 6 === 0 };
};
const ASSETS = (n) => Array.from({ length: n }, (_, i) => mk(i + 1));
const profile = (a) => {
  const m = a.exposureScore != null;
  return { asset: a.asset,
    scores: { exposureScore: a.exposureScore, exposureMeasurable: m, attackPathScore: a.attackPathScore, attackPathMeasurable: m, detectionCoverageScore: a.detectionCoverageScore, detectionMeasurable: m, vulnerabilityScore: m ? 71 : null, vulnerabilityMeasurable: m },
    vulnerabilities: m ? [{ cveId: 'CVE-2024-3400', cvss: 10, kev: true, epssScore: 0.97, techniqueId: 'T1190' }, { cveId: 'CVE-2023-4966', cvss: 9.4, kev: a.kevExposed, epssScore: 0.88, techniqueId: 'T1190' }] : [],
    recommendations: m ? [{ edge: { from: 'internet', kind: 'exposes', to: a.asset.label }, priority: 'High', reason: 'Internet-facing service with a known exploited CVE and no detection rule.' }] : [],
    findings: { collected: a.asset.managed, openCount: a.openFindingsCount, criticalCount: Math.floor(a.openFindingsCount / 4), findings: a.asset.managed && a.openFindingsCount ? [{ techniqueId: 'T1003', techniqueName: 'OS Credential Dumping', severity: 'Critical', exposureState: 'open' }, { techniqueId: 'T1486', techniqueName: 'Data Encrypted for Impact', severity: 'High', exposureState: 'open' }] : [] },
    threatIntel: m ? [{ groupName: 'APT29' }, { groupName: 'FIN7' }] : [] };
};
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
  const state = { fail: {}, status: {}, reqs: [], assets: opts.empty ? [] : ASSETS(opts.n || 40) };
  const errs = [];
  page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
  await page.addInitScript((r) => { localStorage.setItem('bas_role', r); localStorage.setItem('audspect_theme', 'dark'); }, opts.role || 'admin');
  const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/*', async (r) => {
    const req = r.request(), u = new URL(req.url()), path = u.pathname;
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' });
    if (!path.startsWith('/api/exposure')) { if (path === '/ready' || path.startsWith('/api/')) return json(r, fx(req.method(), u)); return r.continue(); }
    state.reqs.push(path);
    const fk = Object.keys(state.fail).find((k) => path.includes(k));
    if (fk) return json(r, { error: state.fail[fk] }, state.status[fk] || 500);
    if (path === '/api/exposure/assets') return json(r, state.assets);
    const key = decodeURIComponent(path.split('/').pop()); const a = state.assets.find((x) => x.asset.hostKey === key);
    return a ? json(r, profile(a)) : json(r, { error: 'asset not found' }, 404);
  });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none');
  await page.waitForTimeout(700);
  const go = async () => { await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'exposure'); el && el.click(); }); await page.waitForTimeout(1600); };
  const toast = () => page.evaluate(() => { const e = document.getElementById('toast'); return e ? (e.className + ': ' + e.textContent).slice(0, 170) : ''; });
  const close = async () => { await browser.close(); server.close(); };
  return { page, state, errs, go, toast, close, T: 'C:/Users/Administrator/AppData/Local/Temp/' };
}
