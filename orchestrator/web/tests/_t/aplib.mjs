// Stateful dummy backend for the Attack Path page: summary, correlation, history, assets, schedule and collection
// jobs that can be pushed through their stages over the WebSocket. Shared by the ap*.mjs scripts.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';

const NOW = Date.now();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();
const REL = { smb: 41, winrm: 18, rdp: 12, 'admin-to': 9, 'has-session': 14, 'member-of': 27, credential: 6 };

export const SUMMARY = (over = {}) => ({
  collected: true,
  agentMeta: [{ agentId: 'a-3', hostname: 'DC-PRI-01', collectedAt: iso(5 * 60), edgeCount: Object.values(REL).reduce((a, b) => a + b, 0) }],
  summary: {
    attackPathScore: 58, band: 'Medium',
    scoreDrivers: [{ label: 'Domain Admin reachable from a workstation', deficit: 14.5 }, { label: 'Local administrator reuse across hosts', deficit: 9.0 }, { label: 'Flat network between server segments', deficit: 6.5 }, { label: 'Credential exposure on file servers', deficit: 0 }],
    avgBlastRadius: 3.4, maxBlastRadius: 9, maxBlastEntry: 'WS-FIN-0142', lateralMovementBand: 'High',
    domainCompromise: true, domainCompromiseStatus: 'reachable', shortestDomainAdminDifficulty: 'Medium',
    shortestDomainAdminPath: [{ from: 'WS-FIN-0142', to: 'FS-LEG-01', kind: 'smb' }, { from: 'FS-LEG-01', to: 'svc-backup', kind: 'has-session' }, { from: 'svc-backup', to: 'DC-PRI-01', kind: 'admin-to' }, { from: 'DC-PRI-01', to: 'Domain Admins', kind: 'member-of' }],
    confidence: { level: 'Medium', based: ['Host reachability probes', 'Local administrator enumeration', 'Active session listing'], missing: ['Active Directory relationships'] },
    relationshipCounts: REL,
    crownJewels: [{ node: 'lnx-db-02', tag: 'Payments ledger', reachable: true, entryHosts: 4, minHops: 3 }, { node: 'CA-ISS-01', tag: 'Issuing CA', reachable: true, entryHosts: 2, minHops: 4 }, { node: 'DC-PRI-01', tag: 'Identity', reachable: true, entryHosts: 6, minHops: 2 }],
    chokePoints: [{ label: 'FS-LEG-01', onPaths: 14, coverage: 0.61 }, { label: 'svc-backup', onPaths: 11, coverage: 0.48 }, { label: 'DC-SEC-02', onPaths: 6, coverage: 0.26 }],
    segmentationViolations: [{ from: 'WS-FIN-0143', fromSegment: 'Finance LAN', kind: 'smb', to: 'FS-LEG-01', toSegment: 'Server LAN' }, { from: 'lnx-web-07', fromSegment: 'DMZ', kind: 'rdp', to: 'lnx-db-02', toSegment: 'Payments' }],
    hosts: 12, users: 38, groups: 21, edges: Object.values(REL).reduce((a, b) => a + b, 0),
  },
  coverage: { targetsRequested: 12, targetsRepresented: 9, completeness: 'Limited', sharpHoundRequested: true, sharpHoundAvailable: false },
  ...over,
});
const CORR = { gaps: [
  { priority: 'Critical', edge: { from: 'FS-LEG-01', to: 'svc-backup', kind: 'has-session' }, reason: 'Backup service account session on a file server with no credential-theft detection.', remediation: 'Move the backup service to a gMSA and enable LSASS protection.' },
  { priority: 'High', edge: { from: 'WS-FIN-0143', to: 'FS-LEG-01', kind: 'smb' }, reason: 'Finance workstation can reach the legal file server over SMB.', remediation: 'Restrict SMB between the Finance LAN and the Server LAN to approved shares.' },
  { priority: 'Medium', edge: { from: 'lnx-web-07', to: 'lnx-db-02', kind: 'rdp' }, reason: 'DMZ web host reaches the payments database on a management port.', remediation: 'Allow only the application port from the DMZ and require a bastion.' },
] };
const ASSETS = () => ['DC-PRI-01', 'FS-LEG-01', 'WS-FIN-0142', 'lnx-db-02', 'CA-ISS-01'].map((h, i) => ({ hostKey: h.toLowerCase(), label: h, crownJewel: i === 3 ? 'Payments ledger' : '', segment: i === 1 ? 'Server LAN' : '', highValue: i === 0, criticalityTier: i === 0 ? 'critical' : '', internetFacing: false, identityExposed: i === 0, production: true, complianceScope: i === 3 ? ['PCI-DSS'] : [] }));
const HISTORY = () => [
  { collectedAt: iso(5 * 60), hostname: 'DC-PRI-01', nodeCount: 71, edgeCount: 127, durationMs: 94000, sharpHound: false, status: 'completed' },
  { collectedAt: iso(29 * 60), hostname: 'DC-PRI-01', nodeCount: 69, edgeCount: 121, durationMs: 88000, sharpHound: true, status: 'completed' },
  { collectedAt: iso(53 * 60), hostname: 'FS-LEG-01', nodeCount: 12, edgeCount: 9, durationMs: 21000, sharpHound: false, status: 'failed', errorMsg: 'target unreachable: connection timed out after 30 seconds' },
];

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };

// boot({ empty }) -> page wired to the stateful backend. push(job) sends an ap_job_update over the WebSocket.
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
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const state = {
    summary: opts.empty ? { collected: false } : SUMMARY(opts.summary || {}), corr: CORR, assets: ASSETS(), history: HISTORY(),
    schedule: { enabled: false, intervalMinutes: 1440, targets: [], segment: '', runSharpHound: false, lastRunAt: null },
    jobs: {}, seq: 0, fail: {}, delay: {},
  };
  const reqs = [], dialogs = [], errs = [];
  let wsConn = null;
  page.on('pageerror', (e) => errs.push(e.message.slice(0, 140)));
  page.on('dialog', async (d) => { dialogs.push({ type: d.type(), msg: d.message().slice(0, 100) }); if (opts.dialogAnswer === 'accept') await d.accept(); else await d.dismiss(); });
  await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
  const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/*', async (r) => {
    const req = r.request(), u = new URL(req.url()), m = req.method(), path = u.pathname;
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' });
    if (!path.startsWith('/api/attackpath')) {
      if (path === '/ready' || path.startsWith('/api/')) return json(r, fx(m, u));
      return r.continue();
    }
    if (m !== 'GET') reqs.push(m + ' ' + path + ' ' + (req.postData() || '').slice(0, 160));
    const fk = Object.keys(state.fail).find((k) => path.includes(k));
    if (fk) return json(r, { error: state.fail[fk] }, 500);
    const dk = Object.keys(state.delay).find((k) => path.includes(k));
    if (dk) await new Promise((res) => setTimeout(res, state.delay[dk]));
    let g;
    if (m === 'GET' && path === '/api/attackpath/summary') return json(r, state.summary);
    if (m === 'GET' && path === '/api/attackpath/correlation') return json(r, state.corr);
    if (m === 'GET' && path === '/api/attackpath/history') return json(r, state.history);
    if (m === 'GET' && path === '/api/attackpath/assets') return json(r, { assets: state.assets });
    if (m === 'POST' && path === '/api/attackpath/assets') { const b = JSON.parse(req.postData()); const i = state.assets.findIndex((a) => a.hostKey === b.hostKey); if (i >= 0) state.assets[i] = { ...state.assets[i], ...b }; return json(r, { ok: true }); }
    if (m === 'GET' && path === '/api/attackpath/schedule') return json(r, state.schedule);
    if (m === 'POST' && path === '/api/attackpath/schedule') { state.schedule = { ...state.schedule, ...JSON.parse(req.postData()) }; return json(r, state.schedule); }
    if (m === 'GET' && (g = path.match(/^\/api\/attackpath\/subnet\/(.+)$/))) return json(r, { subnet: '10.20.2.0/24', targets: ['10.20.2.10', '10.20.2.11', '10.20.2.60', 'FS-LEG-01', 'DC-PRI-01'] });
    if (m === 'POST' && path === '/api/attackpath/jobs') {
      const b = JSON.parse(req.postData() || '{}'); const id = 'job' + (++state.seq) + '-aaaa-bbbb-cccc-0000';
      state.jobs[id] = { id, agentId: b.agentId, status: 'dispatched', targetCount: (b.targets || []).length, error: '', payload: b };
      return json(r, { job: state.jobs[id], sharpHoundDelivered: !!b.runSharpHound && !opts.noSharp });
    }
    if (m === 'GET' && (g = path.match(/^\/api\/attackpath\/jobs\/([^/]+)$/))) { const j = state.jobs[g[1]]; return j ? json(r, j) : json(r, { error: 'not found' }, 404); }
    if (m === 'POST' && (g = path.match(/^\/api\/attackpath\/jobs\/([^/]+)\/cancel$/))) { const j = state.jobs[g[1]]; j.status = 'cancelled'; j.error = 'cancelled'; return json(r, { job: j }); }
    if (m === 'POST' && (g = path.match(/^\/api\/attackpath\/jobs\/([^/]+)\/retry$/))) { const o = state.jobs[g[1]]; const id = 'job' + (++state.seq) + '-retry-bbbb-cccc-0000'; state.jobs[id] = { ...o, id, status: 'dispatched', error: '' }; return json(r, state.jobs[id]); }
    return json(r, {});
  });
  await page.routeWebSocket(/ws/, (ws) => { wsConn = ws; });
  await page.goto(origin + '/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none');
  await page.waitForTimeout(700);
  const go = async () => { await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'attackpath'); el && el.click(); }); await page.waitForTimeout(1800); };
  const push = async (id, patch) => { Object.assign(state.jobs[id], patch); wsConn && wsConn.send(JSON.stringify({ type: 'ap_job_update', agentId: state.jobs[id].agentId, data: state.jobs[id] })); await page.waitForTimeout(500); };
  const progress = async (id, p) => { wsConn && wsConn.send(JSON.stringify({ type: 'ap_job_progress', agentId: state.jobs[id].agentId, data: { jobId: id, agentId: state.jobs[id].agentId, progress: p } })); await page.waitForTimeout(400); };
  const toast = () => page.evaluate(() => { const e = document.getElementById('toast'); return e ? (e.className + ': ' + e.textContent).slice(0, 130) : ''; });
  const vis = (sel) => page.evaluate((s) => { const e = document.querySelector(s); return !!e && getComputedStyle(e).display !== 'none' && e.offsetParent !== null; }, sel);
  const close = async () => { await browser.close(); server.close(); };
  return { page, state, reqs, dialogs, errs, go, push, progress, toast, vis, close, T: 'C:/Users/Administrator/AppData/Local/Temp/' };
}
