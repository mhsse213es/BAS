// Stateful dummy backend for the Remediation page: technique fixes (GET /api/remediations), the by-endpoint view
// (with Phase 2 requests), ITSM configs, and bulk ticket push with real per-finding partial failure.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';

const NOW = Date.now();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();

const rem = (severity, techniqueId, techniqueName, controlClasses, missed, detectedOnly, mitigations, detection, targets) => ({
  severity, techniqueId, techniqueName, findingCount: missed + detectedOnly, agentCount: targets.length, controlClasses, missed, detectedOnly,
  mitigations, detection, recommendedTargets: targets,
  findingIds: Array.from({ length: missed + detectedOnly }, (_, i) => `f-${techniqueId}-${i + 1}`),
});
const REMS = () => [
  rem('Critical', 'T1486', 'Data Encrypted for Impact', ['AV', 'EDR', 'Identity'], 6, 0, [{ name: 'Data Backup', description: 'Keep offline, immutable copies of file server data and test restores quarterly.' }, { name: 'Behavior Prevention on Endpoint', description: 'Turn on ransomware protection and controlled folder access for user profile paths.' }], 'Alert on mass file renames with new extensions and rapid entropy increase in user directories.', ['WS-FIN-0142', 'FS-LEG-01', 'MAC-DES-221', 'WS-FIN-0143', 'lnx-db-02', 'WS-HR-0031']),
  rem('Critical', 'T1003.001', 'LSASS Memory', ['Identity', 'Network', 'Email', 'AV'], 5, 0, [{ name: 'Credential Access Protection', description: 'Enable LSASS protection (RunAsPPL) and Credential Guard on all domain-joined Windows hosts.' }, { name: 'Privileged Account Management', description: 'Remove local administrator rights from standard finance workstation users.' }], 'Monitor access to LSASS from unexpected processes.', ['WS-FIN-0142', 'WS-FIN-0143', 'DC-SEC-02', 'FS-LEG-01', 'WS-HR-0031']),
  rem('Critical', 'T1190', 'Exploit Public-Facing Application', ['Identity', 'Network', 'AV'], 4, 0, [{ name: 'Update Software', description: 'Patch the web tier to the vendor fixed release for the KEV-listed CVE.' }], 'Alert on web server processes spawning shells or writing executable content.', ['lnx-web-07', 'lnx-web-08', 'lnx-db-02', 'CA-ISS-01']),
  rem('High', 'T1562.001', 'Disable or Modify Tools', ['Network', 'AV', 'Identity'], 5, 0, [{ name: 'Restrict Registry Permissions', description: 'Limit write access to security tooling configuration keys to administrators.' }], 'Alert on security service stop and tamper events.', ['WS-FIN-0142', 'WS-FIN-0143', 'DC-PRI-01', 'FS-LEG-01', 'WS-HR-0031']),
  rem('High', 'T1055', 'Process Injection', ['Email', 'EDR'], 3, 1, [{ name: 'Behavior Prevention on Endpoint', description: 'Block cross-process memory writes from untrusted parents.' }], '', ['WS-FIN-0142', 'WS-FIN-0143', 'MAC-DES-222', 'WS-HR-0031']),
  rem('High', 'T1548.002', 'Bypass User Account Control', ['EDR', 'AV'], 2, 1, [], '', ['WS-FIN-0143', 'WS-HR-0031', 'WS-FIN-0142']),
  rem('Medium', 'T1070.001', 'Clear Windows Event Logs', ['EDR', 'Identity', 'Email', 'AV'], 6, 1, [{ name: 'Remote Data Storage', description: 'Forward Windows security logs to the central SIEM so local clearing is visible.' }], 'Alert on event log clearing (Event ID 1102 and 104).', ['DC-SEC-02', 'DC-PRI-01', 'WS-FIN-0142', 'WS-FIN-0143', 'FS-LEG-01', 'CA-ISS-01', 'WS-HR-0031']),
  rem('Low', 'T1082', 'System Information Discovery', ['EDR'], 0, 3, [], '', ['WS-HR-0031']),
  // a row with no finding ids at all (the page tells the user to re-validate)
  { ...rem('Medium', 'T1005', 'Data from Local System', ['EDR', 'Email'], 2, 1, [], '', ['WS-FIN-0142']), findingIds: [] },
];

const fnd = (techniqueId, name, severity, exposureState, mitigations) => ({ id: 'ef-' + techniqueId, agentId: '', techniqueId, techniqueName: name, tactic: 'impact', severity, exposureState, controlClass: 'EDR', mitigations });
const EPS = () => [
  { agentId: 'a1b2c3d4e5f60001', hostname: 'WS-FIN-0142', status: 'Open', openFindings: 4, techniqueCount: 4, severity: { critical: 2, high: 1, medium: 1, low: 0 },
    findings: [fnd('T1486', 'Data Encrypted for Impact', 'critical', 'open', ['Data Backup', 'Behavior Prevention on Endpoint', 'Encrypt Sensitive Information', 'Network Segmentation', 'User Training']), fnd('T1003.001', 'LSASS Memory', 'critical', 'open', ['Credential Access Protection', 'Privileged Account Management']), fnd('T1562.001', 'Disable or Modify Tools', 'high', 'open', ['Restrict Registry Permissions']), fnd('T1548.002', 'Bypass User Account Control', 'medium', 'open', [])] },
  { agentId: 'a1b2c3d4e5f60002', hostname: 'FS-LEG-01', status: 'Phase 2', openFindings: 2, techniqueCount: 2, severity: { critical: 1, high: 1, medium: 0, low: 0 },
    findings: [fnd('T1486', 'Data Encrypted for Impact', 'critical', 'open', ['Data Backup']), fnd('T1490', 'Inhibit System Recovery (not in technique list)', 'high', 'open', ['Operating System Configuration'])],
    requests: [
      { requestId: 'req-9001', remediationId: 'rem-lsass', checkId: 'lsass-runasppl', status: 'In progress', executionStatus: 'running', requestedBy: 'analyst1', requestedAt: iso(90), closureVerified: false },
      { requestId: 'req-8990', remediationId: 'rem-vss', checkId: 'vss-restrict', status: 'Completed', executionStatus: 'completed', requestedBy: 'admin', requestedAt: iso(2 * 1440), verificationStatus: 'passed', verificationReason: 'technique no longer executes', closureVerified: true },
      { requestId: 'req-8801', remediationId: 'rem-rdp', checkId: 'rdp-nla', status: 'Failed', executionStatus: 'failed', error: 'agent offline during execution', requestedBy: 'analyst1', requestedAt: iso(5 * 1440), closureVerified: false },
    ] },
  { agentId: 'a1b2c3d4e5f60003', hostname: '', status: 'Open', openFindings: 1, techniqueCount: 1, severity: { critical: 0, high: 0, medium: 1, low: 0 }, findings: [fnd('T1070.001', 'Clear Windows Event Logs', 'medium', 'open', ['Remote Data Storage'])] },
  { agentId: 'a1b2c3d4e5f60004', hostname: 'DC-PRI-01', status: 'No remediation required', openFindings: 0, techniqueCount: 0, severity: { critical: 0, high: 0, medium: 0, low: 0 }, findings: [] },
];

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
  const ctx = await browser.newContext({ viewport: opts.viewport || { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const state = {
    rems: opts.empty ? [] : REMS(), eps: opts.empty ? [] : EPS(), role: opts.role || 'admin', fail: {}, reqs: [],
    configs: opts.configs || [{ id: 'cfg-snow', name: 'ServiceNow (prod)', enabled: true }, { id: 'cfg-jira', name: 'Jira Service Desk', enabled: true }, { id: 'cfg-old', name: 'Legacy Remedy', enabled: false }],
    pushFail: new Set(opts.pushFail || []), tickets: 0,
  };
  const reqs = state.reqs, dialogs = [], errs = [];
  page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
  page.on('dialog', async (d) => { dialogs.push({ type: d.type(), msg: d.message().slice(0, 100) }); await d.dismiss(); });
  await page.addInitScript((role) => { localStorage.setItem('bas_role', role); localStorage.setItem('audspect_theme', 'dark'); }, state.role);
  const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/*', async (r) => {
    const req = r.request(), u = new URL(req.url()), m = req.method(), path = u.pathname;
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' });
    const mine = path.startsWith('/api/remediations') || path.startsWith('/api/ticketing/push') || path === '/api/ticketing/configs';
    if (!mine) { if (path === '/ready' || path.startsWith('/api/')) return json(r, fx(m, u)); return r.continue(); }
    if (m !== 'GET') reqs.push(m + ' ' + path + ' ' + (req.postData() || '').slice(0, 240));
    const fk = Object.keys(state.fail).find((k) => path.includes(k));
    if (fk) return json(r, { error: state.fail[fk] }, 500);
    if (m === 'GET' && path === '/api/remediations') return json(r, state.rems);
    if (m === 'GET' && path === '/api/remediations/by-endpoint') return json(r, state.eps);
    if (m === 'GET' && path === '/api/ticketing/configs') return json(r, state.configs);
    if (m === 'POST' && path === '/api/ticketing/push/bulk') {
      const b = JSON.parse(req.postData() || '{}');
      return json(r, (b.findingIds || []).map((id) => state.pushFail.has(id) ? { findingId: id, error: 'ServiceNow: assignment group is required' } : { findingId: id, ticketId: 'INC' + String(1000 + (++state.tickets)).padStart(7, '0'), ticketUrl: 'https://snow.example/INC' + state.tickets }));
    }
    return json(r, {});
  });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none');
  await page.waitForTimeout(700);
  const go = async () => { await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'remediation'); el && el.click(); }); await page.waitForTimeout(1800); };
  const toast = () => page.evaluate(() => { const e = document.getElementById('toast'); return e ? (e.className + ': ' + e.textContent).slice(0, 150) : ''; });
  const vis = (sel) => page.evaluate((s) => { const e = document.querySelector(s); return !!e && getComputedStyle(e).display !== 'none' && e.offsetParent !== null; }, sel);
  const overlays = () => page.evaluate(() => ['results-overlay', 'confirm-diff-overlay', 'run-modal-overlay', 'modal-overlay'].filter((id) => { const e = document.getElementById(id); return e && e.classList.contains('open'); }).join(','));
  const close = async () => { await browser.close(); server.close(); };
  return { page, state, reqs, dialogs, errs, go, toast, vis, overlays, close, T: 'C:/Users/Administrator/AppData/Local/Temp/' };
}
