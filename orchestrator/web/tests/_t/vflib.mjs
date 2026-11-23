// Stateful dummy backend for the Detection Verification page: runs, expectations (attest / approve / reject with the
// review-permission rule), evidence upload/delete, history, detection connectors (CRUD + test + verify-now),
// detection gaps with rule queries, deployments and re-test.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';

const NOW = Date.now();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();
const PROV = [['Splunk Enterprise Security', 'siem'], ['Palo Alto NGFW', 'network'], ['Proofpoint Email Gateway', 'email'], ['Zscaler Web Gateway', 'network'], ['CrowdStrike Falcon', 'endpoint'], ['Microsoft Defender for Identity', 'identity'], ['Imperva WAF', 'web']];

function mkItems(runN, n) {
  const T = ['T1003', 'T1021', 'T1566', 'T1048', 'T1490', 'T1558', 'T1190', 'T1059', 'T1105', 'T1078'];
  return Array.from({ length: n }, (_, i) => {
    const [provider, domain] = PROV[i % PROV.length];
    const st = ['Detected', 'NotDetected', 'Pending', 'NeedsReview', 'Detected', 'Pending', 'NotApplicable'][i % 7];
    const done = st !== 'Pending';
    return { expectationId: `exp-${runN}-${i + 1}`, verificationId: done ? `ver-${runN}-${i + 1}` : '', techniqueId: T[i % T.length] + (i >= 10 ? '.00' + (i % 4 + 1) : ''),
      provider, providerDisplay: provider, domain, status: st, confidence: ['high', 'medium', 'low'][i % 3], verifiedBy: done ? ['priya.iyer', 'rohan.mehta', 'asha.nair'][i % 3] : null,
      evidenceCount: done ? i % 3 : 0, workflowState: st === 'Pending' ? 'Pending' : st === 'NeedsReview' ? 'NeedsReview' : 'Approved', result: done ? st : '', note: done ? 'Checked the SIEM search for the host in the run window.' : '', alertId: done && st === 'Detected' ? 'INC-4' + i : '' };
  });
}

const rule = (id, title, sev, backends) => ({ id, sigmaId: '5f1c' + id.slice(-4) + '-aa11', title, severity: sev, match: id.endsWith('p') ? 'parent' : 'exact', source: { name: 'SigmaHQ', license: 'DRL 1.1' },
  backends: backends.map((b) => ({ backend: b, language: b === 'splunk' ? 'SPL' : b === 'elastic' ? 'Lucene' : 'KQL', mapping: b === 'elastic' ? 'pipeline' : 'generic', dataSource: b === 'elastic' ? 'Windows Security 4688' : '', verification: 'documented', exportUrl: `/api/gapq/${id}/${b}`, dslExportUrl: b === 'elastic' ? `/api/gapq/${id}/${b}/dsl` : '' })) });
const GAPS = (backend) => {
  const bs = backend ? [backend] : ['microsoft_sentinel', 'splunk', 'elastic'];
  return { summary: { 'Detection gap': 2, Unknown: 2, 'Execution error': 0, Skipped: 0, Detected: 2 }, library: { loaded: true, sigmaCommit: 'ab12cd34ef56', license: 'DRL 1.1' },
    techniques: [
      { techniqueId: 'T1021', name: 'Remote Services', status: 'Detection gap', ruleAvailability: 'Rule available', effectiveness: 'No alert seen', reason: 'The technique ran to completion and the reviewed verification found no alert.', ruleCount: 2, rules: [rule('sigma-rdp-lateral', 'RDP login from unusual host', 'high', bs), rule('sigma-smb-adminp', 'SMB admin share access', 'medium', bs)] },
      { techniqueId: 'T1048', name: 'Exfiltration Over Alternative Protocol', status: 'Detection gap', ruleAvailability: 'No rule available', effectiveness: 'No alert seen', reason: 'Ran to completion; no alert in the reviewed verification.', ruleCount: 0, rules: [] },
      { techniqueId: 'T1003', name: 'OS Credential Dumping', status: 'Detected', ruleAvailability: 'Rule available', effectiveness: 'Alert seen', reason: 'A reviewed verification found an alert.', ruleCount: 0, rules: [] },
      { techniqueId: 'T1566', name: 'Phishing', status: 'Unknown', ruleAvailability: 'Rule available', effectiveness: 'Not verified', reason: 'Nobody has verified this technique yet.', ruleCount: 0, rules: [] },
    ] };
};

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const PERMS = {
  admin: ['verification:view', 'verification:verify', 'verification:review', 'verification:evidence:upload', 'verification:evidence:delete', 'detectverify:configs:list', 'detectverify:run', 'scenarios:run'],
  analyst: ['verification:view', 'verification:verify', 'verification:evidence:upload', 'detectverify:run', 'scenarios:run'],
  viewer: ['verification:view'],
};

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
  const role = opts.role || 'admin';
  const state = {
    role, fail: {}, reqs: [], seq: 0, gapBackend: [],
    runs: [{ id: 'run-1', name: 'Ransomware precursor chain', agentId: 'WS-FIN-0142', startedAt: iso(180) }, { id: 'run-2', name: 'Empty run', agentId: 'WS-FIN-0143', startedAt: iso(900) }, { id: 'run-3', name: 'Large run', agentId: 'FS-LEG-01', startedAt: iso(2000) }],
    items: { 'run-1': mkItems(1, 7), 'run-2': [], 'run-3': mkItems(3, 30) },
    evidence: { 'ver-1-1': [{ id: 'ev-1', originalFilename: 'splunk-alert.png', displayFilename: 'splunk-alert.png', size: 183000, hashAlgorithm: 'SHA-256', contentHash: 'a3f5c9d2e1b04f6a8c7d9e0123456789abcdef', uploadedBy: 'priya.iyer' }] },
    history: {},
    configs: opts.noConfigs ? [] : [{ id: 'dc-1', name: 'Prod Sentinel', provider: 'microsoft_sentinel', enabled: true, autoVerify: true, workspaceId: 'ws-1234', tenantId: 'tn-1', clientId: 'cl-1', hasClientSecret: true, verifyDelaySeconds: 120 }, { id: 'dc-2', name: 'Lab Splunk', provider: 'splunk', enabled: false, autoVerify: false, baseUrl: 'https://splunk.lab:8089', hasApiToken: true, verifyDelaySeconds: 60 }],
    deployments: [], testResult: { ok: true },
  };
  const reqs = state.reqs, dialogs = [], errs = [];
  page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
  page.on('dialog', async (d) => { dialogs.push({ type: d.type(), msg: d.message().slice(0, 110) }); if (opts.acceptDialogs) await d.accept(); else await d.dismiss(); });
  await page.addInitScript((r) => { localStorage.setItem('bas_role', r); localStorage.setItem('audspect_theme', 'dark'); }, role);
  const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/*', async (r) => {
    const req = r.request(), u = new URL(req.url()), m = req.method(), path = u.pathname;
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' });
    const mine = path === '/api/me/permissions' || path === '/api/scenarios/runs' || /^\/api\/scenarios\/runs\/[^/]+\/(verifications|detection-gaps)/.test(path) || path.startsWith('/api/verifications') || path.startsWith('/api/evidence') || path.startsWith('/api/detectverify') || path.startsWith('/api/gapq') || (m === 'POST' && /^\/api\/scenarios\/[^/]+\/run$/.test(path));
    if (!mine) { if (path === '/ready' || path.startsWith('/api/')) return json(r, fx(m, u)); return r.continue(); }
    if (m !== 'GET') reqs.push(m + ' ' + path + ' ' + ((req.headers()['content-type'] || '').includes('multipart') ? '[multipart]' : (req.postData() || '').slice(0, 260)));
    // state.fail['path-fragment'] = 'message' fails every method on it; 'GET:fragment' fails reads only.
    const fk = Object.keys(state.fail).find((k) => (k.startsWith('GET:') ? m === 'GET' && path.includes(k.slice(4)) : path.includes(k)));
    if (fk) return json(r, { error: state.fail[fk] }, 500);
    const body = () => { try { return JSON.parse(req.postData() || '{}'); } catch { return {}; } };
    if (path === '/api/me/permissions') return json(r, { permissions: PERMS[role] });
    if (m === 'GET' && path === '/api/scenarios/runs') return json(r, state.runs);
    let mm;
    if ((mm = path.match(/^\/api\/scenarios\/runs\/([^/]+)\/verifications$/)) && m === 'GET') return json(r, { items: state.items[mm[1]] || [] });
    if ((mm = path.match(/^\/api\/scenarios\/runs\/([^/]+)\/verifications\/([^/]+)\/history$/))) return json(r, { history: state.history[mm[2]] || [] });
    if (m === 'POST' && path === '/api/verifications') {
      const b = body();
      if (!['Detected', 'NotDetected', 'NotApplicable'].includes(b.result)) return json(r, { error: 'result must be Detected, NotDetected or NotApplicable' }, 400);
      if (['Approved', 'Rejected'].includes(b.workflowState) && !PERMS[role].includes('verification:review')) return json(r, { error: 'review permission required to approve or reject' }, 403);
      const it = (state.items[b.runId] || []).find((i) => i.expectationId === b.expectationId);
      if (!it) return json(r, { error: 'expectation not found in run scenario' }, 404);
      const id = it.verificationId || ('ver-' + (++state.seq));
      state.history[it.expectationId] = [{ result: b.result, workflowState: b.workflowState, source: 'manual', verifiedBy: 'me', verifiedAt: iso(0), active: true }, ...(state.history[it.expectationId] || []).map((h) => ({ ...h, active: false }))];
      Object.assign(it, { verificationId: id, result: b.result, status: b.workflowState === 'Rejected' ? 'Pending' : b.workflowState === 'NeedsReview' ? 'NeedsReview' : b.result, workflowState: b.workflowState, verifiedBy: 'me', note: b.note, alertId: b.alertId });
      return json(r, { ok: true, verificationId: id });
    }
    if ((mm = path.match(/^\/api\/verifications\/([^/]+)\/evidence$/))) {
      if (m === 'GET') return json(r, { evidence: state.evidence[mm[1]] || [] });
      const raw = req.postDataBuffer() ? req.postDataBuffer().toString('latin1') : '';
      const fn = (raw.match(/filename="([^"]*)"/) || [])[1] || 'file.bin';
      if (/\.exe$/i.test(fn)) return json(r, { error: 'file type not allowed: .exe' }, 415);
      if (/huge/i.test(fn)) return json(r, { error: 'file exceeds 25 MiB limit' }, 413);
      const list = state.evidence[mm[1]] || (state.evidence[mm[1]] = []);
      const ev = { id: 'ev-' + (++state.seq), originalFilename: fn, displayFilename: fn, size: raw.length, hashAlgorithm: 'SHA-256', contentHash: 'b7e2' + String(state.seq).padStart(8, '0') + 'cafebabe0123456789', uploadedBy: 'me' };
      list.push(ev);
      for (const run of Object.values(state.items)) run.forEach((i) => { if (i.verificationId === mm[1]) i.evidenceCount = list.length; });
      return json(r, ev);
    }
    if ((mm = path.match(/^\/api\/evidence\/([^/]+)$/)) && m === 'DELETE') {
      for (const [vid, list] of Object.entries(state.evidence)) { const k = list.findIndex((e) => e.id === mm[1]); if (k >= 0) { list.splice(k, 1); for (const run of Object.values(state.items)) run.forEach((i) => { if (i.verificationId === vid) i.evidenceCount = list.length; }); } }
      return json(r, { ok: true });
    }
    if (path === '/api/detectverify/configs') {
      if (m === 'GET') return json(r, state.configs);
      const b = body(); const c = { id: 'dc-n' + (++state.seq), name: b.name, provider: b.provider, enabled: b.enabled, autoVerify: b.autoVerify, workspaceId: b.workspaceId, tenantId: b.tenantId, clientId: b.clientId, baseUrl: b.baseUrl, hasClientSecret: !!b.clientSecret, hasApiToken: !!b.apiToken, verifyDelaySeconds: b.verifyDelaySeconds };
      if (state.configs.some((x) => x.name === b.name)) return json(r, { error: 'a connector with this name already exists' }, 409);
      state.configs.push(c); return json(r, c);
    }
    if ((mm = path.match(/^\/api\/detectverify\/configs\/([^/]+)\/test$/))) return json(r, state.testResult);
    if ((mm = path.match(/^\/api\/detectverify\/configs\/([^/]+)$/))) {
      const k = state.configs.findIndex((c) => c.id === mm[1]);
      if (m === 'DELETE') { if (k >= 0) state.configs.splice(k, 1); return json(r, { ok: true }); }
      const b = body(); if (k >= 0) Object.assign(state.configs[k], { name: b.name, enabled: b.enabled, autoVerify: b.autoVerify, verifyDelaySeconds: b.verifyDelaySeconds }); return json(r, state.configs[k] || {});
    }
    if ((mm = path.match(/^\/api\/detectverify\/run\/([^/]+)$/))) return json(r, { message: 'Verification started for 7 expectations. Results are attested as the connector answers.' });
    if ((mm = path.match(/^\/api\/scenarios\/runs\/([^/]+)\/detection-gaps\/deployments\/([^/]+)\/retest$/))) { const d = state.deployments.find((x) => x.id === mm[2]); if (d) { d.status = 'Re-test running'; d.retestRunId = body().retestRunId; } return json(r, d || {}); }
    if ((mm = path.match(/^\/api\/scenarios\/runs\/([^/]+)\/detection-gaps\/deployments$/))) {
      if (m === 'GET') return json(r, { retest: { scenarioId: 'sc-ransom', agentId: 'WS-FIN-0142', mode: opts.retestMode || 'telemetry' }, deployments: state.deployments });
      const b = body(); const d = { id: 'dep-' + (++state.seq), techniqueId: b.techniqueId, ruleId: b.ruleId, ruleTitle: 'RDP login from unusual host', backend: b.backend, backendLabel: b.backend, status: 'Deployed', detail: 'Recorded. Re-test to find out whether the gap is closed.', deployedAt: iso(0), deployedBy: 'me' };
      state.deployments.push(d); return json(r, d);
    }
    if ((mm = path.match(/^\/api\/scenarios\/runs\/([^/]+)\/detection-gaps\/export$/))) return r.fulfill({ status: 200, contentType: 'application/zip', headers: { 'Content-Disposition': 'attachment; filename=gaps.zip' }, body: 'PK-fake' });
    if ((mm = path.match(/^\/api\/scenarios\/runs\/([^/]+)\/detection-gaps$/))) { state.gapBackend.push(u.searchParams.get('backend') || ''); return json(r, GAPS(u.searchParams.get('backend') || '')); }
    if (path.startsWith('/api/gapq/')) return r.fulfill({ status: 200, contentType: 'text/plain', headers: { 'X-Audspect-Data-Source': 'Windows Security 4688' }, body: 'SecurityEvent | where EventID == 4624' });
    if (m === 'POST' && /^\/api\/scenarios\/[^/]+\/run$/.test(path)) return json(r, { runId: 'run-retest-' + (++state.seq) });
    return json(r, {});
  });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none');
  await page.waitForTimeout(700);
  const go = async (runId) => {
    await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'verification'); el && el.click(); });
    await page.waitForTimeout(1500);
    if (runId) { await page.selectOption('#vf-run', runId); await page.waitForTimeout(1500); }
  };
  const toast = () => page.evaluate(() => { const e = document.getElementById('toast'); return e ? (e.className + ': ' + e.textContent).slice(0, 170) : ''; });
  const vis = (sel) => page.evaluate((s) => { const e = document.querySelector(s); return !!e && getComputedStyle(e).display !== 'none' && e.offsetParent !== null; }, sel);
  const overlays = () => page.evaluate(() => ['vf-drawer-overlay', 'confirm-diff-overlay', 'results-overlay'].filter((id) => { const e = document.getElementById(id); return e && e.classList.contains('open'); }).join(','));
  const close = async () => { await browser.close(); server.close(); };
  return { page, state, reqs, dialogs, errs, go, toast, vis, overlays, close, T: 'C:/Users/Administrator/AppData/Local/Temp/' };
}
