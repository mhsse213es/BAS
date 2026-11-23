// Stateful dummy backend for the Exercises page: scenarios, exercises, plans, executions and their drill-downs.
// Launch / approve / abort really change the data, so the aftermath of a click can be seen. Shared by the ex*.mjs scripts.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';

const NOW = Date.now();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();

const sc = (n, name, category, severity, techs, injects) => ({
  OpenAEVScenarioID: 'oaev-sc-' + n, Name: name, Category: category, Severity: severity,
  TechniqueIDs: Array.from({ length: techs }, (_, i) => 'T1' + (100 + n * 7 + i)), InjectsCount: injects, SourceUpdatedAt: iso(n * 900),
});
const SCEN = [
  sc(1, 'Cloud Credential Theft', 'Credential Access', 'high', 4, 9), sc(2, 'Insider Data Staging', 'Collection', 'medium', 4, 7),
  sc(3, 'Lateral Movement via SMB', 'Lateral Movement', 'medium', 4, 6), sc(4, 'Phishing to Domain Admin', 'Initial Access', 'high', 4, 10),
  sc(5, 'Ransomware Precursors', 'Impact', 'critical', 4, 5), sc(6, 'Web Shell Persistence', 'Persistence', 'high', 4, 11),
  sc(7, 'Kerberoasting Walkthrough', 'Credential Access', 'high', 3, 4), sc(8, 'DNS Tunnelling Exfiltration', 'Exfiltration', 'critical', 5, 8),
  sc(9, 'Business Email Compromise', 'Initial Access', 'medium', 3, 6), sc(10, 'Supply Chain Implant', 'Persistence', 'critical', 6, 12),
  { ...sc(11, 'Untitled import with no category', '', '', 0, null), SourceUpdatedAt: '' }, sc(12, 'USB Drop Awareness', 'Initial Access', 'low', 2, 3),
];
const EXS = [sc(21, 'Q3 purple-team exercise', 'Exercise', 'high', 8, 14), sc(22, 'Board ransomware tabletop', 'Exercise', 'critical', 5, 9), sc(23, 'Regional DR drill', 'Exercise', 'medium', 3, 6)];

const plan = (id, name, steps, created, variables) => ({ id, name, steps: Array.from({ length: steps }, (_, i) => ({ id: 's' + i })), created_at: created, variables });
const PLANS = [
  plan('pl-1', 'Ransomware Tabletop + Technical', 5, iso(60 * 24 * 40), [{ name: 'target_group', description: 'Agent group to run the technical steps on', default: 'Finance Workstations' }, { name: 'sender_name', description: 'Display name on the lure email', default: 'IT Service Desk' }]),
  plan('pl-2', 'Phishing Response Drill', 3, iso(60 * 24 * 38), []),
  plan('pl-3', 'Empty plan (no steps yet)', 0, iso(60 * 24 * 3), []),
];

const mkSteps = (kinds, statuses, extra = {}) => kinds.map((k, i) => ({ step_id: 'step-' + (i + 1) + '-' + k.replace('_', '-'), step_type: k, status: statuses[i] || 'pending', ...(extra[i] || {}) }));
const EX = {
  'exec-401': { rec: { id: 'exec-401', plan_id: 'pl-1', name: 'Ransomware Tabletop + Technical #4', status: 'running', steps_done: 2, steps_total: 5, started_at: iso(35) },
    steps: mkSteps(['send_email', 'approval', 'agent_task', 'wait', 'notify'], ['completed', 'completed', 'running'], { 0: { result: { sent: 24, delivered: 24 } } }), score: null },
  'exec-402': { rec: { id: 'exec-402', plan_id: 'pl-2', name: 'Phishing Response Drill #7', status: 'paused', steps_done: 1, steps_total: 3, started_at: iso(95) },
    steps: mkSteps(['send_email', 'approval', 'agent_task'], ['completed', 'waiting', 'pending'], { 0: { result: { sent: 40, delivered: 38 } } }), score: null },
  'exec-403': { rec: { id: 'exec-403', plan_id: 'pl-1', name: 'Data Exfiltration Exercise #2', status: 'completed', steps_done: 4, steps_total: 4, started_at: iso(60 * 24 * 3) },
    steps: mkSteps(['send_email', 'agent_task', 'approval', 'notify'], ['completed', 'completed', 'completed', 'completed'], { 0: { result: { sent: 24, delivered: 24 } }, 1: { result: { task: 'T1048 exfil over alternative protocol', outcome: 'detected' } } }),
    score: { measurable: true, overall: 72, human: { sent: 24, clicked: 5, click_rate: 0.21 }, technical: { edr_detected: true }, management: { sla_met: true } },
    purple: { detectionRate: 66.7, detected: 2, missed: 1, unresolved: 1, techniques: [{ techniqueId: 'T1048', providers: ['Defender'], outcome: 'detected' }, { techniqueId: 'T1567', providers: ['Splunk'], outcome: 'detected' }, { techniqueId: 'T1041', providers: [], outcome: 'missed' }, { techniqueId: 'T1020', providers: [], outcome: 'unjudged' }], gaps: ['T1041 exfiltration over C2 channel raised no alert'], noExpectation: ['T1029'] } },
  'exec-404': { rec: { id: 'exec-404', plan_id: 'pl-2', name: 'BEC response walkthrough', status: 'completed', steps_done: 3, steps_total: 3, started_at: iso(60 * 24 * 6) },
    steps: mkSteps(['approval', 'wait', 'approval'], ['completed', 'completed', 'completed']), score: { measurable: false, human: { sent: 0 } } },
  'exec-405': { rec: { id: 'exec-405', plan_id: 'pl-1', name: 'Insider data staging #1', status: 'failed', steps_done: 1, steps_total: 4, started_at: iso(60 * 24 * 9) },
    steps: mkSteps(['send_email', 'agent_task', 'wait', 'notify'], ['completed', 'failed'], { 1: { error: 'agent a-9 offline: dispatch timed out after 120s' } }), score: null },
  'exec-406': { rec: { id: 'exec-406', plan_id: 'pl-1', name: 'Ransomware Tabletop + Technical #3', status: 'aborted', steps_done: 1, steps_total: 5, started_at: iso(60 * 24 * 12) },
    steps: mkSteps(['send_email', 'approval', 'agent_task', 'wait', 'notify'], ['completed', 'aborted']), score: null },
  'exec-407': { rec: { id: 'exec-407', plan_id: 'pl-2', name: 'Phishing Response Drill #6', status: 'completed', steps_done: 3, steps_total: 3, started_at: iso(60 * 24 * 15) },
    steps: mkSteps(['send_email', 'wait', 'notify'], ['completed', 'completed', 'completed'], { 0: { result: { sent: 40, delivered: 40 } } }),
    score: { measurable: true, overall: 38, human: { sent: 40, clicked: 25, click_rate: 0.625 }, technical: { edr_detected: false }, management: { sla_met: false } } },
  'exec-408': { rec: { id: 'exec-408', plan_id: 'pl-1', name: 'Ransomware Tabletop + Technical #5', status: 'created', steps_done: 0, steps_total: 5, started_at: '', created_at: iso(5) },
    steps: mkSteps(['send_email', 'approval', 'agent_task', 'wait', 'notify'], []), score: null },
  'exec-409': { rec: { id: 'exec-409', plan_id: 'pl-3', name: 'Imported run with no step counts', status: 'completed', started_at: iso(60 * 24 * 20) }, steps: [], score: null },
};

const ROLE = 'admin';
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };

// boot({ empty }) starts a static server over dist/ plus a page wired to the stateful dummy backend.
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
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  const state = {
    scen: opts.empty ? [] : SCEN.slice(), exs: opts.empty ? [] : EXS.slice(), plans: opts.empty ? [] : PLANS.map((p) => ({ ...p })),
    ex: opts.empty ? {} : JSON.parse(JSON.stringify(EX)), seq: 500, fail: {},
  };
  const reqs = [], dialogs = [], errs = [];
  page.on('pageerror', (e) => errs.push(e.message.slice(0, 140)));
  page.on('dialog', async (d) => { dialogs.push({ type: d.type(), msg: d.message().slice(0, 90) }); if (opts.dialogAnswer === 'accept') await d.accept(opts.promptValue || ''); else await d.dismiss(); });
  await page.addInitScript((role) => { localStorage.setItem('bas_role', role); localStorage.setItem('audspect_theme', 'dark'); }, ROLE);
  const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/*', async (r) => {
    const req = r.request(), u = new URL(req.url()), m = req.method(), path = u.pathname;
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' });
    if (!path.startsWith('/api/exercises') && !path.startsWith('/api/openaev/scenarios')) {
      if (path === '/ready' || path.startsWith('/api/')) { if (m !== 'GET') reqs.push(m + ' ' + path); return json(r, fx(m, u)); }
      return r.continue();
    }
    reqs.push(m + ' ' + path + (u.search || ''));
    const failKey = Object.keys(state.fail).find((k) => path.includes(k));
    if (failKey) return json(r, { error: state.fail[failKey] }, 500);
    let g;
    if (m === 'GET' && path === '/api/openaev/scenarios') return json(r, u.searchParams.get('type') === 'exercise' ? state.exs : state.scen);
    if (m === 'GET' && (g = path.match(/^\/api\/openaev\/scenarios\/([^/]+)$/))) {
      const s = [...state.scen, ...state.exs].find((x) => x.OpenAEVScenarioID === g[1]); if (!s) return json(r, { error: 'not found' }, 404);
      return json(r, { scenario: s, detail: { description: 'Simulates ' + s.Name.toLowerCase() + ' against the estate using ' + s.TechniqueIDs.length + ' mapped techniques.', injects: s.TechniqueIDs.slice(0, 4).map((t, i) => ({ title: 'Inject ' + (i + 1) + ': ' + ['Phish a user', 'Dump credentials', 'Move laterally', 'Stage and exfiltrate'][i], techniqueIds: [t] })) } });
    }
    if (m === 'POST' && (g = path.match(/^\/api\/openaev\/scenarios\/([^/]+)\/create-plan$/))) { state.plans.push(plan('pl-' + (++state.seq), 'Plan from ' + g[1], 3, new Date().toISOString(), [])); return json(r, { ok: true }); }
    if (m === 'GET' && path === '/api/exercises/plans') return json(r, state.plans);
    if (m === 'GET' && (g = path.match(/^\/api\/exercises\/plans\/([^/]+)$/))) return json(r, state.plans.find((p) => p.id === g[1]) || { error: 'not found' }, state.plans.find((p) => p.id === g[1]) ? 200 : 404);
    if (m === 'GET' && path === '/api/exercises/executions') return json(r, Object.values(state.ex).map((e) => e.rec).sort((a, b) => String(b.started_at || b.created_at).localeCompare(String(a.started_at || a.created_at))));
    if (m === 'POST' && path === '/api/exercises/executions') {
      const b = JSON.parse(req.postData() || '{}'); const id = 'exec-' + (++state.seq);
      state.ex[id] = { rec: { id, plan_id: b.plan_id, name: b.name + ' #' + (state.seq - 499), status: 'created', steps_done: 0, steps_total: 4, started_at: '', created_at: new Date().toISOString() }, steps: mkSteps(['send_email', 'approval', 'agent_task', 'notify'], []), score: null, vars: b.variables };
      return json(r, { id });
    }
    if (m === 'POST' && (g = path.match(/^\/api\/exercises\/executions\/([^/]+)\/launch$/))) { const e = state.ex[g[1]]; e.rec.status = 'running'; e.rec.started_at = new Date().toISOString(); e.steps[0].status = 'running'; return json(r, { ok: true }); }
    if (m === 'POST' && (g = path.match(/^\/api\/exercises\/executions\/([^/]+)\/abort$/))) { const e = state.ex[g[1]]; e.rec.status = 'aborted'; e.steps.forEach((s) => { if (s.status === 'running' || s.status === 'waiting') s.status = 'aborted'; }); return json(r, { ok: true }); }
    if (m === 'POST' && (g = path.match(/^\/api\/exercises\/executions\/([^/]+)\/steps\/([^/]+)\/approve$/))) { const e = state.ex[g[1]]; const s = e.steps.find((x) => x.step_id === g[2]); s.status = 'completed'; e.rec.status = 'running'; e.rec.steps_done += 1; return json(r, { ok: true }); }
    if (m === 'GET' && (g = path.match(/^\/api\/exercises\/executions\/([^/]+)\/phishing-runs$/))) return json(r, g[1] === 'exec-403' ? [{ id: 'pr-1', scenarioId: 'phish-credential-harvest', status: 'completed', counts: { sent: 24, clicked: 5, reported: 9 } }] : []);
    if (m === 'GET' && (g = path.match(/^\/api\/exercises\/executions\/([^/]+)\/report\.json$/))) { const e = state.ex[g[1]]; return e && e.purple ? json(r, { purple: e.purple }) : json(r, {}); }
    if (m === 'GET' && (g = path.match(/^\/api\/exercises\/executions\/([^/]+)$/))) { const e = state.ex[g[1]]; return e ? json(r, { execution: { ...e.rec, score: e.score }, steps: e.steps }) : json(r, { error: 'not found' }, 404); }
    return json(r, {});
  });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none');
  await page.waitForTimeout(600);
  const go = async (t = 'exercises') => { await page.evaluate((t) => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t); el && el.click(); }, t); await page.waitForTimeout(1800); };
  const overlays = () => page.evaluate(() => ['exercise-detail-overlay', 'openaev-detail-overlay', 'confirm-diff-overlay', 'report-overlay', 'run-overlay'].filter((id) => { const e = document.getElementById(id); return e && e.classList.contains('open'); }).join(','));
  const toast = () => page.evaluate(() => { const e = document.getElementById('toast'); return e ? (e.className + ': ' + e.textContent).slice(0, 110) : ''; });
  const close = async () => { await browser.close(); server.close(); };
  return { page, state, reqs, dialogs, errs, go, overlays, toast, close, T: 'C:/Users/Administrator/AppData/Local/Temp/' };
}
