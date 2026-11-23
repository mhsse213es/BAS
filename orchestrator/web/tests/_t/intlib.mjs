// Stateful dummy backend for the Integrations page (ITSM + EPP + TAXII). Failure switches: state.fail['POST /api/ticketing/configs'] = 'msg'
// (matches "METHOD path" or any path containing the key); state.status[key] sets the HTTP status (default 500).
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const ago = (m) => new Date(Date.now() - m * 60000).toISOString();
export function seed() {
  return {
    itsm: [
      { id: 'i1', name: 'ServiceNow Production', provider: 'servicenow', enabled: true, autoCreate: 'critical', autoUpdate: true, autoClose: true, lastTestOk: true, lastTestAt: ago(12), settings: { instance_url: 'https://acme.service-now.com', username: 'svc_bas', password: '***', insecure_tls: '' } },
      { id: 'i2', name: 'Jira SEC board', provider: 'jira', enabled: true, autoCreate: 'off', autoUpdate: true, autoClose: false, lastTestOk: false, lastTestAt: ago(300), lastTestError: 'HTTP 401: invalid credentials for https://jira.acme.example', settings: { base_url: 'https://jira.acme.example', username: 'bas@acme.example', api_token: '***', project_key: 'SEC' } },
      { id: 'i3', name: 'Ops webhook', provider: 'webhook', enabled: true, autoCreate: 'critical_high', autoUpdate: false, autoClose: false, lastTestOk: null, settings: { url: 'https://hooks.acme.example/bas', secret: '***' } },
      { id: 'i4', name: 'Legacy ServiceNow (old)', provider: 'servicenow', enabled: false, autoCreate: 'off', autoUpdate: false, autoClose: false, lastTestOk: true, lastTestAt: ago(60 * 24 * 9), settings: { instance_url: 'https://old.service-now.com', username: 'x', password: '***' } },
    ],
    epp: [
      { id: 'e1', name: 'Prod CrowdStrike', provider: 'crowdstrike', enabled: true, baseUrl: 'https://api.crowdstrike.com', clientId: 'cs-client-1' },
      { id: 'e2', name: 'Defender tenant', provider: 'microsoft_defender', enabled: false, tenantId: 'b1c2-tenant', killProcessScriptName: 'Audspect-KillProcess.ps1', clientId: 'ms-client-1' },
    ],
    taxii: [
      { id: 't1', name: 'FS-ISAC Production', serverUrl: 'https://taxii.fsisac.example/taxii2/', apiRoot: 'api1', collectionId: 'c-1', authType: 'basic', username: 'u', enabled: true, lastPollAt: ago(25), lastPollStatus: 'ok', lastPollSummary: { processed: 40, skipped: 2, malformed: 0 } },
      { id: 't2', name: 'Auto-ISAC (staging)', serverUrl: 'https://taxii.autoisac.example/', authType: 'none', enabled: true, lastPollStatus: 'error', lastError: 'dial tcp: i/o timeout', lastPollAt: ago(90) },
    ],
    reval: 0,
  };
}
export async function boot(opts = {}) {
  const dist = resolve('dist'), strip = new RegExp('^[/]+');
  const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404); return s.end(); } const ext = f.slice(f.lastIndexOf('.')); s.writeHead(200, { 'content-type': TYPES[ext] || 'application/octet-stream' }); s.end(d); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const fx = fixtureSet('rich');
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: opts.viewport || { width: 1440, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  const base = seed(); const state = Object.assign({ fail: {}, status: {}, calls: [], dialogs: [], delay: {} }, base, opts.data || {});
  const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
  page.on('dialog', async (d) => { state.dialogs.push(d.type() + ': ' + d.message().slice(0, 80)); await d.accept(); });
  await page.addInitScript((t) => { localStorage.setItem('bas_role', t[0]); localStorage.setItem('audspect_theme', t[1]); }, [opts.role || 'admin', opts.theme || 'dark']);
  const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  let seq = 100;
  const MINE = ['/api/ticketing/', '/api/actions/configs', '/api/taxii/'];
  await page.route('**/*', async (r) => {
    const req = r.request(), u = new URL(req.url()), path = u.pathname, m = req.method();
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' });
    if (!MINE.some((p) => path.startsWith(p))) { if (path === '/ready' || path.startsWith('/api/')) return json(r, fx(m, u)); return r.continue(); }
    const body = m === 'GET' || m === 'DELETE' ? null : (() => { try { return JSON.parse(req.postData() || '{}'); } catch { return {}; } })();
    state.calls.push(m + ' ' + path + (body ? ' ' + JSON.stringify(body).slice(0, 220) : ''));
    const fk = Object.keys(state.fail).find((k) => state.fail[k] && (k.includes(' ') ? k === m + ' ' + path : path.includes(k)));
    if (state.delay[path]) await new Promise((x) => setTimeout(x, state.delay[path]));
    if (fk) return json(r, { error: state.fail[fk] }, state.status[fk] || 500);
    const idOf = () => path.split('/')[path.startsWith('/api/actions') ? 4 : path.startsWith('/api/taxii') ? 4 : 4];
    // ── ITSM
    if (path === '/api/ticketing/configs' && m === 'GET') return json(r, state.itsm);
    if (path === '/api/ticketing/configs' && m === 'POST') { const c = Object.assign({ id: 'i' + ++seq, lastTestOk: null }, body); state.itsm.push(c); return json(r, c); }
    if (path.startsWith('/api/ticketing/configs/') && path.endsWith('/test')) { const c = state.itsm.find((x) => x.id === idOf()); const ok = !(c && /fail/i.test(c.name)); if (c) { c.lastTestOk = ok; c.lastTestAt = new Date().toISOString(); if (!ok) c.lastTestError = 'connection refused'; } return json(r, ok ? { ok: true } : { ok: false, error: 'connection refused' }); }
    if (path.startsWith('/api/ticketing/configs/') && m === 'PUT') { const i = state.itsm.findIndex((x) => x.id === idOf()); if (i < 0) return json(r, { error: 'not found' }, 404); state.itsm[i] = Object.assign({}, state.itsm[i], body); return json(r, state.itsm[i]); }
    if (path.startsWith('/api/ticketing/configs/') && m === 'DELETE') { state.itsm = state.itsm.filter((x) => x.id !== idOf()); return json(r, { ok: true }); }
    if (path === '/api/ticketing/probe/projects') return json(r, body.provider === 'jira' ? { ok: true, projects: [{ key: 'SEC', name: 'Security' }, { key: 'OPS', name: 'Operations' }] } : { ok: false, error: 'not supported' });
    if (path === '/api/ticketing/probe') return json(r, /bad/.test(JSON.stringify(body)) ? { ok: false, error: 'authentication failed' } : { ok: true });
    if (path === '/api/ticketing/sync') return json(r, { status: 'sync started' });
    if (path === '/api/ticketing/revalidation') return json(r, { pendingRevalidation: state.reval });
    if (path === '/api/ticketing/summary') return json(r, {});
    // ── EPP
    if (path === '/api/actions/configs' && m === 'GET') return json(r, state.epp);
    if (path === '/api/actions/configs' && m === 'POST') { const c = Object.assign({ id: 'e' + ++seq }, body); delete c.clientSecret; delete c.apiToken; state.epp.push(c); return json(r, c); }
    if (path.startsWith('/api/actions/configs/') && path.endsWith('/test')) return json(r, { ok: true });
    if (path.startsWith('/api/actions/configs/') && m === 'PUT') { const i = state.epp.findIndex((x) => x.id === idOf()); if (i < 0) return json(r, { error: 'not found' }, 404); const b = Object.assign({}, body); delete b.clientSecret; delete b.apiToken; state.epp[i] = Object.assign({}, state.epp[i], b); return json(r, state.epp[i]); }
    if (path.startsWith('/api/actions/configs/') && m === 'DELETE') { state.epp = state.epp.filter((x) => x.id !== idOf()); return json(r, { ok: true }); }
    // ── TAXII
    if (path === '/api/taxii/connectors' && m === 'GET') return json(r, state.taxii);
    if (path === '/api/taxii/connectors' && m === 'POST') { const c = Object.assign({ id: 't' + ++seq }, body); delete c.password; state.taxii.push(c); return json(r, c); }
    if (path === '/api/taxii/connectors/test') return json(r, { ok: true, collectionCount: 3 });
    if (path.endsWith('/sync')) { const c = state.taxii.find((x) => x.id === idOf()); if (c) { c.lastPollAt = new Date().toISOString(); c.lastPollStatus = 'ok'; c.lastPollSummary = { processed: 5, skipped: 0, malformed: 0 }; } return json(r, { ok: true }); }
    if (path.startsWith('/api/taxii/connectors/') && m === 'PUT') { const i = state.taxii.findIndex((x) => x.id === idOf()); if (i < 0) return json(r, { error: 'not found' }, 404); const b = Object.assign({}, body); delete b.password; state.taxii[i] = Object.assign({}, state.taxii[i], b); return json(r, state.taxii[i]); }
    if (path.startsWith('/api/taxii/connectors/') && m === 'DELETE') { state.taxii = state.taxii.filter((x) => x.id !== idOf()); return json(r, { ok: true }); }
    return json(r, {});
  });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none');
  await page.waitForTimeout(700);
  const go = async (tab = 'integrations') => { await page.evaluate((t) => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t); el && el.click(); }, tab); await page.waitForTimeout(1200); };
  const toast = () => page.evaluate(() => { const e = document.getElementById('toast'); return e ? (e.className + ': ' + e.textContent).slice(0, 200) : ''; });
  const close = async () => { await browser.close(); server.close(); };
  return { page, state, errs, go, toast, close, T: 'C:/Users/Administrator/AppData/Local/Temp/' };
}
