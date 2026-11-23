// Stateful dummy backend for the Settings page (users, engine, threat intel, TAXII, ART, audit, license, backups).
// Failure switches: state.fail['POST /api/users'] = 'msg' (matches "METHOD path" or any path containing the key);
// state.status[key] sets the HTTP status (default 500). state.delay[path] = ms.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';
import { seed as intSeed } from './intlib.mjs';
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const ago = (m) => new Date(Date.now() - m * 60000).toISOString();
export function seed() {
  const audit = Array.from({ length: 120 }, (_, i) => ({ id: 'a' + i, ts: ago(i * 7), actorName: ['admin', 'priya', 'svc-bas'][i % 3], action: ['user.login', 'scenario.run', 'user.update', 'report.export', 'connector.sync', 'finding.status_change'][i % 6], resource: 'res-' + i, detail: JSON.stringify(i % 6 === 1 ? { scenarioId: 'S-' + i, mode: 'safe' } : i % 6 === 2 ? { username: 'priya', role: 'analyst' } : {}), ip: '10.0.0.' + (i % 20), outcome: i % 17 === 0 ? 'fail' : i % 11 === 0 ? 'warn' : 'ok' }));
  return {
    users: [
      { id: 'u1', username: 'admin', role: 'admin', isActive: true, createdAt: ago(60 * 24 * 90), lastLogin: ago(5) },
      { id: 'u2', username: 'priya', role: 'analyst', isActive: true, createdAt: ago(60 * 24 * 40), lastLogin: ago(60 * 5) },
      { id: 'u3', username: 'ravi', role: 'viewer', isActive: false, createdAt: ago(60 * 24 * 12) },
      { id: 'u4', username: 'temp.contractor', role: 'viewer', isActive: true, mustChangePw: true, createdAt: ago(60 * 24 * 2) },
    ],
    caldera: { reachable: true, url: 'https://caldera.lab:8888', version: '5.0.0', abilityCount: 1840, byPlugin: { stockpile: 700, atomic: 1100, manx: 40 }, uniqueTechniques: 210, adversaryCount: 12, latencyMs: 38 },
    connector: { mispEnabled: true, openctiEnabled: false, otxEnabled: true, bundleEnabled: false, bySource: { misp: { rawCount: 1280, actorCount: 44, fetchedAt: ago(30) } }, lastSyncAt: ago(30), lastSyncStatus: 'ok', scenariosCreated: 12, scenariosUpdated: 3, nextSyncAt: new Date(Date.now() + 3600000).toISOString() },
    ti: { misp: { baseUrl: 'https://misp.acme.local', enabled: true, configured: true, insecureTls: false }, opencti: { baseUrl: '', enabled: false, configured: false }, otx: { baseUrl: '', enabled: true, configured: true } },
    oaev: { baseUrl: 'https://openaev.acme.local', enabled: true, configured: true },
    taxii: intSeed().taxii,
    art: { seeded: true, version: '2026.10', techniquesLoaded: 312, techniqueCount: 312, testCount: 1500, payloadCount: 240, windowsRunnable: 290, kevCount: 41, source: 'content-pack', missingPayloadCount: 0 },
    audit,
    license: { status: 'valid', customer: 'Acme Corp', customerId: 'ACME-001', issuedAt: '2026-01-01', expiresAt: '2027-01-01', tier: 'Enterprise', features: ['edr', 'dlp', 'reports'], productLines: ['av', 'waf', 'email'], daysRemaining: 400 },
    backups: [
      { id: 'b1', requestedAt: ago(60 * 3), trigger: 'manual', localPath: '/var/backups/a.tar', remotePath: 's3://x/a.tar', status: 'protected', archiveSizeBytes: 52428800 },
      { id: 'b2', requestedAt: ago(60 * 27), trigger: 'scheduled', localPath: '/var/backups/b.tar', status: 'local_success', archiveSizeBytes: 51000000 },
      { id: 'b3', requestedAt: ago(60 * 51), trigger: 'scheduled', status: 'failed', errorMessage: 'disk full' },
    ],
  };
}
export async function boot(opts = {}) {
  const dist = resolve('dist'), strip = new RegExp('^[/]+');
  const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404); return s.end(); } const ext = f.slice(f.lastIndexOf('.')); s.writeHead(200, { 'content-type': TYPES[ext] || 'application/octet-stream' }); s.end(d); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const fx = fixtureSet('rich');
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: opts.viewport || { width: 1440, height: 900 }, acceptDownloads: true, permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  const state = Object.assign({ fail: {}, status: {}, calls: [], dialogs: [], delay: {}, prompts: [] }, seed(), opts.data || {});
  const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
  page.on('dialog', async (d) => { state.dialogs.push(d.type() + ': ' + d.message().slice(0, 90)); if (d.type() === 'prompt') await d.accept(state.promptAnswer == null ? 'Temp#Passw0rd' : state.promptAnswer); else await d.accept(); });
  await page.addInitScript((t) => { localStorage.setItem('bas_role', t[0]); localStorage.setItem('audspect_theme', t[1]); }, [opts.role || 'admin', opts.theme || 'dark']);
  const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  let seq = 100;
  const MINE = ['/api/users', '/api/caldera/status', '/api/connector/', '/api/threat-intel/', '/api/openaev/', '/api/taxii/', '/api/art/content', '/api/audit-logs', '/api/license', '/api/backups'];
  await page.route('**/*', async (r) => {
    const req = r.request(), u = new URL(req.url()), path = u.pathname, m = req.method();
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' });
    if (!MINE.some((p) => path.startsWith(p))) { if (path === '/ready' || path.startsWith('/api/')) return json(r, fx(m, u)); return r.continue(); }
    const body = m === 'GET' || m === 'DELETE' ? null : (() => { try { return JSON.parse(req.postData() || '{}'); } catch { return {}; } })();
    state.calls.push(m + ' ' + path + u.search + (body ? ' ' + JSON.stringify(body).slice(0, 200) : ''));
    const fk = Object.keys(state.fail).find((k) => state.fail[k] && (k.includes(' ') ? k === m + ' ' + path : path.includes(k)));
    if (state.delay[path]) await new Promise((x) => setTimeout(x, state.delay[path]));
    if (fk) return json(r, { error: state.fail[fk] }, state.status[fk] || 500);
    const seg = path.split('/');
    // users
    if (path === '/api/users' && m === 'GET') return json(r, state.users);
    if (path === '/api/users' && m === 'POST') { if (state.users.some((x) => x.username === body.username)) return json(r, { error: 'username already exists' }, 409); const c = { id: 'u' + ++seq, username: body.username, role: body.role, isActive: true, mustChangePw: true, createdAt: new Date().toISOString() }; state.users.push(c); return json(r, c); }
    if (seg[3] && path.startsWith('/api/users/') && path.endsWith('/reset-password')) { const c = state.users.find((x) => x.id === seg[3]); if (c) c.mustChangePw = true; return json(r, { ok: true }); }
    if (seg[3] && path.startsWith('/api/users/') && m === 'PUT') { const c = state.users.find((x) => x.id === seg[3]); if (!c) return json(r, { error: 'not found' }, 404); Object.assign(c, body); return json(r, c); }
    // engine
    if (path === '/api/caldera/status') return json(r, state.caldera);
    // connector status / sync
    if (path === '/api/connector/status') return json(r, state.connector);
    if (path === '/api/connector/sync') { state.connector.lastSyncAt = new Date().toISOString(); return json(r, { status: 'queued' }); }
    // threat-intel configs
    if (seg[2] === 'threat-intel' && path.endsWith('/config/test')) return json(r, /bad/.test(JSON.stringify(body)) ? { ok: false, error: '401 unauthorized' } : { ok: true, actorCount: 128 });
    if (seg[2] === 'threat-intel' && path.endsWith('/config')) { const n = seg[3]; if (m === 'GET') return json(r, state.ti[n] || {}); if (m === 'PUT') { state.ti[n] = Object.assign({}, state.ti[n], { baseUrl: body.baseUrl, enabled: body.enabled, insecureTls: body.insecureTls, configured: true }); return json(r, state.ti[n]); } if (m === 'DELETE') { state.ti[n] = { baseUrl: '', enabled: false, configured: false }; return json(r, { ok: true }); } }
    // openaev
    if (path === '/api/openaev/config') { if (m === 'GET') return json(r, state.oaev); if (m === 'PUT') { Object.assign(state.oaev, { baseUrl: body.baseUrl, enabled: body.enabled, configured: true }); return json(r, state.oaev); } if (m === 'DELETE') { state.oaev = { baseUrl: '', enabled: false, configured: false }; return json(r, { ok: true }); } }
    if (path === '/api/openaev/config/test') return json(r, { ok: true });
    if (path === '/api/openaev/status') return json(r, { lastSyncStatus: 'ok', lastSyncCreated: 4, lastSyncUpdated: 1 });
    if (path === '/api/openaev/sync') return json(r, { ok: true });
    // taxii
    if (path === '/api/taxii/connectors' && m === 'GET') return json(r, state.taxii);
    if (path === '/api/taxii/connectors' && m === 'POST') { const c = Object.assign({ id: 't' + ++seq }, body); delete c.password; state.taxii.push(c); return json(r, c); }
    if (path === '/api/taxii/connectors/test') return json(r, { ok: true, collectionCount: 3 });
    if (path.startsWith('/api/taxii/connectors/') && path.endsWith('/sync')) return json(r, { ok: true });
    if (path.startsWith('/api/taxii/connectors/') && m === 'PUT') { const i = state.taxii.findIndex((x) => x.id === seg[4]); if (i >= 0) state.taxii[i] = Object.assign({}, state.taxii[i], body); return json(r, {}); }
    if (path.startsWith('/api/taxii/connectors/') && m === 'DELETE') { state.taxii = state.taxii.filter((x) => x.id !== seg[4]); return json(r, { ok: true }); }
    // ART
    if (path === '/api/art/content/status') return json(r, state.art);
    if (path === '/api/art/content/reseed') return json(r, { techniqueCount: 312, payloadCount: 240 });
    // audit
    if (path === '/api/audit-logs') { const lim = Number(u.searchParams.get('limit')) || 50, off = Number(u.searchParams.get('offset')) || 0; const a = u.searchParams.get('action'), ac = (u.searchParams.get('actor') || '').toLowerCase(); let rows = state.audit.filter((e) => (!a || e.action === a) && (!ac || e.actorName.toLowerCase().includes(ac))); return json(r, { entries: rows.slice(off, off + lim), total: rows.length }); }
    // license
    if (path === '/api/license') return json(r, state.license);
    // backups
    if (path === '/api/backups' && m === 'GET') return json(r, state.backups);
    if (path === '/api/backups' && m === 'POST') { const j = { id: 'b' + ++seq, requestedAt: new Date().toISOString(), trigger: 'manual', status: 'running' }; state.backups.unshift(j); state.running = j; setTimeout(() => { j.status = 'protected'; j.localPath = '/var/backups/n.tar'; j.remotePath = 's3://x/n.tar'; j.archiveSizeBytes = 53000000; }, state.backupMs || 2500); return json(r, j); }
    if (path.endsWith('/restore-marker')) return json(r, { restoreCommand: 'sudo ./restore.sh --backup ' + seg[3] });
    if (path.startsWith('/api/backups/') && m === 'GET') { const j = state.backups.find((x) => x.id === seg[3]); return j ? json(r, j) : json(r, { error: 'not found' }, 404); }
    return json(r, {});
  });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none');
  await page.waitForTimeout(700);
  const go = async (sec) => { await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'settings'); el && el.click(); }); await page.waitForTimeout(500); if (sec) { await page.evaluate((s) => { const el = document.querySelector('[data-set="' + s + '"]'); el && el.click(); }, sec); await page.waitForTimeout(1200); } };
  const toast = () => page.evaluate(() => { const e = document.getElementById('toast'); return e ? (e.className + ': ' + e.textContent).slice(0, 220) : ''; });
  const close = async () => { await browser.close(); server.close(); };
  return { page, state, errs, go, toast, close, T: 'C:/Users/Administrator/AppData/Local/Temp/' };
}
