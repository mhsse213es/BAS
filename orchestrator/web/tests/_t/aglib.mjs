// Stateful dummy backend for the Agents page: agents (filter/paging), groups tree, actions, fail switches.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet, richAgents } from './fixtures-rich.mjs';

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const bucketOf = (a) => (a.state === 'retired' ? 'retired' : a.status);

export async function boot(opts = {}) {
  const dist = resolve('dist'), strip = new RegExp('^[/]+');
  const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': TYPES[extname(f)] || 'application/octet-stream' }).end(d); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const fx = fixtureSet('rich');
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: opts.viewport || { width: 1440, height: 900 }, acceptDownloads: true, permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  let agents = opts.empty ? [] : richAgents();
  if (opts.many) { const base = richAgents(); agents = Array.from({ length: opts.many }, (_, i) => ({ ...base[i % base.length], id: 'm-' + i, agentId: 'm-' + i, hostname: 'HOST-' + String(i).padStart(3, '0'), groupId: 1 + (i % 4) })); }
  agents.push({ ...richAgents()[0], id: 'a-ret', agentId: 'a-ret', hostname: 'OLD-BOX', state: 'retired', status: 'offline' });
  const state = { fail: {}, status: {}, calls: [], dialogs: [], answers: [], groups: [{ id: 1, name: 'Finance', parentId: null, totalAgentCount: 3, children: [{ id: 5, name: 'Branch', parentId: 1, totalAgentCount: 1, children: [] }] }, { id: 2, name: 'Domain controllers', parentId: null, totalAgentCount: 3, children: [] }, { id: 3, name: 'Servers', parentId: null, totalAgentCount: 3, children: [] }, { id: 4, name: 'Lab', parentId: null, totalAgentCount: 3, children: [] }], agents };
  const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
  page.on('dialog', async (d) => { state.dialogs.push(d.type() + ': ' + d.message().slice(0, 90)); const a = state.answers.shift(); if (d.type() === 'prompt') await d.accept(a == null ? '' : String(a)); else if (a === false) await d.dismiss(); else await d.accept(); });
  await page.addInitScript((r) => { localStorage.setItem('bas_role', r); localStorage.setItem('audspect_theme', 'dark'); }, opts.role || 'admin');
  const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/*', async (r) => {
    const req = r.request(), u = new URL(req.url()), path = u.pathname, m = req.method();
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' });
    if (!path.startsWith('/api/agent') && !path.startsWith('/api/fleet') && !path.startsWith('/api/ticketing')) { if (path === '/ready' || path.startsWith('/api/')) return json(r, fx(m, u)); return r.continue(); }
    const fk = Object.keys(state.fail).find((k) => (k.includes(':') ? k === m + ':' + path.replace(/\/[^/]+$/, '/*') || k === m + ':' + path : path.includes(k)));
    if (fk) { state.calls.push(m + ' ' + path + ' -> FAIL'); return json(r, { error: state.fail[fk] }, state.status[fk] || 500); }
    let body = {}; try { body = JSON.parse(req.postData() || '{}'); } catch {}
    if (m !== 'GET') state.calls.push(m + ' ' + path + ' ' + JSON.stringify(body).slice(0, 80));
    if (path === '/api/agents' && m === 'GET' && !u.searchParams.has('limit')) return json(r, state.agents);
    if (path === '/api/agents' && m === 'GET') {
      let l = state.agents.slice(); const q = (u.searchParams.get('q') || '').toLowerCase(), b = u.searchParams.get('bucket'), g = u.searchParams.get('groupId');
      if (q) l = l.filter((a) => a.hostname.toLowerCase().includes(q)); if (b) l = l.filter((a) => bucketOf(a) === b); if (g) l = l.filter((a) => String(a.groupId) === g);
      const all = state.agents, cnt = (s) => all.filter((a) => bucketOf(a) === s).length;
      const lim = Number(u.searchParams.get('limit')) || 100, cur = Number(u.searchParams.get('cursor')) || 0;
      const items = l.slice(cur, cur + lim);
      return json(r, { items, next_cursor: cur + lim < l.length ? String(cur + lim) : '', has_more: cur + lim < l.length, totals: { online: cnt('online'), degraded: cnt('degraded'), offline: cnt('offline'), retired: cnt('retired') } });
    }
    if (path === '/api/agent-groups' && m === 'GET') return json(r, state.groups);
    if (path === '/api/agent-groups' && m === 'POST') { state.groups.push({ id: 90 + state.groups.length, name: body.name, parentId: body.parentId, totalAgentCount: 0, children: [] }); return json(r, { id: 99 }, 201); }
    if (path.startsWith('/api/agent-groups/') && m === 'PATCH') { const g = state.groups.find((x) => String(x.id) === path.split('/').pop()); if (g && body.name) g.name = body.name; return json(r, {}); }
    if (path.startsWith('/api/agent-groups/') && m === 'DELETE') { state.groups = state.groups.filter((x) => String(x.id) !== path.split('/').pop()); return r.fulfill({ status: 204 }); }
    const act = path.match(/^\/api\/agents\/([^/]+)\/(stop|uninstall|revoke|reinstate|allow-reinstall|remove|group|state)$/);
    if (act && m !== 'GET') { const a = state.agents.find((x) => x.agentId === act[1]); if (a && act[2] === 'remove') a.state = 'retired'; if (a && act[2] === 'revoke') a.state = 'revoked'; if (a && act[2] === 'reinstate') a.state = 'active'; if (a && act[2] === 'state') a.state = body.state || a.state; return json(r, {}); }
    if (path === '/api/fleet/min-agent-version') return json(r, { version: '', source: '', default: '1.9.2' });
    if (path === '/api/fleet/tray-icon') return json(r, { hidden: false });
    if (path === '/api/agent-binaries/revocations') return json(r, { items: [] });
    if (path.match(/\/api\/agents\/[^/]+\/(state|risk|telemetry)/) || path.startsWith('/api/agents/')) return json(r, fx(m, u));
    return json(r, fx(m, u));
  });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none');
  await page.waitForTimeout(700);
  const go = async () => { await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'agents'); el && el.click(); }); await page.waitForTimeout(1800); };
  const toast = () => page.evaluate(() => { const e = document.getElementById('toast'); return e ? (e.className + ': ' + e.textContent).slice(0, 200) : ''; });
  const close = async () => { await browser.close(); server.close(); };
  return { page, state, errs, go, toast, close, T: 'C:/Users/Administrator/AppData/Local/Temp/' };
}
