import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises'; import { mkdirSync } from 'node:fs';
import { fixtureSet } from './fixtures-rich.mjs';
const out = resolve(process.argv[2]); mkdirSync(out, { recursive: true }); const MODE = process.argv[3] || 'full';
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich');
const PACKS = { enabled: true, can_run: true, packs: [
  { id: 'zone-isolation', name: 'Zone isolation', description: 'Checks that the IT, OT and DMZ zones cannot reach each other except through approved firewall rules.' },
  { id: 'east-west', name: 'East-west controls', description: 'Tests lateral routes between workstations and servers across the core segment.' } ] };
const RUNS = { runs: [
  { id: 'a1b2c3d4-0001', pack_id: 'zone-isolation', status: 'completed', stable: true, runs: 2, requested_by: 'admin', created_at: '2026-11-20T09:15:00Z', failure_reason: '' },
  { id: 'e5f6a7b8-0002', pack_id: 'east-west', status: 'completed', stable: false, runs: 2, requested_by: 'analyst', created_at: '2026-11-19T14:02:00Z', failure_reason: '' },
  { id: 'c9d0e1f2-0003', pack_id: 'zone-isolation', status: 'failed', stable: null, runs: 1, requested_by: 'admin', created_at: '2026-11-18T10:40:00Z', failure_reason: 'lab host unreachable' } ] };
const PROBES = [
  ['it-to-ot-smb', 'IT workstation', '10.10.5.21', '10.50.1.10', 445, 'tcp', 'deny', 'PASS', ['FW-104'], 'Blocked at the zone boundary as expected'],
  ['it-to-ot-rdp', 'IT workstation', '10.10.5.21', '10.50.1.12', 3389, 'tcp', 'deny', 'FAIL', [], 'Reached the OT historian over RDP'],
  ['dmz-to-core-https', 'DMZ web tier', '172.16.2.8', '10.20.0.40', 443, 'tcp', 'allow', 'PASS', ['FW-021'], 'Approved service path reachable'],
  ['dmz-to-core-ssh', 'DMZ web tier', '172.16.2.8', '10.20.0.40', 22, 'tcp', 'deny', 'UNKNOWN', ['FW-031'], 'Rule matched but no response observed'],
  ['guest-to-core-dns', 'Guest Wi-Fi', '192.168.77.14', '10.20.0.53', 53, 'udp', 'deny', 'ERROR', [], 'Probe host disconnected mid-test'] ];
const DETAIL = { run: RUNS.runs[0], probes: PROBES.flatMap((p, i) => [0, 1].map((k) => ({ probe_id: p[0], run_index: k, src: p[2], dst: p[3], dst_port: p[4], proto: p[5], expect: p[6], verdict: p[7], rule_ids: p[8], reason: p[9] }))) };
const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } }); const page = await ctx.newPage();
const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url());
  const json = (b) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(b) });
  if (u.pathname === '/api/segmentation/packs') return json(MODE === 'empty' ? { enabled: true, can_run: true, packs: [] } : PACKS);
  if (u.pathname === '/api/segmentation/runs') return json(MODE === 'empty' ? { runs: [] } : RUNS);
  if (u.pathname.startsWith('/api/segmentation/runs/')) return json(DETAIL);
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return json(fx(req.method(), u));
  if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'segmentation'); el && el.click(); }); await page.waitForTimeout(1300);
await page.evaluate(() => { const r = document.querySelector('#seg-runs tbody tr'); r && r.click(); }); await page.waitForTimeout(900);
const info = await page.evaluate(() => ({ tabVisible: !document.getElementById('tab-segmentation').classList.contains('is-hidden'), packs: document.querySelectorAll('.seg-pack').length, runRows: document.querySelectorAll('#seg-runs tbody tr').length, probeRows: document.querySelectorAll('#seg-detail tbody tr').length, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth }));
console.log(JSON.stringify({ mode: MODE, ...info, errors: errs }));
await page.screenshot({ path: join(out, 'seg-' + MODE + '.png'), fullPage: true });
await browser.close(); server.close();
