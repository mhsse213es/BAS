// Read-only repro: when does the shell (#app) show through/over the login screen?
import { chromium } from 'playwright-core';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
const dist = resolve('dist'); const out = resolve(process.argv[2] || '.');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const strip = new RegExp('^([/\\\\])+');
const server = createServer(async (req, res) => {
  const p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, ''));
  try { res.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(await readFile(f)); } catch { res.writeHead(404).end(); }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
async function run(name, { role, agentsStatus }) {
  const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  await page.addInitScript((r) => { if (r) localStorage.setItem('bas_role', r); }, role);
  await page.route('**/*', (route) => {
    const u = new URL(route.request().url());
    if (u.pathname === '/ready') return route.fulfill({ status: 200, contentType: 'application/json', body: '{"version":"1.0.0"}' });
    if (u.pathname === '/api/license/status') return route.fulfill({ status: 200, contentType: 'application/json', body: '{"state":"valid"}' });
    if (u.pathname.startsWith('/api/')) { const st = u.pathname === '/api/agents' ? agentsStatus : 500; return route.fulfill({ status: st, contentType: 'application/json', body: st === 200 ? '[]' : '{"error":"x"}' }); }
    if (u.hostname !== '127.0.0.1') return route.fulfill({ status: 204, body: '' });
    return route.continue();
  });
  await page.routeWebSocket(/\/ws\//, () => {});
  await page.goto(origin + '/index.html'); await page.waitForTimeout(1500);
  const st = await page.evaluate(() => {
    const cs = (id) => { const e = document.getElementById(id); const s = getComputedStyle(e); return { display: s.display, position: s.position, z: s.zIndex }; };
    const sb = document.getElementById('sidebar'); const r = sb.getBoundingClientRect();
    return { app: cs('app'), login: cs('login-screen'), sidebar: { z: getComputedStyle(sb).zIndex, pos: getComputedStyle(sb).position, w: Math.round(r.width) }, storedRole: localStorage.getItem('bas_role') };
  });
  await page.screenshot({ path: join(out, `login-${name}.png`) });
  console.log(name.padEnd(20), JSON.stringify(st)); await page.close();
}
await run('fresh-no-role', { role: null, agentsStatus: 200 });
await run('role-agents-401', { role: 'admin', agentsStatus: 401 });
await run('role-agents-500', { role: 'admin', agentsStatus: 500 });
await run('role-agents-200', { role: 'admin', agentsStatus: 200 });
await browser.close(); server.close();
