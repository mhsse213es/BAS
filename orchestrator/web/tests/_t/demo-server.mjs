// Serves the built console (dist/) with dummy data so it can be browsed in a normal browser.
// There is no orchestrator behind it: every /api/* call is answered from fixtures-rich.mjs, and the
// page is started already signed in as an admin. Nothing you click here changes anything real.
//
//   node tools/build.mjs && node tests/redesign/demo-server.mjs [--port 4180] [--set rich|empty|error]
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import { fixtureSet } from './fixtures-rich.mjs';

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d; };
const port = Number(arg('port', 4180));
const dist = resolve(arg('dist', 'dist'));
const fixtures = fixtureSet(arg('set', 'rich'));
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
// Runs before the app: signed in as admin, but keep a theme the viewer already picked.
const boot = '<script>try{localStorage.setItem("bas_role","admin");if(!localStorage.getItem("audspect_theme"))localStorage.setItem("audspect_theme","dark")}catch(e){}</script>';

createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) {
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(fixtures(req.method, u)));
    return;
  }
  const p = decodeURIComponent(u.pathname);
  const file = join(dist, normalize(p === '/' ? '/index.html' : p).replace(/^([/\\])+/, ''));
  if (!file.startsWith(dist)) { res.writeHead(403).end(); return; }
  try {
    let body = await readFile(file);
    if (extname(file) === '.html') body = Buffer.from(body.toString('utf8').replace('<head>', `<head>${boot}`));
    res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' }).end(body);
  } catch {
    res.writeHead(404).end();
  }
}).listen(port, '127.0.0.1', () => console.log(`Audspect console demo (dummy data): http://127.0.0.1:${port}/`));
