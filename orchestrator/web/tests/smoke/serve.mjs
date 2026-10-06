// Minimal static server for the smoke harness. API calls never reach it:
// the Playwright test intercepts /api/* and /ready before they leave the page.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';

const root = resolve(process.argv[2]);
const port = Number(process.argv[3] || 4173);
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2' };
// SMOKE_CSP=enforce|report-only serves the dashboard policy (G1d), read from
// csp-policy.txt -- the same text the Go server's test pins.
const cspMode = process.env.SMOKE_CSP || '';
const csp = readFileSync(new URL('./csp-policy.txt', import.meta.url), 'utf8').trim();
const cspHeader = cspMode === 'enforce' ? 'Content-Security-Policy' : cspMode === 'report-only' ? 'Content-Security-Policy-Report-Only' : '';

createServer(async (req, res) => {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const rel = normalize(urlPath === '/' ? '/index.html' : urlPath).replace(/^([/\\])+/, '');
  const file = join(root, rel);
  if (!file.startsWith(root)) { res.writeHead(403).end(); return; }
  try {
    const body = await readFile(file);
    const headers = { 'Content-Type': types[extname(file)] || 'application/octet-stream' };
    if (cspHeader) headers[cspHeader] = csp;
    res.writeHead(200, headers).end(body);
  } catch {
    res.writeHead(404).end();
  }
}).listen(port, () => console.log(`smoke server: ${root} on ${port}`));
