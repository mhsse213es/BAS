import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { mkdirSync } from 'node:fs'; import { extname, join, normalize, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixtureSet } from './fixtures-rich.mjs';
const out = resolve(process.argv[2]); mkdirSync(out, { recursive: true });
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich');
const CAT = { scenarios: [
  { id: 'aws-bucket', name: 'Bucket walk', provider: 'aws', description: 'Reads buckets', steps: [{}] },
  { id: 'az-vault', name: 'Vault read', provider: 'azure', description: 'Reads vaults', steps: [{}, {}] },
  { id: 'aws-role', name: 'Role chain', provider: 'aws', description: 'Role chain', steps: [{}] } ] };
let runsFail = true; const posted = [];
const browser = await chromium.launch(); const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
const errs = []; page.on('pageerror', (e) => errs.push(e.message));
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url());
  if (u.pathname === '/api/cloud-scenarios') return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(CAT) });
  if (u.pathname === '/api/cloud-runs' && req.method() === 'GET') { if (runsFail) return r.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"db down"}' }); return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([{ id: 'r1', startedAt: new Date().toISOString(), label: 'x', account: '111', status: 'completed', initiatedBy: 'me' }]) }); }
  if (u.pathname === '/api/cloud-scenario-runs' && req.method() === 'POST') { posted.push(JSON.parse(req.postData())); return r.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ id: 'r1', status: 'completed' }) }); }
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
  if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(800);
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'cloud-scenarios'); el && el.click(); });
await page.waitForTimeout(1000);
const opts = () => page.$$eval('#cloud-run-scenario option', (o) => o.map((x) => x.value));
const prov = () => page.$eval('#cloud-run-provider', (s) => s.value);
const report = {};
report.initialOpts = await opts(); report.initialProv = await prov();
report.runsRetry = await page.$eval('#cloud-runs-list', (e) => e.innerText);
await page.selectOption('#cloud-run-provider', 'azure'); await page.waitForTimeout(200);
report.afterAzureOpts = await opts();
await page.selectOption('#cloud-run-scenario', 'az-vault'); await page.waitForTimeout(100);
await page.selectOption('#cloud-run-provider', 'aws'); await page.waitForTimeout(200);
report.afterAwsOpts = await opts(); report.afterAwsScenario = await page.$eval('#cloud-run-scenario', (s) => s.value);
await page.selectOption('#cloud-run-scenario', 'aws-bucket');
report.provAfterAwsPick = await prov();
await page.fill('#cloud-run-account', '111111111111'); await page.fill('#cloud-run-principal', 'arn:aws:iam::1:role/a'); await page.fill('#cloud-run-resource', 'bkt');
await page.click('#cloud-run-submit'); await page.waitForTimeout(600);
report.posted = posted; report.resultText = await page.$eval('#cloud-run-result', (e) => e.innerText);
await page.evaluate(() => { const s = document.getElementById('cloud-run-scenario'); const o = document.createElement('option'); o.value = 'az-vault'; s.appendChild(o); s.value = 'az-vault'; });
await page.click('#cloud-run-submit'); await page.waitForTimeout(300);
report.mismatchText = await page.$eval('#cloud-run-result', (e) => e.innerText); report.postCountAfterMismatch = posted.length;
runsFail = false; await page.click('#cloud-runs-list button'); await page.waitForTimeout(500);
report.runsAfterRetry = await page.$eval('#cloud-runs-list', (e) => e.innerText.slice(0, 60));
const clip = await page.$eval('#cloud-run-form', (e) => { const r = e.getBoundingClientRect(); return { x: r.x, y: r.y + scrollY, width: r.width, height: r.height }; });
await page.screenshot({ path: join(out, 'run-form.png'), fullPage: true, clip: { x: clip.x, y: clip.y, width: clip.width, height: clip.height } });
for (const [id, name] of [['cloud-disc-form','disc-form.png'],['cloud-runs-list','recent-runs.png']]) {
  const c = await page.$eval('#' + id, (e) => { e = e.closest('.cloud-recent') || e; const r = e.getBoundingClientRect(); return { x: r.x, y: r.y + scrollY, width: r.width, height: r.height }; });
  await page.screenshot({ path: join(out, name), fullPage: true, clip: c });
}
report.tone = await page.evaluate(() => [document.getElementById('cloud-run-provider').dataset.provider, document.getElementById('cloud-disc-provider').dataset.provider]);
await page.selectOption('#cloud-disc-provider', 'gcp'); await page.waitForTimeout(150);
report.discGcp = await page.$eval('#cloud-disc-provider', (e) => e.dataset.provider);
await page.selectOption('#cloud-disc-provider', 'aws'); await page.waitForTimeout(150);
const bc = await page.$eval('#cloud-run-provider', (e) => getComputedStyle(e).borderTopColor);
report.runAwsBorder = bc;
report.colours = {};
for (const sel of ['#cloud-run-provider', '#cloud-disc-provider']) for (const v of ['azure', 'gcp', 'aws']) {
  await page.selectOption(sel, v); await page.waitForTimeout(150);
  report.colours[sel + ':' + v] = await page.$eval(sel, (e) => { const c = getComputedStyle(e); return [e.dataset.provider, c.borderTopColor, c.boxShadow.slice(0, 60)]; });
}
for (const v of ['azure','gcp']) { await page.selectOption('#cloud-run-provider', v); await page.waitForTimeout(150); await page.locator('#cloud-run-form').screenshot({ path: join(out, 'run-' + v + '.png') }); }
report.pageErrors = errs;
console.log(JSON.stringify(report, null, 1));
await browser.close(); server.close();
