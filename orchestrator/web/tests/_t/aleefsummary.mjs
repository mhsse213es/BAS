import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { extname, join, normalize, resolve } from 'node:path'; import { readFile } from 'node:fs/promises'; import { mkdirSync } from 'node:fs';
import { fixtureSet } from './fixtures-rich.mjs';
const out = resolve(process.argv[2]); mkdirSync(out, { recursive: true });
const dist = resolve('dist'); const strip = new RegExp('^[/]+');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (q, s) => { const p = decodeURIComponent(new URL(q.url, 'http://x').pathname); const f = join(dist, normalize(p === '/' ? '/index.html' : p).replace(strip, '')); let d; try { d = await readFile(f); } catch { s.writeHead(404).end(); return; } s.writeHead(200, { 'Content-Type': types[extname(f)] || 'application/octet-stream' }).end(d); });
await new Promise((r) => server.listen(0, '127.0.0.1', r)); const origin = 'http://127.0.0.1:' + server.address().port;
const fx = fixtureSet('rich'); const browser = await chromium.launch();
const RUN = { run_id: '074ed860-5126-4d76-957c-ccc7d17e735b', status: 'completed', engagement_id: 'eng-0001', created_at: '2026-11-21T06:50:26Z', finished_at: '2026-11-21T06:50:27Z', halted_reason: '', orphans: [],
  report: { Requests: 0, Findings: null, Verified: 0, Total: 0, Executed: 0, NotExecuted: 0, Halted: '', Model: { Operations: 1, Runnable: 1 },
    Generated: { NoFixtureOps: { get_accounts_by_id: 'account' } },
    PerOperation: { get_accounts_by_id: { Class: 'read', Generated: 0, Executed: 0, NotExecuted: 0, Findings: 0, Verified: 0, Skipped: '' } } } };
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
const errs = []; page.on('pageerror', (e) => errs.push(e.message.slice(0, 140)));
await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url());
  if (u.pathname === '/api/aleef/findings' && req.method() === 'GET') return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({candidates:[],verified:[{id:'f1',run_id:'899b2eb7',test_id:'ALEEF-GEN-P-IDEM-1-d8b77024',property_id:'P-IDEM-1',title:'Idempotency property P-IDEM-1 violated',state:'verified',evidence_hash:'0c17372cdd2a1a337557d0c0708fc33362d295348972f4978b3cee3d6e7e7b93',prior_knowledge:'not_checked',novelty_label:'prior_reports_not_checked',regression_id:'reg-1',created_at:'2026-11-21T06:50:27Z',updated_at:'2026-11-21T06:50:27Z'}],pending_regression:[],unconfirmed:[],rejected:[]}) });
  if (u.pathname === '/api/aleef/runs/074ed860-5126-4d76-957c-ccc7d17e735b' && req.method() === 'GET') return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(RUN) });
  if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
  if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
await page.routeWebSocket(/ws/, () => {});
await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(700);
await page.evaluate(() => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === 'aleef'); el && el.click(); }); await page.waitForTimeout(1000);
await page.fill('#aleef-load-run', '074ed860-5126-4d76-957c-ccc7d17e735b');
await page.evaluate(() => [...document.querySelectorAll('#tab-aleef button')].find((b) => b.textContent.trim() === 'Load').click());
await page.waitForTimeout(1200);
console.log('tiles:', JSON.stringify(await page.$$eval('#tab-aleef .aleef-tile', (ts) => ts.map((t) => t.innerText.replace(/\n+/g, ' | ')))));
console.log('why:', JSON.stringify(await page.$$eval('#tab-aleef .aleef-why', (ws) => ws.map((w) => w.innerText.replace(/\n+/g, ' | ')))));
console.log('details:', JSON.stringify(await page.$$eval('#tab-aleef .aleef-details summary', (d) => d.map((x) => x.textContent))));
console.log('overflow:', JSON.stringify(await page.evaluate(() => { const w=document.querySelector('#aleef-verified .aleef-table-wrap'); return w ? {wrap: w.clientWidth, table: w.scrollWidth} : null; })));
console.log('errors:', JSON.stringify(errs));
await page.locator('#tab-aleef .aleef-tiles').first().screenshot({ path: join(out, 'tiles.png') });
await page.locator('#aleef-verified').first().screenshot({ path: join(out, 'verified.png') });
await page.locator('#tab-aleef .aleef-details').first().evaluate((d) => { d.open = true; });
await page.locator('#tab-aleef .aleef-details').first().screenshot({ path: join(out, 'coverage.png') });
await browser.close(); server.close();
