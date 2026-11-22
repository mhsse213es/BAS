import { chromium } from 'playwright-core';
import { createServer } from 'node:http'; import { mkdirSync, writeFileSync } from 'node:fs'; import { extname, join, normalize, resolve } from 'node:path';
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
  { id: 'gcp-iam', name: 'IAM sweep', provider: 'gcp', description: 'Sweeps IAM', steps: [{}] } ] };
const browser = await chromium.launch();
const result = {};
const TABS = process.argv.slice(3);
for (const tab of TABS) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errs = []; page.on('pageerror', (e) => errs.push(e.message)); page.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 160)); });
  await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); localStorage.setItem('audspect_theme', 'dark'); });
  await page.route('**/*', (r) => { const req = r.request(); const u = new URL(req.url());
    if (u.pathname === '/api/cloud-scenarios') return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(CAT) });
    if (u.pathname === '/api/cloud-runs' && req.method() === 'GET') return r.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
    if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx(req.method(), u)) });
    if (u.hostname !== '127.0.0.1') return r.fulfill({ status: 204, body: '' }); return r.continue(); });
  await page.routeWebSocket(/ws/, () => {});
  await page.goto(origin + '/index.html'); await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none'); await page.waitForTimeout(800);
  await page.evaluate((t) => { const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t); el && el.click(); }, tab);
  await page.waitForTimeout(1200);
  // every visible control inside the tab
  const controls = await page.evaluate((t) => {
    const root = document.getElementById('tab-' + t); if (!root) return { error: 'no tab root' };
    const vis = (e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden'; };
    const list = [...root.querySelectorAll('button, select, input, textarea, a[href], [role="button"], [data-on-click], [data-on-change], [data-on-input]')].filter(vis);
    return list.map((e) => { const c = getComputedStyle(e); const r = e.getBoundingClientRect();
      return { tag: e.tagName.toLowerCase(), id: e.id || '', cls: (e.className && e.className.baseVal === undefined ? e.className : '').toString().slice(0, 80), text: (e.innerText || e.value || e.placeholder || e.getAttribute('aria-label') || '').trim().slice(0, 50), action: e.getAttribute('data-on-click') || e.getAttribute('data-on-change') || e.getAttribute('data-on-input') || '', w: Math.round(r.width), h: Math.round(r.height), font: c.fontSize, radius: c.borderRadius, border: c.borderTopWidth + ' ' + c.borderTopColor, bg: c.backgroundColor, color: c.color, cursor: c.cursor, disabled: !!e.disabled }; });
  }, tab);
  const extra = {};
  if (tab === 'initiatives') {
    await page.click('.init-card >> nth=0'); await page.waitForTimeout(700);
    await page.screenshot({ path: join(out, 'init-drawer.png') });
    extra.drawer = await page.evaluate(() => { const d = document.querySelector('#init-drawer-overlay .drawer'); if (!d) return null; const r = d.getBoundingClientRect(); return { w: Math.round(r.width), h: Math.round(r.height), text: d.innerText.slice(0, 500) }; });
    await page.evaluate(() => document.querySelector('#init-drawer-overlay .drawer-close').click()); await page.waitForTimeout(500);
    await page.evaluate(() => document.querySelector('[data-on-click="openInitiativeCreateDrawer"]').click()); await page.waitForTimeout(700);
    await page.evaluate(() => document.querySelector('#init-create-overlay .overlay-close, #init-create-overlay [data-on-click*="Close"], #init-create-overlay button').click()); await page.waitForTimeout(400);
    await page.click('.init-card >> nth=0'); await page.waitForTimeout(600);
    await page.evaluate(() => { const b = [...document.querySelectorAll('#init-drawer-overlay button')].find((x) => /Attach Job/.test(x.textContent)); b && b.click(); }); await page.waitForTimeout(800);
    await page.screenshot({ path: join(out, 'init-attach.png') });
    extra.attachText = await page.evaluate(() => { const o = document.getElementById('init-attach-overlay'); return o ? o.innerText.slice(0, 300) : null; });
    await page.evaluate(() => { const b = document.querySelector('#init-attach-overlay .drawer-close, #init-attach-overlay button'); b && b.click(); }); await page.waitForTimeout(400);
    await page.evaluate(() => document.querySelector('#init-drawer-overlay .drawer-close').click()); await page.waitForTimeout(400);
    await page.evaluate(() => document.querySelector('[data-on-click="openInitiativeCreateDrawer"]').click()); await page.waitForTimeout(700);
    await page.screenshot({ path: join(out, 'init-create.png') });
    extra.attachOpen = await page.evaluate(() => { const b = document.querySelector('[data-on-click="openInitiativeAttachDrawer"]'); return !!b; });
    extra.create = await page.evaluate(() => { const d = document.getElementById('init-create-overlay'); return d ? d.innerText.slice(0, 400) : null; });
    await page.evaluate(() => { const b = document.querySelector('.drawer-overlay.open .drawer-close, .overlay.open .btn-outline'); b && b.click(); }); await page.waitForTimeout(300);
  }
  if (tab === 'campaigns') {
    await page.evaluate(() => document.querySelector('.cmp-card').click()); await page.waitForTimeout(800);
    await page.screenshot({ path: join(out, 'cmp-drawer.png') });
    extra.drawer = await page.evaluate(() => { const d = document.querySelector('#cmp-drawer-overlay .drawer'); return d ? { w: Math.round(d.getBoundingClientRect().width), text: d.innerText.slice(0, 700), btns: [...d.querySelectorAll('button')].map((b) => b.textContent.trim()).slice(0, 12) } : null; });
    const bd = await page.evaluate(() => { const b = [...document.querySelectorAll('#cmp-drawer-overlay button')].find((x) => /breakdown|agent/i.test(x.textContent)); if (b) { b.click(); return b.textContent.trim(); } return null; });
    await page.waitForTimeout(700); extra.breakdownBtn = bd;
    await page.screenshot({ path: join(out, 'cmp-breakdown.png') });
    await page.evaluate(() => { const b = document.querySelector('#cmp-drawer-overlay .drawer-close'); b && b.click(); }); await page.waitForTimeout(400);
    await page.evaluate(() => document.querySelector('#campaign-overlay') && document.querySelector('[data-on-click="openCampaignLaunch"]') && document.querySelector('[data-on-click="openCampaignLaunch"]').click()); await page.waitForTimeout(700);
    await page.screenshot({ path: join(out, 'cmp-launch.png') });
    extra.launch = await page.evaluate(() => { const o = document.getElementById('campaign-overlay'); return o ? o.innerText.slice(0, 500) : null; });
    await page.evaluate(() => { const b = document.querySelector('#campaign-overlay button'); b && b.click(); }); await page.waitForTimeout(300);
    await page.setViewportSize({ width: 390, height: 844 }); await page.waitForTimeout(400);
    await page.evaluate(() => document.querySelector('[data-on-click="openCampaignLaunch"]').click()); await page.waitForTimeout(600);
    await page.screenshot({ path: join(out, 'cmp-launch-mobile.png') });
    extra.launchMobileOverflow = await page.evaluate(() => { const o = document.querySelector('#campaign-overlay .modal'); return o ? o.scrollWidth - o.clientWidth : null; });
    await page.evaluate(() => { const b = document.querySelector('#campaign-overlay button'); b && b.click(); }); await page.waitForTimeout(300);
    await page.evaluate(() => document.querySelector('.cmp-card').click()); await page.waitForTimeout(700);
    await page.screenshot({ path: join(out, 'cmp-drawer-mobile.png') });
    extra.drawerMobileOverflow = await page.evaluate(() => { const d = document.querySelector('#cmp-drawer-overlay .drawer'); return d ? d.scrollWidth - d.clientWidth : null; });
    await page.evaluate(() => { const b = document.querySelector('#cmp-drawer-overlay .drawer-close'); b && b.click(); });
    await page.setViewportSize({ width: 1440, height: 900 });
  }
  if (tab === 'scheduled-assessments') {
    await page.evaluate(() => { const r = document.querySelector('#sched-table-wrap tbody tr.dt-click, #sched-table-wrap tbody tr'); r && r.click(); }); await page.waitForTimeout(800);
    await page.screenshot({ path: join(out, 'sched-drawer.png') });
    extra.drawerOpen = await page.evaluate(() => { const o = document.getElementById('sched-drawer-overlay'); return o ? o.classList.contains('open') : null; });
    await page.evaluate(() => document.querySelector('#sched-drawer-overlay .drawer-close') && document.querySelector('#sched-drawer-overlay .drawer-close').click()); await page.waitForTimeout(400);
    await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find((x) => /New Scheduled Assessment/.test(x.textContent)); b && b.click(); }); await page.waitForTimeout(800);
    await page.screenshot({ path: join(out, 'sched-wizard.png') });
    for (let i = 2; i <= 4; i++) { await page.evaluate(() => document.getElementById('sched-wz-next').click()); await page.waitForTimeout(500); await page.screenshot({ path: join(out, 'sched-wizard-step' + i + '.png') }); }
    extra.wizardOpen = await page.evaluate(() => { const o = document.getElementById('sched-overlay'); return o ? o.classList.contains('open') : null; });
    await page.evaluate(() => { const o = document.getElementById('sched-overlay'); const b = o && o.querySelector('.modal-close, [data-on-click*="Close"], [data-on-click*="close"]'); b && b.click(); }); await page.waitForTimeout(300);
  }
  // horizontal overflow of the tab at the current width
  const overflow = await page.evaluate((t) => { const root = document.getElementById('tab-' + t); return root ? root.scrollWidth - root.clientWidth : null; }, tab);
  await page.screenshot({ path: join(out, tab + '-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 }); await page.waitForTimeout(600);
  const mobileOverflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  await page.screenshot({ path: join(out, tab + '-mobile.png'), fullPage: true });
  result[tab] = { extra, controls: controls, overflowDesktop: overflow, mobileDocOverflow: mobileOverflow, errors: errs.slice(0, 12) };
  await ctx.close();
}
writeFileSync(join(out, 'inspect.json'), JSON.stringify(result, null, 1));
console.log(JSON.stringify(Object.fromEntries(Object.entries(result).map(([k, v]) => [k, { n: v.controls.length || v.controls.error, overflowDesktop: v.overflowDesktop, mobileDocOverflow: v.mobileDocOverflow, errors: v.errors.length }]))));
await browser.close(); server.close();
