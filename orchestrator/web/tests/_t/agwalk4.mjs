import { boot } from './aglib.mjs';
let b = await boot(); let { page, T, state } = b; await b.go();
const sq = (s) => s.replace(/\s+/g, ' ');
await page.locator('#agents-body tr').first().click(); await page.waitForTimeout(1000);
const tabs = ['Scenarios', 'Logs', 'Health', 'Attack Path', 'Risk'];
const paneId = { Scenarios: 'scenarios', Logs: 'logs', Health: 'health', 'Attack Path': 'attackpath', Risk: 'risk' };
for (const t of tabs) {
  await page.locator('#agt-tab-bar .tab-btn', { hasText: t }).click(); await page.waitForTimeout(1100);
  console.log('TAB', t, '->', sq(await page.locator('#agt-tab-' + paneId[t]).innerText()).slice(0, 190));
  await page.screenshot({ path: T + 'ag4-' + paneId[t] + '.png' });
}
// logs tiers + metric filter
await page.locator('#agt-tab-bar .tab-btn', { hasText: 'Logs' }).click(); await page.waitForTimeout(800);
for (const tier of ['Security', 'Telemetry', 'Operational']) { await page.locator('#agt-tab-logs .tier-btn', { hasText: tier }).click(); await page.waitForTimeout(600); console.log('LOG tier', tier, '->', sq(await page.locator('#agt-tab-logs').innerText()).slice(0, 140)); }
await page.locator('#agt-tab-logs .tier-btn', { hasText: 'Telemetry' }).click(); await page.waitForTimeout(500);
await page.locator('#agt-tab-logs select').selectOption('heartbeat_latency_ms'); await page.waitForTimeout(600); console.log('LOG metric ->', sq(await page.locator('#agt-tab-logs').innerText()).slice(0, 120));
// results button from scenarios tab
await page.locator('#agt-tab-bar .tab-btn', { hasText: 'Scenarios' }).click(); await page.waitForTimeout(800);
const rb = page.locator('#agt-tab-scenarios button', { hasText: 'Results' }); console.log('Results buttons:', await rb.count());
if (await rb.count()) { await rb.first().click(); await page.waitForTimeout(1000); console.log('  Results -> overlay', await page.evaluate(() => [...document.querySelectorAll('.open')].map((e) => e.id).join(',')), '| z drawer vs results', await page.evaluate(() => ['agent-detail-overlay', 'results-overlay'].map((i) => { const e = document.getElementById(i); return i + ':' + (e ? getComputedStyle(e).zIndex + '/' + e.classList.contains('open') : 'none'); }).join(' '))); await page.screenshot({ path: T + 'ag4-results.png' }); }
console.log('errors', JSON.stringify(b.errs), '| native', JSON.stringify(state.dialogs)); await b.close();
// failures per tab
b = await boot(); ({ page, T, state } = b); await b.go();
await page.locator('#agents-body tr').first().click(); await page.waitForTimeout(900);
const fails = { Scenarios: ['/api/scenarios/runs', 'runs db down'], Logs: ['/logs/', 'log store down'], Health: ['/telemetry', 'tsdb down'], 'Attack Path': ['/api/attackpath/jobs', 'jobs table locked'], Risk: ['/risk', 'risk engine down'] };
for (const t of tabs) {
  const [k, m] = fails[t]; state.fail[k] = m;
  await page.locator('#agt-tab-bar .tab-btn', { hasText: t }).click(); await page.waitForTimeout(900);
  console.log('FAIL', t, '->', sq(await page.locator('#agt-tab-' + paneId[t]).innerText()).slice(0, 160), '| retry btn', await page.locator('#agt-tab-' + paneId[t] + ' .agt-tab-fail button').count());
  delete state.fail[k];
  if (await page.locator('#agt-tab-' + paneId[t] + ' .agt-tab-fail button').count()) { await page.locator('#agt-tab-' + paneId[t] + ' .agt-tab-fail button').click(); await page.waitForTimeout(900); console.log('   retry ->', sq(await page.locator('#agt-tab-' + paneId[t]).innerText()).slice(0, 90)); }
}
state.fail['/api/agents'] = 'x'; state.fail['/api/agents'] = '';
await b.close();
b = await boot(); ({ page, T, state } = b); await b.go();
// overview failure: fail the unlimited list only
let first = true;
await page.route('**/api/agents', async (r) => { if (!new URL(r.request().url()).searchParams.has('limit')) return r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'agent store down' }) }); return r.fallback(); });
await page.locator('#agents-body tr').first().click(); await page.waitForTimeout(1000);
console.log('OVERVIEW FAIL ->', sq(await page.locator('#agt-tab-overview').innerText()), '| title', await page.locator('#agt-detail-title').innerText());
await page.screenshot({ path: T + 'ag4-overfail.png' });
console.log('errors', JSON.stringify(b.errs)); await b.close();
