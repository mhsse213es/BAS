import { boot } from './aglib.mjs';
let b = await boot(); let { page, T, state } = b; await b.go();
const sq = (s) => s.replace(/\s+/g, ' ');
const confirmOpen = () => page.evaluate(() => document.getElementById('confirm-diff-overlay').classList.contains('open'));
// toolbar: tray icon
await page.locator('[data-on-click="toggleFleetTrayIcon"]').click(); await page.waitForTimeout(300);
console.log('TRAY confirm ->', await confirmOpen(), sq(await page.locator('#confirm-diff-title').innerText()), '|', sq(await page.locator('#confirm-diff-body').innerText()).slice(0, 140), '| btn', await page.locator('#confirm-diff-submit-btn').innerText());
await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700); console.log('  ->', await b.toast(), '|', state.calls.at(-1));
state.fail['/api/fleet/tray-icon'] = 'policy locked'; await page.locator('[data-on-click="toggleFleetTrayIcon"]').click(); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700); console.log('TRAY FAIL ->', await b.toast()); delete state.fail['/api/fleet/tray-icon'];
// min version
await page.locator('[data-on-click="toggleMinAgentVersion"]').click(); await page.waitForTimeout(300);
console.log('MINVER dialog ->', sq(await page.locator('#confirm-diff-body').innerText()).slice(0, 220));
await page.screenshot({ path: T + 'ag5-minver.png' });
await page.fill('#ask-input', '1.9.7'); await page.keyboard.press('Enter'); await page.waitForTimeout(700); console.log('  set ->', await b.toast(), '|', state.calls.at(-1));
state.fail['/api/fleet/min-agent-version'] = 'invalid version format'; await page.locator('[data-on-click="toggleMinAgentVersion"]').click(); await page.fill('#ask-input', 'abc'); await page.keyboard.press('Enter'); await page.waitForTimeout(700); console.log('  FAIL ->', await b.toast()); delete state.fail['/api/fleet/min-agent-version'];
// move to group via row menu
await page.locator('#agents-body tr').first().locator('.agt-actcol button').first().click(); await page.locator('.row-menu-panel.open .row-menu-item', { hasText: 'Move to group' }).click(); await page.waitForTimeout(300);
console.log('PICKER ->', sq(await page.locator('#group-picker-overlay').innerText()).slice(0, 160), '| options', await page.locator('#gp-select option').count());
await page.locator('#gp-select').selectOption({ index: 2 }); await page.locator('#group-picker-overlay button', { hasText: /Move|Save|OK/ }).first().click(); await page.waitForTimeout(700); console.log('  move ->', await b.toast(), '|', state.calls.at(-1));
state.fail['/group'] = 'group locked'; await page.locator('#agents-body tr').first().locator('.agt-actcol button').first().click(); await page.locator('.row-menu-panel.open .row-menu-item', { hasText: 'Move to group' }).click(); await page.locator('#group-picker-overlay button', { hasText: /Move|Save|OK/ }).first().click(); await page.waitForTimeout(700); console.log('  move FAIL ->', await b.toast(), '| picker still open', await page.evaluate(() => document.getElementById('group-picker-overlay').classList.contains('open'))); delete state.fail['/group'];
await page.evaluate(() => document.getElementById('group-picker-overlay').classList.remove('open'));
// keyboard on rows
await page.locator('#agents-body tr').nth(2).focus(); await page.keyboard.press('Enter'); await page.waitForTimeout(800); console.log('KEYBOARD Enter -> drawer open', await page.evaluate(() => document.getElementById('agent-detail-overlay').classList.contains('open')), '|', await page.locator('#agt-detail-title').innerText());
await page.keyboard.press('Escape'); await page.waitForTimeout(300); console.log('  Escape closes drawer ->', !(await page.evaluate(() => document.getElementById('agent-detail-overlay').classList.contains('open'))));
await page.evaluate(() => document.getElementById('agent-detail-overlay').classList.remove('open'));
// run simulation + safe scan from row menu
await page.locator('#agents-body tr').first().locator('.agt-actcol button').first().click(); await page.locator('.row-menu-panel.open .row-menu-item', { hasText: 'Run simulation' }).click(); await page.waitForTimeout(800);
console.log('RUN SIM -> open overlays', await page.evaluate(() => [...document.querySelectorAll('.open')].map((e) => e.id).join(',')), '| z', await page.evaluate(() => { const e = document.querySelector('.overlay.open, .modal-overlay.open'); return e ? e.id + ':' + getComputedStyle(e).zIndex : ''; }));
await page.screenshot({ path: T + 'ag5-runsim.png' });
await page.evaluate(() => document.querySelectorAll('.open').forEach((e) => e.classList.remove('open')));
// from drawer: run simulation must be above drawer
await page.locator('#agents-body tr').first().click(); await page.waitForTimeout(900); await page.locator('#agt-tab-overview button', { hasText: 'Run simulation' }).click(); await page.waitForTimeout(800);
console.log('DRAWER RUN SIM -> visible above drawer:', await page.evaluate(() => { const ids = [...document.querySelectorAll('.open')].map((e) => e.id + ':' + getComputedStyle(e).zIndex); return ids.join(' '); }));
await page.screenshot({ path: T + 'ag5-drawer-runsim.png' });
console.log('errors', JSON.stringify(b.errs), '| native', JSON.stringify(state.dialogs)); await b.close();
// migration panel states
for (const [label, status] of [['blocked', { daysClean: 5, daysRequired: 30, eligible: false, blockingAgents: [{ agentId: 'a-9', hostname: 'old-linux', lastSeen: new Date().toISOString() }], unattributedRequests: { count: 4 } }], ['eligible', { daysClean: 30, daysRequired: 30, eligible: true, blockingAgents: [], unattributedRequests: null }]]) {
  b = await boot(); await b.page.route('**/api/agents/legacy-migration-status', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(status) })); await b.go(); await b.page.locator('[data-on-click="loadAgents"]').first().click(); await b.page.waitForTimeout(1200);
  console.log('MIGRATION', label, '->', sq(await b.page.locator('#legacy-migration-panel').innerText())); await b.page.locator('#legacy-migration-panel').screenshot({ path: b.T + 'ag5-mig-' + label + '.png' }); await b.close();
}
b = await boot(); await b.page.route('**/api/agents/legacy-migration-status', (r) => r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'x' }) })); await b.go(); await b.page.locator('[data-on-click="loadAgents"]').first().click(); await b.page.waitForTimeout(1000); console.log('MIGRATION fail ->', JSON.stringify(await b.page.locator('#legacy-migration-panel').innerText()), '| toast', await b.toast()); await b.close();
