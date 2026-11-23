import { boot } from './intlib.mjs';
const sq = (s) => s.replace(/\s+/g, ' ');
let b = await boot(); let { page, state, T } = b; await b.go();
const vis = (sel) => page.evaluate((s) => { const e = document.querySelector(s); if (!e) return 'none'; const r = e.getBoundingClientRect(); return (getComputedStyle(e).display === 'none' ? 'hidden' : 'shown') + ' top=' + Math.round(r.top) + ' h=' + Math.round(r.height); }, sel);
// chips + search
await page.locator('.int-chip', { hasText: 'EPP' }).click(); await page.waitForTimeout(200); console.log('CHIP EPP ->', await page.locator('.int-card').count(), 'cards');
await page.locator('.int-chip', { hasText: 'All' }).click();
await page.fill('#int-q', 'jira'); await page.waitForTimeout(200); console.log('SEARCH jira ->', await page.locator('.int-card').count());
await page.fill('#int-q', 'zzz'); await page.waitForTimeout(200); console.log('SEARCH zzz ->', sq(await page.locator('#int-grid').innerText()));
await page.fill('#int-q', ''); await page.waitForTimeout(200);
// Test buttons
await page.locator('.int-card', { hasText: 'ServiceNow Production' }).locator('button', { hasText: 'Test' }).click(); await page.waitForTimeout(700); console.log('TEST ok ->', await b.toast());
state.itsm[2].name = 'Ops FAIL hook'; await page.evaluate(() => document.querySelector('[data-on-click="loadIntegrations"]') || 0); await page.locator('[data-on-click="triggerTicketingSync"]').click(); await page.waitForTimeout(500); console.log('SYNC ITSM ->', await b.toast());
await page.locator('[data-on-click="refreshResponseConnectors"]').click(); await page.waitForTimeout(600); console.log('SYNC EPP ->', await b.toast());
state.fail['/api/ticketing/sync'] = 'ticketing not configured'; await page.locator('[data-on-click="triggerTicketingSync"]').click(); await page.waitForTimeout(500); console.log('SYNC ITSM fail ->', await b.toast()); delete state.fail['/api/ticketing/sync'];
await page.locator('.int-card', { hasText: 'Prod CrowdStrike' }).locator('button', { hasText: 'Test' }).click(); await page.waitForTimeout(600); console.log('TEST EPP ->', await b.toast());
state.fail['/api/actions/configs/e1/test'] = 'upstream 502'; await page.locator('.int-card', { hasText: 'Prod CrowdStrike' }).locator('button', { hasText: 'Test' }).click(); await page.waitForTimeout(600); console.log('TEST EPP http-fail ->', await b.toast()); delete state.fail['/api/actions/configs/e1/test'];
// open form: card click
await page.locator('.int-card', { hasText: 'Jira SEC board' }).click(); await page.waitForTimeout(700);
console.log('CARD click -> form', await vis('#connector-form-wrap'), '| title', await page.locator('#connector-form-title').innerText(), '| scrollY', await page.evaluate(() => document.querySelector('main, #content, .main')?.scrollTop ?? scrollY));
await page.screenshot({ path: T + 'in-form.png' });
console.log('  fields ->', JSON.stringify(await page.evaluate(() => [...document.querySelectorAll('#cf-settings input')].map((i) => i.id + '=' + (i.type === 'checkbox' ? i.checked : i.value)))));
// Test connection in form
await page.locator('[data-on-click="testConnectorForm"]').click(); await page.waitForTimeout(500); console.log('  form test ->', sq(await page.locator('#cf-test-result').innerText()));
await page.fill('#cfs-username', 'bad@x'); await page.locator('[data-on-click="testConnectorForm"]').click(); await page.waitForTimeout(500); console.log('  form test bad ->', sq(await page.locator('#cf-test-result').innerText()));
// Fetch projects
await page.locator('[data-on-click="fetchConnectorProjects"]').click(); await page.waitForTimeout(500); console.log('  fetch ->', sq(await page.locator('#cfs-project_key-hint').innerText()), '| sel visible', await vis('#cfs-project_key-sel'));
// save with a change -> diff modal
await page.fill('#cf-name', 'Jira SEC board 2'); await page.locator('[data-on-click="saveConnectorForm"]').click(); await page.waitForTimeout(500);
console.log('  save -> confirm modal', await page.evaluate(() => document.getElementById('confirm-diff-overlay')?.classList.contains('open')), '|', sq(await page.locator('#confirm-diff-body').innerText()).slice(0, 160));
state.fail['PUT /api/ticketing/configs/i2'] = 'name already in use'; state.status['PUT /api/ticketing/configs/i2'] = 400;
await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700); console.log('  SAVE http 400 ->', await b.toast(), '| form', await vis('#connector-form-wrap'), '| calls', state.calls.at(-1));
delete state.fail['PUT /api/ticketing/configs/i2'];
await page.screenshot({ path: T + 'in-after400.png' });
console.log('errors', JSON.stringify(b.errs), '| native', JSON.stringify(state.dialogs)); await b.close();

// delete + EPP edit/save/delete + TAXII
b = await boot(); ({ page, state, T } = b); await b.go();
await page.locator('.int-card', { hasText: 'Ops webhook' }).locator('button', { hasText: 'Delete' }).click(); await page.waitForTimeout(700);
console.log('DELETE itsm -> native dialogs', JSON.stringify(state.dialogs), '| toast', await b.toast(), '| cards', await page.locator('.int-card').count());
state.fail['DELETE /api/ticketing/configs/i1'] = 'in use by auto-create'; await page.locator('.int-card', { hasText: 'ServiceNow Production' }).locator('button', { hasText: 'Delete' }).click(); await page.waitForTimeout(700);
console.log('DELETE http fail ->', await b.toast(), '| cards', await page.locator('.int-card').count()); delete state.fail['DELETE /api/ticketing/configs/i1'];
await page.locator('.int-card', { hasText: 'Defender tenant' }).locator('button', { hasText: 'Configure' }).click(); await page.waitForTimeout(600);
console.log('EPP edit form ->', await vis('#response-connector-form-wrap'), '| provider', await page.inputValue('#rc-provider'), '| secret', await page.inputValue('#rc-client-secret'), '| defender fields', await vis('#rc-defender-fields'));
await page.screenshot({ path: T + 'in-eppform.png' });
await page.fill('#rc-name', ''); await page.locator('[data-on-click="saveResponseConnectorForm"]').click(); await page.waitForTimeout(400); console.log('  EPP save no name ->', await b.toast());
await page.fill('#rc-name', 'Defender tenant 2'); state.fail['PUT /api/actions/configs/e2'] = 'baseUrl required'; state.status['PUT /api/actions/configs/e2'] = 400;
await page.locator('[data-on-click="saveResponseConnectorForm"]').click(); await page.waitForTimeout(600); console.log('  EPP save http 400 ->', await b.toast(), '| form', await vis('#response-connector-form-wrap')); delete state.fail['PUT /api/actions/configs/e2'];
await page.locator('[data-on-click="saveResponseConnectorForm"]').click(); await page.waitForTimeout(700); console.log('  EPP save ok ->', await b.toast(), '| body', state.calls.filter((c) => c.startsWith('PUT /api/actions')).at(-1));
await page.locator('.int-card', { hasText: 'Prod CrowdStrike' }).locator('button', { hasText: 'Delete' }).click(); await page.waitForTimeout(600); console.log('  EPP delete ->', JSON.stringify(state.dialogs.slice(-1)), await b.toast());
// add flows
await page.locator('[data-on-click="openAddConnectorFor"][data-args*="jira"]').click(); await page.waitForTimeout(500); console.log('ADD jira ->', await page.inputValue('#cf-provider'), '| fields', await page.locator('#cf-settings input').count());
await page.locator('[data-on-click="saveConnectorForm"]').click(); await page.waitForTimeout(700); console.log('  save empty name ->', await b.toast(), '| calls', state.calls.at(-1)?.slice(0, 120));
// TAXII
await page.locator('[data-on-click="openTAXIIConnectorModal"]').first().click(); await page.waitForTimeout(500); console.log('TAXII add modal open ->', await page.evaluate(() => document.getElementById('taxii-connector-overlay').classList.contains('open')));
await page.screenshot({ path: T + 'in-taxii.png' });
await page.fill('#taxii-conn-name', 'New feed'); await page.fill('#taxii-conn-server-url', 'https://x.example'); await page.locator('#taxii-conn-save-btn').click(); await page.waitForTimeout(800);
console.log('  TAXII saved ->', await b.toast(), '| rows on Integrations table', await page.locator('#int-taxii-body tr').count(), '| server rows', state.taxii.length);
console.log('errors', JSON.stringify(b.errs)); await b.close();

// load failures
for (const [label, key] of [['ITSM load fail', 'GET /api/ticketing/configs'], ['EPP load fail', 'GET /api/actions/configs'], ['TAXII load fail', 'GET /api/taxii/connectors']]) {
  b = await boot(); ({ page, state, T } = b); state.fail[key] = 'db unavailable'; await b.go();
  console.log(label.toUpperCase(), '->', sq(await page.locator('#int-grid').innerText()).slice(0, 110), '| hero', sq(await page.locator('#hero-integrations .hero-stats, #hero-integrations').innerText()).slice(-60), '| taxii', sq(await page.locator('#int-taxii-body').innerText()).slice(0, 60), '| boxes empty shown', await page.evaluate(() => [...document.querySelectorAll('#int-itsm-empty,#int-epp-empty')].map((e) => !e.hidden).join(',')));
  if (label === 'ITSM load fail') await page.screenshot({ path: T + 'in-itsmfail.png' });
  await b.close();
}
// empty + revalidation
b = await boot({ data: { itsm: [], epp: [], taxii: [], reval: 4 } }); ({ page, state, T } = b); await b.go();
console.log('EMPTY ->', 'itsm box empty shown', await page.evaluate(() => !document.getElementById('int-itsm-empty').hidden), '| epp', await page.evaluate(() => !document.getElementById('int-epp-empty').hidden), '| grid', JSON.stringify(sq(await page.locator('#int-grid').innerText())), '| taxii', sq(await page.locator('#int-taxii-body').innerText()), '| insights', (await page.locator('#integrations-insights').innerHTML()).length);
console.log('REVAL ->', await vis('#integrations-reval'), sq(await page.locator('#integrations-reval').innerText()));
await page.screenshot({ path: T + 'in-empty.png', fullPage: true });
await b.close();
b = await boot({ viewport: { width: 420, height: 900 } }); await b.go(); await b.page.screenshot({ path: b.T + 'in-phone.png', fullPage: true }); console.log('PHONE h-scroll', await b.page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)); await b.close();
