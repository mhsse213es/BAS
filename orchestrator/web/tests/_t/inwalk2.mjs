import { boot } from './intlib.mjs';
const sq = (s) => s.replace(/\s+/g, ' ');
const isOpen = (page, id) => page.evaluate((i) => !!document.getElementById(i)?.classList.contains('open'), id);
const lastCall = (state, re) => state.calls.filter((c) => re.test(c)).at(-1) || '(none)';
let b = await boot({ data: { reval: 3 } }); let { page, state, T } = b; await b.go();
console.log('HERO ->', sq(await page.locator('#hero-integrations').innerText()).slice(0, 150));
console.log('REVAL ->', sq(await page.locator('#integrations-reval').innerText()));
await page.screenshot({ path: T + 'in2-top.png', fullPage: true });
const hdBtns = await page.evaluate(() => [...document.querySelectorAll('.int-box .rk-hd-actions')].map((a) => [...a.children].map((c) => c.textContent.trim() + ':' + Math.round(c.getBoundingClientRect().width) + '@' + Math.round(c.getBoundingClientRect().top)).join(' | ')));
console.log('BOX BUTTONS ->', JSON.stringify(hdBtns));
// ── ITSM edit dialog
await page.locator('.int-card', { hasText: 'Jira SEC board' }).click(); await page.waitForTimeout(500);
console.log('CARD click -> dialog open', await isOpen(page, 'connector-form-wrap'), '| title', await page.locator('#connector-form-title').innerText(), '| focus', await page.evaluate(() => document.activeElement.id));
console.log('  token box ->', JSON.stringify(await page.evaluate(() => { const e = document.getElementById('cfs-api_token'); return { value: e.value, ph: e.placeholder, keep: e.getAttribute('data-keep') }; })));
await page.screenshot({ path: T + 'in2-itsm.png' });
await page.locator('[data-on-click="testConnectorForm"]').click(); await page.waitForTimeout(500); console.log('  test ->', sq(await page.locator('#cf-test-result').innerText()), '| class', await page.locator('#cf-test-result').getAttribute('class'));
await page.fill('#cfs-username', 'bad@x'); await page.locator('[data-on-click="testConnectorForm"]').click(); await page.waitForTimeout(500); console.log('  test bad ->', sq(await page.locator('#cf-test-result').innerText()), '|', await page.locator('#cf-test-result').getAttribute('class'));
await page.screenshot({ path: T + 'in2-itsm-test.png' });
await page.fill('#cfs-username', 'bas@acme.example');
await page.locator('[data-on-click="fetchConnectorProjects"]').click(); await page.waitForTimeout(500); console.log('  fetch ->', sq(await page.locator('#cfs-project_key-hint').innerText()), '|', await page.locator('#cfs-project_key-hint').getAttribute('class'));
// name required
await page.fill('#cf-name', '   '); await page.locator('#cf-save-btn').click(); await page.waitForTimeout(300); console.log('  blank name ->', await b.toast(), '| dialog still', await isOpen(page, 'connector-form-wrap'), '| puts', state.calls.filter((c) => c.startsWith('PUT')).length);
// refused save
await page.fill('#cf-name', 'Jira SEC board 2'); await page.locator('#cf-save-btn').click(); await page.waitForTimeout(500);
console.log('  save -> confirm modal', await isOpen(page, 'confirm-diff-overlay'), '|', sq(await page.locator('#confirm-diff-body').innerText()).slice(0, 120));
state.fail['PUT /api/ticketing/configs/i2'] = 'name already in use'; state.status['PUT /api/ticketing/configs/i2'] = 400;
await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700);
console.log('  REFUSED save ->', await b.toast(), '| dialog still open', await isOpen(page, 'connector-form-wrap'), '| name kept', await page.inputValue('#cf-name'), '| save btn', await page.locator('#cf-save-btn').innerText());
delete state.fail['PUT /api/ticketing/configs/i2'];
await page.locator('#cf-save-btn').click(); await page.waitForTimeout(400); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(800);
console.log('  OK save ->', await b.toast(), '| dialog open', await isOpen(page, 'connector-form-wrap'), '| body', lastCall(state, /^PUT \/api\/ticketing\/configs\/i2/).slice(0, 330));
console.log('  list now ->', JSON.stringify(await page.locator('.int-card .int-name').allInnerTexts()));
// Escape closes + focus returns
await page.locator('.int-card', { hasText: 'Ops webhook' }).locator('button', { hasText: 'Configure' }).click(); await page.waitForTimeout(400);
await page.keyboard.press('Escape'); await page.waitForTimeout(300); console.log('ESC -> dialog open', await isOpen(page, 'connector-form-wrap'), '| focus back on', await page.evaluate(() => document.activeElement.textContent.trim().slice(0, 20)));
// double-click add -> one POST
await page.locator('[data-on-click="openAddConnectorFor"][data-args*="webhook"]').click(); await page.waitForTimeout(400);
await page.fill('#cf-name', 'Dup test'); await page.fill('#cfs-url', 'https://h.example/x'); await page.locator('#cf-save-btn').dblclick(); await page.waitForTimeout(900);
console.log('DOUBLE-CLICK add -> POSTs', state.calls.filter((c) => c.startsWith('POST /api/ticketing/configs ')).length, '| cards named Dup test', await page.locator('.int-card', { hasText: 'Dup test' }).count());
// ── delete via in-page confirm
await page.locator('.int-card', { hasText: 'Dup test' }).locator('button', { hasText: 'Delete' }).click(); await page.waitForTimeout(400);
console.log('DELETE ->', sq(await page.locator('#confirm-diff-overlay').innerText()).slice(0, 160), '| native', JSON.stringify(state.dialogs));
await page.screenshot({ path: T + 'in2-delete.png' });
await page.locator('#confirm-diff-overlay button', { hasText: /Cancel/ }).first().click(); await page.waitForTimeout(300); console.log('  cancel -> still there', await page.locator('.int-card', { hasText: 'Dup test' }).count(), '| DELETE calls', state.calls.filter((c) => c.startsWith('DELETE')).length);
state.fail['DELETE /api/ticketing/configs/'] = 'x'; delete state.fail['DELETE /api/ticketing/configs/'];
const id = state.itsm.find((c) => c.name === 'Dup test').id; state.fail['DELETE /api/ticketing/configs/' + id] = 'referenced by auto-create rule'; state.status['DELETE /api/ticketing/configs/' + id] = 409;
await page.locator('.int-card', { hasText: 'Dup test' }).locator('button', { hasText: 'Delete' }).click(); await page.waitForTimeout(300); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700);
console.log('  REFUSED delete ->', await b.toast(), '| card still there', await page.locator('.int-card', { hasText: 'Dup test' }).count());
delete state.fail['DELETE /api/ticketing/configs/' + id];
await page.locator('.int-card', { hasText: 'Dup test' }).locator('button', { hasText: 'Delete' }).click(); await page.waitForTimeout(300); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(800);
console.log('  OK delete ->', await b.toast(), '| card gone', (await page.locator('.int-card', { hasText: 'Dup test' }).count()) === 0);
console.log('errors', JSON.stringify(b.errs), '| native', JSON.stringify(state.dialogs)); await b.close();

// ── EPP
b = await boot(); ({ page, state, T } = b); await b.go();
await page.locator('.int-card', { hasText: 'Defender tenant' }).locator('button', { hasText: 'Configure' }).click(); await page.waitForTimeout(500);
console.log('EPP edit -> open', await isOpen(page, 'response-connector-form-wrap'), '| provider', await page.inputValue('#rc-provider'), '| secret box', JSON.stringify(await page.inputValue('#rc-client-secret')), await page.locator('#rc-client-secret').getAttribute('placeholder'));
await page.screenshot({ path: T + 'in2-epp.png' });
await page.fill('#rc-name', ''); await page.locator('#rc-save-btn').click(); await page.waitForTimeout(300); console.log('  no name ->', await b.toast());
await page.fill('#rc-name', 'Defender tenant 2'); state.fail['PUT /api/actions/configs/e2'] = 'tenantId is not a valid GUID'; state.status['PUT /api/actions/configs/e2'] = 400;
await page.locator('#rc-save-btn').click(); await page.waitForTimeout(600); console.log('  REFUSED save ->', await b.toast(), '| dialog open', await isOpen(page, 'response-connector-form-wrap'), '| name kept', await page.inputValue('#rc-name')); delete state.fail['PUT /api/actions/configs/e2'];
await page.locator('#rc-save-btn').click(); await page.waitForTimeout(800); console.log('  OK save ->', await b.toast(), '| dialog open', await isOpen(page, 'response-connector-form-wrap'), '|', lastCall(state, /^PUT \/api\/actions/).slice(0, 300));
await page.locator('[data-on-click="openAddResponseConnectorFor"][data-args*="sentinelone"]').click(); await page.waitForTimeout(400);
console.log('ADD s1 -> provider', await page.inputValue('#rc-provider'), '| s1 fields shown', await page.locator('#rc-sentinelone-fields').isVisible(), '| oauth hidden', !(await page.locator('#rc-oauth-fields').isVisible()), '| cs hidden', !(await page.locator('#rc-crowdstrike-fields').isVisible()));
await page.screenshot({ path: T + 'in2-epp-s1.png' });
await page.fill('#rc-name', 'S1 prod'); await page.fill('#rc-s1-base-url', 'https://x.sentinelone.net'); await page.fill('#rc-s1-api-token', 'tok'); await page.locator('#rc-save-btn').dblclick(); await page.waitForTimeout(800);
console.log('  add s1 -> POSTs', state.calls.filter((c) => c.startsWith('POST /api/actions/configs ')).length, '| cards', await page.locator('.int-card .int-name').allInnerTexts().then((a) => a.join(', ')));
await page.locator('.int-card', { hasText: 'Prod CrowdStrike' }).locator('button', { hasText: 'Delete' }).click(); await page.waitForTimeout(300); console.log('  EPP delete confirm ->', sq(await page.locator('#confirm-diff-overlay').innerText()).slice(0, 150));
await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700); console.log('  deleted ->', await b.toast(), '| cards', await page.locator('.int-card').count());
state.fail['GET /api/actions/configs'] = 'db'; await page.locator('[data-on-click="refreshResponseConnectors"]').click(); await page.waitForTimeout(600); console.log('REFRESH fail ->', await b.toast(), '| grid', sq(await page.locator('#int-grid').innerText()).slice(0, 70));
console.log('errors', JSON.stringify(b.errs), '| native', JSON.stringify(state.dialogs)); await b.close();

// ── TAXII
b = await boot(); ({ page, state, T } = b); await b.go();
console.log('TAXII rows ->', await page.locator('#int-taxii-body tr').count(), '| buttons row1', JSON.stringify(await page.locator('#int-taxii-body tr').first().locator('button').allInnerTexts()));
await page.locator('#int-taxii-body tr', { hasText: 'FS-ISAC' }).locator('button', { hasText: 'Sync now' }).click(); await page.waitForTimeout(800); console.log('  sync ->', await b.toast(), '| last poll', sq(await page.locator('#int-taxii-body tr', { hasText: 'FS-ISAC' }).innerText()).slice(-30));
await page.locator('#int-taxii-body tr', { hasText: 'Auto-ISAC' }).locator('button', { hasText: 'Edit' }).click(); await page.waitForTimeout(500);
console.log('  edit -> open', await isOpen(page, 'taxii-connector-overlay'), '| name', await page.inputValue('#taxii-conn-name'), '| title', await page.locator('#taxii-connector-modal-title').innerText());
await page.screenshot({ path: T + 'in2-taxii.png' });
await page.fill('#taxii-conn-name', 'Auto-ISAC prod'); state.fail['PUT /api/taxii/connectors/t2'] = 'serverUrl unreachable'; state.status['PUT /api/taxii/connectors/t2'] = 502;
await page.locator('#taxii-conn-save-btn').click(); await page.waitForTimeout(600); console.log('  REFUSED save ->', await b.toast(), '| dialog open', await isOpen(page, 'taxii-connector-overlay')); delete state.fail['PUT /api/taxii/connectors/t2'];
await page.locator('[data-on-click="testTAXIIConnectorForm"]').click(); await page.waitForTimeout(500); console.log('  test ->', sq(await page.locator('#taxii-conn-test-result').innerText()), '|', await page.locator('#taxii-conn-test-result').getAttribute('class'));
await page.locator('#taxii-conn-save-btn').click(); await page.waitForTimeout(800); console.log('  OK save ->', await b.toast(), '| table', sq(await page.locator('#int-taxii-body').innerText()).slice(0, 60));
await page.locator('.int-taxii button', { hasText: '+ Add TAXII' }).click(); await page.waitForTimeout(400); console.log('  add (card btn) -> title', await page.locator('#taxii-connector-modal-title').innerText(), '| name empty', (await page.inputValue('#taxii-conn-name')) === '');
await page.fill('#taxii-conn-name', 'New feed'); await page.fill('#taxii-conn-server-url', 'https://x.example'); await page.locator('#taxii-conn-save-btn').dblclick(); await page.waitForTimeout(900);
console.log('  add -> POSTs', state.calls.filter((c) => c.startsWith('POST /api/taxii/connectors ')).length, '| Integrations table rows', await page.locator('#int-taxii-body tr').count(), '| Settings table rows', await page.locator('#taxii-connectors-body tr').count());
await page.locator('#int-taxii-body tr', { hasText: 'New feed' }).locator('button', { hasText: 'Delete' }).click(); await page.waitForTimeout(300); console.log('  delete confirm ->', sq(await page.locator('#confirm-diff-overlay').innerText()).slice(0, 120));
await page.screenshot({ path: T + 'in2-taxii-del.png' });
await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(800); console.log('  deleted ->', await b.toast(), '| rows', await page.locator('#int-taxii-body tr').count());
console.log('errors', JSON.stringify(b.errs), '| native', JSON.stringify(state.dialogs)); await b.close();

// ── load failures
for (const [label, key, status] of [['ITSM load fail', 'GET /api/ticketing/configs', 500], ['ITSM 403', 'GET /api/ticketing/configs', 403], ['EPP load fail', 'GET /api/actions/configs', 500], ['TAXII load fail', 'GET /api/taxii/connectors', 500]]) {
  b = await boot(); ({ page, state, T } = b); state.fail[key] = 'db unavailable'; state.status[key] = status; await b.go();
  console.log(label.toUpperCase(), '->', sq(await page.locator('#int-grid').innerText()).slice(0, 100), '| taxii', sq(await page.locator('#int-taxii-body').innerText()).slice(0, 70), '| empty-boxes shown', await page.evaluate(() => [...document.querySelectorAll('#int-itsm-empty,#int-epp-empty')].map((e) => !e.hidden).join(',')));
  if (label === 'ITSM load fail') { await page.screenshot({ path: T + 'in2-fail.png', fullPage: true }); await page.locator('#int-grid [data-on-click="loadIntegrations"]').click(); await page.waitForTimeout(300); }
  if (label === 'TAXII load fail') { delete state.fail[key]; await page.locator('#int-taxii-body button', { hasText: 'Retry' }).click(); await page.waitForTimeout(600); console.log('  TAXII retry ->', await page.locator('#int-taxii-body tr').count(), 'rows'); }
  await b.close();
}
b = await boot({ data: { itsm: [], epp: [], taxii: [], reval: 0 } }); ({ page, state, T } = b); await b.go();
console.log('EMPTY ->', 'itsm box', await page.evaluate(() => !document.getElementById('int-itsm-empty').hidden), '| epp', await page.evaluate(() => !document.getElementById('int-epp-empty').hidden), '| grid', JSON.stringify(sq(await page.locator('#int-grid').innerText())), '| taxii', sq(await page.locator('#int-taxii-body').innerText()), '| reval hidden', !(await page.locator('#integrations-reval').isVisible()));
await page.screenshot({ path: T + 'in2-empty.png', fullPage: true }); await b.close();
b = await boot({ viewport: { width: 420, height: 900 } }); ({ page, T } = b); await b.go(); await page.screenshot({ path: T + 'in2-phone.png', fullPage: true }); console.log('PHONE h-scroll', await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1));
await page.locator('.int-card').first().locator('button', { hasText: 'Configure' }).click(); await page.waitForTimeout(500); await page.screenshot({ path: T + 'in2-phone-dlg.png' }); await b.close();
