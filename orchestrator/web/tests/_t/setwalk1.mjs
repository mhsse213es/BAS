import { boot } from './setlib.mjs';
const sq = (s) => s.replace(/\s+/g, ' ');
async function run(label, opts, fn) { const b = await boot(opts); try { await fn(b); } catch (e) { console.log(label, 'SCRIPT ERROR', e.message.split('\n')[0].slice(0, 160)); } console.log('  [' + label + '] errors', JSON.stringify(b.errs), '| native', JSON.stringify(b.state.dialogs)); await b.close(); }
const f = (b, k, m, s) => { b.state.fail[k] = m; b.state.status[k] = s || 500; };
await run('intel', {}, async (b) => {
  const { page, state } = b;
  f(b, 'GET /api/connector/status', 'db down'); await b.go('intel');
  console.log('CONNECTOR STATUS 500 ->', sq(await page.locator('#connector-status-wrap').innerText()).slice(0, 160), '| toast', await b.toast());
  delete state.fail['GET /api/connector/status'];
  f(b, 'POST /api/connector/sync', 'queue full'); await page.locator('#connector-sync-btn').click(); await page.waitForTimeout(500); console.log('SYNC refused ->', await b.toast()); delete state.fail['POST /api/connector/sync'];
  f(b, 'GET /api/threat-intel/misp/config', 'forbidden', 403); await page.evaluate(() => document.querySelector('[data-set="intel"]').click()); await page.waitForTimeout(900);
  console.log('MISP cfg 403 ->', JSON.stringify(sq(await page.locator('#ti-misp-config-panel').innerText()).slice(0, 80)), '| toast', await b.toast()); delete state.fail['GET /api/threat-intel/misp/config'];
  await page.evaluate(() => document.querySelector('[data-set="intel"]').click()); await page.waitForTimeout(900);
  f(b, 'PUT /api/threat-intel/misp/config', 'url must be https', 400); await page.fill('#ti-misp-url', 'http://x'); await page.locator('#ti-misp-config-panel button', { hasText: 'Save' }).click(); await page.waitForTimeout(400);
  if (await page.locator('#confirm-diff-submit-btn').isVisible()) await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700); console.log('MISP save refused ->', await b.toast());
  delete state.fail['PUT /api/threat-intel/misp/config'];
  f(b, 'PUT /api/openaev/config', 'bad token', 400); await page.locator('#openaev-config-panel button', { hasText: 'Save' }).click(); await page.waitForTimeout(500);
  if (await page.locator('#confirm-diff-submit-btn').isVisible()) await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700); console.log('OPENAEV save refused ->', await b.toast());
  delete state.fail['PUT /api/openaev/config'];
  f(b, 'DELETE /api/threat-intel/misp/config', 'locked', 409); await page.locator('#ti-misp-config-panel button', { hasText: 'Remove' }).click(); await page.waitForTimeout(400); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700); console.log('MISP remove refused ->', await b.toast());
});
await run('engine', {}, async (b) => { f(b, 'GET /api/caldera/status', 'db down'); await b.go('engine'); console.log('CALDERA 500 ->', sq(await b.page.locator('#caldera-status-wrap').innerText()).slice(0, 140)); });
await run('art', {}, async (b) => {
  const { page, state } = b; f(b, 'GET /api/art/content/status', 'db down'); await b.go('art'); console.log('ART 500 ->', sq(await page.locator('#art-content-wrap').innerText()).slice(0, 150)); delete state.fail['GET /api/art/content/status'];
  await page.evaluate(() => document.querySelector('[data-on-click="loadARTContentStatus"]').click()); await page.waitForTimeout(600);
  f(b, 'POST /api/art/content/reseed', 'pack missing', 500); await page.locator('#art-reseed-btn').click(); await page.waitForTimeout(700); console.log('RESEED refused ->', await b.toast());
});
await run('audit', {}, async (b) => {
  const { page, state } = b; await b.go('audit');
  console.log('AUDIT ok ->', sq(await page.locator('#audit-range-label').innerText()), '| next disabled', await page.locator('#audit-next-btn').isDisabled());
  await page.locator('#audit-next-btn').click(); await page.waitForTimeout(500); await page.locator('#audit-next-btn').click(); await page.waitForTimeout(500);
  console.log('  page3 ->', sq(await page.locator('#audit-range-label').innerText()), '| next disabled', await page.locator('#audit-next-btn').isDisabled(), '(120 rows: page 3 has 20)');
  f(b, 'GET /api/audit-logs', 'db down'); await page.evaluate(() => document.querySelector('[data-on-click="loadAuditLogs"]').click()); await page.waitForTimeout(600);
  console.log('AUDIT 500 ->', sq(await page.locator('#audit-body').innerText()).slice(0, 100));
  const dl = page.waitForEvent('download', { timeout: 2500 }).catch(() => null); await page.evaluate(() => document.querySelector('[data-on-click="exportAuditLogs"]').click()); const d = await dl;
  console.log('EXPORT on 500 -> downloaded a file?', !!d, d ? d.suggestedFilename() : '', '| toast', await b.toast());
});
await run('backup', { data: { backupMs: 1500 } }, async (b) => {
  const { page, state } = b; await b.go('backup');
  f(b, 'POST /api/backups', 'disk full'); await page.locator('#backup-now-btn').click(); await page.waitForTimeout(600); console.log('BACKUP refused -> button', await page.locator('#backup-now-btn').innerText(), '| dialogs', JSON.stringify(state.dialogs)); delete state.fail['POST /api/backups'];
  await page.locator('#backup-now-btn').click(); await page.waitForTimeout(600); console.log('BACKUP ok started -> button', await page.locator('#backup-now-btn').innerText(), '| disabled', await page.locator('#backup-now-btn').isDisabled());
  state.fail['GET /api/backups/' + state.running.id] = 'gone'; await page.waitForTimeout(5000); console.log('  poll error -> button', await page.locator('#backup-now-btn').innerText(), '| disabled', await page.locator('#backup-now-btn').isDisabled());
  delete state.fail['GET /api/backups/' + state.running.id];
  f(b, 'POST /restore-marker', 'x'); state.fail = {}; f(b, 'POST /api/backups/b1/restore-marker', 'marker failed'); await page.locator('#backup-jobs-body button', { hasText: 'Prepare Restore' }).first().click(); await page.waitForTimeout(500); console.log('RESTORE refused -> dialogs', JSON.stringify(state.dialogs.slice(-1)), '|', sq(await page.locator('#restore-command-wrap').innerText()).slice(0, 80)); state.fail = {};
  await page.locator('#backup-jobs-body button', { hasText: 'Prepare Restore' }).first().click(); await page.waitForTimeout(500); await page.screenshot({ path: b.T + 'sw-restore.png' }); console.log('RESTORE ok ->', sq(await page.locator('#restore-command-wrap').innerText()).slice(0, 160));
});
await run('backup-list', {}, async (b) => { f(b, 'GET /api/backups', 'db down'); await b.go('backup'); console.log('BACKUPS 500 ->', sq(await b.page.locator('#backup-status-card-wrap').innerText()).slice(0, 80), '| table', sq(await b.page.locator('#backup-jobs-body').innerText()).slice(0, 60)); });
await run('license', {}, async (b) => { f(b, 'GET /api/license', 'db down'); await b.go('license'); console.log('LICENSE 500 ->', sq(await b.page.locator('#license-card-wrap').innerText()).slice(0, 80)); });
await run('users', {}, async (b) => {
  const { page, state } = b; await b.go('users');
  await page.locator('#users-body tr', { hasText: 'priya' }).locator('button', { hasText: 'Reset PW' }).click(); await page.waitForTimeout(400);
  console.log('RESET PW dialog -> type', await page.locator('#ask-input').getAttribute('type'), '| title', await page.locator('#confirm-diff-title').innerText());
  await page.fill('#ask-input', 'abc'); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(400); console.log('  short ->', await page.locator('#ask-err').innerText(), '| calls', state.calls.filter((c) => /reset-password/.test(c)).length);
  await page.fill('#ask-input', ' Temp#Pass w0rd '); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(600); console.log('  ok ->', await b.toast(), '| body', state.calls.filter((c) => /reset-password/.test(c)).at(-1));
  await page.locator('[data-on-click="openCreateUser"]').click(); await page.waitForTimeout(300); await page.fill('#cu-username', 'priya'); await page.fill('#cu-password', 'Abcdef#123'); await page.locator('#create-user-overlay button', { hasText: /Create/ }).click(); await page.waitForTimeout(600);
  console.log('CREATE dup ->', sq(await page.locator('#cu-err').innerText()), '| overlay open', await page.evaluate(() => document.getElementById('create-user-overlay').classList.contains('open')));
});
