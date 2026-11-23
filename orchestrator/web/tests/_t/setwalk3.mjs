import { boot } from './setlib.mjs';
const sq = (s) => s.replace(/\s+/g, ' ');
let b = await boot(); let { page, state, T } = b; await b.go('users');
const row = (n) => page.locator('#users-body tr', { hasText: n });
console.log('USERS ->', await page.locator('#users-body tr').count(), 'rows | hero count', await page.locator('#users-cnt').innerText());
await row('priya').locator('button', { hasText: 'Edit' }).click(); await page.waitForTimeout(300);
console.log('EDIT dialog ->', await page.locator('#edit-user-title').innerText(), '| role', await page.inputValue('#eu-role'));
await page.selectOption('#eu-role', 'viewer'); state.fail['PUT /api/users/u2'] = 'cannot demote last analyst'; state.status['PUT /api/users/u2'] = 409;
await page.locator('#edit-user-overlay button', { hasText: /Save|Update/ }).first().click(); await page.waitForTimeout(500);
console.log('  refused ->', sq(await page.locator('#eu-err').innerText()), '| open', await page.evaluate(() => document.getElementById('edit-user-overlay').classList.contains('open')));
delete state.fail['PUT /api/users/u2']; await page.locator('#edit-user-overlay button', { hasText: /Save|Update/ }).first().click(); await page.waitForTimeout(600);
console.log('  ok ->', await b.toast(), '| row', sq(await row('priya').innerText()).slice(0, 60));
// disable / enable
const tog = row('ravi').locator('button').filter({ hasText: /Enable|Disable/ });
console.log('TOGGLE labels ->', JSON.stringify(await tog.allInnerTexts()));
await tog.first().click(); await page.waitForTimeout(500); console.log('  toggled ->', await b.toast(), '| status', sq(await row('ravi').innerText()).slice(0, 70));
state.fail['PUT /api/users/u3'] = 'denied'; await row('ravi').locator('button').filter({ hasText: /Enable|Disable/ }).first().click(); await page.waitForTimeout(500); console.log('  refused toggle ->', await b.toast()); delete state.fail['PUT /api/users/u3'];
// self-protection: can the admin disable themself?
console.log('SELF row buttons ->', JSON.stringify(await row('admin').first().locator('button').allInnerTexts()));
// create
await page.locator('[data-on-click="openCreateUser"]').click(); await page.waitForTimeout(300);
await page.locator('#create-user-overlay button', { hasText: /Create/ }).click(); await page.waitForTimeout(300); console.log('CREATE empty ->', await page.locator('#cu-err').innerText());
await page.fill('#cu-username', 'newbie'); await page.fill('#cu-password', 'short'); await page.locator('#create-user-overlay button', { hasText: /Create/ }).click(); await page.waitForTimeout(500); console.log('  weak pw ->', await page.locator('#cu-err').innerText() || '(none, sent)', '| POSTs', state.calls.filter((c) => c.startsWith('POST /api/users ')).length);
await page.fill('#cu-password', 'Str0ng#Passw0rd'); await page.locator('#create-user-overlay button', { hasText: /Create/ }).dblclick(); await page.waitForTimeout(800);
console.log('  ok dblclick -> POSTs', state.calls.filter((c) => c.startsWith('POST /api/users ')).length, '| users', state.users.filter((u) => u.username === 'newbie').length);
await page.screenshot({ path: T + 'sw3-users.png' });
// users empty / 403
await b.close();
b = await boot(); ({ page, state, T } = b); state.users = []; await b.go('users'); console.log('USERS empty ->', sq(await page.locator('#users-box').innerText()).slice(0, 80)); await b.close();
b = await boot(); ({ page, state, T } = b); state.fail['/api/users'] = 'no'; state.status['/api/users'] = 403; await b.go('users'); console.log('USERS 403 ->', sq(await page.locator('#users-box').innerText()).slice(0, 90)); await b.close();
// theme + display + dashprefs
b = await boot(); ({ page, state, T } = b); await b.go('theme');
await page.screenshot({ path: T + 'sw3-theme.png' });
await page.locator('#theme-card-light').click(); await page.waitForTimeout(300); console.log('THEME light ->', await page.evaluate(() => document.body.className + ' | ls ' + localStorage.getItem('audspect_theme')));
for (const k of ['compact', 'reduce']) { await page.locator('[data-display-pref="' + k + '"]').click(); await page.waitForTimeout(150); console.log('DISPLAY', k, '->', await page.locator('[data-display-pref="' + k + '"]').getAttribute('aria-checked'), '| body', await page.evaluate(() => document.body.className + ' ' + document.documentElement.className)); }
const sw = page.locator('.set-swatch'); console.log('SWATCHES ->', await sw.count()); await sw.nth(2).click(); await page.waitForTimeout(200); console.log('  accent ->', await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--accent') + ' | checked ' + document.querySelectorAll('.set-swatch[aria-checked=true]').length));
await page.reload(); await page.waitForTimeout(1500); await b.go('theme'); console.log('PERSIST after reload -> theme', await page.evaluate(() => localStorage.getItem('audspect_theme')), '| compact', await page.locator('[data-display-pref="compact"]').getAttribute('aria-checked'), '| accent', await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--accent')));
await page.screenshot({ path: T + 'sw3-theme-light.png' });
await b.go('dashprefs'); await page.locator('#dashpref-card-executive').click(); await page.waitForTimeout(200); console.log('DASHPREF ->', await page.evaluate(() => localStorage.getItem('bas_dash_pref') + ' | active ' + [...document.querySelectorAll('[id^=dashpref-card-].active')].map((e) => e.id).join(',')));
console.log('errors', JSON.stringify(b.errs)); await b.close();
// connection tests + light theme of every section
b = await boot({ theme: 'light' }); ({ page, state, T } = b); await b.go('intel');
await page.locator('#ti-misp-config-panel button', { hasText: 'Test Connection' }).click(); await page.waitForTimeout(500); console.log('MISP test ok ->', sq(await page.locator('#ti-misp-test-result').innerText()));
await page.fill('#ti-misp-key', 'bad-key'); await page.locator('#ti-misp-config-panel button', { hasText: 'Test Connection' }).click(); await page.waitForTimeout(500); console.log('  bad ->', sq(await page.locator('#ti-misp-test-result').innerText()));
await page.locator('#openaev-config-panel button', { hasText: 'Test Connection' }).click(); await page.waitForTimeout(500); console.log('OPENAEV test ->', sq(await page.locator('#oaev-test-result').innerText()));
for (const s of ['users', 'intel', 'taxii', 'audit', 'license', 'backup']) { await b.go(s); await page.screenshot({ path: T + 'sw3-L-' + s + '.png', fullPage: s !== 'audit' }); }
console.log('errors', JSON.stringify(b.errs), '| native', JSON.stringify(state.dialogs)); await b.close();
