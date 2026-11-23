import { boot } from './tcvlib.mjs';
let b = await boot(); let { page, T } = b; await b.go();
const hero = async () => (await page.locator('#hero-attack-coverage .hero-stats').innerText()).replace(/\s+/g, ' ');
const rng = () => page.locator('#tcv-dt-range').innerText().catch(() => '(no table)');
await page.locator('.tcv-chip', { hasText: 'APT29' }).click(); await page.waitForTimeout(700);
console.log('CHIP APT29 -> hero', await hero(), '|', await rng(), '| note:', await page.locator('#cov-actor-note').innerText(), '| select:', await page.locator('#cov-actor-select').inputValue());
await page.locator('#cov-f-result').selectOption('gaps'); await page.waitForTimeout(300); console.log('  filter gaps ->', await rng());
await page.locator('#cov-actor-select').selectOption('Lazarus Group'); await page.waitForTimeout(700);
console.log('SELECT Lazarus -> filter kept?', await page.locator('#cov-f-result').inputValue(), '|', await rng(), '| chip on:', await page.locator('.tcv-chip.on').innerText());
await page.locator('#cov-actor-select').selectOption('Empty Actor'); await page.waitForTimeout(700);
console.log('EMPTY ACTOR ->', (await page.locator('#cov-table').innerText()).replace(/\s+/g, ' '), '| hero', await hero(), '| summary cards:', await page.locator('#cov-summary').innerHTML().then((h) => h.length));
await page.screenshot({ path: T + 'tcv-empty-actor.png' });
await page.locator('#cov-actor-select').selectOption(''); await page.waitForTimeout(700);
// search / result / table filter
await page.fill('#cov-search', 'T1010'); await page.waitForTimeout(300); console.log('SEARCH T1010 ->', await rng());
await page.fill('#cov-search', 'Credential'); await page.waitForTimeout(300); console.log('SEARCH by NAME "Credential" ->', (await page.locator('#cov-table').innerText()).replace(/\s+/g, ' ').slice(0, 60));
console.log('IN-TABLE FILTER box present:', await page.locator('#tcv-dt-q').count());
// sort + select + export
await page.locator('#tcv-thead th', { hasText: 'Coverage' }).click(); await page.waitForTimeout(200); console.log('SORT coverage asc first row:', (await page.locator('#tcv-body tr').first().innerText()).replace(/\s+/g, ' ').slice(0, 60));
await page.locator('#tcv-body tr').first().click(); await page.waitForTimeout(900);
console.log('ROW CLICK -> drawer open:', await page.evaluate(() => document.getElementById('cov-drawer-overlay').classList.contains('open')), '| title:', await page.locator('#cov-drawer-title').innerText(), '|', await page.locator('#cov-drawer-sub').innerText(), '| dims:', await page.locator('.tcv-dim').count(), '| todo lines:', await page.locator('.tcv-dim-todo').count(), '| buttons:', JSON.stringify(await page.locator('.tcv-dr-acts button').allInnerTexts()), '| about:', (await page.locator('#tcv-dr-about').innerText()).replace(/s+/g,' ').slice(0,90));
await page.locator('#cov-drawer-overlay .drawer').screenshot({ path: T + 'tcv-drawer.png' });
await page.locator('#cov-drawer-overlay .drawer-close').click(); await page.waitForTimeout(300);
await page.locator('#tcv-body tr').nth(2).focus(); await page.keyboard.press('Enter'); await page.waitForTimeout(700); console.log('KEYBOARD Enter -> drawer:', await page.locator('#cov-drawer-title').innerText()); await page.locator('#cov-drawer-overlay .drawer-close').click(); await page.waitForTimeout(300);
await page.locator('#tcv-body tr').nth(3).locator('.dt-cb').click(); await page.waitForTimeout(300); console.log('CHECKBOX click opens drawer?', await page.evaluate(() => document.getElementById('cov-drawer-overlay').classList.contains('open')));
await page.locator('#tcv-body tr').nth(3).locator('.dt-cb').click(); await page.waitForTimeout(200);
await page.locator('#tcv-body tr').first().locator('.dt-cb').check(); await page.waitForTimeout(200); console.log('SELECT -> bulk:', (await page.locator('#tcv-bulk').innerText()).replace(/\s+/g, ' '));
const dl = page.waitForEvent('download', { timeout: 3000 }).catch(() => null); await page.locator('[data-on-click="exportTcvSelected"]').click(); const d = await dl; console.log('EXPORT selected ->', d ? d.suggestedFilename() : 'none', await b.toast());
console.log('errors', JSON.stringify(b.errs)); await b.close();
// failures
b = await boot(); b.state.fail['/api/coverage/matrix'] = 'database unavailable'; await b.go();
console.log('MATRIX FAIL ->', (await b.page.locator('#cov-table').innerText()).replace(/\s+/g, ' '), '| hero', (await b.page.locator('#hero-attack-coverage .hero-stats').innerText()).replace(/\s+/g, ' '));
await b.page.screenshot({ path: T + 'tcv-fail.png' }); await b.close();
b = await boot(); b.state.fail['/api/coverage/actors'] = 'actor index unavailable'; await b.go();
console.log('ACTORS FAIL -> select options:', await b.page.locator('#cov-actor-select option').count(), '| chips:', await b.page.locator('.tcv-chip').count(), '| toast/inline msg:', await b.toast(), (await b.page.locator('.tcv-actor').innerText()).replace(/\s+/g, ' ').slice(0, 120)); await b.close();
b = await boot({ empty: true }); await b.go();
console.log('MATRIX EMPTY ->', (await b.page.locator('#cov-table').innerText()).replace(/\s+/g, ' ')); await b.close();
b = await boot({ viewport: { width: 420, height: 900 } }); await b.go();
console.log('PHONE h-scroll:', await b.page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)); await b.page.screenshot({ path: T + 'tcv-phone.png', fullPage: true }); await b.close();
