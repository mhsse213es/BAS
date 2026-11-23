import { boot } from './exlib2.mjs';
let b = await boot(); let { page, T } = b; await b.go();
const rng = () => page.locator('#exp-dt-range').innerText().catch(() => '(none)');
const hero = async () => (await page.locator('#hero-exposure .hero-stats').innerText()).replace(/\s+/g, ' ');
console.log('START hero:', await hero(), '|', await rng());
for (const f of ['Managed', 'Discovered', 'Crown jewels', 'KEV exposed']) { await page.locator('#exp-seg button', { hasText: f }).click(); await page.waitForTimeout(250); console.log('SEG', f, '->', await page.locator('#exp-count').innerText(), '|', await rng()); }
await page.locator('#exp-seg button', { hasText: 'KEV exposed' }).click(); await page.fill('#exp-search', 'unmanaged'); await page.waitForTimeout(300);
console.log('KEV + search "unmanaged" ->', (await page.locator('#exp-empty').innerText().catch(() => '')).replace(/\s+/g, ' '), '| count', await page.locator('#exp-count').innerText());
await page.locator('#exp-empty button').click().catch(() => {}); await page.waitForTimeout(300);
console.log('  after "Clear filter" -> count', await page.locator('#exp-count').innerText(), '| seg on:', await page.locator('#exp-seg .on').innerText().catch(() => '?'), '| search:', JSON.stringify(await page.inputValue('#exp-search')));
await page.screenshot({ path: T + 'exw-stuck.png' });
await page.locator('#exp-seg button', { hasText: 'All' }).click(); await page.fill('#exp-search', ''); await page.waitForTimeout(200);
// sort
await page.locator('#exp-thead th', { hasText: 'Exposure' }).click(); await page.waitForTimeout(200); console.log('SORT exposure asc -> first:', (await page.locator('#exp-table-body tr').first().innerText()).replace(/\s+/g, ' ').slice(0, 50));
await page.locator('#exp-thead th', { hasText: 'Exposure' }).click(); await page.waitForTimeout(200); console.log('  desc -> first:', (await page.locator('#exp-table-body tr').first().innerText()).replace(/\s+/g, ' ').slice(0, 50));
await page.locator('#exp-thead th', { hasText: 'Crown jewel' }).click(); await page.waitForTimeout(200); console.log('SORT crown -> first:', (await page.locator('#exp-table-body tr').first().innerText()).replace(/\s+/g, ' ').slice(0, 70));
// drawer: normal, keyboard, close, stale, failures
await page.locator('#exp-table-body tr').nth(1).focus(); await page.keyboard.press('Enter'); await page.waitForTimeout(700);
console.log('KEYBOARD open -> title:', await page.locator('#exp-detail-title').innerText());
console.log('  sections:', JSON.stringify(await page.locator('#exp-detail-body .sc-h4').allInnerTexts()));
await page.locator('#exposure-detail-overlay .drawer-body').evaluate((e) => e.scrollTo(0, e.scrollHeight)); await page.waitForTimeout(200);
await page.locator('#exposure-detail-overlay .drawer').screenshot({ path: T + 'exw-drawer-bottom.png' });
console.log('  related link ->'); await page.locator('#exp-detail-body .sc-rel').first().click(); await page.waitForTimeout(900);
console.log('    drawer closed:', !(await page.evaluate(() => document.getElementById('exposure-detail-overlay').classList.contains('open'))), '| now on findings tab visible:', await page.evaluate(() => getComputedStyle(document.getElementById('tab-findings')).display !== 'none'));
await b.go();
// profile failure + 403 + 404
b.state.fail['/api/exposure/assets/'] = 'profile builder crashed';
await page.locator('#exp-table-body tr').first().click(); await page.waitForTimeout(800);
console.log('PROFILE 500 ->', (await page.locator('#exp-detail-body').innerText()).replace(/\s+/g, ' '), '| title kept:', await page.locator('#exp-detail-title').innerText());
await page.screenshot({ path: T + 'exw-profile-fail.png' });
b.state.status['/api/exposure/assets/'] = 403; await page.locator('#exposure-detail-overlay .drawer-close').click(); await page.locator('#exp-table-body tr').nth(1).click(); await page.waitForTimeout(700);
console.log('PROFILE 403 ->', (await page.locator('#exp-detail-body').innerText()).replace(/\s+/g, ' ').slice(0, 140));
delete b.state.fail['/api/exposure/assets/']; delete b.state.status['/api/exposure/assets/'];
await page.locator('#exposure-detail-overlay .drawer-close').click();
// columns / per page / export / select
await page.locator('[data-on-click="toggleExpCols"]').click(); await page.locator('#exp-cols label', { hasText: 'Detection' }).locator('input').uncheck(); await page.waitForTimeout(200);
console.log('HIDE Detection ->', JSON.stringify(await page.locator('#exp-thead th').allInnerTexts()));
await page.locator('#exp-dt-per').selectOption('9999'); await page.waitForTimeout(200); console.log('ALL ROWS ->', await page.locator('#exp-table-body tr').count());
await page.locator('#exp-table-body tr').nth(0).locator('.dt-cb').check(); await page.locator('#exp-table-body tr').nth(1).locator('.dt-cb').check(); await page.waitForTimeout(200);
const dl = page.waitForEvent('download', { timeout: 3000 }).catch(() => null); await page.locator('[data-on-click="exportExpSelected"]').click(); const d = await dl; console.log('EXPORT selected ->', d ? d.suggestedFilename() : 'none', await b.toast());
// refresh
await page.locator('[data-on-click="loadExposureAssets"]').first().click(); await page.waitForTimeout(900); console.log('REFRESH -> rows kept filter state? per page:', await page.locator('#exp-dt-per').inputValue(), '| selection cleared:', !(await page.locator('#exp-bulk').isVisible()));
console.log('errors', JSON.stringify(b.errs)); await b.close();
// load failures / empty / phone
b = await boot(); b.state.fail['/api/exposure/assets'] = 'inventory db down'; await b.go();
console.log('LOAD FAIL ->', (await b.page.locator('#exp-main').innerText()).replace(/\s+/g, ' ').slice(0, 160), '| hero', (await b.page.locator('#hero-exposure .hero-stats').innerText()).replace(/\s+/g, ' '), '| toast', await b.toast());
await b.page.screenshot({ path: b.T + 'exw-fail.png' }); await b.close();
b = await boot({ empty: true }); await b.go(); console.log('EMPTY ->', (await b.page.locator('#exp-main').innerText()).replace(/\s+/g, ' ')); await b.close();
b = await boot({ viewport: { width: 420, height: 900 } }); await b.go(); await b.page.screenshot({ path: b.T + 'exw-phone.png', fullPage: true });
console.log('PHONE h-scroll:', await b.page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)); await b.close();
