import { boot } from './iolib.mjs';
const T = 'C:/Users/Administrator/AppData/Local/Temp/';
const b = await boot(); const { page } = b; await b.go();
const rows = () => page.locator('#ioc-registry-body tr[tabindex]').count();
const hero = async () => (await page.locator('#hero-iocs .hero-stats').innerText()).replace(/\s+/g, ' ');
const post = () => JSON.stringify(b.reqs.splice(0)).slice(0, 200);
console.log('START rows', await rows(), '(page size 25) | hero:', await hero(), '| count:', await page.locator('#ioc-count').innerText());
// keyboard
await page.locator('#ioc-registry-body tr[tabindex]').nth(1).focus(); await page.keyboard.press('Enter'); await page.waitForTimeout(600);
console.log('KEYBOARD Enter ->', await b.overlays()); await page.locator('#ioc-drawer-overlay .drawer-close').click(); await page.waitForTimeout(300);
// copy
await page.context().grantPermissions(['clipboard-read', 'clipboard-write']).catch(() => {});
await page.locator('#ioc-registry-body tr[tabindex]').nth(1).click(); await page.waitForTimeout(600);
await page.locator('#ioc-drawer-body button:has-text("Copy value")').click(); await page.waitForTimeout(400);
console.log('COPY -> toast:', await b.toast(), '| clipboard:', await page.evaluate(() => navigator.clipboard.readText().catch((e) => 'ERR ' + e.message)));
await page.locator('#ioc-drawer-overlay .drawer').screenshot({ path: T + 'io-v-drawer.png' });
await page.locator('#ioc-drawer-overlay .drawer-close').click(); await page.waitForTimeout(300);
// suppress: modal, empty reason, preset, confirm
b.dialogs.length = 0;
await page.locator('#ioc-registry-body tr', { hasText: 'wmic.exe' }).locator('button:has-text("Suppress")').click(); await page.waitForTimeout(500);
console.log('SUPPRESS click -> native dialogs', JSON.stringify(b.dialogs), '| overlay', await b.overlays());
await page.locator('#ioc-sup-overlay .modal').screenshot({ path: T + 'io-v-sup.png' });
await page.locator('#ioc-sup-submit-btn').click(); await page.waitForTimeout(300);
console.log('  empty reason ->', await page.locator('#ioc-sup-err').innerText(), '| posts', post());
await page.locator('.ioc-sup-presets button:has-text("Known lab tool")').click(); console.log('  preset fills:', await page.locator('#ioc-sup-reason').inputValue());
await page.locator('#ioc-sup-submit-btn').click(); await page.waitForTimeout(900);
console.log('  confirmed -> posts', post(), '| toast:', await b.toast(), '| overlay', JSON.stringify(await b.overlays()), '| hero:', await hero(), '| wmic row:', await page.locator('#ioc-registry-body tr', { hasText: 'wmic.exe' }).count());
b.state.fail['/suppress'] = 'registry is locked'; await page.locator('#ioc-registry-body tr', { hasText: 'rundll32.exe' }).locator('button:has-text("Suppress")').click(); await page.waitForTimeout(300);
await page.locator('#ioc-sup-reason').fill('test'); await page.locator('#ioc-sup-submit-btn').click(); await page.waitForTimeout(800);
console.log('SUPPRESS refused -> toast:', await b.toast(), '| modal still open:', await b.overlays(), '| rundll32 still listed:', await page.locator('#ioc-registry-body tr', { hasText: 'rundll32.exe' }).count());
delete b.state.fail['/suppress']; await page.locator('#ioc-sup-overlay .drawer-close, #ioc-sup-overlay button:has-text("Cancel")').first().click(); await page.waitForTimeout(300);
// filters: banner must not follow
await page.locator('.ioc-chip', { hasText: 'IP' }).first().click(); await page.waitForTimeout(1100);
console.log('FILTER IP -> rows', await rows(), '| hero:', await hero(), '| count:', await page.locator('#ioc-count').innerText());
await page.locator('#ioc-filter-search').fill('zzzz'); await page.waitForTimeout(900);
console.log('LIVE SEARCH zzzz (no Enter) -> body:', (await page.locator('#ioc-registry-body').innerText()).replace(/\s+/g, ' '), '| hero:', await hero());
await page.locator('#ioc-registry-body button:has-text("Clear filters")').click(); await page.waitForTimeout(900);
console.log('CLEAR -> rows', await rows(), '| search:', JSON.stringify(await page.locator('#ioc-filter-search').inputValue()));
// show more
await page.locator('.ioc-more button').click().catch(() => {}); await page.waitForTimeout(300);
console.log('SHOW MORE ->', await rows(), '| button left:', await page.locator('.ioc-more').count());
// add
await page.locator('#ioc-add-btn').click(); await page.waitForTimeout(400);
await page.locator('#ioc-add-value').fill('evil-c2.example.org'); console.log('ADD guess domain ->', await page.locator('#ioc-add-type').inputValue());
await page.locator('#ioc-add-value').fill('203.0.113.99'); console.log('  guess ip ->', await page.locator('#ioc-add-type').inputValue());
await page.locator('#ioc-add-type').selectOption('service'); await page.locator('#ioc-add-value').fill('evil-c2.example.org'); console.log('  manual type kept ->', await page.locator('#ioc-add-type').inputValue());
await page.locator('#ioc-add-type').selectOption('domain');
b.state.fail['/import'] = 'database is read-only'; await page.locator('#ioc-add-submit-btn').click(); await page.waitForTimeout(700);
console.log('  refused -> err:', await page.locator('#ioc-add-err').innerText());
delete b.state.fail['/import']; await page.locator('#ioc-add-submit-btn').click(); await page.waitForTimeout(1000);
console.log('  added -> toast:', await b.toast(), '| modal', JSON.stringify(await b.overlays()), '| count:', await page.locator('#ioc-count').innerText(), '| hero:', await hero());
await page.locator('#ioc-add-btn').click(); await page.waitForTimeout(300); await page.locator('#ioc-add-value').fill('evil-c2.example.org'); await page.locator('#ioc-add-submit-btn').click(); await page.waitForTimeout(500);
console.log('  duplicate -> err:', await page.locator('#ioc-add-err').innerText()); await page.locator('#ioc-add-overlay button:has-text("Cancel")').click();
// import
await page.locator('#ioc-import-btn').click(); await page.waitForTimeout(300);
await page.locator('#ioc-import-text').fill('domain,ok1.example\nfoo_type,x'); await page.locator('#ioc-import-submit-btn').click(); await page.waitForTimeout(300);
console.log('IMPORT unknown type ->', await page.locator('#ioc-import-err').innerText().then((t) => t.slice(0, 120)), '| posts', post());
await page.locator('#ioc-import-text').fill('domain,ok1.example\nIP,192.0.2.9\nfile hash,abc123'); await page.locator('#ioc-import-submit-btn').click(); await page.waitForTimeout(1000);
console.log('  valid ->', await b.toast(), '| modal', JSON.stringify(await b.overlays()), '| posts', post());
console.log('errors', JSON.stringify(b.errs), '| native dialogs', JSON.stringify(b.dialogs)); await b.close();
