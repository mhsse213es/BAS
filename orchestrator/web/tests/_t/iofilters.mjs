import { boot } from './iolib.mjs';
const T = 'C:/Users/Administrator/AppData/Local/Temp/';
let b = await boot(); const { page } = b; await b.go();
const rows = () => page.locator('#ioc-registry-body tr').count();
const hero = async () => (await page.locator('#hero-iocs .hero-stats').innerText()).replace(/\s+/g, ' ');
const first = async () => (await page.locator('#ioc-registry-body tr').first().innerText()).replace(/\s+/g, ' ').slice(0, 60);
// type chip
await page.locator('.ioc-chip', { hasText: 'IP' }).first().click(); await page.waitForTimeout(900);
console.log('chip IP -> rows', await rows(), '| type select =', await page.locator('#ioc-filter-type').inputValue(), '| hero:', await hero(), '| chips still shown:', await page.locator('.ioc-chip').count(), '| clear btn:', await b.vis('#ioc-clear-btn'));
await page.locator('.ioc-chip', { hasText: 'All types' }).click(); await page.waitForTimeout(800); console.log('All types chip -> rows', await rows());
// search: typing then Enter
await page.locator('#ioc-filter-search').fill('example'); await page.waitForTimeout(500);
console.log('typed "example" (no Enter) -> rows', await rows());
await page.locator('#ioc-filter-search').press('Enter'); await page.waitForTimeout(800);
console.log('Enter -> rows', await rows(), '| hero:', await hero());
await page.locator('#ioc-filter-search').fill('zzzzzz'); await page.locator('#ioc-searchbar button:has-text("Search")').click(); await page.waitForTimeout(800);
console.log('no match -> body:', (await page.locator('#ioc-registry-body').innerText()).replace(/\s+/g, ' '), '| charts present:', await page.locator('#ioc-side').innerText().then((t) => t.length), '| hero:', await hero());
await page.screenshot({ path: T + 'io-f-nomatch.png', clip: { x: 240, y: 60, width: 1200, height: 900 } });
await page.locator('#ioc-clear-btn').click(); await page.waitForTimeout(800); console.log('Clear filters -> rows', await rows(), '| search:', JSON.stringify(await page.locator('#ioc-filter-search').inputValue()));
// selects
await page.locator('#ioc-filter-status').selectOption('missed'); await page.waitForTimeout(800); console.log('status=missed -> rows', await rows(), '| hero:', await hero());
await page.locator('#ioc-filter-source').selectOption('manual'); await page.waitForTimeout(800); console.log('+ source=manual -> rows', await rows(), '|', await first());
await page.locator('#ioc-clear-btn').click(); await page.waitForTimeout(500);
// failure
b.state.fail['/api/iocs'] = 'database unavailable'; await page.locator('#ioc-searchbar button:has-text("Search")').click(); await page.waitForTimeout(900);
console.log('LOAD FAIL -> body:', (await page.locator('#ioc-registry-body').innerText()).replace(/\s+/g, ' '), '| hero:', await hero());
await page.screenshot({ path: T + 'io-f-fail.png', clip: { x: 240, y: 60, width: 1200, height: 900 } });
console.log('errors', JSON.stringify(b.errs)); await b.close();
// empty
b = await boot({ empty: true }); await b.go(); await b.page.screenshot({ path: T + 'io-f-empty.png', clip: { x: 240, y: 60, width: 1200, height: 800 } });
console.log('EMPTY -> hero:', (await b.page.locator('#hero-iocs .hero-stats').innerText()).replace(/\s+/g, ' '), '| body:', (await b.page.locator('#ioc-registry-body').innerText()).replace(/\s+/g, ' '), '| tiles:', (await b.page.locator('#ioc-analytics-tiles').innerText()).replace(/\s+/g, ' ').slice(0, 120));
await b.close();
// viewer
b = await boot({ role: 'viewer' }); await b.go();
console.log('VIEWER -> add btn:', await b.vis('#ioc-add-btn'), '| import btns:', await b.vis('#ioc-import-btn'), await b.vis('#ioc-import-btn2'), '| suppress buttons:', await b.page.locator('#ioc-registry-body button').count());
await b.page.locator('#ioc-registry-body tr').first().click(); await b.page.waitForTimeout(700); console.log('  viewer drawer suppression section:', (await b.page.locator('#ioc-drawer-body').innerText()).includes('SUPPRESSION'));
await b.close();
