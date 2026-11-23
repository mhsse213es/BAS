import { boot } from './iolib.mjs';
const b = await boot(); const { page, T } = b; await b.go();
const rows = () => page.locator('#ioc-registry-body tr').count();
const hero = async () => (await page.locator('#hero-iocs .hero-stats').innerText().catch(() => '')).replace(/\s+/g, ' ');
console.log('start rows', await rows(), '| hero:', await hero());
// drawer w/ sightings
await page.locator('#ioc-registry-body tr', { hasText: 'rundll32.exe' }).click(); await page.waitForTimeout(900);
await page.locator('#ioc-drawer-overlay .drawer').screenshot({ path: T + 'io-w-drawer.png' });
console.log('drawer ->', await b.overlays(), '|', (await page.locator('#ioc-drawer-body').innerText()).replace(/\s+/g, ' ').slice(0, 260));
await page.locator('#ioc-drawer-overlay .drawer-close').click(); await page.waitForTimeout(300);
// zero sightings + suppressed drawer
await page.locator('#ioc-registry-body tr', { hasText: 'billing@invoice' }).click(); await page.waitForTimeout(900);
console.log('zero-sighting drawer ->', (await page.locator('#ioc-detail-relationships').innerText()).replace(/\s+/g, ' '));
await page.locator('#ioc-drawer-overlay .drawer-close').click(); await page.waitForTimeout(300);
// keyboard
await page.locator('#ioc-registry-body tr').nth(1).focus().catch(() => {}); await page.keyboard.press('Enter'); await page.waitForTimeout(600);
console.log('Enter on focused row ->', JSON.stringify(await b.overlays()), '| row focusable:', await page.locator('#ioc-registry-body tr').first().getAttribute('tabindex'));
// suppress via row, native prompt cancelled
b.dialogs.length = 0; b.reqs.length = 0;
await page.locator('#ioc-registry-body tr', { hasText: 'wmic.exe' }).locator('button:has-text("Suppress")').click(); await page.waitForTimeout(700);
console.log('suppress (prompt dismissed) -> dialogs', JSON.stringify(b.dialogs), '| posts', JSON.stringify(b.reqs), '| rows', await rows(), '| toast:', await b.toast());
await b.close();
const c = await boot({ promptAnswer: 'Known red-team tooling' }); await c.go();
await c.page.locator('#ioc-registry-body tr', { hasText: 'wmic.exe' }).locator('button:has-text("Suppress")').click(); await c.page.waitForTimeout(1000);
console.log('suppress (answered) -> posts', JSON.stringify(c.reqs), '| rows', await c.page.locator('#ioc-registry-body tr').count(), '| toast:', await c.toast(), '| hero:', (await c.page.locator('#hero-iocs .hero-stats').innerText()).replace(/\s+/g, ' '));
console.log('wmic still visible:', await c.page.locator('#ioc-registry-body tr', { hasText: 'wmic.exe' }).count());
await c.page.locator('#ioc-filter-suppressed').check(); await c.page.waitForTimeout(800);
console.log('show suppressed ->', await c.page.locator('#ioc-registry-body tr').count(), '| clear btn visible:', await c.vis('#ioc-clear-btn'));
await c.page.locator('#ioc-registry-body tr', { hasText: 'wmic.exe' }).click(); await c.page.waitForTimeout(800);
await c.page.locator('#ioc-drawer-overlay .drawer').screenshot({ path: T + 'io-w-drawer-sup.png' });
console.log('errors', JSON.stringify(c.errs)); await c.close();
