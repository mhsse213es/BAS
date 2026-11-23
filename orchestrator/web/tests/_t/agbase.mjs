import { boot } from './aglib.mjs';
const b = await boot(); const { page, T } = b; await b.go();
console.log('errors', JSON.stringify(b.errs), '| height', await page.evaluate(() => document.documentElement.scrollHeight));
await page.screenshot({ path: T + 'ag-0.png', fullPage: true });
await page.locator('#agents-body tr').first().click(); await page.waitForTimeout(1200);
await page.screenshot({ path: T + 'ag-drawer.png' });
await b.close();
