import { boot } from './tcvlib.mjs';
const b = await boot(); const { page, T } = b; await b.go();
console.log('errors', JSON.stringify(b.errs), '| height', await page.evaluate(() => document.documentElement.scrollHeight));
console.log('rows', await page.locator('#tcv-body tr').count(), '|', await page.locator('#tcv-dt-range').innerText(), '| pages', (await page.locator('#tcv-dt-pager').innerText()).replace(/\s+/g, ' '));
await page.screenshot({ path: T + 'tcv-0.png', fullPage: true });
await b.close();
