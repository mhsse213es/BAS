import { boot } from './intlib.mjs';
const b = await boot(); await b.go();
const { page, T } = b;
await page.screenshot({ path: T + 'in-0.png', fullPage: true });
console.log('hero', (await page.locator('#hero-integrations').innerText()).replace(/\s+/g, ' ').slice(0, 200));
console.log('errors', JSON.stringify(b.errs));
await b.close();
