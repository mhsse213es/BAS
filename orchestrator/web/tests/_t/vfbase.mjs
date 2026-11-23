import { boot } from './vflib.mjs';
const b = await boot(); const { page, T } = b; await b.go('run-1');
console.log('errors', JSON.stringify(b.errs), '| height', await page.evaluate(() => document.documentElement.scrollHeight));
await page.screenshot({ path: T + 'vf-0.png', fullPage: true });
await b.close();
