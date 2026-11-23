import { boot } from './aplib.mjs';
const b = await boot(); const { page, T } = b;
await b.go();
const h = await page.evaluate(() => document.documentElement.scrollHeight); console.log('height', h);
for (let y = 0, i = 0; y < h; y += 900, i++) await page.screenshot({ path: T + 'ap-base-' + i + '.png', fullPage: true, clip: { x: 240, y, width: 1200, height: Math.min(900, h - y) } });
console.log('errors', JSON.stringify(b.errs), 'dialogs', JSON.stringify(b.dialogs));
await b.close();
