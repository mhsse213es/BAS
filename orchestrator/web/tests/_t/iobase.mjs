import { boot } from './iolib.mjs';
const b = await boot(); const { page, T } = b; await b.go();
const h = await page.evaluate(() => document.documentElement.scrollHeight); console.log('height', h);
for (let y = 0, i = 0; y < h; y += 900, i++) await page.screenshot({ path: T + 'io-base-' + i + '.png', fullPage: true, clip: { x: 240, y, width: 1200, height: Math.min(900, h - y) } });
console.log('visible hero buttons:', JSON.stringify(await page.evaluate(() => [...document.querySelectorAll('#hero-iocs button, #tab-iocs button')].filter((e) => e.offsetParent).map((e) => (e.id || '') + ':' + e.textContent.trim().slice(0, 20)))));
console.log('errors', JSON.stringify(b.errs)); await b.close();
