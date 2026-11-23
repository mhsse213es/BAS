import { boot } from './setlib.mjs';
const b = await boot(); const { page } = b; await b.go('theme');
const acc = () => page.evaluate(() => getComputedStyle(document.body).getPropertyValue('--accent').trim() || getComputedStyle(document.documentElement).getPropertyValue('--accent').trim());
const out = [await acc()];
for (let i = 0; i < 5; i++) { await page.locator('.set-swatch').nth(i).click(); await page.waitForTimeout(150); out.push(await acc() + ' ' + (await page.evaluate(() => localStorage.getItem('audspect_accent') || [...Object.keys(localStorage)].filter((k) => /accent/.test(k)).join(',')))); }
console.log(JSON.stringify(out)); await b.close();
