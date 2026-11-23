import { boot } from './aplib.mjs';
const b = await boot(); const { page } = b; await b.go();
await page.locator('#ap-collect-btn').click(); await page.waitForTimeout(400);
console.log(JSON.stringify(await page.evaluate(() => ['#ap-collect', '#ap-collect .dash-panel-body', '#ap-form', '#ap-form > div:first-child', '#ap-form > div:first-child > button'].map((s) => { const e = document.querySelector(s); const r = e.getBoundingClientRect(); const c = getComputedStyle(e); return [s, Math.round(r.width), c.maxWidth, c.display, c.justifyContent]; })), null, 0));
await b.close();
