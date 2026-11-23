import { boot } from './intlib.mjs';
const b = await boot(); await b.go('dashboard'); await b.page.waitForTimeout(2500);
const info = await b.page.evaluate(() => { const root = document.getElementById('dash-view-operational'); const heads = [...root.querySelectorAll('.rk-hd h2, h2, .rk-card > h3, .card-title')].filter((e) => e.offsetParent).map((e) => e.textContent.trim().replace(/\s+/g, ' ')); const c = {}; heads.forEach((h) => c[h] = (c[h] || 0) + 1); return { heads, dup: Object.entries(c).filter(([, n]) => n > 1) }; });
console.log(JSON.stringify(info.heads)); console.log('DUP', JSON.stringify(info.dup));
await b.page.screenshot({ path: b.T + 'dd.png', fullPage: true }); console.log('errors', JSON.stringify(b.errs)); await b.close();
