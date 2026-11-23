import { boot } from './aglib.mjs';
const b = await boot(); const { page } = b; await b.go();
await page.locator('#hero-agents button', { hasText: 'Deploy Agent' }).click();
for (const t of [300, 900, 1800, 3000]) { await page.waitForTimeout(t === 300 ? 300 : 700); console.log(t, await page.evaluate(() => ({ y: Math.round(scrollY), top: Math.round(document.getElementById('agent-deploy-section').getBoundingClientRect().top), h: document.documentElement.scrollHeight, vh: innerHeight, scroller: (document.scrollingElement || {}).tagName }))); }
console.log(await page.evaluate(() => { const m = document.querySelector('main, .main, #main-content, .content'); return m ? m.className + ' ' + m.scrollTop + '/' + m.scrollHeight + '/' + m.clientHeight : 'no main'; }));
await b.close();
