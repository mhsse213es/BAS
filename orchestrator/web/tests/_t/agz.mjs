import { boot } from './aglib.mjs';
const b = await boot(); const { page, T } = b; await b.go();
await page.locator('#agents-body tr').first().click(); await page.waitForTimeout(1000);
await page.locator('#agt-tab-overview button', { hasText: 'Stop Agent' }).click(); await page.waitForTimeout(400);
console.log(await page.evaluate(() => ['stop-agent-overlay', 'agent-detail-overlay', 'confirm-diff-overlay'].map((id) => { const e = document.getElementById(id); return id + ' z=' + getComputedStyle(e).zIndex + ' open=' + e.classList.contains('open'); }).join(' | ')));
await page.screenshot({ path: T + 'agz.png' });
await b.close();
