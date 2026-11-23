import { boot } from './exlib.mjs';
const b = await boot(); const { page, T } = b; await b.go('exercises');
await page.locator('#openaev-scenarios-body tr').first().click(); await page.waitForTimeout(700);
await page.locator('#openaev-detail-overlay button:has-text("Create exercise plan")').click(); await page.waitForTimeout(900);
await page.screenshot({ path: T + 'ex-c-after.png' });
console.log('new plan highlighted:', await page.locator('.ex-plan-new').count(), '| in viewport:', await page.locator('.ex-plan-new').evaluate((n) => { const r = n.getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight; }).catch(() => 'n/a'));
console.log(JSON.stringify(b.errs)); await b.close();
