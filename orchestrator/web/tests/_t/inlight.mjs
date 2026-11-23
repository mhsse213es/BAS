import { boot } from './intlib.mjs';
const b = await boot({ theme: 'light', data: { reval: 2 } }); const { page, T } = b; await b.go();
console.log('theme attr', await page.evaluate(() => document.documentElement.getAttribute('data-theme') + ' bg ' + getComputedStyle(document.body).backgroundColor));
await page.screenshot({ path: T + 'inl-top.png', fullPage: true });
await page.locator('.int-card', { hasText: 'Jira SEC board' }).click(); await page.waitForTimeout(500);
await page.fill('#cfs-username', 'bad@x'); await page.locator('[data-on-click="testConnectorForm"]').click(); await page.waitForTimeout(500);
await page.screenshot({ path: T + 'inl-dlg.png' });
console.log('errors', JSON.stringify(b.errs)); await b.close();
