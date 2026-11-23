import { boot } from './rmlib.mjs';
let b = await boot(); const { page, T } = b; await b.go();
const post = () => JSON.stringify(b.reqs.splice(0)).slice(0, 400);
// endpoint expand
await page.locator('.rem-ep-head').nth(1).click(); await page.waitForTimeout(400);
await page.screenshot({ path: T + 'rmw-ep.png', fullPage: true });
console.log('EXPAND FS-LEG-01 -> aria', await page.locator('.rem-ep-head').nth(1).getAttribute('aria-expanded'), '| text:', (await page.locator('.rem-ep').nth(1).innerText()).replace(/\s+/g, ' ').slice(0, 600));
// endpoint finding View
await page.locator('.rem-ep').nth(1).locator('button:has-text("View")').first().click(); await page.waitForTimeout(500);
console.log('EP View ->', await b.overlays(), '| title:', await page.locator('#results-title').innerText());
await page.screenshot({ path: T + 'rmw-view.png' });
await page.locator('#results-overlay .drawer-close').click().catch(() => {}); await page.waitForTimeout(300);
// endpoint finding whose technique has no card (T1490)
const noCard = await page.locator('.rem-ep').nth(1).locator('.rem-ep-f', { hasText: 'T1490' }).locator('button').allInnerTexts();
console.log('T1490 (no technique card) buttons:', JSON.stringify(noCard));
// technique view
await page.locator('[data-on-click="setRemView"]', { hasText: 'By technique' }).click(); await page.waitForTimeout(400);
// Ticket single
await page.locator('.rem-fix').first().locator('button:has-text("Ticket")').click(); await page.waitForTimeout(600);
console.log('TICKET click -> overlays', await b.overlays(), '| dialogs', JSON.stringify(b.dialogs));
await page.locator('#confirm-diff-overlay .modal').screenshot({ path: T + 'rmw-confirm.png' }).catch(() => {});
console.log('  modal text:', (await page.locator('#confirm-diff-overlay').innerText()).replace(/\s+/g, ' ').slice(0, 300));
await page.locator('#confirm-diff-overlay button', { hasText: /Create ticket/ }).click(); await page.waitForTimeout(900);
console.log('  confirmed -> posts', post(), '| toast:', await b.toast(), '| button:', await page.locator('.rem-fix').first().locator('button').nth(1).innerText());
// partial failure
b.state.pushFail.add('f-T1003.001-2'); b.state.pushFail.add('f-T1003.001-3');
await page.locator('.rem-fix').nth(1).locator('button:has-text("Ticket")').click(); await page.waitForTimeout(500);
await page.locator('#confirm-diff-overlay button', { hasText: /Create ticket/ }).click(); await page.waitForTimeout(900);
console.log('PARTIAL FAIL (2 of 5 refused) -> toast:', await b.toast(), '| button:', await page.locator('.rem-fix').nth(1).locator('button').nth(1).innerText());
// all fail
for (let i = 1; i <= 4; i++) b.state.pushFail.add('f-T1190-' + i);
await page.locator('.rem-fix').nth(2).locator('button:has-text("Ticket")').click(); await page.waitForTimeout(500);
await page.locator('#confirm-diff-overlay button', { hasText: /Create ticket/ }).click(); await page.waitForTimeout(900);
console.log('ALL FAIL -> toast:', await b.toast());
// server 500
b.state.fail['push/bulk'] = 'connector timed out';
await page.locator('.rem-fix').nth(3).locator('button:has-text("Ticket")').click(); await page.waitForTimeout(500);
await page.locator('#confirm-diff-overlay button', { hasText: /Create ticket/ }).click(); await page.waitForTimeout(900);
console.log('SERVER 500 -> toast:', await b.toast()); delete b.state.fail['push/bulk'];
// no finding ids
await page.locator('.rem-fix', { hasText: 'T1005' }).locator('button:has-text("Ticket")').click(); await page.waitForTimeout(500);
console.log('NO FINDING IDS -> toast:', await b.toast());
// bulk critical
await page.locator('#rem-ticket-actions button', { hasText: 'All Critical' }).click(); await page.waitForTimeout(500);
console.log('BULK CRITICAL -> modal:', (await page.locator('#confirm-diff-overlay').innerText()).replace(/\s+/g, ' ').slice(0, 260));
await page.screenshot({ path: T + 'rmw-bulk.png' });
await page.locator('#confirm-diff-overlay button', { hasText: /Cancel/ }).click().catch(() => {}); await page.waitForTimeout(300);
// bulk all
await page.locator('#rem-ticket-actions button', { hasText: 'Create Tickets for All' }).last().click(); await page.waitForTimeout(500);
console.log('BULK ALL -> modal title:', (await page.locator('#confirm-diff-overlay').innerText()).replace(/\s+/g, ' ').slice(0, 120));
await page.locator('#confirm-diff-overlay button', { hasText: /Cancel/ }).click().catch(() => {}); await page.waitForTimeout(300);
// view drawer technique
await page.locator('.rem-fix').first().locator('button:has-text("View")').click(); await page.waitForTimeout(500);
await page.locator('#results-overlay .drawer').screenshot({ path: T + 'rmw-drawer.png' });
console.log('VIEW drawer -> header buttons:', JSON.stringify(await page.locator('#results-export button').allInnerTexts()));
await page.locator('#results-overlay .drawer-close').click().catch(() => {}); await page.waitForTimeout(300);
// revalidate
await page.locator('.rem-fix').first().locator('button:has-text("Re-validate")').click(); await page.waitForTimeout(900);
console.log('REVALIDATE ->', await b.overlays(), '| toast:', await b.toast());
await page.screenshot({ path: T + 'rmw-reval.png' });
console.log('errors', JSON.stringify(b.errs), '| native dialogs', JSON.stringify(b.dialogs));
await b.close();
