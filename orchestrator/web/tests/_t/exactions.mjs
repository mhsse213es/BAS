import { boot } from './exlib.mjs';
const b = await boot(); const { page, T } = b;
await b.go('exercises');
const log = async (l) => console.log(l.padEnd(30), '| dlg:', JSON.stringify(b.dialogs.splice(0)), '| posts:', JSON.stringify(b.reqs.splice(0).filter((r) => r.startsWith('POST')).map((r) => r.replace('/api/exercises/', ''))), '| overlays:', await b.overlays(), '| toast:', await b.toast());
b.reqs.length = 0;
// launch with variables
await page.locator('.ex-plan', { hasText: 'Ransomware Tabletop' }).locator('button:has-text("Launch")').click(); await page.waitForTimeout(700);
await page.locator('#confirm-diff-overlay .modal').screenshot({ path: T + 'ex-launch-modal.png' });
await page.locator('#ex-var-0').fill('Domain Controllers');
await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(1500); await log('launch with vars');
console.log('  newest row:', await page.locator('#ex-execs-box tbody tr').first().innerText().then((t) => t.replace(/\s+/g, ' ')));
console.log('  vars sent:', JSON.stringify(b.state.ex['exec-501'].vars));
// empty plan
console.log('  empty plan button disabled:', await page.locator('.ex-plan', { hasText: 'Empty plan' }).locator('button').isDisabled());
// approve
await page.evaluate(() => document.getElementById('exercise-detail-overlay').classList.remove('open')); await page.locator('#ex-execs-box tbody tr', { hasText: 'Drill #7' }).click(); await page.waitForTimeout(800);
await page.locator('#exercise-detail-overlay .drawer').screenshot({ path: T + 'ex-dr-paused2.png' });
await page.locator('#exercise-detail-overlay button:has-text("Approve")').click(); await page.waitForTimeout(1000); await log('approve');
// abort via drawer -> modal
await page.locator('#exercise-detail-overlay button:has-text("Abort exercise")').click(); await page.waitForTimeout(500);
await page.locator('#confirm-diff-overlay .modal').screenshot({ path: T + 'ex-abort-modal.png' });
await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(1200); await log('abort confirm');
console.log('  drawer status now:', await page.locator('#exercise-detail-body .rk-pill').first().innerText());
console.log('errors', JSON.stringify(b.errs));
await b.close();
