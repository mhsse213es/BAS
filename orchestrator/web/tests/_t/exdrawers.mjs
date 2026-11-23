import { boot } from './exlib.mjs';
const b = await boot(); const { page, T } = b;
await b.go('exercises');
const P = '#ex-execs-box ';
const names = { running: 'Technical #4', paused: 'Drill #7', scored: 'Exfiltration Exercise #2', notmeasurable: 'BEC response', failed: 'Insider data staging', aborted: 'Technical #3', lowscore: 'Drill #6', created: 'Technical #5' };
for (const [k, n] of Object.entries(names)) {
  await page.locator(P + 'tbody tr', { hasText: n }).first().click(); await page.waitForTimeout(900);
  await page.locator('#exercise-detail-overlay .drawer').screenshot({ path: T + 'ex-dr-' + k + '.png' });
  await page.evaluate(() => document.getElementById('exercise-detail-overlay').classList.remove('open'));
}
// scenario drawer
await page.locator('#openaev-scenarios-body tr').first().click(); await page.waitForTimeout(800);
await page.locator('#openaev-detail-overlay .drawer').screenshot({ path: T + 'ex-dr-scenario.png' });
console.log('errors', JSON.stringify(b.errs));
await b.close();
