import { boot } from './rclib.mjs';
let b = await boot(); let { page, T } = b; await b.go();
const sq = (s) => s.replace(/\s+/g, ' ');
console.log('START hero:', sq(await page.locator('#hero-recommendations .hero-stats').innerText()), '| reqs', JSON.stringify(b.state.reqs));
for (const k of ['Top 10', 'Top 50', 'Top 20']) { await page.locator('#rec-controls button', { hasText: k }).click(); await page.waitForTimeout(700); console.log('LIMIT', k, '->', await page.locator('#rec-dt-count').innerText(), '| last req', b.state.reqs.at(-1), '| active', await page.locator('#rec-controls .on').innerText().catch(() => '?')); }
// sort
for (const c of ['Score', 'Score', 'Coverage', 'Technique', 'Environment']) { await page.locator('#rec-thead th', { hasText: c }).click(); await page.waitForTimeout(150); console.log('SORT', c, '->', sq(await page.locator('#rec-table-body tr').first().innerText()).slice(0, 60)); }
await page.fill('#rec-dt-q', 'credential'); await page.waitForTimeout(200); console.log('SEARCH credential ->', await page.locator('#rec-dt-count').innerText());
await page.fill('#rec-dt-q', 'zzz'); await page.waitForTimeout(200); console.log('SEARCH zzz ->', sq(await page.locator('#rec-empty').innerText())); await page.locator('#rec-empty button').click(); await page.waitForTimeout(150);
// copy
await page.locator('[data-on-click="copyRecommendedScenario"]').click(); await page.waitForTimeout(500); console.log('COPY ->', await b.toast(), '| clipboard:', await page.evaluate(() => navigator.clipboard.readText()));
// details
await page.locator('#rec-table-body tr').first().locator('button', { hasText: 'Details' }).click(); await page.waitForTimeout(900);
console.log('DETAILS -> drawer open', await page.evaluate(() => document.getElementById('cov-drawer-overlay').classList.contains('open')), '| title', await page.locator('#cov-drawer-title').innerText());
await page.screenshot({ path: T + 'rcw-details.png' });
await page.evaluate(() => document.getElementById('cov-drawer-overlay').classList.remove('open'));
b.state.fail['/api/attack/technique'] = 'attack data down'; await page.locator('#rec-table-body tr').first().locator('button', { hasText: 'Details' }).click(); await page.waitForTimeout(700); console.log('DETAILS FAIL -> toast', await b.toast(), '| drawer open', await page.evaluate(() => document.getElementById('cov-drawer-overlay').classList.contains('open'))); delete b.state.fail['/api/attack/technique'];
// revalidate
await page.locator('#rec-table-body tr').first().locator('button', { hasText: 'Re-validate' }).click(); await page.waitForTimeout(900); console.log('REVALIDATE -> toast', await b.toast(), '| wizard', await page.evaluate(() => [...document.querySelectorAll('.modal-overlay.open, #modal-overlay.open')].length));
await page.screenshot({ path: T + 'rcw-reval.png' });
await page.keyboard.press('Escape'); await page.evaluate(() => document.querySelectorAll('.open').forEach((e) => e.classList.remove('open')));
// custom id row has no Re-validate?
await page.locator('#rec-dt-q').fill('CUSTOM'); await page.waitForTimeout(200); console.log('CUSTOM-7 row buttons ->', JSON.stringify(await page.locator('#rec-table-body tr').first().locator('button').allInnerTexts())); await page.fill('#rec-dt-q', '');
// columns/per/export/select
await page.locator('[data-on-click="toggleRecCols"]').click(); await page.locator('#rec-cols label', { hasText: 'Why' }).locator('input').uncheck(); await page.waitForTimeout(150); console.log('HIDE Why ->', JSON.stringify(await page.locator('#rec-thead th').allInnerTexts()));
await page.locator('#rec-dt-per').selectOption('9999'); await page.waitForTimeout(150); console.log('ALL ->', await page.locator('#rec-table-body tr').count());
await page.locator('#rec-table-body tr').nth(0).locator('.dt-cb').check(); const dl = page.waitForEvent('download', { timeout: 3000 }).catch(() => null); await page.locator('[data-on-click="exportRecSelected"]').click(); const d = await dl; console.log('EXPORT ->', d ? d.suggestedFilename() : 'none', await b.toast());
console.log('errors', JSON.stringify(b.errs)); await b.close();
// failures
b = await boot(); b.state.fail['/api/recommend'] = 'engine down'; await b.go(); console.log('LOAD FAIL ->', sq(await b.page.locator('#rec-table').innerText()).slice(0, 170), '| hero', sq(await b.page.locator('#hero-recommendations .hero-stats').innerText()), '| summary', (await b.page.locator('#rec-summary').innerHTML()).length);
b.state.fail = {}; await b.page.locator('#rec-table .rk-failed button').click(); await b.page.waitForTimeout(800); console.log('  RETRY ->', await b.page.locator('#rec-dt-count').innerText());
b.state.status['/api/recommend'] = 403; b.state.fail['/api/recommend'] = 'forbidden'; await b.page.locator('[data-on-click="loadRecommendations"]').first().click(); await b.page.waitForTimeout(700); console.log('  403 ->', sq(await b.page.locator('#rec-table').innerText()).slice(0, 120)); await b.close();
b = await boot({ n: 0 }); await b.go(); console.log('EMPTY ->', sq(await b.page.locator('#rec-table').innerText()), '| copy:', await (async () => { await b.page.locator('[data-on-click="copyRecommendedScenario"]').click(); await b.page.waitForTimeout(300); return b.toast(); })(), '| summary len', (await b.page.locator('#rec-summary').innerHTML()).length); await b.close();
b = await boot({ noclip: true }); await b.go(); await b.page.evaluate(() => { Object.defineProperty(navigator, 'clipboard', { value: { writeText: () => Promise.reject(new Error('denied')) }, configurable: true }); }); await b.page.locator('[data-on-click="copyRecommendedScenario"]').click(); await b.page.waitForTimeout(500); console.log('COPY DENIED ->', await b.toast()); await b.close();
b = await boot({ role: 'viewer' }); await b.go(); console.log('VIEWER buttons row1 ->', JSON.stringify(await b.page.locator('#rec-table-body tr').first().locator('button').allInnerTexts())); await b.close();
b = await boot({ viewport: { width: 420, height: 900 } }); await b.go(); await b.page.screenshot({ path: b.T + 'rcw-phone.png', fullPage: true }); console.log('PHONE h-scroll:', await b.page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)); await b.close();
