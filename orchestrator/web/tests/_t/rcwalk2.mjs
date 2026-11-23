import { boot } from './rclib.mjs';
let b = await boot(); let { page, T } = b; await b.go();
const sq = (s) => s.replace(/\s+/g, ' ');
const first = async () => sq(await page.locator('#rec-table-body tr').first().innerText()).slice(0, 60);
console.log('TIERBAR ->', sq(await page.locator('#rec-tierbar').innerText()));
for (const t of ['Critical', 'High', 'Medium', 'Low']) { await page.locator('#rec-tierbar .cov-seg button, #rec-tierbar button', { hasText: t }).first().click(); await page.waitForTimeout(200); console.log('TIER', t, '->', await page.locator('#rec-dt-count').innerText(), '| rows', await page.locator('#rec-table-body tr').count(), '| first', await first()); }
await page.locator('#rec-tierbar button', { hasText: 'Critical' }).first().click(); await page.locator('.rec-never').click(); await page.waitForTimeout(200);
console.log('CRITICAL + never ->', await page.locator('#rec-dt-count').innerText(), '| pressed', await page.locator('.rec-never').getAttribute('aria-pressed'));
await page.fill('#rec-dt-q', 'zzz'); await page.waitForTimeout(200); console.log('  + search zzz ->', sq(await page.locator('#rec-empty').innerText()));
await page.locator('#rec-empty button').click(); await page.waitForTimeout(200); console.log('  Clear filters ->', await page.locator('#rec-dt-count').innerText(), '| all active', await page.locator('#rec-tierbar .on').first().innerText(), '| never pressed', await page.locator('.rec-never').getAttribute('aria-pressed'), '| search', JSON.stringify(await page.inputValue('#rec-dt-q')));
// rank stays the server rank when sorted / filtered
await page.locator('#rec-thead th', { hasText: 'Technique' }).click(); await page.waitForTimeout(200);
console.log('RANK after sort by name ->', JSON.stringify(await page.locator('#rec-table-body .rec-rank').allInnerTexts()));
await page.locator('#rec-tierbar button', { hasText: 'High' }).first().click(); await page.waitForTimeout(200);
console.log('RANK in High tier ->', JSON.stringify(await page.locator('#rec-table-body .rec-rank').allInnerTexts()));
// header help
console.log('HEADER help ->', JSON.stringify(await page.locator('#rec-thead th[title]').evaluateAll((e) => e.map((x) => x.textContent.trim().replace(/[▲▼]/g, '') + ': ' + x.title.slice(0, 40)))));
// suggest card + limit reset
await page.locator('#rec-controls button', { hasText: 'Top 10' }).click(); await page.waitForTimeout(800); console.log('TOP 10 -> tier reset', await page.locator('#rec-tierbar .on').first().innerText(), '| suggest', sq(await page.locator('.rec-suggest').innerText()).slice(0, 90));
await page.screenshot({ path: T + 'rc2-filtered.png' });
// skeleton visible while loading
await page.route('**/api/recommend/simulations*', async (r) => { await new Promise((x) => setTimeout(x, 1500)); r.fallback(); });
await page.locator('#rec-controls button', { hasText: 'Top 50' }).click(); await page.waitForTimeout(300);
console.log('SKELETON ->', await page.locator('.rec-skel-row').count(), 'rows | suggest cleared', (await page.locator('#rec-suggest').innerHTML()).length === 0);
await page.screenshot({ path: T + 'rc2-skel.png' }); await page.waitForTimeout(1600);
// keyboard
await page.locator('#rec-table-body tr').first().focus(); await page.keyboard.press('Enter'); await page.waitForTimeout(800); console.log('KEYBOARD Enter -> drawer', await page.evaluate(() => document.getElementById('cov-drawer-overlay').classList.contains('open')));
console.log('errors', JSON.stringify(b.errs)); await b.close();
// suggested card states
b = await boot({ n: 3 }); await b.go(); console.log('SMALL (3) ->', sq(await b.page.locator('.rec-suggest').innerText()).slice(0, 120)); await b.close();
b = await boot(); await b.page.route('**/api/recommend/simulations*', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ techniques: [{ techniqueId: 'CUSTOM-1', name: 'Custom thing', tactic: 'Impact', score: 50, tier: 'Medium', coverageState: 'stale', reasons: [] }], suggestedScenario: { artTechniques: [] } }) })); await b.go();
console.log('NO ART ->', sq(await b.page.locator('.rec-suggest').innerText()), '| why cell', sq(await b.page.locator('#rec-table-body .rec-why').innerText())); await b.page.locator('.rec-suggest-none').screenshot({ path: b.T + 'rc2-noart.png' }); await b.close();
b = await boot({ viewport: { width: 420, height: 900 } }); await b.go(); await b.page.screenshot({ path: b.T + 'rc2-phone.png', fullPage: true }); console.log('PHONE h-scroll', await b.page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)); await b.close();
