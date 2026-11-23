import { boot } from './exlib.mjs';
const b = await boot(); const { page, T } = b;
await b.go('exercises');
const scrollY = () => page.evaluate(() => document.scrollingElement.scrollTop + (document.querySelector('main, .main, #content')?.scrollTop || 0));
// 1 create plan from scenario
await page.locator('#openaev-scenarios-body tr').first().click(); await page.waitForTimeout(700);
await page.locator('#openaev-detail-overlay button:has-text("Create exercise plan")').click(); await page.waitForTimeout(1500);
console.log('create plan -> overlays:', JSON.stringify(await b.overlays()), '| toast:', await b.toast(), '| plans:', await page.locator('.ex-plan').count(), '| banner plans:', await page.locator('#ex-hs-plans').innerText().catch(() => '?'));
await page.screenshot({ path: T + 'ex-d-createplan.png' });
// 2 exercises row drawer (half-width table)
await page.locator('#openaev-exercises-body tr').first().click(); await page.waitForTimeout(700);
console.log('exercise row drawer title:', await page.locator('#openaev-detail-title').innerText());
await page.locator('#openaev-detail-overlay .drawer-close').click(); await page.waitForTimeout(300);
// 3 untitled scenario (no category/severity/injects)
await page.locator('#ex-scen-box select.dt-per').selectOption('15'); await page.waitForTimeout(300);
await page.locator('#openaev-scenarios-body tr', { hasText: 'Untitled import' }).click(); await page.waitForTimeout(700);
await page.locator('#openaev-detail-overlay .drawer').screenshot({ path: T + 'ex-d-untitled.png' });
await page.locator('#openaev-detail-overlay .drawer-close').click(); await page.waitForTimeout(300);
// 4 columns menu
await page.locator('#ex-scen-box button:has-text("Columns")').click(); await page.waitForTimeout(300);
await page.screenshot({ path: T + 'ex-d-cols.png', clip: { x: 640, y: 300, width: 560, height: 300 } });
await page.keyboard.press('Escape'); await page.mouse.click(700, 150);
// 5 CSV export
const [dl] = await Promise.all([page.waitForEvent('download', { timeout: 4000 }).catch(() => null), page.locator('#ex-execs-box button:has-text("Export CSV")').click()]);
console.log('csv download:', dl ? dl.suggestedFilename() : 'NONE', '| toast:', await b.toast());
// 6 keyboard open of a row
await page.locator('#ex-execs-box tbody tr').nth(2).focus(); await page.keyboard.press('Enter'); await page.waitForTimeout(700);
console.log('Enter on row ->', await b.overlays());
// 7 live refresh: change data while drawer open
b.state.ex['exec-401'].steps[2].status = 'completed'; b.state.ex['exec-401'].rec.steps_done = 3;
await page.locator('#exercise-detail-overlay .drawer-close').click(); await page.waitForTimeout(400);
await page.locator('#ex-execs-box tbody tr', { hasText: 'Technical #4' }).click(); await page.waitForTimeout(700);
console.log('before poll:', await page.locator('#exercise-detail-body .exd-prog small').innerText());
b.state.ex['exec-401'].rec.steps_done = 4; b.state.ex['exec-401'].steps[3].status = 'completed';
await page.waitForTimeout(6000);
console.log('after poll :', await page.locator('#exercise-detail-body .exd-prog small').innerText());
// 8 narrow + light
await page.locator('#exercise-detail-overlay .drawer-close').click(); await page.waitForTimeout(400);
await page.setViewportSize({ width: 420, height: 900 }); await page.waitForTimeout(400);
await page.screenshot({ path: T + 'ex-d-mobile.png', fullPage: false });
await page.locator('#ex-execs-box tbody tr').first().scrollIntoViewIfNeeded();
await page.locator('#ex-execs-box tbody tr', { hasText: 'Drill #7' }).click(); await page.waitForTimeout(700);
await page.screenshot({ path: T + 'ex-d-mobile-drawer.png' });
console.log('errors', JSON.stringify(b.errs)); await b.close();
