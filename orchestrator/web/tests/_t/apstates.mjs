import { boot, SUMMARY } from './aplib.mjs';
const T = 'C:/Users/Administrator/AppData/Local/Temp/';
// 1 no data
let b = await boot({ empty: true }); await b.go();
await b.page.screenshot({ path: T + 'ap-s-empty.png', clip: { x: 240, y: 60, width: 1200, height: 640 } });
console.log('EMPTY: meta bar visible:', await b.vis('#ap-current-graph-bar'), '| body:', (await b.page.locator('#ap-body').innerText()).replace(/\n+/g, ' / ').slice(0, 160));
await b.page.locator('#ap-body button:has-text("Run Collection")').click(); await b.page.waitForTimeout(400);
console.log('  body button opens panel:', await b.vis('#ap-collect'));
await b.close();
// 2 summary load fails
b = await boot(); b.state.fail['/summary'] = 'database unavailable'; await b.go();
await b.page.screenshot({ path: T + 'ap-s-fail.png', clip: { x: 240, y: 60, width: 1200, height: 560 } });
console.log('SUMMARY FAIL ->', (await b.page.locator('#ap-body').innerText()).replace(/\n+/g, ' / ').slice(0, 140));
delete b.state.fail['/summary']; await b.page.locator('#ap-body button:has-text("Try again")').click(); await b.page.waitForTimeout(900);
console.log('  after Try again ->', (await b.page.locator('#ap-body').innerText()).replace(/\n+/g, ' / ').slice(0, 60));
// 3 history states + schedule + assets saves
b.state.history = []; await b.page.locator('#ap-history-toggle').click(); await b.page.waitForTimeout(700);
console.log('HISTORY empty ->', (await b.page.locator('#ap-history-body').innerText()).trim());
b.state.fail['/history'] = 'history store offline'; await b.page.locator('#ap-history-toggle').click(); await b.page.waitForTimeout(300); await b.page.locator('#ap-history-toggle').click(); await b.page.waitForTimeout(700);
console.log('HISTORY error ->', (await b.page.locator('#ap-history-body').innerText()).trim());
delete b.state.fail['/history'];
await b.page.locator('.ap-actions button:has-text("Schedule")').click(); await b.page.waitForTimeout(600);
await b.page.locator('#ap-sched-enabled').check(); await b.page.locator('#ap-sched-interval').fill('30'); await b.page.locator('#ap-schedule button:has-text("Save")').click(); await b.page.waitForTimeout(500);
console.log('SCHEDULE interval 30 ->', await b.toast(), '| panel open:', await b.vis('#ap-schedule'));
await b.page.locator('#ap-sched-interval').fill('120'); await b.page.locator('#ap-sched-targets').fill('DC01\nFILE01');
b.state.fail['/schedule'] = 'scheduler is disabled by policy'; await b.page.locator('#ap-schedule button:has-text("Save")').click(); await b.page.waitForTimeout(700);
console.log('SCHEDULE refused ->', await b.toast(), '| panel open:', await b.vis('#ap-schedule'));
delete b.state.fail['/schedule']; await b.page.locator('#ap-schedule button:has-text("Save")').click(); await b.page.waitForTimeout(700);
console.log('SCHEDULE saved ->', await b.toast(), '| panel open:', await b.vis('#ap-schedule'), '| server has:', JSON.stringify(b.state.schedule).slice(0, 110));
await b.page.locator('.ap-actions button:has-text("Schedule")').click(); await b.page.waitForTimeout(600);
console.log('  reopened -> enabled', await b.page.locator('#ap-sched-enabled').isChecked(), 'interval', await b.page.locator('#ap-sched-interval').inputValue(), '|', await b.page.locator('#ap-sched-last').innerText());
// assets
await b.page.locator('.ap-actions button:has-text("Tag Assets")').click(); await b.page.waitForTimeout(700);
await b.page.locator('#apt-cj-1').fill('File share'); b.state.fail['/assets'] = 'asset store is read-only';
await b.page.locator('#ap-assets-body tr').nth(1).locator('button:has-text("Save")').click(); await b.page.waitForTimeout(700);
console.log('ASSET refused ->', await b.toast());
delete b.state.fail['/assets']; const y0 = await b.page.evaluate(() => scrollY);
await b.page.locator('#ap-assets-body tr').nth(1).locator('button:has-text("Save")').click(); await b.page.waitForTimeout(900);
console.log('ASSET saved ->', await b.toast(), '| panel still open:', await b.vis('#ap-assets'), '| input kept:', await b.page.locator('#apt-cj-1').inputValue(), '| scroll', y0, '->', await b.page.evaluate(() => scrollY));
console.log('errors', JSON.stringify(b.errs)); await b.close();
