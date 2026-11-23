import { boot } from './aplib.mjs';
const b = await boot(); const { page, T } = b; await b.go();
const panel = (n, h = 560) => page.screenshot({ path: T + 'ap-j-' + n + '.png', clip: { x: 240, y: 300, width: 1200, height: h } });
const tl = async () => (await page.locator('#ap-timeline').innerText().catch(() => '')).replace(/\n+/g, ' / ').slice(0, 300);
const open = async () => { await page.locator('#ap-collect-btn').click(); await page.waitForTimeout(400); await page.locator('#ap-targets').fill('DC01\nFILE01\n10.0.0.20'); await page.locator('#ap-sharphound').check(); };
// 1 server refuses dispatch
b.state.fail['/api/attackpath/jobs'] = 'agent a1b2 is revoked'; await open();
await page.locator('#ap-collect button:has-text("Start Collection")').click(); await page.waitForTimeout(900);
console.log('REFUSED dispatch -> progress visible:', await b.vis('#ap-progress'), '| toast:', await b.toast(), '| timeline:', await tl());
delete b.state.fail['/api/attackpath/jobs'];
// 2 happy dispatch (sharphound not delivered)
await page.locator('#ap-collect button:has-text("Start Collection")').click(); await page.waitForTimeout(900);
console.log('dispatch -> timeline:', await tl()); await panel('dispatched');
const id = Object.keys(b.state.jobs)[0];
await b.push(id, { status: 'running' }); await b.progress(id, { stage: 'probing', progressPercent: 40, targetsTotal: 3, targetsCompleted: 1 }); await panel('running');
console.log('running -> timeline:', await tl(), '| cancel visible:', await b.vis('#ap-cancel-action'));
// 3 Run Collection clicked while running
await page.locator('#ap-collect-btn').click(); await page.waitForTimeout(500);
console.log('click Run Collection mid-job -> form visible:', await b.vis('#ap-form'), '| progress visible:', await b.vis('#ap-progress'));
await panel('midjob-click');
// 4 cancel (native confirm?)
const b2 = b.dialogs.length;
await page.locator('#ap-cancel-action button').click({ timeout: 3000 }).catch((e) => console.log('cancel click failed:', e.message.slice(0, 80)));
await page.waitForTimeout(700); console.log('cancel dialogs:', JSON.stringify(b.dialogs.slice(b2)), '| timeline:', await tl());
console.log('errors', JSON.stringify(b.errs)); await b.close();
