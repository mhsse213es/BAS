import { boot } from './aplib.mjs';
const b = await boot(); const { page, T } = b; await b.go();
const shot = (n, h = 900) => page.screenshot({ path: T + 'ap-p-' + n + '.png', clip: { x: 240, y: 60, width: 1200, height: h } });
const hero = page.locator('#hero-attackpath button, #hero-attackpath .btn').first();
console.log('hero button:', await hero.innerText());
b.reqs.length = 0; await hero.click(); await page.waitForTimeout(800);
console.log('hero click -> body:', (await page.locator('#ap-body').innerText()).slice(0, 40).replace(/\n/g, ' '), '| toast:', await b.toast());
// Run Collection
await page.locator('#ap-collect-btn').click(); await page.waitForTimeout(500); await shot('collect');
console.log('agents in select:', await page.locator('#ap-agent option').count(), '| first:', await page.locator('#ap-agent option').first().innerText());
await page.locator('#ap-discover-btn').click(); await page.waitForTimeout(900); await shot('discover');
console.log('discover -> targets:', (await page.locator('#ap-targets').inputValue()).split('\n').length, '| count:', await page.locator('#ap-target-count').innerText(), '| toast:', await b.toast());
// dispatch with zero targets
await page.locator('#ap-targets').fill(''); await page.locator('#ap-collect button:has-text("Start Collection")').click(); await page.waitForTimeout(900);
console.log('zero targets dispatch -> posts:', JSON.stringify(b.reqs.slice(-1)), '| form visible:', await b.vis('#ap-form'), '| progress visible:', await b.vis('#ap-progress'), '| toast:', await b.toast());
await shot('zero');
await page.locator('#ap-collect button:has-text("Cancel")').first().click().catch(() => {}); await page.waitForTimeout(300);
console.log('collect panel after Cancel:', await b.vis('#ap-collect'));
// Tag assets
await page.locator('.ap-actions button:has-text("Tag Assets")').click(); await page.waitForTimeout(800); await shot('assets', 700);
// Schedule while assets open
await page.locator('.ap-actions button:has-text("Schedule")').click(); await page.waitForTimeout(800);
console.log('both panels open: assets', await b.vis('#ap-assets'), 'schedule', await b.vis('#ap-schedule'));
await shot('schedule', 1100);
// History
await page.locator('#ap-history-toggle').click(); await page.waitForTimeout(800);
console.log('history rows:', await page.locator('#ap-history-body tr').count());
await page.screenshot({ path: T + 'ap-p-history.png', fullPage: true, clip: { x: 240, y: 60, width: 1200, height: 1700 } });
// About
await page.locator('.ap-actions button:has-text("About")').click(); await page.waitForTimeout(500);
await page.screenshot({ path: T + 'ap-p-about.png' });
console.log('errors', JSON.stringify(b.errs), 'dialogs', JSON.stringify(b.dialogs));
await b.close();
