import { boot } from './rmlib.mjs';
const T = 'C:/Users/Administrator/AppData/Local/Temp/';
let b = await boot(); await b.go(); const p = b.page;
const post = () => JSON.stringify(b.reqs.splice(0)).slice(0, 300);
// endpoint ticket: one finding only
await p.locator('.rem-ep-head').nth(1).click(); await p.waitForTimeout(300);
await p.locator('.rem-ep').nth(1).locator('button:has-text("Ticket")').first().click(); await p.waitForTimeout(400);
console.log('EP TICKET modal:', (await p.locator('#confirm-diff-overlay').innerText()).replace(/\s+/g, ' ').slice(0, 130));
await p.locator('#confirm-diff-overlay button', { hasText: /Create ticket/ }).click(); await p.waitForTimeout(800);
console.log('  posts', post(), '| toast', await b.toast(), '| btn:', await p.locator('.rem-ep').nth(1).locator('.rem-ep-f').first().locator('button').nth(1).innerText());
await p.screenshot({ path: T + 'rms-ep.png', fullPage: true });
// partial failure marks only on full success
await p.locator('[data-on-click="setRemView"]', { hasText: 'By technique' }).click(); await p.waitForTimeout(300);
b.state.pushFail.add('f-T1003.001-2');
await p.locator('.rem-fix').nth(1).locator('button:has-text("Ticket")').click(); await p.waitForTimeout(400);
await p.locator('#confirm-diff-overlay button', { hasText: /Create ticket/ }).click(); await p.waitForTimeout(800);
console.log('PARTIAL -> toast:', await b.toast(), '| card button still enabled:', await p.locator('.rem-fix').nth(1).locator('button').nth(1).isEnabled());
await p.screenshot({ path: T + 'rms-partial.png' });
// connectors endpoint fails
b.state.fail['/api/ticketing/configs'] = 'itsm service down';
await p.locator('.rem-fix').nth(0).locator('button:has-text("Ticket")').click().catch(() => {}); await p.waitForTimeout(600);
console.log('CONFIGS FAIL -> toast:', await b.toast()); delete b.state.fail['/api/ticketing/configs'];
// no connectors
b.state.configs.length = 0; await p.locator('.rem-fix').nth(2).locator('button:has-text("Ticket")').click(); await p.waitForTimeout(500);
console.log('NO CONNECTORS -> toast:', await b.toast());
// search + empty
await p.locator('#rem-search').fill('lsass'); await p.waitForTimeout(400);
console.log('SEARCH lsass -> cards', await p.locator('.rem-fix').count(), '|', await p.locator('#rem-showing').innerText());
await p.locator('#rem-search').fill('zzz'); await p.waitForTimeout(400);
console.log('SEARCH zzz ->', (await p.locator('#rem-list').innerText()).replace(/\s+/g, ' '));
await p.locator('#rem-search').fill(''); await p.locator('[data-on-click="setRemFilter"]', { hasText: 'Low' }).click(); await p.waitForTimeout(300);
console.log('LOW ->', await p.locator('.rem-fix').count(), '| search box kept?', JSON.stringify(await p.locator('#rem-search').inputValue()));
// View drawer -> Re-validate while drawer open
await p.locator('[data-on-click="setRemFilter"]', { hasText: 'All' }).click(); await p.waitForTimeout(200);
await p.locator('.rem-fix').first().locator('button:has-text("View")').click(); await p.waitForTimeout(400);
await p.locator('#results-export button:has-text("Re-validate")').click(); await p.waitForTimeout(800);
console.log('REVALIDATE FROM DRAWER -> overlays:', await b.overlays());
await p.screenshot({ path: T + 'rms-drawer-reval.png' });
await b.close();
// failures / empty
b = await boot(); b.state.fail['/api/remediations'] = 'database unavailable'; await b.go();
console.log('LOAD FAIL ->', (await b.page.locator('#rem-list').innerText()).replace(/\s+/g, ' '), '| hero:', (await b.page.locator('#hero-remediation .hero-stats').innerText()).replace(/\s+/g, ' '));
await b.page.screenshot({ path: T + 'rms-fail.png' });
delete b.state.fail['/api/remediations']; await b.page.locator('#rem-list button:has-text("Try again")').click(); await b.page.waitForTimeout(1000);
console.log('  retry ->', await b.page.locator('.rem-ep').count(), 'endpoint cards'); await b.close();
b = await boot({ empty: true }); await b.go();
console.log('EMPTY endpoint view ->', (await b.page.locator('#rem-list').innerText()).replace(/\s+/g, ' '));
await b.page.locator('[data-on-click="setRemView"]', { hasText: 'By technique' }).click(); await b.page.waitForTimeout(300);
console.log('EMPTY technique view ->', (await b.page.locator('#rem-list').innerText()).replace(/\s+/g, ' '), '| bulk buttons visible:', await b.vis('#rem-ticket-actions'));
await b.page.screenshot({ path: T + 'rms-empty.png' }); await b.close();
b = await boot({ role: 'viewer' }); await b.go();
await b.page.locator('[data-on-click="setRemView"]', { hasText: 'By technique' }).click(); await b.page.waitForTimeout(300);
console.log('VIEWER -> bulk visible:', await b.vis('#rem-ticket-actions'), '| Ticket buttons:', await b.page.locator('.rem-fix button:has-text("Ticket")').count(), '| Re-validate buttons:', await b.page.locator('.rem-fix button:has-text("Re-validate")').count()); await b.close();
b = await boot({ viewport: { width: 420, height: 900 } }); await b.go();
await b.page.locator('[data-on-click="setRemView"]', { hasText: 'By technique' }).click(); await b.page.waitForTimeout(300);
await b.page.screenshot({ path: T + 'rms-phone.png' });
console.log('PHONE h-scroll:', await b.page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)); await b.close();
