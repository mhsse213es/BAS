import { boot } from './vflib.mjs';
const T = 'C:/Users/Administrator/AppData/Local/Temp/';
const drawerText = async (p) => (await p.locator('#vf-detail').innerText()).replace(/\s+/g, ' ');
// analyst: no review, no connectors card
let b = await boot({ role: 'analyst' }); await b.go('run-1');
console.log('ANALYST -> connectors card visible:', await b.vis('#dc-card'), '| verify-now visible:', await b.vis('#vf-verify-now'));
await b.page.locator('#vf-body tr', { hasText: 'Proofpoint' }).click(); await b.page.waitForTimeout(500);
console.log('  drawer buttons:', JSON.stringify(await b.page.locator('#vf-detail .vf-actions button').allInnerTexts()), '| help:', (await b.page.locator('#vf-detail .vf-help').first().innerText()).slice(0, 80));
await b.page.locator('#vf-res-NotDetected').click(); await b.page.locator('#vf-detail .vf-actions button').first().click(); await b.page.waitForTimeout(900);
console.log('  submit for review -> toast:', await b.toast(), '| row status:', (await b.page.locator('#vf-body tr', { hasText: 'Proofpoint' }).locator('td').nth(1).innerText()).replace(/\s+/g, ' '), '| posts', JSON.stringify(b.reqs.splice(0)).slice(0, 200));
await b.page.screenshot({ path: T + 'vfr-analyst.png' }); await b.close();
// viewer
b = await boot({ role: 'viewer' }); await b.go('run-1');
await b.page.locator('#vf-body tr', { hasText: 'Splunk' }).click(); await b.page.waitForTimeout(500);
console.log('VIEWER -> verify-now:', await b.vis('#vf-verify-now'), '| drawer:', (await drawerText(b.page)).slice(0, 400)); await b.close();
// no connectors at all, admin
b = await boot({ noConfigs: true }); await b.go('run-1');
console.log('NO CONNECTORS -> card open by default:', await b.vis('#dc-list'), '| summary:', await b.page.locator('#dc-sum').innerText(), '| list:', (await b.page.locator('#dc-list').innerText()).replace(/\s+/g, ' ').slice(0, 120));
await b.page.locator('#vf-verify-now').click(); await b.page.waitForTimeout(500);
console.log('  Verify now -> toast:', await b.toast(), '| posts', JSON.stringify(b.reqs.splice(0)));
await b.page.screenshot({ path: T + 'vfr-noconn.png' }); await b.close();
// connectors exist but all disabled
b = await boot(); b.state.configs.forEach((c) => c.enabled = false); await b.go('run-1');
await b.page.locator('#vf-verify-now').click(); await b.page.waitForTimeout(600);
console.log('ALL DISABLED, Verify now -> toast:', await b.toast(), '| card now open:', await b.vis('#dc-list'), '| posts', JSON.stringify(b.reqs.splice(0)));
// verify now fails
b.state.configs[0].enabled = true; await b.page.reload(); await b.page.waitForTimeout(600); await b.go('run-1');
b.state.fail['/api/detectverify/run'] = 'connector is not reachable';
await b.page.locator('#vf-verify-now').click(); await b.page.waitForTimeout(700);
console.log('VERIFY NOW server error -> toast:', await b.toast(), '| button:', await b.page.locator('#vf-verify-now').innerText(), '| disabled:', await b.page.locator('#vf-verify-now').isDisabled()); await b.close();
// runs list fails
b = await boot(); b.state.fail['GET:/api/scenarios/runs'] = 'run store unavailable'; await b.go();
console.log('RUNS FAIL ->', (await b.page.locator('#vf-queue').innerText()).replace(/\s+/g, ' '));
await b.page.screenshot({ path: T + 'vfr-runsfail.png' }); await b.close();
// phone
b = await boot({ viewport: { width: 420, height: 900 } }); await b.go('run-1');
console.log('PHONE h-scroll:', await b.page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1));
await b.page.screenshot({ path: T + 'vfr-phone.png', fullPage: true });
await b.page.locator('#vf-body tr', { hasText: 'Proofpoint' }).click(); await b.page.waitForTimeout(500);
await b.page.screenshot({ path: T + 'vfr-phone-drawer.png' });
console.log('PHONE drawer h-scroll:', await b.page.evaluate(() => { const d = document.querySelector('#vf-drawer-overlay .drawer'); return d.scrollWidth > d.clientWidth + 1; })); await b.close();
