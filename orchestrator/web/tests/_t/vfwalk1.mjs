import { boot } from './vflib.mjs';
import fs from 'node:fs';
const b = await boot({ acceptDialogs: false }); const { page, T } = b; await b.go('run-1');
const post = () => JSON.stringify(b.reqs.splice(0)).slice(0, 330);
fs.writeFileSync(T + 'ev-ok.png', Buffer.from('iVBORw0KGgo=', 'base64')); fs.writeFileSync(T + 'bad.exe', 'MZ'); fs.writeFileSync(T + 'huge-dump.bin', 'x');
// open a Pending row
await page.locator('#vf-body tr', { hasText: 'Proofpoint' }).click(); await page.waitForTimeout(600);
console.log('OPEN pending ->', await b.overlays());
await page.locator('#vf-drawer-overlay .drawer').screenshot({ path: T + 'vfw-drawer.png' });
await page.locator('#vf-drawer-overlay button:has-text("Submit for Review")').click(); await page.waitForTimeout(300);
console.log('SUBMIT w/o result -> toast', await b.toast(), '| posts', post(), '| drawer still open', await b.overlays());
await page.locator('#vf-res-Detected').click();
await page.locator('#vf-note').fill('Saw the alert in Splunk at 10:42.'); await page.locator('#vf-alert').fill('INC-9001');
await page.locator('#vf-drawer-overlay .drawer').screenshot({ path: T + 'vfw-drawer2.png' });
await page.locator('button[data-on-click="vfSubmit"]', { hasText: 'Approve' }).click(); await page.waitForTimeout(1200);
console.log('APPROVE -> toast', await b.toast(), '| posts', post(), '| overlays', JSON.stringify(await b.overlays()));
console.log('  row now:', (await page.locator('#vf-body tr', { hasText: 'Proofpoint' }).innerText()).replace(/\s+/g, ' '), '| hero:', (await page.locator('#hero-verification .hero-stats').innerText()).replace(/\s+/g, ' '));
await page.screenshot({ path: T + 'vfw-after-approve.png' });
// reopen: evidence
await page.waitForTimeout(500);
console.log('REOPEN -> evidence text:', (await page.locator('#vf-evlist').innerText()).replace(/\s+/g, ' '));
console.log('ATTACH button disabled before choosing a file:', await page.locator('#vf-attach').isDisabled());
await page.setInputFiles('#vf-evfile', T + 'ev-ok.png'); await page.locator('#vf-drawer-overlay button:has-text("Attach")').click(); await page.waitForTimeout(900);
console.log('ATTACH png -> toast', await b.toast(), '| list:', (await page.locator('#vf-evlist').innerText()).replace(/\s+/g, ' '), '| file input cleared:', JSON.stringify(await page.locator('#vf-evfile').inputValue()));
await page.setInputFiles('#vf-evfile', T + 'bad.exe'); await page.locator('#vf-drawer-overlay button:has-text("Attach")').click(); await page.waitForTimeout(700); console.log('ATTACH exe -> toast', await b.toast());
await page.setInputFiles('#vf-evfile', T + 'huge-dump.bin'); await page.locator('#vf-drawer-overlay button:has-text("Attach")').click(); await page.waitForTimeout(700); console.log('ATTACH too big -> toast', await b.toast());
await page.locator('#vf-drawer-overlay .drawer').screenshot({ path: T + 'vfw-drawer3.png' });
b.dialogs.length = 0;
await page.locator('#vf-evlist button:has-text("Delete")').first().click(); await page.waitForTimeout(500);
console.log('DELETE evidence -> native dialogs', JSON.stringify(b.dialogs), '| list after (dialog dismissed):', (await page.locator('#vf-evlist').innerText()).replace(/\s+/g, ' ').slice(0, 80));
console.log('  confirm modal:', (await page.locator('#confirm-diff-overlay').innerText()).replace(/s+/g,' ').slice(0,200), '| overlays', await b.overlays());
await page.locator('#confirm-diff-overlay').screenshot({ path: T + 'vfw-delconfirm.png' }).catch(()=>{});
await page.screenshot({ path: T + 'vfw-del-full.png' });
console.log('  facts before confirm: ', (await page.locator('#vf-facts').innerText()).replace(/s+/g,' ').slice(-40));
await page.locator('#confirm-diff-overlay button', { hasText: 'Delete file' }).click(); await page.waitForTimeout(900);
console.log('  after confirm -> toast', await b.toast(), '| list:', (await page.locator('#vf-evlist').innerText()).replace(/s+/g,' '), '| facts:', (await page.locator('#vf-facts').innerText()).replace(/s+/g,' ').slice(-30), '| posts', post());
// history
await page.waitForTimeout(200);
console.log('HISTORY ->', (await page.locator('#vf-history').innerText()).replace(/\s+/g, ' '));
await page.locator('#vf-drawer-overlay .drawer').screenshot({ path: T + 'vfw-drawer4.png' });
// server errors on submit
b.state.fail['/api/verifications'] = 'another analyst just updated this verification — reload and retry';
await page.locator('#vf-res-NotDetected').click(); await page.locator('#vf-drawer-overlay button:has-text("Reject")').click(); await page.waitForTimeout(700);
console.log('SUBMIT server err -> toast', await b.toast(), '| drawer still open (keeps typed note):', await b.overlays());
console.log('errors', JSON.stringify(b.errs));
await b.close();
