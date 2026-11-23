import { boot, SUMMARY } from './aplib.mjs';
const b = await boot(); const { page, T } = b; await b.go();
const panel = (n, h = 640) => page.screenshot({ path: T + 'ap-k-' + n + '.png', clip: { x: 240, y: 300, width: 1200, height: h } });
const tl = async () => (await page.locator('#ap-timeline').innerText().catch(() => '')).replace(/\n+/g, ' / ').slice(0, 260);
const start = async () => { await page.locator('#ap-collect-btn').click(); await page.waitForTimeout(400); await page.locator('#ap-targets').fill('DC01\nFILE01'); await page.locator('#ap-collect button:has-text("Start Collection")').click(); await page.waitForTimeout(800); return Object.keys(b.state.jobs).slice(-1)[0]; };
// A: cancel flow
let id = await start(); await b.push(id, { status: 'running' });
await page.locator('#ap-cancel-action button').click(); await page.waitForTimeout(500);
await page.screenshot({ path: T + 'ap-k-cancelmodal.png' });
console.log('cancel modal title:', await page.locator('#confirm-diff-title').innerText(), '| btn:', await page.locator('#confirm-diff-submit-btn').innerText());
await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(900);
console.log('cancelled ->', await tl(), '| toast:', await b.toast(), '| done actions:', await b.vis('#ap-done-actions'), '| retry:', await b.vis('#ap-retry-btn'), '| view results:', await b.vis('#ap-done-actions .btn-primary')); await panel('cancelled');
await page.locator('#ap-collect button:has-text("Close")').last().click(); await page.waitForTimeout(300);
// B: failure then retry
id = await start(); await b.push(id, { status: 'running' }); await b.push(id, { status: 'failed', error: 'agent_offline' });
console.log('failed ->', await tl(), '| retry visible:', await b.vis('#ap-retry-btn'), '| toast:', await b.toast()); await panel('failed');
await page.locator('#ap-retry-btn').click(); await page.waitForTimeout(800);
console.log('retry ->', await tl(), '| toast:', await b.toast(), '| posts:', JSON.stringify(b.reqs.slice(-1)).slice(0, 90));
// C: complete -> results refresh
const rid = Object.keys(b.state.jobs).slice(-1)[0];
b.state.summary = SUMMARY(); b.state.summary.summary.attackPathScore = 81; b.state.summary.summary.band = 'Low'; b.state.summary.summary.domainCompromise = false; b.state.summary.summary.domainCompromiseStatus = 'not-observed'; b.state.summary.summary.shortestDomainAdminPath = [];
await b.push(rid, { status: 'running' }); await b.push(rid, { status: 'completed', metrics: { nodeCount: 71, edgeCount: 127 } });
await page.waitForTimeout(800);
console.log('completed ->', await tl(), '| toast:', await b.toast(), '| done actions:', await b.vis('#ap-done-actions'), '| view results btn:', await b.vis('#ap-done-actions .btn-primary'));
console.log('score now:', (await page.locator('.ap-score-val').innerText()), '| scrollY:', await page.evaluate(() => scrollY)); await panel('completed');
await page.locator('#ap-done-actions .btn-primary').click(); await page.waitForTimeout(600);
console.log('after View Results -> panel open:', await b.vis('#ap-collect'));
console.log('errors', JSON.stringify(b.errs), 'native dialogs', JSON.stringify(b.dialogs)); await b.close();
