import { boot } from './vflib.mjs';
let b = await boot({ acceptDialogs: false }); let { page, T } = b; await b.go('run-1');
const post = () => JSON.stringify(b.reqs.splice(0)).slice(0, 320);
const g = page.locator('#gap-panel');
// gaps
await g.locator('details.gap-t').first().locator('summary').click(); await page.waitForTimeout(300);
await page.screenshot({ path: T + 'vfg-open.png', fullPage: true });
await g.locator('button:has-text("Copy KQL")').first().click(); await page.waitForTimeout(500);
console.log('COPY -> toast:', await b.toast());
await g.locator('button:has-text("Mark deployed")').first().click(); await page.waitForTimeout(900);
console.log('MARK DEPLOYED -> toast:', await b.toast(), '| still open:', await g.locator('details.gap-t[open]').count(), '| deployed block:', (await g.locator('.gap-deps').innerText().catch(() => 'none')).replace(/\s+/g, ' ').slice(0, 140), '| posts', post());
// re-test chain (telemetry mode -> 2 confirms)
await g.locator('button:has-text("Re-test")').first().click(); await page.waitForTimeout(500);
console.log('RETEST step1 -> native', JSON.stringify(b.dialogs), '| modal:', (await page.locator('#confirm-diff-overlay').innerText()).replace(/\s+/g, ' ').slice(0, 220));
await page.locator('#confirm-diff-overlay button:has-text("Cancel")').click(); await page.waitForTimeout(300); console.log('  cancelled -> posts', post(), '| overlays', await b.overlays());
await g.locator('button:has-text("Re-test")').first().click(); await page.waitForTimeout(400);
await page.locator('#confirm-diff-overlay button:has-text("Continue")').click().catch(() => {}); await page.waitForTimeout(400);
console.log('  step2 modal:', (await page.locator('#confirm-diff-overlay').innerText()).replace(/\s+/g, ' ').slice(0, 200));
await page.locator('#confirm-diff-overlay .modal').screenshot({ path: T + 'vfg-confirm2.png' }).catch(() => {});
await page.locator('#confirm-diff-overlay button:has-text("Start re-test")').click(); await page.waitForTimeout(900);
console.log('  started -> toast', await b.toast(), '| posts', post(), '| dep row:', (await g.locator('.gap-dep').innerText()).replace(/\s+/g, ' ').slice(0, 120));
// switch SIEM
await page.selectOption('#gap-backend', 'splunk'); await page.waitForTimeout(800);
console.log('SWITCH SIEM -> backends asked:', JSON.stringify(b.state.gapBackend), '| copy buttons:', JSON.stringify(await g.locator('.gap-copy button').allInnerTexts()).slice(0, 160));
// export
const dl = page.waitForEvent('download', { timeout: 4000 }).catch(() => null);
await g.locator('button:has-text("Export gaps")').click(); const d = await dl; await page.waitForTimeout(400);
console.log('EXPORT -> download:', d ? d.suggestedFilename() : 'none', '| toast:', await b.toast());
// gaps failure
b.state.fail['GET:/detection-gaps'] = 'rule library unavailable'; await page.selectOption('#gap-backend', ''); await page.waitForTimeout(800);
console.log('GAPS FAIL ->', (await g.innerText()).replace(/\s+/g, ' ').slice(0, 140));
delete b.state.fail['GET:/detection-gaps']; await g.locator('button:has-text("Try again")').click(); await page.waitForTimeout(900); console.log('  retry -> tiles', await g.locator('.gap-tile').count());
// table controls
await page.selectOption('#vf-run', 'run-3'); await page.waitForTimeout(1500);
const rows = () => page.locator('#vf-body tr').count();
console.log('RUN-3 (30 items) -> rows', await rows(), '|', await page.locator('#vf-dt-range').innerText(), '| pager:', (await page.locator('#vf-dt-pager').innerText()).replace(/\s+/g, ' '));
await page.locator('#vf-dt-pager button:has-text("Next")').click(); await page.waitForTimeout(200); console.log('  next ->', await page.locator('#vf-dt-range').innerText());
await page.locator('#vf-body tr').first().locator('.dt-cb').check(); await page.locator('#vf-body tr').nth(1).locator('.dt-cb').check(); await page.waitForTimeout(200);
console.log('  select 2 -> bulk bar:', (await page.locator('#vf-bulk').innerText()).replace(/\s+/g, ' '));
await page.locator('#vf-thead th', { hasText: 'Technique' }).click(); await page.waitForTimeout(200); console.log('  sort technique -> first:', await page.locator('#vf-body tr').first().locator('td').nth(2).innerText());
await page.locator('#vf-f-status').selectOption('Pending'); await page.waitForTimeout(300); console.log('  filter Pending ->', await page.locator('#vf-dt-count').innerText(), '| selection kept?', await page.locator('#vf-bulk').isVisible());
await page.fill('#vf-search', 'zzz'); await page.waitForTimeout(400); console.log('  search zzz ->', (await page.locator('#vf-table-host').innerText()).replace(/\s+/g, ' ').slice(0, 80));
await page.locator('#vf-clear').click(); await page.waitForTimeout(300); console.log('  clear ->', await page.locator('#vf-dt-count').innerText());
await page.locator('[data-on-click="vfToggleCols"]').click(); await page.waitForTimeout(200); await page.locator('#vf-cols label', { hasText: 'Confidence' }).locator('input').uncheck(); await page.waitForTimeout(200);
console.log('  hide column Confidence ->', JSON.stringify(await page.locator('#vf-thead th').allInnerTexts()));
const dl2 = page.waitForEvent('download', { timeout: 3000 }).catch(() => null);
await page.locator('[data-on-click="vfExportCsv"]').click(); const d2 = await dl2; console.log('  CSV ->', d2 ? d2.suggestedFilename() : 'none', '| toast', await b.toast());
await page.selectOption('#vf-run', 'run-2'); await page.waitForTimeout(1200);
console.log('RUN-2 EMPTY ->', (await page.locator('#vf-queue').innerText()).replace(/\s+/g, ' '), '| hero', (await page.locator('#hero-verification .hero-stats').innerText()).replace(/\s+/g, ' '), '| verify-now visible:', await b.vis('#vf-verify-now'));
await page.screenshot({ path: T + 'vfg-empty.png' });
await page.selectOption('#vf-run', ''); await page.waitForTimeout(500); console.log('RUN none ->', (await page.locator('#vf-queue').innerText()).replace(/\s+/g, ' '), '| gaps hidden:', !(await b.vis('#gap-panel')));
b.state.fail['GET:/verifications'] = 'database unavailable'; await page.selectOption('#vf-run', 'run-1'); await page.waitForTimeout(1000);
console.log('QUEUE FAIL ->', (await page.locator('#vf-queue').innerText()).replace(/\s+/g, ' '), '| hero', (await page.locator('#hero-verification .hero-stats').innerText()).replace(/\s+/g, ' '));
await page.screenshot({ path: T + 'vfg-fail.png' });
delete b.state.fail['GET:/verifications']; await page.locator('#vf-queue button:has-text("Try again")').click(); await page.waitForTimeout(1000); console.log('  retry -> rows', await rows());
console.log('errors', JSON.stringify(b.errs), '| native dialogs', JSON.stringify(b.dialogs));
await b.close();
