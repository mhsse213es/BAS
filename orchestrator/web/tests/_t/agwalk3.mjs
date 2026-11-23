import { boot } from './aglib.mjs';
let b = await boot(); let { page, T, state } = b; await b.go();
const sq = (s) => s.replace(/\s+/g, ' ');
await page.locator('[data-agents-view="operational"]').click(); await page.waitForTimeout(1200);
console.log('OS donut center ->', sq(await page.locator('#agent-operational-insights .chart-center, #agent-operational-insights').first().innerText()).slice(0, 260));
// connection config
console.log('SECRET masked ->', await page.locator('#cfg-agent-secret').innerText());
await page.locator('[data-on-click="toggleSecret"]').click(); console.log('  Show ->', await page.locator('#cfg-agent-secret').innerText(), '| btn', await page.locator('[data-on-click="toggleSecret"]').innerText());
await page.locator('[data-on-click="toggleSecret"]').click();
await page.locator('[data-on-click="copyText"][data-args=\'["cfg-agent-secret"]\']').click(); await page.waitForTimeout(300); console.log('  Copy secret -> clipboard', JSON.stringify(await page.evaluate(() => navigator.clipboard.readText())), '| btn', await page.locator('[data-on-click="copyText"][data-args=\'["cfg-agent-secret"]\']').innerText());
console.log('  fingerprint ->', await page.locator('#cfg-deployment-fingerprint').innerText());
// tokens
await page.locator('#enroll-tok-generate').click(); await page.waitForTimeout(300); console.log('TOKENS empty ->', await b.toast());
await page.fill('#enroll-tok-hosts', 'WS-1\nWS-2, ws-1\nWS-1'); await page.locator('#enroll-tok-generate').click(); await page.waitForTimeout(600);
console.log('  generate ->', await b.toast(), '|', sq(await page.locator('#enroll-tok-results').innerText()).slice(0, 200), '| warning', (await page.locator('#enroll-tok-warning').innerText()).length > 20);
await page.locator('#enroll-tok-results summary').click(); await page.locator('#enroll-tok-results button').first().click(); await page.waitForTimeout(300); console.log('  copy one ->', await b.toast(), '|', await page.evaluate(() => navigator.clipboard.readText()));
const dl = page.waitForEvent('download', { timeout: 3000 }).catch(() => null); await page.locator('[data-on-click="downloadEnrollmentTokensCsv"]').click(); const d = await dl; console.log('  CSV ->', d ? d.suggestedFilename() : 'none');
await page.screenshot({ path: T + 'ag3-tokens.png', clip: { x: 260, y: 560, width: 1180, height: 520 } });
await page.locator('[data-on-click="clearEnrollmentTokens"]').click(); console.log('  clear ->', JSON.stringify(await page.locator('#enroll-tok-results').innerText()), '| hosts', JSON.stringify(await page.inputValue('#enroll-tok-hosts')));
await page.locator('[data-on-click="downloadEnrollmentTokensCsv"]').click(); await page.waitForTimeout(200); console.log('  CSV after clear ->', await b.toast());
state.fail['/api/enrollment-tokens'] = 'token store full'; await page.fill('#enroll-tok-hosts', 'X1'); await page.locator('#enroll-tok-generate').click(); await page.waitForTimeout(500); console.log('  generate FAIL ->', await b.toast(), '| button re-enabled', await page.locator('#enroll-tok-generate').isEnabled()); delete state.fail['/api/enrollment-tokens'];
// hero buttons
await page.locator('[data-agents-view="systemtree"]').click(); await page.waitForTimeout(400);
await page.locator('#hero-agents button', { hasText: 'Connection Config' }).click(); await page.waitForTimeout(900);
console.log('HERO Connection Config -> view operational visible', await page.locator('#agents-view-operational').isVisible(), '| scrolled to', await page.evaluate(() => Math.round(scrollY)));
await page.locator('[data-agents-view="systemtree"]').click(); await page.waitForTimeout(300);
await page.locator('#hero-agents button', { hasText: 'Deploy Agent' }).click(); await page.waitForTimeout(1800);
console.log('HERO Deploy Agent -> operational visible', await page.locator('#agents-view-operational').isVisible(), '| deploy section in view', await page.evaluate(() => { const r = document.getElementById('agent-deploy-section').getBoundingClientRect(); return r.top >= 0 && r.top < innerHeight; }));
await page.locator('#hero-agents button', { hasText: 'Refresh' }).click(); await page.waitForTimeout(800); console.log('HERO Refresh -> reqs', state.calls.length);
// deploy downloads: just check hrefs resolve to real API paths
console.log('DOWNLOAD links ->', JSON.stringify(await page.locator('#agent-deploy-section ~ * a[href^="/api"], a[download]').evaluateAll((a) => a.map((x) => x.getAttribute('href')).slice(0, 14))));
console.log('errors', JSON.stringify(b.errs)); await b.close();
// connection config failure
b = await boot({ fail: { '/api/config/connection': 'forbidden' }, status: { '/api/config/connection': 403 } }); await b.go(); await b.page.locator('#hero-agents button', { hasText: 'Connection Config' }).click(); await b.page.waitForTimeout(900);
console.log('CONFIG 403 ->', sq(await b.page.locator('#conn-cfg-wrap').innerText()).slice(0, 220), '| toast', await b.toast()); await b.close();
b = await boot({ role: 'analyst' }); await b.go(); console.log('ANALYST hero Connection Config visible ->', await b.page.locator('#agt-conn-cfg-btn').isVisible()); await b.page.locator('#hero-agents button', { hasText: 'Deploy Agent' }).click(); await b.page.waitForTimeout(1800); console.log('  Deploy Agent -> config card visible', await b.page.locator('#conn-cfg-wrap').isVisible(), '| deploy in view', await b.page.evaluate(() => { const r = document.getElementById('agent-deploy-section').getBoundingClientRect(); return r.top >= -5 && r.top < innerHeight; }), '| toast', await b.toast()); await b.close();
