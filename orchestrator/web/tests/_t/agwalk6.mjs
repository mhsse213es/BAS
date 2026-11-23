import { boot } from './aglib.mjs';
const b = await boot(); const { page, state, T } = b; await b.go();
const H = 'ab'.repeat(32);
state.agents[0].binaryHash = H; state.agents[0].agentVersion = '1.9.2';
await page.evaluate(() => document.querySelector('[data-on-click="loadAgents"]').click()); await page.waitForTimeout(900);
await page.locator('#agents-body tr', { hasText: 'WS-FIN-0142' }).click(); await page.waitForTimeout(1000);
const sq = (s) => s.replace(/\s+/g, ' ');
console.log('BINARY row ->', sq(await page.locator('#agt-tab-overview').innerText()).match(/Binary.{0,60}/)[0], '| buttons', JSON.stringify(await page.locator('#agt-tab-overview button').allInnerTexts()).slice(0, 120));
const rv = page.locator('#agt-tab-overview button', { hasText: /Revoke binary|Revoke$/ }); console.log('revoke-binary buttons:', await rv.count());
if (await rv.count()) {
  await rv.first().click(); await page.waitForTimeout(300); console.log('REVOKE BIN confirm ->', sq(await page.locator('#confirm-diff-body').innerText()).slice(0, 120));
  state.fail['/api/agent-binaries/revocations'] = 'hash not allowed'; await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700); console.log('  FAIL ->', await b.toast()); delete state.fail['/api/agent-binaries/revocations'];
  await rv.first().click(); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(800); console.log('  OK ->', await b.toast(), '|', state.calls.at(-1));
}
console.log('errors', JSON.stringify(b.errs), '| native', JSON.stringify(state.dialogs)); await b.close();
