import { boot } from './aglib.mjs';
let b = await boot(); let { page, T, state } = b; await b.go();
const sq = (s) => s.replace(/\s+/g, ' ');
const rows = () => page.locator('#agents-body tr').count();
const confirmOpen = () => page.evaluate(() => document.getElementById('confirm-diff-overlay').classList.contains('open'));
console.log('START hero:', sq(await page.locator('#hero-agents .hero-stats').innerText()), '| rows', await rows(), '| range', await page.locator('#agt-range').innerText());
// filters
await page.fill('#agent-search', 'lnx'); await page.waitForTimeout(700); console.log('SEARCH lnx ->', await page.locator('#agt-count').innerText());
await page.fill('#agent-search', 'zzzz'); await page.waitForTimeout(700); console.log('SEARCH zzzz ->', sq(await page.locator('#agent-table-mount').innerText()).slice(0, 90));
await page.fill('#agent-search', ''); await page.waitForTimeout(700);
await page.locator("#agent-filter-selects select").first().selectOption({ index: 2 }); await page.waitForTimeout(700); console.log('STATUS idx2 ->', await page.locator('#agt-count').innerText(), '| clear btn:', await page.locator('[data-on-click="clearAgentFilters"]').count());
await page.locator('[data-on-click="clearAgentFilters"]').click(); await page.waitForTimeout(700);
await page.locator("#agent-filter-selects select").nth(1).selectOption({ index: 1 }); await page.waitForTimeout(300); console.log('OS idx1 ->', await page.locator('#agt-count').innerText());
await page.locator('[data-on-click="clearAgentFilters"]').click(); await page.waitForTimeout(500);
// groups
await page.locator('.at-node', { hasText: 'Domain controllers' }).first().click(); await page.waitForTimeout(700); console.log('GROUP Domain controllers ->', await page.locator('#agt-count').innerText(), '| reqs');
await page.locator('.at-node', { hasText: 'All agents' }).click(); await page.waitForTimeout(500);
// group menu
await page.locator('.at-node', { hasText: 'Lab' }).locator('.at-menu').click(); await page.waitForTimeout(200);
console.log('MENU items ->', JSON.stringify(await page.locator('#ag-menu button').allInnerTexts()), '| native dialogs', state.dialogs.length);
await page.screenshot({ path: T + 'agw-menu.png', clip: { x: 260, y: 720, width: 420, height: 330 } });
await page.locator('#ag-menu button', { hasText: 'Rename' }).click(); await page.waitForTimeout(300);
console.log('RENAME dialog open', await confirmOpen(), '| prefilled', JSON.stringify(await page.inputValue('#ask-input')));
await page.screenshot({ path: T + 'agw-ask.png' });
await page.fill('#ask-input', ''); await page.keyboard.press('Enter'); await page.waitForTimeout(300); console.log('  empty submit -> reopened', await confirmOpen(), '| err', await page.locator('#ask-err').innerText());
await page.fill('#ask-input', 'Lab 2'); await page.keyboard.press('Enter'); await page.waitForTimeout(700); console.log('  Enter ->', await b.toast(), '| tree has Lab 2:', (await page.locator('#agent-tree-root').innerText()).includes('Lab 2'), '| calls', state.calls.at(-1));
await page.locator('.at-node', { hasText: 'Servers' }).locator('.at-menu').click(); await page.locator('#ag-menu button', { hasText: 'New subgroup' }).click(); await page.fill('#ask-input', 'Web'); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700); console.log('NEW subgroup ->', await b.toast(), '|', state.calls.at(-1));
state.fail['/api/agent-groups'] = 'name taken'; await page.locator('.at-node', { hasText: 'Servers' }).locator('.at-menu').click(); await page.locator('#ag-menu button', { hasText: 'New subgroup' }).click(); await page.fill('#ask-input', 'Dup'); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(700); console.log('NEW fail ->', await b.toast()); delete state.fail['/api/agent-groups'];
await page.locator('.at-node', { hasText: 'Lab 2' }).locator('.at-menu').click(); await page.locator('#ag-menu button', { hasText: 'Delete' }).click(); await page.waitForTimeout(300); console.log('DELETE confirm body ->', sq(await page.locator('#confirm-diff-body').innerText()));
await page.screenshot({ path: T + 'agw-del.png' });
await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(800); console.log('  deleted ->', await b.toast(), '| tree:', (await page.locator('#agent-tree-root').innerText()).includes('Lab 2'));
await page.locator('.at-node', { hasText: 'Servers' }).locator('.at-menu').click(); await page.keyboard.press('Escape'); console.log('ESC closes menu:', (await page.locator('#ag-menu').count()) === 0);
// table controls
await page.locator('#agt-thead th', { hasText: 'Host' }).click(); await page.waitForTimeout(150);
await page.locator('[data-on-click="toggleAgtCols"]').click(); await page.locator('#agt-cols input[data-args="[2]"]').uncheck(); await page.waitForTimeout(150); console.log('HIDE OS ->', JSON.stringify(await page.locator('#agt-thead th').allInnerTexts()));
await page.locator('#agt-per').selectOption('9999'); await page.waitForTimeout(150); console.log('ALL ->', await rows());
// row menu
await page.locator('#agents-body tr').first().locator('.agt-actcol button').first().click(); await page.waitForTimeout(300);
console.log('ROW MENU ->', JSON.stringify(await page.locator('.row-menu-item').allInnerTexts()).slice(0, 300));
await page.screenshot({ path: T + 'agw-rowmenu.png' });
await page.keyboard.press('Escape');
console.log('errors', JSON.stringify(b.errs), '| native dialogs', JSON.stringify(state.dialogs)); await b.close();

// drawer actions
b = await boot(); ({ page, T, state } = b); await b.go();
const open = async (i = 0) => { await page.locator('#agents-body tr').nth(i).click(); await page.waitForTimeout(1000); };
await open(0);
await page.locator('#agt-tab-overview button', { hasText: 'Quarantine' }).first().click(); await page.waitForTimeout(300);
console.log('QUARANTINE confirm ->', sq(await page.locator('#confirm-diff-body').innerText()), '| btn', await page.locator('#confirm-diff-submit-btn').innerText(), '| native', state.dialogs.length);
await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(900); console.log('  ->', await b.toast(), '|', state.calls.at(-1));
state.fail['/api/agents/a-1/state'] = 'state locked'; await page.locator('#agt-tab-overview button', { hasText: 'Retire' }).first().click(); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(800); console.log('RETIRE fail ->', await b.toast()); delete state.fail['/api/agents/a-1/state'];
// stop agent modal
await page.locator('#agt-tab-overview button', { hasText: 'Stop Agent' }).first().click(); await page.waitForTimeout(300);
await page.locator('#stop-agent-submit-btn').click(); await page.waitForTimeout(200); console.log('STOP no reason ->', await b.toast());
await page.fill('#stop-agent-reason', 'decommission'); await page.locator('#stop-agent-submit-btn').click(); await page.waitForTimeout(400);
console.log('STOP sure ->', sq(await page.locator('#confirm-diff-body').innerText()), '| confirm z above modal:', await page.evaluate(() => { const e = document.elementFromPoint(720, 450); return !!(e && e.closest('#confirm-diff-overlay')); }));
await page.screenshot({ path: T + 'agw-stop.png' });
state.fail['/stop'] = 'agent unreachable'; await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(800);
console.log('STOP FAIL ->', await b.toast(), '| modal still open', await page.evaluate(() => document.getElementById('stop-agent-overlay').classList.contains('open')));
delete state.fail['/stop']; await page.locator('#stop-agent-submit-btn').click(); await page.waitForTimeout(300); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(800); console.log('STOP ok ->', await b.toast(), '| modal closed', !(await page.evaluate(() => document.getElementById('stop-agent-overlay').classList.contains('open'))));
// remove, with failure
await page.locator('#agt-tab-overview button', { hasText: 'Force Remove' }).first().click(); await page.fill('#remove-agent-reason', 'dup'); await page.locator('#remove-agent-submit-btn').click(); await page.waitForTimeout(300);
state.fail['/remove'] = 'db error'; await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(800); console.log('REMOVE FAIL ->', await b.toast()); delete state.fail['/remove'];
await page.locator('#remove-agent-submit-btn').click(); await page.waitForTimeout(300); await page.locator('#confirm-diff-submit-btn').click(); await page.waitForTimeout(1000); console.log('REMOVE ok ->', await b.toast(), '| retired count in hero', sq(await page.locator('#hero-agents .hero-stats').innerText()));
console.log('errors', JSON.stringify(b.errs), '| native dialogs', JSON.stringify(state.dialogs)); await b.close();

// load failures, empty, paging, views, viewer, phone
b = await boot(); b.state.fail['GET:/api/agents'] = 'x'; b.state.fail['/api/agents?'] = ''; await b.close();
b = await boot(); b.state.fail['/api/agent-groups'] = 'groups down'; await b.go(); console.log('GROUPS FAIL ->', sq(await b.page.locator('#agent-tree-root').innerText()), '| table still', await b.page.locator('#agents-body tr').count()); await b.close();
b = await boot({ empty: true }); await b.go(); console.log('EMPTY ->', sq(await b.page.locator('#agent-table-mount').innerText())); await b.close();
b = await boot({ many: 250 }); await b.go(); console.log('MANY ->', await b.page.locator('#agt-count').innerText(), '|', await b.page.locator('#agt-more-note').innerText(), '| load more visible', await b.page.locator('#agt-load-more').isVisible());
await b.page.locator('#agt-load-more').click(); await b.page.waitForTimeout(800); console.log('  after load more ->', await b.page.locator('#agt-count').innerText(), '|', await b.page.locator('#agt-more-note').innerText()); await b.close();
b = await boot({ role: 'viewer' }); await b.go(); await b.page.locator('#agents-body tr').first().click(); await b.page.waitForTimeout(900); console.log('VIEWER drawer buttons ->', JSON.stringify(await b.page.locator('#agt-tab-overview button').allInnerTexts()), '| tree menu', await b.page.locator('.at-menu').count(), '| New group', await b.page.locator('.agt-newgroup button').count()); await b.close();
b = await boot({ viewport: { width: 420, height: 900 } }); await b.go(); await b.page.screenshot({ path: b.T + 'agw-phone.png', fullPage: true }); console.log('PHONE h-scroll:', await b.page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)); await b.close();
