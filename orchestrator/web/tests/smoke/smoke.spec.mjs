import { test, expect } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { RENDER_MARKERS } from './fixtures.mjs';
import { boot, tabNames, openTab, DRAWERS, openDrawer } from './harness.mjs';

const BASELINE = fileURLToPath(new URL('./baseline.json', import.meta.url));
const RECORD = process.env.SMOKE_RECORD === '1';

// Inline handlers and javascript: URLs left in the live DOM (G1d strict mode).
async function inlineLeft(page) {
  return page.evaluate(() => {
    const out = [];
    for (const el of document.querySelectorAll('*')) {
      for (const a of el.attributes) {
        if (/^on[a-z]+$/.test(a.name)) out.push(`inline handler left: ${a.name} on <${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}>`);
        if ((a.name === 'href' || a.name === 'src' || a.name === 'action') && /^\s*javascript:/i.test(a.value)) out.push(`javascript: URL left on <${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}>`);
      }
    }
    return [...new Set(out)].sort();
  });
}

// One representative action per tab beyond the tab switch (G1d spec 6.3).
// Both are view/filter buttons: setAgentsView('systemtree') re-selects the agents view and moves
// the "on" highlight; setCampaignTab('all') re-renders the campaign toolbar
// (under the fixtures only "All" exists). No dialogs, navigation or pickers.
const ACTION_CLICKS = {
  agents: `button[data-on-click="setAgentsView"][data-args='["systemtree"]']`,
  campaigns: '#campaign-toolbar button[data-on-click="setCampaignTab"]',
};

// Every inline handler in the live DOM whose called function is not on window.
async function unresolvedHandlers(page) {
  return page.evaluate(() => {
    const bad = new Set();
    const skip = new Set(['if', 'for', 'while', 'switch', 'function', 'return', 'typeof', 'event', 'this', 'var', 'let', 'const', 'new']);
    for (const el of document.querySelectorAll('*')) {
      for (const a of el.attributes) {
        if (!a.name.startsWith('on')) continue;
        // Blank out string literals first: text such as 'rgba(…)' or
        // 'Custom (3 tests)' inside a handler is not a call.
        const code = a.value.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"/g, "''");
        for (const m of code.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(/g)) {
          if (!skip.has(m[1]) && typeof window[m[1]] !== 'function') bad.add(m[1]);
        }
      }
    }
    return [...bad].sort();
  });
}

test('every tab renders with no errors beyond the monolith baseline', async ({ page }) => {
  const errors = await boot(page);
  const result = { tabs: {} };
  for (const tab of await tabNames(page)) {
    errors.length = 0;
    // element.click() rather than page.click(): some nav entries (e.g. Profile)
    // live in a collapsed dropdown and are not "visible" to Playwright.
    await openTab(page, tab);
    await page.waitForTimeout(400);
    const extra = [];
    if (ACTION_CLICKS[tab]) {
      const hit = await page.evaluate((sel) => { const el = document.querySelector(sel); if (!el) return false; el.click(); return true; }, ACTION_CLICKS[tab]);
      if (!hit) extra.push(`action click target missing: ${ACTION_CLICKS[tab]}`);
      await page.waitForTimeout(300);
    }
    if (process.env.SMOKE_STRICT === '1') extra.push(...await inlineLeft(page));
    const unresolved = await unresolvedHandlers(page);
    const missing = [];
    if (RENDER_MARKERS[tab] && !(await page.evaluate((m) => document.body.innerText.includes(m), RENDER_MARKERS[tab]))) {
      missing.push(`fixture not rendered: ${RENDER_MARKERS[tab]}`);
    }
    result.tabs[tab] = [...new Set([...errors, ...missing, ...extra, ...unresolved.map((n) => `unresolved handler: ${n}`)])].sort();
  }
  const xss = await page.evaluate(() => window.__xss);
  expect(xss, 'a fixture payload executed').toBeUndefined();

  if (RECORD) { writeFileSync(BASELINE, JSON.stringify(result, null, 2) + '\n'); return; }
  const baseline = JSON.parse(readFileSync(BASELINE, 'utf8'));
  const regressions = [];
  for (const [tab, errs] of Object.entries(result.tabs)) {
    const known = new Set(baseline.tabs[tab] || []);
    for (const e of errs) if (!known.has(e)) regressions.push(`${tab}: ${e}`);
  }
  for (const tab of Object.keys(baseline.tabs)) if (!(tab in result.tabs)) regressions.push(`${tab}: tab disappeared`);
  expect(regressions, 'new errors versus the monolith baseline').toEqual([]);
});

test('drawers open and render with no errors', async ({ page }) => {
  const errors = await boot(page);
  const problems = [];
  for (const d of DRAWERS) {
    errors.length = 0;
    // Recorded, not thrown, so one broken drawer cannot hide the next.
    try {
      await openDrawer(page, d);
    } catch (e) { problems.push(`${d.name}: ${e.message.split('\n')[0]}`); continue; }
    const text = await page.evaluate((sel) => document.querySelector(sel)?.textContent || '', d.selector);
    if (!text.includes(d.marker)) problems.push(`${d.name}: marker "${d.marker}" not rendered`);
    for (const e of errors) problems.push(`${d.name}: ${e}`);
  }
  expect(await page.evaluate(() => window.__xss), 'a fixture payload executed').toBeUndefined();
  expect(problems).toEqual([]);
});

// Detection Verification > Detection connectors: the add form shows the provider's own fields, refuses an
// incomplete form without calling the server, and posts the body the server expects (enabled explicit, unused
// fields empty, no secret echoed back anywhere).
test('detection connectors: add form validates and posts the expected body', async ({ page }) => {
  const errors = await boot(page);
  const posts = [];
  await page.route('**/api/detectverify/configs', (route) => {
    if (route.request().method() !== 'POST') return route.fallback();
    posts.push(JSON.parse(route.request().postData() || '{}'));
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ id: 'dc-new' }) });
  });
  await openTab(page, 'verification');
  await expect(page.locator('#dc-card')).toBeVisible();

  await page.click('[data-on-click="dcAdd"]');
  await page.selectOption('#dc-provider', 'splunk');
  await expect(page.locator('#dc-f-baseUrl')).toBeVisible();
  await expect(page.locator('#dc-f-tenantId')).toHaveCount(0); // a Sentinel field must not show for Splunk

  await page.fill('#dc-name', 'Prod Splunk');
  await page.click('[data-on-click="dcSave"]'); // base URL and token still empty
  expect(posts).toHaveLength(0);

  await page.fill('#dc-f-baseUrl', 'https://splunk.example:8089');
  await page.fill('#dc-f-apiToken', 'tok-123');
  await page.click('[data-on-click="dcSave"]');
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0]).toMatchObject({ provider: 'splunk', name: 'Prod Splunk', enabled: true, autoVerify: false,
    baseUrl: 'https://splunk.example:8089', apiToken: 'tok-123', tenantId: '', workspaceId: '', clientId: '', verifyDelaySeconds: 120 });
  expect(await page.evaluate(() => window.__xss)).toBeUndefined();
  // the earlier (intentional) validation toast is an error toast; nothing else may be
  expect(errors.filter((e) => !/toast: (Name|Base URL|API token)/.test(e) && !/toast: .* is required/.test(e))).toEqual(expect.not.arrayContaining([expect.stringMatching(/pageerror|csp:/)]));
});

test('detection connectors: Verify now appears once a run is picked', async ({ page }) => {
  await boot(page);
  const calls = [];
  await page.route('**/api/detectverify/run/**', (route) => {
    calls.push(route.request().url());
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ status: 'verifying', message: 'started' }) });
  });
  await openTab(page, 'verification');
  await expect(page.locator('#vf-verify-now')).toBeHidden();
  await page.selectOption('#vf-run', 'run-smoke-1');
  await expect(page.locator('#vf-verify-now')).toBeVisible();
  await page.click('#vf-verify-now');
  await expect.poll(() => calls.length).toBe(1);
  expect(calls[0]).toContain('/api/detectverify/run/run-smoke-1');
});

// Detection Verification > Detection gaps: picking a run shows its gaps with the rules that could close them, says
// plainly that rules are not validated, escapes everything the server sent, and the export asks for the right file.
test('detection gaps: panel shows a gap with its rules, escapes content, and exports', async ({ page }) => {
  const errors = await boot(page);
  const evil = '<img src=x onerror="window.__xss=1">';
  const gaps = {
    runId: 'run-smoke-1',
    summary: { 'Detection gap': 1, Unknown: 1, Detected: 1 },
    library: { loaded: true, sigmaCommit: '0e3b749e0d85cd943706ed610a1447f0d54e8388', license: 'DRL-1.1' },
    techniques: [
      { techniqueId: 'T1059.001', name: evil, status: 'Detection gap', reason: 'The technique ran to completion and a reviewed verification found no alert.',
        steps: { fail: 1 }, ruleAvailability: 'Rule available', effectiveness: 'Not validated', ruleCount: 1,
        rules: [{ id: 'AUDRULE-000001', sigmaId: 'abc', title: evil, severity: 'high', match: 'exact', source: { name: 'SigmaHQ', license: 'DRL-1.1' },
          backends: [{ backend: 'splunk', language: 'SPL', mapping: 'pipeline', dataSource: 'Sysmon event 1',
            exportUrl: '/api/rules/export?id=AUDRULE-000001&format=spl' }] }] },
      { techniqueId: 'T9999', name: 'No rule', status: 'Detection gap', reason: 'r', steps: { fail: 1 }, ruleAvailability: 'No rule available',
        effectiveness: 'Not validated', ruleCount: 0 },
      { techniqueId: 'T1003', name: 'LSASS', status: 'Unknown', reason: 'The technique ran, but no detection verification was recorded.',
        steps: { fail: 1 }, ruleAvailability: 'Rule available', effectiveness: 'Not validated', ruleCount: 3 },
    ],
  };
  const exports = [];
  await page.route('**/api/scenarios/runs/run-smoke-1/detection-gaps**', (route) => {
    const url = route.request().url();
    if (url.includes('/export')) {
      exports.push(url);
      return route.fulfill({ status: 200, contentType: 'application/zip', body: 'PK' });
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(gaps) });
  });
  await openTab(page, 'verification');
  await expect(page.locator('#gap-panel')).toBeHidden();
  await page.selectOption('#vf-run', 'run-smoke-1');
  const panel = page.locator('#gap-panel');
  await expect(panel).toBeVisible();
  await expect(panel).toContainText('T1059.001');
  // Each technique starts collapsed to its title row; the rules and copy buttons open on click.
  await expect(panel.locator('details.gap-t[open]')).toHaveCount(0);
  await panel.locator('.gap-t-head').first().click();
  await expect(panel.locator('details.gap-t[open]')).toHaveCount(1);
  await panel.evaluate((el) => el.querySelectorAll('details.gap-t').forEach((d) => { d.open = true; }));
  await expect(panel).toContainText('Not validated');
  await expect(panel).toContainText('No rule available');
  await expect(panel).toContainText('SigmaHQ');
  await expect(panel).toContainText('Nothing is invented');
  await expect(panel.locator('[data-on-click="gapCopy"]')).toHaveCount(1);
  await expect(panel.locator('.gap-t')).toHaveCount(2); // only the two gaps get a block; Unknown is listed apart
  expect(await page.evaluate(() => window.__xss), 'server content executed').toBeUndefined();

  await page.selectOption('#gap-backend', 'splunk');
  await page.click('[data-on-click="gapExport"]');
  await expect.poll(() => exports.length).toBe(1);
  expect(exports[0]).toContain('/detection-gaps/export?backend=splunk');
  expect(errors.filter((e) => /pageerror|csp:/.test(e))).toEqual([]);
});

// Detection gaps: recording a deployed rule and re-testing it. Deployment claims nothing; the re-test starts through
// the normal run endpoint with the original run's scenario/agent/mode and is then linked to the deployment.
test('detection gaps: mark a rule deployed, then re-test it', async ({ page }) => {
  const errors = await boot(page);
  const evil = '<img src=x onerror="window.__xss=1">';
  const gaps = {
    runId: 'run-smoke-1', summary: { 'Detection gap': 1 },
    library: { loaded: true, sigmaCommit: '0e3b749e0d85cd943706ed610a1447f0d54e8388', license: 'DRL-1.1' },
    techniques: [{ techniqueId: 'T1059.001', name: 'PowerShell', status: 'Detection gap', reason: 'r', steps: { fail: 1 },
      ruleAvailability: 'Rule available', effectiveness: 'Not validated', ruleCount: 1,
      rules: [{ id: 'AUDRULE-000001', sigmaId: 'abc', title: 'Rule', severity: 'high', match: 'exact', source: { name: 'SigmaHQ', license: 'DRL-1.1' },
        backends: [{ backend: 'splunk', language: 'SPL', mapping: 'pipeline', dataSource: 'Sysmon event 1', exportUrl: '/api/rules/export?id=AUDRULE-000001&format=spl' }] }] }],
  };
  const deps = { retest: { scenarioId: 'scn-1', agentId: 'a1', mode: '' }, deployments: [
    { id: 'd1', techniqueId: 'T1059.001', ruleId: 'AUDRULE-000001', ruleTitle: evil, backend: 'splunk', backendLabel: 'Splunk', status: 'Deployed',
      detail: 'Deployment recorded.', deployedAt: '2026-11-03T10:00:00Z', deployedBy: 'user:zain', note: evil }] };
  const posted = [];
  await page.route('**/api/scenarios/runs/run-smoke-1/detection-gaps**', (route) => {
    const req = route.request();
    if (req.url().includes('/deployments')) {
      if (req.method() === 'POST') {
        posted.push(req.url().replace(/^.*\/api/, '/api') + ' ' + req.postData());
        return route.fulfill({ status: 201, contentType: 'application/json', body: '{"id":"d2"}' });
      }
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(deps) });
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(gaps) });
  });
  await page.route('**/api/scenarios/scn-1/run', (route) => {
    posted.push('/api/scenarios/scn-1/run ' + route.request().postData());
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{"runId":"run-retest-9","status":"dispatched","mode":"posture"}' });
  });
  await openTab(page, 'verification');
  await page.selectOption('#vf-run', 'run-smoke-1');
  const panel = page.locator('#gap-panel');
  await panel.evaluate((el) => el.querySelectorAll('details.gap-t').forEach((d) => { d.open = true; }));
  await expect(panel).toContainText('Deployed rules');
  await expect(panel).toContainText('Deployment recorded.');
  expect(await page.evaluate(() => window.__xss), 'server content executed').toBeUndefined();

  await page.click('[data-on-click="gapDeploy"]');
  await expect.poll(() => posted.length).toBe(1);
  expect(posted[0]).toContain('/deployments {"techniqueId":"T1059.001","ruleId":"AUDRULE-000001","backend":"splunk"}');

  await page.click('[data-on-click="gapRetest"]');
  await expect.poll(() => posted.length).toBe(3);
  expect(posted[1]).toContain('/api/scenarios/scn-1/run');
  expect(posted[1]).toContain('"agentId":"a1"');
  expect(posted[1]).toContain('"mode":"posture"');
  expect(posted[2]).toContain('/deployments/d1/retest {"retestRunId":"run-retest-9"}');
  expect(errors.filter((e) => /pageerror|csp:/.test(e))).toEqual([]);
});

// Factory Health's Re-check button must visibly answer a click, including when the server has nothing to show.
test('factory health: Re-check answers the click', async ({ page }) => {
  await boot(page);
  let calls = 0;
  await page.route('**/api/analytics/factory-health', (route) => {
    calls++;
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });
  await openTab(page, 'factory-health');
  await expect.poll(() => calls).toBeGreaterThan(0);
  const before = calls;
  await page.click('#hero-factory [data-on-click="recheckFactoryHealth"]');
  await expect.poll(() => calls).toBe(before + 1);
  await expect(page.locator('#toast')).toContainText('Factory health is not available');
  await expect(page.locator('#hero-factory [data-on-click="recheckFactoryHealth"]')).toBeEnabled();
});

// Coverage's Recalculate hides failed reads inside its panels; it must still say so.
test('coverage: Recalculate reports a panel that could not be reloaded', async ({ page }) => {
  await boot(page);
  await openTab(page, 'coverage');
  await page.route('**/api/techniques/unified', (route) => route.abort());
  await page.click('#hero-coverage [data-on-click="recalcCoverage"]');
  await expect(page.locator('#toast')).toContainText('could not be reloaded');
});

// Variants and Email refresh several panels; a panel that cannot reload must be reported, not hidden.
for (const [tab, route, action, word] of [
  ['variants', '**/api/variants/stats', 'refreshVariantTab', 'variants'],
  ['email', '**/api/emailgw/metrics', 'refreshEmailTab', 'email'],
]) {
  test(`${tab}: Refresh reports a panel that could not be refreshed`, async ({ page }) => {
    await boot(page);
    await openTab(page, tab);
    await page.route(route, (r) => r.abort());
    await page.click(`[data-on-click="${action}"]`);
    await expect(page.locator('#toast')).toContainText(`${word} panels could not be refreshed`);
  });
}

// Threat Actor Library: cards match the scenario cards, and an explicit button collapses/expands it.
test('threat actor library: sc-card style and a Collapse button', async ({ page }) => {
  await boot(page);
  await page.route('**/api/caldera/adversaries', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify([{ id: 'a1', name: 'APT29', description: 'A group.', tactics: ['collection', 'discovery'], abilityCount: 79 }]) }));
  await openTab(page, 'scenarios');
  await page.evaluate(() => document.querySelector('[data-on-click="loadAdversariesStop"]').click());
  await expect(page.locator('#adv-grid .sc-card')).toHaveCount(1);
  await expect(page.locator('#adv-collapse-btn')).toHaveText('Expand');
  await expect(page.locator('#adversary-body')).toBeHidden();
  await page.click('#adv-collapse-btn');
  await expect(page.locator('#adversary-body')).toBeVisible();
  await expect(page.locator('#adv-collapse-btn')).toHaveText('Collapse');
  await page.click('#adv-collapse-btn');
  await expect(page.locator('#adversary-body')).toBeHidden();
});

// Threat-Intel category: intel scenarios stay out of All Scenarios, and skipped actors are explained.
test('threat intel category: separate from All, with the skipped-actors note', async ({ page }) => {
  await boot(page);
  const sc = (id, name, extra) => ({ id, name, description: 'd', productLine: 'common', supportedOs: ['windows'], mitrePhases: [], steps: [], tags: [], ...extra });
  await page.route('**/api/scenarios', (r) => r.request().method() !== 'GET' ? r.fallback() : r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify([sc('b1', 'Builtin One', {}), sc('i1', 'Actor X — Active Campaign (Intel)', { intelSource: 'opencti', source: 'intel', intelActor: 'Actor X' })]) }));
  await page.route('**/api/scenarios/intel-skipped', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ minTechniques: 2, actors: [{ name: 'UNC788', reason: 'below_min_techniques' }] }) }));
  await openTab(page, 'scenarios');
  await page.evaluate(() => document.querySelector('[data-on-click="loadScenarios"]').click());
  await expect(page.locator('#sc-tile-grid')).toContainText('Builtin One');
  await expect(page.locator('#sc-tile-grid')).not.toContainText('Actor X');
  await page.locator('#sc-cats .sc-cat-item', { hasText: 'Threat-Intel' }).click();
  await expect(page.locator('#sc-tile-grid')).toContainText('Actor X');
  await expect(page.locator('.sc-skip-note')).toContainText('UNC788');
  await page.locator('#sc-cats .sc-cat-item', { hasText: 'All Scenarios' }).click();
  await expect(page.locator('.sc-skip-note')).toHaveCount(0);
});
