import { test, expect } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { fixtureFor, RENDER_MARKERS } from './fixtures.mjs';

const BASELINE = fileURLToPath(new URL('./baseline.json', import.meta.url));
const RECORD = process.env.SMOKE_RECORD === '1';

// Errors are compared after removing volatile parts (asset hashes, line/col,
// URLs), so the monolith baseline is comparable with the bundled build.
function normalize(msg) {
  return msg
    .replace(/https?:\/\/[^\s)]+/g, '<url>')
    .replace(/:\d+:\d+/g, '')
    .replace(/app\.[0-9A-Za-z]+\.js/g, 'app.js')
    .trim();
}

async function boot(page) {
  const errors = [];
  page.on('pageerror', (e) => errors.push(normalize(`pageerror: ${e.message}`)));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(normalize(`console: ${m.text()}`)); });
  await page.addInitScript(() => {
    localStorage.setItem('bas_role', 'admin');
    window.__xss = undefined;
    // Every CSP violation is an error (G1d). Without a policy header this
    // never fires.
    document.addEventListener('securitypolicyviolation', (e) => {
      console.error(`csp: ${e.effectiveDirective} blocked ${e.blockedURI || 'inline'} at ${e.sourceFile || ''}:${e.lineNumber || 0}`);
    });
    // Loaders catch their own errors and show them as an error toast
    // (#toast.err) instead of throwing; surface those as errors too, or a
    // ReferenceError inside a .then() would go unnoticed.
    document.addEventListener('DOMContentLoaded', () => {
      const toast = document.getElementById('toast');
      if (!toast) return;
      new MutationObserver(() => {
        if (toast.classList.contains('err')) console.error(`toast: ${toast.textContent}`);
      }).observe(toast, { attributes: true, childList: true, characterData: true, subtree: true });
    });
  });
  await page.route('**/*', (route) => {
    const u = new URL(route.request().url());
    if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fixtureFor(route.request().method(), u)) });
    }
    if (u.hostname !== '127.0.0.1') return route.fulfill({ status: 204, body: '' }); // fonts etc.: never leave the sandbox
    return route.continue();
  });
  // The live-update socket is accepted and kept silent, so its connection
  // error cannot land nondeterministically on whichever tab is open.
  await page.routeWebSocket(/\/ws\//, () => {});
  await page.goto('/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none', null, { timeout: 15_000 });
  // Let boot-time loaders settle so their errors cannot be attributed to the
  // first tab measured on a slower machine.
  await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => {});
  return errors;
}

// Tabs are discovered from the markup -- inline onclick="showTab('x')" or the
// G1d form data-on-click="showTab" data-args='["x"]' -- never from app internals.
async function tabNames(page) {
  return page.$$eval('[onclick^="showTab(\'"],[data-on-click="showTab"]', (els) => [...new Set(els.map((e) => {
    const a = e.getAttribute('data-args');
    return a ? JSON.parse(a)[0] : e.getAttribute('onclick').match(/showTab\('([^']+)'\)/)[1];
  }))].sort());
}

async function openTab(page, tab) {
  await page.evaluate((t) => {
    const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t)
      || document.querySelector(`[onclick="showTab('${t}')"]`);
    el.click(); // element.click(): some nav entries live in a collapsed dropdown
  }, tab);
}

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
// Both are filter buttons: setAgentFilter('online') reloads agents and moves
// the "on" highlight; setCampaignTab('all') re-renders the campaign toolbar
// (under the fixtures only "All" exists). No dialogs, navigation or pickers.
const ACTION_CLICKS = {
  agents: `#agent-toolbar button[data-on-click="setAgentFilter"][data-args='["online"]']`,
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

// Drawers reachable from the tabs, opened through the same window functions
// their rows' handlers call (spec section 9). Each must render its marker
// with no errors; there is no monolith baseline for these, so none are known.
const DRAWERS = [
  { name: 'live run', open: "openRunPanel('run-smoke-1', 'Run', 2)", selector: '#run-live-timeline', marker: 'T1059' },
  { name: 'run results', open: "viewRunResults({ id: 'run-smoke-1', name: 'Smoke run', status: 'completed', results: [] })", selector: '#results-title', marker: 'Smoke run' },
  { name: 'finding', open: "openFinding('finding-smoke-1')", selector: '#results-title', marker: 'Finding' },
  { name: 'agent detail', open: "openAgentDetail('agent-smoke-1')", selector: '#agt-detail-title', marker: 'Agent: host' },
  { name: 'campaign detail', open: "openCampaignDetail('campaign-smoke-1')", selector: 'body', marker: 'Campaign "><img' },
];

test('drawers open and render with no errors', async ({ page }) => {
  const errors = await boot(page);
  const problems = [];
  for (const d of DRAWERS) {
    errors.length = 0;
    // Recorded, not thrown, so one broken drawer cannot hide the next.
    try { await page.evaluate((code) => { (0, eval)(code); }, d.open); } catch (e) { problems.push(`${d.name}: ${e.message.split('\n')[0]}`); continue; }
    await page.waitForTimeout(500);
    const text = await page.evaluate((sel) => document.querySelector(sel)?.textContent || '', d.selector);
    if (!text.includes(d.marker)) problems.push(`${d.name}: marker "${d.marker}" not rendered`);
    for (const e of errors) problems.push(`${d.name}: ${e}`);
  }
  expect(await page.evaluate(() => window.__xss), 'a fixture payload executed').toBeUndefined();
  expect(problems).toEqual([]);
});
