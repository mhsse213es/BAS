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
