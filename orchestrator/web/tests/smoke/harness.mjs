// Page helpers shared by the smoke harness and the G1e visual comparison.
import { fixtureFor } from './fixtures.mjs';

// Errors are compared after removing volatile parts (asset hashes, line/col,
// URLs), so the monolith baseline is comparable with the bundled build.
export function normalize(msg) {
  return msg
    .replace(/https?:\/\/[^\s)]+/g, '<url>')
    .replace(/:\d+:\d+/g, '')
    .replace(/app\.[0-9A-Za-z]+\.js/g, 'app.js')
    .trim();
}

export async function boot(page, origin = '') {
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
  await page.goto(`${origin}/index.html`);
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none', null, { timeout: 15_000 });
  // Let boot-time loaders settle so their errors cannot be attributed to the
  // first tab measured on a slower machine.
  await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => {});
  return errors;
}

// Deterministic page for the G1e visual comparison: fixed clock (timers keep
// running) and a seeded Math.random, identical for both builds.
export async function makeDeterministic(page) {
  await page.clock.setFixedTime(new Date('2026-01-15T12:00:00Z'));
  await page.addInitScript(() => {
    let s = 0x2f6b1d3;
    Math.random = () => { s = (Math.imul(s, 1103515245) + 12345) >>> 0; return s / 4294967296; };
  });
}

// Tabs are discovered from the markup -- inline onclick="showTab('x')" or the
// G1d form data-on-click="showTab" data-args='["x"]' -- never from app internals.
export async function tabNames(page) {
  return page.$$eval('[onclick^="showTab(\'"],[data-on-click="showTab"]', (els) => [...new Set(els.map((e) => {
    const a = e.getAttribute('data-args');
    return a ? JSON.parse(a)[0] : e.getAttribute('onclick').match(/showTab\('([^']+)'\)/)[1];
  }))].sort());
}

export async function openTab(page, tab) {
  await page.evaluate((t) => {
    const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t)
      || document.querySelector(`[onclick="showTab('${t}')"]`);
    el.click(); // element.click(): some nav entries live in a collapsed dropdown
  }, tab);
}

// Drawers reachable from the tabs, opened through the same ACTIONS their rows'
// data-on-click attributes name (spec section 9): a throwaway element carrying
// the real attributes is clicked, so the delegated dispatcher resolves the
// action exactly as it does for a row. Nothing is looked up on window. Each must render its marker
// with no errors; there is no monolith baseline for these, so none are known.
export const DRAWERS = [
  { name: 'live run', action: 'openRunPanelAction', args: ['run-smoke-1', 'Run', 2, '', ''], selector: '#run-live-timeline', marker: 'T1059' },
  { name: 'run results', action: 'viewRunResults', args: [{ id: 'run-smoke-1', name: 'Smoke run', status: 'completed', results: [] }], selector: '#results-title', marker: 'Smoke run' },
  { name: 'finding', action: 'openFinding', args: ['finding-smoke-1'], selector: '#results-title', marker: 'Finding' },
  { name: 'agent detail', action: 'rowMenuDetail', args: ['agent-smoke-1'], selector: '#agt-detail-title', marker: 'Agent: host' },
  { name: 'campaign detail', action: 'openCampaignDetail', args: ['campaign-smoke-1'], selector: 'body', marker: 'Campaign "><img' },
];

// Opens one drawer through its action and gives it time to render. Throws if
// the click itself fails; the caller checks the drawer's marker.
export async function openDrawer(page, drawer) {
  await page.evaluate(({ action, args }) => {
    const el = document.createElement('button');
    el.setAttribute('data-on-click', action);
    el.setAttribute('data-args', JSON.stringify(args));
    document.body.appendChild(el);
    el.click();
    el.remove();
  }, { action: drawer.action, args: drawer.args });
  await page.waitForTimeout(500);
}
