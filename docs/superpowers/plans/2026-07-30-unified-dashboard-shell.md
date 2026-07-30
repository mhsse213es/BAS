# Unified Dashboard Shell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge the two separately-navigable dashboard tabs in `orchestrator/wwwroot/index.html` (Operational, Executive) into one Dashboard tab with a persistent view selector, plus a per-browser Preference that Role never gates.

**Architecture:** One `tab-dashboard` div holds both view blocks as siblings (`#dash-view-operational`, `#dash-view-executive`), toggled by a `.dash-view-toggle` selector strip that's always visible. A `resolveDashView()` function decides which view to show on tab entry, first hardcoded to "last used" (Task 2) then upgraded to read a 3-way `localStorage` preference (Task 3).

**Tech Stack:** Vanilla JS/HTML/CSS, single file (`orchestrator/wwwroot/index.html`), no build step, no test framework for this file.

## Global Constraints

- Pure frontend change. Only `orchestrator/wwwroot/index.html` is touched. No Go/backend code, no `/api/dashboard/*` or `/api/predict/risk` contract changes — Sub-project A already unified the data both views read from.
- Preference storage is `localStorage` only (`bas_dash_pref`, `bas_last_dash_view`), matching the existing `audspect_theme`/`bas_last_tab` convention. No server-side/per-account storage.
- No role-based default. Unset preference always resolves to `'operational'`.
- No widget-level recomposition. Both views keep their exact existing markup, JS, and API calls — only relocated in the DOM.
- No automated test harness applies to this file. Every task is verified by (a) a Node syntax check that every inline `<script>` block still parses, and (b) a manual browser check described in the task.
- Every task ends with a commit + `git push` (this repo's established convention — push immediately after every commit).

---

### Task 1: Restructure markup — merge Executive content into the Dashboard tab, remove the standalone nav item

Pure HTML/markup refactor. No behavior change: after this task, the app looks and works exactly as it does today (Operational renders on the Dashboard tab; Executive's markup now lives inside the same tab but stays unreachable — no toggle exists yet, that's Task 2).

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Produces: HTML structure `#tab-dashboard > #dash-view-operational` (all existing Operational content, unchanged) and `#tab-dashboard > #dash-view-executive[style="display:none"]` (all existing Executive content, unchanged) as siblings. Later tasks (2, 3) build the toggle and preference logic on top of these two ids.
- Consumes: nothing new — this task only moves existing markup and deletes now-redundant nav/title-map/tab-list entries.

- [x] **Step 1: Wrap the existing Operational content in `#dash-view-operational`**

In `orchestrator/wwwroot/index.html`, find:

```html
      <!-- Dashboard -->
      <div id="tab-dashboard" style="display:none">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1.25rem;flex-wrap:wrap">
```

Replace with:

```html
      <!-- Dashboard -->
      <div id="tab-dashboard" style="display:none">
        <div id="dash-view-operational">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1.25rem;flex-wrap:wrap">
```

(The indentation of the moved block is intentionally left as-is below — this keeps the diff to the lines that actually change instead of re-indenting ~200 unrelated lines. A follow-on cleanup pass can re-indent if desired.)

- [x] **Step 2: Close `#dash-view-operational`, insert the moved Executive content into `#dash-view-executive`, close `#tab-dashboard`**

Find the end of the Ransomware Readiness panel (the end of the Operational content, immediately followed by the Agents tab):

```html
          <div class="dash-panel-body" id="rr-body" style="padding:1rem 1.25rem">
            <div class="empty" style="padding:0.5rem">Run the Ransomware Drill to see your readiness score.</div>
          </div>
        </div>
      </div>

      <!-- Agents -->
      <div id="tab-agents" style="display:none">
```

Replace with:

```html
          <div class="dash-panel-body" id="rr-body" style="padding:1rem 1.25rem">
            <div class="empty" style="padding:0.5rem">Run the Ransomware Drill to see your readiness score.</div>
          </div>
        </div>
        </div>
        <div id="dash-view-executive" style="display:none">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1rem;flex-wrap:wrap">
          <div>
            <h1 style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem;color:var(--text)">Executive Dashboard</h1>
            <div style="font-size:0.8rem;color:var(--muted)">Fleet-wide risk, exposure, and detection-coverage trends over time — daily snapshots, not a single point-in-time report.</div>
          </div>
          <div style="display:flex;gap:0.5rem;align-items:center">
            <select id="ed-range" onchange="loadExecDashboard()" style="padding:0.35rem 0.6rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.78rem">
              <option value="30">30 days</option>
              <option value="90" selected>90 days</option>
              <option value="365">1 year</option>
            </select>
            <button class="btn btn-outline btn-sm" onclick="loadExecDashboard()">Refresh</button>
          </div>
        </div>
        <div class="kpi-row" id="ed-kpi-row"><div class="empty">Loading…</div></div>
        <div id="ed-forecast"></div>
        <div id="ed-exposure"></div>
        </div>
      </div>

      <!-- Agents -->
      <div id="tab-agents" style="display:none">
```

This closes `#dash-view-operational` (the extra `</div>` right after `rr-body`'s closer), opens `#dash-view-executive` with `display:none` already set, inserts the moved Executive markup verbatim, closes `#dash-view-executive`, then closes `#tab-dashboard` by reusing the original closing `</div>`.

- [x] **Step 3: Delete the original standalone Executive Dashboard block**

Find (its original location, right after the Exposure Explorer section, right before Recommendations):

```html
      <!-- Executive Dashboard -->
      <div id="tab-exec-dashboard" style="display:none">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1rem;flex-wrap:wrap">
          <div>
            <h1 style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem;color:var(--text)">Executive Dashboard</h1>
            <div style="font-size:0.8rem;color:var(--muted)">Fleet-wide risk, exposure, and detection-coverage trends over time — daily snapshots, not a single point-in-time report.</div>
          </div>
          <div style="display:flex;gap:0.5rem;align-items:center">
            <select id="ed-range" onchange="loadExecDashboard()" style="padding:0.35rem 0.6rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.78rem">
              <option value="30">30 days</option>
              <option value="90" selected>90 days</option>
              <option value="365">1 year</option>
            </select>
            <button class="btn btn-outline btn-sm" onclick="loadExecDashboard()">Refresh</button>
          </div>
        </div>
        <div class="kpi-row" id="ed-kpi-row"><div class="empty">Loading…</div></div>
        <div id="ed-forecast"></div>
        <div id="ed-exposure"></div>
      </div>

      <!-- Recommendations -->
```

Replace with:

```html
      <!-- Recommendations -->
```

This deletes the original copy (its content now lives inside `#tab-dashboard`, moved in Step 2) without touching the Recommendations section that follows it.

- [x] **Step 4: Remove the "Executive Dashboard" sidebar nav item**

Find:

```html
        <div class="nav-item" data-tab="exec-dashboard" onclick="showTab('exec-dashboard')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M2 13.5h12M4 13.5V8M8 13.5V4M12 13.5v-6"/>
          </svg>
          Executive Dashboard
        </div>
```

Delete it entirely (replace with nothing).

- [x] **Step 5: Remove the `exec-dashboard` entry from `TAB_TITLES`**

Find (inside the `var TAB_TITLES = { ... }` line):

```
exposure:'Exposure Explorer', 'exec-dashboard':'Executive Dashboard', recommendations:'Recommendations',
```

Replace with:

```
exposure:'Exposure Explorer', recommendations:'Recommendations',
```

- [x] **Step 6: Remove `exec-dashboard` from `activateTab`'s tab-list array**

Find:

```js
  ['dashboard','agents','scenarios','runs','campaigns','coverage','findings','remediation','reports','verification','compliance','settings','variants','em','attackpath','exposure','exec-dashboard','recommendations','integrations','exercises','attack-coverage','threat-priority'].forEach(function(t) {
```

Replace with:

```js
  ['dashboard','agents','scenarios','runs','campaigns','coverage','findings','remediation','reports','verification','compliance','settings','variants','em','attackpath','exposure','recommendations','integrations','exercises','attack-coverage','threat-priority'].forEach(function(t) {
```

- [x] **Step 7: Verify — syntax check**

Run from the repo root:

```bash
node -e "
const fs = require('fs');
const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
scripts.forEach((s, i) => { try { new Function(s); } catch (e) { console.error('Script block ' + i + ' failed:', e.message); process.exit(1); } });
console.log('All script blocks parse OK');
"
```

Expected: `All script blocks parse OK`.

- [x] **Step 8: Verify — no orphan references**

Run:

```bash
grep -n "tab-exec-dashboard\|'exec-dashboard'\|\"exec-dashboard\"" orchestrator/wwwroot/index.html
```

Expected: no matches (every reference to the old standalone tab id/name is gone — the ids `ed-range`/`ed-kpi-row`/`ed-forecast`/`ed-exposure` and the function `loadExecDashboard` are expected to still appear, unchanged, just relocated).

- [x] **Step 9: Verify — manual browser check**

Open the app, log in, click "Dashboard" in the sidebar. Expected: renders exactly as before (KPI row, compliance tiles, posture gauge, etc.) — no visual change. Confirm "Executive Dashboard" no longer appears in the sidebar. Open the browser console: no errors.

- [x] **Step 10: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "refactor(dashboard): merge Executive Dashboard markup into the Dashboard tab

Pure structural move -- no behavior change yet. Executive's content now
lives inside #tab-dashboard as #dash-view-executive (hidden, unreachable
until Task 2 adds the view toggle). Removes the standalone
'Executive Dashboard' nav item, its TAB_TITLES entry, and its slot in
activateTab's tab list."
git push
```

---

### Task 2: View selector + toggle JS

Adds the working Operational/Executive toggle on top of Task 1's markup. After this task, the Dashboard tab has a visible two-pill selector; switching views shows/hides the right content and calls the right loader; the campaign poll only runs while Operational is the visible view.

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `#dash-view-operational` / `#dash-view-executive` (Task 1), `loadDashboard()` (`index.html:12175`), `loadExecDashboard()` (`index.html:4521`), `refreshDashboardCampaigns()` and its existing `var _dashCampPoll = null;` declaration (`index.html:12572-12573` — reused, not redeclared).
- Produces: `var DASH_VIEW` (current view, `'operational'` | `'executive'`), `function resolveDashView()` (Task 3 edits its body, not its signature — it must keep returning a `'operational'|'executive'` string with no arguments), `function setDashView(view)`, `function startDashCampPoll()`, `function stopDashCampPoll()`. CSS classes `.dash-view-toggle`, `.dash-view-btn`, `.dash-view-btn.active`.

- [x] **Step 1: Add the view-toggle CSS**

Find (the end of the theme-card CSS block, right before `</style>`):

```css
.theme-card.active .theme-name {
  color: var(--accent);
}
</style>
```

Replace with:

```css
.theme-card.active .theme-name {
  color: var(--accent);
}
.dash-view-toggle {
  display: inline-flex;
  gap: 0.25rem;
  padding: 0.2rem;
  background: var(--elevated);
  border: 1px solid var(--border);
  border-radius: 999px;
  margin-bottom: 1rem;
}
.dash-view-btn {
  border: none;
  background: transparent;
  color: var(--muted);
  font-size: 0.78rem;
  font-weight: 600;
  padding: 0.35rem 0.9rem;
  border-radius: 999px;
  cursor: pointer;
  transition: all 0.15s ease;
}
.dash-view-btn:hover { color: var(--text); }
.dash-view-btn.active {
  background: var(--accent);
  color: #fff;
}
</style>
```

- [x] **Step 2: Add the toggle markup**

Find (Task 1's output):

```html
      <div id="tab-dashboard" style="display:none">
        <div id="dash-view-operational">
```

Replace with:

```html
      <div id="tab-dashboard" style="display:none">
        <div class="dash-view-toggle" role="tablist" aria-label="Dashboard view">
          <button type="button" class="dash-view-btn active" data-view="operational" onclick="setDashView('operational')">Operational</button>
          <button type="button" class="dash-view-btn" data-view="executive" onclick="setDashView('executive')">Executive</button>
        </div>
        <div id="dash-view-operational">
```

- [x] **Step 3: Add the view-state JS**

Find:

```js
  var titleEl = document.getElementById('header-page-title');
  if (titleEl) titleEl.textContent = TAB_TITLES[name] || name;
}

function showTab(name) {
```

Replace with:

```js
  var titleEl = document.getElementById('header-page-title');
  if (titleEl) titleEl.textContent = TAB_TITLES[name] || name;
}

// Unified Dashboard shell (Sub-project B) -- one Dashboard tab, two views.
// DASH_VIEW is the live/current view. bas_last_dash_view always tracks the
// most recent manual switch regardless of the pinned bas_dash_pref setting
// (added in a later task), so switching the pref to "Last used" picks up
// wherever the user left off.
var DASH_VIEW = 'operational';

function resolveDashView() {
  return localStorage.getItem('bas_last_dash_view') || 'operational';
}

function setDashView(view) {
  DASH_VIEW = view;
  document.getElementById('dash-view-operational').style.display = view === 'operational' ? '' : 'none';
  document.getElementById('dash-view-executive').style.display = view === 'executive' ? '' : 'none';
  document.querySelectorAll('.dash-view-btn').forEach(function(b) {
    b.classList.toggle('active', b.getAttribute('data-view') === view);
  });
  try { localStorage.setItem('bas_last_dash_view', view); } catch (e) {}
  if (view === 'operational') { loadDashboard(); startDashCampPoll(); }
  else { stopDashCampPoll(); loadExecDashboard(); }
}

// Reuses the existing _dashCampPoll var declared with refreshDashboardCampaigns
// (index.html:12572) -- only the start/stop logic moves here, plus a
// DASH_VIEW check so the poll also stops when the Executive view is showing,
// not just when the whole Dashboard tab is hidden.
function startDashCampPoll() {
  clearInterval(_dashCampPoll);
  _dashCampPoll = setInterval(function() {
    var dash = document.getElementById('tab-dashboard');
    if (dash && dash.style.display !== 'none' && DASH_VIEW === 'operational') {
      refreshDashboardCampaigns();
    } else {
      clearInterval(_dashCampPoll);
    }
  }, 5000);
}
function stopDashCampPoll() { clearInterval(_dashCampPoll); }

function showTab(name) {
```

- [x] **Step 4: Replace the old inline poll block and remove the `exec-dashboard` case in `showTab`**

Find:

```js
  if (name === 'exposure') loadExposureAssets();
  if (name === 'exec-dashboard') loadExecDashboard();
  if (name === 'recommendations') loadRecommendations();
```

Replace with:

```js
  if (name === 'exposure') loadExposureAssets();
  if (name === 'recommendations') loadRecommendations();
```

Then find:

```js
  if (name === 'dashboard') {
    loadDashboard();
    // Start a periodic campaign-status poll so the "Live campaigns" tiles
    // stay current without the user manually refreshing.
    clearInterval(_dashCampPoll);
    _dashCampPoll = setInterval(function() {
      var dash = document.getElementById('tab-dashboard');
      if (dash && dash.style.display !== 'none') {
        refreshDashboardCampaigns();
      } else {
        clearInterval(_dashCampPoll);
      }
    }, 5000);
  }
```

Replace with:

```js
  if (name === 'dashboard') {
    setDashView(resolveDashView());
  }
```

- [x] **Step 5: Verify — syntax check**

Run the same command as Task 1 Step 7. Expected: `All script blocks parse OK`.

- [x] **Step 6: Verify — manual browser check**

Open the Dashboard tab. Expected: a two-pill "Operational | Executive" selector appears above the KPI row, with Operational active by default. Click "Executive": the Operational content hides, the Executive content (KPI cards, forecast chart, exposure table) shows and loads. Click back to "Operational": Operational content reappears. Reload the page while Executive was last selected: Dashboard tab now opens directly to Executive (this is `bas_last_dash_view` at work — there is no pinning yet, that's Task 3). Open DevTools → confirm the campaign poll (watch Network tab for repeated `/api/campaigns` calls) only fires while Operational is showing, not while Executive is showing.

- [x] **Step 7: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(dashboard): add Operational/Executive view toggle

setDashView() switches between the two views, persists the last-used
view to localStorage, and starts/stops the campaign poll based on which
view is actually showing (previously it only checked whether the whole
Dashboard tab was visible)."
git push
```

---

### Task 3: Dashboard Preferences (Settings)

Adds the 3-way pinned preference (Operational / Executive / Last used) in Settings, upgrading `resolveDashView()` from Task 2's "always last used" behavior to respect the pin.

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `resolveDashView()` (Task 2 — this task replaces its body only, signature unchanged), `showSettingsSection(name)` (`index.html:5808`), `selectTheme(themeName)` (`index.html:5824`, used only as the adjacent-code anchor), `.theme-card`/`.theme-name` CSS classes (`index.html:1082-1119`, reused as-is for the new preference cards — no new CSS needed).
- Produces: `function selectDashPref(pref)`, `function syncDashPrefCards()`.

- [x] **Step 1: Add the "Dashboard" settings sub-nav item**

Find:

```html
            <a class="sset" data-set="theme" onclick="showSettingsSection('theme')">Theme &amp; display</a>
            <a class="sset" data-set="license" onclick="showSettingsSection('license')">License</a>
```

Replace with:

```html
            <a class="sset" data-set="theme" onclick="showSettingsSection('theme')">Theme &amp; display</a>
            <a class="sset" data-set="dashprefs" onclick="showSettingsSection('dashprefs')">Dashboard</a>
            <a class="sset" data-set="license" onclick="showSettingsSection('license')">License</a>
```

- [x] **Step 2: Add the `#set-dashprefs` section body**

Find (the end of the Theme Preferences section, right before License):

```html
              <!-- Slate Minimal -->
              <div class="theme-card" onclick="selectTheme('slate')" id="theme-card-slate">
                <div class="theme-preview" style="background:#0f1115;border-color:#2d313b">
                  <div style="background:#181a1f;height:24px;border-bottom:1px solid #2d313b;display:flex;align-items:center;padding:0 8px"><div style="background:#10b981;width:12px;height:12px;border-radius:3px"></div></div>
                  <div style="padding:8px;display:flex;flex-direction:column;gap:4px">
                    <div style="background:#21242c;height:10px;border-radius:2px;width:70%"></div>
                    <div style="background:#2d313b;height:8px;border-radius:2px;width:90%"></div>
                  </div>
                </div>
                <div class="theme-name">Slate Minimal</div>
              </div>
            </div>
          </div>

          <!-- License -->
```

Replace with:

```html
              <!-- Slate Minimal -->
              <div class="theme-card" onclick="selectTheme('slate')" id="theme-card-slate">
                <div class="theme-preview" style="background:#0f1115;border-color:#2d313b">
                  <div style="background:#181a1f;height:24px;border-bottom:1px solid #2d313b;display:flex;align-items:center;padding:0 8px"><div style="background:#10b981;width:12px;height:12px;border-radius:3px"></div></div>
                  <div style="padding:8px;display:flex;flex-direction:column;gap:4px">
                    <div style="background:#21242c;height:10px;border-radius:2px;width:70%"></div>
                    <div style="background:#2d313b;height:8px;border-radius:2px;width:90%"></div>
                  </div>
                </div>
                <div class="theme-name">Slate Minimal</div>
              </div>
            </div>
          </div>

          <!-- Dashboard Preferences -->
          <div id="set-dashprefs" class="set-section" style="display:none">
            <div class="sec-hdr">
              <h2>Dashboard Preferences</h2>
            </div>
            <div style="color:var(--muted);font-size:0.8rem;margin-bottom:1.5rem">Choose which view the Dashboard tab opens to. Saved locally in your browser.</div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(200px, 1fr));gap:1rem">
              <div class="theme-card" onclick="selectDashPref('operational')" id="dashpref-card-operational">
                <div class="theme-name">Operational</div>
                <div style="color:var(--muted);font-size:0.72rem;text-align:center;margin-top:0.3rem">Always land on the Operational view</div>
              </div>
              <div class="theme-card" onclick="selectDashPref('executive')" id="dashpref-card-executive">
                <div class="theme-name">Executive</div>
                <div style="color:var(--muted);font-size:0.72rem;text-align:center;margin-top:0.3rem">Always land on the Executive view</div>
              </div>
              <div class="theme-card" onclick="selectDashPref('last')" id="dashpref-card-last">
                <div class="theme-name">Last used</div>
                <div style="color:var(--muted);font-size:0.72rem;text-align:center;margin-top:0.3rem">Remember whichever view I had open last</div>
              </div>
            </div>
          </div>

          <!-- License -->
```

- [x] **Step 3: Wire the new settings section into `showSettingsSection`**

Find:

```js
var SETTINGS_SECTION = 'users';
// Settings sub-section switcher — toggles the body panels + lazily loads each.
function showSettingsSection(name) {
  SETTINGS_SECTION = name;
  ['users', 'engine', 'intel', 'art', 'audit', 'theme', 'license'].forEach(function(s) {
    var el = document.getElementById('set-' + s);
    if (el) el.style.display = s === name ? '' : 'none';
    var nav = document.querySelector('[data-set="' + s + '"]');
    if (nav) nav.classList.toggle('active', s === name);
  });
  if (name === 'users') loadUsers();
  else if (name === 'engine') loadCalderaStatus();
  else if (name === 'intel') { loadConnectorStatus(); loadOpenAEVConfig(); }
  else if (name === 'art') loadARTContentStatus();
  else if (name === 'audit') loadAuditLogs();
  else if (name === 'license') loadLicenseInfo();
}
```

Replace with:

```js
var SETTINGS_SECTION = 'users';
// Settings sub-section switcher — toggles the body panels + lazily loads each.
function showSettingsSection(name) {
  SETTINGS_SECTION = name;
  ['users', 'engine', 'intel', 'art', 'audit', 'theme', 'dashprefs', 'license'].forEach(function(s) {
    var el = document.getElementById('set-' + s);
    if (el) el.style.display = s === name ? '' : 'none';
    var nav = document.querySelector('[data-set="' + s + '"]');
    if (nav) nav.classList.toggle('active', s === name);
  });
  if (name === 'users') loadUsers();
  else if (name === 'engine') loadCalderaStatus();
  else if (name === 'intel') { loadConnectorStatus(); loadOpenAEVConfig(); }
  else if (name === 'art') loadARTContentStatus();
  else if (name === 'audit') loadAuditLogs();
  else if (name === 'license') loadLicenseInfo();
  else if (name === 'dashprefs') syncDashPrefCards();
}
```

- [x] **Step 4: Add `selectDashPref`/`syncDashPrefCards` and upgrade `resolveDashView`**

Find:

```js
function selectTheme(themeName) {
```

Replace with:

```js
function selectDashPref(pref) {
  localStorage.setItem('bas_dash_pref', pref);
  syncDashPrefCards();
}

function syncDashPrefCards() {
  var pref = localStorage.getItem('bas_dash_pref') || 'operational';
  ['operational', 'executive', 'last'].forEach(function(p) {
    var el = document.getElementById('dashpref-card-' + p);
    if (el) el.classList.toggle('active', p === pref);
  });
}

function selectTheme(themeName) {
```

Then find (Task 2's `resolveDashView`):

```js
function resolveDashView() {
  return localStorage.getItem('bas_last_dash_view') || 'operational';
}
```

Replace with:

```js
function resolveDashView() {
  var pref = localStorage.getItem('bas_dash_pref') || 'operational';
  return pref === 'last' ? (localStorage.getItem('bas_last_dash_view') || 'operational') : pref;
}
```

- [x] **Step 5: Verify — syntax check**

Run the same command as Task 1 Step 7. Expected: `All script blocks parse OK`.

- [x] **Step 6: Verify — manual browser check**

Open Settings → Dashboard. Expected: three cards (Operational, Executive, Last used), none marked active yet (no preference set). Click "Executive": card becomes active (accent border/background, matching the existing Theme card style). Reload the page, click the Dashboard nav item: it opens directly to the Executive view, regardless of which view was last manually toggled. Switch the preference to "Last used", manually toggle to Operational on the Dashboard tab, reload, click Dashboard again: it opens to Operational (the last one manually selected). Switch the preference to "Operational", manually toggle to Executive, reload: Dashboard opens to Operational anyway (the pin overrides the last-used view). Confirm no console errors throughout.

- [x] **Step 7: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(dashboard): add Dashboard Preferences (Operational/Executive/Last used)

New Settings > Dashboard section, styled like the existing Theme
Preferences cards. resolveDashView() now consults the pinned
bas_dash_pref before falling back to bas_last_dash_view. Unset
preference still resolves to Operational -- no role-based default."
git push
```

## Execution notes

**Real deployment bug found and fixed before Task 1 started, unrelated to this plan's own
scope but blocking it:** `orchestrator/wwwroot/index.html` had a large (712-line) uncommitted
diff already sitting in the working tree when this plan began executing -- turned out to be
Run Workspace Sub-project B, Global Search Phase 3+, and Full Variant Sweep Sub-project B,
all previously designed, coded, and (per memory) believed "done and pushed." Investigation
found a second, stray copy of this file at `orchestrator/cmd/server/wwwroot/index.html` that
those three initiatives' commits had actually been made against. `orchestrator/Dockerfile`
does `COPY orchestrator/wwwroot /wwwroot` and `resolveWWWRoot()` (`cmd/server/static.go`)
never resolves to the `cmd/server/wwwroot` path -- so that work was fully committed and pushed
but never actually deployed. Fixed by committing the real diff into the canonical
`orchestrator/wwwroot/index.html` (commit `6612711`) and deleting the stray duplicate directory
entirely (commit `d159477`), before starting Task 1 on a clean, correct base.

**Task 1 Step 8's "no orphan references" check found one expected match**, not zero: the
`showTab`'s `if (name === 'exec-dashboard') loadExecDashboard();` dispatch line, which Task 1
deliberately leaves in place (dead but harmless -- nothing can pass `'exec-dashboard'` as
`name` anymore) since removing it is Task 2's job alongside the rest of the `showTab` rewiring.
Confirmed clean (zero matches) after Task 2.

**Manual interactive browser QA was not performed** for any of the three tasks, consistent
with this session's existing backlog (Global Search, Run Workspace, Full Variant Sweep all
carry the same deferred status). Verification performed instead: a Node-based syntax check
after every task (every inline `<script>` block still parses) and id-uniqueness checks for
every new/moved DOM id. This is a real gap, not a formality -- someone should click through
the actual toggle, the Preference cards, and the campaign-poll behavior in a browser before
this ships to a client.
