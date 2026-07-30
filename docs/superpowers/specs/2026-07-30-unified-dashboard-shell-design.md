# Unified Dashboard Shell — Design Spec

**Sub-project B of the Unified Analytics Layer initiative.** Sub-project A (`internal/analytics`:
`FleetRisk`, `Compliance`, `Campaigns`, `BuildFleetExposure`/`FindingExposureWindows`) is done and
merged to `main` — `dashboard.Compute()` and `ListCampaigns` already delegate to it. This
sub-project is the frontend piece: merge the two separate dashboard tabs in
`orchestrator/wwwroot/index.html` into one Dashboard with a View selector, plus a per-user
Preference that Role never gates.

## Goal

Replace two separately-navigable dashboard tabs (`dashboard` / Operational, `exec-dashboard` /
Executive) with one `dashboard` tab containing both views, switchable via a persistent selector,
with a per-browser Preference controlling which view a user lands on.

## Context: current state

Both tabs already read from the same backend as of Sub-project A, but they are two independently
maintained pieces of markup/JS with almost no widget overlap:

- **Operational** (`tab-dashboard`, `index.html:1380-1585`): KPI row (open findings, attack
  surface age, prevention score, ATT&CK coverage, active campaigns), regulatory compliance tiles,
  ITSM tickets, threat-intel KEV widget, readiness trends table, posture-score gauge,
  control-effectiveness donut, live campaigns panel, top exposure gaps (stub), recent runs, top
  failing techniques, attack flow, ATT&CK tactic coverage grid, ransomware readiness. Populated by
  `loadDashboard()` (`index.html:12175`), which computes its KPIs client-side from raw
  `/api/agents` and `/api/scenarios/runs` — it does not call `/api/dashboard/*` today. A campaign
  poll (`_dashCampPoll`, `index.html:4150-4158`) refreshes the live-campaigns panel every 5s while
  this tab is visible.
- **Executive** (`tab-exec-dashboard`, `index.html:2786-2805`): a day-range selector (30/90/365),
  4 KPI cards with sparklines/trend chips (Risk Score, Exposure Score, Detection Coverage, Fleet
  Assets), a risk-score forecast chart, and an open-exposure-windows aging table. Populated by
  `loadExecDashboard()` (`index.html:4521`), which calls `/api/dashboard/current`,
  `/api/dashboard/trends`, and `/api/predict/risk` — the endpoints already backed by
  `internal/analytics` and `internal/predict`.

Real RBAC roles are `admin` / `analyst` / `viewer` (`ROLE_LABELS`, `index.html:12031`) — permission
levels, not job personas. There is no role that cleanly maps to "this user wants the executive
view by default."

Every existing UI preference in this app (theme: `audspect_theme`; last-active tab:
`bas_last_tab`) is `localStorage`-only, per-browser, with no server-side user-preference storage.
`internal/` has no code referencing the `exec-dashboard` tab id (confirmed via grep) — nothing
server-side depends on it existing as a distinct destination.

## Decisions made during brainstorming

1. **Shell only, this sub-project.** Both widget sets move under one tab unchanged — no promoting
   Executive's KPI cards into Operational's KPI row or any other widget-level recomposition. That
   is explicitly deferred to later polish, once the shell exists.
2. **Preference storage is `localStorage`**, matching the existing theme/last-tab convention
   exactly. Not server-side/per-account — per-browser, zero backend work, ships entirely in this
   sub-project.
3. **No role-based initial default.** Every first-time user lands on Operational. Role suggesting
   an initial default was the original proposal, but since real roles are permission levels (not
   personas), inventing an "admin → Executive" mapping would be an unfounded assumption. Preference
   is 100% authoritative once set.

## Architecture

One `tab-dashboard` div holds both view blocks as siblings, toggled by a persistent view-selector
strip. No backend changes — Sub-project A already unified the data layer.

### 1. Nav & tab structure

- Remove the `exec-dashboard` nav-item (`index.html:1278-1283`).
- Remove its entry from `TAB_TITLES` (`index.html:3983`).
- Remove `'exec-dashboard'` from `activateTab`'s tab-list array (`index.html:4115`) — it is no
  longer a routable top-level tab.
- `tab-exec-dashboard`'s content (`index.html:2786-2805`) moves inside `tab-dashboard` as a second
  view block:
  - `<div id="dash-view-operational">` wraps the existing Operational content
    (`index.html:1391-1584`) unchanged, byte-for-byte.
  - `<div id="dash-view-executive" style="display:none">` wraps the existing Executive content
    (header, range selector, refresh button, KPI row, forecast, exposure table) unchanged,
    byte-for-byte.
- A view-selector strip sits above both, inside `tab-dashboard`, always visible regardless of
  which view is active — two pill buttons ("Operational" / "Executive"), reusing the pill-chip
  visual pattern already used by `vfRenderDomainChips` (`index.html:4225-4235`:
  `border-radius:999px`, accent border + background when active, muted otherwise).

### 2. View state (JS)

```js
var DASH_VIEW = 'operational';

function setDashView(view) {
  DASH_VIEW = view;
  document.getElementById('dash-view-operational').style.display = view === 'operational' ? '' : 'none';
  document.getElementById('dash-view-executive').style.display = view === 'executive' ? '' : 'none';
  document.querySelectorAll('.dash-view-toggle [data-view]').forEach(function(b) {
    b.classList.toggle('active', b.getAttribute('data-view') === view);
  });
  try { localStorage.setItem('bas_last_dash_view', view); } catch (e) {}
  if (view === 'operational') { loadDashboard(); startDashCampPoll(); }
  else { stopDashCampPoll(); loadExecDashboard(); }
}
```

The existing inline campaign-poll block in `showTab` (`index.html:4150-4158`) is extracted into
`startDashCampPoll()` / `stopDashCampPoll()`:

```js
var _dashCampPoll;
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
```

This is a real (if minor) behavior fix over today's code: previously the poll only stopped when
the whole Dashboard tab was hidden, not when a user switched away from the Operational view within
it — after this sub-project, that condition doesn't exist yet (Operational and Executive are still
one tab each today), but it will as soon as they become two views of one tab, so the poll must
check `DASH_VIEW` too or it will keep firing needlessly while Executive is showing.

`showTab`'s `'dashboard'` case (`index.html:4146-4159`) changes from calling `loadDashboard()`
directly to:

```js
if (name === 'dashboard') setDashView(resolveDashView());
```

The `'exec-dashboard'` case (`index.html:4140`) is deleted — `exec-dashboard` is no longer a
routable tab name.

### 3. Preference (Settings)

A new "Dashboard Preferences" settings section, `#set-dashprefs`, styled like the existing Theme
Preferences cards (`index.html:2036-2091`: `.set-section`, `.theme-card`-style selectable cards),
added to `showSettingsSection`'s section array (`index.html:5810`) and to the Settings sidebar nav
list alongside Users/Engine/Intel/ART/Audit/Theme/License. Three choices, each a card:

- **Operational** — always land on Operational.
- **Executive** — always land on Executive.
- **Last used** — remember whichever view was open last.

Stored in `localStorage['bas_dash_pref']` as `'operational' | 'executive' | 'last'`.

```js
function resolveDashView() {
  var pref = localStorage.getItem('bas_dash_pref') || 'operational';
  return pref === 'last' ? (localStorage.getItem('bas_last_dash_view') || 'operational') : pref;
}

function selectDashPref(pref) {
  localStorage.setItem('bas_dash_pref', pref);
  document.querySelectorAll('.dashpref-card').forEach(function(c) {
    c.classList.toggle('active', c.id === 'dashpref-card-' + pref);
  });
}
```

Unset (`localStorage.getItem` returns `null`) resolves to `'operational'` — satisfying "no
role-based default, everyone lands on Operational first."  Manually switching views via the
selector (`setDashView`) always updates `bas_last_dash_view` regardless of the pinned preference,
so switching the preference to "Last used" later picks up wherever the user left off, without
needing the preference itself to be "last" at the moment of switching.

## Non-goals

- No widget-level recomposition — both views keep their exact current markup, JS, and API calls.
- No backend changes. No changes to `/api/dashboard/current`, `/api/dashboard/trends`, or
  `/api/predict/risk` contracts — Sub-project A already unified what feeds them.
- No server-side user-preference storage — `localStorage` only, matching existing convention.
- No change to Global Search's indexing. Confirmed via grep that no Go code hardcodes the
  `exec-dashboard` tab id, so nothing server-side breaks. If Search's own index surfaces
  "Executive Dashboard" as a distinct jump target, it will now land on the merged Dashboard tab at
  whichever view `resolveDashView()` picks — a minor landing-view inaccuracy, not a broken link or
  data regression. Fixing Search's own index (if it needs it) is out of scope here.

## Testing

This is a pure frontend change with no Go code touched — no `go test` coverage applies. Verification
is manual browser QA (consistent with this session's existing backlog of deferred manual QA for
Global Search, Run Workspace, Full Variant Sweep): confirm both views render their existing widgets
unchanged, the selector toggles between them without a page reload, the campaign poll stops when
Executive is showing, the three Preference options resolve correctly on next tab entry (including
across a hard reload), and that no console errors reference `tab-exec-dashboard` or `exec-dashboard`
after the nav-item removal.
