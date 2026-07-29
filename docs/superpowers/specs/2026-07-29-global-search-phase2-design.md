# Global Search Phase 2 (Command-Interface Rebuild) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-29.
**Depends on:** [[Global Search]] Phase 1 (`GET /api/search`, `internal/search`). No backend changes this phase — pure frontend, one file (`cmd/server/wwwroot/index.html`, a single-page vanilla-JS app with no build step or framework).

## Problem

The title bar's `openCmdk()` command palette is pure client-side navigation today — it filters a static, hardcoded list of tab shortcuts and admin actions (`cmdkCommands()`), with zero connection to real platform data. Phase 1 built a real, ranked, multi-entity search API with nothing consuming it. This phase wires the two together: typing in the existing palette also searches real data, and selecting a result takes you somewhere real.

## Non-Goals

- **No search-operator query language** (`type:scenario status:failed`) — Phase 4.
- **No ranking/personalization beyond what Phase 1's `ts_rank` already provides** (popularity, recency, favorites) — Phase 3.
- **No new detail views built from scratch for Threat Campaign/Malware/Tool.** Nothing in this app renders those entities today (confirmed: zero references to `/api/intelligence/*` anywhere in `index.html`). Building real detail pages for them is out of scope — see Architecture §4 for the minimal fallback instead.
- **No changes to the static Navigate/Actions list's existing behavior.** Empty-input state is untouched.
- **No new CSS file or component library.** Reuses existing `.cmdk-*` classes and the existing `#results-overlay` drawer pattern exactly as `openFinding`/`openTechnique` already use it.

## Architecture

### 1. Debounced search, merged into the existing render, request-race-safe

`openCmdk()`'s existing `draw(q)` function still runs the static-list filter synchronously on every keystroke, unchanged. A new debounced call is added alongside it:

```js
var cmdkSearchToken = 0;
var cmdkSearchResults = []; // last successful search response, kept across in-flight requests to avoid flicker
var cmdkSearchTimer = null;

function cmdkSearch(q, onDone) {
  clearTimeout(cmdkSearchTimer);
  if (!q) { cmdkSearchResults = []; onDone(); return; }
  cmdkSearchTimer = setTimeout(function() {
    var token = ++cmdkSearchToken;
    apicall('/api/search?q=' + encodeURIComponent(q) + '&limit=20')
      .then(function(results) {
        if (token !== cmdkSearchToken) return; // a newer keystroke already superseded this request
        cmdkSearchResults = results || [];
        onDone();
      })
      .catch(function() {
        if (token !== cmdkSearchToken) return;
        cmdkSearchResults = null; // null = "search failed", distinct from [] = "no results"
        onDone();
      });
  }, 150);
}
```

`draw(q)` calls `cmdkSearch(q, function() { draw2() })` where `draw2` is the existing render logic extracted to also append `cmdkSearchResults` as additional sections (see §2) after the static ones. Debounce is 150ms — short enough to feel live, long enough that fast typing doesn't fire a request per keystroke. Uses the existing `apicall()` helper (`credentials:'same-origin'`, JSON parsing, 401→logout), not raw `fetch()` — matches this file's established convention.

### 2. Result sections, reusing existing `.cmdk-sec`/`.cmdk-item` styling

Each non-empty `docType` group in `cmdkSearchResults` becomes one more section, appended after the static Navigate/Actions sections, using a label map:

```js
var CMDK_SEARCH_LABELS = {
  scenario: 'Scenarios', run: 'Runs', finding: 'Findings',
  actor: 'Threat Actors', campaign: 'Threat Campaigns', // not "Campaigns" -- the sidebar's existing
                                                          // Campaigns tab is internal/campaign (BAS
                                                          // execution rollups), a different concept
  malware: 'Malware', tool: 'Tools', technique: 'Techniques'
};
```

If `cmdkSearchResults === null` (the request failed), render one line "Search unavailable" instead of a section — the static list above it keeps working regardless. If `cmdkSearchResults` is `[]` (empty query or genuinely no matches) with a non-empty `q`, no extra section renders (existing "No matches" empty-state logic already handles the case where nothing at all matched).

### 3. Selection dispatch — closes the palette first (matching existing `run(i)` behavior exactly), then routes by `docType`

```js
function cmdkOpenResult(r) {
  if (r.docType === 'run') {
    openRunReport(r.sourceId);
  } else if (r.docType === 'finding') {
    showTab('findings');
    setTimeout(function() { openFinding(r.sourceId); }, 150);
  } else if (r.docType === 'actor') {
    showTab('threat-priority');
    setTimeout(function() { showThreatPriorityDetail(r.title); }, 150);
  } else if (r.docType === 'technique') {
    showTab('attack-coverage');
    setTimeout(function() { openTechnique(r.sourceId); }, 150);
  } else if (r.docType === 'scenario') {
    showTab('scenarios');
    setTimeout(function() {
      document.getElementById('sc-search').value = r.title;
      renderScenarios();
    }, 150);
  } else {
    cmdkResultFallback(r);
  }
}
```

The 150ms delay before `openFinding`/`showThreatPriorityDetail`/`openTechnique` matches the exact pattern already used elsewhere in this file (e.g. the existing `showTab('findings');setTimeout(function(){openFinding(id)},150)` call site) — necessary in at least `openTechnique`'s case for a real reason, not just caution: it reads `window._covSt[id]`, a coverage-status lookup populated by `loadCoverageMatrix()`, which `showTab('attack-coverage')` kicks off asynchronously; calling `openTechnique` before that resolves would show a wrong "Untested" badge for a technique that's actually covered. Applying the same delay uniformly across all four tab-switch cases is the consistent, low-risk choice rather than proving each one race-free individually.

`actor` uses `r.title` (the actor's real name, e.g. `"APT29"`) — `showThreatPriorityDetail` takes a name, not a normalized key, and search results already carry the actor's display title unchanged from `threat_actor_profiles.name`.

`scenario` has no true "open by ID" anywhere in this app (scenarios expand inline within the Scenarios tab's own tile grid) — reusing the *existing* `sc-search` filter box (setting its value and calling the *existing* `renderScenarios()`) is the realistic action here, not new expand-by-ID logic.

`run` uses `openRunReport(runId)` — this opens a download-options modal for the HTML report (not an inline detail view; no simpler "just show me this run" opener exists that works from an ID alone without an extra fetch), still real, useful content about that run.

### 4. Fallback for Threat Campaign/Malware/Tool — reuse the existing `#results-overlay` drawer, no fetch needed

`openFinding`/`openTechnique` both already populate a single shared drawer (`#results-overlay`, `#results-title`, `#results-body`) and call `.classList.add('open')` on it (closed via the already-existing `closeResults()`). The fallback reuses this exact same drawer rather than inventing a new popup element:

```js
function cmdkResultFallback(r) {
  document.getElementById('results-title').textContent = r.title + ' — ' + CMDK_SEARCH_LABELS[r.docType];
  document.getElementById('results-export').innerHTML = '';
  document.getElementById('results-summary').innerHTML = '';
  document.getElementById('results-body').innerHTML =
    (r.description ? '<p style="margin-bottom:0.8rem">' + x(r.description) + '</p>' : '') +
    ((r.tags || []).length ? '<div style="display:flex;gap:0.4rem;flex-wrap:wrap">' +
      r.tags.map(function(t) { return '<span class="sbadge" style="background:transparent;border:1px solid var(--border)">' + x(t) + '</span>'; }).join('') +
      '</div>' : '');
  document.getElementById('results-overlay').classList.add('open');
}
```

No network request — the search result already carries everything this shows (`title`/`description`/`tags`), unlike `openFinding`/`openTechnique` which fetch fresh detail by ID. `x()` is the existing HTML-escaping helper already used throughout this file.

## Testing

This is a single-file vanilla-JS frontend with no existing test harness or build step (confirmed: no `package.json`/test runner anywhere under `cmd/server/wwwroot/`) — matches this app's established pattern of manual browser verification for UI changes, not automated frontend tests. Verification for this phase is manual:
- Start the server locally, open the app, confirm ⌘K still shows the static Navigate/Actions list with empty input (regression check — must be byte-for-byte the same behavior as before this phase).
- Type a term matching at least one entity from each of the 8 `docType`s (using real or seeded data) and confirm the corresponding section appears, labeled correctly, ranked with title matches above description-only matches (inherited from Phase 1, just needs to render correctly here).
- Select one result of each type via both mouse click and keyboard (arrow to it, Enter) and confirm the correct navigation/fallback happens.
- Kill the `/api/search` route temporarily (or throttle/fail it via browser devtools) and confirm the static list still works and "Search unavailable" shows instead of a crash.
- Type quickly (simulating fast keystrokes) and confirm no visibly wrong/stale result flashes appear (request-race guard working).
