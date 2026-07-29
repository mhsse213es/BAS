# Global Search Phase 2 (Command-Interface Rebuild) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing ⌘K command palette (`openCmdk()`, pure client-side navigation today) to Phase 1's `GET /api/search`, so typing searches real platform data and selecting a result navigates somewhere real.

**Architecture:** One JS function (`openCmdk()`) gets extended, not replaced — the existing static Navigate/Actions list keeps rendering synchronously exactly as today; a new debounced, request-race-safe search call merges results in as additional sections using the same `flat`/`selectable`/`run`/`paint` mechanism the static list already uses, so keyboard nav and click-to-select need zero changes. Selecting a result dispatches to a real navigation action per entity type, or a minimal fallback popup (reusing the existing `#results-overlay` drawer) for the three types with no detail view yet.

**Tech Stack:** Vanilla JS, no framework, no build step, no bundler — `cmd/server/wwwroot/index.html` is one file served as-is. No backend changes this phase.

## Global Constraints

- Empty-input behavior is byte-for-byte unchanged — the static Navigate/Actions list renders exactly as it does today. (Spec §Non-Goals)
- No new CSS, no new UI components beyond what's specified — reuse `.cmdk-sec`/`.cmdk-item`/`.cmdk-empty` and the existing `#results-overlay` drawer exactly as `openFinding`/`openTechnique` already use it. (Spec §Architecture 2, 4)
- Search results merge into the *same* `flat` array the static list already populates, reusing `run(i)`/`selectable()`/`paint()`/`move()` unchanged — do not fork a second selection/keyboard-nav mechanism. (Spec §Architecture 1, confirmed against real code during planning)
- Section label for `doc_type: "campaign"` is **"Threat Campaigns"**, never "Campaigns" — the sidebar's existing Campaigns tab is a different concept (`internal/campaign`, BAS execution rollups). (Spec §Architecture 2)
- Use the existing `apicall()` helper for the search fetch, not raw `fetch()` — matches this file's established convention and gets 401-session-expiry handling for free.
- **This file has no automated test harness** (confirmed: no `package.json`/test runner anywhere under `cmd/server/wwwroot/`) — every verification step in this plan is a described manual browser check, not a script. This is a deliberate departure from this project's usual TDD-with-real-tests discipline, not an oversight: it matches what the spec's own Testing section already committed to.

---

## File Structure

- Modify `orchestrator/cmd/server/wwwroot/index.html` — the entire change lives inside and immediately around the existing `openCmdk()` function (currently lines 11675-11757). No other file changes.

---

### Task 1: Extend `openCmdk()` with live search

**Files:**
- Modify: `orchestrator/cmd/server/wwwroot/index.html:11675-11757`

**Interfaces:**
- Produces: `cmdkSearch(q, onDone)`, `CMDK_SEARCH_LABELS`, `cmdkOpenResult(r)`, `cmdkResultFallback(r)` — all new, all self-contained within this one edit, nothing else in the file calls them yet or needs to.

This is one cohesive change to one function — it can't be shipped half-done (a partially-wired search box would either not render results or break keyboard nav), so it's a single task with several ordered steps, each independently checkable in a browser before moving to the next.

- [ ] **Step 1: Confirm the current exact content before editing**

```bash
cd orchestrator && sed -n '11675,11757p' cmd/server/wwwroot/index.html
```

Confirm this matches the block quoted in Step 2 below exactly (this file is actively developed elsewhere in this codebase; if it has drifted, stop and re-read the current version before proceeding — do not blindly apply the diff below over different content).

- [ ] **Step 2: Replace the header comment + `openCmdk()` body**

Replace this exact current block:

```js
/* ── Command palette (Ctrl/Cmd-K) ─────────────────────────────────────────
   Self-contained launcher routing to existing tabs + global actions. Respects
   role: Users/Settings (admin) and New scenario (admin/analyst) appear only when
   permitted — same gating as the sidebar. No backend; pure navigation. */
var _cmdkOpen = false;
function cmdkCommands() {
  var nav = [
    { t: 'Dashboard',   fn: function() { showTab('dashboard'); } },
    { t: 'Scenarios',   fn: function() { showTab('scenarios'); } },
    { t: 'Live Runs',   fn: function() { showTab('runs'); } },
    { t: 'Compliance',  fn: function() { showTab('compliance'); } },
    { t: 'Agents',      fn: function() { showTab('agents'); } }
  ];
  if (ROLE === 'admin') {
    nav.push({ t: 'Users & roles', fn: function() { showTab('settings'); showSettingsSection('users'); } });
    nav.push({ t: 'Settings', fn: function() { showTab('settings'); } });
  }
  var actions = [{ t: 'Run simulation', fn: function() { openModal(null, null); } }];
  if (ROLE === 'admin' || ROLE === 'analyst') {
    actions.unshift({ t: 'New scenario', fn: function() { openBuilder(); } });
  }
  return [{ sec: 'Navigate', items: nav }, { sec: 'Actions', items: actions }];
}
function openCmdk() {
  if (_cmdkOpen || !ROLE) return;
  _cmdkOpen = true;
  var cmds = cmdkCommands();
  var wrap = document.createElement('div');
  wrap.className = 'cmdk-scrim';
  wrap.innerHTML =
    '<div class="cmdk" role="dialog" aria-label="Command palette">' +
      '<div class="cmdk-in">' +
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>' +
        '<input id="cmdk-input" placeholder="Type a command or search…" autocomplete="off">' +
        '<span class="cmdk-esc">esc</span>' +
      '</div><div class="cmdk-list" id="cmdk-list"></div></div>';
  document.body.appendChild(wrap);
  var input = wrap.querySelector('#cmdk-input');
  var list = wrap.querySelector('#cmdk-list');
  var flat = [], active = 0;
  function selectable() { return flat.map(function(f, i) { return f.sec ? -1 : i; }).filter(function(i) { return i >= 0; }); }
  function paint() {
    var nodes = list.querySelectorAll('[data-ci]');
    Array.prototype.forEach.call(nodes, function(n) { n.classList.toggle('active', +n.dataset.ci === active); });
  }
  function draw(q) {
    q = (q || '').toLowerCase(); flat = [];
    cmds.forEach(function(c) {
      var items = c.items.filter(function(i) { return i.t.toLowerCase().indexOf(q) >= 0; });
      if (items.length) { flat.push({ sec: c.sec }); items.forEach(function(i) { flat.push(i); }); }
    });
    var sel = selectable(); active = sel.length ? sel[0] : 0;
    if (!flat.length) { list.innerHTML = '<div class="cmdk-empty">No matches</div>'; return; }
    list.innerHTML = flat.map(function(f, i) {
      return f.sec ? '<div class="cmdk-sec">' + x(f.sec) + '</div>'
                   : '<div class="cmdk-item" data-ci="' + i + '">' + x(f.t) + '</div>';
    }).join('');
    Array.prototype.forEach.call(list.querySelectorAll('[data-ci]'), function(node) {
      node.onmousemove = function() { active = +node.dataset.ci; paint(); };
      node.onclick = function() { run(+node.dataset.ci); };
    });
    paint();
  }
  function move(dir) {
    var sel = selectable(); if (!sel.length) return;
    var pos = sel.indexOf(active); if (pos < 0) pos = 0;
    active = sel[(pos + dir + sel.length) % sel.length]; paint();
    var node = list.querySelector('[data-ci="' + active + '"]'); if (node) node.scrollIntoView({ block: 'nearest' });
  }
  function run(i) { var it = flat[i]; if (!it || it.sec) return; close(); it.fn(); }
  function close() { _cmdkOpen = false; document.removeEventListener('keydown', onKey, true); wrap.remove(); }
  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
    else if (e.key === 'Enter') { e.preventDefault(); run(active); }
  }
  wrap.addEventListener('mousedown', function(e) { if (e.target === wrap) close(); });
  document.addEventListener('keydown', onKey, true);
  input.addEventListener('input', function() { draw(input.value); });
  draw('');
  setTimeout(function() { input.focus(); }, 20);
}
```

With:

```js
/* ── Command palette (Ctrl/Cmd-K) ─────────────────────────────────────────
   Launcher routing to existing tabs + global actions, plus live search
   (Global Search Phase 2) over GET /api/search -- results merge into the
   same flat/selectable/run mechanism the static nav list already uses, so
   keyboard nav and click-to-select work identically for both. Respects
   role: Users/Settings (admin) and New scenario (admin/analyst) appear only
   when permitted — same gating as the sidebar. */
var _cmdkOpen = false;
function cmdkCommands() {
  var nav = [
    { t: 'Dashboard',   fn: function() { showTab('dashboard'); } },
    { t: 'Scenarios',   fn: function() { showTab('scenarios'); } },
    { t: 'Live Runs',   fn: function() { showTab('runs'); } },
    { t: 'Compliance',  fn: function() { showTab('compliance'); } },
    { t: 'Agents',      fn: function() { showTab('agents'); } }
  ];
  if (ROLE === 'admin') {
    nav.push({ t: 'Users & roles', fn: function() { showTab('settings'); showSettingsSection('users'); } });
    nav.push({ t: 'Settings', fn: function() { showTab('settings'); } });
  }
  var actions = [{ t: 'Run simulation', fn: function() { openModal(null, null); } }];
  if (ROLE === 'admin' || ROLE === 'analyst') {
    actions.unshift({ t: 'New scenario', fn: function() { openBuilder(); } });
  }
  return [{ sec: 'Navigate', items: nav }, { sec: 'Actions', items: actions }];
}

// CMDK_SEARCH_LABELS maps a search result's docType to its section header.
// "campaign" -> "Threat Campaigns", deliberately not "Campaigns" -- the
// sidebar's existing Campaigns tab is internal/campaign (BAS execution
// rollups), a different concept from intelligence_campaigns.
var CMDK_SEARCH_LABELS = {
  scenario: 'Scenarios', run: 'Runs', finding: 'Findings',
  actor: 'Threat Actors', campaign: 'Threat Campaigns',
  malware: 'Malware', tool: 'Tools', technique: 'Techniques'
};

// cmdkOpenResult dispatches a selected search result to a real navigation
// action per docType, or the minimal fallback popup for the 3 types with
// no detail view anywhere in this app yet (campaign/malware/tool).
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
    // The 150ms delay matters here, not just as a defensive habit:
    // openTechnique() reads window._covSt[id], populated asynchronously by
    // loadCoverageMatrix() (kicked off by showTab('attack-coverage')) --
    // calling it too early shows a wrong "Untested" badge for a technique
    // that may actually be covered.
    showTab('attack-coverage');
    setTimeout(function() { openTechnique(r.sourceId); }, 150);
  } else if (r.docType === 'scenario') {
    // No true "open by ID" exists for scenarios -- they expand inline
    // within the Scenarios tab's own tile grid. Reuse the existing sc-search
    // filter box rather than building new expand-by-ID logic.
    showTab('scenarios');
    setTimeout(function() {
      document.getElementById('sc-search').value = r.title;
      renderScenarios();
    }, 150);
  } else {
    cmdkResultFallback(r);
  }
}

// cmdkResultFallback reuses the existing #results-overlay drawer (the same
// one openFinding/openTechnique already populate) to show a search result's
// own title/description/tags for entity types with no detail view built
// yet. No network request -- everything shown is already in `r`.
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

function openCmdk() {
  if (_cmdkOpen || !ROLE) return;
  _cmdkOpen = true;
  var cmds = cmdkCommands();
  var wrap = document.createElement('div');
  wrap.className = 'cmdk-scrim';
  wrap.innerHTML =
    '<div class="cmdk" role="dialog" aria-label="Command palette">' +
      '<div class="cmdk-in">' +
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>' +
        '<input id="cmdk-input" placeholder="Type a command or search…" autocomplete="off">' +
        '<span class="cmdk-esc">esc</span>' +
      '</div><div class="cmdk-list" id="cmdk-list"></div></div>';
  document.body.appendChild(wrap);
  var input = wrap.querySelector('#cmdk-input');
  var list = wrap.querySelector('#cmdk-list');
  var flat = [], active = 0;

  // Search state: cmdkSearchResults holds the last successful response
  // (kept across in-flight requests so results don't flicker to empty
  // while typing), null means the last request failed, [] means empty
  // query or genuinely no matches. cmdkSearchToken discards responses to
  // requests a newer keystroke has already superseded.
  var cmdkSearchResults = [];
  var cmdkSearchToken = 0;
  var cmdkSearchTimer = null;
  function cmdkSearch(q, onDone) {
    clearTimeout(cmdkSearchTimer);
    if (!q) { cmdkSearchResults = []; onDone(); return; }
    cmdkSearchTimer = setTimeout(function() {
      var token = ++cmdkSearchToken;
      apicall('/api/search?q=' + encodeURIComponent(q) + '&limit=20')
        .then(function(results) {
          if (token !== cmdkSearchToken) return;
          cmdkSearchResults = Array.isArray(results) ? results : null;
          onDone();
        })
        .catch(function() {
          if (token !== cmdkSearchToken) return;
          cmdkSearchResults = null;
          onDone();
        });
    }, 150);
  }

  function selectable() { return flat.map(function(f, i) { return f.sec ? -1 : i; }).filter(function(i) { return i >= 0; }); }
  function paint() {
    var nodes = list.querySelectorAll('[data-ci]');
    Array.prototype.forEach.call(nodes, function(n) { n.classList.toggle('active', +n.dataset.ci === active); });
  }

  function staticFlatFor(q) {
    var out = [];
    cmds.forEach(function(c) {
      var items = c.items.filter(function(i) { return i.t.toLowerCase().indexOf(q) >= 0; });
      if (items.length) { out.push({ sec: c.sec }); items.forEach(function(i) { out.push(i); }); }
    });
    return out;
  }

  function searchFlat() {
    var out = [];
    if (cmdkSearchResults === null) { out.push({ sec: 'Search unavailable' }); return out; }
    var byType = {};
    cmdkSearchResults.forEach(function(r) { (byType[r.docType] = byType[r.docType] || []).push(r); });
    ['scenario', 'run', 'finding', 'actor', 'campaign', 'malware', 'tool', 'technique'].forEach(function(dt) {
      var items = byType[dt];
      if (!items || !items.length) return;
      out.push({ sec: CMDK_SEARCH_LABELS[dt] });
      items.forEach(function(r) { out.push({ t: r.title, fn: function() { cmdkOpenResult(r); } }); });
    });
    return out;
  }

  function render(q) {
    flat = staticFlatFor(q).concat(searchFlat());
    var sel = selectable(); active = sel.length ? sel[0] : 0;
    if (!flat.length) { list.innerHTML = '<div class="cmdk-empty">No matches</div>'; return; }
    list.innerHTML = flat.map(function(f, i) {
      return f.sec ? '<div class="cmdk-sec">' + x(f.sec) + '</div>'
                   : '<div class="cmdk-item" data-ci="' + i + '">' + x(f.t) + '</div>';
    }).join('');
    Array.prototype.forEach.call(list.querySelectorAll('[data-ci]'), function(node) {
      node.onmousemove = function() { active = +node.dataset.ci; paint(); };
      node.onclick = function() { run(+node.dataset.ci); };
    });
    paint();
  }

  function draw(q) {
    q = (q || '').toLowerCase();
    render(q);
    cmdkSearch(input.value, function() { render(q); });
  }

  function move(dir) {
    var sel = selectable(); if (!sel.length) return;
    var pos = sel.indexOf(active); if (pos < 0) pos = 0;
    active = sel[(pos + dir + sel.length) % sel.length]; paint();
    var node = list.querySelector('[data-ci="' + active + '"]'); if (node) node.scrollIntoView({ block: 'nearest' });
  }
  function run(i) { var it = flat[i]; if (!it || it.sec) return; close(); it.fn(); }
  function close() { _cmdkOpen = false; document.removeEventListener('keydown', onKey, true); wrap.remove(); }
  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
    else if (e.key === 'Enter') { e.preventDefault(); run(active); }
  }
  wrap.addEventListener('mousedown', function(e) { if (e.target === wrap) close(); });
  document.addEventListener('keydown', onKey, true);
  input.addEventListener('input', function() { draw(input.value); });
  draw('');
  setTimeout(function() { input.focus(); }, 20);
}
```

Note what changed and what didn't, precisely:
- `selectable()`, `paint()`, `move(dir)`, `run(i)`, `close()`, `onKey(e)`, the two `addEventListener` calls, and the trailing `draw(''); setTimeout(...)` are **byte-for-byte unchanged**.
- `draw(q)`'s old body (the static-list-filter-and-render logic) is split into `staticFlatFor(q)` (just the filtering, no rendering) and folded into the new `render(q)` (rendering, now shared by both the static and search-augmented paths) — behaviorally identical for the static portion, just factored so `render(q)` can be called twice (once synchronously, once again when search resolves) without recomputing or duplicating the static filter twice.
- `CMDK_SEARCH_LABELS`, `cmdkOpenResult`, `cmdkResultFallback` are new module-level functions (outside `openCmdk()`, since they don't need any of its closure state — `cmdkSearch`/`cmdkSearchResults`/`cmdkSearchToken`/`cmdkSearchTimer`/`staticFlatFor`/`searchFlat`/`render` stay inside `openCmdk()`'s closure, same as every other helper it already defines).

- [ ] **Step 3: Manual check — empty-input regression**

This project has no documented one-command local dev-run path (confirmed during Phase 1 planning: no `docker-compose.yml`, no dev-run script at the repo root) — running the server requires a real Postgres connection and whatever config this deployment already uses (`go run ./cmd/server` from `orchestrator/`, with the same environment/connection setup already in place for this environment). This step is for a human operator to execute, not something to automate here.

Open the running app in a browser, log in, press ⌘K/Ctrl-K. Confirm the palette opens showing exactly the same Navigate/Actions list as before this change (Dashboard, Scenarios, Live Runs, Compliance, Agents, + admin-only Users & roles/Settings, + Run simulation/New scenario). This must look and behave identically to before Step 2 — if it doesn't, stop and re-check the `staticFlatFor`/`render` split before continuing.

- [ ] **Step 4: Manual check — live search renders grouped results**

With at least one real scenario, run, finding, actor, campaign, malware, tool, and technique present in the system (seed via the existing UI/connectors if a fresh environment has none), type a term into the open palette that matches at least one of each. Confirm:
- New sections appear below the static Navigate/Actions sections, labeled per `CMDK_SEARCH_LABELS` (specifically confirm the campaign section says "Threat Campaigns", not "Campaigns")
- Results within each section look correctly ranked (a title match should appear before a description-only match for the same query, inherited from Phase 1's `ts_rank` — already proven server-side, this step just confirms it renders in the right order)
- Typing continues to also filter the static Navigate/Actions list exactly as before (both behaviors coexist)

- [ ] **Step 5: Manual check — selection dispatch, one per docType**

For each of the 8 types, select a result (both by mouse click and by arrow-key-then-Enter) and confirm the expected outcome:
- `run` → download-options modal opens (from `openRunReport`)
- `finding` → Findings tab opens, then the specific finding's detail drawer opens
- `actor` → Threat Priority tab opens, then that actor's detail view opens
- `technique` → Attack Coverage tab opens, then that technique's detail drawer opens, with the *correct* coverage badge (not a stale "Untested")
- `scenario` → Scenarios tab opens, its own search box is pre-filled with the scenario's name, filtered results show it
- `campaign` / `malware` / `tool` → the fallback drawer opens showing that result's own title/description/tags, no navigation

- [ ] **Step 6: Manual check — degraded/edge states**

- Simulate `/api/search` failing (browser devtools request-blocking, or temporarily stop the server's DB connection) and confirm: the static list still works, and the search section shows "Search unavailable" instead of the palette breaking or throwing a JS error (check the browser console).
- Type quickly (or paste a multi-character string) and confirm no visibly wrong/stale result flashes appear before settling — this is the request-race guard (`cmdkSearchToken`) working.
- Clear the input back to empty after having typed something — confirm the search sections disappear and the palette returns to exactly the Step 3 empty-input state.

- [ ] **Step 7: Commit**

```bash
git add cmd/server/wwwroot/index.html
git commit -m "feat(ui): wire command palette to Global Search API (Global Search Phase 2)"
```

---

### Task 2: Full regression

**Files:** none (verification only)

Only one file changed, a static asset with no automated tests, but this is still part of the same Go module (the server embeds/serves this file) — confirm nothing else in the build was accidentally affected.

- [ ] **Step 1: Full build**

Run: `cd orchestrator && go build ./...`
Expected: no errors

- [ ] **Step 2: Full vet**

Run: `cd orchestrator && go vet ./...`
Expected: no errors

- [ ] **Step 3: Full test suite**

Run: `cd orchestrator && go test ./... -count=1` (run in background if it exceeds the interactive timeout)
Expected: PASS across all packages (Docker Desktop must be running). If a single unrelated package fails with a `testcontainers`/Docker provider connection error under full-suite load, re-run that package alone before treating it as a real regression — this project has hit this exact transient flake repeatedly across every phase this session, always confirmed harmless by isolation re-run.

- [ ] **Step 4: Confirm Task 1's full manual QA pass (Steps 3-6) is complete**

This is the actual verification for this phase's real change — Steps 1-3 above only confirm the unrelated Go backend still compiles and passes, which this phase didn't touch. If Task 1's manual checks weren't all completed, do them now before considering Phase 2 done.
