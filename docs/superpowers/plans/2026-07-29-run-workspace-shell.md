# Run Results Investigation Workspace — Sub-project A (Shell) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the run-results view inside `#results-overlay` from a cramped 520px stacked panel into a ~90vw investigation workspace with a command-center header, a real KPI strip, and a sticky 11-tab bar — while the same shared drawer, used for findings/techniques/search-fallback, stays exactly as compact and unchanged as it is today.

**Architecture:** A `run-mode` CSS class toggled only by `viewRunResults`/`closeResults` widens the shared `.drawer` and reveals 3 new containers (`#run-kpi-strip`, `#run-tabbar`, `#run-tab-content`) that don't exist for the other 3 callers. All of the run view's actual data computation (`scorePanel`, `checksHtml`, `renderAttackFlow`, `renderVariantCoverage`, `loadSIEMCorrelationPanel`) is untouched — only *where* each piece's output gets written changes, from 4 flat sibling divs behind a 3-button switcher to named panels behind a real sticky tab bar. The KPI strip and header toolbar reuse existing helper functions/CSS (`gaugeSVG`, `sparkSVG`, `.kpi-card`, `.sbadge`) verbatim.

## Global Constraints

- `.drawer-overlay.run-mode .drawer` is the **only** new width rule — the default `.drawer` (520px) must render identically for `openFinding`/`openTechnique`/`cmdkResultFallback`. (Spec §Architecture 1)
- `closeResults()` is confirmed the single close path for all 4 callers — it must remove `run-mode` unconditionally on every close. (Spec §Architecture 1)
- No new charting code — KPI gauges/sparklines reuse the existing `gaugeSVG(value, size, stroke)` (`index.html:12053`) and `sparkSVG(data, w, h, color)` (`index.html:12041`) verbatim. (Spec §Non-Goals)
- Never fabricate data. Compare and Re-run are **not real features anywhere in this app today** (confirmed: only a disabled "coming soon" Re-run button exists, for campaigns, not runs) — the header toolbar must render them the same way, disabled with a "coming soon" title, using the exact existing pattern (`index.html:6567`), not as working buttons. Any KPI card whose backing value isn't available renders an em-dash, never an invented number.
- Execution Timeline, MITRE ATT&CK, Indicators (IOCs), Endpoint Changes, and Recommendation tabs all render the existing `.dash-soon` "Coming soon" placeholder pattern (`index.html:738-744`) — no new content for any of them this sub-project. (Spec §Architecture 5)
- `rv-table`/`rv-flow`/`rv-coverage`/`rv-siem`/`rvt-results`/`rvt-flow`/`rvt-coverage`/`rvt-siem` are confirmed used **only** within the `viewRunResults`/`switchResultsView`/`loadSIEMCorrelationPanel` function cluster (`index.html:9884-10270`) — safe to restructure without hidden breakage elsewhere in this 14,000+ line file.
- This project has no automated frontend test harness — every verification step is a described manual browser check, matching every prior UI phase this session.

---

## File Structure

- Modify `orchestrator/cmd/server/wwwroot/index.html` only — the entire change lives inside the existing `<style>` block, the `#results-overlay` markup, and the `viewRunResults`/`switchResultsView`/`closeResults`/`openFinding`/`openTechnique`/`cmdkResultFallback` region. No other file changes.

---

### Task 1: CSS + HTML skeleton + `run-mode` lifecycle

**Files:**
- Modify: `orchestrator/cmd/server/wwwroot/index.html:653` (CSS insertion point)
- Modify: `orchestrator/cmd/server/wwwroot/index.html:3699-3711` (`#results-overlay` markup)
- Modify: `orchestrator/cmd/server/wwwroot/index.html` — `viewRunResults`, `closeResults`, `openFinding`, `openTechnique`, `cmdkResultFallback`

**Interfaces:**
- Produces: `.drawer-overlay.run-mode` CSS modifier; `#run-kpi-strip`/`#run-tabbar`/`#run-tab-content`/`#results-header-actions` DOM containers (all empty/hidden until later tasks populate them) — every later task in this plan writes into these exact IDs.

- [ ] **Step 1: Confirm current exact content before editing**

```bash
cd orchestrator && sed -n '624,653p;3699,3711p' cmd/server/wwwroot/index.html
```

Confirm this matches the blocks quoted in Steps 2-3 below exactly. This file is a single 14,000+ line SPA actively touched by many features — if it has drifted, stop and re-read before proceeding.

- [ ] **Step 2: Add the CSS**

Replace this exact current block:

```css
.drawer-body { flex: 1; overflow-y: auto; overflow-x: hidden; padding: 1.25rem; }
.drawer-body::-webkit-scrollbar { width: 3px; }
.drawer-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
```

With:

```css
.drawer-body { flex: 1; overflow-y: auto; overflow-x: hidden; padding: 1.25rem; }
.drawer-body::-webkit-scrollbar { width: 3px; }
.drawer-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

/* Run-results investigation workspace (Sub-project A) -- only applied when
   #results-overlay carries .run-mode, toggled by viewRunResults/closeResults.
   findings/technique/search-fallback (the drawer's 3 other callers) never
   set this class, so they keep the default 520px .drawer width above. */
.drawer-overlay.run-mode .drawer { width: 90vw; max-width: 1600px; }
.run-tabbar {
  position: sticky; top: 0; z-index: 5; background: var(--surface);
  display: flex; gap: 0.25rem; flex-wrap: wrap;
  border-bottom: 1px solid var(--border); margin-bottom: 1rem;
}
.run-tab-btn {
  background: transparent; border: none; border-bottom: 2px solid transparent;
  color: var(--muted); font-size: 0.78rem; font-weight: 600;
  padding: 0.55rem 0.85rem; cursor: pointer; font-family: inherit;
  white-space: nowrap; transition: color .15s, border-color .15s;
}
.run-tab-btn:hover { color: var(--text); }
.run-tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
.run-tab-grid { display: grid; grid-template-columns: 1fr; gap: 1rem; }
.run-tab-grid.with-side { grid-template-columns: 1fr 340px; }
@media (max-width: 900px) { .run-tab-grid.with-side { grid-template-columns: 1fr; } }
```

- [ ] **Step 3: Add the new header/body containers**

Replace this exact current block:

```html
<div id="results-overlay" class="drawer-overlay" onclick="if(event.target===this)closeResults()">
  <div class="drawer">
    <div class="drawer-header">
      <h3 id="results-title">Run Results</h3>
      <button class="drawer-close" onclick="closeResults()">&#10005;</button>
    </div>
    <div class="drawer-body">
      <div id="results-summary" style="margin-bottom:0.75rem;font-size:0.8rem"></div>
      <div id="results-export"></div>
      <div id="results-body" style="font-size:0.8rem"></div>
    </div>
  </div>
</div>
```

With:

```html
<div id="results-overlay" class="drawer-overlay" onclick="if(event.target===this)closeResults()">
  <div class="drawer">
    <div class="drawer-header">
      <h3 id="results-title">Run Results</h3>
      <div id="results-header-actions" style="display:flex;gap:0.5rem;align-items:center;margin-left:auto;margin-right:0.75rem"></div>
      <button class="drawer-close" onclick="closeResults()">&#10005;</button>
    </div>
    <div class="drawer-body">
      <div id="results-summary" style="margin-bottom:0.75rem;font-size:0.8rem"></div>
      <div id="results-export"></div>
      <div id="run-kpi-strip" style="display:none"></div>
      <div id="run-tabbar" style="display:none"></div>
      <div id="run-tab-content" style="display:none"></div>
      <div id="results-body" style="font-size:0.8rem"></div>
    </div>
  </div>
</div>
```

`#results-header-actions` stays empty for the other 3 callers (they never write to it) — only `viewRunResults` (Task 2) populates it.

- [ ] **Step 4: Wire `run-mode` on and off**

In `viewRunResults(run)`, the current first line is:

```js
function viewRunResults(run) {
  document.getElementById('results-title').textContent = run.name + ' — Results';
```

Replace with:

```js
function viewRunResults(run) {
  document.getElementById('results-overlay').classList.add('run-mode');
  document.getElementById('results-title').textContent = run.name + ' — Results';
```

Replace the current `closeResults()`:

```js
function closeResults() { document.getElementById('results-overlay').classList.remove('open'); }
```

With:

```js
function closeResults() { document.getElementById('results-overlay').classList.remove('open', 'run-mode'); }
```

In `openFinding(id)`, the current first line is:

```js
function openFinding(id) {
  apicall('/api/findings/' + encodeURIComponent(id)).then(function(f) {
```

Replace with:

```js
function openFinding(id) {
  document.getElementById('results-overlay').classList.remove('run-mode');
  apicall('/api/findings/' + encodeURIComponent(id)).then(function(f) {
```

In `openTechnique(id)`, the current first line is:

```js
function openTechnique(id) {
  var st = (window._covSt || {})[id] || 'none';
```

Replace with:

```js
function openTechnique(id) {
  document.getElementById('results-overlay').classList.remove('run-mode');
  var st = (window._covSt || {})[id] || 'none';
```

In `cmdkResultFallback(r)` (Global Search Phase 2), the current first line is:

```js
function cmdkResultFallback(r) {
  document.getElementById('results-title').textContent = r.title + ' — ' + CMDK_SEARCH_LABELS[r.docType];
```

Replace with:

```js
function cmdkResultFallback(r) {
  document.getElementById('results-overlay').classList.remove('run-mode');
  document.getElementById('results-title').textContent = r.title + ' — ' + CMDK_SEARCH_LABELS[r.docType];
```

These 3 defensive removals mean the narrow-drawer callers can never inherit stale wide-mode state even if some future code path skips `closeResults()`.

- [ ] **Step 5: Manual check — regression and expansion**

`go run ./cmd/server` from `orchestrator/` (human operator, matches every prior UI phase's verification approach — no dev-run script exists for this project).

- Open a finding, a technique, and a ⌘K search-fallback result — confirm all 3 still render in the original 520px drawer.
- Open a completed run's results — confirm the drawer visibly expands to ~90vw with the page behind it still faintly visible through the scrim.
- Close the run drawer, then immediately open a finding — confirm it's back to 520px (`run-mode` correctly removed).

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add cmd/server/wwwroot/index.html
git commit -m "feat(ui): run-mode drawer expansion shell (Run Workspace Sub-project A, Task 1)"
```

---

### Task 2: Header command center

**Files:**
- Modify: `orchestrator/cmd/server/wwwroot/index.html` — `viewRunResults`

**Interfaces:**
- Consumes: `#results-title`, `#results-header-actions` (Task 1); the existing `exportRunJSON`/`openRunReport`/`downloadRunPDF`/`downloadRunCSV` functions (unchanged, just relocated into this new container).
- Produces: nothing new consumed elsewhere — this task's output is purely visual, populated fresh on every `viewRunResults` call.

- [ ] **Step 1: Confirm current exact content**

```bash
cd orchestrator && sed -n '9884,9927p' cmd/server/wwwroot/index.html
```

Confirm this matches Task 1's final state of `viewRunResults`'s opening (with the `run-mode` line already added) through the existing export-bar block.

- [ ] **Step 2: Populate the header status pill + toolbar, and remove the old inline export bar**

Replace this exact current block:

```js
  // Export bar + view-toggle tabs — only when run has an ID and is completed/partial
  var exportHtml = '';
  var runId = run.id || '';
  if (runId && (run.status === 'completed' || run.status === 'partial')) {
    exportHtml =
      '<div style="display:flex;gap:0.5rem;align-items:center;padding:0.5rem 0.75rem;margin-bottom:0.5rem;' +
                  'background:var(--surface);border:1px solid var(--border);border-radius:4px;flex-wrap:wrap">' +
        '<span style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-right:0.25rem">Export</span>' +
        '<button class="btn btn-sm btn-outline" onclick="exportRunJSON(\'' + runId + '\')" title="Download full run data as JSON">&#8595; JSON</button>' +
        '<button class="btn btn-sm btn-outline" onclick="openRunReport(\'' + runId + '\')" title="Open self-contained HTML report in new tab">&#8595; HTML Report</button>' +
        '<button class="btn btn-sm btn-outline" onclick="downloadRunPDF(\'' + runId + '\')" title="Download PDF report">&#8595; PDF</button>' +
        '<button class="btn btn-sm btn-outline" onclick="downloadRunCSV(\'' + runId + '\')" title="Download forensic CSV (one row per technique)">&#8595; CSV</button>' +
        '<span style="flex:1"></span>' +
        '<button id="rvt-results" class="btn btn-sm" style="background:var(--elevated);color:var(--accent);border:1px solid var(--border);border-bottom:2px solid var(--accent);border-radius:4px 4px 0 0" onclick="switchResultsView(\'table\')">Results</button>' +
        '<button id="rvt-flow" class="btn btn-sm" style="color:var(--muted);border:1px solid transparent;border-radius:4px 4px 0 0" onclick="switchResultsView(\'flow\')">&#9660; Attack Flow</button>' +
        '<button id="rvt-coverage" class="btn btn-sm" style="color:var(--muted);border:1px solid transparent;border-radius:4px 4px 0 0" onclick="switchResultsView(\'coverage\')">&#9632; Variant Coverage</button>' +
      '</div>';
  }
  document.getElementById('results-export').innerHTML = exportHtml;
```

With:

```js
  var runId = run.id || '';
  var hasOutput = runId && (run.status === 'completed' || run.status === 'partial');
  document.getElementById('results-export').innerHTML = '';

  // Header status pill -- reuses the exact status->color mapping the Live
  // Runs table already applies (index.html:13171), and the .sbadge pill
  // pattern already used for license/status badges elsewhere (index.html:12905).
  var runStatusColor = { completed: 'var(--success)', running: 'var(--accent)', partial: 'var(--warning)', failed: 'var(--danger)' }[run.status] || 'var(--muted)';
  document.getElementById('results-title').innerHTML =
    x(run.name) + ' — Results ' +
    '<span class="sbadge" style="background:' + runStatusColor + '22;color:' + runStatusColor + ';border:1px solid ' + runStatusColor + '44;font-size:0.65rem;margin-left:0.4rem;vertical-align:middle">' + x(run.status || '') + '</span>';

  // Header toolbar -- real export actions relocated verbatim from the old
  // inline export bar. Compare/Re-run are NOT real features anywhere in this
  // app today (confirmed: the only existing "Re-run" is a disabled
  // "coming soon" button, for campaigns, not runs -- index.html:6567), so
  // they render the same disabled way here rather than as working buttons.
  var actionsHtml = '';
  if (hasOutput) {
    actionsHtml =
      '<button class="btn btn-sm btn-outline" onclick="exportRunJSON(\'' + runId + '\')" title="Download full run data as JSON">&#8595; JSON</button>' +
      '<button class="btn btn-sm btn-outline" onclick="openRunReport(\'' + runId + '\')" title="Open self-contained HTML report in new tab">&#8595; HTML Report</button>' +
      '<button class="btn btn-sm btn-outline" onclick="downloadRunPDF(\'' + runId + '\')" title="Download PDF report">&#8595; PDF</button>' +
      '<button class="btn btn-sm btn-outline" onclick="downloadRunCSV(\'' + runId + '\')" title="Download forensic CSV (one row per technique)">&#8595; CSV</button>' +
      '<button class="btn btn-outline btn-sm" disabled style="opacity:0.5;cursor:not-allowed" title="Compare against another run — coming soon">Compare</button>' +
      '<button class="btn btn-outline btn-sm" disabled style="opacity:0.5;cursor:not-allowed" title="Re-run this execution — coming soon">Re-run</button>';
  }
  document.getElementById('results-header-actions').innerHTML = actionsHtml;
```

Note: `x()` here is the file's existing global HTML-escape helper (used throughout, e.g. `index.html:10290`), not a new function — confirm it's already in scope at this call site (it is; every other call site inside `viewRunResults` already uses it, e.g. `x(run.agentId)` in the summary line just above this block).

- [ ] **Step 3: Manual check**

Open a completed run's results. Confirm: the header shows the scenario name with a colored status pill matching the run's actual status, the toolbar on the right has working JSON/HTML Report/PDF/CSV buttons (identical behavior to before this task), and greyed-out, tooltip-explained Compare/Re-run buttons that do nothing when clicked (matching the app's existing "coming soon" convention).

- [ ] **Step 4: Commit**

```bash
cd orchestrator
git add cmd/server/wwwroot/index.html
git commit -m "feat(ui): run header command center (Run Workspace Sub-project A, Task 2)"
```

---

### Task 3: KPI summary strip

**Files:**
- Modify: `orchestrator/cmd/server/wwwroot/index.html` — `viewRunResults`

**Interfaces:**
- Consumes: `#run-kpi-strip` (Task 1); `gaugeSVG(value, size, stroke)`, `sparkSVG(data, w, h, color)` (existing, `index.html:12053`/`12041`); `.kpi-row`/`.kpi-card`/`.kpi-label`/`.kpi-value`/`.kpi-sub`/`.ring`/`.ring-c` (existing CSS).
- Produces: nothing new consumed elsewhere.

- [ ] **Step 1: Confirm current exact content**

```bash
cd orchestrator && sed -n '9929,9935p' cmd/server/wwwroot/index.html
```

Confirm this is the start of the existing `scorePanel` computation (`if (run.score && typeof run.score.preventionScore !== 'undefined') { var s = run.score; ...`), unchanged by Tasks 1-2.

- [ ] **Step 2: Add the KPI strip renderer**

Immediately after this line (still inside the `if (run.score && ...)` block, right after `var cls = s.classification || '';`):

```js
    var cls     = s.classification || '';
```

Insert:

```js
    var cls     = s.classification || '';

    // KPI strip -- reuses the exact gaugeSVG/sparkSVG helpers and .kpi-card
    // CSS the main Dashboard already uses (index.html:12041-12063, :670-697).
    // Detection Rate is derived the same way the existing summary line
    // above already computes pass/fail; every other value comes straight
    // off run.score, already confirmed real during brainstorming. No card
    // here is backed by fabricated data -- a missing value renders '—'.
    (function() {
      var detRate = results.length ? Math.round(pass * 100 / results.length) : 0;
      var deltaHtml = (typeof s.previousPreventionScore !== 'undefined' && s.previousPreventionScore !== null)
        ? (function() {
            var delta = Math.round(prevPct - s.previousPreventionScore);
            var arrow = delta > 0 ? '↑' : delta < 0 ? '↓' : '→';
            var col = delta > 0 ? 'var(--success)' : delta < 0 ? 'var(--danger)' : 'var(--muted)';
            return '<span style="color:' + col + '">' + arrow + ' ' + Math.abs(delta) + ' pts vs last run</span>';
          })()
        : '';
      function kpiGaugeCard(label, value, sub) {
        return '<div class="kpi-card" style="display:flex;align-items:center;gap:0.75rem">' +
          '<div class="ring" style="width:64px;height:64px">' + gaugeSVG(value, 64, 8) +
            '<div class="ring-c"><div class="rv" style="font-size:0.95rem">' + value + '%</div></div></div>' +
          '<div><div class="kpi-label">' + label + '</div><div class="kpi-sub">' + sub + '</div></div>' +
        '</div>';
      }
      document.getElementById('run-kpi-strip').innerHTML =
        '<div class="kpi-row" style="grid-template-columns:repeat(6,1fr)">' +
          '<div class="kpi-card"><div class="kpi-label">Overall Security Score</div><div class="kpi-value">' + prevPct + '<span style="font-size:0.9rem;color:var(--muted)">/100</span></div><div class="kpi-sub">' + (deltaHtml || '—') + '</div></div>' +
          kpiGaugeCard('Detection Rate', detRate, pass + ' / ' + results.length + ' techniques') +
          kpiGaugeCard('Prevention Rate', prevPct, cls || '—') +
          '<div class="kpi-card"><div class="kpi-label">Exposure Score</div><div class="kpi-value" style="color:' + expCol + '">' + expVal + '</div><div class="kpi-sub">×' + amp + ' kill-chain</div></div>' +
          kpiGaugeCard('Tactic Coverage', covPct, 'of 14 ATT&CK tactics') +
          '<div class="kpi-card"><div class="kpi-label">Risk Level</div><div class="kpi-value" style="color:' + trendCol + '">' + trendIcon + ' ' + x(trend) + '</div><div class="kpi-sub">vs prior run</div></div>' +
        '</div>';
    })();
```

- [ ] **Step 3: Show the strip when run-mode is active**

Find the existing line (still inside `viewRunResults`, near the end where `#results-overlay` is opened):

```js
  document.getElementById('results-overlay').classList.add('open');
```

Replace with:

```js
  document.getElementById('run-kpi-strip').style.display = '';
  document.getElementById('results-overlay').classList.add('open');
```

(Task 4 will add the analogous `display=''` lines for `#run-tabbar`/`#run-tab-content` and the corresponding hides for `#results-summary`/`#results-body` right alongside this — left as one combined edit there to avoid two passes over the same line.)

- [ ] **Step 4: Manual check**

Open a completed run with real score data. Confirm the KPI strip renders 6 cards: Overall Security Score (with a real delta vs. the previous run's prevention score, or `—` if no prior run), Detection Rate and Prevention Rate as circular gauges with correct percentages, Exposure Score, Tactic Coverage as a gauge, and Risk Level with the correct trend arrow/color. Open a run with no `run.score` at all — confirm the strip is simply absent (the surrounding `if (run.score && ...)` guard already handles this, matching today's behavior for score-less runs).

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add cmd/server/wwwroot/index.html
git commit -m "feat(ui): run KPI summary strip (Run Workspace Sub-project A, Task 3)"
```

---

### Task 4: Sticky tab bar + tab switching

**Files:**
- Modify: `orchestrator/cmd/server/wwwroot/index.html` — `viewRunResults`, replaces `switchResultsView`

**Interfaces:**
- Consumes: `#run-tabbar`/`#run-tab-content` (Task 1); `.run-tabbar`/`.run-tab-btn` CSS (Task 1).
- Produces: `switchRunTab(tabId)` — Task 5's relocated content panels are addressed by the `tabId`s this function switches between: `overview`, `flow`, `variant`, `detection`, `evidence`, `reports`, `timeline`, `mitre`, `iocs`, `endpoint`, `recommendation`.

- [ ] **Step 1: Confirm current exact content**

```bash
cd orchestrator && sed -n '10123,10201p' cmd/server/wwwroot/index.html
```

Confirm this matches the comment block through the end of `switchResultsView`, unchanged by Tasks 1-3.

- [ ] **Step 2: Replace the results-body assembly with the new tab bar**

Replace this exact current block (the comment and the `results-body`/`results-overlay` assembly — **not** `switchResultsView`, which is handled separately in Step 3 below since it's a separate function later in the file):

```js
  // scorePanel + run-report-extra (findings/recommendations/attack-flow-summary/
  // alert-fatigue/attack-surface-age/readiness) live INSIDE rv-table so they hide
  // and show together with the Results tab — previously they sat outside the tab
  // toggle entirely and stayed visible under every tab, which is what made
  // switching to Attack Flow or Variant Coverage look like it was appending that
  // tab's data after the Results content instead of replacing it.
  document.getElementById('results-body').innerHTML =
    '<div id="rv-table">' + scorePanel + '<div id="run-report-extra"></div>' + checksHtml + '</div>' +
    '<div id="rv-flow" style="display:none"><div style="color:var(--muted);font-size:0.72rem;padding:1.5rem 0;text-align:center">Loading attack flow…</div></div>' +
    '<div id="rv-coverage" style="display:none"><div style="color:var(--muted);font-size:0.72rem;padding:1.5rem 0;text-align:center">Loading variant coverage&#8230;</div></div>' +
    '<div id="rv-siem" style="display:none"></div>';
  document.getElementById('run-kpi-strip').style.display = '';
  document.getElementById('results-overlay').classList.add('open');
```

With:

```js
  // Overview keeps scorePanel + run-report-extra (findings/recommendations/
  // alert-fatigue/attack-surface-age/readiness); the per-technique checks
  // move to their own Evidence tab -- previously both lived in one "Results"
  // view together. rv-flow/rv-coverage/rv-siem keep their exact existing
  // IDs and lazy-load logic (see the apicall() calls right below this
  // block) -- only their container changed, from flat siblings behind a
  // 3-button switcher to named panels behind the new tab bar.
  var soonPanel = function(label) {
    return '<div class="dash-panel dash-soon" style="padding:2rem;text-align:center;color:var(--muted);font-size:0.8rem">' + x(label) + ' — real data not available for this run yet.</div>';
  };
  document.getElementById('run-tab-content').innerHTML =
    '<div id="run-tab-overview" class="run-tab-panel">' +
      '<div class="run-tab-grid with-side">' +
        '<div>' + scorePanel + '</div>' +
        '<div id="run-report-extra"></div>' +
      '</div>' +
    '</div>' +
    '<div id="run-tab-flow" class="run-tab-panel" style="display:none">' +
      '<div id="rv-flow"><div style="color:var(--muted);font-size:0.72rem;padding:1.5rem 0;text-align:center">Loading attack flow…</div></div>' +
    '</div>' +
    '<div id="run-tab-variant" class="run-tab-panel" style="display:none">' +
      '<div id="rv-coverage"><div style="color:var(--muted);font-size:0.72rem;padding:1.5rem 0;text-align:center">Loading variant coverage&#8230;</div></div>' +
    '</div>' +
    '<div id="run-tab-detection" class="run-tab-panel" style="display:none"><div id="rv-siem"></div></div>' +
    '<div id="run-tab-evidence" class="run-tab-panel" style="display:none">' + checksHtml + '</div>' +
    '<div id="run-tab-reports" class="run-tab-panel" style="display:none"></div>' +
    '<div id="run-tab-timeline" class="run-tab-panel" style="display:none">' + soonPanel('Execution Timeline') + '</div>' +
    '<div id="run-tab-mitre" class="run-tab-panel" style="display:none">' + soonPanel('MITRE ATT&CK') + '</div>' +
    '<div id="run-tab-iocs" class="run-tab-panel" style="display:none">' + soonPanel('Indicators (IOCs)') + '</div>' +
    '<div id="run-tab-endpoint" class="run-tab-panel" style="display:none">' + soonPanel('Endpoint Changes') + '</div>' +
    '<div id="run-tab-recommendation" class="run-tab-panel" style="display:none">' + soonPanel('Recommendation') + '</div>';

  var RUN_TABS = [
    ['overview', 'Overview'], ['timeline', 'Execution Timeline'], ['mitre', 'MITRE ATT&CK'],
    ['detection', 'Detection Validation'], ['flow', 'Attack Flow'], ['variant', 'Variant Analysis'],
    ['evidence', 'Evidence'], ['iocs', 'Indicators (IOCs)'], ['endpoint', 'Endpoint Changes'],
    ['recommendation', 'Recommendation'], ['reports', 'Reports']
  ];
  document.getElementById('run-tabbar').innerHTML = RUN_TABS.map(function(t, i) {
    return '<button class="run-tab-btn' + (i === 0 ? ' active' : '') + '" id="run-tabbtn-' + t[0] + '" onclick="switchRunTab(\'' + t[0] + '\')">' + x(t[1]) + '</button>';
  }).join('');

  document.getElementById('results-summary').style.display = 'none';
  document.getElementById('results-body').style.display = 'none';
  document.getElementById('run-kpi-strip').style.display = '';
  document.getElementById('run-tabbar').style.display = '';
  document.getElementById('run-tab-content').style.display = '';
  document.getElementById('results-overlay').classList.add('open');
```

Note the `soonPanel` reuses the existing `.dash-soon` CSS class (`index.html:738-744`) verbatim — no new placeholder styling invented. **Do not add a closing `}` here** — the function is not done yet. Immediately following this in the original file (unchanged, untouched by this step) is the async block that fetches `run-report-extra`/preloads `rv-flow`/`rv-coverage`/calls `loadSIEMCorrelationPanel` — that block, and `viewRunResults`'s real closing `}`, both stay exactly where they already are. This step's replacement ends at `results-overlay.classList.add('open');` with no brace, so the function body continues straight into that existing async block as it already does today.

- [ ] **Step 3: Replace `switchResultsView` with `switchRunTab`**

`switchResultsView` (the full function you confirmed in Step 1, from its leading comment through its closing `}`, currently right after `viewRunResults`'s own closing `}`) is dead code now — nothing above still calls it after Step 2's edit. Replace it, in full:

```js
// Toggles the run-results drawer between the "Results" table view and the
// "Attack Flow" visualization. Called by the tab buttons in the export bar.
function switchResultsView(view) {
  var tableEl    = document.getElementById('rv-table');
  var flowEl     = document.getElementById('rv-flow');
  var coverageEl = document.getElementById('rv-coverage');
  var siemEl     = document.getElementById('rv-siem');
  var btnT       = document.getElementById('rvt-results');
  var btnF       = document.getElementById('rvt-flow');
  var btnC       = document.getElementById('rvt-coverage');
  var btnS       = document.getElementById('rvt-siem');
  if (!tableEl) return;
  tableEl.style.display    = (view === 'table'    || !view) ? '' : 'none';
  if (flowEl)     flowEl.style.display     = (view === 'flow')     ? '' : 'none';
  if (coverageEl) coverageEl.style.display = (view === 'coverage') ? '' : 'none';
  if (siemEl)     siemEl.style.display     = (view === 'siem')     ? '' : 'none';
  var activeStyle   = { background: 'var(--elevated)', color: 'var(--accent)', borderBottom: '2px solid var(--accent)' };
  var inactiveStyle = { background: '', color: 'var(--muted)', borderBottom: '' };
  function applyTab(btn, isActive) {
    if (!btn) return;
    var s = isActive ? activeStyle : inactiveStyle;
    btn.style.background   = s.background;
    btn.style.color        = s.color;
    btn.style.borderBottom = s.borderBottom;
  }
  applyTab(btnT, view === 'table' || !view);
  applyTab(btnF, view === 'flow');
  applyTab(btnC, view === 'coverage');
  applyTab(btnS, view === 'siem');
}
```

With:

```js
// switchRunTab replaces switchResultsView: shows exactly one of RUN_TABS's
// panels and updates the active tab button, matching the same
// show/hide-by-id mechanism switchResultsView used, generalized to 11
// tabs instead of a hardcoded 3-4.
function switchRunTab(tabId) {
  var content = document.getElementById('run-tab-content');
  if (!content) return;
  Array.prototype.forEach.call(content.querySelectorAll('.run-tab-panel'), function(panel) {
    panel.style.display = (panel.id === 'run-tab-' + tabId) ? '' : 'none';
  });
  Array.prototype.forEach.call(document.getElementById('run-tabbar').querySelectorAll('.run-tab-btn'), function(btn) {
    btn.classList.toggle('active', btn.id === 'run-tabbtn-' + tabId);
  });
}
```

`switchResultsView` is safe to remove in full — every one of its `rv-*`/`rvt-*` references is confirmed (this plan's Global Constraints) to be internal to this exact function cluster, and Step 2 already stopped generating the `rvt-results`/`rvt-flow`/`rvt-coverage` buttons that were its only callers.

- [ ] **Step 4: Update `loadSIEMCorrelationPanel`'s dynamic-button logic**

`loadSIEMCorrelationPanel(runId)` still needs no change to its data-fetching or `#rv-siem` population — `rv-siem` still exists with the exact same ID, just nested one level deeper now (inside `run-tab-detection` instead of being a flat sibling). But it also contains a now-dead block that dynamically injected an `rvt-siem` button next to the old `rvt-coverage` button bar — that bar no longer exists (the Detection Validation tab button is now always present, unconditionally, in `RUN_TABS`). Replace this exact current block:

```js
    if (!corrs || corrs.length === 0) return; // no correlation yet — hide tab
    // Inject SIEM tab button if not already there
    var btnBar = document.getElementById('rvt-coverage');
    if (btnBar && !document.getElementById('rvt-siem')) {
      var siemBtn = document.createElement('button');
      siemBtn.id = 'rvt-siem';
      siemBtn.className = 'btn btn-sm btn-outline';
      siemBtn.style.cssText = 'font-size:0.7rem;padding:0.22rem 0.7rem;color:var(--muted);border-bottom:2px solid transparent';
      siemBtn.textContent = 'SIEM Correlation';
      siemBtn.onclick = function() { switchResultsView('siem'); };
      btnBar.parentNode.insertBefore(siemBtn, btnBar.nextSibling);
    }
    var c = corrs[0]; // most recent correlation
```

With:

```js
    if (!corrs || corrs.length === 0) return; // no correlation yet — Detection Validation tab stays empty
    var c = corrs[0]; // most recent correlation
```

The Detection Validation tab button is now always present in the tab bar (matching the other real tabs) rather than conditionally injected — if there's no correlation data, `#rv-siem` simply stays empty, which is an acceptable, honest empty state (not a fabricated placeholder).

- [ ] **Step 5: Manual check**

Open a completed run. Confirm: 11 tabs render in a sticky bar, Overview is active by default, clicking each tab shows exactly its own content and hides the others, and scrolling a long tab (e.g. Evidence once Task 5 populates it, or Overview meanwhile) keeps the tab bar visible/pinned at the top of the scroll region.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add cmd/server/wwwroot/index.html
git commit -m "feat(ui): sticky 11-tab bar replacing switchResultsView (Run Workspace Sub-project A, Task 4)"
```

---

### Task 5: Evidence tab, Reports tab, and Overview's side-column analytics

**Files:**
- Modify: `orchestrator/cmd/server/wwwroot/index.html` — `viewRunResults`

**Interfaces:**
- Consumes: `#run-tab-evidence`/`#run-tab-reports`/`#run-report-extra` (Task 4); `renderRunReportExtra(rep)` (existing, unchanged); `checksHtml`/`scorePanel` (existing, unchanged, just already correctly targeted by Task 4's Step 2 edit).

- [ ] **Step 1: Confirm the Evidence tab already has real content**

Task 4's Step 2 already placed `checksHtml` (the existing per-tactic grouped technique list — pass/fail, evidence button, remediation, threat impact) directly into `#run-tab-evidence`. No further code change is needed for Evidence — this step is verification only:

```bash
cd orchestrator && grep -n "run-tab-evidence" cmd/server/wwwroot/index.html
```

Expected: one line, `'<div id="run-tab-evidence" class="run-tab-panel" style="display:none">' + checksHtml + '</div>' +`, confirming Task 4 already wired this correctly.

- [ ] **Step 2: Populate the Reports tab**

Find the existing async block (unchanged by prior tasks) that begins:

```js
  if (runId && (run.status === 'completed' || run.status === 'partial')) {
    var extraEl = document.getElementById('run-report-extra');
```

Immediately before this line, insert the Reports tab's content (run metadata + the same export actions, restated as a dedicated tab per the design doc's §5):

```js
  var reportsEl = document.getElementById('run-tab-reports');
  if (reportsEl) {
    if (hasOutput) {
      reportsEl.innerHTML =
        '<div class="dash-panel" style="margin-bottom:1rem"><div class="dash-panel-hdr">Run Metadata</div><div class="dash-panel-body">' +
          '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:0.75rem;font-size:0.78rem">' +
            '<div><div class="kpi-label">Run ID</div><div>' + x(runId) + '</div></div>' +
            '<div><div class="kpi-label">Agent</div><div>' + x(run.agentId || '') + '</div></div>' +
            '<div><div class="kpi-label">Status</div><div>' + x(run.status || '') + '</div></div>' +
          '</div>' +
        '</div></div>' +
        '<div class="dash-panel"><div class="dash-panel-hdr">Export</div><div class="dash-panel-body" style="display:flex;gap:0.5rem;flex-wrap:wrap">' +
          '<button class="btn btn-sm btn-outline" onclick="exportRunJSON(\'' + runId + '\')">&#8595; JSON</button>' +
          '<button class="btn btn-sm btn-outline" onclick="openRunReport(\'' + runId + '\')">&#8595; HTML Report</button>' +
          '<button class="btn btn-sm btn-outline" onclick="downloadRunPDF(\'' + runId + '\')">&#8595; PDF</button>' +
          '<button class="btn btn-sm btn-outline" onclick="downloadRunCSV(\'' + runId + '\')">&#8595; CSV</button>' +
        '</div></div>';
    } else {
      reportsEl.innerHTML = '<div style="color:var(--muted);font-size:0.8rem;padding:1rem 0">No exportable output yet — this run hasn\'t completed.</div>';
    }
  }

  if (runId && (run.status === 'completed' || run.status === 'partial')) {
    var extraEl = document.getElementById('run-report-extra');
```

- [ ] **Step 3: Confirm Overview's side column already has real content**

Task 4's Step 2 already placed `scorePanel` in Overview's main column and `#run-report-extra` (populated asynchronously by the existing `renderRunReportExtra(rep)` call, which builds the Alert Fatigue & Noise Analysis / Attack Surface Age / Endpoint Stability tiles) in its side column, via `.run-tab-grid.with-side`. Verify:

```bash
cd orchestrator && grep -n "run-tab-overview" cmd/server/wwwroot/index.html
```

Expected: the `run-tab-grid with-side` wrapper from Task 4 Step 2, containing `scorePanel` and `run-report-extra` in the 2-column layout — no further change needed here either.

- [ ] **Step 4: Manual check**

Open a completed run. Confirm: Evidence tab shows the same per-technique list that used to be under "Results", Reports tab shows run metadata plus working export buttons, and Overview shows the score panel next to a side column containing Alert Fatigue & Noise Analysis / Attack Surface Age / Endpoint Stability (once `renderRunReportExtra`'s async fetch resolves) — all matching their pre-redesign content exactly, just in their new homes.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add cmd/server/wwwroot/index.html
git commit -m "feat(ui): Reports tab + confirm Evidence/Overview relocation (Run Workspace Sub-project A, Task 5)"
```

---

### Task 6: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Full build**

Run: `cd orchestrator && go build ./...`
Expected: no errors (this phase only touches a static asset the Go server embeds, but confirm nothing else in the build was accidentally affected).

- [ ] **Step 2: Full vet**

Run: `cd orchestrator && go vet ./...`
Expected: no errors.

- [ ] **Step 3: Full test suite**

Run: `cd orchestrator && go test ./... -count=1 > /tmp/run_workspace_fulltest.log 2>&1; echo "EXIT_CODE:$?"` (redirect to a file and check `$?` directly, not through `tail`, which masks the real exit code — this project hit that exact masking bug during a prior phase's regression run). Run in background if it exceeds the interactive timeout.
Expected: exit code 0, PASS across all packages (Docker Desktop must be running). If a single package fails with a `testcontainers`/Docker connection error under full-suite load, re-run that package alone before treating it as a real regression — this project has hit this exact transient flake repeatedly, always confirmed harmless by isolation re-run.

- [ ] **Step 4: Full manual QA pass**

This is the actual verification for this phase's real change — Steps 1-3 only confirm the unrelated Go backend still compiles (this phase touched none of it). Re-run every manual check from Tasks 1-5 in one continuous pass on a real run with real score/evidence/attack-flow/variant-coverage/SIEM data:

- Findings/technique/search-fallback drawers stay compact (Task 1).
- Run drawer expands to ~90vw, header shows status pill + real export actions + disabled Compare/Re-run (Task 2).
- KPI strip shows 6 real-data cards, gauges render correctly, no fabricated numbers (Task 3).
- All 11 tabs switch correctly, tab bar stays pinned while scrolling (Task 4).
- Evidence/Reports/Overview-side-column all show their real, unchanged content in their new homes; the 5 deferred tabs show "Coming soon" (Task 5).
