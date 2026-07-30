# Full Variant Sweep Frontend Rewire (Sub-project B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewire the Full Sweep panel in `cmd/server/wwwroot/index.html` to poll Sub-project A's server-side sweep API instead of running the old client-side orchestration loop, and expand it into a multi-sweep list view.

**Architecture:** A single 3s poller (`pollVexSweeps`) replaces the old `_vexSweepQueue`/`_vexSweepPollAndNext` chain, calling `GET /api/vex/sweeps?status=running` and re-rendering a card per active sweep from scratch each tick. Each card fires one more request (`GET /api/variants/run/{currentVariantRunId}`, pre-existing endpoint) for the innermost "current variant" detail. Completion is detected by diffing sweep IDs between ticks. This is a single-file, plain-JS change — no build step, no framework, no automated test harness in this codebase.

**Tech Stack:** Vanilla JS (ES5-style, matching the rest of this file), plain HTML, existing `apicall()`/`showToast()`/`x()` helpers already used throughout `index.html`.

## Global Constraints

- No backend changes — every endpoint this plan calls already exists and is tested (Sub-project A, merged to `main`).
- No changes to the ad-hoc single-variant-run flow (`_vexActivePoll`, `_vexAbortRequested`, `_vexActiveScenarioRunId`, the plain `stopVex()`) — those stay exactly as they are, genuinely shared with code this plan doesn't touch.
- No WebSocket push — polling only, 3s cadence (matches the old sweep poll's cadence).
- `variant.Result`'s real JSON field names (confirmed against `internal/variant/types.go`): `verdict`, `encoding`, `execContext`, `evasion` — used exactly as-is, no renaming.
- No automated tests exist for this file in this codebase — every step's verification is a manual read-through / grep-based sanity check, not a test run. Full manual browser QA is Task 3's own step and is expected to be deferred, matching this session's established pattern for UI-only work.

---

### Task 1: HTML — list container, agent-conflict hint, select onchange

**Files:**
- Modify: `orchestrator/cmd/server/wwwroot/index.html:3266` (add `onchange` to `#vex-sweep-agent`)
- Modify: `orchestrator/cmd/server/wwwroot/index.html:3279-3291` (replace the static progress block with an empty list container + hint span)

**Interfaces:**
- Produces: `<div id="vex-sweep-list">` (consumed by Task 2's `renderVexSweepList`), `<span id="vex-sweep-agent-hint">` (consumed by Task 2's `_vexCheckAgentSweepConflict`), `#vex-sweep-agent`'s `onchange="_vexCheckAgentSweepConflict()"` attribute (calls a Task 2 function).

- [ ] **Step 1: Add the agent-select onchange and hint span**

In `orchestrator/cmd/server/wwwroot/index.html`, find (line 3266):

```html
              <select id="vex-sweep-agent" class="btn btn-outline" style="font-size:0.8rem;min-width:140px">
                <option value="">Select agent…</option>
              </select>
```

Replace with:

```html
              <select id="vex-sweep-agent" class="btn btn-outline" style="font-size:0.8rem;min-width:140px" onchange="_vexCheckAgentSweepConflict()">
                <option value="">Select agent…</option>
              </select>
              <span id="vex-sweep-agent-hint" class="tiny" style="color:var(--warning)"></span>
```

- [ ] **Step 2: Replace the static progress block with the list container**

Find (lines 3279-3291):

```html
          <div id="vex-sweep-progress" style="display:none;margin-top:0.75rem;border-top:1px solid var(--border);padding-top:0.75rem">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.35rem;font-size:0.78rem">
              <span id="vex-sweep-status" style="color:var(--muted)"></span>
              <span style="display:flex;align-items:center;gap:0.6rem">
                <span id="vex-sweep-pct" style="font-weight:700;color:var(--accent)"></span>
                <button id="vex-sweep-stop-btn" class="btn btn-outline btn-sm" style="display:none;color:var(--danger);border-color:var(--danger);padding:2px 8px;font-size:0.7rem" onclick="stopVex()">&#9632; Stop</button>
              </span>
            </div>
            <div style="height:5px;background:var(--border);border-radius:3px;overflow:hidden">
              <div id="vex-sweep-bar" style="height:5px;background:var(--accent);border-radius:3px;width:0%;transition:width 0.5s ease"></div>
            </div>
            <div id="vex-sweep-timing" class="tiny muted" style="margin-top:0.4rem"></div>
          </div>
```

Replace with:

```html
          <div id="vex-sweep-list" style="margin-top:0.75rem"></div>
```

- [ ] **Step 3: Sanity-check the HTML**

Run: `grep -n "vex-sweep-progress\|vex-sweep-status\|vex-sweep-pct\|vex-sweep-bar\|vex-sweep-timing\|vex-sweep-stop-btn" orchestrator/cmd/server/wwwroot/index.html`

Expected: no matches in the HTML markup (these IDs are gone from the `<div>` structure). Note this grep will still find references inside the OLD JavaScript functions (`_vexSweepQueue`, `_vexSweepPollAndNext`, `vexRunFullSweep`, `stopVex`) — that's expected and fine, those get removed/rewritten in Task 2.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(vex-sweep-ui): replace static progress block with multi-sweep list container"
git push
```

---

### Task 2: JS — poller, per-sweep cards, start/stop, agent-conflict hint

**Files:**
- Modify: `orchestrator/cmd/server/wwwroot/index.html:13772-14001` (remove `_vexSweepRunning`/`_vexSweepStartedAt` var declarations and the `vexRunFullSweep`/`_vexSweepQueue`/`_vexSweepPollAndNext` functions; add the new poller/render/stop functions in their place)
- Modify: `orchestrator/cmd/server/wwwroot/index.html:13773-13778` (`loadVariantTab()` — add `startVexSweepPolling()` call)

**Interfaces:**
- Consumes: `apicall(url, opts)`, `showToast(msg, kind)`, `x(str)` (existing helpers, used throughout this file — no new signature, just reused); `_vexAllTechniques`, `_vexAvailableVariants` (existing module vars, read-only, used only for the pre-flight confirm-dialog estimate); `loadVariantStats()`, `loadVariantCoverage()` (existing functions, called on sweep completion, unchanged).
- Produces: `startVexSweepPolling()`, `pollVexSweeps()`, `reportVexSweepFinished(sweepId)`, `renderVexSweepList(sweeps)`, `loadVexSweepVariantDetail(sweepId, variantRunId)`, `vexRunFullSweep()` (rewritten), `stopVexSweep(sweepId)`, `_vexCheckAgentSweepConflict()` — `vexRunFullSweep`'s `onclick` reference already exists in the HTML (`index.html:3276`, unchanged by Task 1), `stopVexSweep`/`_vexCheckAgentSweepConflict` are called from HTML generated by `renderVexSweepList`/from Task 1's `onchange` attribute respectively.

- [ ] **Step 1: Remove the two obsolete module-level vars**

Find (lines 13872-13873):

```javascript
var _vexSweepRunning = false;
var _vexSweepStartedAt = null; // Date the current/last sweep started, or null if none run yet this session
```

Delete both lines entirely. `_vexFormatDuration` and `_vexRenderSweepTiming` (the functions immediately below them) stay untouched — they're generic formatting utilities, not removed by this plan even though nothing calls them from the sweep path anymore (a reasonable, small follow-up if per-card elapsed-time display is wanted later, out of scope here per the design spec's Non-Goals).

- [ ] **Step 2: Replace `vexRunFullSweep`, `_vexSweepQueue`, and `_vexSweepPollAndNext`**

Find the three functions (originally lines 13902-14001, now shifted up by 2 lines after Step 1's deletion — locate by function name, not line number):

```javascript
function vexRunFullSweep() {
  if (_vexSweepRunning) { showToast('Sweep already in progress', 'err'); return; }
  var agentId = (document.getElementById('vex-sweep-agent') || {}).value || '';
  if (!agentId) { showToast('Select an agent in the Full Sweep panel first', 'err'); return; }
  if (!_vexAllTechniques.length) { showToast('Technique list still loading — wait a moment', 'err'); return; }
  var n = _vexAllTechniques.length;
  var mode = (document.getElementById('vex-sweep-mode') || {}).value || 'sequential';
  var advanced = document.getElementById('vex-sweep-advanced') ? document.getElementById('vex-sweep-advanced').checked : false;
  // Quote the same real, server-computed total shown in the "Total Variants"
  // stat card (loadVariantStats) rather than a separate rough estimate — the
  // two used to disagree (e.g. ~10k here vs ~27k above) because this dialog
  // computed its own guess independently of the actual variant count.
  var variantTotal = _vexAvailableVariants || (n * 33);
  if (!confirm('Start Full Variant Sweep:\n\n  ' + n + ' techniques dispatched sequentially\n  ~' + variantTotal.toLocaleString() + '+ individual variants\n\nThis runs each technique to completion before the next. Depending on your endpoint it may take hours.\n\nContinue?')) return;

  var techniques = _vexAllTechniques.map(function(t) { return t.id; });
  _vexAbortRequested = false; _vexActiveScenarioRunId = null;
  _vexSweepRunning = true;
  _vexSweepStartedAt = new Date();
  var btn = document.getElementById('vex-sweep-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Sweeping…'; }
  var prog = document.getElementById('vex-sweep-progress');
  if (prog) prog.style.display = 'block';
  var stopBtn = document.getElementById('vex-sweep-stop-btn');
  if (stopBtn) stopBtn.style.display = '';
  _vexRenderSweepTiming(null);
  _vexSweepQueue(agentId, techniques, mode, advanced, 0);
}

function _vexSweepQueue(agentId, techniques, mode, advanced, idx) {
  var n = techniques.length;
  var btn = document.getElementById('vex-sweep-btn');
  var statusEl = document.getElementById('vex-sweep-status');
  var pctEl = document.getElementById('vex-sweep-pct');
  var barEl = document.getElementById('vex-sweep-bar');

  if (_vexAbortRequested || idx >= n) {
    _vexSweepRunning = false;
    if (btn) { btn.disabled = false; btn.textContent = '▶ Start Sweep'; }
    var stopBtnEl = document.getElementById('vex-sweep-stop-btn');
    if (stopBtnEl) stopBtnEl.style.display = 'none';
    // Progress panel stays visible (not hidden) after a sweep ends, so the
    // start/end timestamps remain on screen until the next sweep begins —
    // previously this block hid the whole panel immediately, discarding any
    // record of when the sweep ran the moment the toast faded.
    if (_vexAbortRequested) {
      if (statusEl) statusEl.textContent = 'Sweep stopped';
      _vexRenderSweepTiming('Stopped');
      showToast('Sweep stopped', 'warn');
    } else {
      if (statusEl) statusEl.textContent = 'Sweep complete — ' + n + ' techniques tested';
      if (pctEl) pctEl.textContent = '100%';
      if (barEl) barEl.style.width = '100%';
      _vexRenderSweepTiming('Completed');
      showToast('Full sweep complete — ' + n + ' techniques', 'ok');
      loadVariantStats();
      loadVariantCoverage();
    }
    return;
  }

  var pct = Math.round((idx / n) * 100);
  var tid = techniques[idx];
  if (statusEl) statusEl.textContent = 'Running ' + x(tid) + ' (' + (idx + 1) + ' / ' + n + ')';
  if (pctEl) pctEl.textContent = pct + '%';
  if (barEl) barEl.style.width = pct + '%';
  if (btn) btn.textContent = (idx + 1) + '/' + n + ' Sweeping…';
  _vexRenderSweepTiming(null);

  apicall('/api/variants/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId: agentId, techniqueId: tid, executionMode: mode, includeAdvanced: advanced })
  }).then(function(resp) {
    _vexActiveScenarioRunId = resp.scenarioRunId;
    // Poll until this technique's variant run completes, then continue.
    _vexSweepPollAndNext(resp.variantRunId, agentId, techniques, mode, advanced, idx);
  }).catch(function(e) {
    // Dispatch failed — log and continue to next technique.
    if (statusEl) statusEl.textContent = 'Error on ' + x(tid) + ': ' + (e.message || 'failed') + ' — continuing…';
    setTimeout(function() { _vexSweepQueue(agentId, techniques, mode, advanced, idx + 1); }, 1500);
  });
}

function _vexSweepPollAndNext(vrId, agentId, techniques, mode, advanced, idx) {
  if (_vexActivePoll) clearInterval(_vexActivePoll);
  _vexActivePoll = setInterval(function() {
    if (_vexAbortRequested) { clearInterval(_vexActivePoll); _vexActivePoll = null; return; }
    apicall('/api/variants/run/' + vrId).then(function(detail) {
      var s = detail.run && detail.run.status;
      if (s === 'completed' || s === 'failed' || s === 'partial') {
        clearInterval(_vexActivePoll); _vexActivePoll = null;
        _vexSweepQueue(agentId, techniques, mode, advanced, idx + 1);
      }
    }).catch(function() {
      clearInterval(_vexActivePoll); _vexActivePoll = null;
      _vexSweepQueue(agentId, techniques, mode, advanced, idx + 1);
    });
  }, 3000);
}
```

Replace all three functions (the entire span from `function vexRunFullSweep() {` through the closing `}` of `_vexSweepPollAndNext`) with:

```javascript
var _vexSweepPollTimer = null;
var _vexKnownRunningSweepIds = []; // sweep IDs seen in the previous tick, for completion-diffing

// startVexSweepPolling begins the 3s poll loop against the server-owned
// sweep API. Idempotent -- safe to call more than once (e.g. if
// loadVariantTab() runs again after a tab re-visit).
function startVexSweepPolling() {
  if (_vexSweepPollTimer) return;
  pollVexSweeps();
  _vexSweepPollTimer = setInterval(pollVexSweeps, 3000);
}

function pollVexSweeps() {
  apicall('/api/vex/sweeps?status=running').then(function(sweeps) {
    sweeps = sweeps || [];
    var currentIds = sweeps.map(function(s) { return s.id; });

    // Completion detection: any previously-tracked ID missing from this
    // tick's list just finished (completed/stopped/failed) -- fetch its
    // final state once for the toast, since the running-list endpoint no
    // longer includes it.
    _vexKnownRunningSweepIds.forEach(function(id) {
      if (currentIds.indexOf(id) === -1) reportVexSweepFinished(id);
    });
    _vexKnownRunningSweepIds = currentIds;

    renderVexSweepList(sweeps);
  }).catch(function() {});
}

function reportVexSweepFinished(sweepId) {
  apicall('/api/vex/sweeps/' + sweepId).then(function(sw) {
    if (sw.status === 'completed') {
      showToast('Full sweep complete — ' + sw.totalTechniques + ' techniques (' + sw.agentId + ')', 'ok');
      loadVariantStats();
      loadVariantCoverage();
    } else if (sw.status === 'stopped') {
      showToast('Sweep stopped (' + sw.agentId + ')', 'warn');
    } else if (sw.status === 'failed') {
      showToast('Sweep failed on ' + sw.agentId + ': ' + (sw.error || 'unknown error'), 'err');
    }
  }).catch(function() {});
}

function renderVexSweepList(sweeps) {
  var el = document.getElementById('vex-sweep-list');
  if (!el) return;
  if (!sweeps.length) { el.innerHTML = ''; return; }

  el.innerHTML = sweeps.map(function(sw) {
    var pct = sw.totalVariants > 0 ? Math.round((sw.completedVariants / sw.totalVariants) * 100) : 0;
    return '<div class="card" style="margin-top:0.5rem;padding:0.75rem 1rem" id="vex-sweep-card-' + x(sw.id) + '">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;font-size:0.78rem;margin-bottom:0.3rem">' +
        '<span style="font-weight:600">' + x(sw.agentId) + '</span>' +
        '<span style="display:flex;align-items:center;gap:0.6rem">' +
          '<span style="font-weight:700;color:var(--accent)">' + pct + '%</span>' +
          '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger);padding:2px 8px;font-size:0.7rem" onclick="stopVexSweep(\'' + x(sw.id) + '\')">&#9632; Stop</button>' +
        '</span>' +
      '</div>' +
      '<div style="height:5px;background:var(--border);border-radius:3px;overflow:hidden">' +
        '<div style="height:5px;background:var(--accent);border-radius:3px;width:' + pct + '%;transition:width 0.5s ease"></div>' +
      '</div>' +
      '<div class="tiny muted" style="margin-top:0.35rem">Technique ' + (sw.currentIndex + 1) + '/' + sw.totalTechniques + ': ' + x(sw.currentTechnique) + '</div>' +
      '<div class="tiny muted" id="vex-sweep-variant-' + x(sw.id) + '">Loading current variant…</div>' +
    '</div>';
  }).join('');

  sweeps.forEach(function(sw) {
    if (sw.currentVariantRunId) loadVexSweepVariantDetail(sw.id, sw.currentVariantRunId);
  });
}

// loadVexSweepVariantDetail fetches the current technique's own variant
// run (the same endpoint the ad-hoc single-run view already polls) purely
// to derive "variant N/M: <what's running>" -- the sweep-list endpoint
// itself only tracks per-technique progress, not per-variant.
function loadVexSweepVariantDetail(sweepId, variantRunId) {
  apicall('/api/variants/run/' + variantRunId).then(function(detail) {
    var el = document.getElementById('vex-sweep-variant-' + sweepId);
    if (!el) return; // card was removed by a later tick before this resolved
    var results = detail.results || [];
    var doneCount = results.filter(function(r) { return r.verdict !== 'PENDING'; }).length;
    var current = results[doneCount]; // next un-run entry, in dispatch order
    if (current) {
      el.textContent = 'Variant ' + (doneCount + 1) + '/' + results.length + ': ' +
        current.encoding + ' / ' + current.execContext + ' / ' + current.evasion;
    } else {
      el.textContent = 'Variant ' + results.length + '/' + results.length + ' — finishing…';
    }
  }).catch(function() {});
}

function vexRunFullSweep() {
  var agentId = (document.getElementById('vex-sweep-agent') || {}).value || '';
  if (!agentId) { showToast('Select an agent in the Full Sweep panel first', 'err'); return; }
  var mode = (document.getElementById('vex-sweep-mode') || {}).value || 'sequential';
  var advanced = document.getElementById('vex-sweep-advanced') ? document.getElementById('vex-sweep-advanced').checked : false;
  // n/variantTotal are a pre-flight estimate only (from the ad-hoc picker's
  // already-loaded technique list) -- the server independently and
  // authoritatively resolves the real technique list and count at creation
  // time; that's what actually gets dispatched.
  var n = _vexAllTechniques.length;
  var variantTotal = _vexAvailableVariants || (n * 33);
  if (!confirm('Start Full Variant Sweep:\n\n  ~' + n + ' techniques dispatched sequentially\n  ~' + variantTotal.toLocaleString() + '+ individual variants\n\nThis runs each technique to completion before the next. Depending on your endpoint it may take hours.\n\nContinue?')) return;

  apicall('/api/vex/sweeps', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId: agentId, mode: mode, includeAdvanced: advanced })
  }).then(function() {
    pollVexSweeps(); // render the new sweep immediately instead of waiting up to 3s for the next tick
  }).catch(function(e) {
    showToast(e.message || 'Failed to start sweep', 'err');
  });
}

function stopVexSweep(sweepId) {
  if (!confirm('Stop this sweep? The current technique finishes or is cancelled; no further techniques will be dispatched.')) return;
  apicall('/api/vex/sweeps/' + sweepId + '/cancel', { method: 'POST' })
    .then(function() { pollVexSweeps(); })
    .catch(function(e) { showToast(e.message || 'Failed to stop sweep', 'err'); });
}

function _vexCheckAgentSweepConflict() {
  var agentId = (document.getElementById('vex-sweep-agent') || {}).value || '';
  var hint = document.getElementById('vex-sweep-agent-hint');
  if (!hint) return;
  if (!agentId) { hint.textContent = ''; return; }
  apicall('/api/vex/sweeps/active?agentId=' + encodeURIComponent(agentId)).then(function() {
    hint.textContent = 'This agent already has a sweep running.';
  }).catch(function() {
    hint.textContent = ''; // 404 (no active sweep) is the expected non-error case here
  });
}
```

- [ ] **Step 3: Wire `startVexSweepPolling()` into `loadVariantTab()`**

Find (`index.html:13773-13778` — this line number is from *before* Steps 1-2's edits and `loadVariantTab` sits earlier in the file than the deleted/replaced code, so it's unaffected by those line shifts; re-locate by content if line numbers have drifted):

```javascript
function loadVariantTab() {
  loadVariantStats();
  loadVariantCoverage();
  populateVexAgents();
  populateVexTechniques();
}
```

Replace with:

```javascript
function loadVariantTab() {
  loadVariantStats();
  loadVariantCoverage();
  populateVexAgents();
  populateVexTechniques();
  startVexSweepPolling();
}
```

- [ ] **Step 4: Sanity-check for leftover references to removed identifiers**

Run: `grep -n "_vexSweepRunning\|_vexSweepStartedAt\|_vexSweepQueue\|_vexSweepPollAndNext\|_vexRenderSweepTiming" orchestrator/cmd/server/wwwroot/index.html`

Expected: no matches anywhere in the file. If any remain, find and remove them before continuing.

**Real gap found during implementation, not anticipated by this plan:** `stopVex()` (the function this plan's Step 2 preamble described as "genuinely shared with the unrelated ad-hoc single-run flow... stays exactly as it is") turned out to have real sweep-specific branches baked in from the old architecture — `var wasSweeping = _vexSweepRunning`, resetting `vex-sweep-btn`/`vex-sweep-stop-btn`, and an `if (wasSweeping) {...}` block referencing `vex-sweep-status`/`vex-sweep-progress` (both removed by Task 1's HTML change) and `_vexRenderSweepTiming`. Since the sweep's Stop button now calls the fully independent `stopVexSweep(sweepId)` and never `stopVex()` at all, none of that sweep branching is reachable anymore — but it was still there, referencing deleted identifiers. Fix: strip `stopVex()` back to pure ad-hoc-run cancellation logic (remove `wasSweeping`, the `vex-sweep-btn`/`vex-sweep-stop-btn` resets, and the entire `if (wasSweeping)` block and its trailing `vex-sweep-progress` hide-call), update its comment to describe the new, fully-separated reality.

Separately, `_vexRenderSweepTiming` (defined a few functions above the ones this step replaces) had zero remaining callers after this rewrite and still referenced the deleted `_vexSweepStartedAt` twice — dead *and* broken, not just unused as originally assumed. Removed entirely. `_vexFormatDuration` (a correct, generic millisecond formatter with no dependency on the deleted variable) stays, unused for now — a reasonable small follow-up if per-card elapsed-time display is wanted later.

- [ ] **Step 5: Sanity-check every new function is defined exactly once and every referenced ID exists**

Run: `grep -n "function pollVexSweeps\|function renderVexSweepList\|function reportVexSweepFinished\|function loadVexSweepVariantDetail\|function stopVexSweep\|function _vexCheckAgentSweepConflict\|function startVexSweepPolling\|function vexRunFullSweep" orchestrator/cmd/server/wwwroot/index.html`

Expected: exactly one match per function name. Then run: `grep -n 'id="vex-sweep-list"\|id="vex-sweep-agent-hint"' orchestrator/cmd/server/wwwroot/index.html` — expected: one match each (from Task 1's HTML), confirming the IDs Task 2's JS reads/writes actually exist in the markup.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(vex-sweep-ui): poll server-owned sweep API instead of client-side orchestration loop"
git push
```

---

### Task 3: Manual QA and finishing

**Files:** none (verification only)

- [ ] **Step 1: Start the local server and open the Variant Execution Suite tab**

Confirm `orchestrator.exe` (or `go run ./cmd/server`) is running against a real Postgres instance with at least one connected agent, then open the app in a browser and navigate to the tab containing the Full Sweep card.

- [ ] **Step 2: Manual verification checklist**

Walk through each item, matching the design spec's Testing section exactly:

- Start a sweep on one agent — confirm a card appears within ~3s showing the agent name, an overall percentage, a technique line, and a variant line that updates as variants complete (not stuck at "Loading current variant…").
- Reload the page mid-sweep — confirm the card reappears with the sweep's real current progress (not reset to 0%, not gone).
- Start a second sweep on a *different* agent — confirm two independent cards render simultaneously, each progressing on its own.
- Select an agent in the Start form that already has a running sweep — confirm the "This agent already has a sweep running." hint appears next to the dropdown.
- Click a card's Stop button, confirm the browser's confirm dialog appears, confirm — the card disappears and a "Sweep stopped" toast fires within the next poll tick.
- Let a sweep run to completion (or use a very small/fast technique set if available) — confirm a "Full sweep complete — N techniques (agentId)" toast fires, the card disappears, and the Total Variants / coverage stats on the page refresh.

- [ ] **Step 3: Report results**

If every item in Step 2 passes, report Sub-project B complete. If any item fails, treat it as a real bug — return to Task 2 and fix it following the systematic-debugging process (root cause first, not a quick patch) before considering this plan done. This sub-project executes directly on `main` (matching this session's established inline-execution convention) — no branch/worktree/PR decision needed.
