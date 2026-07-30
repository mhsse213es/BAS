# Full Variant Sweep — Frontend Rewire (Sub-project B) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-30.
**Depends on:** Sub-project A (`docs/superpowers/specs/2026-07-30-vex-full-sweep-server-orchestration-design.md`), DONE and pushed to `main` — `POST /api/vex/sweeps`, `GET /api/vex/sweeps/active?agentId=X`, `GET /api/vex/sweeps/{id}`, `GET /api/vex/sweeps?status=running`, `POST /api/vex/sweeps/{id}/cancel` are all live. Also depends on the existing `GET /api/variants/run/{id}` endpoint (pre-existing, unchanged), which supplies per-variant detail for the innermost progress level.

## Problem

The Full Sweep panel in `cmd/server/wwwroot/index.html` (`vexRunFullSweep()`/`_vexSweepQueue()`/`_vexSweepPollAndNext()`) still runs the pre-Sub-project-A client-side orchestration loop — Sub-project A built the server-side replacement but deliberately shipped zero frontend changes. The panel needs to be rewired to the new API, and to actually deliver the three things that motivated this whole effort: a reload/crash-resilient UI, a smooth variant-based progress bar instead of one that sits at 0% for an entire technique, and a Stop button that always works.

Mid-brainstorm the scope grew: the backend now allows multiple sweeps running concurrently across different agents (Sub-project A's per-agent conflict model), and the user chose to build real UI for that — a list of active sweeps, not a single static panel — rather than deferring it.

## Non-Goals

- **No WebSocket push.** Progress comes from polling `GET /api/vex/sweeps?status=running` every 3s (matching the old sweep poll's cadence) plus one `GET /api/variants/run/{currentVariantRunId}` per visible card per tick — both are plain HTTP polls, no new WS message types.
- **No changes to the ad-hoc single-variant-run flow** (`vex-agent`/`vex-technique-list`/`renderVariantRun`/the plain `stopVex()` for a lone run). `_vexActivePoll`, `_vexAbortRequested`, and `_vexActiveScenarioRunId` stay exactly as they are today — they're genuinely shared with that unrelated flow, which this sub-project doesn't touch.
- **No backend changes.** Every endpoint this sub-project calls already exists and is already tested (Sub-project A). This is a pure `cmd/server/wwwroot/index.html` rewrite.
- **No sweep history/audit view.** Only currently-running sweeps are shown; a completed/stopped/failed sweep gets a one-time toast at the moment its card disappears, not a persistent history list. (`vex_sweeps` rows for finished sweeps remain queryable via the API for a future history feature — out of scope here.)
- **No inline start-time technique/variant preview list.** The old confirm() dialog quoted an estimated technique/variant count from `_vexAllTechniques`/`_vexAvailableVariants` (client-side data, loaded for the unrelated ad-hoc picker) — this stays as a rough pre-flight estimate only; the server independently and authoritatively resolves the real technique list and count at creation time, and that's what actually gets dispatched.

## Architecture

### 1. HTML — replace the single progress block with a list container

In the `#vex-sweep-card` block (`index.html:3256-3292`), the existing `<div id="vex-sweep-progress">...</div>` (lines 3279-3291, with its `vex-sweep-status`/`vex-sweep-pct`/`vex-sweep-stop-btn`/`vex-sweep-bar`/`vex-sweep-timing` children) is replaced by an empty container the JS renders into:

```html
<div id="vex-sweep-list" style="margin-top:0.75rem"></div>
```

Each running sweep gets one card, built entirely in JS (template literal), reusing the existing `.card`/`.prog`/`btn-outline-red` styling already used elsewhere in this file rather than inventing new CSS classes. A card shows: agent name, overall progress bar + percentage, current technique, current variant line, and its own Stop button.

The `vex-sweep-agent` `<select>` (line 3266) gains an `onchange="_vexCheckAgentSweepConflict()"` attribute.

### 2. JS — the poller replaces the old queue

```javascript
var _vexSweepPollTimer = null;
var _vexKnownRunningSweepIds = []; // sweep IDs seen in the previous tick, for completion-diffing

function startVexSweepPolling() {
  if (_vexSweepPollTimer) return; // idempotent -- safe to call from multiple init paths
  pollVexSweeps();
  _vexSweepPollTimer = setInterval(pollVexSweeps, 3000);
}

function pollVexSweeps() {
  apicall('/api/vex/sweeps?status=running').then(function(sweeps) {
    sweeps = sweeps || [];
    var currentIds = sweeps.map(function(s) { return s.id; });

    // Completion detection: any previously-tracked ID missing from this
    // tick's list just finished (completed/stopped/failed) -- fetch its
    // final state once for the toast, since the list endpoint no longer
    // includes it.
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

A small `<span id="vex-sweep-agent-hint" class="tiny" style="color:var(--warning)"></span>` is added next to the agent `<select>` for `_vexCheckAgentSweepConflict`'s message.

`startVexSweepPolling()` is called once from `loadVariantTab()` (`index.html:13773-13778`), the existing function that already calls `populateVexAgents()`/`populateVexTechniques()` when the Variant Execution Suite tab is initialized — confirmed by reading the real function, not guessed.

### 3. Removed entirely

`_vexSweepQueue`, `_vexSweepPollAndNext`, `_vexSweepRunning`, `_vexSweepStartedAt`, `_vexRenderSweepTiming`'s sweep-specific call sites (the function itself is generic and stays, but nothing calls it from the sweep path anymore since per-card timing isn't part of this design — `_vexFormatDuration`/`_vexRenderSweepTiming` remain defined but this sub-project doesn't wire elapsed-time display into the new cards; adding it is a small, obvious follow-up if wanted, not included here to keep the card layout matched to what was actually approved above).

## Testing

No automated frontend test harness exists in this codebase (confirmed — every prior Global Search phase and Run Workspace sub-project this session hit the same fact). Manual QA, deferred per this session's established pattern: start a sweep, reload mid-run and confirm the card reappears with correct progress (not reset to 0%); start two sweeps on two different agents and confirm both cards render independently; stop a sweep from its card and confirm the row disappears and the toast fires; let a sweep run to completion and confirm the completion toast and stats refresh; confirm the agent-conflict hint appears when selecting an agent that already has a running sweep.
