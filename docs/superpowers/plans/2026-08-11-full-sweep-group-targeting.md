# Full Variant Sweep: Agent Group Targeting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the Full Sweep card launch one independent sweep per agent in one-or-many selected Agent Groups, instead of only a single agent at a time.

**Architecture:** A Target Mode radio (Individual / Agent Group(s)) in the existing `#vex-sweep-card`. Group(s) mode reuses the group-resolution helpers already built for the Run Scenario wizard (`gpFlattenGroups`, `resolveGroupTargetAgents`) with no OS filtering (Full Sweep has no scenario/supportedOs concept). Dispatch fans out `Promise.all` over the existing `POST /api/vex/sweeps` endpoint, one call per resolved agent — no backend changes, no new entity, each launched sweep is exactly as independent and self-contained as it is today.

**Tech Stack:** Vanilla JS in `orchestrator/wwwroot/index.html`, no framework, no JS test runner — verification is `node --check` plus a standalone Node harness for the pure dispatch-summary logic, plus manual browser QA, per established project convention.

## Global Constraints

- No backend changes. `POST /api/vex/sweeps` keeps its existing `{agentId, mode, includeAdvanced}` shape, called once per resolved agent.
- No "All Agents" target mode — Individual and Agent Group(s) only.
- No hard cap on the number of agents one launch can target — a blast-radius confirm is the only gate.
- Group-resolved agents are NOT filtered by OS eligibility (`osEligibleAgents`, index.html:10440, is scenario-`supportedOs`-specific and does not apply here) — every resolved agent is targeted; an incompatible or offline agent simply fails its own dispatch, reported in the summary toast like any other failure.
- The existing `_vexCheckAgentSweepConflict()` live-hint stays wired to the single-agent `<select>` only and is not modified — it does not run in Group(s) mode.
- The existing sweep progress list (`#vex-sweep-list`/`renderVexSweepList`/`pollVexSweeps`) is not modified — it already renders any number of concurrent sweeps.
- Syntax verification for every task:
  ```bash
  awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
  ```
  Run from the repo root (`C:\Users\Administrator\Downloads\Audspect_Cloud`).

---

## Task A: Target Mode HTML in the Full Sweep card

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (`#vex-sweep-card` markup, currently lines 3538-3565)

**Interfaces:**
- Produces: `#vex-sweep-individual-wrap` (wraps the existing agent `<select>` + hint span, unchanged IDs inside), `#vex-sweep-group-wrap` (new, hidden by default), `#vex-sweep-group-list`, `#vex-sweep-group-summary` — all consumed by Task B.

- [ ] **Step 1: Replace the card's control row**

Find (exact, confirmed):
```html
        <!-- Full Sweep banner -->
        <div class="card" id="vex-sweep-card" style="margin-bottom:1rem;padding:1rem 1.2rem">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.75rem">
            <div>
              <div style="font-weight:700;font-size:0.9rem;margin-bottom:0.25rem;display:flex;align-items:center;gap:0.5rem">
                <svg viewBox="0 0 20 20" fill="none" stroke="var(--accent)" stroke-width="1.6" style="width:16px;height:16px;flex-shrink:0"><path d="M3 10a7 7 0 1 1 14 0A7 7 0 0 1 3 10z"/><path d="m10 7 3 3-3 3M7 10h6"/></svg>
                Full Variant Sweep
              </div>
              <div class="tiny muted">Run all <strong id="vex-sweep-tech-count" style="color:var(--text)">—</strong> ART techniques sequentially · <span id="vex-sweep-total-variants" style="color:var(--text)">—</span> total variants · <span class="tiny muted">runs technique-by-technique; you can see live progress</span></div>
            </div>
            <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap">
              <select id="vex-sweep-agent" class="btn btn-outline" style="font-size:0.8rem;min-width:140px" onchange="_vexCheckAgentSweepConflict()">
                <option value="">Select agent…</option>
              </select>
              <span id="vex-sweep-agent-hint" class="tiny" style="color:var(--warning)"></span>
              <select id="vex-sweep-mode" class="btn btn-outline" style="font-size:0.8rem">
                <option value="sequential">All variants</option>
                <option value="adaptive">Adaptive (stop on bypass)</option>
              </select>
              <label style="display:flex;align-items:center;gap:0.35rem;font-size:0.78rem;color:var(--muted);cursor:pointer;white-space:nowrap">
                <input type="checkbox" id="vex-sweep-advanced" style="accent-color:var(--accent)"> Advanced Pack
              </label>
              <button id="vex-sweep-btn" class="btn btn-primary" onclick="vexRunFullSweep()" style="white-space:nowrap">▶ Start Sweep</button>
            </div>
          </div>
          <div id="vex-sweep-list" style="margin-top:0.75rem"></div>
        </div>
```

Replace with:
```html
        <!-- Full Sweep banner -->
        <div class="card" id="vex-sweep-card" style="margin-bottom:1rem;padding:1rem 1.2rem">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.75rem">
            <div>
              <div style="font-weight:700;font-size:0.9rem;margin-bottom:0.25rem;display:flex;align-items:center;gap:0.5rem">
                <svg viewBox="0 0 20 20" fill="none" stroke="var(--accent)" stroke-width="1.6" style="width:16px;height:16px;flex-shrink:0"><path d="M3 10a7 7 0 1 1 14 0A7 7 0 0 1 3 10z"/><path d="m10 7 3 3-3 3M7 10h6"/></svg>
                Full Variant Sweep
              </div>
              <div class="tiny muted">Run all <strong id="vex-sweep-tech-count" style="color:var(--text)">—</strong> ART techniques sequentially · <span id="vex-sweep-total-variants" style="color:var(--text)">—</span> total variants · <span class="tiny muted">runs technique-by-technique; you can see live progress</span></div>
            </div>
            <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap">
              <div style="display:flex;gap:0.6rem;margin-right:0.4rem">
                <label style="display:flex;align-items:center;gap:0.3rem;cursor:pointer;font-size:0.78rem;color:var(--muted);white-space:nowrap">
                  <input type="radio" name="vex-target-mode" value="individual" checked onchange="setVexTargetMode('individual')"> Individual
                </label>
                <label style="display:flex;align-items:center;gap:0.3rem;cursor:pointer;font-size:0.78rem;color:var(--muted);white-space:nowrap">
                  <input type="radio" name="vex-target-mode" value="group" onchange="setVexTargetMode('group')"> Group(s)
                </label>
              </div>
              <div id="vex-sweep-individual-wrap" style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap">
                <select id="vex-sweep-agent" class="btn btn-outline" style="font-size:0.8rem;min-width:140px" onchange="_vexCheckAgentSweepConflict()">
                  <option value="">Select agent…</option>
                </select>
                <span id="vex-sweep-agent-hint" class="tiny" style="color:var(--warning)"></span>
              </div>
              <select id="vex-sweep-mode" class="btn btn-outline" style="font-size:0.8rem">
                <option value="sequential">All variants</option>
                <option value="adaptive">Adaptive (stop on bypass)</option>
              </select>
              <label style="display:flex;align-items:center;gap:0.35rem;font-size:0.78rem;color:var(--muted);cursor:pointer;white-space:nowrap">
                <input type="checkbox" id="vex-sweep-advanced" style="accent-color:var(--accent)"> Advanced Pack
              </label>
              <button id="vex-sweep-btn" class="btn btn-primary" onclick="vexRunFullSweep()" style="white-space:nowrap">▶ Start Sweep</button>
            </div>
          </div>
          <div id="vex-sweep-group-wrap" style="display:none;margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border)">
            <div id="vex-sweep-group-list" style="max-height:160px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius);padding:0.4rem"></div>
            <p class="tiny muted" id="vex-sweep-group-summary" style="margin-top:0.4rem"></p>
          </div>
          <div id="vex-sweep-list" style="margin-top:0.75rem"></div>
        </div>
```

Note: `<select id="vex-sweep-agent">` and `<span id="vex-sweep-agent-hint">` keep their exact same IDs, just wrapped in the new `#vex-sweep-individual-wrap` div — every other place in the file that looks them up by ID (e.g. `loadCatalogs()` populating the agent dropdown's options) is unaffected.

- [ ] **Step 2: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0 (this step only changed HTML, so the script block itself is untouched, but confirms the overall file still parses cleanly — the `<script>` extraction is unaffected by markup elsewhere).

- [ ] **Step 3: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(full-sweep): add Target Mode radio to the Full Sweep card"
```

---

## Task B: Group selection state, list rendering, and resolution

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (new globals + functions, placed near `vexRunFullSweep()`, currently ~line 16414)

**Interfaces:**
- Consumes: `gpFlattenGroups`, `resolveGroupTargetAgents` (both pre-existing, index.html:6698/6734), global `agentGroupTree`, `x()` (HTML-escape helper), elements from Task A.
- Produces (used by Task C): global `_vexTargetMode` (`'individual' | 'group'`, default `'individual'`), global `_vexGroupSel` (`{[groupId]: true}`), `setVexTargetMode(mode)`, `vexResolvedGroupAgents()` → array of agent objects, `renderVexGroupSummary()`.

- [ ] **Step 1: Add the globals and functions**

Find `vexRunFullSweep()` (search for `function vexRunFullSweep`). Immediately before it, add:
```js
var _vexTargetMode = 'individual'; // 'individual' | 'group'
var _vexGroupSel = {}; // { [groupId]: true } for checked groups in the Full Sweep card's Group(s) mode

// setVexTargetMode switches the Full Sweep card between its single-agent
// select and the group checkbox list, clearing the OTHER mode's selection
// state so a stale pick can't silently leak into a dispatch.
function setVexTargetMode(mode) {
  _vexTargetMode = mode;
  if (mode !== 'group') _vexGroupSel = {};
  var indWrap = document.getElementById('vex-sweep-individual-wrap');
  var grpWrap = document.getElementById('vex-sweep-group-wrap');
  if (indWrap) indWrap.style.display = mode === 'individual' ? 'flex' : 'none';
  if (grpWrap) grpWrap.style.display = mode === 'group' ? 'block' : 'none';
  if (mode === 'group') renderVexGroupList();
}

// renderVexGroupList renders the checkbox list of every group, flattened by
// gpFlattenGroups (the same helper the Run Scenario wizard's own Group(s)
// mode already uses), each row showing that group's own totalAgentCount.
function renderVexGroupList() {
  var list = document.getElementById('vex-sweep-group-list');
  if (!list) return;
  var options = gpFlattenGroups(agentGroupTree, 0, null, []);
  if (!options.length) {
    list.innerHTML = '<p class="tiny muted" style="margin:0">No agent groups have been created yet.</p>';
    renderVexGroupSummary();
    return;
  }
  var countMap = {};
  (function walk(nodes) {
    (nodes || []).forEach(function(n) { countMap[n.id] = n.totalAgentCount; walk(n.children); });
  })(agentGroupTree);
  list.innerHTML = options.map(function(o) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox" ' + (_vexGroupSel[o.id] ? 'checked' : '') +
      ' onchange="_vexGroupSel[' + o.id + ']=this.checked;renderVexGroupSummary()">' +
      '<span style="font-size:0.8rem">' + x(o.label) + '</span>' +
      '<span class="tiny muted">(' + (countMap[o.id] || 0) + ' agents)</span></label>';
  }).join('');
  renderVexGroupSummary();
}

// vexResolvedGroupAgents resolves the currently-checked groups to their
// member agents via the pre-existing resolveGroupTargetAgents helper.
// Deliberately NOT run through osEligibleAgents -- Full Sweep has no
// scenario/supportedOs concept, so every resolved agent is targeted as-is.
function vexResolvedGroupAgents() {
  var selectedGroupIds = Object.keys(_vexGroupSel).filter(function(k) { return _vexGroupSel[k]; }).map(Number);
  return resolveGroupTargetAgents(selectedGroupIds);
}

function renderVexGroupSummary() {
  var el = document.getElementById('vex-sweep-group-summary');
  if (!el) return;
  var selectedCount = Object.keys(_vexGroupSel).filter(function(k) { return _vexGroupSel[k]; }).length;
  if (!selectedCount) { el.textContent = 'No groups selected.'; return; }
  var resolved = vexResolvedGroupAgents();
  el.textContent = resolved.length + ' agent(s) across ' + selectedCount + ' group(s).';
}
```

- [ ] **Step 2: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0.

- [ ] **Step 3: Verify with a standalone Node harness**

`gpFlattenGroups`/`resolveGroupTargetAgents`/`buildGroupDescendantMap` were already verified against synthetic fixtures earlier this session (Run Scenario Group Targeting plan, Task 1) and are reused here unmodified, so they don't need re-verification. This step confirms `vexResolvedGroupAgents`'s composition of `_vexGroupSel` + `resolveGroupTargetAgents` is correct:

```bash
mkdir -p "C:\Users\ADMINI~1\AppData\Local\Temp\claude\C--Users-Administrator-Downloads-Audspect-Cloud\76be556d-bf6b-4e85-a7ce-d0885849aac3\scratchpad"
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html > "C:\Users\ADMINI~1\AppData\Local\Temp\claude\C--Users-Administrator-Downloads-Audspect-Cloud\76be556d-bf6b-4e85-a7ce-d0885849aac3\scratchpad\bundle.js"
```

Then run a harness (adapt path separators for the current OS/shell) that extracts `gpFlattenGroups`, `buildGroupDescendantMap`, `resolveGroupTargetAgents` from `bundle.js` (same extraction technique as the earlier session's `verify_task1.js`: find `function <name>(...) {`, then walk brace depth to the matching `}`), defines synthetic `agentGroupTree`/`agents` fixtures, then inlines and calls the small `vexResolvedGroupAgents`-equivalent composition directly (since it references module-level `_vexGroupSel`, test it as an inline expression rather than extracting the whole function):
```js
// fixtures: Root(1) -> Child(2); a1 in Root, a2 in Child, a3 ungrouped
var agentGroupTree = [{ id: 1, name: 'Root', totalAgentCount: 2, children: [
  { id: 2, name: 'Child', totalAgentCount: 1, children: [] }
]}];
var agents = [
  { agentId: 'a1', groupId: 1 },
  { agentId: 'a2', groupId: 2 },
  { agentId: 'a3', groupId: null }
];
var _vexGroupSel = { 1: true }; // selecting the parent group only

var selectedGroupIds = Object.keys(_vexGroupSel).filter(function(k) { return _vexGroupSel[k]; }).map(Number);
var resolved = resolveGroupTargetAgents(selectedGroupIds); // the extracted real function

console.assert(resolved.length === 2, 'expected parent-group selection to include child-group agents too: ' + JSON.stringify(resolved));
console.log(resolved.length === 2 ? 'PASS' : 'FAIL');
```
Expected: `PASS` — selecting the parent group resolves to both `a1` (direct member) and `a2` (in the child group), matching the same "selecting a parent surfaces its children's agents too" rule already proven for the Run Scenario wizard.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(full-sweep): add group selection state and resolution for the sweep card"
```

---

## Task C: Wire group targeting into `vexRunFullSweep()`'s dispatch

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (`vexRunFullSweep()`, currently lines 16414-16436)

**Interfaces:**
- Consumes: `_vexTargetMode`, `_vexGroupSel`, `vexResolvedGroupAgents()` (Task B), `apicall`, `showToast`, `pollVexSweeps` (pre-existing, unmodified).
- Produces: nothing consumed by later tasks — this is the last task.

- [ ] **Step 1: Replace `vexRunFullSweep()`**

Find (exact, confirmed):
```js
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
```

Replace with:
```js
function vexRunFullSweep() {
  var mode = (document.getElementById('vex-sweep-mode') || {}).value || 'sequential';
  var advanced = document.getElementById('vex-sweep-advanced') ? document.getElementById('vex-sweep-advanced').checked : false;
  // n/variantTotal are a pre-flight estimate only (from the ad-hoc picker's
  // already-loaded technique list) -- the server independently and
  // authoritatively resolves the real technique list and count at creation
  // time; that's what actually gets dispatched.
  var n = _vexAllTechniques.length;
  var variantTotal = _vexAvailableVariants || (n * 33);

  if (_vexTargetMode === 'group') {
    var resolved = vexResolvedGroupAgents();
    if (!resolved.length) { showToast('Select at least one group with agents', 'err'); return; }
    var groupCount = Object.keys(_vexGroupSel).filter(function(k) { return _vexGroupSel[k]; }).length;
    var msg = 'Start Full Variant Sweep on ' + resolved.length + ' agent(s) across ' + groupCount + ' group(s):\n\n' +
      '  ~' + n + ' techniques dispatched sequentially PER AGENT\n' +
      '  ~' + variantTotal.toLocaleString() + '+ individual variants PER AGENT\n\n' +
      'This starts ' + resolved.length + ' independent sweeps. Each runs every technique to completion before the next and may take hours per agent.\n\nContinue?';
    if (!confirm(msg)) return;

    // Each dispatch is independent: a rejected promise or a {error:...}
    // response body is normalized into a resolved {ok:false} result so one
    // agent's failure (already sweeping, offline, etc.) can never abort or
    // block the others -- same isolation pattern confirmRun() already uses
    // for the Run Scenario wizard's multi-agent dispatch.
    var dispatches = resolved.map(function(a) {
      return apicall('/api/vex/sweeps', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId: a.agentId, mode: mode, includeAdvanced: advanced })
      }).then(function(res) {
        if (res && res.error) return { agentId: a.agentId, ok: false, error: res.error };
        return { agentId: a.agentId, ok: true };
      }).catch(function(e) {
        return { agentId: a.agentId, ok: false, error: e.message };
      });
    });

    Promise.all(dispatches).then(function(results) {
      var ok = results.filter(function(r) { return r.ok; });
      var failed = results.filter(function(r) { return !r.ok; });
      if (!failed.length) {
        showToast('Started ' + ok.length + ' sweep(s).', 'ok');
      } else if (ok.length) {
        showToast('Started ' + ok.length + '/' + results.length + ' sweeps. Failed: ' +
          failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
      } else {
        showToast('All ' + results.length + ' sweep dispatches failed. ' +
          failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
      }
      pollVexSweeps();
    });
    return;
  }

  var agentId = (document.getElementById('vex-sweep-agent') || {}).value || '';
  if (!agentId) { showToast('Select an agent in the Full Sweep panel first', 'err'); return; }
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
```
The Individual-mode branch (bottom half) is byte-for-byte identical to the original function — only the Group(s)-mode branch (top half, gated by `if (_vexTargetMode === 'group') { ... return; }`) is new.

- [ ] **Step 2: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0.

- [ ] **Step 3: Verify the dispatch-summary branching with a standalone Node harness**

This isolates the pure `results -> toast message` branching logic (all-ok / partial / all-fail) without touching the DOM or network:
```js
function summarize(results) {
  var ok = results.filter(function(r) { return r.ok; });
  var failed = results.filter(function(r) { return !r.ok; });
  if (!failed.length) return { kind: 'ok', text: 'Started ' + ok.length + ' sweep(s).' };
  if (ok.length) return { kind: 'partial', text: 'Started ' + ok.length + '/' + results.length + ' sweeps. Failed: ' +
    failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', ') };
  return { kind: 'fail', text: 'All ' + results.length + ' sweep dispatches failed. ' +
    failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', ') };
}

var failures = [];
function check(cond, msg) { if (!cond) failures.push(msg); }

check(summarize([{agentId:'a1',ok:true},{agentId:'a2',ok:true}]).kind === 'ok', 'all-ok should be kind=ok');
check(summarize([{agentId:'a1',ok:true},{agentId:'a2',ok:false,error:'agent offline'}]).kind === 'partial', 'mixed should be kind=partial');
check(summarize([{agentId:'a1',ok:false,error:'already sweeping'}]).kind === 'fail', 'all-fail should be kind=fail');
check(summarize([{agentId:'a1',ok:false,error:'already sweeping'}]).text.indexOf('a1 (already sweeping)') !== -1, 'fail message should name the agent and reason');

console.log(failures.length ? 'FAILURES:\n - ' + failures.join('\n - ') : 'ALL TASK C SUMMARY CHECKS PASSED');
if (failures.length) process.exit(1);
```
Expected: `ALL TASK C SUMMARY CHECKS PASSED` — confirms the exact branching logic implemented in `vexRunFullSweep()`'s `Promise.all(...).then(...)` block above (the harness's `summarize` body is copied verbatim from that block).

- [ ] **Step 4: Manual browser QA checklist**

(Flag as deferred if no live orchestrator instance with real registered agents/groups is available — same caveat as this session's prior frontend-only work, logged to the Pending Manual QA Backlog memory.)
- Individual mode: confirm behavior is byte-for-byte identical to before this change (single agent, single confirm, single dispatch).
- Switch to Group(s) mode: confirm the agent select/hint hide and the group checkbox list appears with correct per-group agent counts.
- Check a single group: confirm the summary line shows the correct resolved agent count.
- Check a parent group and one of its own children together: confirm the resolved count does not double-count overlapping agents.
- Click "Start Sweep" with groups selected: confirm the blast-radius confirm shows the correct agent/group counts, and after confirming, one sweep is created per resolved agent (verify via `#vex-sweep-list` showing N new cards, or the Network tab showing N `POST /api/vex/sweeps` calls).
- With one of the resolved agents already mid-sweep (start it individually first, then include it in a group launch): confirm the batch still starts sweeps for the other agents and the summary toast reports that one agent's failure.
- Confirm `#vex-sweep-list` shows all newly-started sweeps as separate cards without a page reload (relies on the pre-existing, unmodified `pollVexSweeps()` call at the end of the dispatch).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(full-sweep): dispatch group-targeted launches as N independent sweeps"
```

---

## Post-implementation

After Task C's QA passes, this feature is complete: the Full Sweep card can launch a sweep against one agent (unchanged) or fan out one independent sweep per agent across one-or-many selected Agent Groups, with zero backend changes and zero changes to the existing sweep progress list or Live Runs' sweep-collapsing.
