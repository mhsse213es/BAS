# Ad-hoc Variant Run: Agent Group / All Agents Targeting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the "Run Variants" card dispatch a single checked technique to one-or-many Agent Groups, or (Admin-only) every agent, in addition to today's single-agent behavior.

**Architecture:** A Target Mode radio (Individual / Agent Group(s) / All Agents) in the existing Run Variants card. Group(s)/All Agents targeting is only valid when exactly one technique is checked, keeping multi-agent dispatch architecturally identical to Full Sweep's just-shipped pattern: N independent, stateless `POST /api/variants/run` calls via `Promise.all`, no client-side sequential queue involved. Multi-technique dispatch stays exactly as it works today, single-agent only, via the existing `_vexRunVariantQueue` client-side loop, completely untouched.

**Tech Stack:** Vanilla JS in `orchestrator/wwwroot/index.html`, no framework, no JS test runner — verification is `node --check` plus standalone Node harnesses for the pure resolution/branching logic, plus manual browser QA, per established project convention.

## Global Constraints

- No backend changes. `POST /api/variants/run` keeps its existing `{agentId, techniqueId, executionMode, includeAdvanced}` shape, called once per resolved agent.
- Group(s)/All Agents mode is valid only when exactly one technique is checked. Clicking Run with more than one technique checked in that mode shows a toast and dispatches nothing.
- No new progress UI for multi-agent dispatch — a summary toast plus the existing Live Runs tab (each dispatch creates a normal `scenario_runs` row) is sufficient. `#vex-result-panel`, `pollVariantRun`, `stopVex()`, `_vexRunVariantQueue`, `_vexWaitAndNext` are not modified and only ever run for the Individual-mode path.
- Group-resolved agents are NOT filtered by OS eligibility (`osEligibleAgents` is scenario-`supportedOs`-specific and does not apply here) — every resolved agent is targeted; a failed dispatch (offline, conflict, etc.) is reported per-agent in the summary toast.
- All new globals/element IDs are distinctly named from both the Run Scenario wizard's (`_targetMode`/`_groupSel`) and Full Sweep's (`_vexTargetMode`/`_vexGroupSel`/`vex-sweep-*`) to avoid any collision: this plan uses `_vexRunTargetMode`/`_vexRunGroupSel`/`vex-run-*`.
- Syntax verification for every task:
  ```bash
  awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
  ```
  Run from the repo root (`C:\Users\Administrator\Downloads\Audspect_Cloud`).

---

## Task A: Target Mode HTML in the Run Variants card

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (Run Variants card markup, currently lines 3581-3623)

**Interfaces:**
- Produces: `#vex-run-individual-wrap` (wraps the existing `<select id="vex-agent">`, unchanged ID/behavior inside), `#vex-run-group-wrap`, `#vex-run-group-list`, `#vex-run-group-summary`, `#vex-run-all-wrap`, `#vex-run-all-label` (hidden by default) — all consumed by Task B.

- [ ] **Step 1: Replace the Agent block with a Target section**

Find (exact, confirmed):
```html
          <!-- Run form -->
          <div class="card" style="padding:1rem">
            <div class="card-title" style="margin-bottom:0.75rem">Run Variants</div>
            <div style="display:flex;flex-direction:column;gap:0.6rem">
              <div>
                <label class="modal-lbl" style="display:block;margin-bottom:0.25rem">Agent</label>
                <select id="vex-agent" class="btn btn-outline" style="width:100%;text-align:left"></select>
              </div>
              <div>
                <label class="modal-lbl" style="display:block;margin-bottom:0.25rem">Tactic</label>
```

Replace with:
```html
          <!-- Run form -->
          <div class="card" style="padding:1rem">
            <div class="card-title" style="margin-bottom:0.75rem">Run Variants</div>
            <div style="display:flex;flex-direction:column;gap:0.6rem">
              <div>
                <label class="modal-lbl" style="display:block;margin-bottom:0.25rem">Target</label>
                <div style="display:flex;gap:0.9rem;flex-wrap:wrap;margin-bottom:0.4rem">
                  <label style="display:flex;align-items:center;gap:0.3rem;cursor:pointer;font-size:0.78rem;color:var(--muted)">
                    <input type="radio" name="vex-run-target-mode" value="individual" checked onchange="setVexRunTargetMode('individual')"> Individual
                  </label>
                  <label style="display:flex;align-items:center;gap:0.3rem;cursor:pointer;font-size:0.78rem;color:var(--muted)">
                    <input type="radio" name="vex-run-target-mode" value="group" onchange="setVexRunTargetMode('group')"> Group(s)
                  </label>
                  <label id="vex-run-all-label" style="display:none;align-items:center;gap:0.3rem;cursor:pointer;font-size:0.78rem;color:var(--muted)">
                    <input type="radio" name="vex-run-target-mode" value="all" onchange="setVexRunTargetMode('all')"> All Agents
                  </label>
                </div>
                <div id="vex-run-individual-wrap">
                  <select id="vex-agent" class="btn btn-outline" style="width:100%;text-align:left"></select>
                </div>
                <div id="vex-run-group-wrap" style="display:none">
                  <div id="vex-run-group-list" style="max-height:140px;overflow-y:auto;border:1px solid var(--border);border-radius:6px;padding:0.35rem;background:var(--surface)"></div>
                  <p class="tiny muted" id="vex-run-group-summary" style="margin-top:0.3rem"></p>
                </div>
                <div id="vex-run-all-wrap" style="display:none">
                  <p class="tiny muted" style="margin:0">Every agent will be targeted (Admin only).</p>
                </div>
              </div>
              <div>
                <label class="modal-lbl" style="display:block;margin-bottom:0.25rem">Tactic</label>
```

Everything from the "Tactic" select through the end of the card (`</div></div>` closing it) stays exactly as it is today — only the "Agent" block at the top is replaced.

- [ ] **Step 2: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(variant-run): add Target Mode radio to the Run Variants card"
```

---

## Task B: Group selection state, list rendering, resolution, and the All-Agents Admin gate

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (new globals + functions placed near `runVariants()`, currently ~line 16655; `populateVexAgents()`, currently lines 16267-16279)

**Interfaces:**
- Consumes: `gpFlattenGroups`, `resolveGroupTargetAgents` (both pre-existing), global `agentGroupTree`, `x()`, `ROLE`, elements from Task A.
- Produces (used by Task C): global `_vexRunTargetMode` (`'individual' | 'group' | 'all'`, default `'individual'`), global `_vexRunGroupSel` (`{[groupId]: true}`), `setVexRunTargetMode(mode)`, `vexRunResolvedGroupAgents()` → array of agent objects, `renderVexRunGroupSummary()`.

- [ ] **Step 1: Add the globals and functions**

Find `runVariants()` (search for `function runVariants`). Immediately before it, add:
```js
var _vexRunTargetMode = 'individual'; // 'individual' | 'group' | 'all'
var _vexRunGroupSel = {}; // { [groupId]: true } for checked groups in the Run Variants card's Group(s) mode

// setVexRunTargetMode switches the Run Variants card between its
// single-agent select, the group checkbox list, and the All Agents notice,
// clearing the OTHER modes' selection state so a stale pick can't silently
// leak into a dispatch.
function setVexRunTargetMode(mode) {
  _vexRunTargetMode = mode;
  if (mode !== 'group') _vexRunGroupSel = {};
  var indWrap = document.getElementById('vex-run-individual-wrap');
  var grpWrap = document.getElementById('vex-run-group-wrap');
  var allWrap = document.getElementById('vex-run-all-wrap');
  if (indWrap) indWrap.style.display = mode === 'individual' ? 'block' : 'none';
  if (grpWrap) grpWrap.style.display = mode === 'group' ? 'block' : 'none';
  if (allWrap) allWrap.style.display = mode === 'all' ? 'block' : 'none';
  if (mode === 'group') renderVexRunGroupList();
}

// renderVexRunGroupList renders the checkbox list of every group, flattened
// by gpFlattenGroups (the same helper both the Run Scenario wizard's and
// Full Sweep's own Group(s) modes already use), each row showing that
// group's own totalAgentCount.
function renderVexRunGroupList() {
  var list = document.getElementById('vex-run-group-list');
  if (!list) return;
  var options = gpFlattenGroups(agentGroupTree, 0, null, []);
  if (!options.length) {
    list.innerHTML = '<p class="tiny muted" style="margin:0">No agent groups have been created yet.</p>';
    renderVexRunGroupSummary();
    return;
  }
  var countMap = {};
  (function walk(nodes) {
    (nodes || []).forEach(function(n) { countMap[n.id] = n.totalAgentCount; walk(n.children); });
  })(agentGroupTree);
  list.innerHTML = options.map(function(o) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox" ' + (_vexRunGroupSel[o.id] ? 'checked' : '') +
      ' onchange="_vexRunGroupSel[' + o.id + ']=this.checked;renderVexRunGroupSummary()">' +
      '<span style="font-size:0.8rem">' + x(o.label) + '</span>' +
      '<span class="tiny muted">(' + (countMap[o.id] || 0) + ' agents)</span></label>';
  }).join('');
  renderVexRunGroupSummary();
}

// vexRunResolvedGroupAgents resolves the currently-checked groups to their
// member agents via the pre-existing resolveGroupTargetAgents helper.
// Deliberately NOT run through osEligibleAgents -- this flow has no
// scenario/supportedOs concept, so every resolved agent is targeted as-is.
function vexRunResolvedGroupAgents() {
  var selectedGroupIds = Object.keys(_vexRunGroupSel).filter(function(k) { return _vexRunGroupSel[k]; }).map(Number);
  return resolveGroupTargetAgents(selectedGroupIds);
}

function renderVexRunGroupSummary() {
  var el = document.getElementById('vex-run-group-summary');
  if (!el) return;
  var selectedCount = Object.keys(_vexRunGroupSel).filter(function(k) { return _vexRunGroupSel[k]; }).length;
  if (!selectedCount) { el.textContent = 'No groups selected.'; return; }
  var resolved = vexRunResolvedGroupAgents();
  el.textContent = resolved.length + ' agent(s) across ' + selectedCount + ' group(s).';
}
```

- [ ] **Step 2: Gate the All-Agents radio behind `ROLE === 'admin'`**

Find `populateVexAgents()` (index.html:16267-16279, exact, confirmed):
```js
function populateVexAgents() {
  apicall('/api/agents').then(function(agents) {
    var online = (agents || []).filter(function(a) { return a.status !== 'offline'; });
    var opts = '<option value="">Select agent…</option>' +
      online.map(function(a) {
        return '<option value="' + x(a.agentId) + '">' + x(a.hostname || a.agentId) + '</option>';
      }).join('');
    var sel = document.getElementById('vex-agent');
    if (sel) sel.innerHTML = opts;
    var sweepSel = document.getElementById('vex-sweep-agent');
    if (sweepSel) sweepSel.innerHTML = opts;
  }).catch(function() {});
}
```
Replace with (only the addition after the existing two `innerHTML` assignments — note the `.then(function(agents) {...})` parameter `agents` here is a local shadow of the outer global `agents` array; the new line below does not use it, only `document.getElementById` and the global `ROLE`):
```js
function populateVexAgents() {
  apicall('/api/agents').then(function(agents) {
    var online = (agents || []).filter(function(a) { return a.status !== 'offline'; });
    var opts = '<option value="">Select agent…</option>' +
      online.map(function(a) {
        return '<option value="' + x(a.agentId) + '">' + x(a.hostname || a.agentId) + '</option>';
      }).join('');
    var sel = document.getElementById('vex-agent');
    if (sel) sel.innerHTML = opts;
    var sweepSel = document.getElementById('vex-sweep-agent');
    if (sweepSel) sweepSel.innerHTML = opts;
    var allLabel = document.getElementById('vex-run-all-label');
    if (allLabel) allLabel.style.display = (ROLE === 'admin') ? 'flex' : 'none';
  }).catch(function() {});
}
```

- [ ] **Step 3: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0.

- [ ] **Step 4: Verify with a standalone Node harness**

`gpFlattenGroups`/`resolveGroupTargetAgents`/`buildGroupDescendantMap` were already verified against synthetic fixtures earlier this session and are reused here unmodified. This step confirms `vexRunResolvedGroupAgents`'s composition of `_vexRunGroupSel` + `resolveGroupTargetAgents` is correct:
```bash
mkdir -p "C:\Users\ADMINI~1\AppData\Local\Temp\claude\C--Users-Administrator-Downloads-Audspect-Cloud\76be556d-bf6b-4e85-a7ce-d0885849aac3\scratchpad"
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html > "C:\Users\ADMINI~1\AppData\Local\Temp\claude\C--Users-Administrator-Downloads-Audspect-Cloud\76be556d-bf6b-4e85-a7ce-d0885849aac3\scratchpad\bundle.js"
```
Then run a harness that extracts `buildGroupDescendantMap` and `resolveGroupTargetAgents` from `bundle.js` (find `function <name>(...) {`, walk brace depth to the matching `}`), defines synthetic `agentGroupTree`/`agents` fixtures, then calls the same composition `vexRunResolvedGroupAgents` uses:
```js
var fs = require('fs');
var path = require('path');
var script = fs.readFileSync(path.join(__dirname, 'bundle.js'), 'utf8');

function extractFn(name) {
  var re = new RegExp('function ' + name + '\\s*\\([^)]*\\)\\s*\\{');
  var m = re.exec(script);
  if (!m) throw new Error('not found: ' + name);
  var start = m.index;
  var i = script.indexOf('{', start);
  var depth = 0;
  for (; i < script.length; i++) {
    if (script[i] === '{') depth++;
    else if (script[i] === '}') { depth--; if (depth === 0) { i++; break; } }
  }
  return script.slice(start, i);
}

var buildGroupDescendantMap = eval('(' + extractFn('buildGroupDescendantMap').replace('function buildGroupDescendantMap', 'function') + ')');
var resolveGroupTargetAgents = eval('(' + extractFn('resolveGroupTargetAgents').replace('function resolveGroupTargetAgents', 'function') + ')');

var agentGroupTree = [{ id: 1, name: 'Root', totalAgentCount: 2, children: [
  { id: 2, name: 'Child', totalAgentCount: 1, children: [] }
]}];
var agents = [
  { agentId: 'a1', groupId: 1 },
  { agentId: 'a2', groupId: 2 },
  { agentId: 'a3', groupId: null }
];

var failures = [];
function check(cond, msg) { if (!cond) failures.push(msg); }

var _vexRunGroupSel = { 1: true };
var selected = Object.keys(_vexRunGroupSel).filter(function(k) { return _vexRunGroupSel[k]; }).map(Number);
var resolved = resolveGroupTargetAgents(selected);
check(resolved.length === 2, 'parent-group selection should include child-group agents: ' + JSON.stringify(resolved));
check(resolved.some(function(a){return a.agentId==='a1';}) && resolved.some(function(a){return a.agentId==='a2';}), 'expected a1 and a2 present');
check(!resolved.some(function(a){return a.agentId==='a3';}), 'ungrouped agent must not leak in');

var _vexRunGroupSelBoth = { 1: true, 2: true };
var selectedBoth = Object.keys(_vexRunGroupSelBoth).filter(function(k) { return _vexRunGroupSelBoth[k]; }).map(Number);
var resolvedBoth = resolveGroupTargetAgents(selectedBoth);
check(resolvedBoth.length === 2, 'parent+child selected together should still dedupe to 2 agents: ' + resolvedBoth.length);

if (failures.length) {
  console.log('FAILURES:');
  failures.forEach(function(f) { console.log(' - ' + f); });
  process.exit(1);
} else {
  console.log('ALL TASK B VERIFICATION CHECKS PASSED');
}
```
Expected: `ALL TASK B VERIFICATION CHECKS PASSED`.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(variant-run): add group selection state, resolution, and All-Agents Admin gate"
```

---

## Task C: Wire the scope guard and multi-agent dispatch into `runVariants()`

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (`runVariants()`, currently lines 16655-16666)

**Interfaces:**
- Consumes: `_vexRunTargetMode`, `_vexRunGroupSel`, `vexRunResolvedGroupAgents()` (Task B), global `agents`, `apicall`, `showToast`, `vexSelectedTechniques()`, `_vexRunVariantQueue`, `loadVariantCoverage`, `loadVariantStats` (all pre-existing, unmodified).
- Produces: nothing consumed by later tasks — this is the last task.

- [ ] **Step 1: Replace `runVariants()`**

Find (exact, confirmed):
```js
function runVariants() {
  var agentId = document.getElementById('vex-agent') ? document.getElementById('vex-agent').value : '';
  var techniques = vexSelectedTechniques();
  var mode = document.getElementById('vex-mode') ? document.getElementById('vex-mode').value : 'sequential';
  var advanced = document.getElementById('vex-advanced') ? document.getElementById('vex-advanced').checked : false;
  if (!agentId) { showToast('Select an agent first', 'err'); return; }
  if (!techniques.length) { showToast('Check at least one technique', 'err'); return; }
  _vexAbortRequested = false; _vexActiveScenarioRunId = null;
  var btn = document.getElementById('vex-run-btn');
  if (btn) { btn.disabled = true; }
  _vexRunVariantQueue(agentId, techniques, mode, advanced, 0);
}
```

Replace with:
```js
function runVariants() {
  var techniques = vexSelectedTechniques();
  var mode = document.getElementById('vex-mode') ? document.getElementById('vex-mode').value : 'sequential';
  var advanced = document.getElementById('vex-advanced') ? document.getElementById('vex-advanced').checked : false;
  if (!techniques.length) { showToast('Check at least one technique', 'err'); return; }

  if (_vexRunTargetMode === 'group' || _vexRunTargetMode === 'all') {
    if (techniques.length > 1) {
      showToast('Group/All-Agent targeting requires exactly one technique — uncheck the rest, or switch to Individual for a multi-technique run.', 'err');
      return;
    }
    var resolved = _vexRunTargetMode === 'group' ? vexRunResolvedGroupAgents() : agents.slice();
    if (!resolved.length) { showToast('Select at least one group with agents', 'err'); return; }
    var techId = techniques[0];

    if (resolved.length > 1) {
      if (!confirm('Run ' + techId + ' on ' + resolved.length + ' agent(s)?')) return;
    }

    // Each dispatch is independent: a rejected promise or a {error:...}
    // response body is normalized into a resolved {ok:false} result so one
    // agent's failure (offline, conflict, etc.) can never abort or block
    // the others -- same isolation pattern used for Full Sweep's group
    // targeting and the Run Scenario wizard's multi-agent dispatch.
    var dispatches = resolved.map(function(a) {
      return apicall('/api/variants/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId: a.agentId, techniqueId: techId, executionMode: mode, includeAdvanced: advanced })
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
        showToast('Dispatched to ' + ok.length + ' agent(s).', 'ok');
      } else if (ok.length) {
        showToast('Dispatched to ' + ok.length + '/' + results.length + ' agents. Failed: ' +
          failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
      } else {
        showToast('All ' + results.length + ' dispatches failed. ' +
          failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
      }
      loadVariantCoverage();
      loadVariantStats();
    });
    return;
  }

  var agentId = document.getElementById('vex-agent') ? document.getElementById('vex-agent').value : '';
  if (!agentId) { showToast('Select an agent first', 'err'); return; }
  _vexAbortRequested = false; _vexActiveScenarioRunId = null;
  var btn = document.getElementById('vex-run-btn');
  if (btn) { btn.disabled = true; }
  _vexRunVariantQueue(agentId, techniques, mode, advanced, 0);
}
```
The Individual-mode branch (bottom half) is functionally identical to the original function — same `agentId` lookup, same guard, same `_vexAbortRequested`/`_vexActiveScenarioRunId` reset, same `_vexRunVariantQueue` call. Only the Group(s)/All-mode branch (top half, gated by `if (_vexRunTargetMode === 'group' || _vexRunTargetMode === 'all') { ... return; }`) is new.

- [ ] **Step 2: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0.

- [ ] **Step 3: Verify the dispatch-summary branching with a standalone Node harness**

```js
function summarize(results) {
  var ok = results.filter(function(r) { return r.ok; });
  var failed = results.filter(function(r) { return !r.ok; });
  if (!failed.length) return { kind: 'ok', text: 'Dispatched to ' + ok.length + ' agent(s).' };
  if (ok.length) return { kind: 'partial', text: 'Dispatched to ' + ok.length + '/' + results.length + ' agents. Failed: ' +
    failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', ') };
  return { kind: 'fail', text: 'All ' + results.length + ' dispatches failed. ' +
    failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', ') };
}

var failures = [];
function check(cond, msg) { if (!cond) failures.push(msg); }

check(summarize([{agentId:'a1',ok:true},{agentId:'a2',ok:true}]).kind === 'ok', 'all-ok should be kind=ok');
check(summarize([{agentId:'a1',ok:true},{agentId:'a2',ok:false,error:'agent offline'}]).kind === 'partial', 'mixed should be kind=partial');
check(summarize([{agentId:'a1',ok:false,error:'agent offline'}]).kind === 'fail', 'all-fail should be kind=fail');
check(summarize([{agentId:'a1',ok:false,error:'agent offline'}]).text.indexOf('a1 (agent offline)') !== -1, 'fail message should name the agent and reason');

if (failures.length) {
  console.log('FAILURES:');
  failures.forEach(function(f) { console.log(' - ' + f); });
  process.exit(1);
} else {
  console.log('ALL TASK C SUMMARY CHECKS PASSED');
}
```
Expected: `ALL TASK C SUMMARY CHECKS PASSED` — the harness's `summarize` body is copied verbatim from `runVariants()`'s `Promise.all(...).then(...)` block above.

- [ ] **Step 4: Manual browser QA checklist**

(Flag as deferred if no live orchestrator instance with real registered agents/groups is available — same caveat as every other frontend task this session, logged to the Pending Manual QA Backlog memory.)
- Individual mode, single technique: confirm behavior is byte-for-byte identical to before this change.
- Individual mode, multiple techniques: confirm the existing client-side queue (Queue Progress panel, Stop button) still works exactly as before.
- Group(s) mode with exactly one technique checked: confirm dispatch fires one `POST /api/variants/run` per resolved agent, the summary toast is correct, and Live Runs shows one new row per agent.
- Group(s) mode, then check a second technique, then click Run: confirm the scope-guard toast appears and no dispatch happens.
- All Agents mode: confirm it's invisible to a non-Admin user, and for an Admin, dispatches to every agent.
- A group containing an agent that's offline or already busy: confirm the batch still dispatches to the others and the summary toast reports that one agent's failure.
- Confirm a parent group + one of its own children checked together doesn't double-dispatch to the same agent.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(variant-run): dispatch group/all-agent single-technique runs as N independent calls"
```

---

## Post-implementation

After Task C's QA passes, this feature is complete: the Run Variants card can target one agent (single or multiple techniques, unchanged), or fan out a single checked technique to one-or-many Agent Groups or every agent (Admin-only), with zero backend changes and zero changes to the existing multi-technique client-side queue.
