# Run Scenario Wizard: Agent Group Targeting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the Run Scenario wizard target one or more Agent Groups (or, Admin-only, all agents) in addition to its existing individual-agent targeting, with zero backend changes.

**Architecture:** A new "Target Mode" radio (Individual / Agent Group(s) / All Agents) in the wizard's existing Target step. Group(s)/All resolve to a filtered agent-ID list entirely client-side, from data already loaded in the browser (`agentGroupTree`, `agents`) — no new API calls. The resolved list feeds directly into `confirmRun()`'s existing per-agent `Promise.all` dispatch loop, which is otherwise untouched.

**Tech Stack:** Vanilla JS embedded in `orchestrator/wwwroot/index.html` (no framework, no bundler, no JS test runner in this codebase — verification is `node --check` for syntax plus manual browser QA, per established project convention).

## Global Constraints

- Frontend-only. No Go files change. No new API endpoints, no new permissions.
- Group/All-resolved agent sets are filtered through the exact same OS-eligibility rule the existing "Additional Agents" checkbox list already uses (`sc.supportedOs` vs `cmpAgentOS(a)`) — extracted into one shared function, not duplicated.
- Incompatible agents in a selected group/all set are silently excluded from dispatch (not blocked), with a visible eligible/skipped count.
- The "All Agents" target mode is visible only when `ROLE === 'admin'` (same client-side gate already used for Campaigns' "All Agents" option at `index.html:7586`).
- A blast-radius confirm (`This will run on N agent(s)...`) is required before dispatching any Group/All-targeted run, in every execution mode including posture.
- `confirmRun()`'s downstream dispatch logic (`baseBody` construction, the `dispatches` map, `Promise.all`, result toasts) must not change — only how `agentIds` is computed and which confirm dialogs appear before it.
- Syntax verification for every task: extract the inline `<script>` block and pipe to `node --check`:
  ```bash
  awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
  ```
  Run from the repo root (`C:\Users\Administrator\Downloads\Audspect_Cloud`).

---

## Task 1: Data-layer helpers — group resolution + shared OS-eligibility filter

**Files:**
- Modify: `orchestrator/wwwroot/index.html`
  - Add new functions near `gpFlattenGroups` (currently at line ~6655), since they operate on the same `agentGroupTree` global and belong next to it.
  - Modify `eligibleAdditionalAgents()` (currently at line ~10239-10249) to use the new shared filter instead of its own inline OS-compat condition.

**Interfaces:**
- Consumes: global `agentGroupTree` (array of `{id, name, children, totalAgentCount}` nodes, populated by `loadAgentGroupTree()`), global `agents` (array of agent objects, each with `.agentId`, `.osVersion`, `.groupId` — `.groupId` is `undefined` for an ungrouped agent since the Go struct tag is `json:"groupId,omitempty"`), global `scenarios`, existing `cmpAgentOS(a)` helper (`index.html:7879`, returns `'windows'|'darwin'|'linux'`).
- Produces (used by Task 2 and Task 3):
  - `osEligibleAgents(list, sc)` → filters `list` (array of agent objects) down to those whose OS is in `sc.supportedOs` (case-insensitive), or returns `list` unchanged if `sc.supportedOs` is empty/absent.
  - `buildGroupDescendantMap(nodes)` → returns a plain object `{ [groupId]: [groupId, ...all descendant group ids] }` for every node in the tree.
  - `resolveGroupTargetAgents(selectedGroupIds)` → given an array of numeric group IDs, returns the array of agent objects (from global `agents`) whose `.groupId` falls in the union of those groups' descendant sets. No OS filtering applied here (that's a separate step, done by callers).

- [ ] **Step 1: Add `osEligibleAgents` and refactor `eligibleAdditionalAgents` to use it**

Locate the current `eligibleAdditionalAgents()` function:
```js
function eligibleAdditionalAgents() {
  var primaryId = document.getElementById('modal-agent').value;
  var scId = _modalScId || document.getElementById('modal-sc').value;
  var sc = scenarios.find(function(s) { return s.id === scId; });
  var supported = ((sc && sc.supportedOs) || []).map(function(o) { return o.toLowerCase(); });
  return agents.filter(function(a) {
    if (a.agentId === primaryId) return false;
    if (supported.length && supported.indexOf(cmpAgentOS(a)) === -1) return false;
    return true;
  });
}
```

Replace it with:
```js
// osEligibleAgents filters `list` down to agents whose OS matches sc.supportedOs
// (case-insensitive). An empty/absent supportedOs means "any OS" — used by every
// agent-targeting path in the Run Scenario wizard (individual, group, all) so OS
// compatibility is defined in exactly one place.
function osEligibleAgents(list, sc) {
  var supported = ((sc && sc.supportedOs) || []).map(function(o) { return o.toLowerCase(); });
  if (!supported.length) return list;
  return list.filter(function(a) { return supported.indexOf(cmpAgentOS(a)) !== -1; });
}

function eligibleAdditionalAgents() {
  var primaryId = document.getElementById('modal-agent').value;
  var scId = _modalScId || document.getElementById('modal-sc').value;
  var sc = scenarios.find(function(s) { return s.id === scId; });
  return osEligibleAgents(agents.filter(function(a) { return a.agentId !== primaryId; }), sc);
}
```

- [ ] **Step 2: Add `buildGroupDescendantMap` and `resolveGroupTargetAgents` next to `gpFlattenGroups`**

Find `gpFlattenGroups` (search for `function gpFlattenGroups`). Immediately after its closing `}`, add:
```js
// buildGroupDescendantMap walks the group tree once and returns, for every
// group id, the list of that group's own id plus every descendant group's id
// (post-order: children are resolved before their parent so parents can just
// concatenate their already-computed children's lists). Mirrors the same
// "selecting a parent surfaces its children's agents too" rule the backend
// applies in GET /api/agents?groupId= and jobs.Store.ResolveGroupAgentIDs.
function buildGroupDescendantMap(nodes) {
  var map = {};
  function walk(list) {
    (list || []).forEach(function(n) {
      var ids = [n.id];
      if (n.children && n.children.length) {
        walk(n.children);
        n.children.forEach(function(c) { ids = ids.concat(map[c.id]); });
      }
      map[n.id] = ids;
    });
  }
  walk(nodes);
  return map;
}

// resolveGroupTargetAgents returns every agent (from the global `agents` array)
// belonging to any of selectedGroupIds or their descendant groups. Pure client-side
// set math over already-loaded data -- no API call. Does not apply OS filtering;
// callers run the result through osEligibleAgents separately.
function resolveGroupTargetAgents(selectedGroupIds) {
  if (!selectedGroupIds.length) return [];
  var map = buildGroupDescendantMap(agentGroupTree);
  var idSet = {};
  selectedGroupIds.forEach(function(gid) {
    (map[gid] || [gid]).forEach(function(id) { idSet[id] = true; });
  });
  return agents.filter(function(a) { return a.groupId != null && idSet[a.groupId]; });
}
```

- [ ] **Step 3: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0.

- [ ] **Step 4: Manual verification via browser console**

Start the orchestrator locally (or use an already-running dev instance), open the dashboard in a browser, open the JS console, and run:
```js
osEligibleAgents(agents, { supportedOs: ['windows'] }).every(a => cmpAgentOS(a) === 'windows')
// expect: true

buildGroupDescendantMap(agentGroupTree)
// expect: an object keyed by every group id currently in the tree, each value an array including that id

resolveGroupTargetAgents([/* pick a real group id from agentGroupTree */]).length > 0
// expect: true if that group (or a descendant) has agents
```
Confirm the outputs match expectations for at least one real group ID from the current `agentGroupTree`.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(run-scenario): add client-side group-to-agent resolution helpers"
```

---

## Task 2: Target Mode UI — HTML, rendering, and mode switching

**Files:**
- Modify: `orchestrator/wwwroot/index.html`
  - HTML: Step 2 (Target) pane, currently lines 3687-3701.
  - JS: `openModal()` (currently ~10078-10121), `renderRunMode()` (currently ~10125-10228).

**Interfaces:**
- Consumes: `osEligibleAgents`, `resolveGroupTargetAgents`, `gpFlattenGroups` (Task 1 and pre-existing), global `agentGroupTree`, `agents`, `scenarios`, `ROLE`.
- Produces (used by Task 3):
  - Global `_targetMode` (`'individual' | 'group' | 'all'`, default `'individual'`, reset by `openModal()`).
  - Global `_groupSel` (object, `{ [groupId]: true }` for checked groups, mirrors the existing `_addlSel` pattern).
  - `resolvedGroupTargetIds()` → `{ eligible: [agent, ...], total: N }` for the currently-checked groups.
  - `resolvedAllTargetIds()` → `{ eligible: [agent, ...], total: N }` for every agent.

- [ ] **Step 1: Replace the Step 2 (Target) HTML pane**

Find:
```html
      <!-- Step 2: Target -->
      <div class="wz-pane" data-pane="2" style="display:none">
        <label class="modal-lbl">Primary Agent</label>
        <select id="modal-agent" onchange="renderRunMode()"></select>
        <p class="sub2" style="margin-top:0.55rem">The endpoint that will execute this run.</p>

        <div id="modal-addl-wrap" style="display:none;margin-top:0.9rem">
          <label class="modal-lbl">Run on Additional Agents <span class="tiny muted" id="modal-addl-cnt">(0 selected)</span></label>
          <div style="display:flex;justify-content:flex-end;margin-bottom:0.4rem">
            <button class="btn btn-outline btn-sm" onclick="selectAllAdditionalAgents()">Select all</button>
          </div>
          <div id="modal-addl-list" style="max-height:200px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius);padding:0.4rem"></div>
          <p class="sub2" style="margin-top:0.4rem">Same scenario, mode, and options will be dispatched to each checked agent.</p>
        </div>
      </div>
```

Replace with:
```html
      <!-- Step 2: Target -->
      <div class="wz-pane" data-pane="2" style="display:none">
        <div style="margin-bottom:0.9rem">
          <label class="modal-lbl">Target</label>
          <div style="display:flex;gap:1.1rem;margin-top:0.35rem;flex-wrap:wrap">
            <label style="display:flex;align-items:center;gap:0.35rem;cursor:pointer;font-size:0.82rem">
              <input type="radio" name="modal-target-mode" value="individual" checked onchange="setTargetMode('individual')"> Individual Agent(s)
            </label>
            <label style="display:flex;align-items:center;gap:0.35rem;cursor:pointer;font-size:0.82rem">
              <input type="radio" name="modal-target-mode" value="group" onchange="setTargetMode('group')"> Agent Group(s)
            </label>
            <label id="modal-target-all-label" style="display:none;align-items:center;gap:0.35rem;cursor:pointer;font-size:0.82rem">
              <input type="radio" name="modal-target-mode" value="all" onchange="setTargetMode('all')"> All Agents
            </label>
          </div>
        </div>

        <div id="modal-individual-wrap">
          <label class="modal-lbl">Primary Agent</label>
          <select id="modal-agent" onchange="renderRunMode()"></select>
          <p class="sub2" style="margin-top:0.55rem">The endpoint that will execute this run.</p>

          <div id="modal-addl-wrap" style="display:none;margin-top:0.9rem">
            <label class="modal-lbl">Run on Additional Agents <span class="tiny muted" id="modal-addl-cnt">(0 selected)</span></label>
            <div style="display:flex;justify-content:flex-end;margin-bottom:0.4rem">
              <button class="btn btn-outline btn-sm" onclick="selectAllAdditionalAgents()">Select all</button>
            </div>
            <div id="modal-addl-list" style="max-height:200px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius);padding:0.4rem"></div>
            <p class="sub2" style="margin-top:0.4rem">Same scenario, mode, and options will be dispatched to each checked agent.</p>
          </div>
        </div>

        <div id="modal-group-wrap" style="display:none">
          <label class="modal-lbl">Agent Group(s)</label>
          <div id="modal-group-list" style="max-height:200px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius);padding:0.4rem"></div>
          <p class="sub2" id="modal-group-summary" style="margin-top:0.4rem"></p>
        </div>

        <div id="modal-all-wrap" style="display:none">
          <p class="sub2" id="modal-all-summary"></p>
        </div>
      </div>
```

- [ ] **Step 2: Add `_targetMode`, `_groupSel` globals and target-mode functions**

Find the existing `_addlSel` global declaration (search for `var _addlSel`). Immediately after it, add:
```js
var _targetMode = 'individual'; // 'individual' | 'group' | 'all'
var _groupSel = {}; // { [groupId]: true } for checked groups in Group(s) mode
```

Then, near `renderAdditionalAgents()`/`selectAllAdditionalAgents()` (search for `function selectAllAdditionalAgents`), add after it:
```js
// setTargetMode switches which Target-step sub-panel is visible and clears the
// OTHER modes' selection state so a stale pick from a previous mode can never
// silently leak into a dispatch (e.g. switching from Group back to Individual
// must not leave old group checkboxes still "selected" underneath).
function setTargetMode(mode) {
  _targetMode = mode;
  if (mode !== 'group') _groupSel = {};
  if (mode !== 'individual') _addlSel = {};
  document.getElementById('modal-individual-wrap').style.display = mode === 'individual' ? 'block' : 'none';
  document.getElementById('modal-group-wrap').style.display = mode === 'group' ? 'block' : 'none';
  document.getElementById('modal-all-wrap').style.display = mode === 'all' ? 'block' : 'none';
  if (mode === 'group') renderGroupTargetList();
  renderRunMode();
}

// resolvedGroupTargetIds/resolvedAllTargetIds both return {eligible, total} so
// callers can show "X of Y eligible" without a second pass over the data.
function resolvedGroupTargetIds() {
  var scId = _modalScId || document.getElementById('modal-sc').value;
  var sc = scenarios.find(function(s) { return s.id === scId; });
  var selectedGroupIds = Object.keys(_groupSel).filter(function(k) { return _groupSel[k]; }).map(Number);
  var candidates = resolveGroupTargetAgents(selectedGroupIds);
  return { eligible: osEligibleAgents(candidates, sc), total: candidates.length };
}

function resolvedAllTargetIds() {
  var scId = _modalScId || document.getElementById('modal-sc').value;
  var sc = scenarios.find(function(s) { return s.id === scId; });
  return { eligible: osEligibleAgents(agents, sc), total: agents.length };
}

// renderGroupTargetList renders the checkbox list of every group, flattened by
// gpFlattenGroups (same helper the Move-to-Group picker uses), each row also
// showing that group's own totalAgentCount as a quick-glance hint before any
// OS filtering is applied.
function renderGroupTargetList() {
  var list = document.getElementById('modal-group-list');
  if (!list) return;
  var options = gpFlattenGroups(agentGroupTree, 0, null, []);
  if (!options.length) {
    list.innerHTML = '<p class="sub2" style="margin:0">No agent groups have been created yet.</p>';
    renderGroupTargetSummary();
    return;
  }
  var countMap = {};
  (function walk(nodes) {
    (nodes || []).forEach(function(n) { countMap[n.id] = n.totalAgentCount; walk(n.children); });
  })(agentGroupTree);
  list.innerHTML = options.map(function(o) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox" ' + (_groupSel[o.id] ? 'checked' : '') +
      ' onchange="_groupSel[' + o.id + ']=this.checked;renderRunMode()">' +
      '<span style="font-size:0.8rem">' + x(o.label) + '</span>' +
      '<span class="tiny muted">(' + (countMap[o.id] || 0) + ' agents)</span></label>';
  }).join('');
  renderGroupTargetSummary();
}

// renderGroupTargetSummary/renderAllTargetSummary only update their own summary
// text -- they do NOT call renderRunMode() themselves. renderRunMode() is the
// single top-level orchestrator that calls these (see Step 3): if these called
// renderRunMode() too, a checkbox's onchange -> renderRunMode() -> (mode ===
// 'group') -> renderGroupTargetSummary() -> renderRunMode() chain would recurse
// forever. renderGroupTargetList() (which runs once per mode-switch, not per
// render) is the one place that calls renderGroupTargetSummary() directly for
// its initial paint, and that call site does not sit inside renderRunMode().
function renderGroupTargetSummary() {
  var el = document.getElementById('modal-group-summary');
  if (!el) return;
  var r = resolvedGroupTargetIds();
  if (r.total === 0) { el.textContent = 'No groups selected.'; return; }
  var skipped = r.total - r.eligible.length;
  el.textContent = r.eligible.length + ' of ' + r.total + ' group agent(s) eligible' +
    (skipped ? ' (' + skipped + ' skipped: OS mismatch)' : '') + '.';
}

function renderAllTargetSummary() {
  var el = document.getElementById('modal-all-summary');
  if (!el) return;
  var r = resolvedAllTargetIds();
  var skipped = r.total - r.eligible.length;
  el.textContent = r.eligible.length + ' of ' + r.total + ' agent(s) eligible' +
    (skipped ? ' (' + skipped + ' skipped: OS mismatch)' : '') + '.';
}
```

- [ ] **Step 3: Update `renderRunMode()` to handle group/all eligibility and skip the per-agent OS check outside Individual mode**

Find the start of `renderRunMode()` through the OS-compatibility block:
```js
function renderRunMode() {
  renderModalSelection();
  renderAdditionalAgents();
  var id = _modalScId || document.getElementById('modal-sc').value;
  var sc = scenarios.find(function(s) { return s.id === id; });
  var wrap = document.getElementById('modal-mode-wrap');
  var modeSel = document.getElementById('modal-mode');
  var warn = document.getElementById('modal-mode-warn');
  var btn = document.getElementById('modal-run-btn');

  // OS compatibility check
  var agentId = document.getElementById('modal-agent').value;
  var agent = agents.find(function(a) { return a.agentId === agentId; });
  var agentOSClass = '';
  if (agent && agent.osVersion) {
    var ov = agent.osVersion.toLowerCase();
    agentOSClass = ov.indexOf('windows') !== -1 ? 'windows' : ov.indexOf('darwin') !== -1 || ov.indexOf('macos') !== -1 ? 'darwin' : 'linux';
  }
  var osMismatch = false;
  var osMismatchMsg = '';
  if (sc && (sc.supportedOs || []).length > 0 && agentOSClass) {
    var supported = (sc.supportedOs || []).some(function(o) { return o.toLowerCase() === agentOSClass; });
    if (!supported) {
      osMismatch = true;
      var targetOS = (sc.supportedOs || []).join(' / ');
      osMismatchMsg = '&#9888; <strong>OS mismatch:</strong> this scenario targets <strong>' + x(targetOS) +
        '</strong> but the selected agent is <strong>' + x(agent.osVersion) + '</strong>. ' +
        'Posture checks will return "not applicable". Live execution will be blocked by the server.';
    }
  }
```

Replace with:
```js
function renderRunMode() {
  renderModalSelection();
  renderAdditionalAgents();
  if (_targetMode === 'group') renderGroupTargetSummary();
  if (_targetMode === 'all') renderAllTargetSummary();
  var id = _modalScId || document.getElementById('modal-sc').value;
  var sc = scenarios.find(function(s) { return s.id === id; });
  var wrap = document.getElementById('modal-mode-wrap');
  var modeSel = document.getElementById('modal-mode');
  var warn = document.getElementById('modal-mode-warn');
  var btn = document.getElementById('modal-run-btn');

  // Group/All targeting: eligibility is evaluated across the whole resolved set,
  // not one primary agent's OS, so it takes a simpler path than the per-agent
  // mismatch check below (which only applies in Individual mode). Agents were
  // already OS-filtered when the set was resolved, so the only remaining
  // question here is whether ANY eligible agent survived that filter.
  if (_targetMode === 'group' || _targetMode === 'all') {
    var resolved = _targetMode === 'group' ? resolvedGroupTargetIds() : resolvedAllTargetIds();
    if (!resolved.eligible.length) {
      wrap.style.display = 'none';
      warn.style.display = 'none';
      btn.disabled = true;
      btn.innerHTML = '&#9888; No Eligible Agents';
      return;
    }
  }

  // OS compatibility check (Individual mode's primary agent only — Group/All
  // targeting has no single "the selected agent", eligibility is handled above).
  var osMismatch = false;
  var osMismatchMsg = '';
  if (_targetMode === 'individual') {
    var agentId = document.getElementById('modal-agent').value;
    var agent = agents.find(function(a) { return a.agentId === agentId; });
    var agentOSClass = '';
    if (agent && agent.osVersion) {
      var ov = agent.osVersion.toLowerCase();
      agentOSClass = ov.indexOf('windows') !== -1 ? 'windows' : ov.indexOf('darwin') !== -1 || ov.indexOf('macos') !== -1 ? 'darwin' : 'linux';
    }
    if (sc && (sc.supportedOs || []).length > 0 && agentOSClass) {
      var supported = (sc.supportedOs || []).some(function(o) { return o.toLowerCase() === agentOSClass; });
      if (!supported) {
        osMismatch = true;
        var targetOS = (sc.supportedOs || []).join(' / ');
        osMismatchMsg = '&#9888; <strong>OS mismatch:</strong> this scenario targets <strong>' + x(targetOS) +
          '</strong> but the selected agent is <strong>' + x(agent.osVersion) + '</strong>. ' +
          'Posture checks will return "not applicable". Live execution will be blocked by the server.';
      }
    }
  }
  btn.disabled = false;
```

Note the trailing `btn.disabled = false;` — the original function never explicitly reset `disabled` before its later mode-specific branches (it relied on the OS-mismatch branch further down setting `btn.disabled = true` only when needed). Because Group/All's own zero-eligible check above now already `return`s early with `btn.disabled = true` when appropriate, this explicit reset ensures a *previous* render's disabled state (e.g. from a prior zero-eligible Group selection) doesn't linger after switching to a now-valid target. Leave the rest of `renderRunMode()` (the `if (!sc || !sc.executable)` block onward, through the variant-depth logic at the end) exactly as it is today — it already reads only `sc`, `mode`, `osMismatch`, `osMismatchMsg`, `wrap`, `warn`, `btn`, all of which are still correctly populated.

- [ ] **Step 4: Update `openModal()` to reset target-mode state on every open**

Find:
```js
  document.getElementById('modal-mode').value = 'posture'; // always default to safe
  document.getElementById('modal-max-privilege').value = ''; // always default to no limit
  _addlSel = {};
  renderRunMode();
```

Replace with:
```js
  document.getElementById('modal-mode').value = 'posture'; // always default to safe
  document.getElementById('modal-max-privilege').value = ''; // always default to no limit
  _addlSel = {};
  _groupSel = {};
  _targetMode = 'individual';
  var indRadio = document.querySelector('input[name="modal-target-mode"][value="individual"]');
  if (indRadio) indRadio.checked = true;
  document.getElementById('modal-individual-wrap').style.display = 'block';
  document.getElementById('modal-group-wrap').style.display = 'none';
  document.getElementById('modal-all-wrap').style.display = 'none';
  var allLabel = document.getElementById('modal-target-all-label');
  if (allLabel) allLabel.style.display = (ROLE === 'admin') ? 'flex' : 'none';
  renderRunMode();
```

- [ ] **Step 5: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0.

- [ ] **Step 6: Manual browser QA**

Open the dashboard, log in as an Admin user, open the Run Scenario wizard from any scenario card:
- Confirm the Target step shows three radio options: Individual Agent(s), Agent Group(s), All Agents.
- Click "Agent Group(s)": confirm the group checkbox list renders (indented by hierarchy depth, each with an agent count), and the Primary Agent / Additional Agents block hides.
- Check a group with a known agent count: confirm the summary line shows "N of M group agent(s) eligible" (or lists OS-mismatch skips if the scenario has a `supportedOs` restriction and the group has mixed-OS agents).
- Check a parent group and one of its own children at the same time: confirm the summary count does not double-count the overlapping agents.
- Click "All Agents": confirm the group list hides, the all-agents summary renders, and the Run button is disabled with "No Eligible Agents" only if truly zero agents match (unlikely in a populated environment — verify the button is otherwise enabled).
- Switch back to "Individual Agent(s)": confirm the original Primary Agent dropdown and Additional Agents checkboxes reappear exactly as before, with no leftover group selections.
- Log in as a non-Admin (Analyst) user, open the wizard: confirm "All Agents" is not shown as an option at all (not just disabled).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(run-scenario): add Target Mode selector for Agent Group(s) and All Agents"
```

---

## Task 3: Wire group/all targeting into `confirmRun()`'s dispatch + blast-radius confirm

**Files:**
- Modify: `orchestrator/wwwroot/index.html` — `confirmRun()`, currently lines 13475-13586.

**Interfaces:**
- Consumes: `_targetMode`, `_groupSel`, `resolvedGroupTargetIds()`, `resolvedAllTargetIds()` (all from Task 2), `additionalAgentIds()` (pre-existing, unchanged).
- Produces: nothing consumed by later tasks — this is the last task.

- [ ] **Step 1: Replace `confirmRun()`'s target resolution (top of the function)**

Find:
```js
function confirmRun() {
  var scenarioId = _modalScId || document.getElementById('modal-sc').value;
  var primaryId  = document.getElementById('modal-agent').value;
  if (!scenarioId || !primaryId) { showToast('Select scenario and agent', 'err'); return; }
  var agentIds = [primaryId].concat(additionalAgentIds());
  var multi = agentIds.length > 1;
```

Replace with:
```js
function confirmRun() {
  var scenarioId = _modalScId || document.getElementById('modal-sc').value;
  var groupTargeted = (_targetMode === 'group' || _targetMode === 'all');
  var agentIds;
  if (groupTargeted) {
    var resolved = _targetMode === 'group' ? resolvedGroupTargetIds() : resolvedAllTargetIds();
    agentIds = resolved.eligible.map(function(a) { return a.agentId; });
    if (!scenarioId || !agentIds.length) { showToast('Select scenario and at least one eligible agent', 'err'); return; }
  } else {
    var primaryId = document.getElementById('modal-agent').value;
    if (!scenarioId || !primaryId) { showToast('Select scenario and agent', 'err'); return; }
    agentIds = [primaryId].concat(additionalAgentIds());
  }
  var multi = agentIds.length > 1;
```

- [ ] **Step 2: Insert the blast-radius confirm and adjust the existing posture-mode `multi` confirm**

Find:
```js
  var agentListText = agentIds.map(function(id) {
    var a = agents.find(function(ag) { return ag.agentId === id; });
    return '• ' + (a ? a.agentId + ' — ' + a.hostname : id);
  }).join('\n');
  var header = 'Scenario: ' + (sc ? sc.name : scenarioId) + '\nFramework: ' + frameworkDisplayName(scenarioFramework(sc));

  if (mode === 'telemetry') {
```

Replace with:
```js
  var agentListText = agentIds.map(function(id) {
    var a = agents.find(function(ag) { return ag.agentId === id; });
    return '• ' + (a ? a.agentId + ' — ' + a.hostname : id);
  }).join('\n');
  var header = 'Scenario: ' + (sc ? sc.name : scenarioId) + '\nFramework: ' + frameworkDisplayName(scenarioFramework(sc));

  // Group/All targeting can silently resolve to far more agents than a user
  // manually checking boxes would ever pick, so it always gets its own explicit
  // confirm regardless of run mode. In posture mode this REPLACES the existing
  // manual-multi-agent confirm below (same purpose, group-aware wording) rather
  // than showing two confirms back to back. In telemetry/lab mode it is
  // additional to — shown before — those modes' own existing confirms.
  if (groupTargeted) {
    var groupCount = _targetMode === 'group'
      ? Object.keys(_groupSel).filter(function(k) { return _groupSel[k]; }).length : 0;
    var blastMsg = _targetMode === 'all'
      ? 'This will run on all ' + agentIds.length + ' eligible agent(s).\n\nProceed?'
      : 'This will run on ' + agentIds.length + ' agent(s) across ' + groupCount + ' group(s).\n\nProceed?';
    if (!confirm(blastMsg)) return;
  }

  if (mode === 'telemetry') {
```

Then find the existing posture-mode branch:
```js
  } else if (multi) {
    // Posture mode has zero confirmation for a single agent today; a batch of 2+
    // targets is a bigger blast radius, so gate it with one lightweight confirm.
    var postureMsg = 'Run scenario?\n\n' + header + '\n\nAgents (' + agentIds.length + '):\n' + agentListText + '\n\nProceed?';
    if (!confirm(postureMsg)) return;
  }
```

Replace with:
```js
  } else if (multi && !groupTargeted) {
    // Posture mode has zero confirmation for a single agent today; a batch of 2+
    // manually-picked targets is a bigger blast radius, so gate it with one
    // lightweight confirm. Group/All targeting already showed its own
    // group-aware blast-radius confirm above, so it's excluded here to avoid
    // asking the operator to confirm the same dispatch twice.
    var postureMsg = 'Run scenario?\n\n' + header + '\n\nAgents (' + agentIds.length + '):\n' + agentListText + '\n\nProceed?';
    if (!confirm(postureMsg)) return;
  }
```

Leave the `telemetry`/`lab` branches, and everything from `var reasonEl = ...` through the end of the function (`baseBody` construction, the `dispatches` map, `Promise.all(...).then(...)`), exactly as they are today — they operate only on `agentIds`, `multi`, `mode`, `baseBody`, all of which are correctly populated regardless of target mode.

- [ ] **Step 3: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0.

- [ ] **Step 4: Manual browser QA — full dispatch flow**

With the orchestrator running and at least one Agent Group containing 2+ real (even if offline/test) agents:
- **Group targeting, posture mode:** open Run Scenario on a posture-capable scenario, switch to Agent Group(s), check one group, proceed through to Run. Confirm exactly ONE confirm dialog appears (the blast-radius message, correctly naming the agent and group counts), and after confirming, the dispatch fires one `POST /api/scenarios/{id}/run` per eligible agent in that group (verify via the Network tab or by checking the Runs tab afterward for one new run per agent).
- **Group targeting, telemetry mode:** same setup but switch Execution Mode to Telemetry. Confirm TWO confirms appear in sequence: the blast-radius confirm first, then the existing Telemetry warning confirm.
- **All Agents targeting (Admin):** switch to All Agents, proceed to Run in posture mode. Confirm the blast-radius message says "all N eligible agent(s)" and dispatches to every OS-eligible agent.
- **Individual targeting (regression check):** switch back to Individual Agent(s), pick a primary agent plus 2 additional agents, run in posture mode. Confirm behavior is byte-for-byte identical to before this change: one confirm showing the existing `postureMsg` wording (agent list with bullet points), not the new blast-radius wording.
- **Single individual agent (regression check):** pick only a primary agent, no additional agents, run in posture mode. Confirm zero confirm dialogs appear (unchanged from today).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(run-scenario): dispatch group/all-targeted runs through existing per-agent fan-out"
```

---

## Post-implementation

After Task 3's QA passes, this feature is complete: individual agent, multiple individual agents, and one-or-many Agent Groups (or, Admin-only, all agents) are all selectable as Run Scenario targets, entirely via existing dispatch and permission infrastructure.
