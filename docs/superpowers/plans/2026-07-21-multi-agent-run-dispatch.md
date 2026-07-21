# Multi-Agent Run Dispatch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator run a scenario against a Primary Agent plus any number of checked "Additional Agents" from the existing Run Scenario wizard, with a deterministic dispatch order, a richer confirmation dialog, independent per-agent success/failure handling, and a forward-compat `batchId` — with zero backend changes.

**Architecture:** All changes are confined to `orchestrator/wwwroot/index.html` (and its hardlinked twin `orchestrator/cmd/server/wwwroot/index.html`). The existing single-agent `#modal-agent` `<select>` becomes the "Primary Agent" and is untouched in behavior. A new checkbox list ("Run on Additional Agents") is added to Step 2 of the existing 4-step Run wizard, filtered to OS-compatible, non-primary agents, mirroring the checkbox-list pattern already used by the Campaign modal (`cmp-targets`/`_cmpSel`). `confirmRun()` is extended to compute `[primary, ...checked additional]`, show a richer `confirm()` when 2+ agents are targeted, and dispatch one `POST /api/scenarios/{id}/run` per agent concurrently (`Promise.all` over a per-call normalizer, equivalent to `allSettled` — no request can abort another). The single-agent path's exact copy, toasts, and control flow are preserved unchanged.

**Tech Stack:** Vanilla JS (no framework, no build step), inline in a single HTML file. No JS test runner exists for this file in this repo.

## Global Constraints

- No backend changes. `POST /api/scenarios/{scenarioId}/run` keeps its existing single-`agentId` contract (verified: `internal/api/handlers.go:1216-1235`, decoder has no `DisallowUnknownFields()`, so an added `batchId` field is silently ignored).
- `orchestrator/wwwroot/index.html` and `orchestrator/cmd/server/wwwroot/index.html` are OS-level hardlinks (same inode, identical bytes) but are two separate paths in git. Every edit in this plan must be applied to `orchestrator/wwwroot/index.html`, then verified identical via `diff` against the `cmd/server` copy (hardlink propagation happens automatically on save — `diff` merely confirms it), and both paths must be `git add`ed in the same commit.
- The single-agent run path's existing copy, toasts, and control flow (`confirmRun()`'s telemetry/lab `confirm()` text, the `'Dispatched (' + mode + ') — Run ID: ' + res.runId` toast, `'Run failed: ' + ...` error toast) must remain byte-for-byte unchanged when exactly one agent is targeted — this is the spec's explicit "unchanged for the single-agent case" requirement.
- This repo has no JS unit-test harness for `wwwroot/index.html`. Verification in this plan is: (a) structural `grep` checks that new markup/functions exist, (b) running the Go server locally and `curl`-diffing the served HTML for the new elements, (c) a manual browser checklist for the operator to run before merging (no browser-automation tool is available in this environment, so interactive verification cannot be performed by the implementer — this must be disclosed, not silently skipped).

---

### Task 1: Additional Agents picker — markup, state, and OS-filtered rendering

**Files:**
- Modify: `orchestrator/wwwroot/index.html:3191-3196` (Step 2 wizard pane)
- Modify: `orchestrator/wwwroot/index.html:3712` (modal state vars — add `_addlSel`)
- Modify: `orchestrator/wwwroot/index.html:8163-8204` (`openModal` — reset `_addlSel` on open)
- Modify: `orchestrator/wwwroot/index.html:8208-8218` (`renderRunMode` — call the new render function)
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (same edits, hardlinked twin)

**Interfaces:**
- Consumes: global `agents` array (`{agentId, hostname, osVersion, status}`), global `scenarios` array, existing `cmpAgentOS(a)` helper (`orchestrator/wwwroot/index.html:6367`, returns `'windows'|'darwin'|'linux'`), existing `x(s)` HTML-escape helper, existing `scenarioFramework(sc)` — none modified.
- Produces: `function additionalAgentIds()` returning `string[]` of checked, OS-eligible, non-primary agent IDs **in `agents` array order** (this is the "list order" the spec requires — Task 2 and Task 3 both call this and depend on that ordering guarantee). `function renderAdditionalAgents()` (re-renders the checkbox list; call after any change to primary agent or scenario). `function selectAllAdditionalAgents()`. `function renderAdditionalAgentsCount()`.

- [ ] **Step 1: Add the `_addlSel` state variable**

In `orchestrator/wwwroot/index.html`, find line 3712:
```js
var _runSelection = null;  // {scId, fw:'art'|'caldera', ids:[]} — operator-chosen subset for the next run
```
Add immediately after it:
```js
var _addlSel = {};  // {agentId: true} — checked "Run on Additional Agents" state for the next run
```

- [ ] **Step 2: Add the Additional Agents markup to Step 2 of the wizard**

Find (lines 3191-3196):
```html
      <!-- Step 2: Target -->
      <div class="wz-pane" data-pane="2" style="display:none">
        <label class="modal-lbl">Target Agent</label>
        <select id="modal-agent" onchange="renderRunMode()"></select>
        <p class="sub2" style="margin-top:0.55rem">The endpoint that will execute this run.</p>
      </div>
```
Replace with:
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
Note: the primary agent never appears in this checkbox list by construction (Step 4 filters it out) — this is what makes dedupe structurally unnecessary, per spec.

- [ ] **Step 3: Add the render/select-all/id-collection functions**

Find the end of `renderRunMode` (lines 8300-8310 in the unmodified file):
```js
  // Show variant depth selector for live ART runs only (posture has no variant value).
  var fw = scenarioFramework(sc);
  var variantWrap = document.getElementById('modal-variant-wrap');
  var showVariant = (mode === 'telemetry' || mode === 'lab') && (fw === 'art');
  if (variantWrap) {
    variantWrap.style.display = showVariant ? 'block' : 'none';
    if (showVariant) updateVariantDepthNote();
  }
}
```
Insert the following new functions immediately after that closing `}` (i.e., between `renderRunMode` and the `// updateVariantDepthNote updates...` comment that follows it):

```js
// additionalAgentIds returns checked, OS-eligible, non-primary agent IDs in
// `agents` array order — this ordering is load-bearing: Task 2's review list
// and Task 3's dispatch order both rely on it matching render order exactly.
function additionalAgentIds() {
  var primaryId = document.getElementById('modal-agent').value;
  return agents.filter(function(a) { return a.agentId !== primaryId && _addlSel[a.agentId]; })
               .map(function(a) { return a.agentId; });
}

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

function renderAdditionalAgents() {
  var wrap = document.getElementById('modal-addl-wrap');
  var list = document.getElementById('modal-addl-list');
  if (!wrap || !list) return;
  var eligible = eligibleAdditionalAgents();
  // Prune selections for agents that just became ineligible (scenario or primary
  // agent changed) so additionalAgentIds() never returns a hidden/stale checkbox.
  var eligibleIds = {};
  eligible.forEach(function(a) { eligibleIds[a.agentId] = true; });
  Object.keys(_addlSel).forEach(function(k) { if (!eligibleIds[k]) delete _addlSel[k]; });
  if (!eligible.length) { wrap.style.display = 'none'; return; }
  wrap.style.display = 'block';
  list.innerHTML = eligible.map(function(a) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox" ' + (_addlSel[a.agentId] ? 'checked' : '') +
      ' onchange="_addlSel[\'' + x(a.agentId) + '\']=this.checked;renderAdditionalAgentsCount()">' +
      '<code style="font-size:0.72rem">' + x(a.agentId) + '</code><span class="tiny muted">' + x(a.hostname) + ' · ' + cmpAgentOS(a) + '</span></label>';
  }).join('');
  renderAdditionalAgentsCount();
}

function renderAdditionalAgentsCount() {
  var n = additionalAgentIds().length;
  var el = document.getElementById('modal-addl-cnt');
  if (el) el.textContent = '(' + n + ' selected)';
}

function selectAllAdditionalAgents() {
  eligibleAdditionalAgents().forEach(function(a) { _addlSel[a.agentId] = true; });
  renderAdditionalAgents();
}
```

- [ ] **Step 4: Reset selections when the modal opens, and render on every mode refresh**

Find in `openModal` (around line 8188-8190):
```js
  document.getElementById('modal-mode').value = 'posture'; // always default to safe
  renderRunMode();
```
Replace with:
```js
  document.getElementById('modal-mode').value = 'posture'; // always default to safe
  _addlSel = {};
  renderRunMode();
```

Find the start of `renderRunMode` (around line 8208-8209):
```js
function renderRunMode() {
  renderModalSelection();
```
Replace with:
```js
function renderRunMode() {
  renderModalSelection();
  renderAdditionalAgents();
```

- [ ] **Step 5: Verify the hardlink twin is in sync**

Run:
```bash
diff orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
```
Expected: no output (files identical — the hardlink already propagated the edit). If there is output, the hardlink is broken; apply Steps 1-4 to `orchestrator/cmd/server/wwwroot/index.html` manually.

- [ ] **Step 6: Structural verification**

Run:
```bash
grep -n "additionalAgentIds\|renderAdditionalAgents\|modal-addl-wrap\|Run on Additional Agents" orchestrator/wwwroot/index.html
```
Expected: matches for the new markup IDs and all four new/modified function names.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): add Additional Agents checkbox picker to Run wizard"
```

---

### Task 2: Review step — multi-agent list and posture-subset warning

**Files:**
- Modify: `orchestrator/wwwroot/index.html:8373-8411` (`renderWizardReview`)
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (same edit, hardlinked twin)

**Interfaces:**
- Consumes: `additionalAgentIds()` (Task 1), `agents`, `scenarios`, `scenarioFramework(sc)`, `_runSelection`, existing `row(k, v)` local helper.
- Produces: no new functions — `renderWizardReview()`'s output changes only when `additionalAgentIds().length > 0`.

- [ ] **Step 1: Replace the single "Target agent" row with a conditional multi-agent list**

Find (lines 8373-8411 in the unmodified file):
```js
function renderWizardReview() {
  renderRunMode(); // refresh the OS-mismatch / mode warning + Run button state
  var scId = _modalScId || document.getElementById('modal-sc').value;
  var sc = scenarios.find(function(s) { return s.id === scId; });
  var agSel = document.getElementById('modal-agent');
  var agTxt = (agSel.options[agSel.selectedIndex] || {}).text || agSel.value;
  var modeWrap = document.getElementById('modal-mode-wrap');
  var mode = (modeWrap.style.display !== 'none') ? document.getElementById('modal-mode').value : 'posture';
  var modeLabel = { posture: 'Posture — read-only', telemetry: 'Telemetry — identity-safe', lab: 'Lab — full-fidelity' }[mode] || mode;
  var fw = scenarioFramework(sc);
  var noun = (fw === 'art') ? 'techniques' : (fw === 'caldera') ? 'abilities' : (fw === 'posture') ? 'checks' : 'steps';
  var sel = _runSelection && _runSelection.scId === scId && _runSelection.ids.length;
  var subset = sel
    ? ((_runSelection.locked && _runSelection.ids.length === 1)
        ? _runSelection.ids[0] + ' (targeted re-validate)'
        : _runSelection.ids.length + ' ' + noun + ' (subset)')
    : 'All ' + noun;
  var reasonEl = document.getElementById('modal-reason');
  var reason = (mode !== 'posture' && reasonEl && reasonEl.value.trim()) ? reasonEl.value.trim() : '';
  var row = function(k, v) { return '<div class="wz-rev-row"><span>' + k + '</span><span>' + v + '</span></div>'; };
  var variantDepthEl2 = document.getElementById('modal-variant-depth');
  var variantWrap2 = document.getElementById('modal-variant-wrap');
  var variantLabel = '';
  if (variantDepthEl2 && variantWrap2 && variantWrap2.style.display !== 'none') {
    var vd = variantDepthEl2.value || 'none';
    variantLabel = { none: 'None (base only)', quick: 'Quick (~5 per PS step)', standard: 'Standard (~15 per PS step)', full: 'Full (33 per PS step)' }[vd] || vd;
  }
  var html = row('Scenario', x(sc ? sc.name : scId)) +
             row('Target agent', x(agTxt)) +
             row('Mode', x(modeLabel)) +
             row('Scope', x(subset)) +
             (variantLabel ? row('Variant depth', x(variantLabel)) : '') +
             (reason ? row('Reason', x(reason)) : '');
  var warnEl = document.getElementById('modal-mode-warn');
  if (warnEl.style.display !== 'none' && warnEl.innerHTML.trim()) {
    html += '<div class="wz-rev-warn">' + warnEl.innerHTML + '</div>';
  }
  document.getElementById('wz-review').innerHTML = html;
```
Replace with:
```js
function renderWizardReview() {
  renderRunMode(); // refresh the OS-mismatch / mode warning + Run button state
  var scId = _modalScId || document.getElementById('modal-sc').value;
  var sc = scenarios.find(function(s) { return s.id === scId; });
  var agSel = document.getElementById('modal-agent');
  var agTxt = (agSel.options[agSel.selectedIndex] || {}).text || agSel.value;
  var modeWrap = document.getElementById('modal-mode-wrap');
  var mode = (modeWrap.style.display !== 'none') ? document.getElementById('modal-mode').value : 'posture';
  var modeLabel = { posture: 'Posture — read-only', telemetry: 'Telemetry — identity-safe', lab: 'Lab — full-fidelity' }[mode] || mode;
  var fw = scenarioFramework(sc);
  var noun = (fw === 'art') ? 'techniques' : (fw === 'caldera') ? 'abilities' : (fw === 'posture') ? 'checks' : 'steps';
  var sel = _runSelection && _runSelection.scId === scId && _runSelection.ids.length;
  var subset = sel
    ? ((_runSelection.locked && _runSelection.ids.length === 1)
        ? _runSelection.ids[0] + ' (targeted re-validate)'
        : _runSelection.ids.length + ' ' + noun + ' (subset)')
    : 'All ' + noun;
  var reasonEl = document.getElementById('modal-reason');
  var reason = (mode !== 'posture' && reasonEl && reasonEl.value.trim()) ? reasonEl.value.trim() : '';
  var row = function(k, v) { return '<div class="wz-rev-row"><span>' + k + '</span><span>' + v + '</span></div>'; };
  var variantDepthEl2 = document.getElementById('modal-variant-depth');
  var variantWrap2 = document.getElementById('modal-variant-wrap');
  var variantLabel = '';
  if (variantDepthEl2 && variantWrap2 && variantWrap2.style.display !== 'none') {
    var vd = variantDepthEl2.value || 'none';
    variantLabel = { none: 'None (base only)', quick: 'Quick (~5 per PS step)', standard: 'Standard (~15 per PS step)', full: 'Full (33 per PS step)' }[vd] || vd;
  }
  var addlIds = additionalAgentIds();
  var agentsRow;
  if (addlIds.length) {
    var allIds = [agSel.value].concat(addlIds);
    var names = allIds.map(function(id) {
      var a = agents.find(function(ag) { return ag.agentId === id; });
      return x(a ? (a.agentId + ' — ' + a.hostname) : id);
    });
    agentsRow = '<div class="wz-rev-row"><span>Agents (' + allIds.length + ')</span><span>' + names.join('<br>') + '</span></div>';
  } else {
    agentsRow = row('Target agent', x(agTxt));
  }
  var html = row('Scenario', x(sc ? sc.name : scId)) +
             agentsRow +
             row('Mode', x(modeLabel)) +
             row('Scope', x(subset)) +
             (variantLabel ? row('Variant depth', x(variantLabel)) : '') +
             (reason ? row('Reason', x(reason)) : '');
  var warnEl = document.getElementById('modal-mode-warn');
  if (warnEl.style.display !== 'none' && warnEl.innerHTML.trim()) {
    html += '<div class="wz-rev-warn">' + warnEl.innerHTML + '</div>';
  }
  if (fw === 'posture' && sel && addlIds.length) {
    html += '<div class="wz-rev-warn">This check subset was built from ' + x(agTxt) +
      '\'s catalog — any check not present on other selected agents will report not applicable.</div>';
  }
  document.getElementById('wz-review').innerHTML = html;
```
(The closing `}` of the function is unchanged — do not duplicate it.)

- [ ] **Step 2: Verify the hardlink twin is in sync**

```bash
diff orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
```
Expected: no output.

- [ ] **Step 3: Structural verification**

```bash
grep -n "Agents (' + allIds.length\|built from ' + x(agTxt)" orchestrator/wwwroot/index.html
```
Expected: both lines present.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): show full agent list and posture-subset warning in Run review step"
```

---

### Task 3: Dispatch — confirmation dialogs, concurrent per-agent requests, aggregated result toast

**Files:**
- Modify: `orchestrator/wwwroot/index.html:10707-10746` (`confirmRun`)
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (same edit, hardlinked twin)

**Interfaces:**
- Consumes: `additionalAgentIds()` (Task 1), `agents`, `scenarios`, `scenarioFramework(sc)`, `_runSelection`, `apicall(path, opts)` (`orchestrator/wwwroot/index.html:5389` — resolves to parsed JSON body on any HTTP response, including `{error: "..."}"` bodies; rejects only on session-expiry (401) or network/parse failure), `x(s)`, `showToast(msg, kind)`, `closeModal()`, `showTab(name)`, `loadRuns()`.
- Produces: `function frameworkDisplayName(fw)`, `function genBatchId()`. `confirmRun()`'s external behavior for a single targeted agent is unchanged; for 2+ targeted agents it now shows one richer `confirm()`, dispatches concurrently, and shows one aggregated toast.

- [ ] **Step 1: Replace `confirmRun()`**

Find (lines 10707-10746 in the unmodified file):
```js
function confirmRun() {
  var scenarioId = _modalScId || document.getElementById('modal-sc').value;
  var agentId    = document.getElementById('modal-agent').value;
  if (!scenarioId || !agentId) { showToast('Select scenario and agent', 'err'); return; }
  var modeWrap = document.getElementById('modal-mode-wrap');
  var mode = (modeWrap.style.display !== 'none') ? document.getElementById('modal-mode').value : 'posture';
  var confirmLive = false, confirmLab = false;
  if (mode === 'telemetry') {
    if (!confirm('TELEMETRY mode runs real, identity-safe techniques and WILL generate EDR/SIEM alerts.\n\nProceed only on an approved, monitored target. Continue?')) return;
    confirmLive = true;
  } else if (mode === 'lab') {
    if (!confirm('LAB mode runs FULL-FIDELITY techniques (LSASS dump, allowlisted spray) and will trigger EDR.\n\nISOLATED AD RANGE ONLY — never production. Continue?')) return;
    if (!confirm('Second confirmation required for LAB mode.\n\nConfirm the target is an isolated lab/range with a snapshot?')) return;
    confirmLive = true; confirmLab = true;
  }
  var reasonEl = document.getElementById('modal-reason');
  var reason = (mode !== 'posture' && reasonEl) ? reasonEl.value.trim() : '';
  var variantDepthEl = document.getElementById('modal-variant-depth');
  var variantDepth = (variantDepthEl && document.getElementById('modal-variant-wrap').style.display !== 'none')
    ? variantDepthEl.value : 'none';
  var body = { agentId: agentId, mode: mode, confirmLive: confirmLive, confirmLab: confirmLab,
               reason: reason, variantDepth: variantDepth };
  if (_runSelection && _runSelection.scId === scenarioId && _runSelection.ids.length) {
    if (_runSelection.fw === 'art') body.techniques = _runSelection.ids;
    else if (_runSelection.fw === 'caldera') body.abilities = _runSelection.ids;
    else if (_runSelection.fw === 'steps') body.steps = _runSelection.ids.map(Number);
    else if (_runSelection.fw === 'posture') body.checks = _runSelection.ids;
    if (_runSelection.locked && _runSelection.ids.length === 1) {
      body.runLabel = _runSelection.ids[0] + ' — Re-validate';
    }
  }
  apicall('/api/scenarios/' + encodeURIComponent(scenarioId) + '/run', {
    method: 'POST', body: JSON.stringify(body)
  }).then(function(res) {
    if (res && res.error) { showToast('Run failed: ' + res.error, 'err'); return; }
    closeModal();
    showToast('Dispatched (' + (res.mode || mode) + ') — Run ID: ' + res.runId, 'ok');
    showTab('runs'); loadRuns();
  }).catch(function(e) { showToast('Run failed: ' + e.message, 'err'); });
}
```
Replace with:
```js
function frameworkDisplayName(fw) {
  return { art: 'Atomic Red Team', caldera: 'Caldera', posture: 'Posture Checks', steps: 'Custom Steps' }[fw] || fw || 'Unknown';
}

function genBatchId() {
  if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  return 'batch-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
}

function confirmRun() {
  var scenarioId = _modalScId || document.getElementById('modal-sc').value;
  var primaryId  = document.getElementById('modal-agent').value;
  if (!scenarioId || !primaryId) { showToast('Select scenario and agent', 'err'); return; }
  var agentIds = [primaryId].concat(additionalAgentIds());
  var multi = agentIds.length > 1;

  var sc = scenarios.find(function(s) { return s.id === scenarioId; });
  var modeWrap = document.getElementById('modal-mode-wrap');
  var mode = (modeWrap.style.display !== 'none') ? document.getElementById('modal-mode').value : 'posture';
  var confirmLive = false, confirmLab = false;

  var agentListText = agentIds.map(function(id) {
    var a = agents.find(function(ag) { return ag.agentId === id; });
    return '• ' + (a ? a.agentId + ' — ' + a.hostname : id);
  }).join('\n');
  var header = 'Scenario: ' + (sc ? sc.name : scenarioId) + '\nFramework: ' + frameworkDisplayName(scenarioFramework(sc));

  if (mode === 'telemetry') {
    var telemetryMsg = multi
      ? 'TELEMETRY mode runs real, identity-safe techniques and WILL generate EDR/SIEM alerts.\n\n' +
        header + '\n\nAgents (' + agentIds.length + '):\n' + agentListText +
        '\n\nProceed only on approved, monitored targets. Continue?'
      : 'TELEMETRY mode runs real, identity-safe techniques and WILL generate EDR/SIEM alerts.\n\nProceed only on an approved, monitored target. Continue?';
    if (!confirm(telemetryMsg)) return;
    confirmLive = true;
  } else if (mode === 'lab') {
    var labMsg = multi
      ? 'LAB mode runs FULL-FIDELITY techniques (LSASS dump, allowlisted spray) and will trigger EDR.\n\n' +
        header + '\n\nAgents (' + agentIds.length + '):\n' + agentListText +
        '\n\nISOLATED AD RANGE ONLY — never production. Continue?'
      : 'LAB mode runs FULL-FIDELITY techniques (LSASS dump, allowlisted spray) and will trigger EDR.\n\nISOLATED AD RANGE ONLY — never production. Continue?';
    if (!confirm(labMsg)) return;
    if (!confirm('Second confirmation required for LAB mode.\n\nConfirm the target is an isolated lab/range with a snapshot?')) return;
    confirmLive = true; confirmLab = true;
  } else if (multi) {
    // Posture mode has zero confirmation for a single agent today; a batch of 2+
    // targets is a bigger blast radius, so gate it with one lightweight confirm.
    var postureMsg = 'Run scenario?\n\n' + header + '\n\nAgents (' + agentIds.length + '):\n' + agentListText + '\n\nProceed?';
    if (!confirm(postureMsg)) return;
  }

  var reasonEl = document.getElementById('modal-reason');
  var reason = (mode !== 'posture' && reasonEl) ? reasonEl.value.trim() : '';
  var variantDepthEl = document.getElementById('modal-variant-depth');
  var variantDepth = (variantDepthEl && document.getElementById('modal-variant-wrap').style.display !== 'none')
    ? variantDepthEl.value : 'none';

  var baseBody = { mode: mode, confirmLive: confirmLive, confirmLab: confirmLab,
                    reason: reason, variantDepth: variantDepth, batchId: genBatchId() };
  if (_runSelection && _runSelection.scId === scenarioId && _runSelection.ids.length) {
    if (_runSelection.fw === 'art') baseBody.techniques = _runSelection.ids;
    else if (_runSelection.fw === 'caldera') baseBody.abilities = _runSelection.ids;
    else if (_runSelection.fw === 'steps') baseBody.steps = _runSelection.ids.map(Number);
    else if (_runSelection.fw === 'posture') baseBody.checks = _runSelection.ids;
    if (_runSelection.locked && _runSelection.ids.length === 1) {
      baseBody.runLabel = _runSelection.ids[0] + ' — Re-validate';
    }
  }

  var runBtn = document.getElementById('modal-run-btn');
  if (multi) {
    runBtn.disabled = true;
    runBtn.innerHTML = 'Dispatching to ' + agentIds.length + ' agents…';
  }

  // Each dispatch is independent: a rejected promise or a {error:...} response
  // body is normalized into a resolved {ok:false} result so one agent's failure
  // can never abort or block the others (equivalent to Promise.allSettled).
  var dispatches = agentIds.map(function(agentId) {
    var body = Object.assign({ agentId: agentId }, baseBody);
    return apicall('/api/scenarios/' + encodeURIComponent(scenarioId) + '/run', {
      method: 'POST', body: JSON.stringify(body)
    }).then(function(res) {
      if (res && res.error) return { agentId: agentId, ok: false, error: res.error };
      return { agentId: agentId, ok: true, runId: res && res.runId, mode: res && res.mode };
    }).catch(function(e) {
      return { agentId: agentId, ok: false, error: e.message };
    });
  });

  Promise.all(dispatches).then(function(results) {
    if (multi) { runBtn.disabled = false; runBtn.innerHTML = '&#9654; Run'; }
    var ok = results.filter(function(r) { return r.ok; });
    var failed = results.filter(function(r) { return !r.ok; });

    if (!multi) {
      if (failed.length) { showToast('Run failed: ' + failed[0].error, 'err'); return; }
      closeModal();
      showToast('Dispatched (' + (ok[0].mode || mode) + ') — Run ID: ' + ok[0].runId, 'ok');
      showTab('runs'); loadRuns();
      return;
    }

    closeModal();
    if (!failed.length) {
      showToast('Dispatched to ' + ok.length + ' agents.', 'ok');
    } else if (ok.length) {
      showToast('Dispatched to ' + ok.length + '/' + agentIds.length + ' agents. Failed: ' +
        failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
    } else {
      showToast('All ' + agentIds.length + ' dispatches failed. ' +
        failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
    }
    // Successful runs (if any) are real and worth seeing, same as the single-agent path.
    showTab('runs'); loadRuns();
  });
}
```

- [ ] **Step 2: Verify the hardlink twin is in sync**

```bash
diff orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
```
Expected: no output.

- [ ] **Step 3: Structural verification**

```bash
grep -n "function confirmRun\|function frameworkDisplayName\|function genBatchId\|Dispatching to \|Dispatched to \|dispatches = agentIds.map" orchestrator/wwwroot/index.html
```
Expected: one match each, confirming the new functions and the multi-agent toast strings are present exactly once.

- [ ] **Step 4: Live-server smoke test (structural, not interactive)**

Start a throwaway Postgres + the Go server, following the pattern already used elsewhere in this project:
```bash
docker run -d --name masd-verify -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=bas -p 55440:5432 postgres:16-alpine
```
Wait for Postgres to accept connections (`docker logs masd-verify` shows "database system is ready to accept connections"), then in `orchestrator/`:
```bash
DATABASE_URL="postgres://postgres:postgres@localhost:55440/bas?sslmode=disable" JWT_SECRET=dev-secret BAS_LICENSE_PATH="C:/Users/Administrator/Downloads/Audspect_Cloud/audspect-dev.lic" HTTP_PORT=8099 go run ./cmd/server
```
In a second shell, once the server is up:
```bash
curl -s http://localhost:8099/ | grep -o "Run on Additional Agents\|modal-addl-wrap\|Primary Agent"
```
Expected: all three strings present in the served HTML (confirms the compiled/served page matches the edited source — this project bakes `wwwroot` into the binary at build time in production, but `go run` serves the on-disk file directly, which is what this check validates).

Then stop the server (the compiled child process holds the port, not `go run` itself):
```bash
powershell -Command "Get-NetTCPConnection -LocalPort 8099 | Select-Object -ExpandProperty OwningProcess | ForEach-Object { Stop-Process -Id $_ -Force }"
docker rm -f masd-verify
```

- [ ] **Step 5: Record the manual browser checklist (cannot be executed by the implementer — no browser automation tool is available in this environment)**

Before this branch is merged, a human must verify in an actual browser:
1. Open Run Scenario on a scenario with 3+ compatible online agents. Confirm the Primary Agent select shows every agent, and the "Run on Additional Agents" list never includes whichever agent is currently selected as primary.
2. Change the Primary Agent — confirm the just-selected primary drops out of the Additional Agents list and any previously-checked box for it disappears (no stale duplicate selection).
3. Click "Select all" — confirm every visible additional agent gets checked and the count updates.
4. Advance to Review (Step 4) with 2+ agents checked — confirm the "Agents (N)" row lists Primary first, then additional agents in the same order they appeared in the checkbox list.
5. Click Run in posture mode with 2+ agents — confirm a `confirm()` dialog appears listing the scenario, framework, and agent count/names, and cancelling it leaves the modal open with nothing dispatched.
6. Accept the dialog — confirm the Run button reads "Dispatching to N agents…" briefly, then the modal closes, a toast reports "Dispatched to N agents.", and the Runs tab shows N new runs.
7. Repeat with a scenario that has a posture check-subset customized via "Customize" — confirm the inline warning about the subset being built from the primary agent's catalog appears on the Review step when 2+ agents are targeted.
8. Test a single-agent run (no additional agents checked) end-to-end in posture, telemetry, and lab mode — confirm the dialogs, button label, and toast are byte-for-byte identical to pre-change behavior (no "Dispatching to N agents…" label, no agent list in the confirm dialogs).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): dispatch scenario runs to multiple agents concurrently"
```

---

## Self-Review Notes

**Spec coverage:**
- "Additional Agents" naming, primary excluded from checklist, deterministic Select All → Task 1.
- Preserved dispatch/display ordering (`[primary, ...additional in list order]`) → Task 1 (`additionalAgentIds()`), reused identically in Task 2 and Task 3.
- Confirmation dialog with count, two variants (posture new / telemetry+lab merged), lab's second confirm unchanged → Task 3.
- Customized-subset warning note → Task 2.
- Progress label + independent per-agent dispatch + aggregated toast (3 formats) → Task 3.
- Forward-compat `batchId`, no backend change → Task 3 (`genBatchId()`, included in `baseBody` for every dispatch, single or multi).
- Out-of-scope items (backend `batchId` persistence, live per-agent checklist, OS/env filter dropdowns, Campaign flow changes) — no task touches any of them, confirmed by the diff scope above (only `confirmRun`, `renderRunMode`, `renderWizardReview`, `openModal`, and new standalone functions).

**Placeholder scan:** none — every step contains complete, runnable code or an exact shell command with expected output.

**Type/name consistency:** `additionalAgentIds()` (Task 1) is called with that exact name and no arguments in Task 2 and Task 3. `frameworkDisplayName(fw)` and `genBatchId()` (Task 3) are used nowhere else. `_addlSel` (Task 1) is read/written only inside Task 1's functions and the inline `onchange` handler generated by `renderAdditionalAgents()` — no other task touches it directly.
