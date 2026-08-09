# Scheduled Assessments UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Scheduled Assessments page in the orchestrator dashboard — a nav tab that lists existing schedules and a wizard modal to create new ones — consuming the already-shipped `POST/GET /api/scheduled-assessments` and `POST /api/scheduled-assessments/{id}/cancel` endpoints.

**Architecture:** Pure frontend addition to the single-file dashboard (`orchestrator/wwwroot/index.html`, HTML+CSS+vanilla JS, no build step, no framework). One new nav tab (list view) plus one new wizard modal (create flow), following exactly the patterns the file already uses elsewhere: `nav-item`/`showTab`/`tab-<name>` for tab routing, `.overlay`/`.modal.wz-modal` for the wizard, a per-feature state object (like the existing `VF` object for Verification) for the new JS. No backend changes — the API is complete.

**Tech Stack:** Vanilla JS (ES5-style, matching the rest of the file — `var`, no arrow functions, no template literals used elsewhere in this file's JS), inline CSS reuse, `fetch`-based `apicall()` helper already defined in the file.

## Global Constraints

- Frontend-only. Do not modify any `.go` file in this plan.
- Do not modify the existing Run Scenario wizard (`run-overlay`, `wizardSet`, `confirmRun`, `_wzStep`/`_wzMin`, `data-pane`/`data-pip` attributes) or the existing single-select Agents-tab group tree (`agentGroupTree`, `renderAgentGroupTree`, `renderAgentGroupNode`, `#agent-tree-root`, `activeAgentGroupId`). Both are read-only precedent; write new, separately-named functions and DOM ids for the new feature.
- `jobs.Schedule` (the API's list/get response shape) has no JSON struct tags — it marshals with exact Go field names: `ID, Type, Payload, AgentIDs, DayOfWeek, TimeOfDay, Timezone, Enabled, CreatedBy, CreatedAt, LastOccurrenceAt, LastSpawnedJobID, RecurrenceType, RunAt, DayOfMonth, EndDate, ConcurrencyLimit, GroupIDs, Mode, ApprovedBy, ApprovedAt, ApprovalVersion, Reason`. JS must read these exact PascalCase keys — do not assume camelCase.
- The create payload (POST body) uses camelCase per `scheduled_assessment_handlers.go`'s request struct: `scenarioId, mode, agentIds, groupIds, recurrenceType, runAt, dayOfWeek, dayOfMonth, timeOfDay, timezone, endDate, concurrencyLimit, reason`. Do not send `techniques`/`steps` — V1 always schedules the full scenario (per spec Non-goals).
- No subset/Customize picker. No schedule editing (create + cancel only). No computed "next run" — display only the stored recurrence rule and `LastOccurrenceAt`, never a predicted next-fire time.
- Telemetry mode is only ever shown as a selectable option when `ROLE === 'admin'`. Every existing schedule (including ones created by an Admin) is still visible and readable to Analysts in the list.
- No automated test suite exists for this file. Each task's verification step is (a) a Node.js syntax check of the file's single inline `<script>` block and (b) precise DOM-shape assertions to read back with the `Read` tool. Full click-through browser QA is out of scope for this plan (tracked in the project's existing Pending Manual QA Backlog) — do not invent a JS test framework or a headless-browser test step.

---

## File Structure

Everything in this plan touches exactly one file: `orchestrator/wwwroot/index.html`. There is no per-feature file split in this codebase's frontend (it is deliberately one file — see the existing `VF`/Verification and `agentGroupTree`/Agents features, both entirely inline in the same file), so this plan follows that convention rather than introducing a new one.

Within that one file, five kinds of edits recur across tasks:
1. **Nav markup** (~line 1301) — one new `nav-item`.
2. **Tab content markup** (~line 2449) — one new `<div id="tab-scheduled-assessments">`.
3. **Wiring** — `TAB_TITLES` (~line 4275), `activateTab`'s tab-name array (~line 4408), `showTab()` (~line 4506), `bootApp()`'s role-visibility block (~line 4351).
4. **Modal markup** (~line 3746, right after the Run wizard's closing `</div></div>`) — one new `<div id="sched-overlay" class="overlay">` wizard.
5. **JS** — one new contiguous block, all functions prefixed `sched`/`Sched`/`SCHED`, added just before the closing `</script>` tag (currently line 16167) so it never has to be threaded between unrelated existing functions.

Because tasks insert code sequentially, later tasks' line numbers will have shifted from what's written here. Every step below identifies its insertion point by **exact surrounding text** (for use with an exact-match string edit), not by line number — re-locate the anchor text with a search before editing if a line number mentioned in prose looks off.

## Verification helper (used by every task)

Every task's syntax-check step runs this same two-line command. It extracts the file's single inline `<script>...</script>` block (confirmed to be the only `<script>` tag in the file, spanning from the line after `<script>` to the line before `</script>`) and asks Node to parse it without executing it:

```bash
cd "orchestrator/wwwroot"
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/sched-ui-check.js
node --check /tmp/sched-ui-check.js
```

Expected on success: no output, exit code 0. On failure: Node prints a `SyntaxError` with a line number *relative to the extracted file* — subtract the line number of `<script>` in `index.html` (currently 4270) plus 1 to map it back to the real file.

---

### Task 1: Nav entry, tab shell, and read-only list view

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `apicall(path, opts)` (existing, returns a Promise of parsed JSON), `x(s)` (existing HTML-escape), `fmtDate(iso)` (existing, `new Date(iso).toLocaleString()` or `'—'`), `showToast(msg, type)` (existing), the global `scenarios` array (existing, populated by `loadScenarios()`, each item has `.id` and `.name`), the global `ROLE` string (existing).
- Produces: `SCHED` state object, `loadScheduledAssessments()`, `renderScheduledAssessmentsList()`, `schedRecurrenceText(sch)`, `schedTargetsText(sch)`, `schedFlattenGroupNames(nodes, map)`. Later tasks (2-6) extend `SCHED` and call these.

- [ ] **Step 1: Add the nav item**

In `orchestrator/wwwroot/index.html`, find this exact block (the Live Runs nav item, immediately followed by the Campaigns nav item):

```html
        <div class="nav-item" data-tab="runs" onclick="showTab('runs')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <polygon points="3,2 13,8 3,14" stroke-linejoin="round"/>
          </svg>
          Live Runs
        </div>
        <div class="nav-item" data-tab="campaigns" onclick="showTab('campaigns')">
```

Replace it with (inserting the new nav item between the two, hidden by default — visibility is turned on per-role in Step 4):

```html
        <div class="nav-item" data-tab="runs" onclick="showTab('runs')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <polygon points="3,2 13,8 3,14" stroke-linejoin="round"/>
          </svg>
          Live Runs
        </div>
        <div class="nav-item" id="nav-scheduled-assessments" data-tab="scheduled-assessments" onclick="showTab('scheduled-assessments')" style="display:none">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <circle cx="8" cy="8" r="6"/><path d="M8 4.5V8l2.5 1.5"/>
          </svg>
          Scheduled Assessments
        </div>
        <div class="nav-item" data-tab="campaigns" onclick="showTab('campaigns')">
```

- [ ] **Step 2: Add the tab content shell**

Find this exact block (the end of `tab-runs`, immediately followed by the Campaigns tab comment and opening div):

```html
            <tbody id="runs-body">
              <tr><td colspan="9" class="empty">No runs yet.</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Campaigns -->
      <div id="tab-campaigns" style="display:none">
```

Replace it with:

```html
            <tbody id="runs-body">
              <tr><td colspan="9" class="empty">No runs yet.</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Scheduled Assessments -->
      <div id="tab-scheduled-assessments" style="display:none">
        <div class="sec-hdr">
          <h2>Scheduled Assessments <span id="sched-cnt" class="cnt">0</span></h2>
          <button class="btn btn-outline btn-sm" onclick="loadScheduledAssessments()">Refresh</button>
        </div>
        <div class="tbl-wrap">
          <table>
            <thead><tr>
              <th>Assessment</th><th>Mode</th><th>Targets</th><th>Recurrence</th>
              <th>Last run</th><th>Status</th><th></th>
            </tr></thead>
            <tbody id="sched-body">
              <tr><td colspan="7" class="empty">Loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Campaigns -->
      <div id="tab-campaigns" style="display:none">
```

- [ ] **Step 3: Wire tab routing**

Find this exact line (in `TAB_TITLES`):

```html
var TAB_TITLES = { dashboard:'Dashboard', agents:'Agents', scenarios:'Scenarios', runs:'Live Runs', campaigns:'Campaigns', coverage:'ATT&CK Coverage', findings:'Findings', remediation:'Remediation', reports:'Reports', verification:'Detection Verification', users:'Users', compliance:'Compliance', settings:'Settings', variants:'Variant Executor', em:'Endpoint Mastery', exposure:'Exposure Explorer', recommendations:'Recommendations', exercises:'Exercises', 'attack-coverage':'Technique Coverage', 'threat-priority':'Threat Prioritization', iocs:'IOC Registry' };
```

Replace `runs:'Live Runs',` with `runs:'Live Runs', 'scheduled-assessments':'Scheduled Assessments',` (same line, one insertion).

Find this exact block (`activateTab`'s hardcoded tab-name array):

```js
function activateTab(name) {
  ['dashboard','agents','scenarios','runs','campaigns','coverage','findings','remediation','reports','verification','compliance','settings','variants','em','attackpath','exposure','recommendations','integrations','exercises','attack-coverage','threat-priority','iocs'].forEach(function(t) {
```

Replace `'runs','campaigns'` with `'runs','scheduled-assessments','campaigns'` (same line, one insertion).

Find this exact line (in `showTab`):

```js
  if (name === 'campaigns') closeCampaignDetail();
```

Replace it with:

```js
  if (name === 'campaigns') closeCampaignDetail();
  if (name === 'scheduled-assessments') loadScheduledAssessments();
```

- [ ] **Step 4: Wire role-based nav visibility**

Find this exact block (in `bootApp`, the Integrations nav-item admin-only toggle):

```js
  // Integrations nav — admin only
  var navInt = document.getElementById('nav-integrations');
  if (navInt) navInt.style.display = ROLE === 'admin' ? '' : 'none';
```

Replace it with:

```js
  // Integrations nav — admin only
  var navInt = document.getElementById('nav-integrations');
  if (navInt) navInt.style.display = ROLE === 'admin' ? '' : 'none';
  // Scheduled Assessments nav — Analyst+Admin (same tier the API itself requires)
  var navSched = document.getElementById('nav-scheduled-assessments');
  if (navSched) navSched.style.display = (ROLE === 'admin' || ROLE === 'analyst') ? '' : 'none';
```

- [ ] **Step 5: Add the list-rendering JS**

Find the end of the file's inline script — the exact last two lines are:

```html
})();
</script>
```

(This is the file's closing IIFE-and-tag pair; confirm by reading the last 5 lines of the file before editing — if the exact trailing content differs from this, insert immediately before the `</script>` tag instead, wherever it is.)

Insert this new block immediately before `</script>` (i.e., right after whatever the second-to-last statement in the file currently is):

```js
// ── Scheduled Assessments ──────────────────────────────────────────────────
// List + create + cancel for POST/GET /api/scheduled-assessments and
// POST /api/scheduled-assessments/{id}/cancel. jobs.Schedule has no JSON
// struct tags server-side, so every field read off a schedule object below
// uses the exact Go field name (PascalCase), not camelCase.
var SCHED = {
  schedules: [],   // raw list from GET /api/scheduled-assessments
  groups: [],      // nested group tree, fetched fresh when the wizard opens
  groupsById: {},  // flat id -> name, built from `groups`
  agentsAll: [],   // flat agent list, fetched fresh when the wizard opens
  selGroups: {},   // groupId -> true for wizard checkbox state
  selAgents: {},   // agentId -> true for wizard checkbox state
  step: 1
};

function loadScheduledAssessments() {
  apicall('/api/scheduled-assessments').then(function(res) {
    SCHED.schedules = (res && res.schedules) || [];
    renderScheduledAssessmentsList();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function schedFlattenGroupNames(nodes, map) {
  (nodes || []).forEach(function(n) {
    map[n.id] = n.name;
    if (n.children && n.children.length) schedFlattenGroupNames(n.children, map);
  });
  return map;
}

var SCHED_DOW = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];

function schedRecurrenceText(sch) {
  var tz = sch.Timezone || 'UTC';
  var type = sch.RecurrenceType || 'weekly';
  if (type === 'once') {
    return 'Once · ' + (sch.RunAt ? new Date(sch.RunAt).toLocaleString() : '—') + ' · ' + tz;
  }
  if (type === 'daily') {
    return 'Daily · ' + (sch.TimeOfDay || '—') + ' · ' + tz;
  }
  if (type === 'monthly') {
    return 'Monthly · Day ' + sch.DayOfMonth + ' · ' + (sch.TimeOfDay || '—') + ' · ' + tz;
  }
  // '' aliases to weekly, matching the backend's nextOccurrenceSince aliasing.
  return 'Weekly · ' + (SCHED_DOW[sch.DayOfWeek] || '—') + ' · ' + (sch.TimeOfDay || '—') + ' · ' + tz;
}

function schedTargetsText(sch) {
  var parts = [];
  var groupIds = sch.GroupIDs || [];
  if (groupIds.length) {
    var names = groupIds.map(function(id) { return SCHED.groupsById[id] || ('#' + id); });
    parts.push(names.join(', '));
  }
  var agentCount = (sch.AgentIDs || []).length;
  if (agentCount) parts.push(agentCount + ' agent' + (agentCount === 1 ? '' : 's'));
  return parts.length ? parts.join(' + ') : '—';
}

function renderScheduledAssessmentsList() {
  document.getElementById('sched-cnt').textContent = SCHED.schedules.length;
  var tbody = document.getElementById('sched-body');
  if (!SCHED.schedules.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">No scheduled assessments yet.</td></tr>';
    return;
  }
  tbody.innerHTML = SCHED.schedules.map(function(sch) {
    var payload = {};
    try { payload = JSON.parse(sch.Payload || '{}'); } catch (e) { payload = {}; }
    var sc = scenarios.find(function(s) { return s.id === payload.scenarioId; });
    var name = sc ? sc.name : (payload.scenarioId || '—');
    var modeColor = sch.Mode === 'telemetry' ? 'var(--warning)' : 'var(--muted)';
    var modeLabel = sch.Mode === 'telemetry' ? 'Telemetry' : 'Posture';
    var statusColor = sch.Enabled ? 'var(--success)' : 'var(--muted)';
    var statusLabel = sch.Enabled ? 'Enabled' : 'Cancelled';
    var lastRun = sch.LastOccurrenceAt ? fmtDate(sch.LastOccurrenceAt) : 'Never';
    return '<tr>' +
      '<td>' + x(name) + '</td>' +
      '<td><span class="badge" style="color:' + modeColor + ';border-color:' + modeColor + '">' + modeLabel + '</span></td>' +
      '<td>' + x(schedTargetsText(sch)) + '</td>' +
      '<td>' + x(schedRecurrenceText(sch)) + '</td>' +
      '<td>' + x(lastRun) + '</td>' +
      '<td><span class="badge" style="color:' + statusColor + ';border-color:' + statusColor + '">' + statusLabel + '</span></td>' +
      '<td></td>' +
    '</tr>';
  }).join('');
}
```

- [ ] **Step 6: Syntax-check**

```bash
cd "orchestrator/wwwroot"
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/sched-ui-check.js
node --check /tmp/sched-ui-check.js
```

Expected: no output, exit code 0.

- [ ] **Step 7: Read back the edited regions to confirm well-formed HTML**

Use the `Read` tool on `orchestrator/wwwroot/index.html` around the nav insertion and tab-content insertion (search for `id="nav-scheduled-assessments"` and `id="tab-scheduled-assessments"` to find current line numbers) and confirm every opened `<div>` in the pasted blocks has a matching `</div>`, matching the sibling tabs' structure exactly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): Scheduled Assessments nav tab and read-only list view"
```

---

### Task 2: Cancel action

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `SCHED.schedules`, `renderScheduledAssessmentsList()`, `apicall()`, `showToast()` (all from Task 1).
- Produces: `cancelScheduledAssessment(id)`. Modifies `renderScheduledAssessmentsList()`'s Actions cell (last task allowed to touch that function's row-building logic before Task 6 reads it as an established interface).

- [ ] **Step 1: Add the Cancel button to each row**

Find this exact line (the empty Actions cell from Task 1):

```js
      '<td></td>' +
    '</tr>';
```

Replace it with:

```js
      '<td>' + (sch.Enabled ? '<button class="btn btn-outline btn-sm" onclick="cancelScheduledAssessment(\'' + x(sch.ID) + '\')">Cancel</button>' : '') + '</td>' +
    '</tr>';
```

- [ ] **Step 2: Add the cancel function**

Find the `renderScheduledAssessmentsList` function's closing brace — the exact text is:

```js
    '</tr>';
  }).join('');
}
```

(This now appears once, at the end of `renderScheduledAssessmentsList` from Task 1 Step 5 as modified by this task's Step 1.) Insert immediately after it:

```js

function cancelScheduledAssessment(id) {
  if (!confirm('Cancel this scheduled assessment? It will stop firing future runs; the schedule stays visible in this list as Cancelled.')) return;
  apicall('/api/scheduled-assessments/' + encodeURIComponent(id) + '/cancel', { method: 'POST' }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    showToast('Schedule cancelled', 'ok');
    loadScheduledAssessments();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

- [ ] **Step 3: Syntax-check**

```bash
cd "orchestrator/wwwroot"
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/sched-ui-check.js
node --check /tmp/sched-ui-check.js
```

Expected: no output, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): Scheduled Assessments cancel action"
```

---

### Task 3: Create wizard shell (modal, step navigation, Step 1 Scenario)

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `SCHED` (Task 1), `scenarios` global array, `x()`, `showToast()`, the `.overlay`/`.modal.wz-modal`/`.wz-steps`/`.wz-pip`/`.wz-pip-n`/`.wz-actions` CSS classes (existing, generic — reused visually, not by sharing IDs with the Run wizard).
- Produces: the `#sched-overlay` modal DOM, `openSchedWizard()`, `closeSchedWizard()`, `schedWizardSet(step)`, `schedWizardNav(dir)`. `SCHED.step`. Adds the "+ New Schedule" button to the list header (wired to `openSchedWizard()`), since a button pointing at a function must land in the same task as that function's definition. Tasks 4-6 add panes 2-4's content into the pane shells this task creates and extend `schedWizardSet`'s step===N side effects.

**Note on why this is a separate wizard, not a reuse of the Run wizard:** the Run wizard's step navigation (`wizardSet`, `_wzStep`/`_wzMin`, `data-pane`/`data-pip` attribute selectors) is `document.querySelector`-based and global to the whole document — a second modal reusing `data-pane="1"` etc. would collide (chosen deliberately in the design spec; see "Create flow — dedicated wizard modal" in the design doc).

- [ ] **Step 1: Add the "+ New Schedule" button**

Find this exact block (from Task 1 Step 2, the list header):

```html
        <div class="sec-hdr">
          <h2>Scheduled Assessments <span id="sched-cnt" class="cnt">0</span></h2>
          <button class="btn btn-outline btn-sm" onclick="loadScheduledAssessments()">Refresh</button>
        </div>
```

Replace it with:

```html
        <div class="sec-hdr">
          <h2>Scheduled Assessments <span id="sched-cnt" class="cnt">0</span></h2>
          <div style="display:flex;gap:0.5rem">
            <button class="btn btn-outline btn-sm" onclick="loadScheduledAssessments()">Refresh</button>
            <button class="btn btn-primary btn-sm" onclick="openSchedWizard()">+ New Schedule</button>
          </div>
        </div>
```

- [ ] **Step 2: Add the modal markup**

Find this exact block (the end of the Run wizard modal, immediately followed by the Response Action modal):

```html
    <div class="modal-actions wz-actions">
      <button class="btn btn-outline btn-sm" onclick="closeModal()">Cancel</button>
      <span style="flex:1"></span>
      <button id="wz-back" class="btn btn-outline btn-sm" onclick="wizardNav(-1)" style="display:none">&#8592; Back</button>
      <button id="wz-next" class="btn btn-primary btn-sm" onclick="wizardNav(1)">Next &#8594;</button>
      <button id="modal-run-btn" class="btn btn-outline-green btn-sm" onclick="confirmRun()" style="display:none">&#9654; Run</button>
    </div>
  </div>
</div>

<!-- Response Action Modal (Isolate / Release / Kill Process / Quarantine File) -->
```

Replace it with (appending the new modal after the Run wizard's closing `</div></div>`, before the Response Action comment):

```html
    <div class="modal-actions wz-actions">
      <button class="btn btn-outline btn-sm" onclick="closeModal()">Cancel</button>
      <span style="flex:1"></span>
      <button id="wz-back" class="btn btn-outline btn-sm" onclick="wizardNav(-1)" style="display:none">&#8592; Back</button>
      <button id="wz-next" class="btn btn-primary btn-sm" onclick="wizardNav(1)">Next &#8594;</button>
      <button id="modal-run-btn" class="btn btn-outline-green btn-sm" onclick="confirmRun()" style="display:none">&#9654; Run</button>
    </div>
  </div>
</div>

<!-- Scheduled Assessment Wizard -->
<div id="sched-overlay" class="overlay">
  <div class="modal wz-modal">
    <h3>New Scheduled Assessment</h3>
    <div class="wz-steps">
      <div class="wz-pip" data-sched-pip="1"><span class="wz-pip-n">1</span><span>Scenario</span></div>
      <div class="wz-pip" data-sched-pip="2"><span class="wz-pip-n">2</span><span>Targets</span></div>
      <div class="wz-pip" data-sched-pip="3"><span class="wz-pip-n">3</span><span>Mode &amp; Recurrence</span></div>
      <div class="wz-pip" data-sched-pip="4"><span class="wz-pip-n">4</span><span>Review</span></div>
    </div>

    <div class="wz-body">
      <!-- Step 1: Scenario -->
      <div class="wz-pane" data-sched-pane="1">
        <label class="modal-lbl">Scenario</label>
        <select id="sched-scenario"></select>
        <p class="sub2" style="margin-top:0.55rem">The full scenario runs on every occurrence — there is no per-run technique subset in a schedule.</p>
      </div>

      <!-- Step 2: Targets (Task 4) -->
      <div class="wz-pane" data-sched-pane="2" style="display:none">
        <div id="sched-targets-pane"></div>
      </div>

      <!-- Step 3: Mode & Recurrence (Task 5) -->
      <div class="wz-pane" data-sched-pane="3" style="display:none">
        <div id="sched-mode-recurrence-pane"></div>
      </div>

      <!-- Step 4: Review & Authorize (Task 6) -->
      <div class="wz-pane" data-sched-pane="4" style="display:none">
        <div id="sched-review"></div>
      </div>
    </div>

    <div class="modal-actions wz-actions">
      <button class="btn btn-outline btn-sm" onclick="closeSchedWizard()">Cancel</button>
      <span style="flex:1"></span>
      <button id="sched-wz-back" class="btn btn-outline btn-sm" onclick="schedWizardNav(-1)" style="display:none">&#8592; Back</button>
      <button id="sched-wz-next" class="btn btn-primary btn-sm" onclick="schedWizardNav(1)">Next &#8594;</button>
      <button id="sched-create-btn" class="btn btn-outline-green btn-sm" onclick="submitScheduledAssessment()" style="display:none">Create Schedule</button>
    </div>
  </div>
</div>

<!-- Response Action Modal (Isolate / Release / Kill Process / Quarantine File) -->
```

- [ ] **Step 3: Add the wizard open/close/navigation JS**

Insert immediately before the closing `</script>` tag (after the block Task 1/2 added):

```js

function openSchedWizard() {
  SCHED.selGroups = {}; SCHED.selAgents = {};
  var sel = document.getElementById('sched-scenario');
  sel.innerHTML = scenarios.map(function(s) { return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>'; }).join('');
  document.getElementById('sched-overlay').classList.add('open');
  schedWizardSet(1);
}

function closeSchedWizard() {
  document.getElementById('sched-overlay').classList.remove('open');
}

function schedWizardSet(step) {
  if (step < 1) step = 1;
  if (step > 4) step = 4;
  SCHED.step = step;
  [1, 2, 3, 4].forEach(function(n) {
    var pane = document.querySelector('[data-sched-pane="' + n + '"]');
    if (pane) pane.style.display = (n === step) ? 'block' : 'none';
    var pip = document.querySelector('[data-sched-pip="' + n + '"]');
    if (pip) { pip.classList.toggle('active', n === step); pip.classList.toggle('done', n < step); }
  });
  document.getElementById('sched-wz-back').style.display = (step > 1) ? '' : 'none';
  document.getElementById('sched-wz-next').style.display = (step < 4) ? '' : 'none';
  document.getElementById('sched-create-btn').style.display = (step === 4) ? '' : 'none';
}

function schedWizardNav(dir) { schedWizardSet(SCHED.step + dir); }
```

- [ ] **Step 4: Syntax-check**

```bash
cd "orchestrator/wwwroot"
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/sched-ui-check.js
node --check /tmp/sched-ui-check.js
```

Expected: no output, exit code 0.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): Scheduled Assessments create-wizard shell and Scenario step"
```

---

### Task 4: Targets step (group + agent multi-select)

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `SCHED.selGroups`, `SCHED.selAgents`, `SCHED.groups`, `SCHED.groupsById`, `SCHED.agentsAll`, `schedFlattenGroupNames` (Task 1), `openSchedWizard()`/`schedWizardSet` (Task 3), `x()`, `apicall()`, the `.at-node`/`.at-children` CSS classes (existing, visual only — this task does not touch `renderAgentGroupTree`/`renderAgentGroupNode`, it writes new functions).
- Produces: `renderSchedTargetsPane()`, `renderSchedGroupTree()`, `renderSchedGroupNode(node)`, `renderSchedAgentList()`, `schedToggleGroup(id, checked)`, `schedToggleAgent(id, checked)`. Task 6's payload assembly reads `SCHED.selGroups`/`SCHED.selAgents` (both `{id: true}` maps — `Object.keys(...).map(Number)` or as-is for the POST body's `groupIds`/`agentIds` arrays).

- [ ] **Step 1: Fill in the Targets pane markup**

Find this exact block (the Step-2 pane placeholder from Task 3):

```html
      <!-- Step 2: Targets (Task 4) -->
      <div class="wz-pane" data-sched-pane="2" style="display:none">
        <div id="sched-targets-pane"></div>
      </div>
```

Replace it with:

```html
      <!-- Step 2: Targets -->
      <div class="wz-pane" data-sched-pane="2" style="display:none">
        <label class="modal-lbl">Target groups <span class="tiny muted" id="sched-group-cnt">(0 selected)</span></label>
        <div id="sched-group-tree" style="max-height:180px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius);padding:0.4rem"></div>
        <p class="sub2" style="margin-top:0.4rem">Groups are resolved live at execution time — agents added to a selected group later are automatically included in future runs.</p>

        <label class="modal-lbl" style="margin-top:0.9rem;display:block">Individual agents <span class="tiny muted" id="sched-agent-cnt">(0 selected)</span></label>
        <div id="sched-agent-list" style="max-height:180px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius);padding:0.4rem"></div>
        <p class="sub2" style="margin-top:0.4rem">Individual agents are explicitly included in this schedule regardless of group membership.</p>
      </div>
```

- [ ] **Step 2: Fetch groups/agents when the wizard opens, and render the Targets pane**

Find this exact block (from Task 3 Step 3, `openSchedWizard`):

```js
function openSchedWizard() {
  SCHED.selGroups = {}; SCHED.selAgents = {};
  var sel = document.getElementById('sched-scenario');
  sel.innerHTML = scenarios.map(function(s) { return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>'; }).join('');
  document.getElementById('sched-overlay').classList.add('open');
  schedWizardSet(1);
}
```

Replace it with:

```js
function openSchedWizard() {
  SCHED.selGroups = {}; SCHED.selAgents = {};
  var sel = document.getElementById('sched-scenario');
  sel.innerHTML = scenarios.map(function(s) { return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>'; }).join('');
  Promise.all([apicall('/api/agent-groups'), apicall('/api/agents')]).then(function(res) {
    SCHED.groups = Array.isArray(res[0]) ? res[0] : [];
    SCHED.groupsById = schedFlattenGroupNames(SCHED.groups, {});
    SCHED.agentsAll = Array.isArray(res[1]) ? res[1] : [];
    renderSchedGroupTree();
    renderSchedAgentList();
  }).catch(function(e) { showToast(e.message, 'err'); });
  document.getElementById('sched-overlay').classList.add('open');
  schedWizardSet(1);
}
```

- [ ] **Step 3: Add the group tree and agent list rendering JS**

Insert immediately before the closing `</script>` tag:

```js

function schedToggleGroup(id, checked) {
  if (checked) SCHED.selGroups[id] = true; else delete SCHED.selGroups[id];
  document.getElementById('sched-group-cnt').textContent = '(' + Object.keys(SCHED.selGroups).length + ' selected)';
}

function schedToggleAgent(id, checked) {
  if (checked) SCHED.selAgents[id] = true; else delete SCHED.selAgents[id];
  document.getElementById('sched-agent-cnt').textContent = '(' + Object.keys(SCHED.selAgents).length + ' selected)';
}

function renderSchedGroupTree() {
  var root = document.getElementById('sched-group-tree');
  if (!root) return;
  if (!SCHED.groups.length) { root.innerHTML = '<div class="empty">No agent groups defined.</div>'; return; }
  root.innerHTML = SCHED.groups.map(renderSchedGroupNode).join('');
}

function renderSchedGroupNode(node) {
  var hasChildren = node.children && node.children.length;
  var checked = SCHED.selGroups[node.id] ? ' checked' : '';
  var html = '<div class="at-node">' +
    '<label style="display:flex;align-items:center;gap:6px;cursor:pointer;width:100%">' +
    '<input type="checkbox"' + checked + ' onchange="schedToggleGroup(' + node.id + ',this.checked)">' +
    '<span class="at-name">' + x(node.name) + '</span>' +
    '<span class="at-count">' + node.totalAgentCount + '</span>' +
    '</label></div>';
  if (hasChildren) {
    html += '<div class="at-children">' + node.children.map(renderSchedGroupNode).join('') + '</div>';
  }
  return html;
}

function renderSchedAgentList() {
  var root = document.getElementById('sched-agent-list');
  if (!root) return;
  if (!SCHED.agentsAll.length) { root.innerHTML = '<div class="empty">No agents registered.</div>'; return; }
  root.innerHTML = SCHED.agentsAll.map(function(a) {
    var checked = SCHED.selAgents[a.agentId] ? ' checked' : '';
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox"' + checked + ' onchange="schedToggleAgent(\'' + x(a.agentId) + '\',this.checked)">' +
      '<code style="font-size:0.72rem">' + x(a.agentId) + '</code><span class="tiny muted">' + x(a.hostname) + '</span></label>';
  }).join('');
}
```

- [ ] **Step 4: Syntax-check**

```bash
cd "orchestrator/wwwroot"
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/sched-ui-check.js
node --check /tmp/sched-ui-check.js
```

Expected: no output, exit code 0.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): Scheduled Assessments Targets step (group + agent multi-select)"
```

---

### Task 5: Mode & Recurrence step

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `ROLE` global, `SCHED`, `x()`, `schedWizardSet`/pane markup (Task 3).
- Produces: `renderSchedModeRecurrencePane()`, `schedOnModeChange()`, `schedOnRecurrenceChange()`. Called once, the first time step 3 is shown (wired into `schedWizardSet` below), so the Mode dropdown's Telemetry option is (re)built fresh against the current `ROLE` every time the wizard opens — a stale build from a previous session/role can never leak through. Task 6 reads the field values this task creates by exact element id: `sched-mode`, `sched-reason`, `sched-recurrence-type`, `sched-runat`, `sched-timeofday`, `sched-dow`, `sched-dom`, `sched-timezone`, `sched-enddate`, `sched-concurrency`.

- [ ] **Step 1: Fill in the Mode & Recurrence pane markup**

Find this exact block (the Step-3 pane placeholder from Task 3):

```html
      <!-- Step 3: Mode & Recurrence (Task 5) -->
      <div class="wz-pane" data-sched-pane="3" style="display:none">
        <div id="sched-mode-recurrence-pane"></div>
      </div>
```

Replace it with:

```html
      <!-- Step 3: Mode & Recurrence -->
      <div class="wz-pane" data-sched-pane="3" style="display:none">
        <label class="modal-lbl">Execution mode</label>
        <select id="sched-mode" onchange="schedOnModeChange()"></select>
        <div id="sched-mode-warn" style="display:none;margin-top:0.6rem;padding:0.6rem 0.75rem;border-radius:var(--radius);font-size:0.78rem;line-height:1.45;border:1px solid rgba(210,153,34,0.5);background:rgba(210,153,34,0.08);color:var(--warning)">This assessment executes real, alert-generating techniques against the selected targets and will run unattended.</div>
        <div id="sched-reason-wrap" style="display:none;margin-top:0.6rem">
          <label class="modal-lbl">Reason / authorization basis (required, audited)</label>
          <input type="text" id="sched-reason" placeholder="e.g. Approved recurring detection validation — CR-1234" autocomplete="off"
                 style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">
        </div>

        <label class="modal-lbl" style="margin-top:0.9rem;display:block">Recurrence</label>
        <select id="sched-recurrence-type" onchange="schedOnRecurrenceChange()">
          <option value="once">Once</option>
          <option value="daily">Daily</option>
          <option value="weekly" selected>Weekly</option>
          <option value="monthly">Monthly</option>
        </select>

        <div id="sched-once-wrap" style="display:none;margin-top:0.6rem">
          <label class="modal-lbl">Date &amp; time</label>
          <input type="datetime-local" id="sched-runat" style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">
        </div>

        <div id="sched-dow-wrap" style="margin-top:0.6rem">
          <label class="modal-lbl">Day of week</label>
          <select id="sched-dow">
            <option value="0">Sunday</option><option value="1">Monday</option><option value="2">Tuesday</option>
            <option value="3">Wednesday</option><option value="4">Thursday</option><option value="5">Friday</option>
            <option value="6">Saturday</option>
          </select>
        </div>

        <div id="sched-dom-wrap" style="display:none;margin-top:0.6rem">
          <label class="modal-lbl">Day of month (1–28)</label>
          <input type="number" id="sched-dom" min="1" max="28" value="1"
                 style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">
        </div>

        <div id="sched-time-wrap" style="margin-top:0.6rem">
          <label class="modal-lbl">Time</label>
          <input type="time" id="sched-timeofday" value="02:00"
                 style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">
        </div>

        <div style="margin-top:0.6rem">
          <label class="modal-lbl">Timezone (IANA)</label>
          <input type="text" id="sched-timezone" placeholder="e.g. Asia/Kolkata"
                 style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">
        </div>

        <div style="margin-top:0.6rem">
          <label class="modal-lbl">End date (optional)</label>
          <input type="date" id="sched-enddate"
                 style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">
        </div>

        <div style="margin-top:0.6rem">
          <label class="modal-lbl">Concurrency limit (optional — blank means unlimited)</label>
          <input type="number" id="sched-concurrency" min="1"
                 style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">
        </div>
      </div>
```

- [ ] **Step 2: Add the Mode/Recurrence rendering and change-handler JS**

Insert immediately before the closing `</script>` tag:

```js

function renderSchedModeRecurrencePane() {
  var modeSel = document.getElementById('sched-mode');
  var opts = '<option value="posture">Posture — read-only, safe on any host</option>';
  if (ROLE === 'admin') {
    opts += '<option value="telemetry">Telemetry — real identity-safe techniques (requires authorization)</option>';
  }
  modeSel.innerHTML = opts;
  modeSel.value = 'posture';
  document.getElementById('sched-timezone').value = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  schedOnModeChange();
  schedOnRecurrenceChange();
}

function schedOnModeChange() {
  var mode = document.getElementById('sched-mode').value;
  var isTelemetry = mode === 'telemetry';
  document.getElementById('sched-mode-warn').style.display = isTelemetry ? 'block' : 'none';
  document.getElementById('sched-reason-wrap').style.display = isTelemetry ? 'block' : 'none';
}

function schedOnRecurrenceChange() {
  var type = document.getElementById('sched-recurrence-type').value;
  document.getElementById('sched-once-wrap').style.display = (type === 'once') ? 'block' : 'none';
  document.getElementById('sched-dow-wrap').style.display = (type === 'weekly') ? 'block' : 'none';
  document.getElementById('sched-dom-wrap').style.display = (type === 'monthly') ? 'block' : 'none';
  document.getElementById('sched-time-wrap').style.display = (type === 'once') ? 'none' : 'block';
}
```

- [ ] **Step 3: Call the render function when step 3 is reached**

Find this exact block (from Task 3 Step 3, `schedWizardSet`):

```js
  document.getElementById('sched-wz-back').style.display = (step > 1) ? '' : 'none';
  document.getElementById('sched-wz-next').style.display = (step < 4) ? '' : 'none';
  document.getElementById('sched-create-btn').style.display = (step === 4) ? '' : 'none';
}
```

Replace it with:

```js
  document.getElementById('sched-wz-back').style.display = (step > 1) ? '' : 'none';
  document.getElementById('sched-wz-next').style.display = (step < 4) ? '' : 'none';
  document.getElementById('sched-create-btn').style.display = (step === 4) ? '' : 'none';
  if (step === 3) renderSchedModeRecurrencePane();
}
```

- [ ] **Step 4: Syntax-check**

```bash
cd "orchestrator/wwwroot"
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/sched-ui-check.js
node --check /tmp/sched-ui-check.js
```

Expected: no output, exit code 0.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): Scheduled Assessments Mode & Recurrence step"
```

---

### Task 6: Review & Authorize step, submit, and final wiring

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: every field/id from Tasks 3-5 (`sched-scenario`, `SCHED.selGroups`/`selAgents`, `sched-mode`, `sched-reason`, `sched-recurrence-type`, `sched-runat`, `sched-timeofday`, `sched-dow`, `sched-dom`, `sched-timezone`, `sched-enddate`, `sched-concurrency`), `scenarios` global, `x()`, `showToast()`, `apicall()`, `closeSchedWizard()`, `loadScheduledAssessments()`, `schedWizardSet` (called with `step === 4` to trigger review rendering, same pattern as Task 5 Step 3).
- Produces: `renderSchedReview()`, `schedBuildPayload()`, `submitScheduledAssessment()`. Nothing later consumes these — this is the last task.

- [ ] **Step 1: Add the review-step render call**

Find this exact block (from Task 5 Step 3, now the last line of `schedWizardSet`):

```js
  if (step === 3) renderSchedModeRecurrencePane();
}
```

Replace it with:

```js
  if (step === 3) renderSchedModeRecurrencePane();
  if (step === 4) renderSchedReview();
}
```

- [ ] **Step 2: Add the payload-builder, review-renderer, and submit JS**

Insert immediately before the closing `</script>` tag:

```js

// schedBuildPayload assembles the exact POST body scheduled_assessment_handlers.go
// expects. Techniques/steps are intentionally omitted -- V1 always schedules the
// full scenario. runAt/endDate are sent as ISO 8601 (RFC3339), matching Go's
// *time.Time JSON unmarshalling.
function schedBuildPayload() {
  var mode = document.getElementById('sched-mode').value;
  var type = document.getElementById('sched-recurrence-type').value;
  var body = {
    scenarioId: document.getElementById('sched-scenario').value,
    mode: mode,
    agentIds: Object.keys(SCHED.selAgents),
    groupIds: Object.keys(SCHED.selGroups).map(Number),
    recurrenceType: type,
    timezone: document.getElementById('sched-timezone').value
  };
  if (mode === 'telemetry') body.reason = document.getElementById('sched-reason').value.trim();
  if (type === 'once') {
    var runAt = document.getElementById('sched-runat').value;
    body.runAt = runAt ? new Date(runAt).toISOString() : null;
  } else {
    body.timeOfDay = document.getElementById('sched-timeofday').value;
    if (type === 'weekly') body.dayOfWeek = Number(document.getElementById('sched-dow').value);
    if (type === 'monthly') body.dayOfMonth = Number(document.getElementById('sched-dom').value);
  }
  var endDate = document.getElementById('sched-enddate').value;
  if (endDate) body.endDate = new Date(endDate).toISOString();
  var conc = document.getElementById('sched-concurrency').value;
  if (conc) body.concurrencyLimit = Number(conc);
  return body;
}

function renderSchedReview() {
  var payload = schedBuildPayload();
  var sc = scenarios.find(function(s) { return s.id === payload.scenarioId; });
  var groupNames = (payload.groupIds || []).map(function(id) { return SCHED.groupsById[id] || ('#' + id); });
  var targetsLine = [groupNames.join(', '), payload.agentIds.length ? (payload.agentIds.length + ' agent(s)') : '']
    .filter(function(s) { return s; }).join(' + ') || '—';
  var recurrenceLine = payload.recurrenceType === 'once'
    ? 'Once · ' + (payload.runAt ? new Date(payload.runAt).toLocaleString() : '—')
    : payload.recurrenceType === 'daily' ? 'Daily · ' + payload.timeOfDay
    : payload.recurrenceType === 'monthly' ? 'Monthly · Day ' + payload.dayOfMonth + ' · ' + payload.timeOfDay
    : 'Weekly · ' + SCHED_DOW[payload.dayOfWeek] + ' · ' + payload.timeOfDay;

  var html = '<div style="font-size:0.82rem;line-height:1.9">' +
    '<div><strong>Scenario:</strong> ' + x(sc ? sc.name : payload.scenarioId) + '</div>' +
    '<div><strong>Mode:</strong> ' + x(payload.mode === 'telemetry' ? 'Telemetry' : 'Posture') + '</div>' +
    '<div><strong>Targets:</strong> ' + x(targetsLine) + '</div>' +
    '<div><strong>Recurrence:</strong> ' + x(recurrenceLine) + ' · ' + x(payload.timezone) + '</div>' +
    '<div><strong>Concurrency:</strong> ' + x(payload.concurrencyLimit || 'Unlimited') + '</div>' +
    '<div><strong>End date:</strong> ' + x(payload.endDate ? new Date(payload.endDate).toLocaleDateString() : 'None') + '</div>' +
    '</div>';

  var authWrap = '';
  if (payload.mode === 'telemetry') {
    authWrap = '<div style="margin-top:0.9rem;padding:0.75rem;border-radius:var(--radius);border:1px solid rgba(210,153,34,0.5);background:rgba(210,153,34,0.08)">' +
      '<div style="font-weight:600;color:var(--warning);margin-bottom:0.4rem">&#9888; Unattended Telemetry Authorization</div>' +
      '<div style="font-size:0.78rem;line-height:1.5;margin-bottom:0.5rem">This schedule will execute real techniques that may generate security alerts on the selected targets, on every future occurrence, with no further confirmation.</div>' +
      '<div style="font-size:0.78rem;margin-bottom:0.5rem"><strong>Reason:</strong> ' + x(payload.reason || '(none entered)') + '</div>' +
      '<label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;font-size:0.8rem">' +
      '<input type="checkbox" id="sched-auth-check" onchange="document.getElementById(\'sched-create-btn\').disabled=!this.checked">' +
      'I authorize this recurring unattended execution</label>' +
      '</div>';
  }

  document.getElementById('sched-review').innerHTML = html + authWrap;
  var createBtn = document.getElementById('sched-create-btn');
  createBtn.disabled = (payload.mode === 'telemetry'); // re-enabled by the checkbox above once checked
}

function submitScheduledAssessment() {
  var payload = schedBuildPayload();
  if (!payload.scenarioId) { showToast('Select a scenario', 'err'); return; }
  if (!payload.agentIds.length && !payload.groupIds.length) { showToast('Select at least one target group or agent', 'err'); return; }
  if (payload.mode === 'telemetry' && !payload.reason) { showToast('Reason is required for a telemetry-mode schedule', 'err'); return; }

  var btn = document.getElementById('sched-create-btn');
  btn.disabled = true;
  apicall('/api/scheduled-assessments', { method: 'POST', body: JSON.stringify(payload) }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); btn.disabled = false; return; }
    showToast('Scheduled assessment created', 'ok');
    closeSchedWizard();
    loadScheduledAssessments();
  }).catch(function(e) { showToast(e.message, 'err'); btn.disabled = false; });
}
```

- [ ] **Step 3: Syntax-check**

```bash
cd "orchestrator/wwwroot"
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/sched-ui-check.js
node --check /tmp/sched-ui-check.js
```

Expected: no output, exit code 0.

- [ ] **Step 4: Read back the full new JS block**

Use the `Read` tool to view the whole "Scheduled Assessments" JS section (search for `// ── Scheduled Assessments ──` to find its current line number) in one pass, and confirm every function referenced by an `onclick=`/`onchange=` attribute added across Tasks 1-6 (`loadScheduledAssessments`, `openSchedWizard`, `closeSchedWizard`, `schedWizardNav`, `cancelScheduledAssessment`, `schedToggleGroup`, `schedToggleAgent`, `schedOnModeChange`, `schedOnRecurrenceChange`, `submitScheduledAssessment`) is defined exactly once in this file.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): Scheduled Assessments Review & Authorize step and submit"
```

---

## Self-Review

**Spec coverage:**
- Nav placement (Operations, between Live Runs and Campaigns, Analyst+Admin visibility) — Task 1.
- List view (Assessment/Mode/Targets/Recurrence/Last run/Status/Actions, empty state, no computed next-run, `LastOccurrenceAt`/"Never") — Task 1.
- Cancel flow (confirm, POST cancel, refresh, row stays with Cancelled badge) — Task 2.
- 4-step dedicated wizard, full-scenario-only Scenario step — Task 3.
- Targets step, group checkbox tree (non-cascading) + individual agent checklist, live-resolution/explicit-inclusion captions — Task 4.
- Mode & Recurrence step, Telemetry hidden entirely for non-Admin, warning + required reason for Telemetry, all 4 recurrence types with correct per-type fields, end date, concurrency — Task 5.
- Review & Authorize step, full read-only summary, Telemetry warning + reason + required authorization checkbox gating Create — Task 6.
- Viewing existing telemetry schedules as non-Admin (list shows Mode/authorization regardless of role, Cancel available to Analyst too since the backend doesn't Admin-gate cancel) — covered by Task 1/2's list rendering not branching on `ROLE` at all for any row, and by not adding any role check to `cancelScheduledAssessment`.

**Placeholder scan:** no TBD/TODO; every step has literal exact-match old/new HTML or complete JS function bodies; no "similar to Task N" references — Tasks 4-6 each repeat the full surrounding context they modify rather than pointing at an earlier task's code.

**Type consistency:** `SCHED` object shape (`schedules, groups, groupsById, agentsAll, selGroups, selAgents, step`) declared once in Task 1 and used with the same key names in Tasks 3-6. `schedRecurrenceText`/`schedTargetsText` (Task 1, list-row formatting) and the review step's inline recurrence/targets formatting (Task 6) are deliberately separate — the list reads a stored `jobs.Schedule` (PascalCase Go fields), the review step reads the in-progress form payload (camelCase POST-body shape) — the plan does not conflate the two field-name conventions anywhere. `SCHED_DOW` is declared once (Task 1) and reused as-is (not redeclared) in Task 6.
