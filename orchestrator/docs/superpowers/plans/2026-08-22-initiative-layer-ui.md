# Initiative Layer UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `wwwroot/index.html` frontend for the already-shipped Initiative layer backend (6 REST endpoints, commits `07c02b2`..`a13a748`) — a list view with state filtering, a create flow, and a detail drawer with contextual Close/Archive lifecycle actions.

**Architecture:** Pure frontend addition to the existing single-page-app pattern in `wwwroot/index.html`. No backend changes. Vanilla JS (`apicall()` fetch wrapper + string-templated HTML), reusing the file's existing nav/tab/drawer/badge/table/progress-bar CSS and JS conventions exactly — no new patterns introduced.

**Tech Stack:** Plain HTML/CSS/JS embedded in `wwwroot/index.html`, served as-is by the Go orchestrator (no build step, no bundler).

**Spec:** `docs/superpowers/specs/2026-08-22-initiative-layer-ui-design.md`

## Global Constraints

- **JSON field casing is inconsistent across the API response and MUST be read exactly as verified below** — this was confirmed by reading the actual Go source, not assumed:
  - The `initiative` object (from every endpoint) and the `progress` object (from `GetInitiative`) serialize with **capitalized Go field names, no JSON tags**: `ID`, `Name`, `Description`, `State`, `CreatedBy`, `CreatedAt`, `ClosedAt`, `ArchivedAt` for initiative; `Total`, `Requested`, `Running`, `Completed`, `Partial`, `Failed`, `Cancelled`, `PercentComplete` for progress.
  - The `jobs` array (from `GetInitiative` only) uses **explicit lowercase camelCase JSON tags**: `id`, `type`, `state`, `createdAt`, `completedAt`.
  - The outer response envelope keys are always lowercase: `{"initiative": ..., "progress": ..., "jobs": [...]}`, `{"initiatives": [...]}`, `{"initiative": ...}`.
- Reuse existing helpers exactly: `apicall(path, opts)` (fetch wrapper, `internal` line ~7511 — handles `Content-Type`, 401→logout), `x(s)` (HTML-escape, line ~15826), `showToast(msg, type)` (line ~15846, `type` is `'ok'` or `'err'`), `fmtDate(iso)` (already used throughout the file for date formatting — grep for its exact name at implementation time if it differs from this).
- Reuse existing CSS classes exactly, add none new: `.badge` (rounded-pill status labels), `.sec-hdr` (list header row), `.tbl-wrap > table` (list table), `.cnt` (count badge next to a section title), `.empty` (empty-state table row), `.drawer-overlay` / `.drawer` / `.drawer-header` / `.drawer-close` / `.drawer-body` (side drawer), `.bar-row` / `.bar-label` / `.bar-track` / `.bar-fill` (progress bar), `.btn` / `.btn-primary` / `.btn-outline` / `.btn-sm` (buttons).
- No new JS test framework — this codebase has none for `wwwroot`. Verification throughout is manual: load the page in a real browser and click through the described flow.
- Commit after each task; `git push` immediately after every commit (this repo builds directly on `main`, no branches/PRs).

---

## Task 1: Nav item, tab skeleton, list load + render + state filter

**Files:**
- Modify: `wwwroot/index.html` (5 separate edit points, detailed below)

**Interfaces:**
- Produces: `var INITIATIVES = { list: [], filter: 'active' };`, `function loadInitiatives()`, `function renderInitiativesList()`, `function initiativeSetFilter(state)`, `function initiativeStateColor(state)`, `function initiativeStateLabel(state)`. Task 2 depends on `INITIATIVES.list` and the state-color/label helpers; Task 4 depends on `loadInitiatives()` to refresh the list after create.

- [ ] **Step 1: Add the nav item**

In the Operations `<div class="nav-group">` block, immediately after the "Scheduled Assessments" `nav-item` (closing `</div>` right before the `<div class="nav-item" data-tab="campaigns"...>` comment-free block — the exact text to anchor on is `Scheduled Assessments\n        </div>\n        <div class="nav-item" data-tab="campaigns"`), insert a new nav item before the Campaigns one:

```html
        <div class="nav-item" data-tab="initiatives" onclick="showTab('initiatives')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/>
            <rect x="2" y="9" width="5" height="5" rx="1"/><path d="M9 11.5h5M11.5 9v5"/>
          </svg>
          Initiatives
        </div>
```

(Icon: a 2x2 grid of small squares with the bottom-right one replaced by a plus, suggesting "a container that groups multiple items" -- distinct from Campaigns' bar-chart icon and Scheduled Assessments' clock icon already in this same list.)

- [ ] **Step 2: Add the tab-content skeleton**

Immediately after `</div>` that closes `<div id="tab-scheduled-assessments" ...>` (the line right before the `<!-- Campaigns -->` HTML comment), insert:

```html
      <!-- Initiatives -->
      <div id="tab-initiatives" style="display:none">
        <div class="sec-hdr">
          <h2>Initiatives <span id="init-cnt" class="cnt">0</span></h2>
          <div style="display:flex;gap:0.5rem;align-items:center">
            <div id="init-filter" style="display:flex;gap:0.3rem">
              <button class="btn btn-outline btn-sm active" data-init-filter="active" onclick="initiativeSetFilter('active')">Active</button>
              <button class="btn btn-outline btn-sm" data-init-filter="closed" onclick="initiativeSetFilter('closed')">Closed</button>
              <button class="btn btn-outline btn-sm" data-init-filter="archived" onclick="initiativeSetFilter('archived')">Archived</button>
              <button class="btn btn-outline btn-sm" data-init-filter="all" onclick="initiativeSetFilter('all')">All</button>
            </div>
            <button class="btn btn-outline btn-sm" onclick="loadInitiatives()">Refresh</button>
            <button class="btn btn-primary btn-sm" onclick="openInitiativeCreateDrawer()">+ New Initiative</button>
          </div>
        </div>
        <div class="tbl-wrap">
          <table>
            <thead><tr>
              <th>Name</th><th>State</th><th>Created by</th><th>Created</th>
            </tr></thead>
            <tbody id="init-body">
              <tr><td colspan="4" class="empty">Loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>
```

- [ ] **Step 3: Register the tab in `TAB_TITLES`, `activateTab`, and `showTab`**

In the `TAB_TITLES` object literal (the long single line starting `var TAB_TITLES = { dashboard:'Dashboard', ...`), add `initiatives:'Initiatives',` anywhere in the list (e.g. right after `'scheduled-assessments':'Scheduled Assessments',`).

In `activateTab(name)`'s hardcoded array (`['dashboard','agents','scenarios','runs','scheduled-assessments','campaigns',...]`), add `'initiatives'` to the list (e.g. right after `'scheduled-assessments'`).

In `showTab(name)`, add a new dispatch line alongside the existing ones (e.g. right after `if (name === 'scheduled-assessments') loadScheduledAssessments();`):

```js
  if (name === 'initiatives') loadInitiatives();
```

- [ ] **Step 4: Write the state-color/label helpers and the list load/render/filter functions**

Add this new block immediately after the closing `}` of `showTab(name)` (right before the `// ── Detection Verification (SP2) ──` comment):

```js
// ── Initiative Layer ─────────────────────────────────────────────────────
// Frontend for docs/superpowers/specs/2026-08-22-initiative-layer-ui-design.md.
// Field-casing note: the `initiative` and `progress` objects serialize with
// capitalized Go field names (no json tags, matching internal/jobs.Job's
// established convention) -- e.g. it.ID, it.State, progress.PercentComplete.
// The `jobs` array inside GET /api/initiatives/{id} is the one exception:
// it has explicit lowercase camelCase json tags (id/type/state/createdAt/
// completedAt). Verified against the actual Go source, not assumed.
var INITIATIVES = { list: [], filter: 'active' };

function initiativeStateColor(state) {
  return state === 'active' ? 'var(--success)' : 'var(--muted)';
}
function initiativeStateLabel(state) {
  if (state === 'active') return 'Active';
  if (state === 'closed') return 'Closed';
  if (state === 'archived') return 'Archived';
  return state;
}

function initiativeSetFilter(state) {
  INITIATIVES.filter = state;
  document.querySelectorAll('#init-filter [data-init-filter]').forEach(function(b) {
    b.classList.toggle('active', b.getAttribute('data-init-filter') === state);
  });
  loadInitiatives();
}

function loadInitiatives() {
  var q = INITIATIVES.filter === 'all' ? '' : ('?state=' + INITIATIVES.filter);
  apicall('/api/initiatives' + q).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    INITIATIVES.list = (res && res.initiatives) || [];
    renderInitiativesList();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function renderInitiativesList() {
  document.getElementById('init-cnt').textContent = INITIATIVES.list.length;
  var tbody = document.getElementById('init-body');
  if (!INITIATIVES.list.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty">No initiatives yet.</td></tr>';
    return;
  }
  tbody.innerHTML = INITIATIVES.list.map(function(it) {
    var col = initiativeStateColor(it.State);
    return '<tr onclick="openInitiativeDrawer(\'' + x(it.ID) + '\')" style="cursor:pointer">' +
      '<td>' + x(it.Name) + '</td>' +
      '<td><span class="badge" style="color:' + col + ';border-color:' + col + '">' + initiativeStateLabel(it.State) + '</span></td>' +
      '<td>' + x(it.CreatedBy || '—') + '</td>' +
      '<td>' + x(fmtDate(it.CreatedAt)) + '</td>' +
    '</tr>';
  }).join('');
}
```

- [ ] **Step 5: Manual verification**

Start the app (see Task 5 for the full dev-server procedure; a quick check here just needs the server running and a browser open to it). Log in, click "Initiatives" in the sidebar. Expected: the tab shows, header says "Initiatives", the Active/Closed/Archived/All filter buttons render, and the table shows either real rows (if any active initiatives already exist from earlier backend testing this session) or "No initiatives yet." — either is correct, this step only confirms nothing throws a JS error and the list loads.

- [ ] **Step 6: Commit**

```bash
git add wwwroot/index.html
git commit -m "feat(ui): add Initiatives nav tab with list view and state filter

Read-only list (name/state/created-by/created-at) against the existing
GET /api/initiatives endpoint, with an Active/Closed/Archived/All
filter mapped to the API's ?state= param. Detail drawer, lifecycle
actions, and create flow land in the next 3 tasks."
git push
```

---

## Task 2: Detail drawer (read-only: header, description, progress, jobs)

**Files:**
- Modify: `wwwroot/index.html`

**Interfaces:**
- Consumes: `x()`, `apicall()`, `showToast()`, `initiativeStateColor()`/`initiativeStateLabel()` (Task 1), `fmtDate()`.
- Produces: `function openInitiativeDrawer(id)`, `function closeInitiativeDrawer()`. Task 3 adds the Close/Archive buttons into this same drawer's header, reusing `openInitiativeDrawer`'s render function to refresh in place.

- [ ] **Step 1: Add the drawer HTML**

Add this near the other drawer overlays (e.g. immediately after the `<!-- Results Drawer -->` block's closing `</div>` tags, or any other existing drawer block — exact placement doesn't matter since drawers are `position:fixed`):

```html
<!-- Initiative Detail Drawer -->
<div id="init-drawer-overlay" class="drawer-overlay" onclick="if(event.target===this)closeInitiativeDrawer()">
  <div class="drawer" style="width:480px;max-width:94vw">
    <div class="drawer-header">
      <h3 id="init-drawer-title">Initiative</h3>
      <button class="drawer-close" onclick="closeInitiativeDrawer()">&#10005;</button>
    </div>
    <div class="drawer-body" id="init-drawer-body"></div>
  </div>
</div>
```

- [ ] **Step 2: Write the render + open/close functions**

Add immediately after `renderInitiativesList()` (Task 1's last function):

```js
var INIT_CURRENT = null; // the currently-open drawer's Initiative object, or null

function closeInitiativeDrawer() {
  document.getElementById('init-drawer-overlay').classList.remove('open');
  INIT_CURRENT = null;
}

function openInitiativeDrawer(id) {
  apicall('/api/initiatives/' + encodeURIComponent(id)).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    INIT_CURRENT = res.initiative;
    renderInitiativeDrawer(res.initiative, res.progress, res.jobs || []);
    document.getElementById('init-drawer-overlay').classList.add('open');
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function initiativeProgressCounts(p) {
  var parts = [p.Total + ' total'];
  if (p.Completed)  parts.push(p.Completed + ' completed');
  if (p.Running)    parts.push(p.Running + ' running');
  if (p.Requested)  parts.push(p.Requested + ' requested');
  if (p.Partial)    parts.push(p.Partial + ' partial');
  if (p.Failed)     parts.push(p.Failed + ' failed');
  if (p.Cancelled)  parts.push(p.Cancelled + ' cancelled');
  return parts.join(' · ');
}

function renderInitiativeDrawer(it, progress, jobs) {
  document.getElementById('init-drawer-title').textContent = it.Name;
  var col = initiativeStateColor(it.State);
  var pct = Math.round(progress.PercentComplete || 0);

  var jobRows = jobs.length
    ? jobs.map(function(j) {
        return '<tr>' +
          '<td class="tiny muted" style="font-family:var(--font-mono)">' + x(j.id.slice(0, 8)) + '</td>' +
          '<td>' + x(j.type) + '</td>' +
          '<td><span class="badge">' + x(j.state) + '</span></td>' +
          '<td>' + x(fmtDate(j.createdAt)) + '</td>' +
          '<td>' + (j.completedAt ? x(fmtDate(j.completedAt)) : '—') + '</td>' +
        '</tr>';
      }).join('')
    : '<tr><td colspan="5" class="empty">No jobs yet.</td></tr>';

  document.getElementById('init-drawer-body').innerHTML =
    '<div style="margin-bottom:1rem">' +
      '<span class="badge" style="color:' + col + ';border-color:' + col + '">' + initiativeStateLabel(it.State) + '</span> ' +
      '<span class="tiny muted">Created by ' + x(it.CreatedBy || '—') + ' · ' + x(fmtDate(it.CreatedAt)) + '</span>' +
    '</div>' +
    '<div id="init-drawer-actions" style="display:flex;gap:0.5rem;margin-bottom:1rem"></div>' +
    '<div id="init-drawer-error" style="margin-bottom:0.85rem"></div>' +
    (it.Description ? '<p style="font-size:0.8rem;color:var(--text-dim);margin-bottom:1.1rem;line-height:1.5">' + x(it.Description) + '</p>' : '') +
    '<div class="bar-row" style="margin-bottom:1.25rem">' +
      '<div class="bar-label"><span>Progress</span><span>' + pct + '%</span></div>' +
      '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:var(--accent)"></div></div>' +
      '<div class="tiny muted" style="margin-top:0.3rem">' + x(initiativeProgressCounts(progress)) + '</div>' +
    '</div>' +
    '<h4 style="font-size:0.78rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:0.5rem">Jobs</h4>' +
    '<div class="tbl-wrap"><table><thead><tr>' +
      '<th>ID</th><th>Type</th><th>State</th><th>Created</th><th>Completed</th>' +
    '</tr></thead><tbody>' + jobRows + '</tbody></table></div>';
}
```

Note: `initiativeDrawerActions` (the Close/Archive buttons) is left as an empty placeholder `<div id="init-drawer-actions">` in this task — Task 3 populates it. This task's drawer is fully viewable and correct on its own; it just has no action buttons yet.

- [ ] **Step 3: Manual verification**

Reload the page, open Initiatives tab. If at least one initiative exists (there should be several real ones from this session's backend test runs — `TestGetInitiative_ReturnsProgressAndJobList`'s "detail-view" etc. are in a test-container DB, not the dev DB, so the dev DB is likely empty; use Task 4's create flow first if needed, or create one via `curl`/Postman against the running dev server to have something to click). Click a row. Expected: drawer slides in from the right, shows name/state/created-by/created-at, description (if any), a progress bar with the counts string underneath, and a Jobs table (either real rows or "No jobs yet."). Click the X or click outside the drawer — it closes.

- [ ] **Step 4: Commit**

```bash
git add wwwroot/index.html
git commit -m "feat(ui): add Initiative detail drawer (read-only)

Header (name/state/created-by/created-at), description, a progress
bar + raw counts string, and a read-only Jobs table -- all from the
single GET /api/initiatives/{id} call. Close/Archive action buttons
land in the next task."
git push
```

---

## Task 3: Lifecycle actions (Close/Archive) with 409 handling

**Files:**
- Modify: `wwwroot/index.html`

**Interfaces:**
- Consumes: `INIT_CURRENT`, `renderInitiativeDrawer()`, `openInitiativeDrawer()` (Task 2), `loadInitiatives()` (Task 1).
- Produces: `function initiativeCloseAction()`, `function initiativeArchiveAction()`.

- [ ] **Step 1: Add the action-button rendering into `renderInitiativeDrawer`**

Modify the line that currently reads:

```js
    '<div id="init-drawer-actions" style="display:flex;gap:0.5rem;margin-bottom:1rem"></div>' +
```

to instead build real button HTML based on state:

```js
    '<div style="display:flex;gap:0.5rem;margin-bottom:1rem">' +
      (it.State === 'active' ? '<button class="btn btn-outline btn-sm" onclick="initiativeCloseAction()">Close Initiative</button>' : '') +
      (it.State === 'closed' ? '<button class="btn btn-outline btn-sm" onclick="initiativeArchiveAction()">Archive Initiative</button>' : '') +
    '</div>' +
```

(This replaces the empty placeholder div from Task 2 Step 2 with real conditional buttons — same insertion point, now state-aware.)

- [ ] **Step 2: Write the action functions**

Add after `renderInitiativeDrawer()`:

```js
function initiativeShowDrawerError(msg) {
  var el = document.getElementById('init-drawer-error');
  if (el) el.innerHTML = msg ? '<div class="tiny" style="color:var(--danger)">' + x(msg) + '</div>' : '';
}

function initiativeCloseAction() {
  if (!INIT_CURRENT) return;
  initiativeShowDrawerError('');
  apicall('/api/initiatives/' + encodeURIComponent(INIT_CURRENT.ID) + '/close', { method: 'POST' }).then(function(res) {
    if (res && res.error) { initiativeShowDrawerError(res.error); return; }
    showToast('Initiative closed', 'ok');
    openInitiativeDrawer(INIT_CURRENT.ID); // re-fetch to refresh drawer state/buttons
    loadInitiatives(); // refresh the underlying list row
  }).catch(function(e) { initiativeShowDrawerError(e.message); });
}

function initiativeArchiveAction() {
  if (!INIT_CURRENT) return;
  initiativeShowDrawerError('');
  apicall('/api/initiatives/' + encodeURIComponent(INIT_CURRENT.ID) + '/archive', { method: 'POST' }).then(function(res) {
    if (res && res.error) { initiativeShowDrawerError(res.error); return; }
    showToast('Initiative archived', 'ok');
    openInitiativeDrawer(INIT_CURRENT.ID);
    loadInitiatives();
  }).catch(function(e) { initiativeShowDrawerError(e.message); });
}
```

Note on error surfacing: `apicall()` (Task 1's Global Constraints) always resolves with the parsed JSON body, even on a non-2xx status — it does not throw for 409/404, only for a network failure or 401. The `jsonError(w, msg, code)` backend helper writes `{"error": "<msg>"}` as the body regardless of status code, so `res.error` is the correct and only place both a 409 (`"initiative is not active"` / `"initiative is not closed"`) and a 404 surface. Confirm this against `apicall`'s actual implementation at Step 1 of Task 1 was read correctly (it was — `return r.json()` unconditionally except on 401) before assuming `.catch()` fires for a 409; it will not.

- [ ] **Step 3: Manual verification**

Open an active initiative's drawer, click "Close Initiative". Expected: toast "Initiative closed", drawer refreshes showing the Closed badge and now an "Archive Initiative" button instead of "Close Initiative". Click "Archive Initiative". Expected: toast "Initiative archived", drawer refreshes showing the Archived badge, no action buttons left. This step covers only the happy path (state-gated buttons doing the right thing at each transition) — the 409 error-banner path, which requires bypassing the UI's own state-gating to reach, is exercised deliberately in Task 5 Step 2.10 rather than here.

- [ ] **Step 4: Commit**

```bash
git add wwwroot/index.html
git commit -m "feat(ui): add Close/Archive lifecycle actions to the Initiative drawer

Buttons are conditionally shown by state (Close only when active,
Archive only when closed) and re-fetch the detail endpoint on success
to refresh both the drawer and the underlying list row. A 409 from
the API (defensive -- not normally reachable since buttons are
state-gated) surfaces as an inline error in the drawer, not a toast,
since the drawer's own context is what needs the correction."
git push
```

---

## Task 4: Create flow

**Files:**
- Modify: `wwwroot/index.html`

**Interfaces:**
- Consumes: `x()`, `apicall()`, `showToast()`, `loadInitiatives()` (Task 1).
- Produces: `function openInitiativeCreateDrawer()`, `function closeInitiativeCreateDrawer()`, `function submitInitiativeCreate()`.

- [ ] **Step 1: Add the create-drawer HTML**

Add alongside the detail drawer from Task 2:

```html
<!-- Initiative Create Drawer -->
<div id="init-create-overlay" class="drawer-overlay" onclick="if(event.target===this)closeInitiativeCreateDrawer()">
  <div class="drawer" style="width:420px;max-width:94vw">
    <div class="drawer-header">
      <h3>New Initiative</h3>
      <button class="drawer-close" onclick="closeInitiativeCreateDrawer()">&#10005;</button>
    </div>
    <div class="drawer-body">
      <label style="font-size:0.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:700;display:block;margin-bottom:0.35rem">Name</label>
      <input type="text" id="init-create-name" placeholder="Q3 2026 Patch Compliance" style="width:100%;padding:0.5rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;margin-bottom:0.85rem;font-size:0.8rem;font-family:inherit">

      <label style="font-size:0.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:700;display:block;margin-bottom:0.35rem">Description (optional)</label>
      <textarea id="init-create-desc" rows="3" placeholder="Quarterly patch push across the BFSI fleet" style="width:100%;padding:0.5rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;margin-bottom:0.85rem;font-size:0.8rem;font-family:inherit;resize:vertical"></textarea>

      <div id="init-create-error" style="margin-bottom:0.85rem"></div>

      <div style="display:flex;gap:0.5rem;justify-content:flex-end">
        <button class="btn btn-outline btn-sm" onclick="closeInitiativeCreateDrawer()">Cancel</button>
        <button class="btn btn-primary btn-sm" onclick="submitInitiativeCreate()">Create</button>
      </div>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Write the open/close/submit functions**

Add after `initiativeArchiveAction()` (Task 3's last function):

```js
function openInitiativeCreateDrawer() {
  document.getElementById('init-create-name').value = '';
  document.getElementById('init-create-desc').value = '';
  document.getElementById('init-create-error').innerHTML = '';
  document.getElementById('init-create-overlay').classList.add('open');
}

function closeInitiativeCreateDrawer() {
  document.getElementById('init-create-overlay').classList.remove('open');
}

function submitInitiativeCreate() {
  var name = document.getElementById('init-create-name').value.trim();
  var errEl = document.getElementById('init-create-error');
  if (!name) {
    errEl.innerHTML = '<div class="tiny" style="color:var(--danger)">Name is required.</div>';
    return;
  }
  errEl.innerHTML = '';
  var desc = document.getElementById('init-create-desc').value.trim();
  apicall('/api/initiatives', { method: 'POST', body: JSON.stringify({ name: name, description: desc }) }).then(function(res) {
    if (res && res.error) { errEl.innerHTML = '<div class="tiny" style="color:var(--danger)">' + x(res.error) + '</div>'; return; }
    showToast('Initiative created', 'ok');
    closeInitiativeCreateDrawer();
    loadInitiatives();
  }).catch(function(e) { errEl.innerHTML = '<div class="tiny" style="color:var(--danger)">' + x(e.message) + '</div>'; });
}
```

- [ ] **Step 3: Manual verification**

Click "+ New Initiative". Try submitting with an empty name — expect the inline "Name is required." error, no network call fired (verify via browser devtools Network tab if in doubt). Fill in a name (and optionally a description), click Create. Expected: toast "Initiative created", drawer closes, the list (currently filtered to "Active", the default) refreshes and shows the new initiative.

- [ ] **Step 4: Commit**

```bash
git add wwwroot/index.html
git commit -m "feat(ui): add Initiative create flow

Small drawer-form (name + optional description), client-side
required-name validation mirroring the API's own 400, POST + list
refresh on success. Completes the Initiative layer UI's 4 interaction
surfaces (list/filter, detail, lifecycle actions, create)."
git push
```

---

## Task 5: Full manual QA walkthrough

**Files:** none (verification only).

**Interfaces:** none.

- [ ] **Step 1: Start the app**

Use the `run` skill (or this project's established dev-server startup procedure if the `run` skill doesn't have a project-specific pattern cached yet) to launch the orchestrator with its Postgres dependency running, and open `wwwroot/index.html` in an actual browser via the running server's URL — not `file://`, since `apicall()`'s relative paths (`/api/...`) require being served from the same origin.

- [ ] **Step 2: Walk the full flow end-to-end**

In order, in the real running browser:
1. Log in, navigate to Initiatives (confirm nav item + page title both read "Initiatives").
2. Confirm the default filter is "Active" and the list loads without a console error.
3. Click "+ New Initiative", submit with an empty name, confirm the inline validation error and that no request fired.
4. Fill in a real name + description, submit, confirm the toast, drawer close, and the new row appearing in the Active-filtered list.
5. Click that new row, confirm the drawer shows the right name/description, a 0%-progress bar (no jobs yet), "No jobs yet." in the Jobs table, and a visible "Close Initiative" button (no "Archive" button).
6. Click "Close Initiative", confirm the toast, the drawer updating to the Closed badge with an "Archive Initiative" button in place of "Close Initiative", and the list (still filtered to Active) no longer showing this initiative.
7. Switch the filter to "Closed", confirm the just-closed initiative now appears there.
8. Open it again, click "Archive Initiative", confirm the toast and the Archived badge with no action buttons.
9. Switch the filter to "Archived", confirm it appears there; switch to "All", confirm it appears alongside any other initiatives regardless of state.
10. Attempt the 409 path for real: with a second, still-active initiative, open its drawer, then from the browser devtools console run `apicall('/api/initiatives/' + INIT_CURRENT.ID + '/archive', {method:'POST'}).then(r=>console.log(r))` (archiving an active initiative directly, bypassing the UI's own state-gated buttons) and confirm the console logs `{error: "initiative is not closed"}` rather than throwing or silently succeeding — this is the one path the UI's own buttons can't normally trigger, so it must be checked this way.

- [ ] **Step 3: Record the real QA result in memory**

This is a `[[project_endpoint_health_remediation]]` memory update, not a code change: append one sentence to Sub-project 13's entry recording that the UI shipped and was manually browser-QA'd on `<today's date>`, following every prior UI sub-project's honest-QA-status convention in this codebase's memory (several are explicitly flagged "not yet browser-QA'd" rather than assumed passing) — write "QA'd clean" only if Step 2 actually passed with zero deviations; otherwise record exactly what didn't work and whether it was fixed.
