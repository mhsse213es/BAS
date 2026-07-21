# EPP Response Actions — Plan 5: UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give operators a way to actually use the response-action backend (Plans 1-4): a Response Connectors admin config screen, and a "Respond" action on the Findings drawer that dispatches Isolate/Release/Kill Process/Quarantine File.

**Architecture:** Both pieces are additive HTML+JS inside `orchestrator/wwwroot/index.html` (and its hardlinked twin `orchestrator/cmd/server/wwwroot/index.html`), following patterns already established elsewhere in the file rather than introducing new ones. The connector screen is a new self-contained section inside the existing (already admin-gated) Integrations tab — deliberately *not* built on top of the ITSM/Ticketing connector machinery (`CONNECTOR_FIELDS`/`renderConnectorSettings`), since that machinery's request body nests under `settings: {...}` and is wired to ticketing-specific concepts (auto-create policy, project pickers) that don't apply here; the actions API expects flat top-level fields. The Respond UI is a new small modal, reusing this app's existing `overlay`/`modal` CSS classes and native-`confirm()` safety pattern (same pattern used by the Run wizard and multi-agent dispatch work).

**Tech Stack:** Vanilla JS (no framework, no build step), inline in a single HTML file. No JS test harness exists for this file — verification is structural (grep) plus a live-server smoke test, matching how every prior UI plan in this session was verified.

## Global Constraints

- This is Plan 5 of 5 — the final plan for EPP Response Actions (spec: `docs/superpowers/specs/2026-07-21-epp-response-actions-design.md`). Plans 1-4 are done and merged (backend fully live at `/api/actions/run`, `/api/actions`, `/api/actions/configs`).
- **Admin-only, hidden not disabled.** This page's permission model is a coarse global `ROLE` string (`'admin' | 'analyst' | 'viewer' | ''`), not the fine-grained permission system used elsewhere in this codebase — matches every existing admin-gated element on this page (e.g. `canPush = ROLE === 'admin' || ROLE === 'analyst'` at `wwwroot/index.html:7204`). The Respond button must only exist in the rendered HTML string when `ROLE === 'admin'` — never rendered-then-hidden via CSS. The backend already enforces this with `CanExecuteResponseAction` regardless of what the client does; this is a UX affordance, not the real security boundary.
- **Flat request bodies.** `POST /api/actions/configs` and `PUT /api/actions/configs/{id}` expect top-level fields (`name`, `provider`, `enabled`, `tenantId`, `clientId`, `clientSecret`, `baseUrl`, `killProcessScriptName`) — confirmed from Plan 4's `CreateResponseConnector`/`UpdateResponseConnector` handlers. Do not nest these under a `settings` object (that's the ticketing connector's shape, not this one's).
- **Action-specific parameter keys**, confirmed from Plan 4's `internal/actions.dispatch`: `endpoint.kill_process` reads `Parameters["pid"]` (a number); `endpoint.quarantine_file` reads `Parameters["quarantineTarget"]` (a string — file path for a `crowdstrike` connector, SHA1 hash for a `microsoft_defender` connector). `endpoint.isolate`/`endpoint.release` take no parameters.
- **Reason is mandatory** — the backend already rejects a missing reason with HTTP 400, but the UI must not rely on that alone; disable/validate before sending, matching the spec's "Every action requires the Reason field before the confirm button enables."
- Every edit to `orchestrator/wwwroot/index.html` must be applied identically to `orchestrator/cmd/server/wwwroot/index.html` (OS-level hardlinks, but two separate git paths) — verify with `diff` before every commit, and `git add` both paths together.
- No browser-automation tool is available in this environment. Verification here is: structural `grep` checks, a live-server + `curl` smoke test confirming the new markup is served, and a written manual browser checklist for a human to run before merging — same disclosed limitation as every other UI plan in this session.

---

### Task 1: Response Connectors admin config screen

**Files:**
- Modify: `orchestrator/wwwroot/index.html:2913-2924` (Integrations tab HTML — new section)
- Modify: `orchestrator/wwwroot/index.html:3882` (tab-switch load hook)
- Modify: `orchestrator/wwwroot/index.html` (new JS functions, appended after `deleteConnector`/`triggerTicketingSync`, ~line 7840)
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (same edits, hardlinked twin)

**Interfaces:**
- Consumes: `apicall`, `showToast`, `x` (HTML-escape helper), `respond`-style CSS classes `conn-cfg-card`/`conn-cfg-label`/`inp-sm`/`btn btn-outline btn-sm`/`btn btn-primary btn-sm` (all already used by the ticketing connector screen this mirrors the *shape* of, not the *body format*).
- Produces: `loadResponseConnectors(cb)`, `renderResponseConnectorList(list)`, `openAddResponseConnector()`, `openEditResponseConnector(id)`, `closeResponseConnectorForm()`, `renderResponseConnectorFields()`, `saveResponseConnectorForm()`, `testResponseConnectorById(id, btn)`, `deleteResponseConnector(id, name)`, global `_responseConnectors` cache array — `_responseConnectors` and `loadResponseConnectors` are consumed by Task 2 (to populate the connector picker in the Respond modal).

- [ ] **Step 1: Add the Response Connectors section to the Integrations tab**

In `orchestrator/wwwroot/index.html`, find (the end of the existing Integrations tab, right before the OpenAEV tab begins):
```html
        <!-- Revalidation summary -->
        <div id="integrations-reval" style="display:none;margin-top:1.25rem">
          <div class="conn-cfg-card" style="display:flex;align-items:center;gap:1rem">
            <div style="font-size:1.5rem;font-weight:800;color:var(--warning)" id="integrations-reval-count">0</div>
            <div>
              <div style="font-size:0.82rem;font-weight:600;color:var(--text)">Pending Revalidation</div>
              <div style="font-size:0.75rem;color:var(--muted)">Tickets resolved in ITSM — run BAS again to confirm prevention before closing finding.</div>
            </div>
            <button class="btn btn-outline btn-sm" style="margin-left:auto" onclick="showTab('findings')">View Findings →</button>
          </div>
        </div>
      </div>

      <!-- ── OpenAEV Connector — synced scenario content library ────────── -->
```
Replace with:
```html
        <!-- Revalidation summary -->
        <div id="integrations-reval" style="display:none;margin-top:1.25rem">
          <div class="conn-cfg-card" style="display:flex;align-items:center;gap:1rem">
            <div style="font-size:1.5rem;font-weight:800;color:var(--warning)" id="integrations-reval-count">0</div>
            <div>
              <div style="font-size:0.82rem;font-weight:600;color:var(--text)">Pending Revalidation</div>
              <div style="font-size:0.75rem;color:var(--muted)">Tickets resolved in ITSM — run BAS again to confirm prevention before closing finding.</div>
            </div>
            <button class="btn btn-outline btn-sm" style="margin-left:auto" onclick="showTab('findings')">View Findings →</button>
          </div>
        </div>

        <!-- EPP Response Connectors — separate from the ITSM connectors above:
             these are write-capable (isolate/kill/quarantine), not read-only. -->
        <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;margin:2rem 0 1rem;flex-wrap:wrap">
          <div>
            <h2 style="font-family:var(--font-display);font-size:1.15rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem;color:var(--text)">EPP Response Connectors</h2>
            <div style="font-size:0.8rem;color:var(--muted)">CrowdStrike / Defender credentials for isolate, kill process, and quarantine actions from the Findings tab.</div>
          </div>
          <button class="btn btn-primary btn-sm" onclick="openAddResponseConnector()">+ Add Connector</button>
        </div>
        <div id="response-connectors-list"><div class="empty" style="padding:2rem">Loading connectors…</div></div>

        <!-- Add / Edit response connector (inline form) -->
        <div id="response-connector-form-wrap" style="display:none;margin-top:1.25rem">
          <div class="conn-cfg-card">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem">
              <div style="font-size:0.85rem;font-weight:600;color:var(--text)" id="response-connector-form-title">Add Connector</div>
              <button class="btn btn-outline btn-sm" onclick="closeResponseConnectorForm()">✕ Cancel</button>
            </div>
            <input type="hidden" id="rc-id">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;margin-bottom:0.75rem">
              <div>
                <div class="conn-cfg-label" style="margin-bottom:0.3rem">Name</div>
                <input id="rc-name" type="text" placeholder="e.g. Prod CrowdStrike" class="inp-sm" style="width:100%">
              </div>
              <div>
                <div class="conn-cfg-label" style="margin-bottom:0.3rem">Provider</div>
                <select id="rc-provider" class="inp-sm" style="width:100%" onchange="renderResponseConnectorFields()">
                  <option value="crowdstrike">CrowdStrike Falcon</option>
                  <option value="microsoft_defender">Microsoft Defender for Endpoint</option>
                </select>
              </div>
            </div>
            <div id="rc-crowdstrike-fields" style="display:none;margin-bottom:0.75rem">
              <div class="conn-cfg-label" style="margin-bottom:0.3rem">Base URL</div>
              <input id="rc-base-url" type="text" placeholder="https://api.crowdstrike.com" class="inp-sm" style="width:100%">
            </div>
            <div id="rc-defender-fields" style="display:none;margin-bottom:0.75rem">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem">
                <div>
                  <div class="conn-cfg-label" style="margin-bottom:0.3rem">Tenant ID</div>
                  <input id="rc-tenant-id" type="text" placeholder="Entra tenant ID" class="inp-sm" style="width:100%">
                </div>
                <div>
                  <div class="conn-cfg-label" style="margin-bottom:0.3rem">Kill Process Script Name <span class="tiny muted">(optional)</span></div>
                  <input id="rc-kill-script" type="text" placeholder="Audspect-KillProcess.ps1" class="inp-sm" style="width:100%">
                </div>
              </div>
              <div style="font-size:0.68rem;color:var(--warning);margin-top:0.35rem">⚠ Kill Process requires this script to already exist in the tenant's Defender Live Response script library — Defender has no built-in kill-process action.</div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;margin-bottom:0.75rem">
              <div>
                <div class="conn-cfg-label" style="margin-bottom:0.3rem">Client ID</div>
                <input id="rc-client-id" type="text" placeholder="API client ID" class="inp-sm" style="width:100%">
              </div>
              <div>
                <div class="conn-cfg-label" style="margin-bottom:0.3rem">Client Secret</div>
                <input id="rc-client-secret" type="password" placeholder="••••••" class="inp-sm" style="width:100%">
              </div>
            </div>
            <label class="conn-cfg-label" style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;margin-bottom:0.75rem">
              <input type="checkbox" id="rc-enabled" checked> Enabled
            </label>
            <div style="display:flex;gap:0.5rem">
              <button class="btn btn-primary btn-sm" onclick="saveResponseConnectorForm()">Save</button>
            </div>
          </div>
        </div>
      </div>

      <!-- ── OpenAEV Connector — synced scenario content library ────────── -->
```

- [ ] **Step 2: Add the load-hook on tab switch**

Find:
```js
  if (name === 'integrations') loadIntegrations();
```
Replace with:
```js
  if (name === 'integrations') { loadIntegrations(); loadResponseConnectors(renderResponseConnectorList); }
```

- [ ] **Step 3: Add the JS functions**

Find (the end of the ticketing connector functions):
```js
function deleteConnector(id, name) {
  if (!confirm('Delete connector "' + name + '"? This cannot be undone.')) return;
  apicall('/api/ticketing/configs/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function() { showToast('Connector deleted', 'ok'); loadIntegrations(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

function triggerTicketingSync() {
```
Replace with:
```js
function deleteConnector(id, name) {
  if (!confirm('Delete connector "' + name + '"? This cannot be undone.')) return;
  apicall('/api/ticketing/configs/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function() { showToast('Connector deleted', 'ok'); loadIntegrations(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// ── EPP Response Connectors ─────────────────────────────────────────────────
// Deliberately separate from the ticketing connector functions above: this
// API's request body is flat (no nested "settings" object) and there are
// only two fixed providers, so this doesn't reuse CONNECTOR_FIELDS/
// renderConnectorSettings — that machinery is ticketing-specific (auto-create
// policy, project pickers) and would be a worse fit than a small dedicated form.
var _responseConnectors = null;

function loadResponseConnectors(cb) {
  apicall('/api/actions/configs').then(function(list) {
    _responseConnectors = list || [];
    if (cb) cb(_responseConnectors);
  }).catch(function() { _responseConnectors = []; if (cb) cb([]); });
}

function renderResponseConnectorList(list) {
  var el = document.getElementById('response-connectors-list');
  if (!el) return;
  if (!list || !list.length) {
    el.innerHTML = '<div class="conn-cfg-card" style="text-align:center;padding:2rem;color:var(--muted)">' +
      '<div style="margin-bottom:0.5rem">No response connectors configured.</div>' +
      '<div class="tiny">Add a CrowdStrike or Defender connector to enable Respond actions from Findings.</div></div>';
    return;
  }
  var providerLabels = { crowdstrike: 'CrowdStrike Falcon', microsoft_defender: 'Microsoft Defender for Endpoint' };
  el.innerHTML = list.map(function(c) {
    var statusColor = c.enabled ? 'var(--success)' : 'var(--muted)';
    var statusLabel = c.enabled ? 'Enabled' : 'Disabled';
    var statusDot = '<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:' + statusColor + ';margin-right:5px"></span>' + statusLabel;
    return '<div class="conn-cfg-card" style="margin-bottom:0.75rem">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;gap:1rem">' +
        '<div><div style="font-weight:600;font-size:0.85rem;color:var(--text)">' + x(c.name) + '</div>' +
          '<div class="tiny muted">' + (providerLabels[c.provider] || c.provider) + '</div></div>' +
        '<div style="display:flex;align-items:center;gap:0.65rem">' +
          '<span class="tiny" style="color:' + statusColor + '">' + statusDot + '</span>' +
          '<button class="btn btn-outline btn-sm" onclick="testResponseConnectorById(\'' + x(c.id) + '\',this)">Test</button>' +
          '<button class="btn btn-outline btn-sm" onclick="openEditResponseConnector(\'' + x(c.id) + '\')">Edit</button>' +
          '<button class="btn btn-sm" style="color:var(--danger);background:rgba(218,54,51,0.08);border:1px solid rgba(218,54,51,0.25)" onclick="deleteResponseConnector(\'' + x(c.id) + '\',\'' + x(c.name) + '\')">Delete</button>' +
        '</div>' +
      '</div>' +
    '</div>';
  }).join('');
}

function renderResponseConnectorFields() {
  var prov = document.getElementById('rc-provider').value;
  document.getElementById('rc-crowdstrike-fields').style.display = (prov === 'crowdstrike') ? '' : 'none';
  document.getElementById('rc-defender-fields').style.display = (prov === 'microsoft_defender') ? '' : 'none';
}

function openAddResponseConnector() {
  document.getElementById('rc-id').value = '';
  document.getElementById('rc-name').value = '';
  document.getElementById('rc-provider').value = 'crowdstrike';
  document.getElementById('rc-base-url').value = '';
  document.getElementById('rc-tenant-id').value = '';
  document.getElementById('rc-kill-script').value = '';
  document.getElementById('rc-client-id').value = '';
  document.getElementById('rc-client-secret').value = '';
  document.getElementById('rc-enabled').checked = true;
  document.getElementById('response-connector-form-title').textContent = 'Add Connector';
  renderResponseConnectorFields();
  document.getElementById('response-connector-form-wrap').style.display = '';
  document.getElementById('response-connector-form-wrap').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function openEditResponseConnector(id) {
  var c = (_responseConnectors || []).find(function(cfg) { return cfg.id === id; });
  if (!c) return;
  document.getElementById('rc-id').value = c.id;
  document.getElementById('rc-name').value = c.name || '';
  document.getElementById('rc-provider').value = c.provider || 'crowdstrike';
  document.getElementById('rc-base-url').value = c.baseUrl || '';
  document.getElementById('rc-tenant-id').value = c.tenantId || '';
  document.getElementById('rc-kill-script').value = c.killProcessScriptName || '';
  document.getElementById('rc-client-id').value = c.clientId || '';
  document.getElementById('rc-client-secret').value = '***';
  document.getElementById('rc-enabled').checked = !!c.enabled;
  document.getElementById('response-connector-form-title').textContent = 'Edit Connector';
  renderResponseConnectorFields();
  document.getElementById('response-connector-form-wrap').style.display = '';
  document.getElementById('response-connector-form-wrap').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function closeResponseConnectorForm() {
  document.getElementById('response-connector-form-wrap').style.display = 'none';
}

function saveResponseConnectorForm() {
  var id = document.getElementById('rc-id').value;
  var body = {
    name:                  document.getElementById('rc-name').value,
    provider:              document.getElementById('rc-provider').value,
    enabled:               document.getElementById('rc-enabled').checked,
    baseUrl:               document.getElementById('rc-base-url').value,
    tenantId:              document.getElementById('rc-tenant-id').value,
    killProcessScriptName: document.getElementById('rc-kill-script').value,
    clientId:              document.getElementById('rc-client-id').value,
    clientSecret:          document.getElementById('rc-client-secret').value
  };
  if (!body.name || !body.provider) { showToast('Name and provider are required', 'err'); return; }
  var url = id ? '/api/actions/configs/' + encodeURIComponent(id) : '/api/actions/configs';
  var method = id ? 'PUT' : 'POST';
  apicall(url, { method: method, body: JSON.stringify(body) })
    .then(function() {
      showToast('Connector saved', 'ok');
      closeResponseConnectorForm();
      loadResponseConnectors(renderResponseConnectorList);
    }).catch(function(e) { showToast(e.message, 'err'); });
}

function testResponseConnectorById(id, btn) {
  var orig = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = 'Testing…'; }
  apicall('/api/actions/configs/' + encodeURIComponent(id) + '/test', { method: 'POST' })
    .then(function(r) {
      showToast(r.ok ? 'Connection OK' : 'Failed: ' + (r.error || 'unknown'), r.ok ? 'ok' : 'err');
    }).catch(function(e) { showToast(e.message, 'err'); })
    .finally(function() { if (btn) { btn.disabled = false; btn.textContent = orig; } });
}

function deleteResponseConnector(id, name) {
  if (!confirm('Delete connector "' + name + '"? This cannot be undone.')) return;
  apicall('/api/actions/configs/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function() { showToast('Connector deleted', 'ok'); loadResponseConnectors(renderResponseConnectorList); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

function triggerTicketingSync() {
```

- [ ] **Step 4: Verify the hardlink twin is in sync**

```bash
diff orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
```
Expected: no output.

- [ ] **Step 5: Structural verification**

```bash
grep -n "response-connectors-list\|openAddResponseConnector\|saveResponseConnectorForm\|EPP Response Connectors" orchestrator/wwwroot/index.html
```
Expected: matches for the new markup IDs and all new function names.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): add EPP Response Connectors admin config screen"
```

---

### Task 2: "Respond" action on the Findings drawer

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (new modal HTML, added near the other modals, e.g. right after the Run Modal's closing `</div>` around line 3250)
- Modify: `orchestrator/wwwroot/index.html:7298-7310` (`openFinding` — add the Respond button)
- Modify: `orchestrator/wwwroot/index.html` (new JS functions, appended after `deleteResponseConnector`, same block Task 1 added)
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (same edits, hardlinked twin)

**Interfaces:**
- Consumes: `_responseConnectors`, `loadResponseConnectors` (Task 1); `apicall`, `showToast`, `x`; global `agents` array (`agentId`, `hostname` fields); global `ROLE` string; `window._findings` (already loaded by `loadFindings`).
- Produces: `openRespondModal()`, `closeRespondModal()`, `renderRespondFields()`, `submitRespondAction()`, module-level `_currentFinding` (set by `openFinding`, read by `openRespondModal`).

- [ ] **Step 1: Add the Respond modal markup**

In `orchestrator/wwwroot/index.html`, find the closing of the Run Modal (the `</div>` that ends `<div id="run-overlay" class="overlay">`, immediately before the `<!-- Technique / Ability Picker -->` comment):
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

<!-- Technique / Ability Picker -->
```
Replace with:
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
<div id="respond-overlay" class="overlay">
  <div class="modal" style="width:440px">
    <h3>Response Action</h3>
    <p class="sub2" id="respond-target-sub"></p>

    <label class="modal-lbl">Action</label>
    <select id="respond-action" onchange="renderRespondFields()">
      <option value="endpoint.isolate">Isolate host</option>
      <option value="endpoint.release">Release from isolation</option>
      <option value="endpoint.kill_process">Kill process</option>
      <option value="endpoint.quarantine_file">Quarantine file</option>
    </select>

    <label class="modal-lbl" style="margin-top:0.6rem">Connector</label>
    <select id="respond-connector" onchange="renderRespondFields()"></select>

    <div id="respond-extra-field" style="margin-top:0.6rem;display:none">
      <label class="modal-lbl" id="respond-extra-label"></label>
      <input type="text" id="respond-extra-value" placeholder=""
             style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">
    </div>

    <label class="modal-lbl" style="margin-top:0.6rem">Reason <span class="tiny muted">(required)</span></label>
    <input type="text" id="respond-reason" placeholder="e.g. confirmed ransomware simulation success"
           style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">

    <label class="modal-lbl" style="margin-top:0.6rem">Ticket reference <span class="tiny muted">(optional)</span></label>
    <input type="text" id="respond-ticket" placeholder="e.g. INC0012345"
           style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">

    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeRespondModal()">Cancel</button>
      <span style="flex:1"></span>
      <button id="respond-submit-btn" class="btn btn-outline-green btn-sm" onclick="submitRespondAction()">&#9654; Execute</button>
    </div>
  </div>
</div>

<!-- Technique / Ability Picker -->
```

- [ ] **Step 2: Add the Respond button to the Findings drawer**

Find:
```js
function openFinding(id) {
  apicall('/api/findings/' + encodeURIComponent(id)).then(function(f) {
    var e = f.enrichment || {};
    document.getElementById('results-title').textContent = (f.techniqueName || f.techniqueId) + ' — Finding';
    var row = function(k, v) { return v && v.length ? '<div style="display:flex;gap:0.6rem;padding:0.35rem 0;border-bottom:1px solid var(--border);font-size:0.8rem"><span style="color:var(--muted);min-width:140px">' + k + '</span><span style="flex:1">' + v + '</span></div>' : ''; };
    var list = function(a) { return (a || []).map(x).join(', '); };
    var canPush = (ROLE === 'admin' || ROLE === 'analyst');
    var pushBtn = canPush ? '<button class="btn btn-outline btn-sm" onclick="pushFindingToITSM(\'' + x(f.id) + '\')">+ Ticket</button>' : '';
    var actions = (canPush
      ? ['open', 'triaged', 'remediated', 'risk_accepted'].filter(function(st) { return st !== f.status; })
          .map(function(st) { return '<button class="btn btn-outline btn-sm" onclick="setFindingStatus(\'' + x(f.id) + '\',\'' + st + '\')">' + st.replace('_', ' ') + '</button>'; }).join(' ')
      : '');
    document.getElementById('results-export').innerHTML = (actions ? actions + ' ' : '') + pushBtn;
```
Replace with:
```js
function openFinding(id) {
  apicall('/api/findings/' + encodeURIComponent(id)).then(function(f) {
    _currentFinding = f;
    var e = f.enrichment || {};
    document.getElementById('results-title').textContent = (f.techniqueName || f.techniqueId) + ' — Finding';
    var row = function(k, v) { return v && v.length ? '<div style="display:flex;gap:0.6rem;padding:0.35rem 0;border-bottom:1px solid var(--border);font-size:0.8rem"><span style="color:var(--muted);min-width:140px">' + k + '</span><span style="flex:1">' + v + '</span></div>' : ''; };
    var list = function(a) { return (a || []).map(x).join(', '); };
    var canPush = (ROLE === 'admin' || ROLE === 'analyst');
    var pushBtn = canPush ? '<button class="btn btn-outline btn-sm" onclick="pushFindingToITSM(\'' + x(f.id) + '\')">+ Ticket</button>' : '';
    var respondBtn = (ROLE === 'admin') ? '<button class="btn btn-outline btn-sm" onclick="openRespondModal()">Respond</button>' : '';
    var actions = (canPush
      ? ['open', 'triaged', 'remediated', 'risk_accepted'].filter(function(st) { return st !== f.status; })
          .map(function(st) { return '<button class="btn btn-outline btn-sm" onclick="setFindingStatus(\'' + x(f.id) + '\',\'' + st + '\')">' + st.replace('_', ' ') + '</button>'; }).join(' ')
      : '');
    document.getElementById('results-export').innerHTML = (actions ? actions + ' ' : '') + pushBtn + (pushBtn && respondBtn ? ' ' : '') + respondBtn;
```
Note: the closing `}` of `openFinding` and everything after the `results-export` line are unchanged — do not duplicate them.

- [ ] **Step 3: Add the JS functions**

Find (the end of Task 1's `deleteResponseConnector`, right before `function triggerTicketingSync() {`):
```js
function deleteResponseConnector(id, name) {
  if (!confirm('Delete connector "' + name + '"? This cannot be undone.')) return;
  apicall('/api/actions/configs/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function() { showToast('Connector deleted', 'ok'); loadResponseConnectors(renderResponseConnectorList); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

function triggerTicketingSync() {
```
Replace with:
```js
function deleteResponseConnector(id, name) {
  if (!confirm('Delete connector "' + name + '"? This cannot be undone.')) return;
  apicall('/api/actions/configs/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function() { showToast('Connector deleted', 'ok'); loadResponseConnectors(renderResponseConnectorList); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// ── Respond (EPP response actions from the Findings drawer) ────────────────
var _currentFinding = null;
var RESPOND_ACTION_LABELS = {
  'endpoint.isolate': 'Isolate host', 'endpoint.release': 'Release from isolation',
  'endpoint.kill_process': 'Kill process', 'endpoint.quarantine_file': 'Quarantine file'
};

function _respondTargetHostname() {
  if (!_currentFinding) return '';
  var agent = (agents || []).find(function(a) { return a.agentId === _currentFinding.agentId; });
  return agent ? (agent.hostname || agent.agentId) : _currentFinding.agentId;
}

function openRespondModal() {
  if (!_currentFinding) return;
  var hostname = _respondTargetHostname();
  document.getElementById('respond-target-sub').textContent = 'Target: ' + hostname;
  document.getElementById('respond-action').value = 'endpoint.isolate';
  document.getElementById('respond-reason').value = '';
  document.getElementById('respond-ticket').value = '';
  document.getElementById('respond-extra-value').value = '';

  loadResponseConnectors(function(list) {
    var enabled = (list || []).filter(function(c) { return c.enabled; });
    var sel = document.getElementById('respond-connector');
    if (!enabled.length) {
      sel.innerHTML = '<option value="">No enabled connector configured</option>';
    } else {
      sel.innerHTML = enabled.map(function(c) {
        return '<option value="' + x(c.id) + '" data-provider="' + x(c.provider) + '">' + x(c.name) + '</option>';
      }).join('');
    }
    renderRespondFields();
  });

  document.getElementById('respond-overlay').classList.add('open');
}

function closeRespondModal() {
  document.getElementById('respond-overlay').classList.remove('open');
}

function renderRespondFields() {
  var action = document.getElementById('respond-action').value;
  var connSel = document.getElementById('respond-connector');
  var provider = (connSel.options[connSel.selectedIndex] || {}).getAttribute
    ? connSel.options[connSel.selectedIndex].getAttribute('data-provider') : '';
  var wrap = document.getElementById('respond-extra-field');
  var label = document.getElementById('respond-extra-label');
  var input = document.getElementById('respond-extra-value');

  if (action === 'endpoint.kill_process') {
    wrap.style.display = '';
    label.textContent = 'Process ID (PID)';
    input.placeholder = 'e.g. 4821';
  } else if (action === 'endpoint.quarantine_file') {
    wrap.style.display = '';
    if (provider === 'microsoft_defender') {
      label.textContent = 'File SHA1 hash';
      input.placeholder = 'e.g. aabbccddeeff00112233445566778899aabbccdd';
    } else {
      label.textContent = 'File path';
      input.placeholder = 'e.g. C:\\Users\\victim\\evil.exe';
    }
  } else {
    wrap.style.display = 'none';
  }
}

function submitRespondAction() {
  if (!_currentFinding) return;
  var action = document.getElementById('respond-action').value;
  var connectorId = document.getElementById('respond-connector').value;
  var reason = document.getElementById('respond-reason').value.trim();
  var ticketRef = document.getElementById('respond-ticket').value.trim();
  var hostname = _respondTargetHostname();

  if (!connectorId) { showToast('Select a connector', 'err'); return; }
  if (!reason) { showToast('Reason is required', 'err'); return; }

  var parameters = {};
  if (action === 'endpoint.kill_process') {
    var pid = parseInt(document.getElementById('respond-extra-value').value, 10);
    if (!pid || pid <= 0) { showToast('Enter a valid process ID', 'err'); return; }
    parameters.pid = pid;
  } else if (action === 'endpoint.quarantine_file') {
    var target = document.getElementById('respond-extra-value').value.trim();
    if (!target) { showToast('Enter the quarantine target', 'err'); return; }
    parameters.quarantineTarget = target;
  }

  var label = RESPOND_ACTION_LABELS[action] || action;
  if (!confirm(label + '\n\nHost: ' + hostname + '\nReason: ' + reason + '\n\nProceed?')) return;

  var btn = document.getElementById('respond-submit-btn');
  btn.disabled = true;
  apicall('/api/actions/run', {
    method: 'POST',
    body: JSON.stringify({
      type: action, hostname: hostname, parameters: parameters, connectorId: connectorId,
      reason: reason, ticketRef: ticketRef
    })
  }).then(function(res) {
    btn.disabled = false;
    if (res && res.status === 'completed') {
      showToast('Dispatched — ' + label, 'ok');
      closeRespondModal();
    } else {
      showToast('Failed: ' + (res && res.error ? res.error : 'unknown error'), 'err');
    }
  }).catch(function(e) { btn.disabled = false; showToast(e.message, 'err'); });
}

function triggerTicketingSync() {
```

- [ ] **Step 4: Verify the hardlink twin is in sync**

```bash
diff orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
```
Expected: no output.

- [ ] **Step 5: Structural verification**

```bash
grep -n "respond-overlay\|openRespondModal\|submitRespondAction\|RESPOND_ACTION_LABELS" orchestrator/wwwroot/index.html
```
Expected: matches for the modal ID and all new function names.

- [ ] **Step 6: Live-server smoke test**

Start a throwaway Postgres + the Go server (same pattern used in every prior UI plan this session):
```bash
docker run -d --name masd-ui-verify -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=bas -p 55450:5432 postgres:16-alpine
```
Wait for it to accept connections, then in `orchestrator/`:
```bash
DATABASE_URL="postgres://postgres:postgres@localhost:55450/bas?sslmode=disable" JWT_SECRET=dev-secret BAS_LICENSE_PATH="C:/Users/Administrator/Downloads/Audspect_Cloud/audspect-dev.lic" HTTP_PORT=8199 go run ./cmd/server
```
In a second shell:
```bash
curl -s http://localhost:8199/ | grep -o "EPP Response Connectors\|respond-overlay\|Kill process"
```
Expected: all three strings present in the served HTML.

Then stop the server and container:
```bash
powershell -Command "Get-NetTCPConnection -LocalPort 8199 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }"
docker rm -f masd-ui-verify
```

- [ ] **Step 7: Record the manual browser checklist (cannot be executed by the implementer — no browser automation tool is available in this environment)**

Before this branch is merged, a human must verify in an actual browser, logged in as Admin:
1. Go to Integrations tab — confirm the new "EPP Response Connectors" section appears below the existing ITSM connectors, with "No response connectors configured" shown initially.
2. Click "+ Add Connector", select CrowdStrike — confirm only the Base URL field shows (not Tenant ID/Kill Script). Fill in real or dummy CrowdStrike credentials, save — confirm it appears in the list as Enabled.
3. Click "+ Add Connector" again, select Microsoft Defender — confirm Tenant ID + Kill Process Script Name fields show instead, and the RTR/Live-Response warning note is visible. Save.
4. Click Edit on the CrowdStrike connector — confirm Client Secret shows as `***` (not the real value), and saving without touching it doesn't corrupt the stored secret (verify via a second Edit — should still show `***`, not blank or garbage).
5. Click Test on a connector — confirm a toast appears (OK or a real vendor error, since this is a dummy/real credential test).
6. Click Delete — confirm the browser's native confirm dialog appears, and the connector is removed from the list on confirm.
7. Log in as a non-admin (Analyst) — confirm the Integrations tab (and therefore the Response Connectors section) isn't reachable at all, matching this tab's existing admin-only gating.
8. As Admin, open a Findings row — confirm a "Respond" button appears in the drawer next to "+ Ticket" / triage-status buttons.
9. Click Respond — confirm the modal shows the target hostname, the action dropdown defaults to "Isolate host", and the connector dropdown lists only enabled connectors (or "No enabled connector configured" if none).
10. Switch the action to "Kill process" — confirm a "Process ID (PID)" text input appears. Switch to "Quarantine file" with a CrowdStrike connector selected — confirm the label reads "File path"; switch the connector to a Defender one (if configured) — confirm the label changes to "File SHA1 hash" without needing to re-open the modal.
11. Leave Reason empty and click Execute — confirm it's rejected client-side with a toast, no `confirm()` dialog shown.
12. Fill in Reason, click Execute — confirm the native `confirm()` dialog shows the action, host, and reason; cancelling leaves the modal open with nothing dispatched.
13. Accept the dialog — confirm a toast reports success or failure, and on success the modal closes. Check the connector's vendor console (or the `action_requests` table directly) to confirm a row was actually persisted with the operator's user ID as `requested_by`.
14. Log in as a non-admin — confirm no "Respond" button appears anywhere on the Findings page.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): add Respond action (isolate/kill/quarantine) to Findings drawer"
```

---

## Self-Review Notes

**Spec coverage:** completes the spec's entire UI section — Response Connectors admin config screen (co-located pattern, same visual language as the existing ITSM connector screen without inheriting its wrong body shape) and the Findings-drawer Respond menu (Admin-only, hostname resolved from the finding's agent, Reason mandatory, native `confirm()` echoing action/host/reason, Kill Process/Quarantine File collect their extra parameter, the Defender-specific SHA1-vs-path label distinction from Plan 3, and the Defender Kill Process script-dependency warning surfaced in the connector form). This is the last plan for the feature — spec fully implemented end to end after this.

**Placeholder scan:** none — every step contains complete markup/code or an exact command with expected output. The manual browser checklist is a genuine limitation (no browser automation available), not a placeholder — it's the same disclosed pattern used in every prior UI plan this session, with concrete numbered steps a human can actually follow.

**Type/name consistency:** Task 2 consumes exactly `_responseConnectors`/`loadResponseConnectors` as named and shaped in Task 1 (array of `{id, name, provider, enabled, ...}`). The request body field names in `submitRespondAction` (`type`, `hostname`, `parameters`, `connectorId`, `reason`, `ticketRef`) match `ExecuteResponseAction`'s exact JSON tags from Plan 4. `parameters.pid`/`parameters.quarantineTarget` match `internal/actions.dispatch`'s exact parameter-key reads from Plan 1. `saveResponseConnectorForm`'s body field names (`name`, `provider`, `enabled`, `baseUrl`, `tenantId`, `killProcessScriptName`, `clientId`, `clientSecret`) match `CreateResponseConnector`/`UpdateResponseConnector`'s exact JSON tags from Plan 4.
