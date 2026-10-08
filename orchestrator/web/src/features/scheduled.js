import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { ROLE } from './shell.js';
import { setDisplay } from '../core/inline-style.js';


// ── Scheduled Assessments ──────────────────────────────────────────────────
// List + create + cancel for POST/GET /api/scheduled-assessments and
// POST /api/scheduled-assessments/{id}/cancel. jobs.Schedule has no JSON
// struct tags server-side, so every field read off a schedule object below
// uses the exact Go field name (PascalCase), not camelCase.
export var SCHED = {
  schedules: [],   // raw list from GET /api/scheduled-assessments
  groups: [],      // nested group tree, fetched fresh when the wizard opens
  groupsById: {},  // flat id -> name, built from `groups`
  agentsAll: [],   // flat agent list, fetched fresh when the wizard opens
  selGroups: {},   // groupId -> true for wizard checkbox state
  selAgents: {},   // agentId -> true for wizard checkbox state
  groupsAccessDenied: false, // true when /api/agent-groups 403'd (Analyst), not just empty
  step: 1,
  editingId: null,        // null when creating; the schedule's ID when editing
  editPrefillMode: '',    // consumed once by renderSchedModeRecurrencePane's first render --
  editPrefillTimezone: '', // see that function for why Mode/Timezone need this indirection
  initiativesActive: [],   // GET /api/initiatives?state=active, fetched fresh when the wizard opens
  editPrefillInitiativeId: '' // same indirection as editPrefillMode -- #sched-initiative has no
                               // <option>s until initiativesActive's fetch resolves and populates it
};

export function loadScheduledAssessments() {
  Promise.all([
    apicall('/api/scheduled-assessments'),
    apicall('/api/agent-groups')
  ]).then(function(res) {
    if (res[0] && res[0].error) { showToast(res[0].error, 'err'); return; }
    SCHED.schedules = (res[0] && res[0].schedules) || [];
    var groups = Array.isArray(res[1]) ? res[1] : [];
    SCHED.groupsById = schedFlattenGroupNames(groups, {});
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

export function renderScheduledAssessmentsList() {
  document.getElementById('sched-cnt').textContent = SCHED.schedules.length;
  var tbody = document.getElementById('sched-body');
  if (!SCHED.schedules.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">No scheduled assessments yet.</td></tr>';
    return;
  }
  tbody.innerHTML = SCHED.schedules.map(function(sch) {
    // sch.Payload is a Go json.RawMessage with no json:"..." tag override, so
    // it arrives already embedded as a real object in the outer response --
    // NOT as a JSON string needing a second JSON.parse (that silently threw,
    // caught below, and always fell back to {} -- see openSchedWizardForEdit's
    // identical fix for the same root cause).
    var payload = sch.Payload || {};
    var sc = state.scenarios.find(function(s) { return s.id === payload.scenarioId; });
    var name = sc ? sc.name : (payload.scenarioId || '—');
    var modeColor = sch.Mode === 'telemetry' ? 'g1-s-d6e5d834' : 'g1-s-8297411d';
    var modeLabel = sch.Mode === 'telemetry' ? 'Telemetry' : 'Posture';
    // A "once" schedule's Enabled flag is never flipped after it fires --
    // only LastOccurrenceAt gets set (see internal/jobs/dispatch.go's
    // spawnDueSchedules -> MarkScheduleOccurrenceHandled). nextOccurrenceOnce
    // already treats LastOccurrenceAt != nil as "never fires again" server-
    // side; mirror that here so Edit/Cancel stop being offered for a
    // one-time schedule that has nothing left to edit or cancel.
    var onceCompleted = sch.RecurrenceType === 'once' && !!sch.LastOccurrenceAt;
    var statusColor = onceCompleted ? 'g1-s-10acb108' : (sch.Enabled ? 'g1-s-f213c12d' : 'g1-s-8297411d');
    var statusLabel = onceCompleted ? 'Completed' : (sch.Enabled ? 'Enabled' : 'Cancelled');
    var lastRun = sch.LastOccurrenceAt ? fmtDate(sch.LastOccurrenceAt) : 'Never';
    return '<tr>' +
      '<td>' + x(name) + '</td>' +
      '<td><span class="badge ' + modeColor + '">' + modeLabel + '</span></td>' +
      '<td>' + x(schedTargetsText(sch)) + '</td>' +
      '<td>' + x(schedRecurrenceText(sch)) + '</td>' +
      '<td>' + x(lastRun) + '</td>' +
      '<td><span class="badge ' + statusColor + '">' + statusLabel + '</span></td>' +
      '<td>' +
        (onceCompleted
          ? '<span class="tiny muted">Ran once — nothing to edit or cancel</span>'
          : '<button class="btn btn-outline btn-sm"' + on('click', 'openSchedWizardForEdit', sch.ID) + '>Edit</button>' +
            (sch.Enabled ? ' <button class="btn btn-outline btn-sm"' + on('click', 'cancelScheduledAssessment', sch.ID) + '>Cancel</button>' : '')) +
      '</td>' +
    '</tr>';
  }).join('');
}

export function cancelScheduledAssessment(id) {
  if (!confirm('Cancel this scheduled assessment? It will stop firing future runs; the schedule stays visible in this list as Cancelled.')) return;
  apicall('/api/scheduled-assessments/' + encodeURIComponent(id) + '/cancel', { method: 'POST' }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    showToast('Schedule cancelled', 'ok');
    loadScheduledAssessments();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function openSchedWizard() {
  SCHED.selGroups = {}; SCHED.selAgents = {};
  SCHED.modeInitialized = false;
  SCHED.groupsAccessDenied = false;
  SCHED.editingId = null;
  SCHED.editPrefillMode = '';
  SCHED.editPrefillTimezone = '';
  SCHED.editPrefillInitiativeId = '';
  document.getElementById('sched-wz-title').textContent = 'New Scheduled Assessment';
  document.getElementById('sched-create-btn').textContent = 'Create Schedule';
  document.getElementById('sched-group-cnt').textContent = '(0 selected)';
  document.getElementById('sched-agent-cnt').textContent = '(0 selected)';
  document.getElementById('sched-reason').value = '';
  document.getElementById('sched-recurrence-type').value = 'weekly';
  document.getElementById('sched-runat').value = '';
  document.getElementById('sched-dow').value = '0';
  document.getElementById('sched-dom').value = '1';
  document.getElementById('sched-timeofday').value = '02:00';
  document.getElementById('sched-enddate').value = '';
  document.getElementById('sched-concurrency').value = '';
  var sel = document.getElementById('sched-scenario');
  sel.innerHTML = state.scenarios.map(function(s) { return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>'; }).join('');
  Promise.all([apicall('/api/agent-groups'), apicall('/api/agents'), apicall('/api/initiatives?state=active')]).then(function(res) {
    SCHED.groupsAccessDenied = !!(res[0] && res[0].error);
    SCHED.groups = Array.isArray(res[0]) ? res[0] : [];
    SCHED.groupsById = schedFlattenGroupNames(SCHED.groups, {});
    SCHED.agentsAll = Array.isArray(res[1]) ? res[1] : [];
    SCHED.initiativesActive = (res[2] && res[2].initiatives) || [];
    renderSchedGroupTree();
    renderSchedAgentList();
    renderSchedInitiativeSelect();
  }).catch(function(e) { showToast(e.message, 'err'); });
  document.getElementById('sched-overlay').classList.add('open');
  schedWizardSet(1);
}

// openSchedWizardForEdit prefills the same wizard openSchedWizard() uses,
// from an existing schedule's current values. Every field can be set with a
// direct .value assignment at this point EXCEPT Mode and Timezone -- #sched-mode
// starts with zero <option> elements (entirely built by
// renderSchedModeRecurrencePane() the first time step 3 renders) and that
// same function's first-render branch unconditionally resets Timezone to the
// browser's local zone. SCHED.editPrefillMode/editPrefillTimezone route
// around that -- see renderSchedModeRecurrencePane's updated first-render
// branch below.
export function openSchedWizardForEdit(id) {
  var sch = SCHED.schedules.find(function(s) { return s.ID === id; });
  if (!sch) { showToast('Schedule not found', 'err'); return; }
  // sch.Payload arrives already parsed (json.RawMessage embeds as a real
  // object, not a JSON string) -- see renderScheduledAssessmentsList's
  // matching fix for the full explanation.
  var payload = sch.Payload || {};

  SCHED.selGroups = {};
  (sch.GroupIDs || []).forEach(function(gid) { SCHED.selGroups[gid] = true; });
  SCHED.selAgents = {};
  (sch.AgentIDs || []).forEach(function(aid) { SCHED.selAgents[aid] = true; });
  SCHED.modeInitialized = false;
  SCHED.groupsAccessDenied = false;
  SCHED.editingId = sch.ID;
  SCHED.editPrefillMode = sch.Mode || 'posture';
  SCHED.editPrefillTimezone = sch.Timezone || '';
  SCHED.editPrefillInitiativeId = sch.InitiativeID || '';

  document.getElementById('sched-wz-title').textContent = 'Edit Scheduled Assessment';
  document.getElementById('sched-create-btn').textContent = 'Save Changes';
  document.getElementById('sched-group-cnt').textContent = '(' + Object.keys(SCHED.selGroups).length + ' selected)';
  document.getElementById('sched-agent-cnt').textContent = '(' + Object.keys(SCHED.selAgents).length + ' selected)';
  document.getElementById('sched-reason').value = sch.Reason || '';
  document.getElementById('sched-recurrence-type').value = sch.RecurrenceType || 'weekly';
  document.getElementById('sched-runat').value = sch.RunAt ? new Date(sch.RunAt).toISOString().slice(0, 16) : '';
  document.getElementById('sched-dow').value = String(sch.DayOfWeek || 0);
  document.getElementById('sched-dom').value = String(sch.DayOfMonth || 1);
  document.getElementById('sched-timeofday').value = sch.TimeOfDay || '02:00';
  document.getElementById('sched-enddate').value = sch.EndDate ? new Date(sch.EndDate).toISOString().slice(0, 10) : '';
  document.getElementById('sched-concurrency').value = sch.ConcurrencyLimit || '';

  var sel = document.getElementById('sched-scenario');
  sel.innerHTML = state.scenarios.map(function(s) { return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>'; }).join('');
  sel.value = payload.scenarioId || '';

  Promise.all([apicall('/api/agent-groups'), apicall('/api/agents'), apicall('/api/initiatives?state=active')]).then(function(res) {
    SCHED.groupsAccessDenied = !!(res[0] && res[0].error);
    SCHED.groups = Array.isArray(res[0]) ? res[0] : [];
    SCHED.groupsById = schedFlattenGroupNames(SCHED.groups, {});
    SCHED.agentsAll = Array.isArray(res[1]) ? res[1] : [];
    SCHED.initiativesActive = (res[2] && res[2].initiatives) || [];
    renderSchedGroupTree();
    renderSchedAgentList();
    renderSchedInitiativeSelect();
  }).catch(function(e) { showToast(e.message, 'err'); });
  document.getElementById('sched-overlay').classList.add('open');
  schedWizardSet(1);
}

export function closeSchedWizard() {
  document.getElementById('sched-overlay').classList.remove('open');
}

function schedWizardSet(step) {
  if (step < 1) step = 1;
  if (step > 4) step = 4;
  SCHED.step = step;
  [1, 2, 3, 4].forEach(function(n) {
    var pane = document.querySelector('[data-sched-pane="' + n + '"]');
    if (pane) setDisplay(pane, (n === step) ? 'block' : 'none');
    var pip = document.querySelector('[data-sched-pip="' + n + '"]');
    if (pip) { pip.classList.toggle('active', n === step); pip.classList.toggle('done', n < step); }
  });
  setDisplay(document.getElementById('sched-wz-back'), (step > 1) ? '' : 'none');
  setDisplay(document.getElementById('sched-wz-next'), (step < 4) ? '' : 'none');
  setDisplay(document.getElementById('sched-create-btn'), (step === 4) ? '' : 'none');
  // Re-evaluate agent platform compatibility every time step 2 is entered --
  // covers Back-then-forward after switching the step-1 scenario selection.
  if (step === 2) renderSchedAgentList();
  if (step === 3) renderSchedModeRecurrencePane();
  if (step === 4) renderSchedReview();
}

export function schedWizardNav(dir) { schedWizardSet(SCHED.step + dir); }

export function schedAuthCheckChange(el) {
  document.getElementById('sched-create-btn').disabled = !el.checked;
}

export function schedToggleGroupFromChecked(id, el) { schedToggleGroup(id, el.checked); }
export function schedToggleAgentFromChecked(id, el) { schedToggleAgent(id, el.checked); }

export function schedToggleGroup(id, checked) {
  if (checked) SCHED.selGroups[id] = true; else delete SCHED.selGroups[id];
  document.getElementById('sched-group-cnt').textContent = '(' + Object.keys(SCHED.selGroups).length + ' selected)';
}

export function schedToggleAgent(id, checked) {
  if (checked) SCHED.selAgents[id] = true; else delete SCHED.selAgents[id];
  document.getElementById('sched-agent-cnt').textContent = '(' + Object.keys(SCHED.selAgents).length + ' selected)';
}

function renderSchedGroupTree() {
  var root = document.getElementById('sched-group-tree');
  if (!root) return;
  if (!SCHED.groups.length) {
    root.innerHTML = SCHED.groupsAccessDenied
      ? '<div class="empty">Group targeting requires Administrator access — select individual agents instead.</div>'
      : '<div class="empty">No agent groups defined.</div>';
    return;
  }
  root.innerHTML = SCHED.groups.map(renderSchedGroupNode).join('');
}

function renderSchedGroupNode(node) {
  var hasChildren = node.children && node.children.length;
  var checked = SCHED.selGroups[node.id] ? ' checked' : '';
  var html = '<div class="at-node">' +
    '<label class="g1-display-flex g1-s-16487d2d">' +
    '<input type="checkbox"' + checked + on('change', 'schedToggleGroupFromChecked', node.id) + '>' +
    '<span class="at-name">' + x(node.name) + '</span>' +
    '<span class="at-count">' + node.totalAgentCount + '</span>' +
    '</label></div>';
  if (hasChildren) {
    html += '<div class="at-children">' + node.children.map(renderSchedGroupNode).join('') + '</div>';
  }
  return html;
}

// schedClassifyOS mirrors the server's classifyAgentOS (internal/api/handlers.go)
// exactly, so an agent's compatibility badge in this wizard never disagrees
// with the server-side scheduleOSCompatibilityError backstop that actually
// enforces it.
export function schedClassifyOS(osVersion) {
  var lower = (osVersion || '').toLowerCase();
  if (lower.indexOf('windows') !== -1) return 'windows';
  if (lower.indexOf('darwin') !== -1 || lower.indexOf('macos') !== -1 || lower.indexOf('mac os') !== -1) return 'darwin';
  if (lower.indexOf('linux') !== -1 || lower.indexOf('ubuntu') !== -1 || lower.indexOf('debian') !== -1 ||
      lower.indexOf('centos') !== -1 || lower.indexOf('rhel') !== -1 || lower.indexOf('fedora') !== -1 ||
      lower.indexOf('kali') !== -1 || lower.indexOf('arch') !== -1) return 'linux';
  return '';
}

// schedAgentCompatible mirrors revalOSCompatible's "empty = unrestricted" rule:
// an empty supportedOS list, or an agent whose OS string doesn't classify to
// anything recognized, is treated as compatible rather than blocked.
export function schedAgentCompatible(agent, supportedOS) {
  if (!supportedOS || !supportedOS.length) return true;
  var agentOS = schedClassifyOS(agent.osVersion);
  if (!agentOS) return true;
  return supportedOS.some(function(o) { return o.toLowerCase() === agentOS; });
}

// vexFilterWindowsAgents drops non-Windows agents from a resolved
// group/all-agent target list -- every variant Template is Windows-only
// PowerShell (internal/variant/generator.go), so this is a flat filter, not
// a per-scenario compatibility check like schedAgentCompatible. An agent
// whose OS string doesn't classify to anything recognized stays included
// (same "unrestricted when unclassified" convention used throughout).
export function vexFilterWindowsAgents(list) {
  return (list || []).filter(function(a) {
    var os = schedClassifyOS(a.osVersion);
    return os !== 'linux' && os !== 'darwin';
  });
}

function schedSelectedScenarioSupportedOS() {
  var sc = state.scenarios.find(function(s) { return s.id === document.getElementById('sched-scenario').value; });
  return (sc && sc.supportedOs) || [];
}

function renderSchedAgentList() {
  var root = document.getElementById('sched-agent-list');
  if (!root) return;
  if (!SCHED.agentsAll.length) { root.innerHTML = '<div class="empty">No agents registered.</div>'; return; }
  var supportedOS = schedSelectedScenarioSupportedOS();
  root.innerHTML = SCHED.agentsAll.map(function(a) {
    var compatible = schedAgentCompatible(a, supportedOS);
    // A previously-checked agent that's now incompatible (scenario changed
    // after selection) must not stay silently selected.
    if (!compatible && SCHED.selAgents[a.agentId]) delete SCHED.selAgents[a.agentId];
    var checked = SCHED.selAgents[a.agentId] ? ' checked' : '';
    var disabled = compatible ? '' : ' disabled';
    var warn = compatible ? '' : ' <span class="tiny u-danger">Platform mismatch</span>';
    return '<label class="g1-display-flex g1-s-199650cf ' + (compatible ? 'g1-s-46d9ceb8' : 'g1-s-3b456e9f') + '">' +
      '<input type="checkbox"' + checked + disabled + on('change', 'schedToggleAgentFromChecked', a.agentId) + '>' +
      '<code class="g1-s-8f55e862">' + x(a.agentId) + '</code><span class="tiny muted">' + x(a.hostname) + ' — ' + x(a.osVersion || 'Unknown OS') + '</span>' + warn + '</label>';
  }).join('');
  document.getElementById('sched-agent-cnt').textContent = '(' + Object.keys(SCHED.selAgents).length + ' selected)';
}

// renderSchedInitiativeSelect populates #sched-initiative from
// SCHED.initiativesActive, applying SCHED.editPrefillInitiativeId the same
// way renderSchedModeRecurrencePane applies editPrefillMode -- the fetch
// that fills initiativesActive resolves after schedWizardSet(1) has already
// run, so an earlier direct .value= assignment would be a no-op. If the
// schedule's current initiative isn't in the active list (closed/archived
// since scheduling, or simply not yet loaded), the assignment silently
// fails and the select falls back to "None" -- same fallback behavior
// #sched-mode already has for a no-longer-valid previous selection.
function renderSchedInitiativeSelect() {
  var sel = document.getElementById('sched-initiative');
  if (!sel) return;
  sel.innerHTML = '<option value="">— None —</option>' +
    SCHED.initiativesActive.map(function(it) { return '<option value="' + x(it.ID) + '">' + x(it.Name) + '</option>'; }).join('');
  sel.value = SCHED.editPrefillInitiativeId || '';
}

function renderSchedModeRecurrencePane() {
  var modeSel = document.getElementById('sched-mode');
  var prevMode = modeSel.value;
  var sc = state.scenarios.find(function(s) { return s.id === document.getElementById('sched-scenario').value; });
  var opts = '<option value="posture">Posture — read-only, safe on any host</option>';
  if (ROLE === 'admin' && sc && sc.executable) {
    opts += '<option value="telemetry">Telemetry — real identity-safe techniques (requires authorization)</option>';
  }
  modeSel.innerHTML = opts;
  if (SCHED.modeInitialized) {
    modeSel.value = prevMode;
    // If the previously-selected mode's option no longer exists (e.g. Back-navigated
    // to step 1 and picked a non-executable scenario while Telemetry was selected),
    // the assignment above silently fails to select anything -- fall back to Posture.
    if (modeSel.value !== prevMode) modeSel.value = 'posture';
  } else {
    // First render: default to Posture + the browser's local timezone, UNLESS
    // openSchedWizardForEdit() stashed a prefill (SCHED.editPrefillMode/
    // editPrefillTimezone) -- #sched-mode has no <option> elements until this
    // function builds them above, so an earlier direct .value= assignment at
    // wizard-open time would have been a no-op; this indirection is required.
    var wantMode = SCHED.editPrefillMode || 'posture';
    modeSel.value = wantMode;
    if (modeSel.value !== wantMode) modeSel.value = 'posture';
    document.getElementById('sched-timezone').value = SCHED.editPrefillTimezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    SCHED.modeInitialized = true;
  }
  schedOnModeChange();
  schedOnRecurrenceChange();
}

export function schedOnModeChange() {
  var mode = document.getElementById('sched-mode').value;
  var isTelemetry = mode === 'telemetry';
  setDisplay(document.getElementById('sched-mode-warn'), isTelemetry ? 'block' : 'none');
  setDisplay(document.getElementById('sched-reason-wrap'), isTelemetry ? 'block' : 'none');
}

export function schedOnRecurrenceChange() {
  var type = document.getElementById('sched-recurrence-type').value;
  setDisplay(document.getElementById('sched-once-wrap'), (type === 'once') ? 'block' : 'none');
  setDisplay(document.getElementById('sched-dow-wrap'), (type === 'weekly') ? 'block' : 'none');
  setDisplay(document.getElementById('sched-dom-wrap'), (type === 'monthly') ? 'block' : 'none');
  setDisplay(document.getElementById('sched-time-wrap'), (type === 'once') ? 'none' : 'block');
}

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
  var initiativeId = document.getElementById('sched-initiative').value;
  if (initiativeId) body.initiativeId = initiativeId;
  return body;
}

function renderSchedReview() {
  var payload = schedBuildPayload();
  var sc = state.scenarios.find(function(s) { return s.id === payload.scenarioId; });
  var groupNames = (payload.groupIds || []).map(function(id) { return SCHED.groupsById[id] || ('#' + id); });
  var targetsLine = [groupNames.join(', '), payload.agentIds.length ? (payload.agentIds.length + ' agent(s)') : '']
    .filter(function(s) { return s; }).join(' + ') || '—';
  var recurrenceLine = payload.recurrenceType === 'once'
    ? 'Once · ' + (payload.runAt ? new Date(payload.runAt).toLocaleString() : '—')
    : payload.recurrenceType === 'daily' ? 'Daily · ' + payload.timeOfDay
    : payload.recurrenceType === 'monthly' ? 'Monthly · Day ' + payload.dayOfMonth + ' · ' + payload.timeOfDay
    : 'Weekly · ' + SCHED_DOW[payload.dayOfWeek] + ' · ' + payload.timeOfDay;
  var initiative = SCHED.initiativesActive.find(function(it) { return it.ID === payload.initiativeId; });

  var html = '<div class="g1-s-1662da4e">' +
    '<div><strong>Scenario:</strong> ' + x(sc ? sc.name : payload.scenarioId) + '</div>' +
    '<div><strong>Mode:</strong> ' + x(payload.mode === 'telemetry' ? 'Telemetry' : 'Posture') + '</div>' +
    '<div><strong>Targets:</strong> ' + x(targetsLine) + '</div>' +
    '<div><strong>Recurrence:</strong> ' + x(recurrenceLine) + ' · ' + x(payload.timezone) + '</div>' +
    '<div><strong>Concurrency:</strong> ' + x(payload.concurrencyLimit || 'Unlimited') + '</div>' +
    '<div><strong>End date:</strong> ' + x(payload.endDate ? new Date(payload.endDate).toLocaleDateString() : 'None') + '</div>' +
    '<div><strong>Initiative:</strong> ' + x(initiative ? initiative.Name : 'None') + '</div>' +
    '</div>';

  var authWrap = '';
  if (payload.mode === 'telemetry') {
    authWrap = '<div class="g1-s-8b8a9186">' +
      '<div class="g1-s-0f7fb8b9">&#9888; Unattended Telemetry Authorization</div>' +
      '<div class="g1-s-e761abd2">This schedule will execute real techniques that may generate security alerts on the selected targets, on every future occurrence, with no further confirmation.</div>' +
      '<div class="g1-s-13741987"><strong>Reason:</strong> ' + x(payload.reason || '(none entered)') + '</div>' +
      '<label class="g1-display-flex g1-s-5914e41c">' +
      '<input type="checkbox" id="sched-auth-check"' + on('change', 'schedAuthCheckChange') + '>' +
      'I authorize this recurring unattended execution</label>' +
      '</div>';
  }

  document.getElementById('sched-review').innerHTML = html + authWrap;
  var createBtn = document.getElementById('sched-create-btn');
  createBtn.disabled = (payload.mode === 'telemetry'); // re-enabled by the checkbox above once checked
}

export function submitScheduledAssessment() {
  var payload = schedBuildPayload();
  if (!payload.scenarioId) { showToast('Select a scenario', 'err'); return; }
  if (!payload.agentIds.length && !payload.groupIds.length) { showToast('Select at least one target group or agent', 'err'); return; }
  if (payload.mode === 'telemetry' && !payload.reason) { showToast('Reason is required for a telemetry-mode schedule', 'err'); return; }
  // Defensive backstop -- the wizard already disables incompatible agent
  // checkboxes, but re-check here in case the scenario changed after step 2
  // without a re-render, or a group's membership includes one at submit time
  // (groups aren't filtered client-side; the server does the real check).
  var supportedOS = schedSelectedScenarioSupportedOS();
  var incompatible = SCHED.agentsAll.filter(function(a) {
    return payload.agentIds.indexOf(a.agentId) !== -1 && !schedAgentCompatible(a, supportedOS);
  });
  if (incompatible.length) {
    showToast('Selected agent(s) do not support the platform required by this scenario.', 'err');
    return;
  }

  var btn = document.getElementById('sched-create-btn');
  btn.disabled = true;
  var isEdit = !!SCHED.editingId;
  var url = isEdit ? '/api/scheduled-assessments/' + encodeURIComponent(SCHED.editingId) : '/api/scheduled-assessments';
  var method = isEdit ? 'PUT' : 'POST';
  apicall(url, { method: method, body: JSON.stringify(payload) }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); btn.disabled = false; return; }
    showToast(isEdit ? 'Scheduled assessment updated' : 'Scheduled assessment created', 'ok');
    closeSchedWizard();
    loadScheduledAssessments();
  }).catch(function(e) { showToast(e.message, 'err'); btn.disabled = false; });
}
