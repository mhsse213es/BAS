import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';

// ── Database Security Simulation (dbsim) ─────────────────
// Console page for the DAM BAS capability. Talks only to the /api/dbsim*
// endpoints: targets, identity checks, client read-only mode, starting and
// cancelling runs, the live status of the active run, the summary, and stored
// results.

// DBSIM_CATALOG mirrors the shipped scenarios in internal/dbsim/expectations.go.
// There is no server-side scenario list for this product, so it is kept here.
var DBSIM_CATALOG = [
  { id: 'dbsim-db01-auth-policy', label: 'DB-01 Authentication policy' },
  { id: 'dbsim-db02-excessive-grants', label: 'DB-02 Excessive grants' },
  { id: 'dbsim-db03-unauthorized-access', label: 'DB-03 Unauthorized access' },
  { id: 'dbsim-db04-audit-coverage', label: 'DB-04 Audit coverage' },
  { id: 'dbsim-db05-suspicious-read', label: 'DB-05 Suspicious read' },
  { id: 'dbsim-db06-account-revocation', label: 'DB-06 Account revocation' },
  { id: 'dbsim-db07-sensitive-classification', label: 'DB-07 Sensitive classification' },
  { id: 'dbsim-db08-audit-tamper-resistance', label: 'DB-08 Audit tamper resistance' },
  { id: 'dbsim-db09-bounded-bulk-read', label: 'DB-09 Bounded bulk read' },
  { id: 'dbsim-db10-write-delete-prevention', label: 'DB-10 Write and delete prevention' },
  { id: 'dbsim-db11-backup-export-permissions', label: 'DB-11 Backup and export permissions' }
];

// Statuses after which a job no longer changes.
var TERMINAL = { completed: true, failed: true, partial: true, cancelled: true };
var POLL_MS = 5000;

var state = {
  settings: null, targets: [], runs: [], summary: null, error: '',
  selected: {},          // scenario id -> true
  labConfirm: '',        // typed target name for a lab run
  targetId: '',          // selected target for a new run
  activeRun: null,       // { runId, status, reason, targetId, agentId }
};
var pollTimer = null;

function toText(v) { return v == null ? '' : String(v); }

function errMsg(res, fallback) {
  if (res && res.error) return String(res.error);
  if (res && res.message) return String(res.message);
  return fallback;
}

function pill(text, tone) {
  return '<span class="pill pill-' + x(tone || 'muted') + '">' + x(text) + '</span>';
}

function identityPill(ic) {
  if (!ic || !ic.checked) return pill('not checked', 'muted');
  return ic.passed ? pill('identity ok', 'ok') : pill('identity failed', 'bad');
}

function modePill(t) {
  if (t.mode === 'client') return pill('client (read-only)', 'warn');
  return t.labConfirmed ? pill('lab, confirmed', 'ok') : pill('lab, not confirmed', 'bad');
}

function statusTone(s) {
  if (s === 'completed') return 'ok';
  if (s === 'failed') return 'bad';
  if (s === 'partial' || s === 'cancelled') return 'warn';
  return 'muted';
}

function selectedIds() {
  return DBSIM_CATALOG.map(function(c) { return c.id; }).filter(function(id) { return state.selected[id]; });
}

function selectedTarget() {
  for (var i = 0; i < state.targets.length; i++) {
    if (state.targets[i].id === state.targetId) return state.targets[i];
  }
  return null;
}

export function loadDBSimTab() {
  state.error = '';
  return Promise.all([
    apicall('/api/dbsim/settings'),
    apicall('/api/dbsim-targets'),
    apicall('/api/dbsim-runs'),
    apicall('/api/dbsim-summary')
  ]).then(function(res) {
    state.settings = res[0] || null;
    state.targets = Array.isArray(res[1]) ? res[1] : (res[1] && res[1].targets) || [];
    state.runs = Array.isArray(res[2]) ? res[2] : (res[2] && res[2].runs) || [];
    state.summary = res[3] && !res[3].error ? res[3] : null;
    renderDBSim();
  }).catch(function(err) {
    state.error = 'Could not load dbsim data: ' + (err && err.message ? err.message : err);
    renderDBSim();
  });
}

export function refreshDBSimTab() { return loadDBSimTab(); }

function renderSummary() {
  var s = state.summary;
  if (!s) return '<div class="muted">Summary unavailable.</div>';
  return '<div class="dbsim-kpis">' +
    '<div><strong>' + x(s.preventionBlocked) + ' / ' + x(s.preventionAssessable) + '</strong><div class="muted small">prevention blocked</div></div>' +
    '<div><strong>' + x(s.detectionCaught) + ' / ' + x(s.detectionAssessable) + '</strong><div class="muted small">detection caught</div></div>' +
    '<div><strong>' + x(s.unableToAssess) + '</strong><div class="muted small">unable to assess</div></div>' +
    '</div>' +
    '<div class="muted small">Counts use the latest run of each scenario and target. Response is not tested by this product.' +
    (s.reportsSkipped ? ' ' + x(s.reportsSkipped) + ' stored report(s) could not be read and are not counted.' : '') + '</div>';
}

function renderSettings() {
  var s = state.settings;
  if (!s) return '<div class="muted">Settings unavailable.</div>';
  var on_ = !!s.clientModeEnabled;
  return '<div class="dbsim-row"><span>Client read-only mode:</span> ' +
    (on_ ? pill('enabled', 'warn') : pill('disabled (default)', 'muted')) +
    ' <button type="button" class="btn btn-outline btn-sm"' +
    on('click', 'dbsimToggleClientMode', on_ ? 'false' : 'true') + '>' +
    (on_ ? 'Disable' : 'Enable') + '</button>' +
    '<div class="muted small">Admin only. Client mode runs read-only checks against customer targets and stays off until enabled.</div></div>';
}

function renderTargets() {
  var rows = state.targets.map(function(t) {
    var where = toText(t.host) + ':' + toText(t.port) + ' / ' + toText(t.database);
    return '<tr>' +
      '<td>' + x(toText(t.displayName) || t.id) + '<div class="muted small">' + x(t.engine) + '</div></td>' +
      '<td>' + x(where) + '</td>' +
      '<td>' + x(toText(t.agentId)) + '</td>' +
      '<td>' + modePill(t) + '</td>' +
      '<td>' + identityPill(t.identityCheck) + '</td>' +
      '<td class="nowrap">' +
        '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'dbsimIdentityCheck', t.id) + '>Check identity</button> ' +
        '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'dbsimDeleteTarget', t.id) + '>Delete</button>' +
      '</td></tr>';
  }).join('');
  if (!rows) rows = '<tr><td colspan="6" class="muted">No targets registered yet.</td></tr>';
  return '<table class="tbl"><thead><tr><th>Target</th><th>Host / database</th><th>Agent</th><th>Mode</th><th>Identity</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>';
}

function renderStartRun() {
  if (!state.targets.length) return '<div class="muted">Register a target before starting a run.</div>';
  var t = selectedTarget();
  var options = '<option value="">Choose a target</option>' + state.targets.map(function(tg) {
    return '<option value="' + x(tg.id) + '"' + (tg.id === state.targetId ? ' selected' : '') + '>' + x(toText(tg.displayName) || tg.id) + ' (' + x(tg.mode) + ')</option>';
  }).join('');
  var boxes = DBSIM_CATALOG.map(function(c) {
    return '<label class="dbsim-check"><input type="checkbox"' + (state.selected[c.id] ? ' checked' : '') + on('change', 'dbsimToggleScenario', c.id) + '> ' + x(c.label) + '</label>';
  }).join('');
  var lab = '';
  if (t && t.mode === 'lab') {
    lab = '<label class="dbsim-field"><span>Type the target id <code>' + x(t.id) + '</code> to confirm this lab run</span>' +
      '<input id="dbsim-lab-confirm" type="text" value="' + x(state.labConfirm) + '"' + on('input', 'dbsimLabConfirmInput') + '></label>';
  }
  var canStart = !!t && selectedIds().length > 0;
  return '<div class="dbsim-field"><span>Target</span><select id="dbsim-run-target"' + on('change', 'dbsimChooseTarget') + '>' + options + '</select></div>' +
    '<div class="dbsim-scenarios">' + boxes + '</div>' + lab +
    '<div class="dbsim-actions"><button type="button" class="btn btn-primary btn-sm"' +
    (canStart ? '' : ' disabled') + on('click', 'dbsimStartRun') + '>Start run</button></div>' +
    '<div class="muted small">A run is one job for the selected scenarios on one target. The agent runs them in order, and the results are graded on the server.</div>';
}

function renderActiveRun() {
  var r = state.activeRun;
  if (!r) return '<div class="muted">No run in progress. Start one above, or pick a stored run below.</div>';
  var terminal = !!TERMINAL[r.status];
  return '<div class="dbsim-row"><span>Run</span> <code>' + x(r.runId) + '</code> ' +
    pill(r.status || 'pending', statusTone(r.status)) +
    (r.reason ? ' <span class="muted small">' + x(r.reason) + '</span>' : '') +
    (terminal ? '' : ' <button type="button" class="btn btn-outline btn-sm"' + on('click', 'dbsimCancelRun', r.runId) + '>Cancel</button>') +
    '</div>';
}

function renderRuns() {
  var rows = state.runs.map(function(r) {
    return '<tr><td>' + x(toText(r.scenarioId)) + '</td><td>' + x(toText(r.engine)) + '</td><td>' + x(toText(r.result) || 'pending') +
      '</td><td>' + x(toText(r.createdAt)) + '</td><td>' +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'dbsimViewReport', r.id) + '>View report</button></td></tr>';
  }).join('');
  if (!rows) rows = '<tr><td colspan="5" class="muted">No runs yet.</td></tr>';
  return '<table class="tbl"><thead><tr><th>Scenario</th><th>Engine</th><th>Result</th><th>Created</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>';
}

function renderDBSim(reportHtml) {
  var host = document.getElementById('tab-dbsim');
  if (!host) return;
  var body = '';
  if (state.error) body += '<div class="banner banner-warn">' + x(state.error) + '</div>';
  body += '<section class="card"><h3>Summary</h3>' + renderSummary() + '</section>';
  body += '<section class="card"><h3>Start a run</h3>' + renderStartRun() + '</section>';
  body += '<section class="card"><h3>Run status</h3>' + renderActiveRun() + '</section>';
  body += '<section class="card"><h3>Settings</h3>' + renderSettings() + '</section>';
  body += '<section class="card"><h3>Targets</h3>' + renderTargets() + '</section>';
  body += '<section class="card"><h3>Register a target</h3>' + renderRegisterForm() + '</section>';
  body += '<section class="card"><h3>Run results</h3>' + renderRuns() + '</section>';
  if (reportHtml) body += '<section class="card"><h3>Report</h3>' + reportHtml + '</section>';
  host.innerHTML = body;
}

function renderRegisterForm() {
  function field(id, label, type, extra) {
    return '<label class="dbsim-field"><span>' + x(label) + '</span><input id="' + id + '" type="' + (type || 'text') + '"' + (extra || '') + '></label>';
  }
  return '<div id="dbsim-register" class="dbsim-form">' +
    field('dbsim-name', 'Display name', 'text', ' required') +
    '<label class="dbsim-field"><span>Engine</span><select id="dbsim-engine"><option value="postgresql">PostgreSQL</option><option value="mysql">MySQL</option></select></label>' +
    field('dbsim-host', 'Host', 'text', ' required') +
    field('dbsim-port', 'Port', 'number', ' required min="1" max="65535"') +
    field('dbsim-database', 'Database', 'text', ' required') +
    field('dbsim-cred', 'Credential reference (name only, no secret)', 'text', ' required') +
    field('dbsim-agent', 'Agent ID', 'text', ' required') +
    field('dbsim-expected', 'Expected identity (role or user)', 'text', ' required') +
    '<label class="dbsim-field"><span>Mode</span><select id="dbsim-mode"><option value="lab">Lab</option><option value="client">Client (read-only)</option></select></label>' +
    '<label class="dbsim-field dbsim-check"><input id="dbsim-lab-confirmed" type="checkbox"> <span>Lab target confirmed</span></label>' +
    '<div class="dbsim-actions"><button type="button" class="btn btn-primary btn-sm"' + on('click', 'dbsimRegister') + '>Register target</button></div>' +
    '<div class="muted small">The secret is set on the agent host, never in this form. The credential reference is only a name.</div>' +
    '</div>';
}

// ── Run start, status and cancel ─────────────────────────

export function dbsimToggleScenario(id, el) {
  state.selected[id] = !!(el && el.checked);
  renderDBSim();
}

export function dbsimChooseTarget(el) {
  state.targetId = el ? el.value : '';
  renderDBSim();
}

export function dbsimLabConfirmInput(el) {
  state.labConfirm = el ? el.value.trim() : '';
}

export function dbsimStartRun() {
  var t = selectedTarget();
  var ids = selectedIds();
  if (!t || !ids.length) { showToast('Choose a target and at least one scenario'); return; }
  apicall('/api/dbsim-runs', {
    method: 'POST',
    body: JSON.stringify({ targetId: t.id, scenarioIds: ids, labConfirmation: state.labConfirm })
  }).then(function(res) {
    if (res && res.error) { showToast(errMsg(res, 'Run not started')); return; }
    state.activeRun = { runId: res.runId, status: res.status || 'pending', reason: '', targetId: t.id };
    showToast('Run started');
    renderDBSim();
    startPolling();
  }).catch(function(err) { showToast('Run not started: ' + err.message); });
}

export function dbsimCancelRun(runId) {
  apicall('/api/dbsim-runs/' + encodeURIComponent(runId) + '/cancel', { method: 'POST' })
    .then(function(res) {
      if (res && res.error) { showToast(errMsg(res, 'Run not cancelled')); return; }
      showToast('Cancel requested');
      return pollOnce();
    })
    .catch(function(err) { showToast('Run not cancelled: ' + err.message); });
}

function pollOnce() {
  var r = state.activeRun;
  if (!r) return Promise.resolve();
  return apicall('/api/dbsim-jobs/' + encodeURIComponent(r.runId)).then(function(job) {
    if (!job || job.error) return;
    state.activeRun = { runId: job.runId, status: job.status, reason: job.reason || '', targetId: job.targetId, agentId: job.agentId };
    if (TERMINAL[job.status]) {
      stopPolling();
      return loadDBSimTab();
    }
    renderDBSim();
  });
}

function startPolling() {
  stopPolling();
  pollTimer = setInterval(function() { pollOnce(); }, POLL_MS);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

// ── Target and settings actions ──────────────────────────

export function dbsimToggleClientMode(value) {
  var enabled = value === 'true';
  apicall('/api/dbsim/settings/client-mode', { method: 'PUT', body: JSON.stringify({ enabled: enabled }) })
    .then(function(res) {
      if (res && res.error) { showToast(errMsg(res, 'Could not change client mode')); return; }
      showToast(enabled ? 'Client read-only mode enabled' : 'Client read-only mode disabled');
      return loadDBSimTab();
    })
    .catch(function(err) { showToast('Could not change client mode: ' + err.message); });
}

var REQUIRED = ['dbsim-name', 'dbsim-host', 'dbsim-port', 'dbsim-database', 'dbsim-cred', 'dbsim-agent', 'dbsim-expected'];

export function dbsimRegister() {
  function val(id) { var n = document.getElementById(id); return n ? n.value.trim() : ''; }
  for (var i = 0; i < REQUIRED.length; i++) {
    if (!val(REQUIRED[i])) { showToast('Fill in every required field'); return; }
  }
  var body = {
    displayName: val('dbsim-name'),
    engine: val('dbsim-engine'),
    host: val('dbsim-host'),
    port: parseInt(val('dbsim-port'), 10),
    database: val('dbsim-database'),
    credentialRef: val('dbsim-cred'),
    agentId: val('dbsim-agent'),
    expectedIdentity: val('dbsim-expected'),
    mode: val('dbsim-mode'),
    labConfirmed: !!(document.getElementById('dbsim-lab-confirmed') || {}).checked
  };
  apicall('/api/dbsim-targets', { method: 'POST', body: JSON.stringify(body) })
    .then(function(res) {
      if (res && res.error) { showToast(errMsg(res, 'Target not saved')); return; }
      showToast('Target registered');
      return loadDBSimTab();
    })
    .catch(function(err) { showToast('Target not saved: ' + err.message); });
}

export function dbsimIdentityCheck(id) {
  apicall('/api/dbsim-targets/' + encodeURIComponent(id) + '/identity-check', { method: 'POST' })
    .then(function(res) {
      if (res && res.error) { showToast(errMsg(res, 'Identity check failed')); return; }
      showToast(res && res.passed ? 'Identity check passed' : 'Identity check did not pass');
      return loadDBSimTab();
    })
    .catch(function(err) { showToast('Identity check failed: ' + err.message); });
}

export function dbsimDeleteTarget(id) {
  if (!window.confirm('Delete this dbsim target?')) return;
  apicall('/api/dbsim-targets/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function(res) {
      if (res && res.error) { showToast(errMsg(res, 'Target not deleted')); return; }
      showToast('Target deleted');
      return loadDBSimTab();
    })
    .catch(function(err) { showToast('Target not deleted: ' + err.message); });
}

export function dbsimViewReport(id) {
  apicall('/api/dbsim-runs/' + encodeURIComponent(id) + '/report')
    .then(function(res) {
      if (res && res.error) { showToast(errMsg(res, 'Report unavailable')); return; }
      renderDBSim('<pre class="dbsim-report">' + x(JSON.stringify(res, null, 2)) + '</pre>');
    })
    .catch(function(err) { showToast('Report unavailable: ' + err.message); });
}
