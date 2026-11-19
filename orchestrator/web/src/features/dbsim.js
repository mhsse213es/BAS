import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';

// ── Database Security Simulation (dbsim) ─────────────────
// Console page for the DAM BAS capability. Talks only to the /api/dbsim*
// endpoints. This first version manages targets, identity checks, the
// client-mode setting and shows run results. Starting a run is NOT here:
// no run-start endpoint exists yet (see the run-API decision in the project
// notes).

var state = { settings: null, targets: [], runs: [], error: '' };

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

export function loadDBSimTab() {
  state.error = '';
  return Promise.all([
    apicall('/api/dbsim/settings'),
    apicall('/api/dbsim-targets'),
    apicall('/api/dbsim-runs')
  ]).then(function(res) {
    state.settings = res[0] || null;
    state.targets = Array.isArray(res[1]) ? res[1] : (res[1] && res[1].targets) || [];
    state.runs = Array.isArray(res[2]) ? res[2] : (res[2] && res[2].runs) || [];
    renderDBSim();
  }).catch(function(err) {
    state.error = 'Could not load dbsim data: ' + (err && err.message ? err.message : err);
    renderDBSim();
  });
}

export function refreshDBSimTab() { return loadDBSimTab(); }

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

function renderRuns() {
  var rows = state.runs.map(function(r) {
    return '<tr><td>' + x(toText(r.scenarioId)) + '</td><td>' + x(toText(r.engine)) + '</td><td>' + x(toText(r.result) || 'pending') +
      '</td><td>' + x(toText(r.createdAt)) + '</td><td>' +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'dbsimViewReport', r.id) + '>View report</button></td></tr>';
  }).join('');
  if (!rows) rows = '<tr><td colspan="5" class="muted">No runs yet. Runs are started by the run API, which is not built yet.</td></tr>';
  return '<table class="tbl"><thead><tr><th>Scenario</th><th>Engine</th><th>Result</th><th>Created</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>';
}

function renderDBSim(reportHtml) {
  var host = document.getElementById('tab-dbsim');
  if (!host) return;
  var body = '';
  if (state.error) body += '<div class="banner banner-warn">' + x(state.error) + '</div>';
  body += '<section class="card"><h3>Settings</h3>' + renderSettings() + '</section>';
  body += '<section class="card"><h3>Targets</h3>' + renderTargets() + '</section>';
  body += '<section class="card"><h3>Register a target</h3>' + renderRegisterForm() + '</section>';
  body += '<section class="card"><h3>Run results</h3>' + renderRuns() + '</section>';
  if (reportHtml) body += '<section class="card"><h3>Report</h3>' + reportHtml + '</section>';
  host.innerHTML = body;
}

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
