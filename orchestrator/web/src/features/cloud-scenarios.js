// Cloud Scenarios page (O-10, first increment). It lists the builtin cloud scenarios, takes a run form, and shows
// the result. Running a scenario discovers the named account read-only and evaluates the scenario against the
// configured permissions. Nothing is changed in the cloud. The server enforces the account allow-list and refuses
// anything not on it, and this page shows that refusal as its own message.
//
// Pure logic lives in cloud-model.js. Every value from the server goes through x() before it reaches the markup.

import { x } from '../core/escape.js';
import { showToast } from '../core/util.js';
import { on } from '../core/actions.js';
import { doLogout } from './shell.js';
import * as M from './cloud-model.js';

var catalogue = [];

// cloudRequest is apicall with the HTTP status kept. The status decides which refusal message to show, so it cannot
// be dropped. A 401 ends the session exactly as apicall does.
function cloudRequest(path, opts) {
  return fetch(path, Object.assign({ credentials: 'same-origin', headers: { 'Content-Type': 'application/json' } }, opts || {}))
    .then(function(r) {
      if (r.status === 401) { doLogout(); throw new Error('Session expired'); }
      return r.json().catch(function() { return {}; }).then(function(body) { return { status: r.status, body: body }; });
    });
}

function el(id) { return document.getElementById(id); }

function fieldValue(id) { var n = el(id); return n ? n.value : ''; }

// loadCloudScenarios fills the catalogue cards and the run form's scenario list. Called when the tab opens.
export function loadCloudScenarios() {
  var host = el('cloud-scen-cards');
  if (host) host.innerHTML = '<div class="empty">Loading…</div>';
  cloudRequest('/api/cloud-scenarios').then(function(r) {
    if (r.status !== 200) throw new Error(M.describeRunError(r.status, r.body && r.body.error));
    catalogue = M.scenarioCards(r.body);
    renderCards();
    populateScenarioSelect();
    loadCloudRuns();
  }).catch(function(err) {
    catalogue = [];
    if (host) host.innerHTML = '<div class="empty">Cloud scenarios are unavailable: ' + x(err.message || 'request failed') + '</div>';
  });
}

function renderCards() {
  var host = el('cloud-scen-cards');
  if (!host) return;
  if (!catalogue.length) { host.innerHTML = '<div class="empty">No cloud scenarios are available on this server.</div>'; return; }
  host.innerHTML = catalogue.map(function(c) {
    return '<div class="cloud-card">' +
      '<div class="cloud-card-h"><strong>' + x(c.name) + '</strong> <span class="cloud-prov">' + x(c.providerLabel) + '</span></div>' +
      '<p class="cloud-card-d">' + x(c.description) + '</p>' +
      '<div class="cloud-card-m">' + x(String(c.stepCount)) + ' steps</div>' +
      '<button type="button" class="btn btn-sm"' + on('click', 'cloudPickScenario', c.id) + '>Use in run form</button>' +
      '</div>';
  }).join('');
}

function populateScenarioSelect() {
  var sel = el('cloud-run-scenario');
  if (!sel) return;
  var prev = sel.value;
  sel.innerHTML = '<option value="">Choose a scenario</option>' + catalogue.map(function(c) {
    return '<option value="' + x(c.id) + '">' + x(c.providerLabel + ': ' + c.name) + '</option>';
  }).join('');
  if (prev) sel.value = prev;
}

// cloudPickScenario selects a card's scenario in the run form and sets its provider.
export function cloudPickScenario(id) {
  var sel = el('cloud-run-scenario');
  var card = catalogue.filter(function(c) { return c.id === id; })[0];
  if (sel) sel.value = id;
  var prov = el('cloud-run-provider');
  if (prov && card && card.provider) prov.value = card.provider;
  var form = el('cloud-run-form');
  if (form && form.scrollIntoView) form.scrollIntoView({ behavior: 'smooth', block: 'start' });
  var acct = el('cloud-run-account');
  if (acct && acct.focus) acct.focus();
}

// cloudSubmitRun checks the form, sends the run, and shows the outcome. The server is the authority: a refused
// account comes back as 403 and is shown as the allow-list message.
export function cloudSubmitRun() {
  var built = M.buildCloudRunRequest({
    scenarioId: fieldValue('cloud-run-scenario'),
    provider: fieldValue('cloud-run-provider'),
    accountId: fieldValue('cloud-run-account'),
    principal: fieldValue('cloud-run-principal'),
    resource: fieldValue('cloud-run-resource'),
    region: fieldValue('cloud-run-region'),
  });
  if (!built.ok) { showToast(built.error, 'error'); return; }

  var btn = el('cloud-run-submit');
  if (btn) btn.disabled = true;
  renderResultPending();
  cloudRequest('/api/cloud-scenario-runs', { method: 'POST', body: JSON.stringify(built.body) }).then(function(r) {
    if (r.status >= 400) throw new Error(M.describeRunError(r.status, r.body && r.body.error));
    renderResult(r.body, 'cloud-run-result');
  }).catch(function(err) {
    renderResultError(err.message || 'The run was not started.', 'cloud-run-result');
  }).then(function() {
    if (btn) btn.disabled = false;
  });
}

function renderResultPending() {
  var out = el('cloud-run-result');
  if (out) out.innerHTML = '<div class="empty">Running. Discovery of the account can take a while.</div>';
}

function renderResult(run, hostId) {
  var out = el(hostId || 'cloud-run-result');
  if (!out) return;
  var status = (run && run.status) || 'submitted';
  var tone = M.runTone(status);
  var html = '<div class="cloud-result cloud-tone-' + x(tone) + '">' +
    '<div>Status: <strong>' + x(status) + '</strong></div>';
  if (run && run.id) html += '<div>Run ID: <code>' + x(run.id) + '</code></div>';
  if (run && run.error) html += '<div class="cloud-result-err">' + x(run.error) + '</div>';
  html += '</div>';
  out.innerHTML = html;
  showToast('Run ' + status, tone === 'bad' ? 'error' : 'success');
}

function renderResultError(message, hostId) {
  var out = el(hostId || 'cloud-run-result');
  if (out) out.innerHTML = '<div class="cloud-result cloud-tone-bad">' + x(message) + '</div>';
  showToast(message, 'error');
}

// ── Discovery-only runs (POST /api/cloud-runs with discover: true) ─────────────────────────────
// The run builds the permission graph from a live discovery pass of the account and asks whether the target is
// reachable from the held identities. Nothing is changed in the cloud.

// cloudSubmitDiscovery checks the discovery form and starts the run. A refusal shows the same messages as a scenario run.
export function cloudSubmitDiscovery() {
  var built = M.buildDiscoveryRunRequest({
    label: fieldValue('cloud-disc-label'),
    provider: fieldValue('cloud-disc-provider'),
    accountId: fieldValue('cloud-disc-account'),
    region: fieldValue('cloud-disc-region'),
    target: fieldValue('cloud-disc-target'),
    held: fieldValue('cloud-disc-held'),
  });
  if (!built.ok) { showToast(built.error, 'error'); return; }

  var btn = el('cloud-disc-submit');
  if (btn) btn.disabled = true;
  var out = el('cloud-disc-result');
  if (out) out.innerHTML = '<div class="empty">Running. Discovery of the account can take a while.</div>';
  cloudRequest('/api/cloud-runs', { method: 'POST', body: JSON.stringify(built.body) }).then(function(r) {
    if (r.status >= 400) throw new Error(M.describeRunError(r.status, r.body && r.body.error));
    renderResult(r.body, 'cloud-disc-result');
    loadCloudRuns();
  }).catch(function(err) {
    renderResultError(err.message || 'The run was not started.', 'cloud-disc-result');
  }).then(function() {
    if (btn) btn.disabled = false;
  });
}

// loadCloudRuns fills the recent-runs table, newest first. Both scenario and discovery runs are listed.
export function loadCloudRuns() {
  var host = el('cloud-runs-list');
  if (!host) return;
  host.innerHTML = '<div class="empty">Loading…</div>';
  cloudRequest('/api/cloud-runs?limit=20').then(function(r) {
    if (r.status !== 200) throw new Error(M.describeRunError(r.status, r.body && r.body.error));
    renderRunsTable(M.runRows(r.body));
  }).catch(function(err) {
    host.innerHTML = '<div class="empty">Runs are unavailable: ' + x(err.message || 'request failed') + '</div>';
  });
}

// cloudRefreshRuns is the refresh button's action.
export function cloudRefreshRuns() { loadCloudRuns(); }

function formatWhen(iso) {
  if (!iso) return '';
  var d = new Date(iso);
  return isNaN(d.getTime()) ? '' : d.toLocaleString();
}

function renderRunsTable(rows) {
  var host = el('cloud-runs-list');
  if (!host) return;
  if (!rows.length) { host.innerHTML = '<div class="empty">No runs yet.</div>'; return; }
  var head = '<tr><th>Started</th><th>Label</th><th>Account</th><th>Status</th><th>By</th><th>Error</th></tr>';
  var body = rows.map(function(r) {
    return '<tr>' +
      '<td>' + x(formatWhen(r.startedAt)) + '</td>' +
      '<td><code>' + x(r.label) + '</code></td>' +
      '<td>' + x(r.account) + '</td>' +
      '<td><span class="cloud-tone-' + x(r.tone) + '">' + x(r.status) + '</span></td>' +
      '<td>' + x(r.initiatedBy) + '</td>' +
      '<td class="cloud-result-err">' + x(r.error) + '</td>' +
      '</tr>';
  }).join('');
  host.innerHTML = '<table class="cloud-runs-table"><thead>' + head + '</thead><tbody>' + body + '</tbody></table>';
}
