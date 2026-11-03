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
    renderResult(r.body);
  }).catch(function(err) {
    renderResultError(err.message || 'The run was not started.');
  }).then(function() {
    if (btn) btn.disabled = false;
  });
}

function renderResultPending() {
  var out = el('cloud-run-result');
  if (out) out.innerHTML = '<div class="empty">Running. Discovery of the account can take a while.</div>';
}

function renderResult(run) {
  var out = el('cloud-run-result');
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

function renderResultError(message) {
  var out = el('cloud-run-result');
  if (out) out.innerHTML = '<div class="cloud-result cloud-tone-bad">' + x(message) + '</div>';
  showToast(message, 'error');
}
