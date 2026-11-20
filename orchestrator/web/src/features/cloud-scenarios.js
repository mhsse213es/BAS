// Cloud Scenarios page (O-10, first increment). It lists the builtin cloud scenarios, takes a run form, and shows
// the result. Running a scenario discovers the named account read-only and evaluates the scenario against the
// configured permissions. Nothing is changed in the cloud. The server enforces the account allow-list and refuses
// anything not on it, and this page shows that refusal as its own message.
//
// Pure logic lives in cloud-model.js. Every value from the server goes through x() before it reaches the markup.

import { x } from '../core/escape.js';
import { showToast } from '../core/util.js';
import { setHeroStat } from './shell-ui.js';
import { on } from '../core/actions.js';
import { doLogout } from './shell.js';
import * as M from './cloud-model.js';

var catalogue = [];
var filterProvider = 'all';
var filterQuery = '';

// Simple provider marks, drawn here so no image is fetched and they follow the page's size and colour rules.
var MARK = {
  aws: '<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M8 29c10 6 22 6 32 0" fill="none" stroke="#ff9900" stroke-width="3.2" stroke-linecap="round"/><path d="M34 28l6 1-2 5" fill="none" stroke="#ff9900" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/><text x="24" y="22" text-anchor="middle" font-family="Arial,sans-serif" font-weight="700" font-size="15" fill="currentColor">aws</text></svg>',
  azure: '<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M20 6L6 40h10l4-10 12 10h10z" fill="#0089d6"/><path d="M20 6l10 22-14 12z" fill="#50b9f0" opacity=".85"/></svg>',
  gcp: '<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M17 33a7 7 0 010-14l1 0a10 10 0 0119-2 8 8 0 01-1 16z" fill="none" stroke="#4285f4" stroke-width="3.4" stroke-linejoin="round"/><path d="M17 33a7 7 0 01-5-12" fill="none" stroke="#ea4335" stroke-width="3.4" stroke-linecap="round"/><path d="M36 33a8 8 0 002-13" fill="none" stroke="#34a853" stroke-width="3.4" stroke-linecap="round"/><path d="M18 19a10 10 0 0119-2" fill="none" stroke="#fbbc05" stroke-width="3.4" stroke-linecap="round"/></svg>'
};
function markFor(provider) { return MARK[provider] || '<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M14 32a8 8 0 010-16 10 10 0 0119 2 7 7 0 01-1 14z" fill="none" stroke="currentColor" stroke-width="3"/></svg>'; }

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
    paintHero();
    renderChips();
    renderCards();
    populateScenarioSelect();
    loadCloudRuns();
  }).catch(function(err) {
    catalogue = [];
    if (host) host.innerHTML = '<div class="empty">Cloud scenarios are unavailable: ' + x(err.message || 'request failed') + ' ' +
      '<button type="button" class="btn btn-sm"' + on('click', 'loadCloudScenarios') + '>Retry</button></div>';
  });
}

function paintHero() {
  var n = M.providerCounts(catalogue);
  [['cloud-hs-total', n.all], ['cloud-hs-aws', n.aws], ['cloud-hs-azure', n.azure], ['cloud-hs-gcp', n.gcp]].forEach(function(p) { setHeroStat(p[0], p[1]); });
}

function renderChips() {
  var host = el('cloud-chips');
  if (!host) return;
  var n = M.providerCounts(catalogue);
  host.innerHTML = [['all', 'All'], ['aws', 'AWS'], ['azure', 'Azure'], ['gcp', 'GCP']].filter(function(c) { return c[0] === 'all' || n[c[0]] > 0; }).map(function(c) {
    return '<button type="button" class="cloud-chip' + (filterProvider === c[0] ? ' on' : '') + '" aria-pressed="' + (filterProvider === c[0]) + '"' + on('click', 'cloudSetProvider', c[0]) + '>' + x(c[1]) + '<em>' + n[c[0]] + '</em></button>';
  }).join('');
}

// cloudSetProvider is the provider chips' action.
export function cloudSetProvider(provider) { filterProvider = provider || 'all'; renderChips(); renderCards(); }

// cloudFilterInput is the filter box's handler: it narrows the cards as the user types.
export function cloudFilterInput(el0) { filterQuery = el0 && el0.value ? el0.value : ''; renderCards(); }

function renderCards() {
  var host = el('cloud-scen-cards');
  if (!host) return;
  if (!catalogue.length) { host.innerHTML = '<div class="empty">No cloud scenarios are available on this server.</div>'; return; }
  var shown = M.filterCards(catalogue, filterProvider, filterQuery);
  if (!shown.length) { host.innerHTML = '<div class="empty cloud-none">No scenario matches that filter.</div>'; return; }
  host.innerHTML = shown.map(function(c) {
    return '<div class="cloud-card cloud-scn cloud-p-' + x(c.provider) + '" id="cloud-scn-' + x(c.id) + '">' +
      '<div class="cloud-card-h"><strong>' + x(c.name) + '</strong><span class="cloud-mark" title="' + x(c.providerLabel) + '">' + markFor(c.provider) + '</span></div>' +
      '<p class="cloud-card-d">' + x(c.description) + '</p>' +
      '<div class="cloud-card-f"><span class="cloud-card-m">' + x(String(c.stepCount)) + (c.stepCount === 1 ? ' step' : ' steps') + '</span>' +
      '<span class="cloud-card-m ro">Read-only</span>' +
      '<button type="button" class="btn btn-sm cloud-use"' + on('click', 'cloudPickScenario', c.id) + '>Use in run form</button></div>' +
      '</div>';
  }).join('');
}

// cloudFocusScenario brings a scenario's card into view and highlights it (used by the global search).
export function cloudFocusScenario(id) {
  filterProvider = 'all'; filterQuery = '';
  var box = el('cloud-find'); if (box) box.value = '';
  renderChips(); renderCards();
  var card = el('cloud-scn-' + id);
  if (!card) return;
  if (card.scrollIntoView) card.scrollIntoView({ behavior: 'smooth', block: 'center' });
  card.classList.add('flash');
  setTimeout(function() { card.classList.remove('flash'); }, 2200);
}

// populateScenarioSelect lists only the scenarios for the provider chosen in the run form, so a mismatched pair
// cannot be picked in the first place. A scenario already chosen is kept when it still matches.
function populateScenarioSelect() {
  var sel = el('cloud-run-scenario');
  if (!sel) return;
  var prev = sel.value;
  var provider = fieldValue('cloud-run-provider');
  var list = M.scenariosForProvider(catalogue, provider);
  sel.innerHTML = '<option value="">Choose a scenario</option>' + list.map(function(c) {
    return '<option value="' + x(c.id) + '">' + x(c.providerLabel + ': ' + c.name) + '</option>';
  }).join('');
  sel.value = list.some(function(c) { return c.id === prev; }) ? prev : '';
}

// cloudRunProviderChanged is the run form's provider change: the scenario list follows it.
export function cloudRunProviderChanged() { populateScenarioSelect(); }

// cloudRunScenarioChanged sets the provider from the chosen scenario, so the pair is consistent.
export function cloudRunScenarioChanged() {
  var target = M.scenarioProvider(catalogue, fieldValue('cloud-run-scenario'));
  var prov = el('cloud-run-provider');
  if (target && prov && prov.value !== target) { prov.value = target; populateScenarioSelect(); }
}

// cloudPickScenario selects a card's scenario in the run form and sets its provider.
export function cloudPickScenario(id) {
  var sel = el('cloud-run-scenario');
  var card = catalogue.filter(function(c) { return c.id === id; })[0];
  var prov = el('cloud-run-provider');
  if (prov && card && card.provider) prov.value = card.provider;
  populateScenarioSelect();
  if (sel) sel.value = id;
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
  var mismatch = M.providerMismatch(catalogue, built.body.scenarioId, built.body.account.provider);
  if (mismatch) { renderResultError(mismatch, 'cloud-run-result'); return; }

  var btn = el('cloud-run-submit');
  if (btn) btn.disabled = true;
  renderResultPending();
  cloudRequest('/api/cloud-scenario-runs', { method: 'POST', body: JSON.stringify(built.body) }).then(function(r) {
    if (r.status >= 400) throw new Error(M.describeRunError(r.status, r.body && r.body.error));
    renderResult(r.body, 'cloud-run-result');
    loadCloudRuns();
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
    host.innerHTML = '<div class="empty">Runs are unavailable: ' + x(err.message || 'request failed') + ' ' +
      '<button type="button" class="btn btn-sm"' + on('click', 'cloudRefreshRuns') + '>Retry</button></div>';
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
