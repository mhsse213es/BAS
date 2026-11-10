// API Inventory: a target's imported OpenAPI inventory, its versions and changes, drift against observed routes, and a preview of
// how it would bind to test data. Everything shown comes from /api/apibas/targets/... and is escaped on the way into markup. The
// page never takes or shows a credential value, and nothing here applies the suggested scope or starts a job.
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { card, pill, chip, seg, empty, kv } from '../core/kit.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './api-inventory-model.js';

var S = { targets: [], sel: '', inv: null, cls: 'all', version: 0, versions: [], stored: null, jobs: [], schedule: null, polls: {} };
var MAX_ROWS = 500;

function el(id) { return document.getElementById(id); }
function base() { return '/api/apibas/targets/' + encodeURIComponent(S.sel); }
function btn(label, action, args, kind) {
  return '<button type="button" class="btn ' + (kind || 'btn-outline') + '"' + on.apply(null, ['click', action].concat(args || [])) + '>' + x(label) + '</button>';
}

export function loadApiInventory() {
  return apicall('/api/apibas/targets').then(function(r) {
    var host = el('api-inv-targets');
    if (!host) return false;
    var err = M.errorText(r);
    if (err || !r || !Array.isArray(r.targets)) {
      host.innerHTML = card('Targets', empty('warn', 'Targets could not be loaded', err || 'The server returned an unexpected answer.'));
      return false;
    }
    S.targets = r.targets;
    renderTargets();
    setHeroStat('ai-hs-targets', S.targets.length);
    setHeroStat('ai-hs-inventories', S.targets.filter(function(t) { return t.inventory; }).length);
    if (S.sel && S.targets.some(function(t) { return t.id === S.sel; })) return loadDetail(S.version);
    S.sel = '';
    renderDetail();
    return true;
  }).catch(function(e) {
    showToast('Could not reach the server: ' + (e && e.message ? e.message : 'request failed'), 'err');
    return false;
  });
}

export function apiInvRefresh() {
  showToast('Refreshing…', 'ok');
  loadApiInventory();
}

function renderTargets() {
  var host = el('api-inv-targets');
  if (!host) return;
  if (!S.targets.length) {
    host.innerHTML = card('Targets', empty('box', 'No API BAS targets are registered', 'A target is registered through POST /api/apibas/targets.'));
    return;
  }
  var rows = S.targets.map(function(t) {
    var inv = t.inventory;
    return '<tr' + (t.id === S.sel ? ' class="ai-sel"' : '') + '>' +
      '<td><b>' + x(t.name) + '</b><div class="ai-sub">' + x(t.id) + '</div></td>' +
      '<td>' + pill(t.environment, M.envTone(t.environment)) + (t.enabled ? '' : ' ' + chip('disabled', 'muted')) + '</td>' +
      '<td class="ai-mono">' + x(t.base_url) + '</td>' +
      '<td>' + (inv ? 'v' + x(inv.version) + ' · ' + x(inv.operations) + ' operations<div class="ai-sub">' + x(fmtDate(inv.imported_at)) + '</div>' : '<span class="ai-sub">None yet</span>') + '</td>' +
      '<td>' + btn('Open', 'apiInvSelect', [t.id]) + '</td></tr>';
  }).join('');
  host.innerHTML = card('Targets', '<div class="tbl-wrap"><table><thead><tr><th>Target</th><th>Environment</th><th>Base URL</th><th>Inventory</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>',
    { sub: S.targets.length + ' registered' });
}

export function apiInvSelect(id) {
  S.sel = id; S.cls = 'all'; S.version = 0; S.inv = null; S.versions = []; S.stored = null; S.jobs = []; S.schedule = null; S.polls = {};
  renderTargets();
  loadDetail(0);
}

function loadDetail(version) {
  if (!S.sel) { renderDetail(); return Promise.resolve(true); }
  S.version = version || 0;
  var q = S.version ? '?version=' + encodeURIComponent(S.version) : '';
  // The stored test data needs the manage permission; for anyone else the read is refused and the page simply shows none.
  return Promise.all([apicall(base() + '/inventory' + q), apicall(base() + '/inventory/versions'), apicall(base() + '/binding').catch(function() { return null; }), apicall(base() + '/jobs').catch(function() { return null; }), apicall(base() + '/schedule').catch(function() { return null; })]).then(function(res) {
    S.jobs = (res[3] && Array.isArray(res[3].jobs)) ? res[3].jobs : [];
    S.schedule = (res[4] && !M.errorText(res[4]) && res[4].target_id) ? res[4] : null;
    var inv = res[0], vers = res[1];
    S.stored = (res[2] && !M.errorText(res[2]) && res[2].spec) ? res[2] : null;
    S.inv = (inv && !M.errorText(inv) && inv.listed_operations) ? inv : null;
    S.versions = (vers && Array.isArray(vers.versions)) ? vers.versions : [];
    renderDetail();
    return true;
  }).catch(function(e) {
    showToast('Could not load the inventory: ' + (e && e.message ? e.message : 'request failed'), 'err');
    return false;
  });
}

function renderDetail() {
  var host = el('api-inv-detail');
  if (!host) return;
  if (!S.sel) { host.innerHTML = card('', empty('radar', 'Select a target', 'Open a target to import its OpenAPI document and see its inventory.')); return; }
  var t = S.targets.filter(function(a) { return a.id === S.sel; })[0];
  var html = card(t ? t.name : S.sel, importBody(), { sub: 'Import an OpenAPI 3 document' });
  if (!S.inv) {
    html += card('Inventory', empty('file', 'No inventory yet', 'Import this target\'s OpenAPI document above. The document itself is not stored, only its parsed shape.'));
    host.innerHTML = html;
    return;
  }
  html += card('Inventory', inventoryMeta() + '<div id="api-inv-ops">' + opsBody() + '</div>', { sub: 'Candidate test classes, not findings' });
  html += card('Versions', versionsBody(), { sub: S.versions.length + ' kept' });
  html += card('Drift against observed routes', driftBody(), { sub: 'Compares routes you list with this inventory; nothing is requested from the target' });
  html += card('Recent jobs', jobsBody(), { sub: 'Newest first, this target only' });
  html += card('Binding preview', bindingBody(), { sub: 'Which scenarios would be generated; nothing is stored or run' });
  html += card('Schedule', scheduleBody(), { sub: 'Run the stored test data on an interval' });
  host.innerHTML = html;
  apiInvWriteOp();
  apiInvWriteSync();
}

function importBody() {
  return '<p class="ai-note">Paste the document (JSON or YAML, up to 8 MiB) or choose a file. Importing needs permission to manage targets. Examples in the document are never stored.</p>' +
    '<textarea id="api-inv-spec" class="ai-text" rows="8" spellcheck="false" aria-label="OpenAPI document"></textarea>' +
    '<div class="ai-row"><input type="file" id="api-inv-file" accept=".json,.yaml,.yml,application/json,text/yaml"' + on('change', 'apiInvLoadFile') + '>' +
    btn('Import', 'apiInvImport', [], 'btn-primary') + '</div><div id="api-inv-import-result"></div>';
}

function inventoryMeta() {
  var i = S.inv;
  var rows = [['Version', 'v' + i.version + (S.version ? '' : ' (newest)')], ['API', (i.title || '—') + ' ' + (i.api_version || '')], ['OpenAPI', i.openapi_version],
    ['Imported', fmtDate(i.imported_at) + ' by ' + i.imported_by], ['Source SHA-256', String(i.source_sha256 || '').slice(0, 16) + '…'], ['Operations', i.operations]];
  var scope = Array.isArray(i.suggested_scope) && i.suggested_scope.length
    ? '<p class="ai-note">Suggested allowed path prefixes (advice only, not applied to the target): <span class="ai-mono">' + i.suggested_scope.map(x).join(' ') + '</span></p>' : '';
  var warn = Array.isArray(i.warnings) && i.warnings.length ? '<p class="ai-note">Warnings: ' + i.warnings.map(x).join('; ') + '</p>' : '';
  return kv(rows) + scope + warn;
}

function opsBody() {
  var i = S.inv;
  var ops = M.filterOps(i.listed_operations, S.cls);
  var filter = seg(M.classOptions(i.listed_operations, i.classes), S.cls, 'apiInvFilter');
  var shown = ops.slice(0, MAX_ROWS);
  var rows = shown.map(function(o) {
    return '<tr><td>' + chip(o.method, 'info') + '</td><td class="ai-mono">' + x(o.path + (o.field ? '#' + o.field : '')) + '</td>' +
      '<td>' + pill(M.authLabel(o.auth), M.authTone(o.auth)) + (o.deprecated ? ' ' + chip('deprecated', 'warn') : '') + '</td>' +
      '<td>' + (o.classes || []).map(function(c) { return chip(M.classLabel(c), 'accent'); }).join(' ') + '</td></tr>';
  }).join('');
  return filter + '<div class="tbl-wrap"><table><thead><tr><th>Method</th><th>Path</th><th>Authentication</th><th>Candidate classes</th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
    (ops.length > MAX_ROWS ? '<p class="ai-note">Showing the first ' + MAX_ROWS + ' of ' + ops.length + ' operations. Use a class filter to narrow the list.</p>' : '');
}

export function apiInvFilter(cls) {
  S.cls = cls;
  var host = el('api-inv-ops');
  if (host) host.innerHTML = opsBody();
}

function versionsBody() {
  if (!S.versions.length) return empty('file', 'No versions');
  var rows = S.versions.map(function(v) {
    return '<tr><td>v' + x(v.version) + '</td><td>' + x(v.operations) + ' operations</td><td>' + x(fmtDate(v.imported_at)) + ' by ' + x(v.imported_by) + '</td>' +
      '<td>' + (v.version === S.inv.version ? chip('viewing', 'ok') : btn('View', 'apiInvVersion', [v.version])) + '</td></tr>';
  }).join('');
  return '<div class="tbl-wrap"><table><thead><tr><th>Version</th><th>Size</th><th>Imported</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>';
}

export function apiInvVersion(n) { loadDetail(n); }

function driftBody() {
  return '<p class="ai-note">One route per line, for example <span class="ai-mono">GET /v2/orders</span>, taken from a gateway log or route table. Lines starting with # are ignored.</p>' +
    '<textarea id="api-inv-observed" class="ai-text" rows="6" spellcheck="false" aria-label="Observed routes"></textarea>' +
    '<div class="ai-row">' + btn('Compare', 'apiInvDrift', [], 'btn-primary') + '</div><div id="api-inv-drift-result"></div>';
}

function jobsRows() {
  if (!S.jobs.length) return empty('runs', 'No jobs yet', 'Run the stored test data below, or submit a job through the API.');
  var rows = S.jobs.map(function(j) {
    return '<tr><td>' + x(fmtDate(j.created_at)) + '</td><td>' + x(j.requested_by) + '</td><td>' + (j.bound ? chip('bound', 'info') : chip('catalogue', 'muted')) + '</td>' +
      '<td>' + pill(j.status, M.jobTone(j.status)) + '</td><td>' + pill(M.countsText(j.results), M.worstTone(j.results)) + '<div class="ai-sub">' + x(j.scenarios) + ' scenario(s)</div></td>' +
      '<td>' + btn('View', 'apiInvJob', [j.id]) + '</td></tr>';
  }).join('');
  return '<div class="tbl-wrap"><table><thead><tr><th>Created</th><th>By</th><th>Kind</th><th>Status</th><th>Results</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>';
}

function jobsBody() {
  return '<div class="ai-row">' + btn('Refresh', 'apiInvJobsRefresh') + '</div><div id="api-inv-jobs-list">' + jobsRows() + '</div><div id="api-inv-jobview"></div>';
}

function refreshJobs() {
  if (!S.sel) return Promise.resolve();
  return apicall(base() + '/jobs').then(function(r) {
    if (!r || !Array.isArray(r.jobs)) return;
    S.jobs = r.jobs;
    var host = el('api-inv-jobs-list');
    if (host) host.innerHTML = jobsRows();
  }).catch(function() { /* the list keeps what it had */ });
}

export function apiInvJobsRefresh() { refreshJobs(); }

// apiInvJob shows one job from the list, following it if it has not ended.
export function apiInvJob(id) { followJob(id, 'api-inv-jobview'); }

function bindingBody() {
  var note = M.storedNote(S.stored);
  var prefill = S.stored ? JSON.stringify(S.stored.spec, null, 2) : '';
  return '<p class="ai-note">Test data as JSON: identities (a name and the <b>name</b> of a credential registered on the target, never its value) and the objects each identity owns. Reads, and PUT or PATCH writes with a <code>write</code> block and <code>allow_writes</code>, are bound. Saving checks the data against the newest inventory.</p>' +
    '<p class="' + (S.stored && S.stored.stale ? 'ai-warn' : 'ai-note') + '" id="api-inv-stored-note">' + (note ? x(note) : 'No test data is stored for this target (or your role cannot read it).') + '</p>' +
    '<textarea id="api-inv-binding" class="ai-text" rows="14" spellcheck="false" aria-label="Binding test data"' + on('input', 'apiInvWriteSync') + '>' + x(prefill) + '</textarea>' +
    '<div class="ai-row">' + btn('Fill a read example', 'apiInvExample') + btn('Fill a write example', 'apiInvExampleWrite') + btn('Fill a function and property example', 'apiInvExampleChecks') + btn('Preview', 'apiInvPlanBinding') +
    btn('Save', 'apiInvSaveBinding', [], 'btn-primary') + (S.stored ? btn('Remove stored data', 'apiInvDeleteBinding') : '') + '</div><div id="api-inv-binding-result"></div>' + writeFormHtml() +
    '<h4 class="ai-h">Run the stored test data</h4><p class="ai-note">Queues a job through the normal approval and scope checks. Production targets are refused, and write scenarios need the target to have allowed paths. Needs permission to run API BAS.</p>' +
    '<div class="ai-row">' + btn('Run stored test data', 'apiInvRunBound', [], 'btn-primary') + '</div><div id="api-inv-job"></div>';
}

export function apiInvLoadFile(inputEl) {
  var f = inputEl && inputEl.files && inputEl.files[0];
  if (!f) return;
  if (f.size > M.MAX_SPEC_BYTES) { showToast('That file is larger than 8 MiB.', 'err'); return; }
  var rd = new FileReader();
  rd.onload = function() { var t = el('api-inv-spec'); if (t) t.value = String(rd.result || ''); };
  rd.onerror = function() { showToast('The file could not be read.', 'err'); };
  rd.readAsText(f);
}

export function apiInvImport() {
  var t = el('api-inv-spec');
  var text = t ? t.value : '';
  if (!text.trim()) { showToast('Paste or choose an OpenAPI document first.', 'err'); return; }
  var out = el('api-inv-import-result');
  if (out) out.innerHTML = '<p class="ai-note">Importing…</p>';
  apicall(base() + '/inventory', { method: 'POST', body: text, headers: { 'Content-Type': 'text/plain' } }).then(function(r) {
    var err = M.errorText(r);
    if (err) { if (out) out.innerHTML = '<p class="ai-err">' + x(err) + '</p>'; return; }
    var lines = M.changeLines(r.changes);
    var html;
    if (r.unchanged) {
      html = '<p class="ai-ok">This document is identical to version ' + x(r.version) + '. Nothing was stored.</p>';
    } else {
      html = '<p class="ai-ok">Stored as version ' + x(r.version) + ' with ' + x(r.operations) + ' operations.</p>' +
        (lines.length ? '<ul class="ai-list">' + lines.map(function(l) { return '<li>' + x(l) + '</li>'; }).join('') + '</ul>' : '<p class="ai-note">No operations were added, removed or re-secured.</p>');
    }
    S.version = 0;
    loadApiInventory().then(function() { var o2 = el('api-inv-import-result'); if (o2) o2.innerHTML = html; });
  }).catch(function(e) {
    if (out) out.innerHTML = '<p class="ai-err">' + x(e && e.message ? e.message : 'The request failed') + '</p>';
  });
}

export function apiInvDrift() {
  var t = el('api-inv-observed');
  var p = M.parseObserved(t ? t.value : '');
  var out = el('api-inv-drift-result');
  if (!out) return;
  if (p.error) { out.innerHTML = '<p class="ai-err">' + x(p.error) + '</p>'; return; }
  var q = S.version ? '?version=' + encodeURIComponent(S.version) : '';
  apicall(base() + '/inventory/drift' + q, { method: 'POST', body: JSON.stringify({ observed: p.routes }) }).then(function(r) {
    var err = M.errorText(r);
    if (err) { out.innerHTML = '<p class="ai-err">' + x(err) + '</p>'; return; }
    var und = (r.undocumented || []).map(function(o) { return '<li class="ai-mono">' + x(o.Method || o.method) + ' ' + x(o.Path || o.path) + '</li>'; }).join('');
    var dep = (r.deprecated_in_use || []).map(function(k) { return '<li class="ai-mono">' + x(k) + '</li>'; }).join('');
    out.innerHTML = kv([['Compared against', 'version ' + r.version], ['Observed but not in the specification', r.undocumented_total], ['In the specification but not seen', r.unserved_total]]) +
      (und ? '<h4 class="ai-h">Not in the specification</h4><ul class="ai-list">' + und + '</ul>' : '') +
      (dep ? '<h4 class="ai-h">Deprecated and in use</h4><ul class="ai-list">' + dep + '</ul>' : '') +
      '<p class="ai-note">' + x(r.note) + '</p>';
  }).catch(function(e) { out.innerHTML = '<p class="ai-err">' + x(e && e.message ? e.message : 'The request failed') + '</p>'; });
}

export function apiInvExample() {
  var t = el('api-inv-binding');
  if (t && S.inv) t.value = JSON.stringify(M.exampleBindingSpec(S.inv.listed_operations), null, 2);
  apiInvWriteSync();
}

function planHtml(r) {
  var bound = (r.bound || []).map(function(b) {
    return '<tr><td class="ai-mono">' + x(b.scenario_id) + '</td><td class="ai-mono">' + x(b.operation) + '</td><td>' + (b.write ? chip('write', 'warn') : chip(M.boundKindLabel(b), 'info')) +
      '</td><td>' + x(M.boundWho(b)) + '</td><td class="ai-mono">' + x(b.path) + '</td></tr>';
  }).join('');
  var skipped = (r.skipped || []).map(function(s) { return '<tr><td class="ai-mono">' + x(s.operation) + '</td><td>' + x(s.reason) + '</td></tr>'; }).join('');
  var writes = (r.bound || []).some(function(b) { return b.write; });
  return '<p class="ai-ok">' + x(r.scenarios) + ' scenario(s) from inventory version ' + x(r.inventory_version) + '.</p>' +
    (writes ? '<p class="ai-warn">Write scenarios try to change the listed objects. A successful change is undone by your restore request, before and after the run. If a restore is refused the result is an error and the object must be checked by hand.</p>' : '') +
    (bound ? '<h4 class="ai-h">Scenarios</h4><div class="tbl-wrap"><table><thead><tr><th>Scenario</th><th>Operation</th><th>Kind</th><th>Attacker → owner</th><th>Request path</th></tr></thead><tbody>' + bound + '</tbody></table></div>' : '') +
    (skipped ? '<h4 class="ai-h">Not bound</h4><div class="tbl-wrap"><table><thead><tr><th>Operation</th><th>Why</th></tr></thead><tbody>' + skipped + '</tbody></table></div>' : '') +
    '<h4 class="ai-h">What a result would and would not show</h4><ul class="ai-list">' + (r.limits || []).map(function(l) { return '<li>' + x(l) + '</li>'; }).join('') + '</ul>';
}

function failText(e) { return x(e && e.message ? e.message : 'The request failed'); }

// apiInvPlanBinding previews the typed test data, or the stored data when the box is empty. Nothing is stored or run.
export function apiInvPlanBinding() {
  var t = el('api-inv-binding');
  var out = el('api-inv-binding-result');
  if (!out) return;
  var typed = t ? t.value.trim() : '';
  var body = '';
  if (typed !== '') {
    var p = M.parseBindingSpec(typed);
    if (p.error) { out.innerHTML = '<p class="ai-err">' + x(p.error) + '</p>'; return; }
    body = JSON.stringify(p.spec);
  } else if (!S.stored) {
    out.innerHTML = '<p class="ai-err">Enter test data, or save some first.</p>';
    return;
  }
  var q = S.version ? '?version=' + encodeURIComponent(S.version) : '';
  apicall(base() + '/binding/plan' + q, { method: 'POST', body: body }).then(function(r) {
    var err = M.errorText(r);
    out.innerHTML = err ? '<p class="ai-err">' + x(err) + '</p>' : planHtml(r);
  }).catch(function(e) { out.innerHTML = '<p class="ai-err">' + failText(e) + '</p>'; });
}

// apiInvSaveBinding stores the typed test data on the target. The server checks it against the newest inventory first.
export function apiInvSaveBinding() {
  var t = el('api-inv-binding');
  var out = el('api-inv-binding-result');
  if (!out) return;
  var p = M.parseBindingSpec(t ? t.value : '');
  if (p.error) { out.innerHTML = '<p class="ai-err">' + x(p.error) + '</p>'; return; }
  apicall(base() + '/binding', { method: 'PUT', body: JSON.stringify(p.spec) }).then(function(r) {
    var err = M.errorText(r);
    if (err) { out.innerHTML = '<p class="ai-err">' + x(err) + '</p>'; return; }
    showToast('Test data stored.', 'ok');
    var html = planHtml(r);
    loadDetail(S.version).then(function() { var o2 = el('api-inv-binding-result'); if (o2) o2.innerHTML = html; });
  }).catch(function(e) { out.innerHTML = '<p class="ai-err">' + failText(e) + '</p>'; });
}

// apiInvDeleteBinding removes the stored test data. It can be typed again, so there is no confirmation step.
export function apiInvDeleteBinding() {
  fetch(base() + '/binding', { method: 'DELETE', credentials: 'same-origin' }).then(function(r) {
    if (r.status === 204) { showToast('Stored test data removed.', 'ok'); S.stored = null; return loadDetail(S.version); }
    return r.json().then(function(b) { showToast(M.errorText(b) || 'Could not remove the test data.', 'err'); });
  }).catch(function(e) { showToast('Could not reach the server: ' + (e && e.message ? e.message : 'request failed'), 'err'); });
}

export function apiInvExampleWrite() {
  var t = el('api-inv-binding');
  if (t && S.inv) t.value = JSON.stringify(M.exampleWriteBindingSpec(S.inv.listed_operations), null, 2);
  apiInvWriteSync();
}

// apiInvRunBound queues a job from the stored test data and follows it until it ends.
export function apiInvRunBound() {
  var out = el('api-inv-job');
  if (!out) return;
  if (!S.stored) { out.innerHTML = '<p class="ai-err">Save test data first. A job runs the stored data, not the box above.</p>'; return; }
  if (S.stored.stale) { out.innerHTML = '<p class="ai-err">' + x(M.storedNote(S.stored)) + '</p>'; return; }
  out.innerHTML = '<p class="ai-note">Queuing…</p>';
  apicall(base() + '/binding/jobs', { method: 'POST', body: JSON.stringify({ key: M.newJobKey() }) }).then(function(r) {
    var err = M.errorText(r);
    if (err || !r.id) { out.innerHTML = '<p class="ai-err">' + x(err || 'The server did not return a job.') + '</p>'; return; }
    followJob(r.id, 'api-inv-job');
  }).catch(function(e) { out.innerHTML = '<p class="ai-err">' + failText(e) + '</p>'; });
}

var POLL_MS = 3000;
var MAX_POLLS = 200;

// followJob renders a job into the element outId and re-checks it until it ends. Each panel follows one job at a time; starting
// another in the same panel, or selecting another target, stops the earlier one.
function followJob(id, outId) {
  outId = outId || 'api-inv-job';
  var token = (S.polls[outId] || 0) + 1;
  S.polls[outId] = token;
  var n = 0;
  function tick() {
    if (S.polls[outId] !== token) return;
    apicall('/api/apibas/jobs/' + encodeURIComponent(id)).then(function(j) {
      if (S.polls[outId] !== token) return;
      var out = el(outId);
      if (!out) return;
      var err = M.errorText(j);
      if (err) { out.innerHTML = '<p class="ai-err">' + x(err) + '</p>'; return; }
      out.innerHTML = jobHtml(j);
      if (M.isFinalStatus(j.status)) { refreshJobs(); return; }
      if (++n >= MAX_POLLS) { out.innerHTML += '<p class="ai-note">Stopped following after 10 minutes. The job may still be running; use Refresh to look again.</p>'; return; }
      setTimeout(tick, POLL_MS);
    }).catch(function(e) {
      var out = el(outId);
      if (out && S.polls[outId] === token) out.innerHTML = '<p class="ai-err">Lost contact with the server: ' + failText(e) + '</p>';
    });
  }
  tick();
}

function jobHtml(j) {
  var rows = (j.reports || []).map(function(rp) {
    return '<tr><td class="ai-mono">' + x(rp.scenario_id) + '</td><td>' + pill(rp.result, M.resultTone(rp.result)) + '</td>' +
      '<td>' + x(rp.exploitability) + '</td><td>' + x(rp.control) + '</td><td>' + x(M.resultText(rp)) + '</td></tr>';
  }).join('');
  return kv([['Job', j.id], ['Status', j.status], ['Environment', j.environment], ['Started', j.started_at ? fmtDate(j.started_at) : '—'], ['Finished', j.finished_at ? fmtDate(j.finished_at) : '—']]) +
    '<p>' + pill(j.status, M.jobTone(j.status)) + (j.failure_reason ? ' <span class="ai-err">' + x(j.failure_reason) + '</span>' : '') + '</p>' +
    (rows ? '<div class="tbl-wrap"><table><thead><tr><th>Scenario</th><th>Result</th><th>Exploitability</th><th>Control</th><th>Meaning</th></tr></thead><tbody>' + rows + '</tbody></table></div>' : '') +
    (M.isFinalStatus(j.status) ? '' : '<p class="ai-note">Running. This page checks every few seconds.</p>');
}

// ---- write-block form. It edits the test-data box above it (the box stays the source of truth) and stores nothing itself.

function writeFormHtml() {
  var wops = S.inv ? M.writeOperations(S.inv.listed_operations) : [];
  if (!wops.length) {
    return '<h4 class="ai-h">Write objects</h4><p class="ai-note">This inventory has no authenticated PUT or PATCH operation with a path parameter, so there is nothing to write-test.</p>';
  }
  var opts = wops.map(function(o) { return '<option value="' + x(M.opKey(o)) + '">' + x(M.opKey(o)) + '</option>'; }).join('');
  return '<h4 class="ai-h">Write objects</h4>' +
    '<p class="ai-warn">A write scenario really tries to change the object named here. A successful change is undone by the restore body, sent as the owner before the run and again after. Use a test object you accept being changed. Adding an object here turns on <code>allow_writes</code> in the test data.</p>' +
    '<div id="api-inv-wlist"></div>' +
    '<div class="ai-form">' +
    '<label class="ai-lbl">Operation<select id="api-inv-w-op" class="ai-in"' + on('change', 'apiInvWriteOp') + '>' + opts + '</select></label>' +
    '<div id="api-inv-w-params"></div>' +
    '<label class="ai-lbl">Owner (an identity in the test data)<select id="api-inv-w-owner" class="ai-in"></select></label>' +
    '<label class="ai-lbl">Attack body (JSON the other identity sends)<textarea id="api-inv-w-attack" class="ai-text" rows="3" spellcheck="false"></textarea></label>' +
    '<label class="ai-lbl">Restore body (JSON the owner sends to put the object back)<textarea id="api-inv-w-restore" class="ai-text" rows="3" spellcheck="false"></textarea></label>' +
    '<label class="ai-lbl">Read the object back through<select id="api-inv-w-read" class="ai-in"></select></label>' +
    '<label class="ai-lbl">Ignored response fields (comma separated, for example updated_at)<input id="api-inv-w-ignore" class="ai-in" type="text" spellcheck="false"></label>' +
    '<div class="ai-row">' + btn('Add to test data', 'apiInvWriteApply', [], 'btn-primary') + btn('Clear form', 'apiInvWriteClear') + '</div></div>' +
    '<div id="api-inv-w-result"></div>';
}

// readSpecLoose reads the test-data box as JSON without requiring the full outline, so the form can start from an empty box.
function readSpecLoose() {
  var t = el('api-inv-binding');
  var raw = t ? t.value.trim() : '';
  if (raw === '') return { spec: {}, error: '' };
  var v;
  try { v = JSON.parse(raw); } catch (e) { return { spec: null, error: 'The test data above is not valid JSON, so the form cannot change it. Fix it first.' }; }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return { spec: null, error: 'The test data must be a JSON object.' };
  return { spec: v, error: '' };
}

function putSpec(spec) {
  var t = el('api-inv-binding');
  if (t) t.value = JSON.stringify(spec, null, 2);
  apiInvWriteSync();
}

function wmsg(html) { var o = el('api-inv-w-result'); if (o) o.innerHTML = html; }

function currentWriteOp() {
  var sel = el('api-inv-w-op');
  if (!sel || !S.inv) return null;
  return M.writeOperations(S.inv.listed_operations).filter(function(o) { return M.opKey(o) === sel.value; })[0] || null;
}

// apiInvWriteOp (re)draws the path-parameter inputs and the read-back choices for the chosen operation.
export function apiInvWriteOp() {
  var op = currentWriteOp();
  var params = el('api-inv-w-params');
  var read = el('api-inv-w-read');
  if (!op || !params || !read) return;
  params.innerHTML = op.path_params.map(function(n) {
    return '<label class="ai-lbl">Value of {' + x(n) + '} for the test object<input class="ai-in" type="text" data-param="' + x(n) + '" spellcheck="false"></label>';
  }).join('');
  var def = M.defaultReadOperation(S.inv.listed_operations, op);
  var choices = M.readChoices(S.inv.listed_operations, op);
  read.innerHTML = '<option value="">' + (def ? 'Same path (' + x(def) + ')' : 'Choose…') + '</option>' +
    choices.filter(function(c) { return c !== def; }).map(function(c) { return '<option value="' + x(c) + '">' + x(c) + '</option>'; }).join('');
}

// apiInvWriteSync redraws the list of write objects and the owner choices from the box. It runs on every edit of the box.
export function apiInvWriteSync() {
  var list = el('api-inv-wlist');
  var owner = el('api-inv-w-owner');
  var r = readSpecLoose();
  if (owner) {
    var keep = owner.value;
    var names = r.spec ? M.identityNames(r.spec) : [];
    owner.innerHTML = names.length ? names.map(function(n) { return '<option value="' + x(n) + '"' + (n === keep ? ' selected' : '') + '>' + x(n) + '</option>'; }).join('')
      : '<option value="">(add identities to the test data first)</option>';
  }
  if (!list) return;
  if (r.error) { list.innerHTML = '<p class="ai-note">' + x(r.error) + '</p>'; return; }
  var ws = M.writeObjectsOf(r.spec);
  if (!ws.length) { list.innerHTML = '<p class="ai-note">No write objects in the test data yet.</p>'; return; }
  list.innerHTML = '<div class="tbl-wrap"><table><thead><tr><th>Operation</th><th>Values</th><th>Owner</th><th>Read back through</th><th></th></tr></thead><tbody>' + ws.map(function(w) {
    var vals = Object.keys(w.params).sort().map(function(k) { return k + '=' + w.params[k]; }).join(', ');
    return '<tr><td class="ai-mono">' + x(w.operation) + '</td><td class="ai-mono">' + x(vals) + '</td><td>' + x(w.owner) + '</td><td class="ai-mono">' +
      x(w.write.read_operation || 'same path') + '</td><td>' + btn('Edit', 'apiInvWriteEdit', [w.index]) + ' ' + btn('Remove', 'apiInvWriteRemove', [w.index]) + '</td></tr>';
  }).join('') + '</tbody></table></div>';
}

function formValues() {
  var params = {};
  var inputs = document.querySelectorAll('#api-inv-w-params [data-param]');
  for (var i = 0; i < inputs.length; i++) params[inputs[i].getAttribute('data-param')] = inputs[i].value;
  var v = function(id) { var e = el(id); return e ? e.value : ''; };
  return { operation: v('api-inv-w-op'), params: params, owner: v('api-inv-w-owner'), attack_body: v('api-inv-w-attack'), restore_body: v('api-inv-w-restore'),
    read_operation: v('api-inv-w-read'), ignore_fields: v('api-inv-w-ignore') };
}

// apiInvWriteApply checks the form and merges the object into the test-data box. Nothing is saved or run.
export function apiInvWriteApply() {
  if (!S.inv) return;
  var built = M.buildWriteObject(formValues(), S.inv.listed_operations);
  if (built.error) { wmsg('<p class="ai-err">' + x(built.error) + '</p>'); return; }
  var cur = readSpecLoose();
  if (cur.error) { wmsg('<p class="ai-err">' + x(cur.error) + '</p>'); return; }
  var merged = M.mergeWriteObject(cur.spec, built.object);
  if (merged.error) { wmsg('<p class="ai-err">' + x(merged.error) + '</p>'); return; }
  putSpec(merged.spec);
  wmsg('<p class="ai-ok">' + (merged.replaced ? 'Replaced the matching object in the test data.' : 'Added to the test data.') + ' It is not saved yet: use Preview to check it and Save to store it.</p>');
}

export function apiInvWriteClear() {
  ['api-inv-w-attack', 'api-inv-w-restore', 'api-inv-w-ignore'].forEach(function(id) { var e = el(id); if (e) e.value = ''; });
  apiInvWriteOp();
  wmsg('');
}

// apiInvWriteEdit loads one write object from the box into the form, so changing it and adding it again replaces it.
export function apiInvWriteEdit(index) {
  var cur = readSpecLoose();
  if (cur.error) { wmsg('<p class="ai-err">' + x(cur.error) + '</p>'); return; }
  var w = M.writeObjectsOf(cur.spec).filter(function(o) { return o.index === index; })[0];
  if (!w) return;
  var sel = el('api-inv-w-op');
  if (sel) {
    var has = Array.prototype.some.call(sel.options, function(o) { return o.value === w.operation; });
    if (!has) { wmsg('<p class="ai-err">' + x(w.operation) + ' is not a PUT or PATCH operation in the current inventory, so the form cannot edit it. Edit the JSON above.</p>'); return; }
    sel.value = w.operation;
  }
  apiInvWriteOp();
  var inputs = document.querySelectorAll('#api-inv-w-params [data-param]');
  for (var i = 0; i < inputs.length; i++) inputs[i].value = w.params[inputs[i].getAttribute('data-param')] || '';
  var set = function(id, val) { var e = el(id); if (e) e.value = val; };
  set('api-inv-w-owner', w.owner);
  set('api-inv-w-attack', w.write.attack_body || '');
  set('api-inv-w-restore', w.write.restore_body || '');
  set('api-inv-w-read', w.write.read_operation || '');
  set('api-inv-w-ignore', Array.isArray(w.write.ignore_fields) ? w.write.ignore_fields.join(', ') : '');
  wmsg('<p class="ai-note">Loaded. Change what you need and choose Add to test data to replace it.</p>');
}

export function apiInvWriteRemove(index) {
  var cur = readSpecLoose();
  if (cur.error) { wmsg('<p class="ai-err">' + x(cur.error) + '</p>'); return; }
  putSpec(M.removeObjectAt(cur.spec, index));
  wmsg('<p class="ai-note">Removed from the test data. Not saved yet.</p>');
}

// ---- schedule card

function scheduleBody() {
  var s = S.schedule;
  var t = S.targets.filter(function(a) { return a.id === S.sel; })[0];
  if (t && t.environment === 'production') {
    return '<p class="ai-note">A production target cannot be scheduled: each production run needs its own approval by a second person.</p>';
  }
  var state = M.scheduleState(s);
  var pill1 = s ? pill(state === 'paused' ? 'paused' : state, M.scheduleTone(s)) + ' ' : '';
  return '<p class="ai-note">Runs this target\'s stored test data on a fixed interval, through the same checks as a manual run: the target must be enabled, its scope and credentials must be registered, and nothing else may be running on it. The first run is one interval after you save. A run missed while the server is down is run once, not made up. Needs permission to manage targets.</p>' +
    '<p class="' + (state === 'paused' ? 'ai-warn' : 'ai-note') + '" id="api-inv-sched-note">' + pill1 + x(M.scheduleNote(s)) + '</p>' +
    '<div class="ai-form">' +
    '<label class="ai-lbl">Run every (hours, 1 to ' + M.MAX_EVERY_HOURS + '; 24 is daily, 168 weekly)<input id="api-inv-sched-hours" class="ai-in" type="text" inputmode="numeric" value="' + x(String(s ? s.every_hours : 24)) + '" spellcheck="false"></label>' +
    '<label class="ai-lbl"><span><input id="api-inv-sched-writes" type="checkbox"' + (s && s.include_writes ? ' checked' : '') + '> Include write scenarios. A write that succeeds changes the customer\'s object while nobody is watching; leave this off unless the objects are meant for it. The target needs registered allowed paths.</span></label>' +
    '<label class="ai-lbl"><span><input id="api-inv-sched-enabled" type="checkbox"' + (!s || s.enabled ? ' checked' : '') + '> Schedule is on</span></label>' +
    '<div class="ai-row">' + btn(s ? 'Save schedule' : 'Create schedule', 'apiInvSaveSchedule', [], 'btn-primary') + (s ? btn('Remove schedule', 'apiInvRemoveSchedule') : '') + '</div></div>' +
    '<div id="api-inv-sched-result"></div>';
}

// apiInvSaveSchedule stores the schedule. Saving a paused schedule resumes it.
export function apiInvSaveSchedule() {
  var out = el('api-inv-sched-result');
  if (!out) return;
  var p = M.parseEveryHours(el('api-inv-sched-hours') ? el('api-inv-sched-hours').value : '');
  if (p.error) { out.innerHTML = '<p class="ai-err">' + x(p.error) + '</p>'; return; }
  var body = { every_hours: p.hours, include_writes: !!(el('api-inv-sched-writes') && el('api-inv-sched-writes').checked), enabled: !!(el('api-inv-sched-enabled') && el('api-inv-sched-enabled').checked) };
  apicall(base() + '/schedule', { method: 'PUT', body: JSON.stringify(body) }).then(function(r) {
    var err = M.errorText(r);
    if (err) { out.innerHTML = '<p class="ai-err">' + x(err) + '</p>'; return; }
    showToast('Schedule saved.', 'ok');
    S.schedule = r;
    renderDetail();
  }).catch(function(e) { out.innerHTML = '<p class="ai-err">' + failText(e) + '</p>'; });
}

export function apiInvRemoveSchedule() {
  fetch(base() + '/schedule', { method: 'DELETE', credentials: 'same-origin' }).then(function(r) {
    if (r.status === 200) { showToast('Schedule removed.', 'ok'); S.schedule = null; renderDetail(); return null; }
    return r.json().then(function(b) { showToast(M.errorText(b) || 'Could not remove the schedule.', 'err'); });
  }).catch(function(e) { showToast('Could not reach the server: ' + (e && e.message ? e.message : 'request failed'), 'err'); });
}

// apiInvExampleChecks fills a starting point for function-level and property-level read checks.
export function apiInvExampleChecks() {
  var t = el('api-inv-binding');
  if (t && S.inv) t.value = JSON.stringify(M.exampleChecksSpec(S.inv.listed_operations), null, 2);
  apiInvWriteSync();
}
