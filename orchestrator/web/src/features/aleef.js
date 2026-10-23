import { ROLE, doLogout } from './shell.js';
import { setDisplay } from '../core/inline-style.js';
import {
  ALEEF_CLASSES, ALEEF_PRIOR_KNOWLEDGE, ALEEF_OPENAPI_WARN_BYTES, ALEEF_OPENAPI_MAX_BYTES, aleefPerms, hasAleefAddon, splitFindings,
  runSummary, createPoller, buildEngagementRequest, buildRunRequest, operationIdsFromOpenAPI, apiErrorMessage
} from './aleef-model.js';

// ── Aleef API discovery console ──────────────────────────────────────────────
// A licensed special add-on. Every string from the server is written with textContent / createElement; nothing here
// uses innerHTML. Candidates and verified findings are separate tables fed from separate API arrays and never merged.
// Tokens never enter the console: an account names a secret reference that the server resolves.

var ENG_KEY = 'aleef_engagements';
var RUN_KEY = 'aleef_last_run';
var poller = null;
var confirmingStop = false;
var currentRunId = '';
var lastSummary = null;

function byId(id) { return document.getElementById(id); }

function el(tag, props, children) {
  var n = document.createElement(tag);
  if (props) {
    Object.keys(props).forEach(function(k) {
      if (k === 'text') n.textContent = props[k];
      else if (k === 'class') n.className = props[k];
      else n.setAttribute(k, props[k]);
    });
  }
  (children || []).forEach(function(c) { if (c) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
  return n;
}

function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); }

function setStatus(msg, kind) {
  var s = byId('aleef-status');
  if (!s) return;
  s.textContent = msg || '';
  s.className = 'aleef-status' + (kind ? ' aleef-' + kind : '');
}

function store(key, val) { try { localStorage.setItem(key, val); } catch (e) { /* storage unavailable: convenience only */ } }
function recall(key) { try { return localStorage.getItem(key) || ''; } catch (e) { return ''; } }

// aleefApi returns { status, body }. A 401 signs the user out, like apicall.
export function aleefApi(path, opts) {
  opts = opts || {};
  return fetch(path, Object.assign({ credentials: 'same-origin' }, opts, {
    headers: Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {})
  })).then(function(r) {
    if (r.status === 401) { doLogout(); }
    return r.json().catch(function() { return {}; }).then(function(body) { return { status: r.status, body: body }; });
  });
}

// ── nav visibility ───────────────────────────────────────────────────────────
// Shown only for a role with aleef:view AND when the licence lists the aleef special add-on. GET /api/license is
// admin only, so other roles are checked by asking the (gated) findings route: a 403 means not licensed.
export function initAleefNav(role) {
  var nav = byId('nav-aleef');
  if (!nav) return Promise.resolve(false);
  setDisplay(nav, 'none');
  if (!aleefPerms(role).view) return Promise.resolve(false);
  var check = role === 'admin'
    ? aleefApi('/api/license').then(function(r) { return r.status === 200 && hasAleefAddon(r.body); })
    : aleefApi('/api/aleef/findings').then(function(r) { return r.status === 200; });
  return check.then(function(ok) { setDisplay(nav, ok ? '' : 'none'); return ok; }).catch(function() { return false; });
}

// ── tab lifecycle ────────────────────────────────────────────────────────────
export function stopAleefPolling() {
  if (poller) poller.stop();
  confirmingStop = false;
}

export function loadAleef() {
  var perms = aleefPerms(ROLE);
  setDisplay(byId('aleef-eng-section'), perms.authorize ? '' : 'none');
  setDisplay(byId('aleef-run-section'), perms.run ? '' : 'none');
  fillEngagementList();
  if (byId('aleef-accounts') && !byId('aleef-accounts').firstChild) addAccountRow();
  setStatus('');
  var id = currentRunId || recall(RUN_KEY);
  if (id) trackRun(id);
  loadAleefFindings();
}

// ── engagements ──────────────────────────────────────────────────────────────
function savedEngagements() {
  try { var v = JSON.parse(recall(ENG_KEY) || '[]'); return Array.isArray(v) ? v : []; } catch (e) { return []; }
}

function fillEngagementList() {
  var dl = byId('aleef-eng-list');
  if (!dl) return;
  clear(dl);
  savedEngagements().forEach(function(e) {
    var o = el('option', { value: e.id }); o.label = (e.customer || '') + ' (' + (e.environment || '') + ')';
    dl.appendChild(o);
  });
}

function val(id) { var n = byId(id); return n ? n.value : ''; }

function submitEngagement() {
  var req = buildEngagementRequest({
    customer: val('aleef-eng-customer'), environment: val('aleef-eng-env'), notBefore: val('aleef-eng-start'), notAfter: val('aleef-eng-end'),
    hosts: val('aleef-eng-hosts'), operations: val('aleef-eng-ops'), targetScopeId: val('aleef-eng-scope'),
    maxRequests: val('aleef-eng-maxreq'), maxConcurrent: val('aleef-eng-maxconc'), rps: val('aleef-eng-rps')
  });
  if (req.error) { setStatus(req.error, 'error'); return Promise.resolve(); }
  return aleefApi('/api/aleef/engagements', { method: 'POST', body: JSON.stringify(req.body) }).then(function(r) {
    if (r.status !== 201) { setStatus(apiErrorMessage(r.status, r.body), 'error'); return; }
    var list = savedEngagements().filter(function(e) { return e.id !== r.body.id; });
    list.unshift({ id: r.body.id, customer: r.body.customer, environment: r.body.environment });
    store(ENG_KEY, JSON.stringify(list.slice(0, 20)));
    fillEngagementList();
    byId('aleef-run-eng').value = r.body.id;
    setStatus('Engagement created. The approver recorded is you; id ' + r.body.id + '.', 'ok');
  }).catch(function(err) { setStatus(err.message || 'Request failed', 'error'); });
}

// ── run form ─────────────────────────────────────────────────────────────────
export function renderClassTable(host, ops, existing) {
  clear(host);
  if (!ops.length) { host.appendChild(el('p', { class: 'muted', text: 'Load an OpenAPI document to classify its operations. Unclassified operations stay unknown and are never executed.' })); return; }
  var tbody = el('tbody');
  ops.forEach(function(op) {
    var sel = el('select', { 'data-aleef-class': op, 'aria-label': 'Class of ' + op });
    ALEEF_CLASSES.forEach(function(c) { var o = el('option', { value: c, text: c }); if ((existing && existing[op] || 'unknown') === c) o.selected = true; sel.appendChild(o); });
    tbody.appendChild(el('tr', null, [el('td', null, [el('code', { text: op })]), el('td', null, [sel])]));
  });
  host.appendChild(el('table', { class: 'tbl' }, [el('thead', null, [el('tr', null, [el('th', { text: 'Operation' }), el('th', { text: 'Class' })])]), tbody]));
}

function readClasses() {
  var out = {};
  document.querySelectorAll('#aleef-classes [data-aleef-class]').forEach(function(s) { out[s.getAttribute('data-aleef-class')] = s.value; });
  return out;
}

function refreshOpenAPI() {
  var text = val('aleef-run-openapi');
  var warn = byId('aleef-openapi-warn');
  var size = text.length;
  warn.textContent = size > ALEEF_OPENAPI_MAX_BYTES ? 'This document is over the size limit and will be refused.'
    : size > ALEEF_OPENAPI_WARN_BYTES ? 'Large document (' + Math.round(size / 1024) + ' KiB): parsing and the request may be slow.' : '';
  var host = byId('aleef-classes');
  if (!text.trim()) { renderClassTable(host, [], null); return; }
  var r = operationIdsFromOpenAPI(text);
  if (r.error) { clear(host); host.appendChild(el('p', { class: 'aleef-error', text: r.error })); return; }
  renderClassTable(host, r.ops, readClasses());
}

function readOpenAPIFile(file) {
  if (!file) return;
  if (file.size > ALEEF_OPENAPI_MAX_BYTES) { setStatus('That file is over the ' + Math.round(ALEEF_OPENAPI_MAX_BYTES / 1048576) + ' MiB limit.', 'error'); return; }
  var fr = new FileReader();
  fr.onload = function() { byId('aleef-run-openapi').value = String(fr.result || ''); refreshOpenAPI(); };
  fr.onerror = function() { setStatus('Could not read the file.', 'error'); };
  fr.readAsText(file);
}

function addAccountRow() {
  var host = byId('aleef-accounts');
  var row = el('div', { class: 'aleef-account-row', 'data-aleef-account': '1' }, [
    el('input', { 'data-f': 'name', placeholder: 'account name', 'aria-label': 'Account name', maxlength: '64' }),
    el('input', { 'data-f': 'customerId', placeholder: 'customer id', 'aria-label': 'Customer id', maxlength: '128' }),
    el('input', { 'data-f': 'role', placeholder: 'role', 'aria-label': 'Role', maxlength: '64' }),
    el('input', { 'data-f': 'tokenRef', placeholder: 'secret reference', 'aria-label': 'Secret reference', maxlength: '64', autocomplete: 'off' }),
    el('button', { class: 'btn btn-outline btn-sm', type: 'button', 'data-aleef-action': 'remove-account', text: 'Remove' })
  ]);
  host.appendChild(row);
}

function readAccounts() {
  return Array.prototype.map.call(document.querySelectorAll('#aleef-accounts [data-aleef-account]'), function(row) {
    var o = {};
    row.querySelectorAll('input[data-f]').forEach(function(i) { o[i.getAttribute('data-f')] = i.value.trim(); });
    return o;
  });
}

function startRun() {
  var req = buildRunRequest({
    engagementId: val('aleef-run-eng').trim(), baseUrl: val('aleef-run-base'), openapi: val('aleef-run-openapi'), accounts: readAccounts(),
    classes: readClasses(), setup: val('aleef-run-setup'), seed: val('aleef-run-seed'), maxTests: val('aleef-run-max'), reproductions: val('aleef-run-repro')
  });
  if (req.error) { setStatus(req.error, 'error'); return Promise.resolve(); }
  return aleefApi('/api/aleef/runs', { method: 'POST', body: JSON.stringify(req.body) }).then(function(r) {
    if (r.status !== 202) { setStatus(apiErrorMessage(r.status, r.body), 'error'); return; }
    setStatus('Run ' + r.body.run_id + ' started.', 'ok');
    trackRun(r.body.run_id);
  }).catch(function(err) { setStatus(err.message || 'Request failed', 'error'); });
}

// ── run status card ──────────────────────────────────────────────────────────
function tableOf(headers, rows) {
  var thead = el('thead', null, [el('tr', null, headers.map(function(h) { return el('th', { text: h }); }))]);
  var tbody = el('tbody', null, rows.map(function(r) { return el('tr', null, r.map(function(c) { return el('td', null, [typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c]); })); }));
  return el('table', { class: 'tbl' }, [thead, tbody]);
}

export function renderRunCard(host, run, perms, confirming) {
  clear(host);
  if (!run) return;
  var s = runSummary(run);
  host.appendChild(el('h3', { text: 'Run ' + s.runId }));
  var line = el('p', null, [el('strong', { text: 'Status: ' }), el('span', { class: 'aleef-run-status', text: s.status || 'unknown' })]);
  if (!s.finished) line.appendChild(document.createTextNode(' (updating every 3 s)'));
  host.appendChild(line);
  if (s.haltedReason) host.appendChild(el('p', { class: 'aleef-warn', text: 'Halted: ' + s.haltedReason }));
  if (s.error) host.appendChild(el('p', { class: 'aleef-error', text: 'Error: ' + s.error }));
  if (s.orphans.length) {
    var w = el('div', { class: 'aleef-warn', role: 'alert' }, [
      el('strong', { text: 'Orphaned objects: ' + s.orphans.length + ' object(s) created by this run could not be cleaned up. Remove them from the target by hand.' })
    ]);
    w.appendChild(tableOf(['Operation', 'Object id', 'Owner'], s.orphans.map(function(o) { return [o.operation, o.id, o.owner]; })));
    host.appendChild(w);
  }
  if (s.total || s.coverage.length) {
    host.appendChild(el('p', { text: 'Tests: ' + s.total + ' generated, ' + s.executed + ' executed, ' + s.notExecuted + ' not executed.' }));
    host.appendChild(tableOf(['Operation', 'Class', 'Generated', 'Executed', 'Not executed', 'Findings', 'Verified', 'Skipped'],
      s.coverage.map(function(c) { return [c.operation, c.cls, c.generated, c.executed, c.notExecuted, c.findings, c.verified, c.skipped]; })));
  }
  if (!s.finished && perms.run) {
    if (confirming) {
      host.appendChild(el('div', { class: 'aleef-confirm', role: 'alertdialog' }, [
        el('span', { text: 'Stop this run? The campaign will clean up everything it created.' }),
        el('button', { class: 'btn btn-primary btn-sm', type: 'button', 'data-aleef-action': 'stop-confirm', text: 'Confirm stop' }),
        el('button', { class: 'btn btn-outline btn-sm', type: 'button', 'data-aleef-action': 'stop-cancel', text: 'Cancel' })
      ]));
    } else {
      host.appendChild(el('button', { class: 'btn btn-outline btn-sm', type: 'button', 'data-aleef-action': 'stop', text: 'STOP' }));
    }
  }
}

function showRun(run) {
  lastSummary = run;
  var host = byId('aleef-run-card');
  if (host) renderRunCard(host, run, aleefPerms(ROLE), confirmingStop);
}

function trackRun(runId) {
  currentRunId = runId;
  store(RUN_KEY, runId);
  if (poller) poller.stop();
  poller = createPoller({
    intervalMs: 3000,
    fetchFn: function() {
      return aleefApi('/api/aleef/runs/' + encodeURIComponent(runId)).then(function(r) {
        if (r.status !== 200) { throw new Error(apiErrorMessage(r.status, r.body)); }
        return r.body;
      });
    },
    onUpdate: function(run) { if (isPanelVisible()) showRun(run); },
    onFinished: function() { confirmingStop = false; loadAleefFindings(); },
    onError: function(err) { setStatus(err.message || 'Could not refresh the run', 'error'); }
  });
  poller.start();
}

function isPanelVisible() {
  var p = byId('tab-aleef');
  return !!p && !p.classList.contains('is-hidden') && p.style.display !== 'none';
}

function stopRun() {
  if (!currentRunId) return Promise.resolve();
  confirmingStop = false;
  return aleefApi('/api/aleef/runs/' + encodeURIComponent(currentRunId) + '/stop', { method: 'POST' }).then(function(r) {
    if (r.status !== 200) { setStatus(apiErrorMessage(r.status, r.body), 'error'); showRun(lastSummary); return; }
    setStatus('Stop requested. The campaign is cleaning up.', 'ok');
    trackRun(currentRunId);
  }).catch(function(err) { setStatus(err.message || 'Request failed', 'error'); });
}

// ── findings ─────────────────────────────────────────────────────────────────
function findingRow(f, verified, perms) {
  var cells = [f.title || '', f.property_id || '', f.test_id || '', f.state || '', f.novelty_label || '', f.evidence_hash || '', f.created_at || ''];
  if (verified) cells.push(f.regression_id || '');
  var tr = el('tr', { 'data-finding-id': f.id || '' });
  cells.forEach(function(c) { tr.appendChild(el('td', { text: String(c) })); });
  if (verified) {
    var actions = el('td');
    actions.appendChild(el('button', { class: 'btn btn-outline btn-sm', type: 'button', 'data-aleef-action': 'download-regression', 'data-finding': f.id || '', text: 'Download regression' }));
    var sel = el('select', { 'data-aleef-pk': f.id || '', 'aria-label': 'Prior knowledge for ' + (f.title || f.id || '') });
    ALEEF_PRIOR_KNOWLEDGE.forEach(function(p) { var o = el('option', { value: p.value, text: p.label }); if ((f.prior_knowledge || 'not_checked') === p.value) o.selected = true; sel.appendChild(o); });
    if (!perms.run) sel.disabled = true;
    actions.appendChild(sel);
    tr.appendChild(actions);
  }
  return tr;
}

function findingsTable(list, verified, perms) {
  var heads = ['Title', 'Property', 'Test', 'State', 'Novelty', 'Evidence hash', 'Created'];
  if (verified) heads = heads.concat(['Regression', 'Actions']);
  return el('table', { class: 'tbl' }, [
    el('thead', null, [el('tr', null, heads.map(function(h) { return el('th', { text: h }); }))]),
    el('tbody', null, list.map(function(f) { return findingRow(f, verified, perms); }))
  ]);
}

function section(id, title, note, list, verified, perms) {
  var wrap = el('section', { id: id, class: 'aleef-findings-section' }, [el('h3', { text: title + ' (' + list.length + ')' })]);
  if (note) wrap.appendChild(el('p', { class: 'muted', text: note }));
  if (!list.length) wrap.appendChild(el('p', { class: 'muted', text: 'None.' }));
  else wrap.appendChild(findingsTable(list, verified, perms));
  return wrap;
}

function collapsed(id, title, list, perms) {
  var d = el('details', { id: id }, [el('summary', { text: title + ' (' + list.length + ')' })]);
  if (list.length) d.appendChild(findingsTable(list, false, perms));
  return d;
}

// renderFindings draws five independent regions from five independent arrays. verified comes only from body.verified.
export function renderFindings(host, body, perms) {
  clear(host);
  var f = splitFindings(body);
  host.appendChild(section('aleef-candidates', 'Candidates (unverified)', 'Reproduced at least once but not verified. Treat as leads, not results.', f.candidates, false, perms));
  host.appendChild(section('aleef-verified', 'Verified (reproduced 3×, owner + negative control, regression saved)', 'Each row has a saved regression. Set the prior-knowledge review before reporting any finding as new.', f.verified, true, perms));
  if (f.pendingRegression.length) {
    host.appendChild(section('aleef-pending', 'Pending regression', 'Verified but the regression is not saved yet, so these are not listed as verified.', f.pendingRegression, false, perms));
  }
  host.appendChild(collapsed('aleef-unconfirmed', 'Unconfirmed', f.unconfirmed, perms));
  host.appendChild(collapsed('aleef-rejected', 'Rejected', f.rejected, perms));
}

export function loadAleefFindings() {
  var host = byId('aleef-findings');
  if (!host) return Promise.resolve();
  return aleefApi('/api/aleef/findings').then(function(r) {
    if (r.status !== 200) { clear(host); setStatus(apiErrorMessage(r.status, r.body), 'error'); return; }
    renderFindings(host, r.body, aleefPerms(ROLE));
  }).catch(function(err) { setStatus(err.message || 'Could not load findings', 'error'); });
}

function downloadRegression(id) {
  return aleefApi('/api/aleef/findings/' + encodeURIComponent(id) + '/regression').then(function(r) {
    if (r.status !== 200) { setStatus(apiErrorMessage(r.status, r.body), 'error'); return; }
    var blob = new Blob([JSON.stringify(r.body, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = el('a', { href: url, download: 'aleef-regression-' + id + '.json' });
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
    setStatus('Regression downloaded.', 'ok');
  }).catch(function(err) { setStatus(err.message || 'Download failed', 'error'); });
}

function setPriorKnowledge(id, value) {
  return aleefApi('/api/aleef/findings/' + encodeURIComponent(id) + '/prior-knowledge', { method: 'POST', body: JSON.stringify({ value: value }) }).then(function(r) {
    if (r.status !== 200) { setStatus(apiErrorMessage(r.status, r.body), 'error'); return loadAleefFindings(); }
    setStatus('Prior-knowledge review recorded.', 'ok');
    return loadAleefFindings();
  }).catch(function(err) { setStatus(err.message || 'Request failed', 'error'); });
}

// ── delegated events (no inline handlers: CSP) ───────────────────────────────
document.addEventListener('click', function(e) {
  var t = e.target && e.target.closest ? e.target.closest('[data-aleef-action]') : null;
  if (!t) return;
  var a = t.getAttribute('data-aleef-action');
  if (a === 'create-engagement') submitEngagement();
  else if (a === 'start-run') startRun();
  else if (a === 'add-account') addAccountRow();
  else if (a === 'remove-account') { var row = t.closest('[data-aleef-account]'); if (row) row.parentNode.removeChild(row); }
  else if (a === 'stop') { confirmingStop = true; showRun(lastSummary); }
  else if (a === 'stop-cancel') { confirmingStop = false; showRun(lastSummary); }
  else if (a === 'stop-confirm') stopRun();
  else if (a === 'refresh-findings') loadAleefFindings();
  else if (a === 'download-regression') downloadRegression(t.getAttribute('data-finding'));
  else if (a === 'load-run') { var id = val('aleef-load-run').trim(); if (id) trackRun(id); }
});

document.addEventListener('change', function(e) {
  var t = e.target;
  if (!t || !t.getAttribute) return;
  var pk = t.getAttribute('data-aleef-pk');
  if (pk) { setPriorKnowledge(pk, t.value); return; }
  if (t.id === 'aleef-run-file') readOpenAPIFile(t.files && t.files[0]);
});

document.addEventListener('input', function(e) {
  if (e.target && e.target.id === 'aleef-run-openapi') refreshOpenAPI();
});
