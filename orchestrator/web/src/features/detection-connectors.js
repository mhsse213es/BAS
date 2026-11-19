import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { pill, empty } from '../core/kit.js';
import { setDisplay } from '../core/inline-style.js';
import * as M from './dc-model.js';

// ── Detection connectors ─────────────────────────────────────────────────────
// The card on the Detection Verification page where an administrator connects the SIEM / XDR that the server
// queries to check whether a simulated technique raised an alert. List, add, edit, test and delete; the server
// (/api/detectverify/configs) does the work and enforces who may. Secrets are never shown back: an edit form
// only learns that one is stored and keeps it unless a new value is typed.

var S = { list: [], perms: null, loaded: false, editing: null /* saved connector, or null when adding */ };

function el(id) { return document.getElementById(id); }

// dcShow is called by the page once it knows what the caller may do. Without the permission the card stays hidden.
export function dcShow(perms) {
  S.perms = perms;
  var card = el('dc-card');
  if (!card) return;
  if (!M.canManage(perms)) { setDisplay(card, 'none'); return; }
  setDisplay(card, '');
  dcLoad();
}

// True when at least one connector is enabled. Null when the list could not be read (caller cannot manage it).
export function dcEnabledCount() {
  if (!S.loaded) return null;
  return S.list.filter(function(c) { return c.enabled; }).length;
}

function dcLoad() {
  var box = el('dc-list');
  if (!box) return;
  apicall('/api/detectverify/configs').then(function(list) {
    S.list = Array.isArray(list) ? list : [];
    S.loaded = true;
    renderList();
  }).catch(function(e) {
    S.loaded = false;
    box.innerHTML = empty('alert', 'Could not load detection connectors', e.message);
  });
}

function renderList() {
  var box = el('dc-list');
  if (!box) return;
  if (!S.list.length) {
    box.innerHTML = empty('layers', 'No detection connector yet',
      'Add the SIEM or XDR your endpoints report to. Runs are then checked against it, instead of an analyst checking each one by hand.');
    return;
  }
  var rows = S.list.map(function(c) {
    var p = M.providerById(c.provider);
    var mode = M.modeLabel(c);
    var tone = !c.enabled ? 'muted' : c.autoVerify ? 'ok' : 'info';
    return '<tr>' +
      '<td><b>' + x(c.name) + '</b></td>' +
      '<td>' + x(p ? p.label : c.provider) + '</td>' +
      '<td class="muted">' + x(M.rowSummary(c)) + '</td>' +
      '<td>' + pill(mode, tone) + '</td>' +
      '<td class="dc-actions">' +
        '<button class="btn btn-sm btn-outline"' + on('click', 'dcTest', c.id) + '>Test</button> ' +
        '<button class="btn btn-sm btn-outline"' + on('click', 'dcEdit', c.id) + '>Edit</button> ' +
        '<button class="btn btn-sm btn-outline"' + on('click', 'dcDelete', c.id) + '>Delete</button>' +
      '</td></tr>';
  }).join('');
  box.innerHTML = '<div class="tbl-wrap"><table><thead><tr><th>Name</th><th>Provider</th><th>Target</th><th>Mode</th><th></th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table></div>';
}

// ── The form ─────────────────────────────────────────────────────────────────

function fieldHtml(key, existing, values) {
  var meta = M.FIELD_META[key];
  var id = 'dc-f-' + key;
  if (key === 'insecureTls') {
    return '<label class="dc-check"><input type="checkbox" id="' + id + '"' + (values[key] ? ' checked' : '') + '> ' + x(meta.label) +
      ' <span class="tiny muted">(only for an appliance with a self-signed certificate)</span></label>';
  }
  var stored = existing && ((key === 'clientSecret' && existing.hasClientSecret) || (key === 'apiToken' && existing.hasApiToken));
  var placeholder = meta.secret ? (stored ? 'Stored: leave blank to keep it' : '') : meta.placeholder;
  return '<div><div class="conn-cfg-label">' + x(meta.label) + '</div>' +
    '<input id="' + id + '" type="' + (meta.secret ? 'password' : 'text') + '" class="inp-sm u-w100" autocomplete="off"' +
    ' value="' + (meta.secret ? '' : x(values[key] || '')) + '" placeholder="' + x(placeholder) + '"></div>';
}

function renderForm(provider, values) {
  var host = el('dc-form');
  if (!host) return;
  var p = M.providerById(provider);
  var editing = S.editing;
  var opts = M.PROVIDERS.map(function(o) {
    return '<option value="' + x(o.id) + '"' + (o.id === provider ? ' selected' : '') + '>' + x(o.label) + '</option>';
  }).join('');
  var keys = M.fieldsFor(provider);
  var fields = keys.filter(function(k) { return k !== 'insecureTls'; }).map(function(k) { return fieldHtml(k, editing, values); }).join('');
  var tls = keys.indexOf('insecureTls') >= 0 ? fieldHtml('insecureTls', editing, values) : '';
  host.innerHTML = '<div class="conn-cfg-card">' +
    '<div class="dc-form-head"><b>' + (editing ? 'Edit connector' : 'Add connector') + '</b>' +
    '<button class="btn btn-outline btn-sm"' + on('click', 'dcCancel') + '>Cancel</button></div>' +
    '<div class="dc-grid">' +
      '<div><div class="conn-cfg-label">Provider</div><select id="dc-provider" class="inp-sm u-w100"' + (editing ? ' disabled' : '') + on('change', 'dcProviderChanged') + '>' + opts + '</select></div>' +
      '<div><div class="conn-cfg-label">Name</div><input id="dc-name" type="text" class="inp-sm u-w100" value="' + x(values.name || '') + '" placeholder="e.g. Prod Sentinel"></div>' +
    '</div>' +
    (p ? '<div class="tiny muted dc-hint">' + x(p.hint) + '</div>' : '') +
    '<div class="dc-grid">' + fields + '</div>' + tls +
    '<div class="dc-grid">' +
      '<div><div class="conn-cfg-label">Wait before checking <span class="tiny muted">(seconds)</span></div>' +
        '<input id="dc-delay" type="text" inputmode="numeric" class="inp-sm u-w100" value="' + x(values.verifyDelaySeconds === undefined ? '120' : String(values.verifyDelaySeconds)) + '"></div>' +
      '<div class="tiny muted dc-hint">SIEMs lag. Giving events a couple of minutes to arrive avoids false "not detected" results.</div>' +
    '</div>' +
    '<label class="dc-check"><input type="checkbox" id="dc-enabled"' + (values.enabled === false ? '' : ' checked') + '> Enabled</label>' +
    '<label class="dc-check"><input type="checkbox" id="dc-auto"' + (values.autoVerify ? ' checked' : '') + '> Check every finished run automatically</label>' +
    '<div class="dc-form-foot"><button class="btn btn-primary btn-sm"' + on('click', 'dcSave') + '>Save</button></div>' +
    '</div>';
  setDisplay(host, '');
}

// Reads what is typed. Secrets stay as typed (blank means "keep" when editing; the model decides).
function readValues(provider) {
  var v = {
    name: (el('dc-name') || {}).value,
    verifyDelaySeconds: (el('dc-delay') || {}).value,
    enabled: !!(el('dc-enabled') || {}).checked,
    autoVerify: !!(el('dc-auto') || {}).checked,
  };
  M.fieldsFor(provider).forEach(function(k) {
    var input = el('dc-f-' + k);
    v[k] = input ? (input.type === 'checkbox' ? input.checked : input.value) : '';
  });
  return v;
}

function currentProvider() {
  var sel = el('dc-provider');
  return sel ? sel.value : '';
}

export function dcAdd() {
  S.editing = null;
  renderForm('microsoft_sentinel', { enabled: true, verifyDelaySeconds: 120 });
  var host = el('dc-form');
  if (host && host.scrollIntoView) host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

export function dcEdit(id) {
  var c = S.list.filter(function(r) { return r.id === id; })[0];
  if (!c) return;
  S.editing = c;
  renderForm(c.provider, c);
  var host = el('dc-form');
  if (host && host.scrollIntoView) host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Changing the provider swaps the fields. What was typed in the name and common settings is kept.
export function dcProviderChanged() {
  var keep = { name: (el('dc-name') || {}).value, verifyDelaySeconds: (el('dc-delay') || {}).value,
    enabled: !!(el('dc-enabled') || {}).checked, autoVerify: !!(el('dc-auto') || {}).checked };
  renderForm(currentProvider(), keep);
}

export function dcCancel() {
  S.editing = null;
  var host = el('dc-form');
  if (host) { host.innerHTML = ''; setDisplay(host, 'none'); }
}

export function dcSave() {
  var editing = S.editing;
  var provider = editing ? editing.provider : currentProvider();
  var values = readValues(provider);
  var problem = M.validate(provider, values, editing);
  if (problem) { showToast(problem, 'err'); return; }
  var body = M.buildBody(provider, values, editing);
  var url = editing ? '/api/detectverify/configs/' + encodeURIComponent(editing.id) : '/api/detectverify/configs';
  apicall(url, { method: editing ? 'PUT' : 'POST', body: JSON.stringify(body) }).then(function() {
    showToast('Connector saved. Use Test to check the connection.', 'ok');
    dcCancel();
    dcLoad();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function dcTest(id) {
  showToast('Testing connection…', 'ok');
  apicall('/api/detectverify/configs/' + encodeURIComponent(id) + '/test', { method: 'POST' }).then(function(r) {
    showToast(r && r.ok ? 'Connection OK' : 'Connection failed: ' + ((r && r.error) || 'unknown error'), r && r.ok ? 'ok' : 'err');
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function dcDelete(id) {
  var c = S.list.filter(function(r) { return r.id === id; })[0];
  if (!c) return;
  if (!confirm('Delete the connector "' + c.name + '"? Runs will no longer be checked against it.')) return;
  apicall('/api/detectverify/configs/' + encodeURIComponent(id), { method: 'DELETE' }).then(function() {
    showToast('Connector deleted', 'ok');
    dcLoad();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
