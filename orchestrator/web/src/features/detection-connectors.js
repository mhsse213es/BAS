import { apicallOk } from '../core/api.js';
import { openConfirmDiffModal } from './compliance.js';
import { fmtDate } from '../core/util.js';
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

var S = { list: [], perms: null, loaded: false, editing: null /* saved connector, or null when adding */, open: false, tests: {} /* id -> { ok, text, at } from this session's Test clicks */, busy: {} };

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

export function dcReload() { dcLoad(); }

function dcLoad() {
  var box = el('dc-list');
  if (!box) return;
  apicallOk('/api/detectverify/configs').then(function(list) {
    S.list = Array.isArray(list) ? list : [];
    S.loaded = true;
    // First load: open the card only when there is nothing yet, so the next step is obvious. Otherwise it stays folded.
    if (!S.seen) { S.seen = true; S.open = !S.list.length; }
    paintFrame();
    renderList();
  }).catch(function(e) {
    S.loaded = false;
    S.open = true;
    paintFrame();
    box.innerHTML = empty('alert', 'Could not load detection connectors', e.message || 'unknown error') +
      '<div class="dc-retry"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'dcReload') + '>Try again</button></div>';
  });
}

// The fold: header summary ("1 of 2 enabled") and the Show / Hide button.
function paintFrame() {
  var body = el('dc-body'), sum = el('dc-sum'), tg = el('dc-toggle');
  if (body) setDisplay(body, S.open ? '' : 'none');
  if (tg) { tg.textContent = S.open ? 'Hide' : 'Manage'; tg.setAttribute('aria-expanded', S.open ? 'true' : 'false'); }
  if (sum) {
    var n = S.list.length, on_ = S.list.filter(function(c) { return c.enabled; }).length;
    sum.textContent = !S.loaded ? '' : !n ? 'None yet' : on_ + ' of ' + n + ' enabled';
  }
}
export function dcToggle() { S.open = !S.open; paintFrame(); }
// Called when something needs a connector (Verify now with none enabled): open the card and bring it into view.
export function dcReveal() {
  S.open = true; paintFrame();
  var c = el('dc-card');
  if (c && c.scrollIntoView) c.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function testCell(c) {
  var t = S.tests[c.id];
  if (!t) return '<span class="tiny muted">Not tested this session</span>';
  return '<span class="tiny ' + (t.ok ? 'dc-ok' : 'dc-bad') + '" title="' + x(t.text) + '">' + (t.ok ? 'Connected' : 'Failed: ' + x(t.text.slice(0, 70))) + ' · ' + x(t.at) + '</span>';
}

function renderList() {
  var box = el('dc-list');
  if (!box) return;
  if (!S.list.length) {
    box.innerHTML = empty('layers', 'No detection connector yet',
      'Without one, an analyst has to attest every item by hand.');
    return;
  }
  var rows = S.list.map(function(c) {
    var p = M.providerById(c.provider);
    var mode = M.modeLabel(c);
    var tone = !c.enabled ? 'muted' : c.autoVerify ? 'ok' : 'info';
    var busy = !!S.busy[c.id];
    return '<tr>' +
      '<td><b>' + x(c.name) + '</b></td>' +
      '<td>' + x(p ? p.label : c.provider) + '</td>' +
      '<td class="muted dc-target">' + x(M.rowSummary(c)) + '</td>' +
      '<td>' + pill(mode, tone) + '</td>' +
      '<td>' + testCell(c) + '</td>' +
      '<td class="dc-actions">' +
        '<button type="button" class="btn btn-sm btn-outline"' + on('click', 'dcTest', c.id) + (busy ? ' disabled' : '') + '>' + (busy ? 'Testing…' : 'Test') + '</button> ' +
        '<button type="button" class="btn btn-sm btn-outline"' + on('click', 'dcEdit', c.id) + '>Edit</button> ' +
        '<button type="button" class="btn btn-sm btn-outline-red"' + on('click', 'dcDelete', c.id) + '>Delete</button>' +
      '</td></tr>';
  }).join('');
  box.innerHTML = '<div class="tbl-wrap"><table><thead><tr><th>Name</th><th>Provider</th><th>Target</th><th>Mode</th><th>Last test</th><th></th></tr></thead>' +
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
    '<input id="' + id + '" type="' + (meta.secret ? 'password' : 'text') + '" class="inp-sm u-w100" autocomplete="' + (meta.secret ? 'new-password' : 'off') + '"' +
    ' value="' + (meta.secret ? '' : x(values[key] || '')) + '" placeholder="' + x(placeholder) + '"' + (meta.secret ? ' data-lpignore="true"' : '') + '></div>';
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
    '</div>' +
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
    '<div class="dc-err is-hidden" id="dc-err" role="alert"></div>' +
    '<div class="dc-form-foot"><button type="button" id="dc-save" class="btn btn-primary btn-sm"' + on('click', 'dcSave') + '>' + (editing ? 'Save changes' : 'Save connector') + '</button><button type="button" class="btn btn-outline btn-sm"' + on('click', 'dcCancel') + '>Cancel</button></div>' +
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

function dcFormError(msg) {
  var e = el('dc-err');
  if (!e) { showToast(msg, 'err'); return; }
  e.textContent = msg; e.classList.remove('is-hidden');
}

export function dcSave() {
  var editing = S.editing;
  var provider = editing ? editing.provider : currentProvider();
  var values = readValues(provider);
  var problem = M.validate(provider, values, editing);
  if (problem) { dcFormError(problem); return; }
  var e0 = el('dc-err'); if (e0) e0.classList.add('is-hidden');
  var body = M.buildBody(provider, values, editing);
  var url = editing ? '/api/detectverify/configs/' + encodeURIComponent(editing.id) : '/api/detectverify/configs';
  var btn = el('dc-save'); if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  apicallOk(url, { method: editing ? 'PUT' : 'POST', body: JSON.stringify(body) }).then(function() {
    showToast((editing ? 'Connector updated' : 'Connector added') + '. Use Test to check the connection.', 'ok');
    S.open = true;
    dcCancel();
    dcLoad();
  }).catch(function(e) {
    if (btn) { btn.disabled = false; btn.textContent = editing ? 'Save changes' : 'Save connector'; }
    dcFormError('Could not save: ' + (e.message || 'error'));
  });
}

function now() { return fmtDate(new Date().toISOString()); }

export function dcTest(id) {
  if (S.busy[id]) return;
  S.busy[id] = true; renderList();
  apicallOk('/api/detectverify/configs/' + encodeURIComponent(id) + '/test', { method: 'POST' }).then(function(r) {
    var ok = !!(r && r.ok);
    S.tests[id] = { ok: ok, text: ok ? 'Connection OK' : ((r && r.error) || 'unknown error'), at: now() };
    showToast(ok ? 'Connection OK' : 'Connection failed: ' + S.tests[id].text, ok ? 'ok' : 'err');
  }).catch(function(e) {
    S.tests[id] = { ok: false, text: e.message || 'error', at: now() };
    showToast('Connection test failed: ' + (e.message || 'error'), 'err');
  }).then(function() { delete S.busy[id]; renderList(); });
}

export function dcDelete(id) {
  var c = S.list.filter(function(r) { return r.id === id; })[0];
  if (!c) return;
  openConfirmDiffModal('Delete the connector "' + c.name + '"?',
    '<p class="tiny">Runs will no longer be checked against it. Verifications it already recorded are kept.' + (c.autoVerify && c.enabled ? ' It is set to check every finished run automatically.' : '') + '</p>',
    function() {
      apicallOk('/api/detectverify/configs/' + encodeURIComponent(id), { method: 'DELETE' }).then(function() {
        showToast('Connector deleted', 'ok');
        delete S.tests[id];
        dcLoad();
      }).catch(function(e) { showToast('Could not delete: ' + (e.message || 'error'), 'err'); });
    }, { sub: 'This removes the connector and its stored credentials.', confirmLabel: 'Delete connector', danger: true });
}
