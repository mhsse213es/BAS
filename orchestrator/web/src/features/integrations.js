import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { _diffRow, _diffSecretRow, openConfirmDiffModal } from './compliance.js';
import { _ticketingConfigs, loadTicketingConfigs } from './findings.js';
import { displayOf, setDisplay } from '../core/inline-style.js';
import { setEppConnectors, setItsmConnectors } from './integrations-insights.js';
import { setIntItsm, setIntEpp, loadIntTaxii } from './int-view.js';


// ── Integrations tab ────────────────────────────────────────────────────────
export function loadIntegrations() {
  loadIntTaxii();
  loadTicketingConfigs(function(list) {
    renderConnectorList(list);
  });
  apicall('/api/ticketing/revalidation').then(function(r) {
    var cnt = r.pendingRevalidation || 0;
    var wrap = document.getElementById('integrations-reval');
    if (!wrap) return;
    if (cnt > 0) {
      setDisplay(wrap, '');
      var el = document.getElementById('integrations-reval-count');
      if (el) el.textContent = cnt;
    } else {
      setDisplay(wrap, 'none');
    }
  }).catch(function() {});
}

var PROVIDER_LABELS = { servicenow: 'ServiceNow', jira: 'Jira', webhook: 'Webhook' };

function renderConnectorList(list) {
  setItsmConnectors(list || []);
  setIntItsm(list || []);
}

var TICKET_CONNECTOR_LOADED = null; // the record being edited (null for Add), for the save confirmation diff

export function openAddConnector() {
  TICKET_CONNECTOR_LOADED = null;
  document.getElementById('cf-id').value = '';
  document.getElementById('cf-name').value = '';
  document.getElementById('cf-provider').value = 'servicenow';
  document.getElementById('cf-auto-create').value = 'off';
  document.getElementById('cf-auto-update').checked = true;
  document.getElementById('cf-auto-close').checked = true;
  document.getElementById('cf-enabled').checked = true;
  document.getElementById('connector-form-title').textContent = 'Add Connector';
  setDisplay(document.getElementById('cf-test-result'), 'none');
  renderConnectorSettings();
  setDisplay(document.getElementById('connector-form-wrap'), '');
  document.getElementById('connector-form-wrap').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// "+ ServiceNow" / "+ Jira" / "+ Webhook" in the ITSM box: the same Add form with the provider chosen.
export function openAddConnectorFor(provider) {
  openAddConnector();
  var sel = document.getElementById('cf-provider');
  if (sel) { sel.value = provider; renderConnectorSettings(); }
}

export function openEditConnector(id) {
  var c = (_ticketingConfigs || []).find(function(cfg) { return cfg.id === id; });
  if (!c) return;
  TICKET_CONNECTOR_LOADED = c;
  document.getElementById('cf-id').value = c.id;
  document.getElementById('cf-name').value = c.name || '';
  document.getElementById('cf-provider').value = c.provider || 'servicenow';
  document.getElementById('cf-auto-create').value = c.autoCreate || 'off';
  document.getElementById('cf-auto-update').checked = !!c.autoUpdate;
  document.getElementById('cf-auto-close').checked = !!c.autoClose;
  document.getElementById('cf-enabled').checked = !!c.enabled;
  document.getElementById('connector-form-title').textContent = 'Edit Connector';
  setDisplay(document.getElementById('cf-test-result'), 'none');
  renderConnectorSettings(c.settings || {});
  setDisplay(document.getElementById('connector-form-wrap'), '');
  document.getElementById('connector-form-wrap').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

export function closeConnectorForm() {
  setDisplay(document.getElementById('connector-form-wrap'), 'none');
}

var CONNECTOR_FIELDS = {
  servicenow: [
    { key: 'instance_url',    label: 'Instance URL',                  placeholder: 'https://instance.service-now.com',         type: 'text' },
    { key: 'username',        label: 'Username',                      placeholder: 'admin',                                    type: 'text' },
    { key: 'password',        label: 'Password',                      placeholder: '••••••',                                   type: 'password' },
    { key: 'category',        label: 'Category (optional)',           placeholder: 'security',                                 type: 'text' },
    { key: 'assignment_group',label: 'Assignment Group (optional)',   placeholder: 'SOC',                                      type: 'text' },
    { key: 'insecure_tls',    label: 'Skip TLS verification',         placeholder: '',                                         type: 'checkbox',
      hint: 'Enable only for self-signed or internal CA certificates' }
  ],
  jira: [
    { key: 'base_url',        label: 'Base URL',                      placeholder: 'https://jira.company.com',                 type: 'text' },
    { key: 'username',        label: 'Username / Email',              placeholder: 'user@company.com',                         type: 'text' },
    { key: 'api_token',       label: 'API Token (or password for Jira Server)', placeholder: '••••••',                         type: 'password' },
    { key: 'project_key',     label: 'Project Key',                   placeholder: 'SEC',                                      type: 'project_picker' },
    { key: 'insecure_tls',    label: 'Skip TLS verification',         placeholder: '',                                         type: 'checkbox',
      hint: 'Enable only for self-signed or internal CA certificates' }
  ],
  webhook: [
    { key: 'url',             label: 'Endpoint URL',                  placeholder: 'https://hooks.example.com/bas',            type: 'text' },
    { key: 'secret',          label: 'HMAC Secret (optional)',        placeholder: 'Signs the X-BAS-Signature header',         type: 'password' },
    { key: 'insecure_tls',    label: 'Skip TLS verification',         placeholder: '',                                         type: 'checkbox',
      hint: 'Enable only for self-signed or internal CA certificates' }
  ]
};

export function renderConnectorSettings(saved) {
  var prov = document.getElementById('cf-provider').value;
  var fields = CONNECTOR_FIELDS[prov] || [];
  var s = saved || {};
  document.getElementById('cf-settings').innerHTML = fields.map(function(f) {
    if (f.type === 'checkbox') {
      return '<div class="g1-s-dd11a3a0">' +
        '<label class="g1-display-flex g1-s-b0ace2ed">' +
          '<input type="checkbox" id="cfs-' + f.key + '"' + (s[f.key] === 'yes' ? ' checked' : '') + '>' +
          '<span class="conn-cfg-label g1-s-ab79ea2b">' + f.label + '</span>' +
        '</label>' +
        (f.hint ? '<div class="g1-s-239398d5">' + f.hint + '</div>' : '') +
        '</div>';
    }
    if (f.type === 'project_picker') {
      return '<div class="g1-s-dd11a3a0">' +
        '<div class="conn-cfg-label g1-s-e02b1221">' + f.label + '</div>' +
        '<div class="g1-display-flex g1-s-35646f83">' +
          '<select id="cfs-' + f.key + '-sel" class="inp-sm is-hidden g1-s-83725d2c"' + on('change', 'connectorProjectSelectChange', f.key) + '></select>' +
          '<input type="text" id="cfs-' + f.key + '" placeholder="' + f.placeholder + '" value="' + x(s[f.key] || '') + '" class="inp-sm u-flex1">' +
          '<button type="button" class="btn btn-outline btn-sm g1-s-975e501c"' + on('click', 'fetchConnectorProjects') + '>↓ Fetch</button>' +
        '</div>' +
        '<div id="cfs-' + f.key + '-hint" class="g1-s-68ab4b84"></div>' +
        '</div>';
    }
    return '<div class="g1-s-dd11a3a0">' +
      '<div class="conn-cfg-label g1-s-e02b1221">' + f.label + '</div>' +
      '<input type="' + f.type + '" id="cfs-' + f.key + '" placeholder="' + f.placeholder + '" value="' + x(s[f.key] || '') + '" class="inp-sm u-w100">' +
      '</div>';
  }).join('');
}

export function connectorProjectSelectChange(key, el) {
  document.getElementById('cfs-' + key).value = el.value;
}

export function fetchConnectorProjects() {
  var prov = document.getElementById('cf-provider').value;
  var fields = CONNECTOR_FIELDS[prov] || [];
  var settings = {};
  fields.forEach(function(f) {
    if (f.type === 'project_picker') return;
    var v = _connectorFieldValue(f);
    if (v && v !== '***') settings[f.key] = v;
  });
  var hint = document.getElementById('cfs-project_key-hint');
  if (hint) { hint.textContent = 'Fetching projects…'; hint.style.color = 'var(--muted)'; }
  apicall('/api/ticketing/probe/projects', { method: 'POST', body: JSON.stringify({ provider: prov, settings: settings }) })
    .then(function(r) {
      if (!r.ok) {
        if (hint) { hint.textContent = r.error || 'Failed'; hint.style.color = 'var(--danger)'; }
        return;
      }
      var projects = r.projects || [];
      var sel = document.getElementById('cfs-project_key-sel');
      var inp = document.getElementById('cfs-project_key');
      if (!sel || !inp) return;
      if (!projects.length) {
        if (hint) { hint.textContent = 'No projects found'; hint.style.color = 'var(--warning)'; }
        return;
      }
      sel.innerHTML = projects.map(function(p) {
        return '<option value="' + x(p.key) + '"' + (inp.value === p.key ? ' selected' : '') + '>' + x(p.key) + ' — ' + x(p.name) + '</option>';
      }).join('');
      setDisplay(sel, 'block');
      setDisplay(inp, 'none');
      if (!inp.value && projects.length) { sel.value = projects[0].key; }
      if (hint) { hint.textContent = projects.length + ' project(s) found'; hint.style.color = 'var(--success)'; }
    })
    .catch(function(e) { if (hint) { hint.textContent = e.message; hint.style.color = 'var(--danger)'; } });
}

function _connectorFieldValue(f) {
  if (f.type === 'project_picker') {
    var sel = document.getElementById('cfs-' + f.key + '-sel');
    if (sel && displayOf(sel) !== 'none') return sel.value || '';
    var inp = document.getElementById('cfs-' + f.key);
    return inp ? (inp.value || '') : '';
  }
  var el = document.getElementById('cfs-' + f.key);
  if (!el) return '';
  return f.type === 'checkbox' ? (el.checked ? 'yes' : '') : (el.value || '');
}

export function saveConnectorForm() {
  var id = document.getElementById('cf-id').value;
  var prov = document.getElementById('cf-provider').value;
  var fields = CONNECTOR_FIELDS[prov] || [];
  var settings = {};
  fields.forEach(function(f) {
    var v = _connectorFieldValue(f);
    if (v) settings[f.key] = v;
  });
  var body = {
    name:       document.getElementById('cf-name').value,
    provider:   prov,
    enabled:    document.getElementById('cf-enabled').checked,
    autoCreate: document.getElementById('cf-auto-create').value,
    autoUpdate: document.getElementById('cf-auto-update').checked,
    autoClose:  document.getElementById('cf-auto-close').checked,
    settings:   settings
  };
  var url = id ? '/api/ticketing/configs/' + encodeURIComponent(id) : '/api/ticketing/configs';
  var method = id ? 'PUT' : 'POST';

  // Only an edit of an existing connector has a prior saved value that could be
  // silently overwritten — a brand-new connector (id empty, TICKET_CONNECTOR_LOADED
  // null) has nothing to diff against, so it always saves directly.
  if (!id || !TICKET_CONNECTOR_LOADED) {
    doSaveConnectorForm(url, method, body);
    return;
  }

  var prev = TICKET_CONNECTOR_LOADED;
  var rows = '';
  if (body.name !== (prev.name || '')) rows += _diffRow('Name', prev.name, body.name);
  if (prov !== (prev.provider || '')) {
    rows += _diffRow('Provider', PROVIDER_LABELS[prev.provider] || prev.provider, PROVIDER_LABELS[prov] || prov);
    rows += '<div class="tiny muted g1-s-0990a875">Changing provider reconfigures every connection field below.</div>';
  } else {
    var prevSettings = prev.settings || {};
    fields.forEach(function(f) {
      var newVal = settings[f.key] || '';
      var oldVal = prevSettings[f.key] || '';
      if (f.type === 'password') {
        if (newVal !== '***') rows += _diffSecretRow(f.label, true);
      } else if (f.type === 'checkbox') {
        if (newVal !== oldVal) rows += _diffRow(f.label, oldVal === 'yes' ? 'Yes' : 'No', newVal === 'yes' ? 'Yes' : 'No');
      } else if (newVal !== oldVal) {
        rows += _diffRow(f.label, oldVal, newVal);
      }
    });
  }
  if (body.enabled !== !!prev.enabled) rows += _diffRow('Enabled', prev.enabled ? 'Yes' : 'No', body.enabled ? 'Yes' : 'No');
  if (body.autoCreate !== (prev.autoCreate || 'off')) rows += _diffRow('Auto-create', prev.autoCreate || 'off', body.autoCreate);
  if (body.autoUpdate !== !!prev.autoUpdate) rows += _diffRow('Auto-update', prev.autoUpdate ? 'Yes' : 'No', body.autoUpdate ? 'Yes' : 'No');
  if (body.autoClose !== !!prev.autoClose) rows += _diffRow('Auto-close', prev.autoClose ? 'Yes' : 'No', body.autoClose ? 'Yes' : 'No');

  if (!rows) {
    doSaveConnectorForm(url, method, body); // nothing to confirm
    return;
  }

  openConfirmDiffModal('Confirm Connector Config Change', rows, function() {
    doSaveConnectorForm(url, method, body);
  });
}

function doSaveConnectorForm(url, method, body) {
  apicall(url, { method: method, body: JSON.stringify(body) })
    .then(function() {
      showToast('Connector saved', 'ok');
      closeConnectorForm();
      loadIntegrations();
    }).catch(function(e) { showToast(e.message, 'err'); });
}

export function testConnectorById(id, btn) {
  var orig = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = 'Testing…'; }
  apicall('/api/ticketing/configs/' + encodeURIComponent(id) + '/test', { method: 'POST' })
    .then(function(r) {
      showToast(r.ok ? 'Connection OK' : 'Failed: ' + (r.error || 'unknown'), r.ok ? 'ok' : 'err');
      loadIntegrations(); // refresh status badge to reflect test result
    }).catch(function(e) {
      showToast(e.message, 'err');
      loadIntegrations();
    })
    .finally(function() { if (btn) { btn.disabled = false; btn.textContent = orig; } });
}

export function testConnectorForm() {
  var prov = document.getElementById('cf-provider').value;
  var fields = CONNECTOR_FIELDS[prov] || [];
  var settings = {};
  fields.forEach(function(f) {
    var v = _connectorFieldValue(f);
    if (v) settings[f.key] = v;
  });
  var res = document.getElementById('cf-test-result');
  setDisplay(res, ''); res.style.color = 'var(--muted)'; res.textContent = 'Testing…';
  apicall('/api/ticketing/probe', { method: 'POST', body: JSON.stringify({ provider: prov, settings: settings }) })
    .then(function(r) {
      res.style.color = r.ok ? 'var(--success)' : 'var(--danger)';
      var msg = r.ok ? 'Connection successful.' : 'Failed: ' + (r.error || 'check credentials');
      res.textContent = msg.length > 220 ? msg.slice(0, 220) + '…' : msg;
    }).catch(function(e) { res.style.color = 'var(--danger)'; res.textContent = e.message; });
}

export function deleteConnector(id, name) {
  if (!confirm('Delete connector "' + name + '"? This cannot be undone.')) return;
  apicall('/api/ticketing/configs/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function() { showToast('Connector deleted', 'ok'); loadIntegrations(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// ── EPP Response Connectors ─────────────────────────────────────────────────
// Deliberately separate from the ticketing connector functions above: this
// API's request body is flat (no nested "settings" object) and there are
// only two fixed providers, so this doesn't reuse CONNECTOR_FIELDS/
// renderConnectorSettings — that machinery is ticketing-specific (auto-create
// policy, project pickers) and would be a worse fit than a small dedicated form.
var _responseConnectors = null;

export function loadResponseConnectors(cb) {
  apicall('/api/actions/configs').then(function(list) {
    _responseConnectors = list || [];
    if (cb) cb(_responseConnectors);
  }).catch(function() { _responseConnectors = []; if (cb) cb([]); });
}

export function renderResponseConnectorList(list) {
  setEppConnectors(list || []);
  setIntEpp(list || []);
}

export function renderResponseConnectorFields() {
  var prov = document.getElementById('rc-provider').value;
  setDisplay(document.getElementById('rc-crowdstrike-fields'), (prov === 'crowdstrike') ? '' : 'none');
  setDisplay(document.getElementById('rc-defender-fields'), (prov === 'microsoft_defender') ? '' : 'none');
  setDisplay(document.getElementById('rc-sentinelone-fields'), (prov === 'sentinelone') ? '' : 'none');
  // SentinelOne authenticates with a single static API token -- it has no
  // OAuth client_id/client_secret pair, so the generic fields are irrelevant.
  setDisplay(document.getElementById('rc-oauth-fields'), (prov === 'sentinelone') ? 'none' : '');
}

export function openAddResponseConnector() {
  document.getElementById('rc-id').value = '';
  document.getElementById('rc-name').value = '';
  document.getElementById('rc-provider').value = 'crowdstrike';
  document.getElementById('rc-base-url').value = '';
  document.getElementById('rc-tenant-id').value = '';
  document.getElementById('rc-kill-script').value = '';
  document.getElementById('rc-client-id').value = '';
  document.getElementById('rc-client-secret').value = '';
  document.getElementById('rc-s1-base-url').value = '';
  document.getElementById('rc-s1-api-token').value = '';
  document.getElementById('rc-enabled').checked = true;
  document.getElementById('response-connector-form-title').textContent = 'Add Connector';
  renderResponseConnectorFields();
  setDisplay(document.getElementById('response-connector-form-wrap'), '');
  document.getElementById('response-connector-form-wrap').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// "+ CrowdStrike" / "+ Defender" / "+ SentinelOne" in the EPP box.
export function openAddResponseConnectorFor(provider) {
  openAddResponseConnector();
  var sel = document.getElementById('rc-provider');
  if (sel) { sel.value = provider; renderResponseConnectorFields(); }
}

// "Sync Now" on the EPP box: re-read the connector list from the server.
export function refreshResponseConnectors() {
  loadResponseConnectors(function(list) { renderResponseConnectorList(list); showToast('Connector state refreshed', 'ok'); });
}

export function openEditResponseConnector(id) {
  var c = (_responseConnectors || []).find(function(cfg) { return cfg.id === id; });
  if (!c) return;
  document.getElementById('rc-id').value = c.id;
  document.getElementById('rc-name').value = c.name || '';
  document.getElementById('rc-provider').value = c.provider || 'crowdstrike';
  document.getElementById('rc-base-url').value = c.baseUrl || '';
  document.getElementById('rc-tenant-id').value = c.tenantId || '';
  document.getElementById('rc-kill-script').value = c.killProcessScriptName || '';
  document.getElementById('rc-client-id').value = c.clientId || '';
  document.getElementById('rc-client-secret').value = '***';
  document.getElementById('rc-s1-base-url').value = c.baseUrl || '';
  document.getElementById('rc-s1-api-token').value = '***';
  document.getElementById('rc-enabled').checked = !!c.enabled;
  document.getElementById('response-connector-form-title').textContent = 'Edit Connector';
  renderResponseConnectorFields();
  setDisplay(document.getElementById('response-connector-form-wrap'), '');
  document.getElementById('response-connector-form-wrap').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

export function closeResponseConnectorForm() {
  setDisplay(document.getElementById('response-connector-form-wrap'), 'none');
}

export function saveResponseConnectorForm() {
  var id = document.getElementById('rc-id').value;
  var provider = document.getElementById('rc-provider').value;
  var baseUrl = (provider === 'sentinelone')
    ? document.getElementById('rc-s1-base-url').value
    : document.getElementById('rc-base-url').value;
  var body = {
    name:                  document.getElementById('rc-name').value,
    provider:              provider,
    enabled:               document.getElementById('rc-enabled').checked,
    baseUrl:               baseUrl,
    tenantId:              document.getElementById('rc-tenant-id').value,
    killProcessScriptName: document.getElementById('rc-kill-script').value,
    clientId:              document.getElementById('rc-client-id').value,
    clientSecret:          document.getElementById('rc-client-secret').value,
    apiToken:              document.getElementById('rc-s1-api-token').value
  };
  if (!body.name || !body.provider) { showToast('Name and provider are required', 'err'); return; }
  var url = id ? '/api/actions/configs/' + encodeURIComponent(id) : '/api/actions/configs';
  var method = id ? 'PUT' : 'POST';
  apicall(url, { method: method, body: JSON.stringify(body) })
    .then(function() {
      showToast('Connector saved', 'ok');
      closeResponseConnectorForm();
      loadResponseConnectors(renderResponseConnectorList);
    }).catch(function(e) { showToast(e.message, 'err'); });
}

export function testResponseConnectorById(id, btn) {
  var orig = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = 'Testing…'; }
  apicall('/api/actions/configs/' + encodeURIComponent(id) + '/test', { method: 'POST' })
    .then(function(r) {
      showToast(r.ok ? 'Connection OK' : 'Failed: ' + (r.error || 'unknown'), r.ok ? 'ok' : 'err');
    }).catch(function(e) { showToast(e.message, 'err'); })
    .finally(function() { if (btn) { btn.disabled = false; btn.textContent = orig; } });
}

export function deleteResponseConnector(id, name) {
  if (!confirm('Delete connector "' + name + '"? This cannot be undone.')) return;
  apicall('/api/actions/configs/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function() { showToast('Connector deleted', 'ok'); loadResponseConnectors(renderResponseConnectorList); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// ── Respond (EPP response actions from the Findings drawer) ────────────────

var RESPOND_ACTION_LABELS = {
  'endpoint.isolate': 'Isolate host', 'endpoint.release': 'Release from isolation',
  'endpoint.kill_process': 'Kill process', 'endpoint.quarantine_file': 'Quarantine file'
};

function _respondTargetHostname() {
  if (!state._currentFinding) return '';
  var agent = (state.agents || []).find(function(a) { return a.agentId === state._currentFinding.agentId; });
  return agent ? (agent.hostname || agent.agentId) : state._currentFinding.agentId;
}

export function openRespondModal() {
  if (!state._currentFinding) return;
  var hostname = _respondTargetHostname();
  document.getElementById('respond-target-sub').textContent = 'Target: ' + hostname;
  document.getElementById('respond-action').value = 'endpoint.isolate';
  document.getElementById('respond-reason').value = '';
  document.getElementById('respond-ticket').value = '';
  document.getElementById('respond-extra-value').value = '';

  loadResponseConnectors(function(list) {
    var enabled = (list || []).filter(function(c) { return c.enabled; });
    var sel = document.getElementById('respond-connector');
    if (!enabled.length) {
      sel.innerHTML = '<option value="">No enabled connector configured</option>';
    } else {
      sel.innerHTML = enabled.map(function(c) {
        return '<option value="' + x(c.id) + '" data-provider="' + x(c.provider) + '">' + x(c.name) + '</option>';
      }).join('');
    }
    renderRespondFields();
  });

  document.getElementById('respond-overlay').classList.add('open');
}

export function closeRespondModal() {
  document.getElementById('respond-overlay').classList.remove('open');
}

export function renderRespondFields() {
  var action = document.getElementById('respond-action').value;
  var connSel = document.getElementById('respond-connector');
  var provider = (connSel.options[connSel.selectedIndex] || {}).getAttribute
    ? connSel.options[connSel.selectedIndex].getAttribute('data-provider') : '';
  var wrap = document.getElementById('respond-extra-field');
  var label = document.getElementById('respond-extra-label');
  var input = document.getElementById('respond-extra-value');
  var warning = document.getElementById('respond-extra-warning');
  setDisplay(warning, 'none');
  warning.textContent = '';

  if (action === 'endpoint.kill_process') {
    setDisplay(wrap, '');
    label.textContent = 'Process ID (PID)';
    input.placeholder = 'e.g. 4821';
    if (provider === 'sentinelone') {
      warning.textContent = '⚠ Not supported for SentinelOne — its mitigation API operates on an already-identified threat ID, not an arbitrary live process ID. This will fail.';
      setDisplay(warning, '');
    }
  } else if (action === 'endpoint.quarantine_file') {
    setDisplay(wrap, '');
    if (provider === 'microsoft_defender') {
      label.textContent = 'File SHA1 hash';
      input.placeholder = 'e.g. aabbccddeeff00112233445566778899aabbccdd';
    } else if (provider === 'sentinelone') {
      label.textContent = 'SentinelOne Threat ID';
      input.placeholder = 'e.g. 1234567890123456789';
      warning.textContent = 'SentinelOne mitigates an already-identified threat by its own ID, not a file path or hash.';
      setDisplay(warning, '');
    } else {
      label.textContent = 'File path';
      input.placeholder = 'e.g. C:\\Users\\victim\\evil.exe';
    }
  } else {
    setDisplay(wrap, 'none');
  }
}

export function submitRespondAction() {
  if (!state._currentFinding) return;
  var action = document.getElementById('respond-action').value;
  var connectorId = document.getElementById('respond-connector').value;
  var reason = document.getElementById('respond-reason').value.trim();
  var ticketRef = document.getElementById('respond-ticket').value.trim();
  var hostname = _respondTargetHostname();

  if (!connectorId) { showToast('Select a connector', 'err'); return; }
  if (!reason) { showToast('Reason is required', 'err'); return; }

  var parameters = {};
  if (action === 'endpoint.kill_process') {
    var pid = parseInt(document.getElementById('respond-extra-value').value, 10);
    if (!pid || pid <= 0) { showToast('Enter a valid process ID', 'err'); return; }
    parameters.pid = pid;
  } else if (action === 'endpoint.quarantine_file') {
    var target = document.getElementById('respond-extra-value').value.trim();
    if (!target) { showToast('Enter the quarantine target', 'err'); return; }
    parameters.quarantineTarget = target;
  }

  var label = RESPOND_ACTION_LABELS[action] || action;
  if (!confirm(label + '\n\nHost: ' + hostname + '\nReason: ' + reason + '\n\nProceed?')) return;

  var btn = document.getElementById('respond-submit-btn');
  btn.disabled = true;
  apicall('/api/actions/run', {
    method: 'POST',
    body: JSON.stringify({
      type: action, hostname: hostname, parameters: parameters, connectorId: connectorId,
      reason: reason, ticketRef: ticketRef
    })
  }).then(function(res) {
    btn.disabled = false;
    if (res && res.status === 'completed') {
      showToast('Dispatched — ' + label, 'ok');
      closeRespondModal();
    } else {
      showToast('Failed: ' + (res && res.error ? res.error : 'unknown error'), 'err');
    }
  }).catch(function(e) { btn.disabled = false; showToast(e.message, 'err'); });
}

// _openAgentActionModal is the shared shape behind Stop/Uninstall/Remove
// Agent's open functions below: set the target-hostname subtitle, clear
// the reason field, show the overlay. idPrefix matches each modal's own
// element-id convention ('stop-agent', 'uninstall-agent', 'remove-agent').
export function _openAgentActionModal(hostname, idPrefix) {
  document.getElementById(idPrefix + '-target-sub').textContent = 'Target: ' + hostname;
  document.getElementById(idPrefix + '-reason').value = '';
  document.getElementById(idPrefix + '-overlay').classList.add('open');
}