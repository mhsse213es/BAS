import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { ago, showToast } from '../core/util.js';
import { loadScenarios } from './attack-path.js';
import { _diffRow, _diffSecretRow, _renderConnectorCard, openConfirmDiffModal } from './compliance.js';
import { ROLE } from './shell.js';
import { setDisplay } from '../core/inline-style.js';


// ── Threat Intel connector config (MISP/OpenCTI/OTX) — editable, matching
// loadOpenAEVConfig's pattern. 'otx' has no URL field (single hosted
// service, unlike self-hosted MISP/OpenCTI).
var TI_CONNECTOR_LABELS = { misp: 'MISP', opencti: 'OpenCTI', otx: 'OTX' };
var TI_CONNECTOR_LOADED = {}; // name -> {baseUrl, enabled} as last fetched from the server, for the save confirmation diff

export function loadThreatIntelConfig(name) {
  var panel = document.getElementById('ti-' + name + '-config-panel');
  if (!panel || ROLE !== 'admin') { if (panel) panel.innerHTML = ''; return; }
  apicall('/api/threat-intel/' + name + '/config').then(function(cfg) {
    TI_CONNECTOR_LOADED[name] = { baseUrl: cfg.baseUrl || '', enabled: !!cfg.enabled, insecureTls: !!cfg.insecureTls, configured: !!cfg.configured };
    var urlField = name === 'otx' ? '' :
      '<input id="ti-' + name + '-url" type="text" placeholder="Base URL" value="' + x(cfg.baseUrl || '') + '" class="inp-sm u-flex1">';
    // MISP is the only curated source whose client honours this -- OTX is a
    // hosted service with a valid cert, and the OpenCTI client always verifies.
    var insecureField = name !== 'misp' ? '' :
      '<label class="tiny muted" style="display:flex;align-items:center;gap:0.3rem" title="Only enable for an air-gapped MISP presenting a self-signed certificate. Disabling verification exposes your API key to interception."><input type="checkbox" id="ti-' + name + '-insecure" ' + (cfg.insecureTls ? 'checked' : '') + '> Skip TLS verify</label>';
    panel.innerHTML =
      '<div class="kpi-row">' +
        urlField +
        '<input id="ti-' + name + '-key" type="password" placeholder="API key (leave blank to keep current)" class="inp-sm u-flex1">' +
        insecureField +
        '<label class="tiny muted" style="display:flex;align-items:center;gap:0.3rem"><input type="checkbox" id="ti-' + name + '-enabled" ' + (cfg.enabled ? 'checked' : '') + '> Enabled</label>' +
      '</div>' +
      '<div class="kpi-row" style="margin-top:0.5rem">' +
        '<button class="btn btn-outline btn-sm"' + on('click', 'testConnectorConfig', name) + '>Test Connection</button>' +
        '<button class="btn btn-primary btn-sm"' + on('click', 'saveConnectorConfig', name) + '>Save</button>' +
        (cfg.configured ? '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger)"' + on('click', 'removeConnectorConfig', name) + '>Remove</button>' : '') +
        '<span id="ti-' + name + '-test-result" class="tiny muted"></span>' +
      '</div>';
  }).catch(function(e) { showToast('Failed to load ' + name + ' config: ' + (e.message || 'error'), 'err'); });
}

export function testConnectorConfig(name) {
  var resultEl = document.getElementById('ti-' + name + '-test-result');
  resultEl.textContent = 'Testing…';
  var urlEl = document.getElementById('ti-' + name + '-url');
  var insecureEl = document.getElementById('ti-' + name + '-insecure');
  apicall('/api/threat-intel/' + name + '/config/test', {
    method: 'POST',
    body: JSON.stringify({
      baseUrl: urlEl ? urlEl.value : '',
      apiKey: document.getElementById('ti-' + name + '-key').value,
      insecureTls: !!(insecureEl && insecureEl.checked)
    })
  }).then(function(res) {
    resultEl.textContent = res.ok ? ('OK — ' + res.actorCount + ' actors visible') : ('Failed: ' + res.error);
    resultEl.style.color = res.ok ? 'var(--success)' : 'var(--danger)';
  }).catch(function(e) {
    resultEl.textContent = 'Failed: ' + (e.message || 'error');
    resultEl.style.color = 'var(--danger)';
  });
}

export function saveConnectorConfig(name) {
  var urlEl = document.getElementById('ti-' + name + '-url');
  var newUrl = urlEl ? urlEl.value : '';
  var newKey = document.getElementById('ti-' + name + '-key').value;
  var newEnabled = document.getElementById('ti-' + name + '-enabled').checked;
  var insecureEl = document.getElementById('ti-' + name + '-insecure');
  var newInsecure = !!(insecureEl && insecureEl.checked);
  var payload = { baseUrl: newUrl, apiKey: newKey, enabled: newEnabled, insecureTls: newInsecure };

  var prev = TI_CONNECTOR_LOADED[name] || { baseUrl: '', enabled: false, insecureTls: false, configured: false };
  var urlChanged = urlEl && newUrl !== prev.baseUrl;
  var keyChanged = newKey !== '';
  var enabledChanged = newEnabled !== prev.enabled;
  var insecureChanged = insecureEl && newInsecure !== prev.insecureTls;

  // A genuine first-time setup has nothing to overwrite -- the confirm
  // modal exists to warn "you're about to replace an existing value", which
  // is meaningless (and confusing) before any value has ever been saved.
  if (!prev.configured || (!urlChanged && !keyChanged && !enabledChanged && !insecureChanged)) {
    doSaveConnectorConfig(name, payload); // nothing to confirm
    return;
  }

  var rows = '';
  if (urlChanged) rows += _diffRow('Base URL', prev.baseUrl, newUrl);
  rows += _diffSecretRow('API key', keyChanged);
  if (enabledChanged) rows += _diffRow('Enabled', prev.enabled ? 'Yes' : 'No', newEnabled ? 'Yes' : 'No');
  if (insecureChanged) rows += _diffRow('Skip TLS verify', prev.insecureTls ? 'Yes' : 'No', newInsecure ? 'Yes' : 'No');

  openConfirmDiffModal('Confirm ' + TI_CONNECTOR_LABELS[name] + ' Config Change', rows, function() {
    doSaveConnectorConfig(name, payload);
  });
}

function doSaveConnectorConfig(name, payload) {
  apicall('/api/threat-intel/' + name + '/config', {
    method: 'PUT',
    body: JSON.stringify(payload)
  }).then(function() {
    showToast(TI_CONNECTOR_LABELS[name] + ' config saved', 'ok');
    loadThreatIntelConfig(name);
    loadConnectorStatus();
  }).catch(function(e) { showToast('Save failed: ' + (e.message || 'error'), 'err'); });
}

// removeConnectorConfig deletes the stored base URL + API key entirely
// (unlike unchecking Enabled + Save, which stops syncing but leaves the
// credentials in place) -- confirmed first since it's destructive and the
// connector stops syncing immediately, no restart needed.
export function removeConnectorConfig(name) {
  var rows = _diffRow('Base URL', TI_CONNECTOR_LOADED[name] ? TI_CONNECTOR_LOADED[name].baseUrl : '', '(removed)') +
    '<div class="tiny muted" style="margin-top:0.4rem">This deletes the stored API key too. ' + TI_CONNECTOR_LABELS[name] + ' will stop syncing immediately.</div>';
  openConfirmDiffModal('Remove ' + TI_CONNECTOR_LABELS[name] + ' Config', rows, function() {
    apicall('/api/threat-intel/' + name + '/config', { method: 'DELETE' }).then(function(res) {
      if (res && res.warning) showToast(res.warning, 'err');
      else showToast(TI_CONNECTOR_LABELS[name] + ' config removed', 'ok');
      loadThreatIntelConfig(name);
      loadConnectorStatus();
    }).catch(function(e) { showToast('Remove failed: ' + (e.message || 'error'), 'err'); });
  });
}

// ── TAXII Connectors (generic TAXII 2.1 -- FS-ISAC/HC-ISAC/Auto-ISAC/any) ──
var TAXII_CONNECTORS = [];
var TAXII_EDITING_ID = null;

export function loadTAXIIConnectors() {
  var tbody = document.getElementById('taxii-connectors-body');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="empty">Loading…</td></tr>';
  apicall('/api/taxii/connectors').then(function(rows) {
    TAXII_CONNECTORS = rows || [];
    renderTAXIIConnectorsList();
  }).catch(function(e) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">Failed to load: ' + x(e.message || 'unknown error') + '</td></tr>';
  });
}

function renderTAXIIConnectorsList() {
  var tbody = document.getElementById('taxii-connectors-body');
  if (!TAXII_CONNECTORS.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No TAXII connectors configured yet.</td></tr>';
    return;
  }
  tbody.innerHTML = TAXII_CONNECTORS.map(function(c) {
    var lastPoll = c.lastPollAt ? ago(c.lastPollAt) : 'Never';
    var resultColor = c.lastPollStatus === 'ok' ? 'var(--success)' : (c.lastPollStatus === 'error' ? 'var(--danger)' : 'var(--muted)');
    var summary = c.lastPollSummary || {};
    var resultText = c.lastPollStatus === 'ok'
      ? (summary.processed || 0) + ' processed, ' + (summary.skipped || 0) + ' skipped, ' + (summary.malformed || 0) + ' malformed'
      : (c.lastPollStatus === 'error' ? x(c.lastError || 'error') : '—');
    return '<tr>' +
      '<td>' + x(c.name) + '</td>' +
      '<td class="tiny muted">' + x(c.serverUrl) + '</td>' +
      '<td>' + (c.enabled ? '<span class="badge" style="color:var(--success);border-color:var(--success)">Enabled</span>' : '<span class="badge" style="color:var(--muted);border-color:var(--muted)">Disabled</span>') + '</td>' +
      '<td class="tiny muted">' + x(lastPoll) + '</td>' +
      '<td class="tiny" style="color:' + resultColor + '">' + resultText + '</td>' +
      '<td>' +
        '<button class="btn btn-outline btn-sm"' + on('click', 'openTAXIIConnectorModal', c.id) + '>Edit</button> ' +
        '<button class="btn btn-outline btn-sm"' + on('click', 'syncTAXIIConnectorNow', c.id) + '>Sync Now</button> ' +
        '<button class="btn btn-outline btn-sm"' + on('click', 'deleteTAXIIConnector', c.id) + '>Delete</button>' +
      '</td>' +
    '</tr>';
  }).join('');
}

export function taxiiToggleAuthFields() {
  var authType = document.getElementById('taxii-conn-auth-type').value;
  setDisplay(document.getElementById('taxii-conn-basic-fields'), authType === 'basic' ? '' : 'none');
}

export function openTAXIIConnectorModal(id) {
  TAXII_EDITING_ID = id;
  document.getElementById('taxii-conn-test-result').textContent = '';
  if (!id) {
    document.getElementById('taxii-connector-modal-title').textContent = 'Add TAXII Connector';
    document.getElementById('taxii-conn-save-btn').textContent = 'Save';
    document.getElementById('taxii-conn-name').value = '';
    document.getElementById('taxii-conn-server-url').value = '';
    document.getElementById('taxii-conn-api-root').value = '';
    document.getElementById('taxii-conn-collection-id').value = '';
    document.getElementById('taxii-conn-auth-type').value = 'none';
    document.getElementById('taxii-conn-username').value = '';
    document.getElementById('taxii-conn-password').value = '';
    document.getElementById('taxii-conn-insecure-tls').checked = false;
    document.getElementById('taxii-conn-enabled').checked = false;
    taxiiToggleAuthFields();
    document.getElementById('taxii-connector-overlay').classList.add('open');
    return;
  }
  var c = TAXII_CONNECTORS.find(function(row) { return row.id === id; });
  if (!c) { showToast('Connector not found', 'err'); return; }
  document.getElementById('taxii-connector-modal-title').textContent = 'Edit TAXII Connector';
  document.getElementById('taxii-conn-save-btn').textContent = 'Save Changes';
  document.getElementById('taxii-conn-name').value = c.name || '';
  document.getElementById('taxii-conn-server-url').value = c.serverUrl || '';
  document.getElementById('taxii-conn-api-root').value = c.apiRoot || '';
  document.getElementById('taxii-conn-collection-id').value = c.collectionId || '';
  document.getElementById('taxii-conn-auth-type').value = c.authType || 'none';
  document.getElementById('taxii-conn-username').value = c.username || '';
  document.getElementById('taxii-conn-password').value = ''; // never round-tripped -- blank means "keep current"
  document.getElementById('taxii-conn-insecure-tls').checked = !!c.insecureTls;
  document.getElementById('taxii-conn-enabled').checked = !!c.enabled;
  taxiiToggleAuthFields();
  document.getElementById('taxii-connector-overlay').classList.add('open');
}

export function closeTAXIIConnectorModal() {
  document.getElementById('taxii-connector-overlay').classList.remove('open');
  TAXII_EDITING_ID = null;
}

function taxiiFormPayload() {
  return {
    name: document.getElementById('taxii-conn-name').value,
    serverUrl: document.getElementById('taxii-conn-server-url').value,
    apiRoot: document.getElementById('taxii-conn-api-root').value,
    collectionId: document.getElementById('taxii-conn-collection-id').value,
    authType: document.getElementById('taxii-conn-auth-type').value,
    username: document.getElementById('taxii-conn-username').value,
    password: document.getElementById('taxii-conn-password').value,
    insecureTls: document.getElementById('taxii-conn-insecure-tls').checked,
    enabled: document.getElementById('taxii-conn-enabled').checked
  };
}

export function testTAXIIConnectorForm() {
  var resultEl = document.getElementById('taxii-conn-test-result');
  resultEl.textContent = 'Testing…';
  resultEl.style.color = 'var(--muted)';
  apicall('/api/taxii/connectors/test', { method: 'POST', body: JSON.stringify(taxiiFormPayload()) })
    .then(function(res) {
      resultEl.textContent = res.ok ? ('OK — ' + res.collectionCount + ' collection(s) visible') : ('Failed: ' + res.error);
      resultEl.style.color = res.ok ? 'var(--success)' : 'var(--danger)';
    })
    .catch(function(e) {
      resultEl.textContent = 'Failed: ' + (e.message || 'error');
      resultEl.style.color = 'var(--danger)';
    });
}

export function saveTAXIIConnectorForm() {
  var payload = taxiiFormPayload();
  if (!payload.name || !payload.serverUrl) { showToast('Name and Server URL are required', 'err'); return; }
  var isEdit = !!TAXII_EDITING_ID;
  var url = isEdit ? '/api/taxii/connectors/' + encodeURIComponent(TAXII_EDITING_ID) : '/api/taxii/connectors';
  apicall(url, { method: isEdit ? 'PUT' : 'POST', body: JSON.stringify(payload) })
    .then(function() {
      showToast('TAXII connector saved', 'ok');
      closeTAXIIConnectorModal();
      loadTAXIIConnectors();
    })
    .catch(function(e) { showToast('Save failed: ' + (e.message || 'error'), 'err'); });
}

export function deleteTAXIIConnector(id) {
  if (!confirm('Delete this TAXII connector? This stops its polling immediately and cannot be undone.')) return;
  apicall('/api/taxii/connectors/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function() { showToast('Connector deleted', 'ok'); loadTAXIIConnectors(); })
    .catch(function(e) { showToast('Delete failed: ' + (e.message || 'error'), 'err'); });
}

export function syncTAXIIConnectorNow(id) {
  apicall('/api/taxii/connectors/' + encodeURIComponent(id) + '/sync', { method: 'POST' })
    .then(function(res) {
      showToast(res.ok ? 'Sync completed' : ('Sync failed: ' + (res.error || 'unknown error')), res.ok ? 'ok' : 'err');
      loadTAXIIConnectors();
    })
    .catch(function(e) { showToast('Sync failed: ' + (e.message || 'error'), 'err'); });
}

export function loadConnectorStatus() {
  var wrap = document.getElementById('connector-status-wrap');
  if (!wrap) return;
  setDisplay(wrap, '');
  apicall('/api/connector/status').then(function(s) {
    var bySource = s.bySource || {};
    _renderConnectorCard('misp', s.mispEnabled, bySource.misp, 'cs-misp-events');
    _renderConnectorCard('opencti', s.openctiEnabled, bySource.opencti, 'cs-opencti-nodes');
    document.getElementById('cs-otx').textContent     = s.otxEnabled     ? '✓ Enabled' : '✗ Not configured';
    document.getElementById('cs-bundle').textContent = s.bundleEnabled ? ('✓ Enabled (v' + (s.bundleVersion || '?') + ')') : '✗ Not configured';
    document.getElementById('cs-last-sync').textContent = s.lastSyncAt ? new Date(s.lastSyncAt).toLocaleString() : 'Never';
    document.getElementById('cs-created').textContent = (s.scenariosCreated || 0) + ' created, ' + (s.scenariosUpdated || 0) + ' updated';
    document.getElementById('cs-next').textContent = s.nextSyncAt ? new Date(s.nextSyncAt).toLocaleString() : '—';
    var statusEl = document.getElementById('cs-status');
    statusEl.textContent = s.lastSyncStatus || 'never';
    statusEl.style.color = s.lastSyncStatus === 'ok' ? '#5cead8' : s.lastSyncStatus === 'error' ? '#f85149' : 'var(--muted)';
    var errEl = document.getElementById('cs-error');
    if (s.lastError) { errEl.textContent = s.lastError; setDisplay(errEl, ''); }
    else { setDisplay(errEl, 'none'); }
  }).catch(function(e) { showToast('Failed to load connector status: ' + (e.message || 'error'), 'err'); });
}

export function triggerConnectorSync() {
  var btn = document.getElementById('connector-sync-btn');
  if (btn) btn.disabled = true;
  apicall('/api/connector/sync', { method: 'POST' })
    .then(function() {
      showToast('Threat-intel sync queued', 'ok');
      setTimeout(function() {
        loadConnectorStatus();
        loadScenarios();
        if (btn) btn.disabled = false;
      }, 3000);
    })
    .catch(function(e) {
      showToast('Sync failed: ' + e.message, 'err');
      if (btn) btn.disabled = false;
    });
}

export function loadARTContentStatus() {
  var wrap = document.getElementById('art-content-wrap');
  if (!wrap) return;
  setDisplay(wrap, '');
  var btn = document.getElementById('art-check-btn');
  if (btn) btn.disabled = true;
  apicall('/api/art/content/status').then(function(d) {
    var statusEl = document.getElementById('cs-art-status');
    if (d.seeded) {
      statusEl.innerHTML = '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--success);margin-right:6px;vertical-align:middle"></span><span class="u-success">Seeded</span>';
    } else {
      statusEl.innerHTML = '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--warning);margin-right:6px;vertical-align:middle"></span><span class="u-warning">Not seeded</span>';
    }
    document.getElementById('cs-art-version').textContent = d.version || '(unversioned)';
    var loaded = d.techniquesLoaded != null ? d.techniquesLoaded : (d.techniqueCount || 0);
    var techEl = document.getElementById('cs-art-techniques');
    techEl.textContent = loaded + ' loaded' + (d.techniqueCount != null ? ' / ' + d.techniqueCount + ' in DB' : '');
    // Loaded and in-DB should always match -- a mismatch means some techniques'
    // rows are missing from art_atomic_tests even though the seed record still
    // counts them (see the field's tooltip). Flag it instead of showing a
    // silently-wrong number, so a stale seed record doesn't look like a healthy one.
    techEl.style.color = (d.techniqueCount != null && loaded !== d.techniqueCount) ? 'var(--warning)' : '';
    var winEl = document.getElementById('cs-art-windows-runnable');
    if (winEl) {
      var winCount = d.windowsRunnable != null ? d.windowsRunnable : 0;
      var nonWin = loaded - winCount;
      winEl.textContent = winCount + ' of ' + loaded + (nonWin > 0 ? ' (' + nonWin + ' Linux/macOS-only, excluded from ART Full Windows Sweep)' : '');
      winEl.style.color = nonWin > 0 ? 'var(--warning)' : '';
    }
    document.getElementById('cs-art-tests').textContent =
      (d.testCount != null ? d.testCount : 0) + ' Windows atomics';
    document.getElementById('cs-art-payloads').textContent = (d.payloadCount || 0) + ' indexed';
    var missingRow = document.getElementById('cs-art-payloads-missing-row');
    var missingCount = d.missingPayloadCount || 0;
    if (missingRow) {
      if (missingCount > 0) {
        var names = (d.missingPayloads || []).slice(0, 5).join(', ');
        var extra = missingCount > 5 ? ' +' + (missingCount - 5) + ' more' : '';
        document.getElementById('cs-art-payloads-missing').textContent =
          '⚠ ' + missingCount + ' referenced but not indexed: ' + names + extra;
        setDisplay(missingRow, '');
      } else {
        setDisplay(missingRow, 'none');
      }
    }
    document.getElementById('cs-art-kev').textContent =
      (d.kevCount != null ? d.kevCount : 0) + ' known-exploited';
    document.getElementById('cs-art-source').textContent = d.source || '—';
    document.getElementById('cs-art-imported').textContent =
      d.importedAt ? new Date(d.importedAt).toLocaleString() : '—';
  }).catch(function(e) {
    document.getElementById('cs-art-status').innerHTML =
      '<span class="u-danger">Error checking status</span>';
  }).finally(function() {
    if (btn) btn.disabled = false;
  });
}

var SIM_COV_OPEN = false;
export function toggleSimCoverage() {
  SIM_COV_OPEN = !SIM_COV_OPEN;
  var det = document.getElementById('sim-cov-detail');
  var car = document.getElementById('sim-caret');
  if (det) setDisplay(det, SIM_COV_OPEN ? '' : 'none');
  if (car) car.innerHTML = SIM_COV_OPEN ? '&#9660;' : '&#9654;';
}
export function simCovHoverOn() { this.style.boxShadow = '0 0 0 1px var(--accent)'; }
export function simCovHoverOff() { this.style.boxShadow = ''; }
export function loadSimCoverage() {
  var totalEl   = document.getElementById('sim-total');
  var variantEl = document.getElementById('sim-variants');
  var subEl     = document.getElementById('sim-sub');
  var bodyEl    = document.getElementById('sim-cov-body');
  if (!totalEl) return;
  totalEl.textContent = '...';
  if (variantEl) variantEl.textContent = '...';
  Promise.all([
    apicall('/api/art/content/status').catch(function() { return {}; }),
    apicall('/api/caldera/abilities').catch(function() { return []; }),
    apicall('/api/scenarios').catch(function() { return []; }),
    apicall('/api/techniques/unified').catch(function() { return []; }),
    apicall('/api/variants/stats').catch(function() { return {}; })
  ]).then(function(res) {
    var art     = res[0] || {};
    var cal     = Array.isArray(res[1]) ? res[1] : [];
    var scen    = Array.isArray(res[2]) ? res[2] : [];
    var unified = Array.isArray(res[3]) ? res[3] : [];
    var vstats  = res[4] || {};

    var artTechniques = art.techniqueCount  || 0;
    var artTests      = art.testCount       || 0;
    var artPS         = art.psTestCount     || 0;
    var artCMD        = art.cmdTestCount    || 0;
    var artVariants   = art.variantCount    || 0;
    var artPayloads   = art.payloadCount    || 0;
    var kevCount      = art.kevCount        || 0;
    var calCount      = cal.length;
    // Combined ART + Caldera total -- /api/variants/stats is the single
    // source of truth for this (see GetVariantStats), so this page's
    // headline number matches the Variant Executor's own dashboard tile
    // instead of drifting as a second, ART-only computation of the same
    // thing.
    var combinedVariants  = vstats.availableVariants        || artVariants;
    var calderaVariants   = vstats.calderaAvailableVariants || 0;
    var builtinScen   = scen.filter(function(s) { return s.source === 'builtin'; }).length;
    var customScen    = scen.filter(function(s) { return s.source === 'custom';  }).length;
    var intelScen     = scen.filter(function(s) { return s.source === 'intel';   }).length;

    var byPlugin = {}, techSet = {}, subTechSet = {};
    var calWin = 0, calLin = 0, calMac = 0;
    cal.forEach(function(ab) {
      var p = ab.plugin || 'other';
      byPlugin[p] = (byPlugin[p] || 0) + 1;
      if (ab.technique) {
        techSet[ab.technique] = true;
        if (ab.technique.indexOf('.') !== -1) subTechSet[ab.technique] = true;
      }
      if (Array.isArray(ab.platforms)) {
        if (ab.platforms.indexOf('windows') !== -1) calWin++;
        if (ab.platforms.indexOf('linux')   !== -1) calLin++;
        if (ab.platforms.indexOf('darwin')  !== -1) calMac++;
      }
    });
    var calEmu         = byPlugin['emu']    || 0;
    var calAtomic      = byPlugin['atomic'] || 0;
    var calOther       = calCount - calEmu - calAtomic;
    var calUniqTech    = Object.keys(techSet).length;
    var calUniqSubTech = Object.keys(subTechSet).length;
    var unifiedTotal   = unified.length;

    // Base = all executable units before variant expansion
    var baseTotal = artTests + calCount + customScen + intelScen + builtinScen;

    totalEl.textContent = baseTotal.toLocaleString();
    if (variantEl) variantEl.textContent = combinedVariants > 0 ? combinedVariants.toLocaleString() + '+' : '--';
    if (subEl) subEl.textContent =
      artTests.toLocaleString() + ' ART base atomics \xb7 ' +
      calCount.toLocaleString() + ' Caldera abilities \xb7 ' +
      (customScen + intelScen + builtinScen) + ' scenarios \xb7 ' +
      unifiedTotal + ' unique ATT&CK techniques';

    if (bodyEl) {
      var rows = [
        // ART Base Library
        ['ART base techniques',                artTechniques,        'Source technique IDs — each maps to 1+ atomic tests'],
        ['ART atomic tests (base)',            artTests,             'Executable Windows test instances; the base simulation count'],
        ['  PowerShell executor',              artPS   || null,      'PS steps: 36 variants each (3 encodings x 3 privilege tiers x 4 exec contexts)'],
        ['  CMD executor',                     artCMD  || null,      'CMD steps: 12 variants each (1 encoding x 3 privilege tiers x 4 exec contexts)'],
        ['ART payload-backed tests',           artPayloads,          'Atomics requiring a bundled binary payload (subset of atomics above)'],
        // Variant Engine
        ['Variant Engine — available variants', combinedVariants, 'Variant Engine total: all encoding x privilege x exec-context combinations across every ART atomic test' + (calderaVariants ? ' + every loaded Caldera ability' : '')],
        ['  Encoding variants (PS only)',      artPS * 3 || null,    'plain / base64 (-EncodedCommand) / charcode ([char]N+IEX)'],
        ['  Privilege variants',               artTests * 3 || null, 'user / admin / system per test'],
        ['  Exec-context variants',            artTests * 4 || null, 'direct / WMI (T1047) / Scheduled Task (T1053.005) / COM WScript.Shell (T1559.001)'],
        // Caldera
        ['Caldera abilities — total',    calCount,              'Raw ability count across all enabled plugins'],
        ['  emu (CTID adversary-emulation)',   calEmu,               'MITRE ATT&CK kill-chain abilities from the adversary-emulation library'],
        ['  atomic (Atomic Red Team)',         calAtomic,            'Atomic Red Team abilities via Caldera atomic plugin'],
        ['  other plugins',                    calOther > 0 ? calOther : null, 'stockpile / other enabled plugins'],
        ['  Windows platform',                 calWin || null,       'Caldera abilities with a Windows executor'],
        ['  Linux platform',                   calLin || null,       'Caldera abilities with a Linux executor'],
        ['  macOS/Darwin platform',            calMac || null,       'Caldera abilities with a macOS executor'],
        ['Caldera unique techniques',          calUniqTech,          'Distinct ATT&CK technique IDs (raw count overstates coverage — this is accurate)'],
        ['Caldera unique sub-techniques',      calUniqSubTech,       'Distinct sub-techniques (e.g. T1059.001)'],
        ['  Caldera variant contribution',     calderaVariants || null, 'Caldera abilities × the same encoding/privilege/exec-context combinatorics ART uses — included in the Variant Engine total above'],
        // Scenarios
        ['Built-in scenarios',                 builtinScen,          'Signed YAML scenarios shipped with the platform'],
        ['Custom / operator scenarios',        customScen,           'Operator-authored scenarios'],
        ['Threat-intel scenarios',             intelScen,            'Auto-generated from MISP / OpenCTI'],
        ['CISA KEV CVEs tracked',              kevCount,             'Known-exploited vulnerabilities — prioritised for CVE-template simulations'],
      ].filter(function(r) { return r[1] !== null && r[1] !== undefined; });

      var sectionKeys = {
        'ART base techniques': true,
        'Variant Engine — available variants': true,
        'Caldera abilities — total': true,
        'Built-in scenarios': true,
      };

      bodyEl.innerHTML = rows.map(function(r, i) {
        var bg = i % 2 === 0 ? '' : 'background:rgba(255,255,255,.02)';
        var isVariantRow = r[0].indexOf('Variant Engine') !== -1;
        var isSection = !!sectionKeys[r[0]];
        var textStyle = isVariantRow ? 'font-weight:700;color:var(--accent)'
                      : isSection    ? 'font-weight:700;color:var(--text)'
                      :                'color:var(--muted)';
        var numStyle = isVariantRow
          ? 'font-family:var(--font-mono);font-size:0.9rem;font-weight:800;color:var(--accent)'
          : 'font-family:var(--font-mono);font-size:0.78rem;color:' + (isSection ? 'var(--text)' : 'var(--muted)');
        return '<tr style="' + bg + '">' +
          '<td style="padding:0.5rem 0.9rem;' + textStyle + '">' + r[0] + '</td>' +
          '<td style="padding:0.5rem 0.9rem;' + numStyle + '">' + (r[1] || 0).toLocaleString() + '</td>' +
          '<td style="padding:0.5rem 0.9rem;font-size:0.74rem;color:var(--muted)">' + r[2] + '</td>' +
        '</tr>';
      }).join('') +
      '<tr style="border-top:1px solid var(--border);background:rgba(47,129,247,.06)">' +
        '<td style="padding:0.55rem 0.9rem;font-weight:700;color:var(--text)">Unique ATT&amp;CK endpoint techniques (all sources)</td>' +
        '<td style="padding:0.55rem 0.9rem;font-family:var(--font-mono);font-size:0.9rem;font-weight:800;color:var(--accent)">' + unifiedTotal.toLocaleString() + '</td>' +
        '<td style="padding:0.55rem 0.9rem;font-size:0.74rem;color:var(--muted)">Deduplicated ATT&CK technique IDs across ART + Caldera + BAS scenarios</td>' +
      '</tr>' +
      '<tr style="border-top:1px solid var(--border);background:rgba(47,129,247,.03)">' +
        '<td style="padding:0.55rem 0.9rem;font-weight:600;color:var(--text)">Base simulations (pre-variant)</td>' +
        '<td style="padding:0.55rem 0.9rem;font-family:var(--font-mono);font-size:0.78rem;font-weight:700;color:var(--text)">' + baseTotal.toLocaleString() + '</td>' +
        '<td style="padding:0.55rem 0.9rem;font-size:0.74rem;color:var(--muted)">ART atomics + Caldera + all scenarios, no variant multiplication</td>' +
      '</tr>';
    }
  }).catch(function() {
    if (totalEl) totalEl.textContent = '--';
    if (variantEl) variantEl.textContent = '--';
    if (subEl) subEl.textContent = 'Could not load coverage data';
  });
}
export function reseedART() {
  if (!confirm('Reseed ART content from the server content pack?\n\nThis re-imports atomics + payload metadata into Postgres and hot-reloads the engine. Existing runs are unaffected.')) return;
  var btn = document.getElementById('art-reseed-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Reseeding…'; }
  apicall('/api/art/content/reseed', { method: 'POST' })
    .then(function(d) {
      showToast('Reseeded: ' + d.techniqueCount + ' techniques, ' + d.payloadCount + ' payloads', 'ok');
      loadARTContentStatus();
    })
    .catch(function(e) {
      showToast('Reseed failed: ' + e.message, 'err');
    })
    .finally(function() {
      if (btn) { btn.disabled = false; btn.textContent = 'Reseed from Pack'; }
    });
}