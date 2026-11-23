import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { failureOf, failureHtml } from '../core/load-state.js';
import { ago, showToast } from '../core/util.js';
import { apColor, apClosePanels } from './attack-path.js';
import { freshness as apAgeChip } from './ap-model.js';
import { apRichBody } from './rich-g4.js';
import { setExRows, setExError, setExPlans, setExPlansError, execDetailHtml, scenarioDetailHtml, launchFormHtml, focusNewPlanNext } from './ex-view.js';
import { _diffRow, _diffSecretRow, openConfirmDiffModal } from './compliance.js';
import { ROLE, showTab } from './shell.js';
import { describePhishingRun } from './phishing-run-view.js';
import { displayOf, setDisplay } from '../core/inline-style.js';


// ── OpenAEV Connector — config/status card lives in Settings → Threat Intel,
// alongside MISP/OpenCTI/OTX (see loadConnectorStatus). Synced scenarios live
// in the Exercises tab (see loadExercisesTab), since that's where they turn
// into exercise plans.
var OAEV_CONFIG_LOADED = { baseUrl: '', enabled: false, configured: false }; // last fetched from the server, for the save confirmation diff

export function loadOpenAEVConfig() {
  var configPanel = document.getElementById('openaev-config-panel');
  if (!configPanel) return;
  if (ROLE === 'admin') {
    apicall('/api/openaev/config').then(function(cfg) {
      var cfail = failureOf(cfg);
      if (cfail) { configPanel.innerHTML = failureHtml('OpenAEV settings', cfail, null); return; }
      OAEV_CONFIG_LOADED = { baseUrl: cfg.baseUrl || '', enabled: !!cfg.enabled, configured: !!cfg.configured };
      configPanel.innerHTML =
        '<div class="kpi-row">' +
          '<div class="field"><label for="oaev-url">Server URL</label><input id="oaev-url" type="text" placeholder="https://openaev.example.local" value="' + x(cfg.baseUrl || '') + '" class="inp-sm u-flex1"></div>' +
          '<div class="field"><label for="oaev-token">API token</label><input id="oaev-token" type="password" placeholder="Leave blank to keep current" class="inp-sm u-flex1"></div>' +
          '<label class="tiny muted" style="display:flex;align-items:center;gap:0.3rem"><input type="checkbox" id="oaev-enabled" ' + (cfg.enabled ? 'checked' : '') + '> Enabled</label>' +
        '</div>' +
        '<div class="kpi-row" style="margin-top:0.5rem">' +
          '<button class="btn btn-outline btn-sm"' + on('click', 'testOpenAEVConfig') + '>Test Connection</button>' +
          '<button class="btn btn-primary btn-sm"' + on('click', 'saveOpenAEVConfig') + '>Save</button>' +
          '<button class="btn btn-outline btn-sm"' + on('click', 'syncOpenAEVNow') + '>Sync Now</button>' +
          (cfg.configured ? '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger)"' + on('click', 'removeOpenAEVConfig') + '>Remove</button>' : '') +
          '<span id="oaev-test-result" class="tiny muted"></span>' +
        '</div>';
    }).catch(function(e) { showToast('Failed to load OpenAEV config: ' + (e.message || 'error'), 'err'); });
  } else {
    configPanel.innerHTML = '';
  }

  apicall('/api/openaev/status').then(function(s) {
    var badge = document.getElementById('openaev-status-badge');
    var color = s.lastSyncStatus === 'ok' ? apColor(100) : s.lastSyncStatus === 'error' ? apColor(0) : 'var(--muted)';
    var label = s.lastSyncStatus || 'never';
    if (s.lastSyncStatus === 'ok') {
      label += ' — ' + (s.lastSyncCreated || 0) + ' created, ' + (s.lastSyncUpdated || 0) + ' updated';
      if (s.lastSyncSkipped) label += ', ' + s.lastSyncSkipped + ' skipped';
      if (s.lastSyncErrored) label += ', ' + s.lastSyncErrored + ' errored';
    }
    badge.textContent = x(label);
    badge.style.color = color;

    // Info-row grid -- same visual shape as the MISP/OpenCTI cards
    // (_renderConnectorCard), using OpenAEV's own status fields (scenario
    // sync counts, not threat-actor extraction).
    var statusEl = document.getElementById('cs-openaev-status');
    if (statusEl) {
      if (s.lastSyncStatus === 'error') { statusEl.textContent = '⚠ Error'; statusEl.style.color = '#f85149'; }
      else if (s.lastSyncStatus === 'ok') { statusEl.textContent = '✓ Connected'; statusEl.style.color = '#5cead8'; }
      else { statusEl.textContent = '— Not synced yet'; statusEl.style.color = 'var(--muted)'; }
    }
    var scenariosEl = document.getElementById('cs-openaev-scenarios');
    if (scenariosEl) scenariosEl.textContent = (s.scenarioCount || 0).toLocaleString();
    var createdEl = document.getElementById('cs-openaev-created');
    if (createdEl) createdEl.textContent = (s.lastSyncCreated || 0) + ' / ' + (s.lastSyncUpdated || 0);
    var lastFetchEl = document.getElementById('cs-openaev-lastfetch');
    if (lastFetchEl) lastFetchEl.textContent = s.lastSyncAt ? new Date(s.lastSyncAt).toLocaleString() : '—';
    var errEl = document.getElementById('cs-openaev-error');
    if (errEl) {
      if (s.lastError) { errEl.textContent = s.lastError; setDisplay(errEl, ''); }
      else { setDisplay(errEl, 'none'); }
    }
  }).catch(function(e) { showToast('Failed to load OpenAEV status: ' + (e.message || 'error'), 'err'); });
}

// removeOpenAEVConfig deletes the stored base URL + bearer token entirely
// (unlike unchecking Enabled + Save, which stops syncing but leaves the
// credentials in place) -- confirmed first since it's destructive. Mirrors
// removeConnectorConfig's existing precedent for MISP/OpenCTI/OTX.
export function removeOpenAEVConfig() {
  var rows = _diffRow('Base URL', OAEV_CONFIG_LOADED.baseUrl, '(removed)') +
    '<div class="tiny muted" style="margin-top:0.4rem">This deletes the stored bearer token too. OpenAEV will stop syncing immediately.</div>';
  openConfirmDiffModal('Remove OpenAEV Config', rows, function() {
    exCall('/api/openaev/config', { method: 'DELETE' }).then(function() {
      showToast('OpenAEV config removed', 'ok');
      loadOpenAEVConfig();
    }).catch(function(e) { showToast('Remove failed: ' + (e.message || 'error'), 'err'); });
  });
}

// exCall: apicall hands back a server error as a plain { error } body instead of throwing, which made a failed load look
// like an empty list and a refused launch / approve / abort look like a success. Raise it instead.
function exCall(path, opts) {
  return apicall(path, opts).then(function(r) {
    if (r && !Array.isArray(r) && typeof r === 'object' && typeof r.error === 'string' && r.error) throw new Error(r.error);
    return r;
  });
}

function loadOpenAEVScenarios(type) {
  var kind = type === 'exercise' ? 'exs' : 'scen';
  exCall('/api/openaev/scenarios?type=' + encodeURIComponent(type || 'scenario')).then(function(list) {
    setExRows(kind, list);
  }).catch(function() { setExError(kind); });
}

export function testOpenAEVConfig() {
  var resultEl = document.getElementById('oaev-test-result');
  resultEl.textContent = 'Testing…';
  apicall('/api/openaev/config/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      baseUrl: document.getElementById('oaev-url').value,
      bearerToken: document.getElementById('oaev-token').value
    })
  }).then(function(res) {
    resultEl.textContent = res.ok ? ('OK — ' + res.scenarioCount + ' scenarios visible') : ('Failed: ' + res.error);
    resultEl.style.color = res.ok ? 'var(--success)' : 'var(--danger)';
  }).catch(function(e) {
    resultEl.textContent = 'Failed: ' + (e.message || 'error');
    resultEl.style.color = 'var(--danger)';
  });
}

export function saveOpenAEVConfig() {
  var newUrl = document.getElementById('oaev-url').value;
  var newToken = document.getElementById('oaev-token').value;
  var newEnabled = document.getElementById('oaev-enabled').checked;
  var payload = { baseUrl: newUrl, bearerToken: newToken, pollIntervalHours: 24, enabled: newEnabled };

  var urlChanged = newUrl !== OAEV_CONFIG_LOADED.baseUrl;
  var tokenChanged = newToken !== '';
  var enabledChanged = newEnabled !== OAEV_CONFIG_LOADED.enabled;

  // A genuine first-time setup has nothing to overwrite -- the confirm
  // modal exists to warn "you're about to replace an existing value", which
  // is meaningless (and confusing) before any value has ever been saved.
  // Same fix as saveConnectorConfig's own !prev.configured check.
  if (!OAEV_CONFIG_LOADED.configured || (!urlChanged && !tokenChanged && !enabledChanged)) {
    doSaveOpenAEVConfig(payload); // nothing to confirm
    return;
  }

  var rows = '';
  if (urlChanged) rows += _diffRow('Base URL', OAEV_CONFIG_LOADED.baseUrl, newUrl);
  rows += _diffSecretRow('Bearer token', tokenChanged);
  if (enabledChanged) rows += _diffRow('Enabled', OAEV_CONFIG_LOADED.enabled ? 'Yes' : 'No', newEnabled ? 'Yes' : 'No');

  openConfirmDiffModal('Confirm OpenAEV Config Change', rows, function() {
    doSaveOpenAEVConfig(payload);
  });
}

function doSaveOpenAEVConfig(payload) {
  exCall('/api/openaev/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function() {
    showToast('OpenAEV config saved', 'ok');
    loadOpenAEVConfig();
  }).catch(function(e) { showToast('Save failed: ' + (e.message || 'error'), 'err'); });
}

export function syncOpenAEVNow() {
  exCall('/api/openaev/sync', { method: 'POST' }).then(function() {
    showToast('OpenAEV sync started', 'ok');
    loadOpenAEVConfig();
  }).catch(function(e) { showToast('Sync failed: ' + (e.message || 'error'), 'err'); });
}

export function openOpenAEVDetail(id) {
  exCall('/api/openaev/scenarios/' + encodeURIComponent(id)).then(function(d) {
    document.getElementById('openaev-detail-title').textContent = d.scenario.Name;
    document.getElementById('openaev-detail-body').innerHTML = scenarioDetailHtml(id, d, ROLE === 'admin');
    document.getElementById('openaev-detail-overlay').classList.add('open');
  }).catch(function(e) { showToast('Failed to load scenario detail: ' + (e.message || 'error'), 'err'); });
}

export function closeOpenAEVDetail() {
  document.getElementById('openaev-detail-overlay').classList.remove('open');
}
export function closeOpenAEVDetailOnBackdrop(el, event) { if (event.target === el) closeOpenAEVDetail(); }

export function loadExercisesTab() {
  loadOpenAEVScenarios('scenario');
  loadOpenAEVScenarios('exercise');
  exCall('/api/exercises/plans').then(function(plans) {
    setExPlans(plans);
  }).catch(function() { setExPlansError(); });

  exCall('/api/exercises/executions').then(function(execs) {
    setExRows('execs', execs);
    if (!execs || !execs.length) { stopExPoll(); return; }
    // Keep the list (and any open detail drawer) live while anything is
    // still running/paused -- previously this was a one-shot snapshot from
    // whenever the tab was opened, so a launched exercise just sat on
    // "running" forever with zero feedback until the operator manually
    // reloaded. The executor itself already ticks server-side every 5s
    // (cmd/server/main.go); this just catches the UI up to it.
    if (execs.some(function(e) { return e.status === 'running' || e.status === 'paused'; })) {
      startExPoll();
    } else {
      stopExPoll();
    }
  }).catch(function(e) { setExError('execs', e && e.message); });
}

var _exPollTimer = null;
function startExPoll() {
  if (_exPollTimer) return;
  _exPollTimer = setInterval(function() {
    var tab = document.getElementById('tab-exercises');
    if (!tab || displayOf(tab) === 'none') { stopExPoll(); return; }
    loadExercisesTab();
    if (_exDetailOpenId) openExerciseDetail(_exDetailOpenId);
  }, 5000);
}
function stopExPoll() { clearInterval(_exPollTimer); _exPollTimer = null; }

export function launchExercisePrompt(planId) {
  exCall('/api/exercises/plans/' + encodeURIComponent(planId)).then(function(p) {
    if (!(p.steps || []).length) { showToast('This plan has no steps yet, so there is nothing to launch.', 'warn'); return; }
    openConfirmDiffModal('Launch "' + (p.name || 'exercise') + '"?', launchFormHtml(p), function() {
      var values = {};
      document.querySelectorAll('#confirm-diff-body .exd-var').forEach(function(inp) { values[inp.getAttribute('data-var')] = inp.value; });
      exCall('/api/exercises/executions', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan_id: planId, name: p.name, targets: [], variables: values })
      }).then(function(ex) {
        return exCall('/api/exercises/executions/' + encodeURIComponent(ex.id) + '/launch', { method: 'POST' }).then(function() { return ex.id; });
      }).then(function(newId) {
        showToast('Exercise launched', 'ok');
        loadExercisesTab();
        // The new run sits in the Executions table, usually below the fold: show it straight away.
        openExerciseDetail(newId);
      }).catch(function(e) { showToast('Launch failed: ' + (e.message || 'error'), 'err'); });
    }, { sub: 'The exercise starts running as soon as you launch it.', confirmLabel: 'Launch' });
  }).catch(function(e) { showToast('Failed to load exercise plan: ' + (e.message || 'error'), 'err'); });
}

// The purple-team debrief: which of the attacks this exercise ran the defenders detected, missed, or nobody has judged
// yet. A rate is only shown once something is resolved; absence of a verdict is never drawn as a result.
export function purpleDebriefHtml(p) {
  if (!p) return '';
  var rate = p.detectionRate == null ? 'Not yet judged'
    : Math.round(p.detectionRate) + '% (' + p.detected + ' of ' + (p.detected + p.missed) + ')';
  var rows = (p.techniques || []).map(function(t) {
    var tone = t.outcome === 'detected' ? 'ok' : t.outcome === 'missed' ? 'bad' : 'muted';
    return '<div class="exd-pt"><span><b class="mono">' + x(t.techniqueId) + '</b>' + (t.providers && t.providers.length ? ' <span class="tiny muted">' + x(t.providers.join(', ')) + '</span>' : '') + '</span>' +
      '<span class="rk-pill tone-' + tone + '">' + x(t.outcome) + '</span></div>';
  }).join('');
  var gaps = (p.gaps || []).length ? '<div class="exd-note tone-bad"><p>Gaps to close: ' + p.gaps.map(x).join('; ') + '</p></div>' : '';
  var none = (p.noExpectation || []).length ? '<p class="exd-quiet">No detection expectation was recorded for ' + p.noExpectation.map(x).join(', ') + ', so these were not judged either way.</p>' : '';
  return '<h4 class="exd-h">Purple-team debrief</h4><p class="exd-desc">Detection rate: ' + x(rate) + '. Awaiting an approved verdict: ' + (p.unresolved || 0) + '.</p>' +
    '<div class="exd-pts">' + rows + '</div>' + gaps + none;
}


var _exDetailOpenId = null;
export function openExerciseDetail(id) {
  _exDetailOpenId = id;
  Promise.all([
    exCall('/api/exercises/executions/' + encodeURIComponent(id)),
    exCall('/api/exercises/executions/' + encodeURIComponent(id) + '/phishing-runs').catch(function() { return []; }),
    exCall('/api/exercises/executions/' + encodeURIComponent(id) + '/report.json').catch(function() { return null; })
  ]).then(function(res) {
    var purple = res[2] && res[2].purple ? res[2].purple : null;
    var d = res[0];
    var phishing = Array.isArray(res[1]) ? res[1] : [];
    var ex = d.execution || {};
    document.getElementById('exercise-detail-title').textContent = ex.name || ex.plan_id || 'Execution';
    // Phishing runs linked to this execution, described by the same view as the library.
    var phishingHtml = phishing.length ? '<h4 class="exd-h">Phishing runs linked to this execution</h4>' +
      phishing.map(function(run) {
        var v = describePhishingRun(run);
        var rows = (v.rows || []).map(function(r) { return '<div class="tiny muted">' + x(r.label) + ': ' + x(r.text) + '</div>'; }).join('');
        return '<div class="exd-phish"><div><b>' + x(v.scenarioId) + '</b> <span class="badge">' + x(v.status) + '</span></div>' +
          (v.note ? '<div class="tiny muted">' + x(v.note) + '</div>' : '') + rows + '</div>';
      }).join('') : '';
    document.getElementById('exercise-detail-body').innerHTML = execDetailHtml(id, d, { purpleHtml: purpleDebriefHtml(purple), phishingHtml: phishingHtml });
    document.getElementById('exercise-detail-overlay').classList.add('open');
  }).catch(function(e) { showToast('Could not load this execution: ' + ((e && e.message) || 'error'), 'err'); });
}

export function closeExerciseDetail() {
  document.getElementById('exercise-detail-overlay').classList.remove('open');
  _exDetailOpenId = null;
}
export function closeExerciseDetailOnBackdrop(el, event) { if (event.target === el) closeExerciseDetail(); }

export function approveExStep(id, stepId) {
  exCall('/api/exercises/executions/' + encodeURIComponent(id) + '/steps/' + encodeURIComponent(stepId) + '/approve', { method: 'POST' })
    .then(function() { showToast('Step approved', 'ok'); openExerciseDetail(id); })
    .catch(function(e) { showToast('Approve failed: ' + (e.message || 'error'), 'err'); });
}

export function abortExecutionStop(id, el, event) { event.stopPropagation(); abortExecution(id); }

export function abortExecution(id) {
  openConfirmDiffModal('Abort this exercise?',
    '<p class="exd-desc">Steps that have not run yet will be skipped. Anything already sent or executed is not undone.</p>',
    function() {
      exCall('/api/exercises/executions/' + encodeURIComponent(id) + '/abort', { method: 'POST' })
        .then(function() { showToast('Execution aborted', 'ok'); openExerciseDetail(id); loadExercisesTab(); })
        .catch(function(e) { showToast('Abort failed: ' + (e.message || 'error'), 'err'); });
    }, { sub: 'This stops the exercise now.', confirmLabel: 'Abort exercise' });
}

export function createPlanFromOpenAEV(id) {
  exCall('/api/openaev/scenarios/' + encodeURIComponent(id) + '/create-plan', { method: 'POST' })
    .then(function() { showToast('Exercise plan created', 'ok'); closeOpenAEVDetail(); focusNewPlanNext(); showTab('exercises'); })
    .catch(function(e) { showToast('Create failed: ' + (e.message || 'error'), 'err'); });
}

export function apNodePill(name, isTarget) {
  var col = isTarget ? 'var(--danger)' : 'var(--border)';
  var bg = isTarget ? 'rgba(218,54,51,0.12)' : 'var(--surface)';
  return '<span style="display:inline-block;padding:0.3rem 0.6rem;border:1px solid ' + col + ';background:' + bg +
    ';border-radius:6px;font-family:var(--font-mono);font-size:0.74rem;color:var(--text);white-space:nowrap">' + x(name) + '</span>';
}
export function apArrow(kind) {
  return '<span style="display:inline-flex;flex-direction:column;align-items:center;color:var(--muted);margin:0 0.1rem">' +
    '<span style="font-size:0.55rem;text-transform:uppercase;letter-spacing:0.04em">' + x(kind) + '</span>' +
    '<span style="font-size:1rem;line-height:0.7">&rarr;</span></span>';
}
function _fmtDuration(ms) {
  if (!ms || ms <= 0) return '—';
  var s = Math.round(ms / 1000);
  if (s < 60) return s + 's';
  return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
}

function _apUpdateMetaBar(d) {
  var bar = document.getElementById('ap-current-graph-bar');
  if (!bar) return;
  if (!d || !d.collected || !d.agentMeta || !d.agentMeta.length) {
    setDisplay(bar, 'none');
    return;
  }
  var m = d.agentMeta[0]; // most recently collected agent
  var ts = m.collectedAt ? new Date(m.collectedAt) : null;
  var tsStr = ts ? ts.toLocaleString('en-GB', {day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'}) : '—';
  var ageMs = ts ? Date.now() - ts.getTime() : 0;
  var ageStr = ageMs > 0 ? (ageMs >= 48 * 3600000 ? Math.floor(ageMs / 86400000) + 'd ago' : ago(ts.toISOString())) : '—';
  document.getElementById('ap-meta-ts').textContent = tsStr;
  document.getElementById('ap-meta-agent').textContent = m.hostname || m.agentId || '—';
  document.getElementById('ap-meta-edges').textContent = m.edgeCount != null ? m.edgeCount : '—';
  document.getElementById('ap-meta-age').textContent = ageStr;
  var fresh = apAgeChip(ageMs);
  var freshEl = document.getElementById('ap-meta-freshness');
  freshEl.textContent = fresh.label;
  freshEl.className = 'rk-chip tone-' + fresh.tone;
  setDisplay(bar, '');
}

// "Score breakdown" on the score card: reveals / hides the server-reported score drivers.
export function toggleAPScore() {
  var el = document.getElementById('ap-score-breakdown');
  var btn = document.getElementById('ap-score-toggle');
  if (!el) return;
  var open = el.classList.toggle('is-hidden') === false;
  if (btn) btn.textContent = 'Score breakdown ' + (open ? '▲' : '▼');
}

export function toggleAPHistory() {
  var p = document.getElementById('ap-history-panel');
  if (displayOf(p) === 'none' || !displayOf(p)) {
    apClosePanels('ap-history-panel');
    setDisplay(p, '');
    loadAPHistory();
  } else {
    setDisplay(p, 'none');
  }
}

function loadAPHistory() {
  var tb = document.getElementById('ap-history-body');
  if (!tb) return;
  tb.innerHTML = '<tr><td colspan="7" class="empty">Loading…</td></tr>';
  exCall('/api/attackpath/history?limit=20').then(function(rows) {
    if (!rows || !rows.length) {
      tb.innerHTML = '<tr><td colspan="7" class="empty">No collection history yet.</td></tr>';
      return;
    }
    tb.innerHTML = rows.map(function(r) {
      var ts = r.collectedAt ? new Date(r.collectedAt).toLocaleString('en-GB',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}) : '—';
      var statusBadge = r.status === 'completed'
        ? '<span class="u-success">&#10003; Completed</span>'
        : '<span class="u-danger"' + (r.errorMsg ? ' title="' + x(r.errorMsg) + '"' : '') + '>&#10005; ' + x(r.status) + (r.errorMsg ? ': ' + x(r.errorMsg.length > 60 ? r.errorMsg.slice(0, 60) + '…' : r.errorMsg) : '') + '</span>';
      return '<tr>' +
        '<td style="font-family:var(--font-mono);font-size:0.76rem">' + ts + '</td>' +
        '<td>' + x(r.hostname || r.agentId) + '</td>' +
        '<td style="text-align:right">' + (r.nodeCount || 0) + '</td>' +
        '<td style="text-align:right">' + (r.edgeCount || 0) + '</td>' +
        '<td style="text-align:right">' + _fmtDuration(r.durationMs) + '</td>' +
        '<td class="u-center">' + (r.sharpHound ? '&#10003;' : '&#8212;') + '</td>' +
        '<td>' + statusBadge + '</td>' +
        '</tr>';
    }).join('');
  }).catch(function(e) {
    tb.innerHTML = '<tr><td colspan="7" class="empty">' + x(e.message) + '</td></tr>';
  });
}

export function renderAttackPath(d, corr) {
  _apUpdateMetaBar(d);
  var body = document.getElementById('ap-body');
  if (!body) return;
  body.innerHTML = apRichBody(d, corr);
}