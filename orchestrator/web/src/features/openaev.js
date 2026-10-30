import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { ago, showToast } from '../core/util.js';
import { apColor } from './attack-path.js';
import { freshness as apAgeChip } from './ap-model.js';
import { apRichBody } from './rich-g4.js';
import { setExRows, setExError, setExPlans, setExPlansError } from './ex-view.js';
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
    apicall('/api/openaev/config', { method: 'DELETE' }).then(function() {
      showToast('OpenAEV config removed', 'ok');
      loadOpenAEVConfig();
    }).catch(function(e) { showToast('Remove failed: ' + (e.message || 'error'), 'err'); });
  });
}

function loadOpenAEVScenarios(type) {
  var kind = type === 'exercise' ? 'exs' : 'scen';
  apicall('/api/openaev/scenarios?type=' + encodeURIComponent(type || 'scenario')).then(function(list) {
    setExRows(kind, list);
  }).catch(function(e) { setExError(kind, e && e.message); });
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
  apicall('/api/openaev/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function() {
    showToast('OpenAEV config saved', 'ok');
    loadOpenAEVConfig();
  }).catch(function(e) { showToast('Save failed: ' + (e.message || 'error'), 'err'); });
}

export function syncOpenAEVNow() {
  apicall('/api/openaev/sync', { method: 'POST' }).then(function() {
    showToast('OpenAEV sync started', 'ok');
    loadOpenAEVConfig();
  }).catch(function(e) { showToast('Sync failed: ' + (e.message || 'error'), 'err'); });
}

export function openOpenAEVDetail(id) {
  apicall('/api/openaev/scenarios/' + encodeURIComponent(id)).then(function(d) {
    document.getElementById('openaev-detail-title').textContent = d.scenario.Name;
    var body = document.getElementById('openaev-detail-body');
    var injectsHtml = (d.detail.injects || []).map(function(inj) {
      return '<div class="kpi-row"><span>' + x(inj.title) + '</span><span class="tiny muted">' + x((inj.techniqueIds || []).join(', ')) + '</span></div>';
    }).join('');
    body.innerHTML = '<div class="tiny muted">' + x(d.detail.description || '') + '</div>' + injectsHtml;
    if (ROLE === 'admin') {
      body.innerHTML += '<div style="margin-top:1rem"><button class="btn btn-primary btn-sm"' + on('click', 'createPlanFromOpenAEV', id) + '>Create Exercise Plan</button></div>';
    }
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
  apicall('/api/exercises/plans').then(function(plans) {
    setExPlans(plans);
  }).catch(function(e) { setExPlansError(e && e.message); });

  apicall('/api/exercises/executions').then(function(execs) {
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
  apicall('/api/exercises/plans/' + encodeURIComponent(planId)).then(function(p) {
    var vars = p.variables || [];
    var values = {};
    for (var i = 0; i < vars.length; i++) {
      var v = vars[i];
      var ans = prompt('Value for "' + v.name + '"' + (v.description ? ' (' + v.description + ')' : '') + ':', v.default || '');
      if (ans === null) return;
      values[v.name] = ans;
    }
    apicall('/api/exercises/executions', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plan_id: planId, name: p.name, targets: [], variables: values })
    }).then(function(ex) {
      return apicall('/api/exercises/executions/' + encodeURIComponent(ex.id) + '/launch', { method: 'POST' });
    }).then(function() {
      showToast('Exercise launched', 'ok');
      loadExercisesTab();
    }).catch(function(e) { showToast('Launch failed: ' + (e.message || 'error'), 'err'); });
  }).catch(function(e) { showToast('Failed to load exercise plan: ' + (e.message || 'error'), 'err'); });
}

var _exDetailOpenId = null;
export function openExerciseDetail(id) {
  _exDetailOpenId = id;
  Promise.all([
    apicall('/api/exercises/executions/' + encodeURIComponent(id)),
    apicall('/api/exercises/executions/' + encodeURIComponent(id) + '/phishing-runs').catch(function() { return []; })
  ]).then(function(res) {
    var d = res[0];
    var phishing = Array.isArray(res[1]) ? res[1] : [];
    var ex = d.execution || {}, steps = d.steps || [];
    document.getElementById('exercise-detail-title').textContent = ex.name || ex.plan_id || 'Execution';
    var sc = ex.score;
    var scoreHtml;
    if (!sc) {
      scoreHtml = '<div class="tiny muted" style="margin-bottom:0.75rem">Not yet scored</div>';
    } else if (!sc.measurable) {
      // Nothing was sent and nothing was detected, so there is no result to
      // report. Say that plainly instead of rendering score.overall, which in
      // this state is a misleading 60 (see ExerciseScore.Measurable in
      // internal/exercise/types.go) that looks identical to a genuinely
      // excellent run.
      var sentCount = (sc.human && sc.human.sent) || 0;
      scoreHtml =
        '<div style="margin-bottom:0.75rem;padding:0.6rem 0.75rem;border:1px solid var(--border);border-left:3px solid var(--warning);border-radius:4px;background:var(--elevated)">' +
          '<div style="font-size:0.8rem;font-weight:600;color:var(--warning)">Not measurable — no result to report</div>' +
          '<div class="tiny muted" style="margin-top:0.25rem;line-height:1.6">' +
            'This exercise completed without producing anything measurable: ' + sentCount + ' inject(s) sent, ' +
            'and no EDR, SIEM, or ticketing signal observed. A score is deliberately withheld rather than ' +
            'shown as a number that would not mean anything. Add a step that actually sends an inject ' +
            '(email/SMS/agent task) to get a real result — approval and wait steps alone perform no ' +
            'technical action and cannot be scored.' +
          '</div>' +
        '</div>';
    } else {
      var hasSent = !!(sc.human && sc.human.sent > 0);
      scoreHtml =
        '<div class="kpi-row" style="margin-bottom:0.75rem">' +
        '<span class="badge">Overall ' + (sc.overall != null ? sc.overall.toFixed(0) : '—') + '</span>' +
        // 0 clicked of 0 sent is not "0% clicked" -- that reads as "nobody fell
        // for it" when nothing was ever sent. Only show a rate with a real
        // denominator.
        '<span class="badge">Click rate ' + ((hasSent && sc.human.click_rate != null) ? (sc.human.click_rate * 100).toFixed(0) + '% (' + (sc.human.clicked || 0) + '/' + sc.human.sent + ')' : '— n/a') + '</span>' +
        '<span class="badge">EDR ' + ((sc.technical && sc.technical.edr_detected) ? 'detected' : '— not detected') + '</span>' +
        '<span class="badge">SLA ' + ((sc.management && sc.management.sla_met) ? 'met' : '— n/a') + '</span>' +
        '</div>';
    }
    // What each step type actually does, so a row of "completed" badges can't
    // be mistaken for "something was tested". Approval/wait in particular
    // perform no technical action at all by design.
    var EX_STEP_WHAT = {
      approval:   'human approval gate — pauses for a person to approve; performs no technical action',
      wait:       'timed delay — performs no technical action',
      send_email: 'sends an email inject to the targets',
      send_sms:   'sends an SMS inject to the targets',
      agent_task: 'dispatches a task to the BAS agent on the endpoint',
      webhook:    'calls an external HTTP endpoint',
      notify:     'sends a notification',
      slack:      'sends a Slack message'
    };
    var stepsHtml = steps.map(function(s) {
      var canApprove = s.status === 'waiting' && s.step_type === 'approval';
      var what = EX_STEP_WHAT[s.step_type] || '';
      // Real per-step outcome the API already returns and this drawer used to
      // discard entirely -- the "no info, no result" gap.
      var detail = '';
      if (s.error) {
        detail = '<div class="tiny" style="color:var(--danger);margin-left:0.2rem">Error: ' + x(s.error) + '</div>';
      } else if (s.result && Object.keys(s.result).length) {
        detail = '<div class="tiny muted" style="margin-left:0.2rem;word-break:break-word">Result: ' + x(JSON.stringify(s.result)) + '</div>';
      } else if (s.status === 'completed' && (s.step_type === 'approval' || s.step_type === 'wait')) {
        detail = '<div class="tiny muted" style="margin-left:0.2rem">No technical action — nothing executed on any endpoint.</div>';
      }
      return '<div style="padding:0.4rem 0;border-bottom:1px solid var(--border)">' +
        '<div class="kpi-row" style="justify-content:space-between">' +
          '<span>' + x(s.step_id) + ' <span class="tiny muted">' + x(s.step_type) + '</span></span>' +
          '<span><span class="badge">' + x(s.status) + '</span>' +
          (canApprove ? ' <button class="btn btn-outline btn-sm"' + on('click', 'approveExStep', id, s.step_id) + '>Approve</button>' : '') +
          '</span>' +
        '</div>' +
        (what ? '<div class="tiny muted" style="margin-left:0.2rem">' + x(what) + '</div>' : '') +
        detail +
      '</div>';
    }).join('');
    var actions = (ex.status === 'running' || ex.status === 'paused') ?
      '<button class="btn btn-outline btn-sm"' + on('click', 'abortExecution', id) + '>Abort</button>' : '';
    // Phishing runs linked to this execution, described by the same view as the library.
    var phishingHtml = phishing.length ? '<div style="margin-bottom:0.75rem"><div class="tiny muted">Phishing runs linked to this execution</div>' +
      phishing.map(function(run) {
        var v = describePhishingRun(run);
        var rows = (v.rows || []).map(function(r) { return '<div class="tiny">' + x(r.label) + ': ' + x(r.text) + '</div>'; }).join('');
        return '<div style="padding:0.4rem 0;border-bottom:1px solid var(--border)"><span>' + x(v.scenarioId) + '</span> <span class="badge">' + x(v.status) + '</span>' +
          (v.note ? '<div class="tiny muted">' + x(v.note) + '</div>' : '') + rows + '</div>';
      }).join('') + '</div>' : '';
    document.getElementById('exercise-detail-body').innerHTML = scoreHtml + stepsHtml + phishingHtml + '<div style="margin-top:0.75rem">' + actions + '</div>';
    document.getElementById('exercise-detail-overlay').classList.add('open');
  }).catch(function() {});
}

export function closeExerciseDetail() {
  document.getElementById('exercise-detail-overlay').classList.remove('open');
  _exDetailOpenId = null;
}
export function closeExerciseDetailOnBackdrop(el, event) { if (event.target === el) closeExerciseDetail(); }

export function approveExStep(id, stepId) {
  apicall('/api/exercises/executions/' + encodeURIComponent(id) + '/steps/' + encodeURIComponent(stepId) + '/approve', { method: 'POST' })
    .then(function() { showToast('Step approved', 'ok'); openExerciseDetail(id); })
    .catch(function(e) { showToast('Approve failed: ' + (e.message || 'error'), 'err'); });
}

export function abortExecutionStop(id, el, event) { event.stopPropagation(); abortExecution(id); }

export function abortExecution(id) {
  if (!confirm('Abort this exercise execution?')) return;
  apicall('/api/exercises/executions/' + encodeURIComponent(id) + '/abort', { method: 'POST' })
    .then(function() { showToast('Execution aborted', 'ok'); openExerciseDetail(id); loadExercisesTab(); })
    .catch(function(e) { showToast('Abort failed: ' + (e.message || 'error'), 'err'); });
}

export function createPlanFromOpenAEV(id) {
  apicall('/api/openaev/scenarios/' + encodeURIComponent(id) + '/create-plan', { method: 'POST' })
    .then(function() { showToast('Exercise plan created', 'ok'); closeOpenAEVDetail(); showTab('exercises'); })
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
  var ageStr = ageMs > 0 ? ago(ts.toISOString()) : '—';
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
  apicall('/api/attackpath/history?limit=20').then(function(rows) {
    if (!rows || !rows.length) {
      tb.innerHTML = '<tr><td colspan="7" class="empty">No collection history yet.</td></tr>';
      return;
    }
    tb.innerHTML = rows.map(function(r) {
      var ts = r.collectedAt ? new Date(r.collectedAt).toLocaleString('en-GB',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}) : '—';
      var statusBadge = r.status === 'completed'
        ? '<span class="u-success">&#10003; Completed</span>'
        : '<span class="u-danger">&#10005; ' + x(r.status) + (r.errorMsg ? ': ' + x(r.errorMsg.slice(0,40)) : '') + '</span>';
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