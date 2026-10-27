import { state } from '../core/state.js';
import { on } from '../core/actions.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { ago, fmtDate, showToast } from '../core/util.js';
import { _templates, renderTemplateGrid } from './adversaries.js';
import { _agtDetailId, downloadAuditPack, downloadBoardScorecard, downloadFullReportCSV, downloadFullReportJSON, downloadFullReportPDF, downloadNavigatorLayer, loadAgtAttackPath, openAgentDetail, openFullReport, safeScan } from './agent-drawer.js';
import { openAllowReinstallModal, openReinstateAgentModal, openRemoveAgentModal, openRevokeAgentModal, openStopAgentModal, openUninstallAgentModal } from './agent-actions.js';
import { loadAuditLogs, loadBackups, loadLicenseInfo } from './audit-logs.js';
import { loadCalderaStatus } from './compliance.js';
import { syncDisplayPrefControls } from './display-prefs.js';
import { loadUsers } from './evidence.js';
import { loadOpenAEVConfig, renderAttackPath } from './openaev.js';
import { setHeroStat } from './shell-ui.js';
import { seg } from '../core/kit.js';
import { loadRuns, loadSIEMCorrelationPanel, openModal, viewRunResults } from './reports.js';
import { SCHED, renderScheduledAssessmentsList } from './scheduled.js';
import { describePhishingRun } from './phishing-run-view.js';
import { LIBRARY_TYPE_PHISHING, buildDispatchFields, buildPhishingRunRequest, libraryEntryRoute, phishingLibraryCounts, showNoScenariosMessage } from './scenario-library-route.js';
import { ROLE, setAgentsView, showTab } from './shell.js';
import { sourceOf as scnSourceOf, heroStats as scnHeroStats, filterList as scnFilterList, sortList as scnSortList, categoryRows as scnCategoryRows, showing as scnShowing } from './scn-model.js';
import { catsHtml as scnCatsHtml, toolbarHtml as scnToolbarHtml, gridHtml as scnGridHtml, emptyHtml as scnEmptyHtml, scnUi, setScenarioViewMode, setScenarioSortMode, setScenarioCatOffMode, hideFilterSelects, openDrawer as openScnDrawer, closeDrawer as closeScnDrawer, drawerTab, drawerScenarioId, paintDrawer, bindApproveButton, runById as scnRunById } from './scn-rich.js';
import { loadARTContentStatus, loadConnectorStatus, loadTAXIIConnectors, loadThreatIntelConfig } from './threat-intel.js';
import { displayOf, setCssText, setDisplay } from '../core/inline-style.js';
import { agentInsightsHtml, agentOperationalHtml, migrationPanelHtml } from './agents-insights.js';
import { kpi, card, chip, empty as kitEmpty, icon as kitIcon } from '../core/kit.js';
import { paintAgentTable, statusCellHtml, resetAgtFilters, agtOsFilter, setAgtOs } from './agt-view.js';
import { osOptions as agtOsOptions, fleetCount as agtFleetCount } from './agt-model.js';
import { renderExecAll, renderRangeSeg } from './dash-exec.js';
import { recLimit, renderRecControls, renderRecError, renderRecLoading, setRecLimitState, showRecommendations } from './recommendations.js';


// ── Attack Path Validation ─────────────────────────────────────────────────
export function loadAttackPath() {
  var body = document.getElementById('ap-body');
  if (body) body.innerHTML = '<div class="empty" style="padding:2rem">Loading…</div>';
  Promise.all([
    apicall('/api/attackpath/summary'),
    apicall('/api/attackpath/correlation').catch(function() { return null; })
  ]).then(function(res) {
    var d = res[0], corr = res[1];
    // Restore in-flight job state from server after a page reload.
    var saved = _apLoadJobId();
    if (saved && saved.jobId && !_apCurrentJobId) {
      apicall('/api/attackpath/jobs/' + saved.jobId).then(function(job) {
        var terminal = ['completed','failed','timed_out','delivery_failed','cancelled'];
        if (terminal.indexOf(job.status) === -1) {
          // Job still active — restore progress panel so the user can watch it.
          _apCurrentJobId = job.id;
          _apCollectAgentId = job.agentId;
          var panel = document.getElementById('ap-collect');
          if (panel) {
            setDisplay(panel, '');
            setDisplay(document.getElementById('ap-form'), 'none');
            setDisplay(document.getElementById('ap-progress'), '');
            _apRenderJobState(job);
          }
        } else if (job.status === 'completed') {
          _apClearJobId();
          showToast('Attack-path collection completed while you were away — results ready.', 'ok');
        } else {
          _apClearJobId();
          showToast('Attack-path job ended with status: ' + job.status, 'warn');
        }
      }).catch(function() { _apClearJobId(); });
    }
    renderAttackPath(d, corr);
  }).catch(function(e) { showToast(e.message, 'err'); });
}
export function apColor(score) {
  return score >= 80 ? 'var(--success)' : score >= 60 ? 'var(--warning)' : score >= 40 ? '#f0883e' : 'var(--danger)';
}
export function apBandColor(band) {
  return band === 'Low' ? 'var(--success)' : band === 'Medium' ? 'var(--warning)' : band === 'High' ? '#f0883e' : 'var(--danger)';
}
export function apFreshness(ageMs) {
  if (ageMs == null || ageMs < 0) return { label: '—', color: 'var(--muted)' };
  var hours = ageMs / 3600000;
  if (hours < 24) return { label: 'Fresh', color: 'var(--success)' };
  if (hours < 24 * 7) return { label: 'Aging', color: 'var(--warning)' };
  return { label: 'Stale', color: 'var(--danger)' };
}
export function apCard(label, val, col, sub) {
  return '<div class="kpi-card"><div class="kpi-label">' + label + '</div>' +
    '<div class="kpi-value" style="color:' + col + '">' + val + '</div>' +
    '<div class="tiny muted">' + (sub || '') + '</div></div>';
}

// Exposure Explorer (table, charts and detail drawer) lives in exp-view.js; re-exported so existing imports keep working.
export { loadExposureAssets, setExposureFilter, onExposureSearch, openExposureDetail, closeExposureDetail, closeExposureDetailOnBackdrop } from './exp-view.js';

var EXEC_DAYS = '90';
export function setExecRange(id) { EXEC_DAYS = id; renderRangeSeg(EXEC_DAYS); loadExecDashboard(); }

export function loadExecDashboard() {
  var days = EXEC_DAYS;
  renderRangeSeg(days);
  Promise.all([
    apicall('/api/dashboard/current'),
    apicall('/api/dashboard/trends?days=' + encodeURIComponent(days)),
    apicall('/api/predict/risk'),
    apicall('/api/findings').catch(function() { return []; })
  ]).then(function(res) {
    var cur = res[0] || {};
    setHeroStat('hs-exec-risk', cur.avgRiskScore != null ? cur.avgRiskScore : '—');
    setHeroStat('hs-exec-exposure', cur.hasAttackPathData ? cur.exposureScore : '—');
    setHeroStat('hs-exec-detect', cur.hasAttackPathData ? cur.detectionCoverage + '%' : '—');
    setHeroStat('hs-exec-fleet', cur.assetCount != null ? cur.assetCount : '—');
    renderExecAll({ current: cur, trends: res[1], predict: res[2], findings: Array.isArray(res[3]) ? res[3] : [], days: days });
  }).catch(function(e) { showToast(e.message, 'err'); });
}

var REC_SCENARIO = null;

// Technique Coverage (actor card, charts, table) lives in tcv-view.js; re-exported so existing imports keep working.
export { loadCoverageActors, loadCoverageMatrix, setCoverageFilter } from './tcv-view.js';

// Threat Prioritization (tier tiles, actor table and detail drawer) lives in tp-view.js; re-exported so existing imports keep working.
export { loadThreatPriorityActors, setThreatPriorityTier, showThreatPriorityDetail, showThreatPriorityList } from './tp-view.js';

export function loadRecommendations() {
  renderRecControls();
  renderRecLoading();
  apicall('/api/recommend/simulations?limit=' + encodeURIComponent(recLimit()))
    .then(function(data) { renderRecommendations(data); })
    .catch(function(e) { renderRecError(e.message); });
}

export function setRecLimit(v) {
  setRecLimitState(v);
  loadRecommendations();
}

function renderRecommendations(data) {
  REC_SCENARIO = (data && data.suggestedScenario) || null;
  showRecommendations(data);
}

export function copyRecommendedScenario() {
  if (!REC_SCENARIO || !REC_SCENARIO.artTechniques || !REC_SCENARIO.artTechniques.length) {
    showToast('Nothing to copy yet — load recommendations first.', 'err');
    return;
  }
  var text = REC_SCENARIO.artTechniques.join(', ');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function() {
      showToast('Copied ' + REC_SCENARIO.artTechniques.length + ' technique IDs — paste into the scenario builder.');
    }).catch(function() { showToast(text); });
  } else {
    showToast(text);
  }
}

// ── Attack Path Collection — job-based execution with full state machine ────────

var _apCollectAgentId = null; // agentId currently being collected (for WS matching)
var _apCurrentJobId   = null; // current job ID for WS event matching
var apActiveJobs      = {};   // agentId → {jobId,status} for agent-table badge

// Persist just the current job ID across page reloads so we can restore state from the server.
function _apSaveJobId(jobId, agentId) {
  try { localStorage.setItem('_apCurrentJob', JSON.stringify({jobId: jobId, agentId: agentId})); } catch(e) {}
}
function _apClearJobId() {
  try { localStorage.removeItem('_apCurrentJob'); } catch(e) {}
}
function _apLoadJobId() {
  try { return JSON.parse(localStorage.getItem('_apCurrentJob') || 'null'); } catch(e) { return null; }
}

// Legacy helpers kept for backward compat with loadAttackPath
function _apSavePending(agentId, agentLabel, targets, shEnabled, sharpHoundDelivered) {}
function _apClearPending() { _apClearJobId(); }
function _apLoadPending() { return null; }

export function apCollectClose() {
  setDisplay(document.getElementById('ap-collect'), 'none');
  _apCollectAgentId = null;
  _apCurrentJobId = null;
  _apClearJobId();
  // reset to form mode for next open
  setDisplay(document.getElementById('ap-form'), '');
  setDisplay(document.getElementById('ap-progress'), 'none');
  setDisplay(document.getElementById('ap-done-actions'), 'none');
}
export function apCollectViewResults() { loadAttackPath(); apCollectClose(); }
export function apAssetsClose() { setDisplay(document.getElementById('ap-assets'), 'none'); }
export function apScheduleClose() { setDisplay(document.getElementById('ap-schedule'), 'none'); }

export function openAPCollect() {
  var sel = document.getElementById('ap-agent');
  var panel = document.getElementById('ap-collect');
  // reset to configure mode
  setDisplay(document.getElementById('ap-form'), '');
  setDisplay(document.getElementById('ap-progress'), 'none');
  setDisplay(document.getElementById('ap-done-actions'), 'none');
  document.getElementById('ap-targets').value = '';
  document.getElementById('ap-target-count').textContent = '';

  // Show neutral current-graph context note if we have metadata
  var ctxEl = document.getElementById('ap-current-ctx');
  var ctxTs = document.getElementById('ap-current-ctx-ts');
  var metaTs = document.getElementById('ap-meta-ts');
  if (metaTs && metaTs.textContent && metaTs.textContent !== '—') {
    if (ctxTs) ctxTs.textContent = metaTs.textContent;
    if (ctxEl) setDisplay(ctxEl, '');
  } else {
    if (ctxEl) setDisplay(ctxEl, 'none');
  }

  function fill() {
    sel.innerHTML = (state.agents || []).map(function(a) {
      return '<option value="' + x(a.agentId) + '">' + x(a.hostname || a.agentId) + (a.status === 'offline' ? ' (offline)' : '') + '</option>';
    }).join('') || '<option value="">No agents enrolled</option>';
    setDisplay(panel, '');
  }
  if (!state.agents || !state.agents.length) {
    apicall('/api/agents').then(function(d) { state.agents = d || []; fill(); }).catch(function(e) { showToast(e.message, 'err'); });
  } else fill();
}

export function apCountTargets() {
  var lines = document.getElementById('ap-targets').value.split('\n').map(function(t) { return t.trim(); }).filter(Boolean);
  var el = document.getElementById('ap-target-count');
  el.textContent = lines.length ? lines.length + ' host' + (lines.length === 1 ? '' : 's') : '';
}

export function apDiscoverSubnet() {
  var agentId = document.getElementById('ap-agent').value;
  if (!agentId) { showToast('Select an agent first', 'err'); return; }
  var btn = document.getElementById('ap-discover-btn');
  btn.disabled = true;
  btn.textContent = 'Discovering…';
  apicall('/api/attackpath/subnet/' + encodeURIComponent(agentId)).then(function(r) {
    btn.disabled = false;
    btn.innerHTML = '&#128270; Discover Subnet';
    if (!r.targets || !r.targets.length) {
      showToast('No subnet info available for this agent yet — try heartbeating first.', 'err');
      return;
    }
    document.getElementById('ap-targets').value = r.targets.join('\n');
    apCountTargets();
    showToast('Populated ' + r.targets.length + ' hosts from ' + r.subnet + ' — review and edit before dispatching.', 'ok');
  }).catch(function(e) {
    btn.disabled = false;
    btn.innerHTML = '&#128270; Discover Subnet';
    showToast(e.message, 'err');
  });
}

// Renders a timeline step. state: 'done' | 'active' | 'pending' | 'warn'
function _apStep(stepState, title, detail) {
  var icon = stepState === 'done' ? '<span class="u-success">&#10003;</span>'
    : stepState === 'active' ? '<span style="animation:spin 1s linear infinite;display:inline-block">&#9696;</span>'
    : stepState === 'warn' ? '<span class="u-warning">&#9888;</span>'
    : '<span class="u-muted">&#9675;</span>';
  var titleColor = stepState === 'pending' ? 'var(--muted)' : 'var(--text)';
  return '<div style="display:flex;gap:0.7rem;align-items:flex-start;padding:0.55rem 0;border-bottom:1px solid var(--border)">' +
    '<div style="width:1.2rem;text-align:center;flex-shrink:0;margin-top:0.05rem;font-size:0.9rem">' + icon + '</div>' +
    '<div><div style="font-size:0.82rem;font-weight:600;color:' + titleColor + '">' + title + '</div>' +
    (detail ? '<div class="tiny muted" style="margin-top:0.2rem">' + detail + '</div>' : '') +
    '</div></div>';
}

function _apTimestamp() {
  return new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

export function dispatchAPCollect() {
  var agentId = document.getElementById('ap-agent').value;
  if (!agentId) { showToast('Select an agent', 'err'); return; }
  var targets = document.getElementById('ap-targets').value.split('\n').map(function(t) { return t.trim(); }).filter(Boolean);
  var agentLabel = document.getElementById('ap-agent').options[document.getElementById('ap-agent').selectedIndex].text;
  var payload = { agentId: agentId, targets: targets, segment: document.getElementById('ap-segment').value.trim(), runSharpHound: document.getElementById('ap-sharphound').checked };
  var shEnabled = payload.runSharpHound;

  apicall('/api/attackpath/jobs', { method: 'POST', body: JSON.stringify(payload) }).then(function(r) {
    _apCollectAgentId = agentId;
    _apCurrentJobId = r.job && r.job.id;
    if (_apCurrentJobId) _apSaveJobId(_apCurrentJobId, agentId);

    // Switch panel to progress timeline
    setDisplay(document.getElementById('ap-form'), 'none');
    setDisplay(document.getElementById('ap-progress'), '');

    var tl = document.getElementById('ap-timeline');
    var shNote = shEnabled ? (r.sharpHoundDelivered ? ' + SharpHound domain mapping' : ' (SharpHound binary not configured server-side — skipping)') : '';
    var shDetail = shEnabled && !r.sharpHoundDelivered ? 'SharpHound was requested but the binary is not configured on the server. TCP-only collection will proceed.' : '';

    var jobStatus = r.job && r.job.status;
    tl.innerHTML =
      _apStep('done', 'Collection started for ' + x(agentLabel) + ' at ' + _apTimestamp(),
        targets.length + ' target' + (targets.length === 1 ? '' : 's') + ' queued — job ' + (r.job ? r.job.id.slice(0,8) : '')) +
      (shDetail ? _apStep('warn', 'SharpHound notice', shDetail) : '') +
      _apStep(jobStatus === 'dispatched' || jobStatus === 'running' ? 'done' : 'active',
        jobStatus === 'dispatched' ? 'WS command sent — waiting for agent ACK…'
          : jobStatus === 'running' ? 'Agent acknowledged — probing the network…'
          : 'Dispatching to agent…',
        'TCP connect on SMB (445), WinRM (5985), RDP (3389)' + shNote) +
      _apStep('pending', 'Agent acknowledged (running)', '') +
      _apStep('pending', 'Collection received by server', '') +
      _apStep('pending', 'Graph built &amp; analysis complete', '');

    // Wire retry button if it exists in the panel
    var retryBtn = document.getElementById('ap-retry-btn');
    if (retryBtn) { retryBtn.onclick = function() { _apRetryJob(r.job && r.job.id); }; }
  }).catch(function(e) {
    showToast('Dispatch failed: ' + e.message, 'err');
  });
}

// Retry a failed or timed-out job by creating a new one from the same payload.
function _apRetryJob(jobId) {
  if (!jobId) return;
  apicall('/api/attackpath/jobs/' + jobId + '/retry', { method: 'POST' }).then(function(r) {
    _apCurrentJobId = r.id;
    if (r.id) _apSaveJobId(r.id, _apCollectAgentId);
    showToast('Retry job created — ' + r.id.slice(0,8), 'ok');
    _apRenderJobState(r);
  }).catch(function(e) { showToast('Retry failed: ' + e.message, 'err'); });
}

var _apStageLabels = {
  initializing:          'Initializing…',
  probing:               'Probing targets',
  enumerating_admins:    'Enumerating local admins',
  enumerating_sessions:  'Enumerating active sessions',
  running_sharphound:    'Running SharpHound',
  building_graph:        'Building graph',
  uploading:             'Uploading results'
};

// Render the timeline from a job object (status, progress, error).
function _apRenderJobState(job) {
  if (!job) return;
  var tl = document.getElementById('ap-timeline');
  if (!tl) return;
  var s = job.status;
  var prog = job.progress;

  var stageLabel = prog && prog.stage ? (_apStageLabels[prog.stage] || x(prog.stage)) : '';
  var pct = prog && prog.progressPercent > 0 ? prog.progressPercent : 0;
  var pctBar = (pct > 0 && pct < 100)
    ? '<div style="margin-top:0.3rem;width:100%;max-width:220px;background:var(--border);border-radius:4px;height:6px;overflow:hidden">' +
      '<div style="width:' + pct + '%;background:var(--accent);height:100%;border-radius:4px;transition:width 0.4s"></div></div>' +
      '<span style="font-size:0.72rem;color:var(--muted)">' + pct + '%</span>'
    : '';
  var progDetail = stageLabel
    + (prog && prog.targetsTotal > 0 ? ' — ' + prog.targetsCompleted + '/' + prog.targetsTotal + ' targets' : '')
    + (pctBar ? '<br>' + pctBar : '');

  var isTerminal = (s === 'completed' || s === 'failed' || s === 'timed_out' || s === 'delivery_failed' || s === 'cancelled');

  // Cancel button: visible while job is active (dispatched or running), hidden once terminal.
  var cancelEl = document.getElementById('ap-cancel-action');
  if (cancelEl) setDisplay(cancelEl, (!isTerminal && s !== 'queued') ? '' : 'none');

  // Step states by job status
  var dispatchState = (s === 'queued') ? 'active' : 'done';
  var ackState = s === 'queued' ? 'pending' : s === 'dispatched' ? 'active' : 'done';
  var probeState = (s === 'queued' || s === 'dispatched') ? 'pending' : (s === 'running') ? 'active' : 'done';
  var uploadState = (s === 'running' && prog && prog.stage === 'uploading') ? 'active' : (s === 'completed') ? 'done' : 'pending';
  var graphState  = s === 'completed' ? 'done' : 'pending';

  if (s === 'failed' || s === 'timed_out' || s === 'delivery_failed' || s === 'cancelled') {
    ackState = probeState = uploadState = graphState = 'warn';
  }

  var failReasonMap = {
    delivery_failed: 'Agent did not ACK the command — check agent connectivity.',
    timeout: 'Execution exceeded the allocated time window.',
    agent_offline: 'Agent went offline during collection.',
    upload_failed: 'Results upload failed.',
    cancelled: 'Cancelled by operator.',
    network_error: 'Network error during collection.',
    authentication_failed: 'Agent authentication failed.',
    permission_denied: 'Permission denied on the agent.'
  };
  var errorDisplay = failReasonMap[job.error] || (job.error ? x(job.error) : '');

  var statusLabel = {
    queued: 'Queued — waiting for agent to connect',
    dispatched: 'Command delivered — waiting for agent ACK…',
    running: stageLabel ? stageLabel : 'Execution in progress…',
    completed: 'Done',
    failed: 'Failed — ' + errorDisplay,
    timed_out: 'Timed out — ' + errorDisplay,
    delivery_failed: 'Delivery failed — ' + errorDisplay,
    cancelled: 'Cancelled — ' + (errorDisplay || 'by operator')
  }[s] || s;

  tl.innerHTML =
    _apStep(dispatchState, 'Job dispatched — ' + job.id.slice(0,8),
      job.targetCount > 0 ? job.targetCount + ' target' + (job.targetCount === 1 ? '' : 's') + ' queued' : '') +
    _apStep(ackState, statusLabel, '') +
    _apStep(probeState, 'Executing on agent', progDetail) +
    _apStep(uploadState, 'Uploading results…', '') +
    _apStep(graphState, 'Graph built &amp; analysis complete',
      job.metrics ? job.metrics.nodeCount + ' nodes · ' + job.metrics.edgeCount + ' edges' : '');

  if (isTerminal) {
    if (cancelEl) setDisplay(cancelEl, 'none');
    var doneDiv = document.getElementById('ap-done-actions');
    if (doneDiv) setDisplay(doneDiv, 'flex');
    var retryBtn2 = document.getElementById('ap-retry-btn');
    if (retryBtn2) setDisplay(retryBtn2, (s === 'completed') ? 'none' : '');
    var viewBtn = doneDiv && doneDiv.querySelector('button.btn-primary');
    if (viewBtn) setDisplay(viewBtn, (s === 'completed') ? '' : 'none');
  }
}

export function _apCancelJob() {
  if (!_apCurrentJobId) return;
  if (!confirm('Cancel this collection? The agent will complete any in-progress probe but no results will be stored.')) return;
  apicall('/api/attackpath/jobs/' + _apCurrentJobId + '/cancel', {method:'POST'})
    .then(function(r) { if (r && r.job) _apRenderJobState(r.job); })
    .catch(function(e) { showToast('Cancel failed: ' + e.message, 'err'); });
}

// Called from the WS onmessage handler for job lifecycle changes.
export function _apOnJobUpdate(msg) {
  if (!msg || !msg.data) return;
  var job = msg.data;
  var agentId = job.agentId || msg.agentId;
  // Update per-agent badge in the agents table regardless of panel state.
  var terminalStates = ['completed','failed','timed_out','delivery_failed','cancelled'];
  if (terminalStates.indexOf(job.status) !== -1) {
    delete apActiveJobs[agentId];
  } else if (agentId) {
    apActiveJobs[agentId] = { jobId: job.id, status: job.status };
  }
  renderAgentRows();
  // Refresh Attack Path tab in the agent detail drawer if it's showing this agent.
  if (_agtDetailId && _agtDetailId === agentId) {
    var apPane = document.getElementById('agt-tab-attackpath');
    if (apPane && displayOf(apPane) !== 'none') loadAgtAttackPath(agentId);
  }
  // Only update the progress panel if this is the panel's current job.
  if (_apCurrentJobId && job.id !== _apCurrentJobId) return;
  if (!_apCurrentJobId && job.id) {
    // Restore from WS if page was reloaded — only if panel is showing progress
    var saved = _apLoadJobId();
    if (!saved || saved.jobId !== job.id) return;
    _apCurrentJobId = job.id;
    _apCollectAgentId = agentId;
    setDisplay(document.getElementById('ap-form'), 'none');
    setDisplay(document.getElementById('ap-progress'), '');
  }
  _apRenderJobState(job);
  if (job.status === 'completed') {
    loadAttackPath();
    _apClearJobId();
    var da = document.getElementById('ap-done-actions');
    if (da) { setDisplay(da, 'flex'); var rb = document.getElementById('ap-retry-btn'); if (rb) setDisplay(rb, 'none'); }
    showToast('Attack-path collection complete — graph updated.', 'ok');
  } else if (job.status === 'timed_out') {
    showToast('Attack-path job timed out — agent did not complete in time.', 'warn');
  } else if (job.status === 'delivery_failed') {
    showToast('Attack-path delivery failed — check agent connectivity.', 'err');
  }
}

// Called from WS for real-time progress updates from agent heartbeats.
export function _apOnProgress(msg) {
  if (!msg || !msg.data) return;
  var d = msg.data;
  if (_apCurrentJobId && d.jobId !== _apCurrentJobId) return;
  if (displayOf(document.getElementById('ap-progress')) === 'none') return;
  // Synthesise a minimal job object so _apRenderJobState can re-render fully.
  _apRenderJobState({
    id: d.jobId || _apCurrentJobId || '',
    agentId: d.agentId || _apCollectAgentId || '',
    status: 'running',
    targetCount: 0,
    progress: d.progress || {}
  });
}

// Called from the WS handler when the server confirms a collection is stored (legacy event).
export function _apOnCollected(msg) {
  if (!msg || !msg.data) return;
  _apClearJobId();
  var d = msg.data;
  var tl = document.getElementById('ap-timeline');
  if (!tl) return;
  // If the job update already rendered completion, skip double-render.
  if (displayOf(document.getElementById('ap-done-actions')) !== 'none') return;

  var label = d.hostname || msg.agentId || 'agent';
  var nodes = d.nodes || 0;
  var edges = d.edges || 0;
  var step1Html = tl.children.length > 0 ? tl.children[0].outerHTML : _apStep('done', 'Command dispatched', '');
  step1Html = step1Html.replace(/animation:spin[^"]+/g, '').replace(/<span[^>]*>&#9696;<\/span>/, '<span class="u-success">&#10003;</span>').replace(/<span[^>]*>&#9675;<\/span>/, '<span class="u-success">&#10003;</span>');
  tl.innerHTML =
    step1Html +
    _apStep('done', 'Agent finished probing at ' + _apTimestamp(), x(label) + ' completed TCP probes across all targets.') +
    _apStep('done', 'Collection received — ' + nodes + ' node' + (nodes === 1 ? '' : 's') + ', ' + edges + ' lateral edge' + (edges === 1 ? '' : 's') + ' mapped',
      'The server has built the updated graph. Previous collection (if any) has been superseded by this result.') +
    _apStep('done', 'Graph analysis complete — results are ready', 'Attack path score, lateral movement risk, and domain reachability have been recalculated. Click View Results to review.');

  var doneDiv2 = document.getElementById('ap-done-actions');
  if (doneDiv2) { setDisplay(doneDiv2, 'flex'); var rb = document.getElementById('ap-retry-btn'); if (rb) setDisplay(rb, 'none'); }
  loadAttackPath();
  showToast(label + ': ' + nodes + ' nodes collected — attack path updated.', 'ok');
}

export function _onSIEMCorrelationComplete(msg) {
  if (!msg || !msg.data) return;
  var d = msg.data;
  var rate = d.detectionRate || 0;
  showToast('SIEM (' + (d.provider || 'qradar') + '): ' + rate + '% detection rate — ' +
    (d.detected || 0) + ' detected, ' + (d.undetected || 0) + ' missed.', rate >= 50 ? 'ok' : 'warn');
  if (d.runId) loadSIEMCorrelationPanel(d.runId);
}

export function _onRevalidationStarted(msg) {
  if (!msg || !msg.data) return;
  var d = msg.data;
  var status = d.status || '';
  var tech = d.techniqueId || '';
  var name = d.techniqueName ? (' — ' + d.techniqueName) : '';
  if (status === 'dispatched') {
    showToast('Auto-revalidation started: ' + tech + name + '. Check Live Runs for progress.', 'ok');
    loadRuns();
  } else if (status === 'no_scenario') {
    showToast('Auto-revalidation: no scenario for ' + tech + ' — re-validate manually via Remediations.', 'warn');
  } else if (status === 'error') {
    // Content Registry gate denial (revalidation.content_not_executable): the
    // scenario is not approved, so this is terminal until an operator approves it.
    showToast(d.message || ('Auto-revalidation of ' + tech + ' was blocked.'), 'err');
  }
}

var AP_ASSETS = [];
var AP_INPUT_STYLE = 'width:100%;padding:0.35rem 0.5rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:5px;font-size:0.78rem';
export function openAPAssets() {
  setDisplay(document.getElementById('ap-assets'), '');
  document.getElementById('ap-assets-body').innerHTML = '<tr><td colspan="5" class="empty">Loading…</td></tr>';
  apicall('/api/attackpath/assets').then(function(d) {
    AP_ASSETS = (d && d.assets) || [];
    renderAPAssets();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
var AP_CRIT_TIERS = ['', 'low', 'medium', 'high', 'critical'];
function renderAPAssets() {
  var tb = document.getElementById('ap-assets-body');
  if (!AP_ASSETS.length) {
    tb.innerHTML = '<tr><td colspan="7" class="empty">No hosts discovered yet — run a collection first.</td></tr>';
    return;
  }
  tb.innerHTML = AP_ASSETS.map(function(a, i) {
    var tierOpts = AP_CRIT_TIERS.map(function(t) {
      return '<option value="' + t + '"' + (a.criticalityTier === t ? ' selected' : '') + '>' + (t || '—') + '</option>';
    }).join('');
    return '<tr>' +
      '<td style="font-family:var(--font-mono);font-size:0.76rem">' + x(a.label || a.hostKey) +
        (a.label && a.label.toUpperCase() !== (a.hostKey || '').toUpperCase() ? '<div class="tiny muted">' + x(a.hostKey) + '</div>' : '') + '</td>' +
      '<td><input id="apt-cj-' + i + '" value="' + x(a.crownJewel || '') + '" placeholder="e.g. ERP, FileServer" style="' + AP_INPUT_STYLE + '"></td>' +
      '<td><input id="apt-seg-' + i + '" value="' + x(a.segment || '') + '" placeholder="e.g. server-vlan" style="' + AP_INPUT_STYLE + '"></td>' +
      '<td class="u-center"><input type="checkbox" id="apt-hv-' + i + '"' + (a.highValue ? ' checked' : '') + '></td>' +
      '<td><select id="apt-crit-' + i + '" style="' + AP_INPUT_STYLE + '">' + tierOpts + '</select></td>' +
      '<td style="font-size:0.72rem;white-space:nowrap">' +
        '<label style="margin-right:0.4rem"><input type="checkbox" id="apt-if-' + i + '"' + (a.internetFacing ? ' checked' : '') + '> Internet</label>' +
        '<label style="margin-right:0.4rem"><input type="checkbox" id="apt-ie-' + i + '"' + (a.identityExposed ? ' checked' : '') + '> Identity</label>' +
        '<label style="margin-right:0.4rem"><input type="checkbox" id="apt-prod-' + i + '"' + (a.production ? ' checked' : '') + '> Prod</label>' +
        '<input id="apt-cs-' + i + '" value="' + x((a.complianceScope || []).join(', ')) + '" placeholder="compliance scope, comma-sep" style="' + AP_INPUT_STYLE + ';margin-top:0.2rem;display:block;width:160px">' +
      '</td>' +
      '<td><button class="btn btn-outline btn-sm"' + on('click', 'saveAPAsset', i) + '>Save</button></td>' +
    '</tr>';
  }).join('');
}
export function saveAPAsset(i) {
  var a = AP_ASSETS[i];
  if (!a) return;
  var cs = document.getElementById('apt-cs-' + i).value.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
  var payload = {
    hostKey: a.hostKey, label: a.label || '',
    crownJewel: document.getElementById('apt-cj-' + i).value.trim(),
    segment: document.getElementById('apt-seg-' + i).value.trim(),
    highValue: document.getElementById('apt-hv-' + i).checked,
    criticalityTier: document.getElementById('apt-crit-' + i).value,
    internetFacing: document.getElementById('apt-if-' + i).checked,
    identityExposed: document.getElementById('apt-ie-' + i).checked,
    production: document.getElementById('apt-prod-' + i).checked,
    complianceScope: cs
  };
  apicall('/api/attackpath/assets', { method: 'POST', body: JSON.stringify(payload) }).then(function() {
    a.crownJewel = payload.crownJewel; a.segment = payload.segment; a.highValue = payload.highValue;
    a.criticalityTier = payload.criticalityTier; a.internetFacing = payload.internetFacing;
    a.identityExposed = payload.identityExposed; a.production = payload.production; a.complianceScope = payload.complianceScope;
    showToast('Saved ' + (a.label || a.hostKey), 'ok');
    loadAttackPath();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function openAPAbout() {
  setDisplay(document.getElementById('ap-about-backdrop'), '');
  setDisplay(document.getElementById('ap-about-modal'), '');
  document.getElementById('ap-about-modal').scrollTop = 0;
}
export function closeAPAbout() {
  setDisplay(document.getElementById('ap-about-backdrop'), 'none');
  setDisplay(document.getElementById('ap-about-modal'), 'none');
}

export function openAPSchedule() {
  var panel = document.getElementById('ap-schedule');
  setDisplay(panel, '');
  document.getElementById('ap-sched-last').textContent = '';
  apicall('/api/attackpath/schedule').then(function(s) {
    document.getElementById('ap-sched-enabled').checked = !!s.enabled;
    document.getElementById('ap-sched-interval').value = s.intervalMinutes || 1440;
    document.getElementById('ap-sched-targets').value = (s.targets || []).join('\n');
    document.getElementById('ap-sched-segment').value = s.segment || '';
    document.getElementById('ap-sched-sharphound').checked = !!s.runSharpHound;
    document.getElementById('ap-sched-last').textContent =
      s.lastRunAt ? 'Last run: ' + new Date(s.lastRunAt).toLocaleString() : 'Never run';
  }).catch(function(e) { showToast(e.message, 'err'); });
}
export function saveAPSchedule() {
  var interval = parseInt(document.getElementById('ap-sched-interval').value, 10);
  if (!interval || interval < 60) { showToast('Minimum interval is 60 minutes', 'err'); return; }
  var payload = {
    enabled: document.getElementById('ap-sched-enabled').checked,
    intervalMinutes: interval,
    targets: document.getElementById('ap-sched-targets').value.split('\n').map(function(t) { return t.trim(); }).filter(Boolean),
    segment: document.getElementById('ap-sched-segment').value.trim(),
    runSharpHound: document.getElementById('ap-sched-sharphound').checked
  };
  apicall('/api/attackpath/schedule', { method: 'POST', body: JSON.stringify(payload) }).then(function(r) {
    setDisplay(document.getElementById('ap-schedule'), 'none');
    showToast(r.enabled ? 'Scheduled collection enabled (every ' + r.intervalMinutes + ' min)' : 'Scheduled collection disabled', 'ok');
  }).catch(function(e) { showToast(e.message, 'err'); });
}


// Settings sub-section switcher — toggles the body panels + lazily loads each.
export function showSettingsSection(name) {
  state.SETTINGS_SECTION = name;
  ['users', 'engine', 'intel', 'taxii', 'art', 'audit', 'theme', 'dashprefs', 'license', 'backup'].forEach(function(s) {
    var el = document.getElementById('set-' + s);
    if (el) setDisplay(el, s === name ? '' : 'none');
    var nav = document.querySelector('[data-set="' + s + '"]');
    if (nav) nav.classList.toggle('active', s === name);
  });
  if (name === 'users') loadUsers();
  else if (name === 'engine') loadCalderaStatus();
  else if (name === 'intel') { loadConnectorStatus(); loadThreatIntelConfig('misp'); loadThreatIntelConfig('opencti'); loadThreatIntelConfig('otx'); loadTAXIIConnectors(); loadOpenAEVConfig(); }
  else if (name === 'taxii') loadTAXIIConnectors();
  else if (name === 'art') loadARTContentStatus();
  else if (name === 'audit') loadAuditLogs();
  else if (name === 'license') loadLicenseInfo();
  else if (name === 'theme') syncDisplayPrefControls();
  else if (name === 'dashprefs') syncDashPrefCards();
  else if (name === 'backup') loadBackups();
}
export function manageUsersLink() { showTab('settings'); showSettingsSection('users'); }

export function selectDashPref(pref) {
  localStorage.setItem('bas_dash_pref', pref);
  syncDashPrefCards();
}

function syncDashPrefCards() {
  var pref = localStorage.getItem('bas_dash_pref') || 'operational';
  ['operational', 'executive', 'last'].forEach(function(p) {
    var el = document.getElementById('dashpref-card-' + p);
    if (el) el.classList.toggle('active', p === pref);
  });
}

export function selectTheme(themeName) {
  // Only Dark and Light exist; a theme saved by an older build (cyberpunk, slate) falls back to Dark.
  if (themeName !== 'light') themeName = 'dark';
  document.body.classList.remove('theme-light');
  if (themeName !== 'dark') {
    document.body.classList.add('theme-' + themeName);
  }
  localStorage.setItem('audspect_theme', themeName);
  document.querySelectorAll('.theme-card').forEach(function(c) {
    c.classList.toggle('active', c.id === 'theme-card-' + themeName);
  });
}

var AGENT_FILTER = 'all';
// agentBucket: retired = uninstalled (see POST /api/agents/unenroll), excluded
// from every other bucket and from the default "All" list -- reachable only
// via the explicit Retired filter, so audit history stays visible without
// cluttering the live endpoint list; online = reachable + active; degraded =
// reachable but lifecycle state != active (quarantined/restricted); offline =
// no heartbeat.
export function agentBucket(a) {
  if (a.state === 'retired' || a.state === 'uninstalled') return 'retired';
  if (a.status === 'offline') return 'offline';
  if (a.state && a.state !== 'active') return 'degraded';
  return 'online';
}
function agentDotColor(b) { return b === 'online' ? 'var(--success)' : b === 'degraded' ? 'var(--warning)' : 'var(--muted)'; }

export var agentGroupTree = [];
var activeAgentGroupId = null; // null = "All" (no filter), otherwise a group id

export function loadAgentGroupTree() {
  apicall('/api/agent-groups').then(function(tree) {
    agentGroupTree = Array.isArray(tree) ? tree : [];
    renderAgentGroupTree();
  }).catch(function() { agentGroupTree = []; renderAgentGroupTree(); });
}

function renderAgentGroupTree() {
  var root = document.getElementById('agent-tree-root');
  if (!root) return;
  var fleet = state.agentTotals ? agtFleetCount(state.agentTotals) : 0;
  var allRow = '<div class="at-node' + (activeAgentGroupId === null ? ' active' : '') + '"' + on('click', 'selectAgentGroup', null) + '>' +
    '<span class="at-caret"></span><span class="at-ico">' + kitIcon('layers') + '</span><span class="at-name">All agents</span>' +
    (fleet ? '<span class="at-count">' + fleet + '</span>' : '') + '</div>';
  root.innerHTML = allRow + agentGroupTree.map(renderAgentGroupNode).join('');
}

function renderAgentGroupNode(node) {
  var hasChildren = node.children && node.children.length;
  var caret = hasChildren ? '&#9662;' : '';
  var active = activeAgentGroupId === node.id ? ' active' : '';
  var html = '<div class="at-node' + active + '"' + on('click', 'selectAgentGroup', node.id) + '>' +
    '<span class="at-caret">' + caret + '</span>' +
    '<span class="at-ico">' + kitIcon('server') + '</span>' +
    '<span class="at-name">' + x(node.name) + '</span>' +
    '<span class="at-count">' + node.totalAgentCount + '</span>' +
    '<span class="at-menu"' + on('click', 'openAgentGroupMenuStop', node.id) + '>&#8942;</span>' +
    '</div>';
  if (hasChildren) {
    html += '<div class="at-children">' + node.children.map(renderAgentGroupNode).join('') + '</div>';
  }
  return html;
}

export function selectAgentGroup(groupId) {
  activeAgentGroupId = groupId;
  renderAgentGroupTree();
  loadAgents();
}

export function openAgentGroupMenuStop(id, el, event) { event.stopPropagation(); openAgentGroupMenu(event, id); }

export function openAgentGroupMenu(ev, groupId) {
  var action = prompt('Type: rename / new / move / delete');
  if (action === 'rename') renameAgentGroupPrompt(groupId);
  else if (action === 'new') createAgentGroupPrompt(groupId);
  else if (action === 'move') moveAgentGroupPrompt(groupId);
  else if (action === 'delete') deleteAgentGroupConfirm(groupId);
}

export function createAgentGroupPrompt(parentId) {
  var name = prompt('New group name:');
  if (!name) return;
  apicall('/api/agent-groups', { method: 'POST', body: JSON.stringify({ name: name, parentId: parentId }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgentGroupTree(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

function renameAgentGroupPrompt(groupId) {
  var name = prompt('New name:');
  if (!name) return;
  apicall('/api/agent-groups/' + groupId, { method: 'PATCH', body: JSON.stringify({ name: name }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgentGroupTree(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// gpFlattenGroups walks the nested group tree depth-first into a flat list
// of {id, label} entries for the picker's <select>, indenting each label by
// its depth so the hierarchy stays legible in a flat list. excludeId (used
// only for the group-reparent flow) skips that one node's own entry -- its
// children are still included, since the backend's existing cycle check
// (agent_groups_handlers.go's UpdateAgentGroup) is the real guard against
// picking a deeper invalid target, not this client-side list.
export function gpFlattenGroups(nodes, depth, excludeId, out) {
  (nodes || []).forEach(function(n) {
    if (n.id !== excludeId) {
      out.push({ id: n.id, label: (depth > 0 ? '— '.repeat(depth) : '') + n.name });
    }
    if (n.children && n.children.length) gpFlattenGroups(n.children, depth + 1, excludeId, out);
  });
  return out;
}

// buildGroupDescendantMap walks the group tree once and returns, for every
// group id, the list of that group's own id plus every descendant group's id
// (post-order: children are resolved before their parent so parents can just
// concatenate their already-computed children's lists). Mirrors the same
// "selecting a parent surfaces its children's agents too" rule the backend
// applies in GET /api/agents?groupId= and jobs.Store.ResolveGroupAgentIDs.
function buildGroupDescendantMap(nodes) {
  var map = {};
  function walk(list) {
    (list || []).forEach(function(n) {
      var ids = [n.id];
      if (n.children && n.children.length) {
        walk(n.children);
        n.children.forEach(function(c) { ids = ids.concat(map[c.id]); });
      }
      map[n.id] = ids;
    });
  }
  walk(nodes);
  return map;
}

// resolveGroupTargetAgents returns every agent (from the global `agents` array)
// belonging to any of selectedGroupIds or their descendant groups. Pure client-side
// set math over already-loaded data -- no API call. Does not apply OS filtering;
// callers run the result through osEligibleAgents separately.
export function resolveGroupTargetAgents(selectedGroupIds) {
  if (!selectedGroupIds.length) return [];
  var map = buildGroupDescendantMap(agentGroupTree);
  var idSet = {};
  selectedGroupIds.forEach(function(gid) {
    (map[gid] || [gid]).forEach(function(id) { idSet[id] = true; });
  });
  return state.agents.filter(function(a) { return a.groupId != null && idSet[a.groupId]; });
}

var _gpMode = null, _gpContextId = null;

function openGroupPicker(mode, contextId) {
  _gpMode = mode;
  _gpContextId = contextId;
  document.getElementById('gp-title').textContent = mode === 'agent' ? 'Move Agent to Group' : 'Move Group to New Parent';
  var excludeId = mode === 'group' ? contextId : null;
  var options = gpFlattenGroups(agentGroupTree, 0, excludeId, []);
  var topLabel = mode === 'agent' ? '— Ungrouped —' : '— Root (no parent) —';
  document.getElementById('gp-select').innerHTML = '<option value="">' + topLabel + '</option>' +
    options.map(function(o) { return '<option value="' + x(o.id) + '">' + x(o.label) + '</option>'; }).join('');
  document.getElementById('group-picker-overlay').classList.add('open');
}

export function closeGroupPicker() {
  document.getElementById('group-picker-overlay').classList.remove('open');
  _gpMode = null;
  _gpContextId = null;
}

export function submitGroupPicker() {
  var selected = document.getElementById('gp-select').value;
  var groupId = selected === '' ? null : parseInt(selected, 10);
  var mode = _gpMode, contextId = _gpContextId;
  var url, body, onSuccess;
  if (mode === 'agent') {
    url = '/api/agents/' + encodeURIComponent(contextId) + '/group';
    body = { groupId: groupId };
    onSuccess = function() { loadAgents(); };
  } else {
    url = '/api/agent-groups/' + contextId;
    body = { parentId: groupId };
    onSuccess = function() { loadAgentGroupTree(); };
  }
  apicall(url, { method: 'PATCH', body: JSON.stringify(body) }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    closeGroupPicker();
    showToast('Moved', 'ok');
    onSuccess();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function moveAgentGroupPrompt(groupId) {
  openGroupPicker('group', groupId);
}

function deleteAgentGroupConfirm(groupId) {
  if (!confirm('Delete this group?')) return;
  fetch('/api/agent-groups/' + groupId, { method: 'DELETE', credentials: 'same-origin' })
    .then(function(r) {
      if (r.status === 204) { showToast('Group deleted', 'ok'); loadAgentGroupTree(); return; }
      r.json().then(function(j) { showToast(j.error || 'Delete failed', 'err'); });
    }).catch(function(e) { showToast(e.message, 'err'); });
}

export function moveAgentToGroupPrompt(agentId) {
  openGroupPicker('agent', agentId);
}

export function loadAgents() {
  var url = '/api/agents?limit=100' + (activeAgentGroupId !== null ? '&groupId=' + activeAgentGroupId : '');
  var searchEl = document.getElementById('agent-search');
  var q = searchEl ? searchEl.value.trim() : '';
  if (q) url += '&q=' + encodeURIComponent(q);
  if (AGENT_FILTER !== 'all') url += '&bucket=' + encodeURIComponent(AGENT_FILTER);
  return apicall(url).then(function(page) {
    state.agents = (page && page.items) || [];
    state.agentsNextCursor = (page && page.next_cursor) || '';
    state.agentsHasMore = !!(page && page.has_more);
    state.agentsPagesLoaded = 1;
    state.agentTotals = (page && page.totals) || { online: 0, degraded: 0, offline: 0, retired: 0 };
    renderAgentHero(); renderAgentInsights(); renderAgentToolbar(); renderAgentRows(); renderAgentGroupTree();
    renderLegacyMigrationPanel();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
function renderLegacyMigrationPanel() {
  var el = document.getElementById('legacy-migration-panel');
  if (!el) return;
  apicall('/api/agents/legacy-migration-status').then(function(status) {
    el.innerHTML = migrationPanelHtml(status, function(t) { return new Date(t).toLocaleString(); });
  }).catch(function(e) { showToast(e.message, 'err'); });
}
export function loadMoreAgents() {
  if (!state.agentsHasMore || !state.agentsNextCursor) return;
  var url = '/api/agents?limit=100&cursor=' + encodeURIComponent(state.agentsNextCursor) +
    (activeAgentGroupId !== null ? '&groupId=' + activeAgentGroupId : '');
  var searchEl = document.getElementById('agent-search');
  var q = searchEl ? searchEl.value.trim() : '';
  if (q) url += '&q=' + encodeURIComponent(q);
  if (AGENT_FILTER !== 'all') url += '&bucket=' + encodeURIComponent(AGENT_FILTER);
  return apicall(url).then(function(page) {
    state.agents = state.agents.concat((page && page.items) || []);
    state.agentsNextCursor = (page && page.next_cursor) || '';
    state.agentsHasMore = !!(page && page.has_more);
    state.agentsPagesLoaded++;
    // totals intentionally NOT updated here -- they were already
    // fleet-wide-accurate from the first page's response, and appending
    // more rows to `agents` doesn't change the true totals.
    renderAgentRows(); renderAgentInsights(); renderAgentToolbar();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
export function onAgentSearchInput() {
  clearTimeout(state.agentSearchDebounceTimer);
  state.agentSearchDebounceTimer = setTimeout(loadAgents, 300);
}
// Live WS pushes (agentUpdate/scenario_result) arrive per-agent -- on a large
// fleet, dozens can fire in a burst. Calling loadAgents() directly on each one
// would both hammer the API and silently collapse any "Load more" pages the
// operator had loaded back down to page 1. This debounces the burst into one
// refresh and re-walks back to the same page depth via loadMoreAgents().
export function requestAgentsLiveRefresh() {
  clearTimeout(state.agentLiveRefreshTimer);
  state.agentLiveRefreshTimer = setTimeout(function() {
    var targetDepth = state.agentsPagesLoaded;
    var chain = loadAgents();
    for (var i = 1; i < targetDepth; i++) chain = chain.then(loadMoreAgents);
  }, 800);
}
// statTileCard renders one label/value KPI tile (no footer line) -- the
// plain "kpi-card stat-tile" shape shared by the agent, SLA, and findings
// tile rows. Distinct from apCard (always shows a sub-line) and the
// footer/icon-bearing tile() variants defined locally where they're used.
export function statTileCard(lbl, val, col) {
  return '<div class="kpi-card stat-tile"><div class="stat-top"><div><div class="kpi-label">' + lbl +
    '</div><div class="kpi-value" style="color:' + col + '">' + val + '</div></div></div></div>';
}
// renderAgentHero fills the chips in the page banner from the server's own bucket totals.
function renderAgentHero() {
  var b = state.agentTotals;
  setHeroStat('hs-agents-total', b.online + b.degraded + b.offline);
  setHeroStat('hs-agents-online', b.online);
  setHeroStat('hs-agents-degraded', b.degraded);
  setHeroStat('hs-agents-offline', b.offline);
  setHeroStat('hs-agents-retired', b.retired);
}
// renderAgentInsights fills the KPI strip and distribution cards from the same page response the table uses.
function renderAgentInsights() {
  var el = document.getElementById('agent-insights');
  if (el) el.innerHTML = agentInsightsHtml(state.agents, state.agentTotals);
  var op = document.getElementById('agent-operational-insights');
  if (op) op.innerHTML = agentOperationalHtml(state.agents, state.agentTotals);
}
// covSegHtml renders the shared "cov-seg" toggle-button-group shape used by
// several toolbars below (agent/campaign/coverage/findings/run-IOC
// filters): one button per [value, label] item, 'on' when it matches
// activeVal, calling setterFnName(value) on click. countFn is optional --
// when given, each button also shows a dimmed count badge (countFn(value)).
export function covSegHtml(items, activeVal, setterFnName, countFn) {
  return '<div class="cov-seg">' + items.map(function(o) {
    var label = o[1] + (countFn ? ' <span style="opacity:.6">' + countFn(o[0]) + '</span>' : '');
    return '<button class="' + (activeVal === o[0] ? 'on' : '') + '"' + on('click', setterFnName, o[0]) + '>' + label + '</button>';
  }).join('') + '</div>';
}
function renderAgentToolbar() {
  var el = document.getElementById('agent-filter-selects');
  if (!el) return;
  var cur = AGENT_FILTER === 'all' ? '' : AGENT_FILTER;
  var os = agtOsFilter();
  var statuses = [['', 'All statuses'], ['online', 'Online'], ['degraded', 'Degraded'], ['offline', 'Offline'], ['retired', 'Retired']];
  var oses = agtOsOptions(state.agents);
  if (os && oses.indexOf(os) < 0) oses.push(os);
  var searchEl = document.getElementById('agent-search');
  var dirty = cur || os || (searchEl && searchEl.value.trim());
  el.innerHTML =
    '<select class="select" aria-label="Status"' + on('change', 'setAgentStatusSelect') + '>' + statuses.map(function(s) {
      return '<option value="' + x(s[0]) + '"' + (s[0] === cur ? ' selected' : '') + '>' + x(s[1]) + '</option>';
    }).join('') + '</select>' +
    '<select class="select" aria-label="Operating system"' + on('change', 'setAgentOsSelect') + '><option value="">All OS</option>' + oses.map(function(o) {
      return '<option value="' + x(o) + '"' + (o === os ? ' selected' : '') + '>' + x(o) + '</option>';
    }).join('') + '</select>' +
    (dirty ? '<button type="button" class="btn btn-ghost btn-sm"' + on('click', 'clearAgentFilters') + '>' + kitIcon('x') + 'Clear</button>' : '');
}
export function setAgentStatusSelect(el) { setAgentFilter((el && el.value) || 'all'); }
export function setAgentOsSelect(el) { setAgtOs(el); renderAgentToolbar(); }
export function clearAgentFilters() {
  AGENT_FILTER = 'all';
  var searchEl = document.getElementById('agent-search');
  if (searchEl) searchEl.value = '';
  resetAgtFilters();
  loadAgents();
}
export function setAgentFilter(v) { AGENT_FILTER = v; loadAgents(); }
function renderAgentRows() {
  // Server already scopes `agents` by bucket/search/group; the table layer only filters, sorts and pages
  // the loaded rows (agt-view.js).
  var searchEl = document.getElementById('agent-search');
  var q = searchEl ? searchEl.value.trim() : '';
  paintAgentTable({
    agents: state.agents,
    totals: state.agentTotals,
    hasMore: state.agentsHasMore,
    filtering: !!(q || AGENT_FILTER !== 'all' || activeAgentGroupId !== null),
    cells: agentCell,
  });
}
// One table cell. Column numbers follow agt-model.js COLUMNS; -1 is the trailing actions cell content.
function agentCell(a, col, idx) {
  var host = a.hostname || a.agentId;
  switch (col) {
    case 0:
      return '<td><div class="agt-host mono" title="' + x(host) + '">' + x(host) + '</div>' +
        '<div class="agt-sub muted" title="' + x(a.agentId) + '">' + x([a.ipAddress, a.agentId].filter(Boolean).join(' · ')) + '</div></td>';
    case 1: return '<td>' + (a.groupName ? x(a.groupName) : '<span class="muted">Ungrouped</span>') + '</td>';
    case 2: return '<td class="muted agt-os" title="' + x(a.osVersion || '') + '">' + x(a.osVersion || '—') + '</td>';
    case 3: return '<td>' + statusCellHtml(a, apActiveJobs[a.agentId]) + '</td>';
    case 4: return '<td class="muted agt-seen">' + ago(a.lastUpdate) + '</td>';
    case 5: return '<td class="num">' + (a.sims || 0) + '</td>';
    default: return agentRowMenu(a, idx);
  }
}
function agentRowMenu(a, idx) {
  var menuId = 'agent-menu-' + idx;
  return '<div class="row-menu-wrap">' +
        '<button class="btn btn-ghost btn-sm row-menu-btn"' + on('click', 'toggleRowMenuById', menuId) + ' title="Actions" aria-label="Actions" aria-haspopup="true">' + kitIcon('more') + '</button>' +
        '<div class="row-menu-panel" id="' + menuId + '">' +
          '<button class="row-menu-item"' + on('click', 'rowMenuDetail', a.agentId) + '>&#128269; Detail</button>' +
          '<button class="row-menu-item"' + on('click', 'rowMenuRunSimulation', a.agentId) + '>&#9654; Run simulation</button>' +
          '<button class="row-menu-item"' + on('click', 'rowMenuSafeScan', a.agentId) + '>&#128737; Safe Scan</button>' +
          '<button class="row-menu-item"' + on('click', 'rowMenuReportHtml', a.agentId) + '>&#128196; Report (HTML)</button>' +
          '<button class="row-menu-item"' + on('click', 'rowMenuReportPdf', a.agentId) + '>&#8595; Report (PDF)</button>' +
          '<button class="row-menu-item"' + on('click', 'rowMenuReportCsv', a.agentId) + '>&#8595; Report (CSV)</button>' +
          '<button class="row-menu-item"' + on('click', 'rowMenuReportJson', a.agentId) + '>&#8595; Report (JSON)</button>' +
          '<button class="row-menu-item"' + on('click', 'rowMenuBoardScorecard', a.agentId) + '>&#128202; Board scorecard (PDF)</button>' +
          '<button class="row-menu-item"' + on('click', 'rowMenuNavigator', a.agentId) + '>&#128506; ATT&amp;CK Navigator (JSON)</button>' +
          '<button class="row-menu-item"' + on('click', 'rowMenuAuditPack', a.agentId) + '>&#8659; Download audit pack</button>' +
          (ROLE === 'admin' ?
            '<button class="row-menu-item"' + on('click', 'rowMenuMoveGroup', a.agentId) + '>&#128193; Move to group…</button>' : '') +
          (ROLE === 'admin' && a.status !== 'offline' ?
            '<button class="row-menu-item row-menu-item-danger"' + on('click', 'rowMenuStopAgent', a.agentId, a.hostname || a.agentId) + '>&#9209; Stop agent</button>' : '') +
          (ROLE === 'admin' ?
            '<button class="row-menu-item row-menu-item-danger"' + on('click', 'rowMenuUninstallAgent', a.agentId, a.hostname || a.agentId) + '>&#128465; Uninstall Agent</button>' : '') +
          agentRevokeMenuItems(a, ROLE === 'admin') +
          (ROLE === 'admin' ?
            '<button class="row-menu-item row-menu-item-danger"' + on('click', 'rowMenuRemoveAgent', a.agentId, a.hostname || a.agentId) + '>&#9888; Force Remove…</button>' : '') +
        '</div>' +
        '</div>';
}
export function agentRowKeydown(id, el, event) {
  if (event && (event.key === 'Enter' || event.key === ' ') && event.target === el) { event.preventDefault(); rowMenuDetail(id); }
}
// Row action menus (the "⋮" dropdown in the Agents table Actions column).
// Only one panel is ever open at a time; toggling re-closes any other open
// panel first so stale menus never linger behind a newly opened one.
export function toggleRowMenuById(id, el, event) { event.stopPropagation(); toggleRowMenu(el, id); }

export function openModalForScenario(id) { openModal(id, null); }

// Agent row-menu items: close the menu, then run the item's action.
export function rowMenuDetail(id) { closeAllRowMenus(); openAgentDetail(id); }
export function rowMenuRunSimulation(id) { closeAllRowMenus(); openModal(null, id); }
export function rowMenuSafeScan(id) { closeAllRowMenus(); safeScan(id); }
export function rowMenuReportHtml(id) { closeAllRowMenus(); openFullReport(id); }
export function rowMenuReportPdf(id) { closeAllRowMenus(); downloadFullReportPDF(id); }
export function rowMenuReportCsv(id) { closeAllRowMenus(); downloadFullReportCSV(id); }
export function rowMenuReportJson(id) { closeAllRowMenus(); downloadFullReportJSON(id); }
export function rowMenuAuditPack(id) { closeAllRowMenus(); downloadAuditPack(id); }
export function rowMenuBoardScorecard(id) { closeAllRowMenus(); downloadBoardScorecard(id); }
export function rowMenuNavigator(id) { closeAllRowMenus(); downloadNavigatorLayer(id); }
export function rowMenuMoveGroup(id) { closeAllRowMenus(); moveAgentToGroupPrompt(id); }
export function rowMenuStopAgent(id, hostname) { closeAllRowMenus(); openStopAgentModal(id, hostname); }
export function rowMenuUninstallAgent(id, hostname) { closeAllRowMenus(); openUninstallAgentModal(id, hostname); }
export function rowMenuAllowReinstall(id, hostname) { closeAllRowMenus(); openAllowReinstallModal(id, hostname); }
export function rowMenuRevokeAgent(id, hostname) { closeAllRowMenus(); openRevokeAgentModal(id, hostname); }
export function rowMenuReinstateAgent(id, hostname) { closeAllRowMenus(); openReinstateAgentModal(id, hostname); }

// The Revoke / Reinstate entries of an agent's row menu. Admin only (the server enforces it too). A
// retired or uninstalled agent has nothing to revoke; a revoked one can only be reinstated.
export function agentRevokeMenuItems(a, isAdmin) {
  if (!isAdmin || a.state === 'retired' || a.state === 'uninstalled') return '';
  if (a.state === 'revoked') {
    return '<button class="row-menu-item"' + on('click', 'rowMenuReinstateAgent', a.agentId, a.hostname || a.agentId) + '>&#8617; Reinstate…</button>';
  }
  return '<button class="row-menu-item"' + on('click', 'rowMenuAllowReinstall', a.agentId, a.hostname || a.agentId) + '>&#8635; Allow reinstall…</button>' +
    '<button class="row-menu-item row-menu-item-danger"' + on('click', 'rowMenuRevokeAgent', a.agentId, a.hostname || a.agentId) + '>&#128683; Revoke…</button>';
}
export function rowMenuRemoveAgent(id, hostname) { closeAllRowMenus(); openRemoveAgentModal(id, hostname); }

export function toggleRowMenu(btn, id) {
  var panel = document.getElementById(id);
  if (!panel) return;
  var wasOpen = panel.classList.contains('open');
  closeAllRowMenus();
  if (wasOpen) return;
  // Position as fixed viewport coordinates from the trigger button's own
  // rect (see the .row-menu-panel CSS comment for why fixed instead of
  // absolute), right-aligned under the button like a standard menu.
  var btnRect = btn.getBoundingClientRect();
  panel.style.right = (window.innerWidth - btnRect.right) + 'px';
  panel.style.left = 'auto';
  panel.style.top = (btnRect.bottom + 4) + 'px';
  panel.style.bottom = 'auto';
  panel.style.maxHeight = 'none';
  panel.classList.add('open');
  // Now that it's rendered, clamp it to the viewport -- a menu opened near
  // the bottom of the screen would otherwise extend past the bottom edge
  // with no way to reach the remaining items.
  var margin = 8;
  var panelRect = panel.getBoundingClientRect();
  if (panelRect.bottom > window.innerHeight - margin) {
    var spaceBelow = window.innerHeight - btnRect.bottom - 4 - margin;
    var spaceAbove = btnRect.top - 4 - margin;
    if (spaceAbove > spaceBelow) {
      panel.style.top = 'auto';
      panel.style.bottom = (window.innerHeight - btnRect.top + 4) + 'px';
      panel.style.maxHeight = Math.max(spaceAbove, 80) + 'px';
    } else {
      panel.style.maxHeight = Math.max(spaceBelow, 80) + 'px';
    }
  }
}
export function closeAllRowMenus() {
  document.querySelectorAll('.row-menu-panel.open').forEach(function(p) { p.classList.remove('open'); });
}
export function __init_L8485() {
document.addEventListener('click', function(e) {
  if (!e.target.closest('.row-menu-wrap')) closeAllRowMenus();
});
}

// A fixed-position panel doesn't track its trigger button on scroll -- close
// it instead of letting it visually drift away from the row it belongs to.
export function __init_L8490() {
window.addEventListener('scroll', closeAllRowMenus, true);
}

// Connection Config (hero button, admin only): open the Operational view at the connection settings.
export function showConnectionConfig() {
  setAgentsView('operational');
  var w = document.getElementById('conn-cfg-wrap');
  if (!w) return;
  setDisplay(w, '');
  if (typeof loadConnectionConfig === 'function') loadConnectionConfig();
  w.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Deploy agent -> open the Operational view at the download / install section (the connection settings
// above it are revealed too, as before).
export function showAgentDownload() {
  setAgentsView('operational');
  var w = document.getElementById('conn-cfg-wrap');
  if (!w) return;
  setDisplay(w, '');
  if (typeof loadConnectionConfig === 'function') loadConnectionConfig();
  var d = document.getElementById('agent-deploy-section');
  (d || w).scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// buildAgentInstallCommands returns the copy-paste install one-liners for each
// OS. It is pure (no DOM, no network) so it can be unit-tested directly.
//
//   origin  the dashboard origin the admin is browsing (window.location.origin)
//           -- used only as the fallback CA-fetch URL when data.caRootPem is
//           unavailable (see below).
//   host    the hostname agents should reach the orchestrator at
//           (window.location.hostname).
//   data    the /api/config/connection response; data.mtlsPort / data.enrollPort
//           are the advertised HOST ports (see config.AdvertisedMTLSPort),
//           defaulting to 9443/9444 for a non-remapped deployment.
//           data.caRootPem, when present, is written directly into the
//           generated command (see below) instead of being fetched again.
//
// Writing the CA root bytes directly into the command, rather than having
// the command fetch them itself, closes a real gap: data.caRootPem already
// arrived over THIS admin's own authenticated dashboard session
// (/api/config/connection is RBAC-gated), so embedding it here means the
// generated command never asks serverURL for a CA root at all -- if
// serverURL were ever wrong (a tampered clipboard, a copy-paste mistake, a
// compromised intermediary), it can no longer hand back its OWN rogue CA
// to be trusted. This falls back to the old unauthenticated curl -k fetch
// only when caRootPem is unavailable (PKI not configured server-side, or
// an older orchestrator build) -- the same residual bootstrap-TOFU
// exposure that existed before this existed, never worse, and still
// honestly present in that one fallback case.
//
// Each command still: (1) installs against the mTLS listener
// (host:mtlsPort), NOT the dashboard port; (2) passes --enroll-port so CSR
// bootstrap reaches the enrollment listener even when its published port
// was remapped. Omitting either strands the agent on legacy transport: it
// never receives the command-signing trust cert and every dispatched
// scenario silently fails.
export function buildAgentInstallCommands(origin, host, data) {
  data = data || {};
  var mtlsPort = data.mtlsPort || '9443';
  var enrollPort = data.enrollPort || '9444';
  var serverURL = 'https://' + host + ':' + mtlsPort;
  var caURL = origin + '/api/config/ca-root';
  var common = ' --install --server ' + serverURL + ' --enroll-port ' + enrollPort;
  var caRootPem = (data.caRootPem || '').trim();
  var dashPort = (origin.match(/:([0-9]+)$/) || [null, '9543'])[1];
  var linuxEnv = 'BAS_SERVER_HOST=' + host + ' BAS_ENROLL_PORT=' + enrollPort + ' BAS_MTLS_PORT=' + mtlsPort + ' BAS_DASHBOARD_PORT=' + dashPort;
  // Every OS gets one line. The CA travels as base64 on that line, so nothing multi-line is pasted
  // into a shell or PowerShell (a heredoc or here-string loses its end marker when pasted).
  var b64 = caRootPem ? window.btoa(caRootPem) : '';

  var linuxCaCmd = caRootPem
    ? 'echo ' + b64 + ' | base64 -d > deployment-ca.pem'
    : 'curl -fsSk -o deployment-ca.pem ' + caURL;
  var macCaCmd = caRootPem
    ? 'echo ' + b64 + ' | openssl base64 -d -A > deployment-ca.pem'
    : 'curl -fsSk -o deployment-ca.pem ' + caURL;
  var winCaCmd = caRootPem
    ? "[IO.File]::WriteAllBytes('deployment-ca.pem', [Convert]::FromBase64String('" + b64 + "'))"
    : 'curl.exe -fsSk -o deployment-ca.pem ' + caURL;

  return {
    serverURL: serverURL,
    // No --secret here: the agent now prompts for it interactively when
    // omitted (promptSecret in agent/promptsecret.go), so pasting this
    // command and running it is the only step -- the secret is typed once,
    // live, never baked into the command text, shell history, or a process
    // listing.
    windows: winCaCmd + '; .\bas-agent-windows-amd64.exe' + common + ' --ca-root .\deployment-ca.pem --env Production',
    linux: linuxCaCmd + ' && curl -fsSk -o install-agent-linux.sh ' + origin + '/api/agent/install-script' +
      ' && sudo env ' + linuxEnv + ' bash install-agent-linux.sh --ca-file ./deployment-ca.pem',
    mac: macCaCmd + ' && xattr -d com.apple.quarantine bas-agent-darwin-* && chmod +x bas-agent-darwin-* && ' +
      'sudo ./bas-agent-darwin-*' + common + ' --ca-root ./deployment-ca.pem --env Production',
  };
}

// injectServerURL fetches the advertised connection config and writes the
// per-OS install commands into the Deploy Agent page. It falls back to
// browser-derived defaults if the config call fails, so the page is never left
// showing a placeholder URL.
export function injectServerURL() {
  var apply = function(data) {
    var c = buildAgentInstallCommands(window.location.origin, window.location.hostname, data);
    var set = function(id, v) { var el = document.getElementById(id); if (el) el.textContent = v; };
    set('win-server-url', c.serverURL);
    set('win-cli-cmd', c.windows);
    set('linux-cli-cmd', c.linux);
    set('mac-cmd', c.mac);
  };
  apicall('/api/config/connection').then(apply).catch(function() { apply({}); });
}

// formatFingerprint groups a SHA-256 fingerprint (64 hex characters) in uppercase blocks of 8 so an
// operator can compare it by eye with the one shown by the installer. Anything else returns '' so
// a malformed value is never shown as if it were a fingerprint.
export function formatFingerprint(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) return '';
  return hex.toUpperCase().match(/.{8}/g).join(' ');
}

export function loadConnectionConfig() {
  apicall('/api/config/connection').then(function(data) {
    var wrap = document.getElementById('conn-cfg-wrap');
    if (!wrap) return;
    setDisplay(wrap, '');
    document.getElementById('cfg-server-url').textContent = window.location.origin;
    var secretEl = document.getElementById('cfg-agent-secret');
    secretEl.dataset.value = data.agentSecret || '';
    // The deployment signing fingerprint is the trust anchor for the Windows MSI bundle: operators
    // compare it with the one the installer shows. It comes from this authenticated call only.
    var fpRow = document.getElementById('cfg-fingerprint-row');
    var fpEl = document.getElementById('cfg-deployment-fingerprint');
    var fpText = formatFingerprint(data.deploymentSigningFingerprint);
    if (fpRow && fpEl) {
      fpEl.textContent = fpText;
      fpEl.dataset.value = fpText ? data.deploymentSigningFingerprint.toLowerCase() : '';
      setDisplay(fpRow, fpText ? '' : 'none');
    }
    // keep masked until user clicks Show
  }).catch(function(e) { showToast('Failed to load connection config: ' + (e.message || 'error'), 'err'); });
}

export function toggleSecret(btn) {
  var el = document.getElementById('cfg-agent-secret');
  var hidden = el.classList.contains('secret-hidden');
  if (hidden) {
    el.textContent = el.dataset.value || '(not configured)';
    el.classList.remove('secret-hidden');
    btn.textContent = 'Hide';
  } else {
    el.textContent = '••••••••••••••••••••••••';
    el.classList.add('secret-hidden');
    btn.textContent = 'Show';
  }
}

export function copyText(elId, btn) {
  var el = document.getElementById(elId);
  // Use data-value when the attribute exists (even if empty string) so masked
  // elements like the agent secret copy the real value, not the bullet placeholder.
  var text = el.hasAttribute('data-value') ? el.dataset.value : el.textContent;
  function onSuccess() {
    var orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(function() { btn.textContent = orig; }, 1500);
  }
  function onFail() { showToast('Copy failed', 'err'); }
  // navigator.clipboard requires a secure context (HTTPS/localhost).
  // Fall back to execCommand for plain-HTTP deployments.
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(onSuccess).catch(onFail);
  } else {
    var ta = document.createElement('textarea');
    ta.value = text;
    setCssText(ta, 'position:fixed;opacity:0;pointer-events:none');
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy') ? onSuccess() : onFail(); } catch(e) { onFail(); }
    document.body.removeChild(ta);
  }
}

// loadCatalogs fetches the live ART + Caldera catalogs so sweep cards show a
// real technique/ability count and the picker has data. Best-effort: a failure
// (e.g. Caldera offline) just leaves that count blank — it never blocks the UI.
// Re-renders the scenario grid once loaded so counts appear without a refresh.
export function loadCatalogs() {
  // apicall resolves even on HTTP errors (the body is the JSON error object), so
  // guard with Array.isArray — an error body must not be mistaken for a catalog.
  apicall('/api/art/techniques').then(function(d) {
    state.artCatalog = Array.isArray(d) ? d : [];
    if (state.scenarios.length) renderScenarios();
  }).catch(function() {});
  apicall('/api/caldera/abilities').then(function(d) {
    state.calderaCatalog = Array.isArray(d) ? d : [];
    if (state.scenarios.length) renderScenarios();
  }).catch(function() {});
}

export function loadScenarios() {
  apicall('/api/scenarios').then(function(data) {
    state.scenarios = (data || []).map(function(s) {
      return {
        id:                 s.id                 || '',
        name:               s.name               || '',
        description:        s.description         || '',
        author:             s.author              || '',
        tags:               s.tags               || [],
        steps:              s.steps              || [],
        mitrePhases:        s.mitrePhases        || [],
        productLine:        s.productLine        || '',
        source:             s.source             || 'builtin',
        executable:         !!s.executable,
        localCheck:         !!s.localCheck,
        calderaAllWindows:  !!s.calderaAllWindows,
        calderaAbilities:   s.calderaAbilities   || [],
        calderaAdversaryId: s.calderaAdversaryId || '',
        artAllWindows:      !!s.artAllWindows,
        artAllPlatform:     !!s.artAllPlatform,
        artSelectiveWindows:  !!s.artSelectiveWindows,
        artSelectivePlatform: !!s.artSelectivePlatform,
        intelSource:        s.intelSource         || '',
        intelActor:         s.intelActor          || '',
        intelConfidence:    s.intelConfidence      || '',
        artTechniques:      s.artTechniques       || [],
        supportedOs:        s.supportedOs         || [],
        registry:           s.registry            || null
      };
    });
    _scnLoadedAt = new Date();
    renderScenarios();
    loadRegistryMigrationBanner();
    // renderScheduledAssessmentsList() looks up each schedule's human name
    // from this scenarios array client-side, falling back to the raw
    // scenario ID when not found. loadScenarios() and
    // loadScheduledAssessments() fire independently at boot with no
    // ordering guarantee -- on a fresh page load, if the schedules list
    // rendered first, it's stuck showing the raw ID until something
    // re-renders it. Re-render now that scenarios is actually populated.
    if (SCHED.schedules.length) renderScheduledAssessmentsList();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

// Approvable: the latest version is a DRAFT/VALIDATED intel or custom one and
// either nothing is executable yet or it is newer than the executable one
// (e.g. an approved intel id's regenerated DRAFT). role defaults to the
// signed-in role (parameter for tests).
export function canApproveForLocal(s, role) {
  if (role === undefined) role = ROLE;
  var r = s.registry;
  if (role !== 'admin' || !r || !(s.source === 'intel' || s.source === 'custom')) return false;
  if (r.latestLifecycle !== 'DRAFT' && r.latestLifecycle !== 'VALIDATED') return false;
  return !r.executableVersion || r.latestVersion > r.executableVersion;
}

function approveButton(s) {
  return '<button class="btn btn-outline btn-sm"' + on('click', 'approveForLocalUse', s.id, s.registry.latestVersionId) + '>&#10003; Approve</button> ';
}

// Approve-for-local-use is a deliberate, in-page confirmation (no
// window.prompt/confirm): it loads the exact version first and shows what it
// will run -- step count, ART techniques, safety verdicts, a link to the
// stored bytes -- and stays disabled until the operator ticks the review box
// and gives a reason. All server text goes through x().
var _approveTarget = null; // { id, versionId } of the loaded version
var _approveSeq = 0;        // request token: only the latest load may render

export function approveForLocalUse(id, versionId) {
  var body = document.getElementById('approve-local-body');
  var overlay = document.getElementById('approve-local-overlay');
  if (!body || !overlay) return;
  _approveTarget = null;
  var tok = ++_approveSeq;
  document.getElementById('approve-local-ack').checked = false;
  document.getElementById('approve-local-reason').value = '';
  document.getElementById('approve-local-submit-btn').disabled = true;
  body.innerHTML = '<p class="sub2">Loading version&hellip;</p>';
  overlay.classList.add('open');
  apicall('/api/content-registry/versions/' + encodeURIComponent(versionId)).then(function(d) {
    if (tok !== _approveSeq) return; // a later click (or close) superseded this load
    if (!d || d.error) throw new Error((d && d.error) || 'version not found');
    if (d.id !== versionId || d.contentId !== id) throw new Error('version does not match this scenario');
    body.innerHTML = approveSummaryHTML(d);
    _approveTarget = { id: id, versionId: versionId };
    approveLocalAckChanged();
  }).catch(function(e) {
    if (tok !== _approveSeq) return;
    body.innerHTML = '<p class="u-danger">Could not load the version to review: ' + x(e.message) + '</p>';
  });
}

function approveSummaryHTML(d) {
  var steps = (d.stepCount === null || d.stepCount === undefined) ? 'unreadable artifact' : String(d.stepCount);
  var techs = d.artTechniques || [];
  var techList = techs.slice(0, 20).join(', ') + (techs.length > 20 ? ', … (+' + (techs.length - 20) + ')' : '');
  var verdicts = Array.isArray(d.safetyVerdicts) ? d.safetyVerdicts : [];
  var safety = verdicts.length
    ? verdicts.map(function(v) { return x(v.classifier) + ' ' + x(v.classifierVersion) + ': <strong>' + x(v.verdict) + '</strong>'; }).join('<br>')
    : 'no safety verdict recorded';
  var href = '/api/content-registry/versions/' + encodeURIComponent(d.id) + '/artifact';
  return '<table class="approve-kv"><tbody>' +
    '<tr><th>Scenario</th><td><code>' + x(d.contentId) + '</code> v' + x(String(d.version)) + '</td></tr>' +
    '<tr><th>State</th><td>' + x(d.lifecycle) + ' / ' + x(d.trust) + ' (' + x(d.intakeSource) + ')</td></tr>' +
    '<tr><th>Custom steps</th><td>' + x(steps) + '</td></tr>' +
    '<tr><th>ART techniques</th><td>' + x(String(techs.length)) + (techs.length ? ' &mdash; ' + x(techList) : '') + '</td></tr>' +
    '<tr><th>Safety</th><td>' + safety + '</td></tr>' +
    '<tr><th>SHA-256</th><td><code>' + x(d.artifactSha256) + '</code></td></tr>' +
    '<tr><th>Artifact</th><td><a href="' + x(href) + '" download>Download the exact bytes to review</a></td></tr>' +
    '</tbody></table>';
}

export function approveLocalAckChanged() {
  var ok = !!_approveTarget && document.getElementById('approve-local-ack').checked &&
    document.getElementById('approve-local-reason').value.trim() !== '';
  document.getElementById('approve-local-submit-btn').disabled = !ok;
}

export function closeApproveLocalModal() {
  _approveTarget = null;
  _approveSeq++; // drop any in-flight load
  document.getElementById('approve-local-overlay').classList.remove('open');
}

export function submitApproveLocal() {
  var t = _approveTarget;
  var reason = document.getElementById('approve-local-reason').value.trim();
  if (!t || !reason || !document.getElementById('approve-local-ack').checked) return;
  var btn = document.getElementById('approve-local-submit-btn');
  btn.disabled = true;
  apicall('/api/content-registry/versions/' + encodeURIComponent(t.versionId) + '/transition', {
    method: 'POST',
    body: JSON.stringify({ to: 'PUBLISHED_LOCAL', reason: reason })
  }).then(function(d) {
    if (d && d.error) throw new Error(d.error);
    closeApproveLocalModal();
    showToast('Approved ' + t.id + ' for local use', 'ok');
    loadScenarios();
  }).catch(function(e) { btn.disabled = false; showToast('Approval failed: ' + e.message, 'err'); });
}

// Admin-only banner: schedules whose scenario is no longer executable after the
// registry migration. Text via textContent only (scenario ids are data).
function loadRegistryMigrationBanner() {
  if (ROLE !== 'admin') return;
  apicall('/api/content-registry/migration-report').then(function(m) {
    var host = document.getElementById('registryMigrationBanner');
    if (!host) return;
    var b = m && m.blockedSchedules;
    if (!b || !b.length) { host.hidden = true; return; }
    host.textContent = b.length + ' scheduled assessment(s) reference threat-intel scenarios that now need approval before they can run (' +
      b.map(function(r) { return r.scenarioId; }).join(', ') + '). Approve them on their scenario cards.';
    host.hidden = false;
  }).catch(function() {});
}

var SCENARIO_CATEGORIES = {
  em:    { label: 'Endpoint Mastery',
           icon: '<svg style="width:18px;height:18px;stroke:var(--accent)" viewBox="0 0 24 24" fill="none"><path d="M12 2L4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3z" stroke-width="2" fill="none"/></svg>' },
  intel: { label: 'Threat-Intel',
           icon: '<svg style="width:18px;height:18px;stroke:var(--accent)" viewBox="0 0 24 24" fill="none"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-width="2"/><path d="M9 12l2 2 4-4" stroke-width="2"/></svg>' },
  phishing: { label: 'Phishing',
           icon: '<svg style="width:18px;height:18px;stroke:var(--accent)" viewBox="0 0 24 24" fill="none"><rect x="3" y="5" width="18" height="14" rx="2" stroke-width="2"/><path d="M3 7l9 6 9-6" stroke-width="2"/></svg>' },
  other: { label: 'Standard & Custom',
           icon: '<svg style="width:18px;height:18px;stroke:var(--muted)" viewBox="0 0 24 24" fill="none"><rect x="3" y="3" width="18" height="18" rx="2" stroke-width="2"/><path d="M3 9h18M9 21V9" stroke-width="2"/></svg>' }
};

// Threat-intel-sourced scenarios (one auto-generated per tracked threat
// actor -- can number in the hundreds) get their own top-level category
// rather than being folded into "Standard & Custom", where a handful of
// real built-in/custom scenarios would otherwise be buried under a huge
// Threat-Intel sub-group. EM still takes priority for the rare case a
// scenario is somehow both (Endpoint Mastery has its own dedicated
// dashboard elsewhere).
// Scenario section grouping by licensed product line. The server sends each scenario's productLine
// (from its signed YAML). Threat-intel scenarios keep their own group, since they are split by source.
export var PRODUCT_LINE_ORDER = ['av', 'waf', 'network', 'email', 'dlp', 'killchain', 'ransomware', 'webgw', 'cloud', 'apibas', 'ad', 'dbsim', 'common'];
var PRODUCT_LINE_LABELS = {
  av: 'Antivirus', waf: 'WAF', network: 'Network', email: 'Email', dlp: 'DLP', apibas: 'API BAS', ad: 'AD BAS', dbsim: 'DB Simulation',
  ransomware: 'Ransomware', killchain: 'Kill Chain', webgw: 'Web Gateway', cloud: 'Cloud', common: 'Simulation Frameworks'
};
PRODUCT_LINE_ORDER.forEach(function(p) {
  SCENARIO_CATEGORIES[p] = { label: PRODUCT_LINE_LABELS[p], icon: SCENARIO_CATEGORIES.other.icon };
});

// scenarioSectionOrder is the order the Scenarios landing shows its sections. Phishing is not a
// scenario product line (its entries come from the phishing library), so it is placed here by key.
export function scenarioSectionOrder() {
  var keys = ['av', 'waf', 'network', 'email', 'dlp', 'phishing', 'killchain', 'ransomware', 'webgw', 'cloud', 'apibas', 'ad', 'dbsim', 'common', 'intel'];
  return keys.map(function(key) { return { key: key, label: SCENARIO_CATEGORIES[key].label }; });
}

export function scenarioProductOf(s) {
  if (scenarioSourceOf(s) === 'intel') return 'intel';
  return PRODUCT_LINE_ORDER.indexOf(s.productLine) !== -1 ? s.productLine : 'common';
}

export function scenarioCategoryOf(s) {
  if ((s.id || '').indexOf('em-') === 0 || (s.tags || []).indexOf('endpoint-mastery') !== -1) return 'em';
  if (scenarioSourceOf(s) === 'intel') return 'intel';
  return 'other';
}

// ── Scenarios page: sidebar + toolbar + grid/list + drawer (see scn-rich.js / scn-model.js) ──
function scenarioSourceOf(s) { return scnSourceOf(s); }

// Set when /api/scenarios last answered; shown as the hero's "Updated" figure.
var _scnLoadedAt = null;

export function scenarioCategoryKeydown(key, el, event) {
  if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openScenarioCategory(key); }
}

export function openScenarioCategory(key) {
  if (key === 'all') key = 'landing';
  state.scenarioView = key;
  closeScenarioOverlay();
  history.pushState({ scenarioView: key }, '', key === 'landing' ? '#tab-scenarios' : '#tab-scenarios/' + key);
  paintScenarios();
}
export function __init_L8723() {
window.addEventListener('popstate', function(e) {
  var tab = document.getElementById('tab-scenarios');
  if (!tab || displayOf(tab) === 'none') return;
  state.scenarioView = (e.state && e.state.scenarioView) || 'landing';
  closeScenarioOverlay();
  paintScenarios();
});
}

function scnFilters() {
  var v = function(id) { var el = document.getElementById(id); return el ? el.value : 'all'; };
  var q = document.getElementById('sc-search');
  return { q: q ? q.value.trim() : '', source: v('sc-filter-source'), os: v('sc-filter-os'), product: v('sc-filter-product') };
}

var _scnProdSig = '';
// "All Product Lines" lists the product lines that really have scenarios, labelled like the sidebar.
function paintProductFilter(all) {
  var sel = document.getElementById('sc-filter-product');
  if (!sel) return;
  var present = {};
  all.forEach(function(s) { present[scenarioProductOf(s)] = 1; });
  var opts = scenarioSectionOrder().filter(function(sec) { return present[sec.key]; });
  var sig = opts.map(function(o) { return o.key; }).join(',');
  if (sig === _scnProdSig) return;
  _scnProdSig = sig;
  var prev = sel.value;
  sel.innerHTML = '<option value="all">All Product Lines</option>' + opts.map(function(o) { return '<option value="' + x(o.key) + '">' + x(o.label) + '</option>'; }).join('');
  sel.value = present[prev] ? prev : 'all';
}

function paintHero(all) {
  var st = scnHeroStats(all, scenarioProductOf);
  setHeroStat('sc-hs-total', st.total);
  setHeroStat('sc-hs-tech', st.techniques);
  setHeroStat('sc-hs-fam', st.families);
  setHeroStat('sc-hs-upd', _scnLoadedAt ? _scnLoadedAt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—');
}

// paintScenarios redraws the whole page body from the loaded scenarios and the toolbar. It never
// fetches, so the library loader can call it when its answer lands without looping.
function paintScenarios() {
  var grid = document.getElementById('sc-tile-grid'), cats = document.getElementById('sc-cats');
  if (!grid || !cats) return;
  var all = state.scenarios, ph = phishingLibraryCounts(_libraryEntries);
  var view = state.scenarioView;
  if (!view || view === 'landing' || view === 'search') view = 'all';
  paintHero(all);
  paintProductFilter(all);
  paintDrawer(scnApproveFor);
  document.getElementById('sc-layout').classList.toggle('cat-off', scnUi().catOff);
  setDisplay(document.getElementById('sc-tmpl-filters'), 'none');
  var foot = document.getElementById('sc-foot'), tools = document.getElementById('sc-toolbar');
  if (foot) foot.textContent = '';

  if (showNoScenariosMessage(all.length, _libraryEntries)) {
    cats.innerHTML = '';
    tools.innerHTML = '';
    grid.innerHTML = kitEmpty('mapped', 'No scenarios loaded');
    return;
  }

  var pool = scnFilterList(all, scnFilters(), scenarioProductOf);
  var subs = {};
  if (ph.total) {
    subs.phishing = [ph.runnable ? ph.runnable + ' runnable here' : '', ph.unavailable ? ph.unavailable + ' need a connector' : '', ph.catalogOnly ? ph.catalogOnly + ' catalogued only' : ''].filter(Boolean).join(' · ');
  }
  var catList = scenarioSectionOrder().map(function(sec) { return { key: sec.key, label: sec.label, icon: sec.key }; });
  if (_templates.length) catList.push({ key: 'templates', label: 'Adversary Templates' });
  var rows = scnCategoryRows(catList, pool.length, function(key) {
    return key === 'phishing' ? ph.total : key === 'templates' ? _templates.length : pool.filter(function(s) { return scenarioProductOf(s) === key; }).length;
  }, subs);
  cats.innerHTML = scnCatsHtml(rows, view);

  var special = view === 'phishing' || view === 'templates';
  hideFilterSelects(special);
  tools.innerHTML = scnToolbarHtml(special);

  if (view === 'phishing') { renderPhishingLibrary(); return; }
  if (view === 'templates') {
    setDisplay(document.getElementById('sc-tmpl-filters'), 'flex');
    renderTemplateGrid();
    return;
  }
  var list = scnSortList(view === 'all' ? pool : pool.filter(function(s) { return scenarioProductOf(s) === view; }), scnUi().sort);
  grid.innerHTML = list.length ? scnGridHtml(list) : scnEmptyHtml();
  if (foot && list.length) foot.textContent = scnShowing(list.length, all.length);
}

// renderScenarios reloads the phishing library and redraws; the toolbar and sidebar call paintScenarios
// directly because they change nothing the library depends on.
export function renderScenarios() {
  if (!document.getElementById('sc-tile-grid')) return;
  loadScenarioLibrary();
  paintScenarios();
}
export function refreshScenarioView() { paintScenarios(); }
export function scenarioSearchClear() { paintScenarios(); }

function scnApproveFor(s) { return canApproveForLocal(s) ? approveButton(s) : ''; }
bindApproveButton(scnApproveFor);

export function setScenarioView(v) { setScenarioViewMode(v); paintScenarios(); }
export function setScenarioSort(el) { setScenarioSortMode(el && el.value); paintScenarios(); }
export function setScenarioCatOff(v) { setScenarioCatOffMode(v); paintScenarios(); }
export function clearScenarioFilters() {
  var q = document.getElementById('sc-search'); if (q) q.value = '';
  ['sc-filter-source', 'sc-filter-os', 'sc-filter-product'].forEach(function(id) { var el = document.getElementById(id); if (el) el.value = 'all'; });
  state.scenarioView = 'landing';
  paintScenarios();
}
export function openScenarioDrawer(id) { openScnDrawer(id); }
export function closeScenarioDrawer() { closeScnDrawer(); }
export function closeScenarioDrawerOnBackdrop(el, event) { if (event.target === el) closeScnDrawer(); }
export function scenarioDrawerTab(id) { drawerTab(id); }
export function scenarioCardKeydown(id, el, event) {
  if (event.target !== el) return;
  if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openScnDrawer(id); }
}
// The Run button sits inside the clickable card, so it must not also open the drawer.
export function runScenarioCard(id, el, event) { event.stopPropagation(); openModal(id, null); }
export function runScenarioFromDrawer(id) { closeScnDrawer(); openModal(id, null); }
export function openScenarioRun(runId) {
  var r = scnRunById(runId);
  if (!r) return;
  closeScnDrawer();
  viewRunResults(r);
}
export function closeScenarioOverlay() { closeScnDrawer(); }
export function __init_L8992() {
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape' && drawerScenarioId()) closeScnDrawer();
});
}
// ── Scenario Library: phishing entries from GET /api/scenarios/library ──
// Phishing entries are listed beside the agent scenarios. A phishing entry gets
// a run control only when its server status is executable or experimental, and
// that control posts to /api/phishing-runs. It never calls the agent path. The
// entry is read from memory by index, not from DOM attributes. The server still
// enforces CanRunScenario on the POST.
var _libraryEntries = [];

// Labels for the server's status. The server decides the status and reason. The
// browser only words them, and never infers availability from an ID or a schema.
const LIBRARY_STATUS_LABEL = {
  available: 'Available on this installation',
  experimental: 'Experimental (runnable here)',
  catalog_only: 'Catalogued only',
};

export function loadScenarioLibrary() {
  return apicall('/api/scenarios/library').then(function(entries) {
    _libraryEntries = Array.isArray(entries) ? entries : [];
    _phishingFormIndex = null; // an index from the old list could point at another entry now
    refreshLibraryViews();
  }).catch(function() {
    _libraryEntries = [];
    _phishingFormIndex = null;
    refreshLibraryViews();
  });
}

// Redraws the page once the library answers (the Phishing count and tiles depend on it). Never calls
// renderScenarios, which itself loads the library, so this cannot loop.
function refreshLibraryViews() { paintScenarios(); }

// The phishing category grid is the shared sc-tile-grid. Clicks on its tiles
// and parameter form go to onPhishingLibraryClick, bound once.
function bindPhishingGrid() {
  var grid = document.getElementById('sc-tile-grid');
  if (grid && !grid._phishingBound) {
    grid.addEventListener('click', onPhishingLibraryClick);
    grid._phishingBound = true;
  }
}

function phishingLibraryTileHTML(entry, index) {
  var runnable = libraryEntryRoute(entry).kind === LIBRARY_TYPE_PHISHING;
  var label = entry.status === 'unavailable'
    ? 'Unavailable: ' + String(entry.reason || 'not configured').split('_').join(' ')
    : (LIBRARY_STATUS_LABEL[entry.status] || 'Not runnable');
  // Experimental stays visible in every state, not only when runnable.
  var tag = entry.experimental && entry.status !== 'experimental' ? ' · Experimental' : '';
  var pill = entry.status === 'available' ? 'ok' : entry.status === 'experimental' ? 'pending' : 'none';
  return '<div class="sc-card src-builtin' + (runnable ? '' : ' unavail') + '" data-entry-index="' + index + '">' +
    '<div class="sc-tags"><span class="sc-tag blue">Phishing</span>' + (entry.experimental ? '<span class="sc-tag amber">Experimental</span>' : '') + '</div>' +
    '<h3>' + x(entry.name) + '</h3><p>' + x(entry.id) + ' · ' + x(label) + x(tag) + '</p>' +
    '<div class="sc-actions"><span class="sc-avail ' + pill + '">&#9679; ' + x(label) + '</span>' +
    '<button type="button" class="btn btn-primary btn-sm" data-entry-index="' + index + '"' + (runnable ? '' : ' disabled') + '>Run</button></div>' +
    '</div>';
}

function renderPhishingLibrary() {
  if (state.scenarioView !== 'phishing') return;
  var grid = document.getElementById('sc-tile-grid');
  if (!grid) return;
  bindPhishingGrid();
  var tiles = [];
  _libraryEntries.forEach(function(entry, index) {
    if (!entry || entry.type !== LIBRARY_TYPE_PHISHING) return;
    tiles.push(phishingLibraryTileHTML(entry, index));
  });
  var open = _libraryEntries[_phishingFormIndex];
  var form = open && libraryEntryRoute(open).kind === LIBRARY_TYPE_PHISHING ? phishingFormHTML(open) : '';
  grid.innerHTML = tiles.length
    ? '<div class="sc-fade"><div class="sc-grid">' + tiles.join('') + '</div>' + form + '</div>'
    : '<p class="empty">No phishing scenarios are catalogued.</p>';
  renderPhishingRunResults(grid);
}

// Recent phishing runs, below the library. Each run is described by
// phishing-run-view.js, so PH-ID-001 behavior and Inconclusive results are worded there.
function renderPhishingRunResults(grid) {
  var box = document.getElementById('phishing-run-results');
  if (!box) {
    box = document.createElement('div');
    box.id = 'phishing-run-results';
    grid.parentNode.insertBefore(box, grid.nextSibling);
  }
  apicall('/api/phishing-runs').then(function(runs) {
    var rows = (runs || []).map(function(run) {
      var view = describePhishingRun(run);
      var cells = view.rows.map(function(r) {
        return '<li class="phish-row phish-' + x(r.tone) + '"><strong>' + x(r.label) + ':</strong> ' + x(r.text) + '</li>';
      }).join('');
      var note = view.note ? '<p class="phish-note">' + x(view.note) + '</p>' : '';
      return '<div class="phish-run"><h4>' + x(view.scenarioId) + ' <span class="phish-status">' + x(view.status) + '</span></h4>' +
        note + (cells ? '<ul>' + cells + '</ul>' : '') + '</div>';
    });
    box.innerHTML = rows.length ? '<h3>Recent phishing runs</h3>' + rows.join('') : '';
  }).catch(function() {
    box.innerHTML = '<p class="empty">Recent phishing runs could not be loaded.</p>';
  });
}

// Index of the phishing entry whose parameter form is open, or null.
var _phishingFormIndex = null;

function phishingFormHTML(entry) {
  var specs = Array.isArray(entry.parameters) ? entry.parameters : [];
  var fields = specs.map(function(spec) {
    var type = spec.kind === 'number' ? 'number' : (spec.kind === 'email' ? 'email' : 'text');
    return '<label class="sc-param">' + x(spec.label || spec.name) +
      (spec.required ? ' *' : '') +
      '<input type="' + type + '" data-param="' + x(spec.name) + '"' +
      (type === 'number' ? ' min="1" step="1"' : '') + '></label>';
  }).join('');
  // Dispatch is opt-in. Ticking it sends a real test email to the scenario's fixed test
  // recipient through EmailGW, so the wording says so.
  var dispatch = '<fieldset class="sc-dispatch"><legend>Real EmailGW dispatch</legend>' +
    '<label class="sc-param"><input type="checkbox" data-dispatch="toggle"> Send a real test email through EmailGW (sends mail to the scenario\'s fixed test recipient)</label>' +
    '<label class="sc-param">Test window ends<input type="datetime-local" data-dispatch="testWindowEnd"></label>' +
    '<label class="sc-param">Campaign (optional)<input type="text" data-dispatch="campaignId"></label>' +
    '</fieldset>';
  return '<div class="sc-phishing-form" data-form-for="' + x(entry.id) + '">' + fields + dispatch +
    '<button type="button" data-library-submit>Run</button> ' +
    '<button type="button" data-library-cancel>Cancel</button></div>';
}

// One idempotency key per open form. A retry after a failed request reuses it, so a
// dispatch can never be sent twice. It is cleared only after a successful submit.
var _dispatchKey = null;

function newDispatchKey() {
  if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID();
  return 'k-' + Date.now() + '-' + Math.random().toString(36).slice(2);
}

function onPhishingLibraryClick(event) {
  var target = event.target;
  if (target.closest && target.closest('[data-library-cancel]')) {
    _dispatchKey = null;
    _phishingFormIndex = null;
    renderPhishingLibrary();
    return;
  }
  if (target.closest && target.closest('[data-library-submit]')) {
    submitPhishingForm();
    return;
  }
  var btn = target.closest && target.closest('[data-entry-index]');
  if (!btn || btn.disabled) return;
  var index = Number(btn.getAttribute('data-entry-index'));
  if (libraryEntryRoute(_libraryEntries[index]).kind !== LIBRARY_TYPE_PHISHING) return;
  _phishingFormIndex = index;
  renderPhishingLibrary();
}

function submitPhishingForm() {
  var entry = _libraryEntries[_phishingFormIndex];
  var el = document.getElementById('sc-tile-grid');
  if (!entry || !el) return;
  var values = {};
  el.querySelectorAll('[data-param]').forEach(function(input) {
    values[input.getAttribute('data-param')] = input.value;
  });
  var built = buildPhishingRunRequest(entry, values);
  if (!built.ok) {
    showToast('Check these fields: ' + built.errors.join(', '), 'err');
    return;
  }
  var dispatchValues = {};
  el.querySelectorAll('[data-dispatch]').forEach(function(input) {
    var key = input.getAttribute('data-dispatch');
    dispatchValues[key] = input.type === 'checkbox' ? input.checked : input.value;
  });
  dispatchValues.dispatch = dispatchValues.toggle === true;
  if (dispatchValues.dispatch && !_dispatchKey) _dispatchKey = newDispatchKey();
  var fields = buildDispatchFields(dispatchValues, Date.now(), _dispatchKey);
  if (!fields.ok) {
    showToast('Check the dispatch fields: ' + fields.errors.join(', '), 'err');
    return;
  }
  Object.assign(built.body.parameters, fields.fields);
  apicall('/api/phishing-runs', { method: 'POST', body: JSON.stringify(built.body) })
    .then(function() {
      showToast('Phishing run started: ' + built.body.scenarioId, 'ok');
      _dispatchKey = null;
      _phishingFormIndex = null;
      renderPhishingLibrary();
    })
    .catch(function(err) {
      showToast('Phishing run failed: ' + (err && err.message ? err.message : String(err)), 'err');
    });
}
