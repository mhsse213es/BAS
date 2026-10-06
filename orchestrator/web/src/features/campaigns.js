import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { covSegHtml, loadScenarios, showThreatPriorityDetail, tpTierBadge } from './attack-path.js';
import { refreshDashboardCampaigns } from './compliance.js';
import { findingSevBadge } from './findings.js';
import { viewRunResults } from './reports.js';
import { ROLE, _riskScoreColor, activateTab, showTab } from './shell.js';


// ── Campaigns ────────────────────────────────────────────────────────────────
function campaignMixBar(s) {
  var seg = function(v, c) { return v > 0 ? '<i style="flex:' + v + ';background:' + c + '"></i>' : ''; };
  var total = (s.prevented || 0) + (s.detected || 0) + (s.missed || 0);
  if (!total) return '<span class="tiny muted">—</span>';
  return '<div class="seg-bar" title="Prevented ' + (s.prevented || 0) + ' · Detected ' + (s.detected || 0) + ' · Missed ' + (s.missed || 0) +
    (s.skipped ? ' · Skipped ' + s.skipped + ' agents' : '') + '" style="display:flex;height:8px;border-radius:5px;overflow:hidden;background:var(--elevated);min-width:120px">' +
    seg(s.prevented, 'var(--success)') + seg(s.detected, 'var(--warning)') + seg(s.missed, 'var(--danger)') + '</div>';
}
// campaignDisplayStatus folds the paused overlay into a single badge state.
// A campaign's summary.status stays 'running' the whole time it's dispatched
// (paused is a separate boolean, mirroring how individual runs track it) --
// without this, the status badge keeps its blinking "Running" dot even while
// dispatch is actually suspended, contradicting the Pause/Resume button (which
// already checks s.paused correctly) right next to it.
export function campaignDisplayStatus(s) {
  if (s.status === 'running' && s.paused) {
    return { cls: 'paused', label: 'paused', live: false };
  }
  return { cls: s.status || 'running', label: s.status || '—', live: s.status === 'running' };
}
var CAMPAIGN_TAB = 'all';
export function loadCampaigns() {
  apicall('/api/campaigns').then(function(list) {
    state._campaigns = list || [];
    document.getElementById('campaign-cnt').textContent = state._campaigns.length;
    renderCampaignToolbar();
    renderCampaignRows();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
function renderCampaignToolbar() {
  var list = state._campaigns || [];
  var count = function(k) { return k === 'all' ? list.length : list.filter(function(c) { return (c.summary || {}).status === k; }).length; };
  var items = [['all', 'All'], ['running', 'Running'], ['completed', 'Completed'], ['partial', 'Partial'], ['failed', 'Failed'], ['stopped', 'Stopped'], ['empty', 'Empty']]
    .filter(function(o) { return o[0] === 'all' || count(o[0]) > 0; });
  document.getElementById('campaign-toolbar').innerHTML = covSegHtml(items, CAMPAIGN_TAB, 'setCampaignTab', count);
}
export function setCampaignTab(v) { CAMPAIGN_TAB = v; renderCampaignToolbar(); renderCampaignRows(); }
function renderCampaignRows() {
  var list = (state._campaigns || []).filter(function(c) { return CAMPAIGN_TAB === 'all' || (c.summary || {}).status === CAMPAIGN_TAB; });
  var tb = document.getElementById('campaigns-body');
  if (!list.length) { tb.innerHTML = '<tr><td colspan="6" class="empty">No campaigns' + (CAMPAIGN_TAB === 'all' ? ' yet.' : ' in this state.') + '</td></tr>'; return; }
  tb.innerHTML = list.map(function(c) {
    var s = c.summary || {};
    var cds = campaignDisplayStatus(s);
    var status = '<span class="sbadge s-' + cds.cls + '">' + x(cds.label) + '</span>';
    if (s.status === 'running') {
      status += '<div class="prog" style="width:90px;margin-top:5px"><i style="width:' + (s.progress || 0) + '%"></i></div>' +
        '<span class="tiny muted">' + (s.progress || 0) + '%</span>';
    }
    var targetLabel = c.targetType === 'group'
      ? (CMP.groupsById[c.targetGroupId] || ('Group #' + c.targetGroupId))
      : c.targetType === 'all' ? 'All Agents' : 'Agents';
    return '<tr class="u-pointer"' + on('click', 'openCampaignDetail', c.id) + '>' +
      '<td><div class="cell-main">' + x(c.name) + '</div><div class="tiny muted" style="font-family:var(--font-mono);font-size:0.6rem">' + x(c.id) + (c.createdBy ? ' · ' + x(c.createdBy) : '') + '</div></td>' +
      '<td class="tiny muted">' + x(c.scenarioName) + '<div class="tiny muted" style="opacity:0.75">' + x(targetLabel) + '</div></td>' +
      '<td class="tiny">' + (s.dispatched || 0) + '/' + (s.targets || 0) + (s.skipped ? ' <span class="tiny muted">(' + s.skipped + ' skipped)</span>' : '') + '</td>' +
      '<td>' + status + '</td>' +
      '<td>' + campaignMixBar(s) + '</td>' +
      '<td class="tiny muted">' + fmtDate(c.startedAt) + '</td></tr>';
  }).join('');
}

export function closeCampaignDetail() {
  document.getElementById('campaigns-detail').style.display = 'none';
  document.getElementById('campaigns-list').style.display = '';
  loadCampaigns();
}
export function openCampaignDetail(id) {
  apicall('/api/campaigns/' + encodeURIComponent(id)).then(function(c) {
    var s = c.summary || {};
    var cds = campaignDisplayStatus(s);
    var status = x(cds.label);
    var liveDot = cds.live ? '<span class="dot-live"></span> ' : '';
    // ── stat tiles ──
    var tile = function(lbl, val, col, foot) {
      return '<div class="kpi-card stat-tile"><div class="stat-top"><div>' +
        '<div class="kpi-label">' + lbl + '</div>' +
        '<div class="kpi-value" style="color:' + (col || 'var(--text)') + '">' + val + '</div></div></div>' +
        (foot ? '<div class="kpi-sub">' + foot + '</div>' : '') + '</div>';
    };
    var mt = (s.prevented || 0) + (s.detected || 0) + (s.missed || 0);
    var eff = mt ? Math.round(((s.prevented || 0) * 100 + (s.detected || 0) * 50) / mt) : 0;
    var effCol = eff >= 60 ? 'var(--success)' : eff >= 40 ? 'var(--warning)' : 'var(--danger)';
    var tiles = '<div class="kpi-row" style="margin-bottom:1.25rem">' +
      tile('Effectiveness', mt ? eff : '—', mt ? effCol : 'var(--muted)', 'weighted result') +
      tile('Prevented', s.prevented || 0, 'var(--success)', 'blocked') +
      tile('Detected only', s.detected || 0, 'var(--warning)', 'alerted, not blocked') +
      tile('Missed', s.missed || 0, (s.missed ? 'var(--danger)' : 'var(--muted)'), 'no control response') + '</div>';
    // ── running banner ──
    var banner = (s.status === 'running')
      ? '<div class="dash-panel" style="margin-bottom:1.25rem;border-color:' + (s.paused ? 'var(--warning)' : 'var(--accent)') + '"><div class="dash-panel-body" style="display:flex;align-items:center;gap:1rem">' +
        (cds.live ? '<span class="dot-live"></span>' : '<span class="sbadge s-paused" style="flex-shrink:0">paused</span>') +
        '<div class="u-flex1"><div class="u-fw600">' + (s.paused ? 'Campaign paused — ' : 'Campaign in progress — ') + (s.dispatched || 0) + '/' + (s.targets || 0) + ' agents dispatched</div>' +
        '<div class="prog" style="margin-top:0.5rem"><i style="width:' + (s.progress || 0) + '%"></i></div></div>' +
        '<div style="font-family:var(--font-display);font-size:1.4rem;font-weight:700">' + (s.progress || 0) + '%</div></div></div>'
      : '';
    // ── per-agent results table (our fan-out equivalent of the mockup step table) ──
    var rows = (c.runs || []).map(function(rn) {
      var col = rn.status === 'completed' ? 'var(--success)' : rn.status === 'failed' ? 'var(--danger)' : 'var(--muted)';
      var rnPaused = rn.status === 'running' && rn.paused;
      return '<tr><td><span class="sbadge ' + (rnPaused ? 's-paused' : 's-' + x(rn.status)) + '">' + (rnPaused ? 'paused' : x(rn.status)) + '</span></td>' +
        '<td style="font-family:var(--font-mono);font-size:0.72rem">' + x(rn.agentId) + '</td>' +
        '<td style="font-weight:600;color:' + col + '">' + (rn.preventionScore ? Math.round(rn.preventionScore) + '%' : '—') + '</td>' +
        '<td class="td-r"><button class="btn btn-outline btn-sm"' + on('click', 'openRunFromCampaign', rn.runId) + '>Results &rarr;</button></td></tr>';
    }).join('') || '<tr><td colspan="4" class="empty">No child runs dispatched.</td></tr>';
    var perAgent = '<div class="dash-panel" style="margin-bottom:1.25rem"><div class="dash-panel-hdr">Per-agent results</div>' +
      '<div class="dash-panel-body" style="padding:0"><div class="tbl-wrap"><table>' +
      '<thead><tr><th>Status</th><th>Agent</th><th>Prevention</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div></div></div>';
    // ── skipped targets ──
    var skips = (c.skips || []).length
      ? '<div class="dash-panel" style="margin-bottom:1.25rem"><div class="dash-panel-hdr">Skipped targets (' + c.skips.length + ')</div><div class="dash-panel-body">' +
        c.skips.map(function(k) { return '<div style="display:flex;gap:0.6rem;padding:0.3rem 0;border-bottom:1px solid var(--border);font-size:0.8rem"><code>' + x(k.agentId) + '</code><span class="tiny muted" style="margin-left:auto">' + x(k.reason) + '</span></div>'; }).join('') + '</div></div>'
      : '';
    // ── run summary ──
    var kv = function(k, v) { return '<div style="display:flex;gap:0.6rem;padding:0.35rem 0;border-bottom:1px solid var(--border);font-size:0.8rem"><span style="color:var(--muted);min-width:120px">' + k + '</span><span class="u-flex1">' + v + '</span></div>'; };
    var targetKv = c.targetType === 'group'
      ? 'Agent Group — ' + x(CMP.groupsById[c.targetGroupId] || ('Group #' + c.targetGroupId))
      : c.targetType === 'all' ? 'All Agents' : (s.targets || 0) + ' agents selected';
    var summary = '<div class="dash-panel"><div class="dash-panel-hdr">Run summary</div><div class="dash-panel-body">' +
      kv('Campaign ID', '<code>' + x(c.id) + '</code>') + kv('Scenario', x(c.scenarioName)) +
      kv('Target', targetKv) +
      kv('Targets', (s.dispatched || 0) + ' dispatched · ' + (s.skipped || 0) + ' skipped of ' + (s.targets || 0)) +
      kv('Mode', x(c.mode || '—')) + kv('Initiated by', x(c.createdBy || '—')) +
      kv('Result mix', campaignMixBar(s)) + '</div></div>';
    // ── actions ──
    var actions = (s.status === 'running')
      ? (s.paused
          ? '<button class="btn btn-outline btn-sm"' + on('click', 'resumeCampaign', c.id) + ' title="Resume every paused child run">&#9654; Resume campaign</button> '
          : '<button class="btn btn-outline btn-sm"' + on('click', 'pauseCampaign', c.id) + ' title="Pause every running child run">&#10073;&#10073; Pause campaign</button> ')
        + '<button class="btn btn-outline-red btn-sm"' + on('click', 'stopCampaign', c.id) + '>&#9632; Stop campaign</button>'
      : '<button class="btn btn-outline btn-sm"' + on('click', 'openCampaignReport', c.id) + ' title="Open the fleet-wide HTML report">&#8599; HTML Report</button>' +
        ' <button class="btn btn-outline btn-sm"' + on('click', 'downloadCampaignReport', c.id) + ' title="Download the fleet-wide report as a PDF file">&#8595; PDF Report</button>' +
        ' <button class="btn btn-outline btn-sm"' + on('click', 'downloadCampaignCSV', c.id) + ' title="Download the fleet forensic CSV (one row per technique across all agents)">&#8595; CSV</button>' +
        ' ' + ((ROLE === 'admin' || ROLE === 'analyst')
          ? '<button class="btn btn-outline btn-sm"' + on('click', 'openCampaignRerunReview', c) + ' title="Review and re-run this exact campaign configuration">Re-run</button>'
          : '<button class="btn btn-outline btn-sm" disabled style="opacity:0.5;cursor:not-allowed" title="Re-run requires the Analyst or Admin role">Re-run</button>');

    document.getElementById('campaigns-detail').innerHTML =
      '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1rem;flex-wrap:wrap">' +
        '<div><a class="tiny" style="color:var(--accent);cursor:pointer"' + on('click', 'closeCampaignDetail') + '>&larr; Campaigns</a>' +
        '<h1 style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;margin:0.3rem 0;color:var(--text)">' + x(c.name) + ' <span class="sbadge s-' + cds.cls + '" style="font-size:0.7rem;vertical-align:middle">' + liveDot + status + '</span></h1>' +
        '<div style="font-size:0.8rem;color:var(--muted)">' + x(c.scenarioName) + ' · ' + (s.dispatched || 0) + '/' + (s.targets || 0) + ' agents · started ' + fmtDate(c.startedAt) + (c.createdBy ? ' by ' + x(c.createdBy) : '') + '</div></div>' +
        '<div style="display:flex;gap:0.5rem;flex-shrink:0">' + actions + '</div>' +
      '</div>' +
      banner + tiles +
      '<div class="dash-grid" style="grid-template-columns:1.5fr 1fr;align-items:start">' +
        '<div>' + perAgent + skips + '</div>' +
        '<div>' + summary + '<div id="cmp-recs" style="margin-top:1.25rem"></div></div>' +
      '</div>';
    activateTab('campaigns'); // in case opened from the dashboard
    document.getElementById('campaigns-list').style.display = 'none';
    document.getElementById('campaigns-detail').style.display = '';
    renderCampaignRecs(c.id);
  }).catch(function(e) { showToast(e.message, 'err'); });
}
// renderCampaignRecs shows this campaign's Top Open findings and Top Regressions
// (not the whole fleet) — the actionable next steps for the run.
function renderCampaignRecs(campaignId) {
  apicall('/api/findings').then(function(fs) {
    var el = document.getElementById('cmp-recs');
    if (!el) return;
    var mine = (fs || []).filter(function(f) { return f.lastCampaignId === campaignId; });
    var open = mine.filter(function(f) { return f.status === 'open'; }).slice(0, 5);
    var regr = mine.filter(function(f) { return f.reopenedCount > 0 && f.status === 'open'; }).slice(0, 3);
    var hdr = function(t) { return '<div style="font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0.5rem 0 0.3rem">' + t + '</div>'; };
    var rowf = function(f) {
      return '<div class="lrow u-pointer"' + on('click', 'openFindingFromDashboard', f.id) + '>' +
        '<div class="lmain"><div class="lt">' + x(f.techniqueName || f.techniqueId) + '</div>' +
        '<div class="ls"><span class="tech-id">' + x(f.techniqueId) + '</span> · ' + x(f.controlClass) + ' · ' + x(f.agentId) + '</div></div>' +
        '<div class="lr">' + findingSevBadge(f.severity, f.exposureState) + '</div></div>';
    };
    if (!open.length && !regr.length) {
      el.innerHTML = hdr('Recommended next steps') + '<div class="tiny muted">No open findings for this campaign.</div>';
      return;
    }
    el.innerHTML = (open.length ? hdr('Top open findings') + open.map(rowf).join('') : '') +
      (regr.length ? hdr('Top regressions') + regr.map(rowf).join('') : '');
  }).catch(function() {});
}
export function openRunFromCampaign(runId) {
  apicall('/api/scenarios/runs').then(function(runs) {
    var r = (runs || []).find(function(item) { return item.id === runId; });
    if (r) viewRunResults(r); else showToast('Run not found', 'err');
  });
}
export function stopCampaign(id) {
  if (!confirm('Stop this campaign? Running child runs will be marked partial.')) return;
  apicall('/api/campaigns/' + encodeURIComponent(id) + '/stop', { method: 'POST' })
    .then(function() { showToast('Campaign stopped', 'ok'); openCampaignDetail(id); })
    .catch(function(e) { showToast(e.message, 'err'); });
}
export function pauseCampaign(id) {
  apicall('/api/campaigns/' + encodeURIComponent(id) + '/pause', { method: 'POST' })
    .then(function(res) { showToast('Pausing ' + ((res && res.pausing) || 0) + ' running child run(s)', 'ok'); openCampaignDetail(id); })
    .catch(function(e) { showToast(e.message, 'err'); });
}
export function resumeCampaign(id) {
  apicall('/api/campaigns/' + encodeURIComponent(id) + '/resume', { method: 'POST' })
    .then(function(res) { showToast('Resuming ' + ((res && res.resuming) || 0) + ' paused child run(s)', 'ok'); openCampaignDetail(id); })
    .catch(function(e) { showToast(e.message, 'err'); });
}


export var CMP = { groups: [], groupsById: {}, exclusions: {} };

function cmpFlattenGroupNames(nodes, map) {
  (nodes || []).forEach(function(n) {
    map[n.id] = n.name;
    if (n.children && n.children.length) cmpFlattenGroupNames(n.children, map);
  });
  return map;
}

export function openCampaignLaunch() {
  if (!state.scenarios.length) { showToast('Scenarios not loaded yet', 'err'); return; }
  if (!state.agents.length) { showToast('No agents registered yet', 'err'); return; }
  document.getElementById('cmp-name').value = '';
  document.getElementById('cmp-notes').value = '';
  document.getElementById('cmp-scenario').innerHTML = '<option value="">— Select a scenario —</option>' +
    state.scenarios.map(function(s) { return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>'; }).join('');
  document.getElementById('cmp-scenario-preview').innerHTML = '';
  document.getElementById('cmp-mode').value = 'posture';
  // Reset Campaign Source to a clean default every time the modal opens --
  // no state should carry over from a previous campaign.
  CMP_SOURCE = 'threat_informed';
  _tiPackData = null;
  _tiGeneratedScenarioId = null;
  document.getElementById('ti-pack-preview').style.display = 'none';
  document.getElementById('ti-generated-preview').style.display = 'none';
  document.querySelectorAll('#ti-pack-grid .btn').forEach(function(b) { b.style.borderColor = ''; });
  document.querySelector('input[name="cmp-source"][value="threat_informed"]').checked = true;
  renderCampaignSourceUI();
  var envs = {};
  state.agents.forEach(function(a) { if (a.envLabel) envs[a.envLabel] = true; });
  document.getElementById('cmp-filter-env').innerHTML = '<option value="">All environments</option>' +
    Object.keys(envs).map(function(e) { return '<option value="' + x(e) + '">' + x(e) + '</option>'; }).join('');
  state._cmpSel = {};
  CMP.exclusions = {};
  var typeSel = document.getElementById('cmp-target-type');
  var opts = '<option value="agents">Agents</option><option value="group">Agent Group</option>';
  if (ROLE === 'admin') opts += '<option value="all">All Agents</option>';
  typeSel.innerHTML = opts;
  typeSel.value = 'agents';
  document.getElementById('cmp-all-confirm').checked = false;
  document.getElementById('cmp-launch-btn').disabled = false;
  apicall('/api/agent-groups').then(function(res) {
    CMP.groups = Array.isArray(res) ? res : [];
    CMP.groupsById = cmpFlattenGroupNames(CMP.groups, {});
    var groupSel = document.getElementById('cmp-group');
    groupSel.innerHTML = Object.keys(CMP.groupsById).map(function(id) {
      return '<option value="' + x(id) + '">' + x(CMP.groupsById[id]) + '</option>';
    }).join('');
  }).catch(function() { CMP.groups = []; CMP.groupsById = {}; });
  renderCampaignTargets();
  cmpOnTargetTypeChange();
  document.getElementById('campaign-overlay').classList.add('open');
}
export function cmpOnTargetTypeChange() {
  var type = document.getElementById('cmp-target-type').value;
  document.getElementById('cmp-target-agents-wrap').style.display = (type === 'agents') ? 'block' : 'none';
  document.getElementById('cmp-target-group-wrap').style.display = (type === 'group') ? 'block' : 'none';
  document.getElementById('cmp-target-all-wrap').style.display = (type === 'all') ? 'block' : 'none';
  var launchBtn = document.getElementById('cmp-launch-btn');
  if (type === 'all') {
    launchBtn.disabled = !document.getElementById('cmp-all-confirm').checked;
    var count = state.agents.filter(function(a) { return a.state !== 'retired'; }).length;
    document.getElementById('cmp-all-count').textContent = '⚠ This campaign will execute against ' + count + ' agents.';
  } else {
    launchBtn.disabled = false;
  }
  if (type === 'group') cmpOnGroupChange();
}

export function cmpOnGroupChange() {
  var groupId = document.getElementById('cmp-group').value;
  CMP.exclusions = {};
  if (!groupId) { document.getElementById('cmp-group-preview').innerHTML = ''; document.getElementById('cmp-exclusions').innerHTML = ''; return; }
  apicall('/api/agents?groupId=' + encodeURIComponent(groupId)).then(function(list) {
    renderCampaignGroupPreview(Array.isArray(list) ? list : []);
  }).catch(function() { renderCampaignGroupPreview([]); });
}

function renderCampaignGroupPreview(list) {
  var osCounts = {};
  var online = 0, offline = 0;
  list.forEach(function(a) {
    var os = cmpAgentOS(a);
    osCounts[os] = (osCounts[os] || 0) + 1;
    if (a.status === 'offline') offline++; else online++;
  });
  var osLine = Object.keys(osCounts).map(function(os) { return osCounts[os] + ' ' + os; }).join(' · ');
  document.getElementById('cmp-group-preview').innerHTML =
    '<div>' + list.length + ' agents — ' + osLine + '</div>' +
    '<div>' + online + ' online · ' + offline + ' offline</div>';
  document.getElementById('cmp-exclusions').innerHTML = list.map(function(a) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox"' + on('change', 'cmpToggleExclusionFromChecked', a.agentId) + '>' +
      '<code style="font-size:0.72rem">' + x(a.agentId) + '</code><span class="tiny muted">' + x(a.hostname) + '</span></label>';
  }).join('');
  cmpUpdateExclusionCount();
}

export function cmpToggleExclusionFromChecked(agentId, el) { cmpToggleExclusion(agentId, el.checked); }

export function cmpSelChange(agentId, el) {
  state._cmpSel[agentId] = el.checked;
  cmpUpdateCount();
}

export function openThreatPriorityActor(actorName) {
  showTab('threat-priority');
  setTimeout(function() { showThreatPriorityDetail(actorName); }, 150);
}

export function cmpToggleExclusion(agentId, checked) {
  if (checked) CMP.exclusions[agentId] = true; else delete CMP.exclusions[agentId];
  cmpUpdateExclusionCount();
}

function cmpUpdateExclusionCount() {
  document.getElementById('cmp-excl-cnt').textContent = '(' + Object.keys(CMP.exclusions).length + ' excluded)';
}

export function closeCampaignLaunch() { document.getElementById('campaign-overlay').classList.remove('open'); }
export function cmpAllConfirmChange() { document.getElementById('cmp-launch-btn').disabled = !this.checked; }

// ── Campaign Source (mutually exclusive) ─────────────────────────────────────
// A campaign has exactly ONE source, never two -- Threat-Informed generation
// and Existing Scenario selection are alternative ways to arrive at a
// scenarioId to launch, not two fields that can independently hold state.
// CMP_SOURCE is the single source of truth the UI derives what to show from;
// avoid adding parallel booleans like isThreatInformedSelected /
// isScenarioSelected, which is exactly how the two states used to mix.
var CMP_SOURCE = 'threat_informed'; // 'threat_informed' | 'existing_scenario'
var _tiGeneratedScenarioId = null;  // set once Generate Campaign succeeds; null = nothing generated yet

function renderCampaignSourceUI() {
  document.getElementById('cmp-source-ti').style.display = (CMP_SOURCE === 'threat_informed') ? '' : 'none';
  document.getElementById('cmp-source-existing').style.display = (CMP_SOURCE === 'existing_scenario') ? '' : 'none';
}

// setCampaignSource: switches the campaign's source. If the source being left
// has real, unsaved work (a generated TI campaign, or a manually-picked
// scenario), confirms first and reverts the radio on cancel; otherwise
// switches immediately and clears the other source's state so it can never
// leak into what actually launches.
export function setCampaignSource(newSource) {
  if (newSource === CMP_SOURCE) return;
  var hasWork = (CMP_SOURCE === 'threat_informed' && _tiGeneratedScenarioId) ||
                (CMP_SOURCE === 'existing_scenario' && document.getElementById('cmp-scenario').value);
  if (hasWork) {
    var msg = CMP_SOURCE === 'threat_informed'
      ? 'Switch campaign source? Your generated threat-informed campaign will be discarded.'
      : 'Switch campaign source? Your selected scenario will be cleared.';
    if (!confirm(msg)) {
      document.querySelector('input[name="cmp-source"][value="' + CMP_SOURCE + '"]').checked = true;
      return;
    }
  }
  CMP_SOURCE = newSource;
  _tiGeneratedScenarioId = null;
  _tiPackData = null;
  document.getElementById('ti-pack-preview').style.display = 'none';
  document.getElementById('ti-generated-preview').style.display = 'none';
  document.querySelectorAll('#ti-pack-grid .btn').forEach(function(b) { b.style.borderColor = ''; });
  document.getElementById('cmp-scenario').value = '';
  document.getElementById('cmp-scenario-preview').innerHTML = '';
  renderCampaignSourceUI();
}

// ── Threat-Informed Campaign Builder ─────────────────────────────────────────
var _tiPackData = null;

var _tiPackIcons = {
  'kev': '&#9760;', 'ransomware': '&#128274;', 'credential-theft': '&#128272;',
  'living-off-the-land': '&#9881;', 'powershell-abuse': '&#128187;', 'lateral-movement': '&#8596;'
};

// selectTIPack: fetches pack metadata and shows the preview panel.
export function selectTIPack(type) {
  var preview = document.getElementById('ti-pack-preview');
  var info = document.getElementById('ti-pack-info');
  preview.style.display = 'none';
  info.textContent = 'Loading…';
  // Picking a (possibly different) pack starts over -- any earlier generated
  // campaign from a prior pack in this same session no longer applies.
  _tiGeneratedScenarioId = null;
  document.getElementById('ti-generated-preview').style.display = 'none';
  // Highlight selected button
  document.querySelectorAll('#ti-pack-grid .btn').forEach(function(b) { b.style.borderColor = ''; });
  event && event.target && (event.target.style.borderColor = 'var(--accent)');
  apicall('/api/ti/suggest-pack?type=' + encodeURIComponent(type)).then(function(pack) {
    _tiPackData = pack;
    if (!pack || !pack.hasData) {
      info.innerHTML = '<span class="u-danger">No data available for this pack — run more scenarios or reseed content first.</span>';
      preview.style.display = '';
      return;
    }
    var tacticSet = {};
    (pack.techniques || []).forEach(function(t) { if (t.tactic) tacticSet[t.tactic] = true; });
    var tacticCount = Object.keys(tacticSet).length;
    var ransomNote = pack.ransomwareCount > 0 ? ' &middot; <strong class="u-warning">' + pack.ransomwareCount + ' ransomware-linked</strong>' : '';
    var kevNote = pack.totalKevCves > 0 ? ' &middot; ' + pack.totalKevCves + ' KEV CVEs' : '';
    info.innerHTML = (_tiPackIcons[type] || '') + ' <strong>' + x(pack.packName) + '</strong><br>' +
      '<span class="u-muted">' + x(pack.description) + '</span><br>' +
      '<span style="font-size:0.75rem;margin-top:4px;display:inline-block"><strong>' + pack.techniqueCount + '</strong> techniques &middot; <strong>' + tacticCount + '</strong> tactics' + kevNote + ransomNote + '</span>';
    preview.style.display = '';
    // Pre-fill campaign name
    var nameEl = document.getElementById('cmp-name');
    if (!nameEl.value) nameEl.value = pack.suggestedName || '';
  }).catch(function() {
    info.innerHTML = '<span class="u-danger">Failed to fetch pack data.</span>';
    preview.style.display = '';
  });
}

// generateTIScenario: creates the scenario from _tiPackData and selects it.
export function generateTIScenario() {
  if (!_tiPackData || !_tiPackData.hasData) { showToast('No pack selected', 'err'); return; }
  var pack = _tiPackData;
  apicall('/api/scenarios', { method: 'POST', body: JSON.stringify(pack.suggestedScenario) })
    .then(function(res) {
      if (res && res.error) {
        if (res.error.indexOf('already exists') >= 0) {
          showToast(pack.packName + ' already exists — selecting it', 'ok');
          loadScenarios();
          setTimeout(function() { _applyGeneratedTIScenario(pack); }, 600);
        } else {
          showToast('Failed: ' + res.error, 'err');
        }
        return;
      }
      showToast(pack.packName + ' created — ' + pack.techniqueCount + ' techniques', 'ok');
      loadScenarios();
      setTimeout(function() { _applyGeneratedTIScenario(pack); }, 600);
    })
    .catch(function() { showToast('Failed to create scenario', 'err'); });
}

// _applyGeneratedTIScenario: records the generated scenario as this
// campaign's source (the "scenario_id = generated scenario result" half of
// the threat_informed branch) and shows the confirmation preview.
function _applyGeneratedTIScenario(pack) {
  _selectCmpScenario(pack.suggestedId);
  _tiGeneratedScenarioId = pack.suggestedId;
  var el = document.getElementById('ti-generated-preview');
  el.style.display = '';
  el.innerHTML = '&#10003; Generated: <strong>' + x(pack.suggestedName) + '</strong> — ' + pack.techniqueCount + ' techniques. Ready to configure targets below.';
}

// loadKEVPack: legacy shortcut (dashboard widget "Create KEV Pack" link).
export function loadKEVPack() {
  apicall('/api/ti/suggest-pack?type=kev').then(function(pack) {
    if (!pack || !pack.hasData) { showToast('KEV data not available — reseed content pack first', 'err'); return; }
    var msg = 'Create "' + pack.suggestedName + '" with ' + pack.techniqueCount + ' KEV-linked techniques' +
              (pack.ransomwareCount > 0 ? ' (' + pack.ransomwareCount + ' ransomware-linked)' : '') + '?';
    if (!confirm(msg)) return;
    apicall('/api/scenarios', { method: 'POST', body: JSON.stringify(pack.suggestedScenario) })
      .then(function(res) {
        if (res && res.error) {
          if (res.error.indexOf('already exists') >= 0) { _selectCmpScenario(pack.suggestedId); }
          else { showToast('Failed: ' + res.error, 'err'); }
          return;
        }
        showToast('KEV Exposure Pack created — ' + pack.techniqueCount + ' techniques', 'ok');
        loadScenarios(); setTimeout(function() { _selectCmpScenario(pack.suggestedId); }, 600);
      }).catch(function() { showToast('Failed to create KEV Pack', 'err'); });
  }).catch(function() { showToast('Could not fetch KEV data', 'err'); });
}

function _selectCmpScenario(id) {
  var sel = document.getElementById('cmp-scenario');
  if (!sel) return;
  for (var i = 0; i < sel.options.length; i++) {
    if (sel.options[i].value === id) { sel.selectedIndex = i; return; }
  }
  document.getElementById('cmp-scenario').innerHTML = '<option value="">— Select a scenario —</option>' +
    state.scenarios.map(function(s) {
      return '<option value="' + x(s.id) + '"' + (s.id === id ? ' selected' : '') + '>' + x(s.name) + '</option>';
    }).join('');
}

// cmpOnExistingScenarioChange: shows a short preview of the manually-picked
// scenario (the "Scenario details/preview" bullet of the Existing Scenario
// branch) -- purely descriptive, no data beyond what's already loaded.
export function cmpOnExistingScenarioChange() {
  var id = document.getElementById('cmp-scenario').value;
  var el = document.getElementById('cmp-scenario-preview');
  if (!id) { el.innerHTML = ''; return; }
  var sc = state.scenarios.find(function(s) { return s.id === id; });
  if (!sc) { el.innerHTML = ''; return; }
  var desc = (sc.description || '').trim();
  if (desc.length > 160) desc = desc.substring(0, 157).replace(/\s+\S*$/, '') + '…';
  var tagsLine = (sc.tags || []).length ? '<br><span style="font-size:0.7rem">' + sc.tags.map(x).join(' &middot; ') + '</span>' : '';
  el.innerHTML = x(desc) + tagsLine;
}

// loadKEVWidget fetches the KEV pack data and populates the dashboard TI KPI tiles.
var _kevWidgetLoaded = false;
export function loadKEVWidget() {
  if (_kevWidgetLoaded) return;
  Promise.all([
    apicall('/api/ti/suggest-pack?type=kev').catch(function() { return null; }),
    apicall('/api/analytics/threat-intel-summary').catch(function() { return null; })
  ]).then(function(res) {
    var pack = res[0];
    var summary = res[1];
    var hasKev = pack && pack.hasData;
    var actors = (summary && summary.topActors) || [];
    if (!hasKev && !actors.length) return;
    _kevWidgetLoaded = true;
    document.getElementById('dash-ti-section').style.display = '';
    var tiles = document.getElementById('dash-ti-tiles');
    tiles.innerHTML = hasKev ?
      '<div class="kpi-card stat-tile" title="Techniques with CISA KEV CVEs — create a pack to validate them">' +
      '<div class="stat-top"><div><div class="kpi-label">KEV-Linked Techniques</div><div class="kpi-value u-danger">' + pack.techniqueCount + '</div></div>' +
      '<div class="stat-icon" style="background:rgba(218,54,51,0.10);color:var(--danger)">&#9760;</div></div>' +
      '<div class="kpi-sub">' + (pack.totalKevCves||0) + ' CVEs · ' + (pack.ransomwareCount||0) + ' ransomware-linked</div></div>' +
      '<div class="kpi-card stat-tile" title="CISA Known Exploited Vulnerabilities under active real-world exploitation">' +
      '<div class="stat-top"><div><div class="kpi-label">Total KEV CVEs</div><div class="kpi-value u-warning">' + (pack.totalKevCves||0) + '</div></div>' +
      '<div class="stat-icon" style="background:rgba(210,153,34,0.10);color:var(--warning)"><svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M8 2l1.5 3.5H13l-2.75 2 1 3.5L8 9 4.75 11l1-3.5L3 5.5h3.5z"/></svg></div></div>' +
      '<div class="kpi-sub">from CISA KEV catalog</div></div>' : '';
    renderTIActors(actors);
  });
}

// renderTIActors shows the fleet's top-priority threat actors below the KEV
// tiles, reusing tpTierBadge (index.html:4834) for the same tier coloring
// the standalone Threat Prioritization tab already uses. Clicking an actor
// jumps to its detail view there rather than duplicating it here.
function renderTIActors(actors) {
  var el = document.getElementById('dash-ti-actors');
  if (!el) return;
  if (!actors.length) { el.innerHTML = ''; return; }
  el.innerHTML =
    '<div style="font-size:0.68rem;font-weight:600;letter-spacing:0.05em;color:var(--muted);text-transform:uppercase;margin:0.75rem 0 0.4rem">Top Threat Actors</div>' +
    actors.map(function(a) {
      return '<div style="display:flex;justify-content:space-between;align-items:center;padding:0.35rem 0;border-bottom:1px solid var(--border)">' +
        '<span style="font-weight:600;cursor:pointer"' + on('click', 'openThreatPriorityActor', a.actorName) + '>' + x(a.actorName) + '</span>' +
        '<span style="display:flex;align-items:center;gap:0.5rem">' + tpTierBadge(a.tier) + '<strong>' + x(a.score) + '</strong></span>' +
        '</div>';
    }).join('');
}

// loadEndpointPostureWidget fetches the fleet-wide endpoint posture summary
// and populates the dashboard's Endpoint Posture KPI tiles. Untrusted
// Binaries and Currently Isolated tiles only render when nonzero, matching
// loadKEVWidget's convention of hiding tiles that have nothing to report.
var _endpointPostureLoaded = false;
export function loadEndpointPostureWidget() {
  if (_endpointPostureLoaded) return;
  apicall('/api/analytics/endpoint-posture').then(function(p) {
    if (!p || !p.totalAgents) return;
    _endpointPostureLoaded = true;
    document.getElementById('dash-endpoint-section').style.display = '';
    var tiles = document.getElementById('dash-endpoint-tiles');
    var html =
      '<div class="kpi-card stat-tile u-pointer"' + on('click', 'showTab', 'agents') + ' title="Agents currently reachable vs. past the 90s heartbeat window">' +
      '<div class="stat-top"><div><div class="kpi-label">Online / Offline</div><div class="kpi-value">' + p.onlineAgents + ' <span class="tiny muted">/ ' + p.offlineAgents + '</span></div></div>' +
      '<div class="stat-icon" style="background:rgba(35,134,54,0.10);color:var(--success)">&#9679;</div></div>' +
      '<div class="kpi-sub">' + p.totalAgents + ' total agents</div></div>' +
      '<div class="kpi-card stat-tile u-pointer"' + on('click', 'showTab', 'agents') + ' title="Agent lifecycle state breakdown">' +
      '<div class="stat-top"><div><div class="kpi-label">Lifecycle</div><div class="kpi-value">' + p.activeAgents + ' <span class="tiny muted">active</span></div></div></div>' +
      '<div class="kpi-sub">' + p.restrictedAgents + ' restricted · ' + p.quarantinedAgents + ' quarantined · ' + p.retiredAgents + ' retired</div></div>';
    if (p.untrustedBinaryCount > 0) {
      html +=
        '<div class="kpi-card stat-tile u-pointer"' + on('click', 'showTab', 'agents') + ' title="Agents whose binary hash failed trust verification">' +
        '<div class="stat-top"><div><div class="kpi-label">Untrusted Binaries</div><div class="kpi-value u-danger">' + p.untrustedBinaryCount + '</div></div>' +
        '<div class="stat-icon" style="background:rgba(218,54,51,0.10);color:var(--danger)">&#9888;</div></div>' +
        '<div class="kpi-sub">binary hash failed trust verification</div></div>';
    }
    if (p.currentlyIsolated > 0) {
      html +=
        '<div class="kpi-card stat-tile u-pointer"' + on('click', 'showTab', 'agents') + ' title="Endpoints currently isolated via an EPP response action">' +
        '<div class="stat-top"><div><div class="kpi-label">Currently Isolated</div><div class="kpi-value u-warning">' + p.currentlyIsolated + '</div></div>' +
        '<div class="stat-icon" style="background:rgba(210,153,34,0.10);color:var(--warning)">&#128274;</div></div>' +
        '<div class="kpi-sub">via EPP response action</div></div>';
    }
    tiles.innerHTML = html;
  }).catch(function() {});
}

// loadReadinessTrends fetches and renders the per-actor readiness history table
// for the most recently active agent. Called from loadDashboard.
var _trendsLoaded = false;
export function loadReadinessTrends() {
  if (_trendsLoaded) return;
  var agentId = state.agents && state.agents.length > 0 ? state.agents[0].agentId : null;
  if (!agentId) return;
  apicall('/api/ti/readiness/history?agentId=' + encodeURIComponent(agentId) + '&limit=5').then(function(data) {
    if (!data || !data.trends || data.trends.length === 0) return;
    _trendsLoaded = true;
    var sec = document.getElementById('dash-trends-section');
    if (sec) sec.style.display = '';
    var el = document.getElementById('dash-trends-table');
    if (!el) return;
    var improved = data.trends.filter(function(t) { return t.direction === 'up'; }).length;
    var regressed = data.trends.filter(function(t) { return t.direction === 'down'; }).length;
    // Summary KPIs
    var summary = document.getElementById('dash-trends-kpis');
    if (summary) {
      summary.innerHTML =
        '<span style="margin-right:1rem"><strong class="u-success">' + improved + '</strong> improved</span>' +
        '<span style="margin-right:1rem"><strong class="u-danger">' + regressed + '</strong> regressed</span>' +
        '<span><strong>' + data.total + '</strong> actors tracked</span>';
    }
    // Trend table — show top 10 by most recent prevention, sorted worst-first
    var rows = data.trends.slice().sort(function(a,b) { return a.latestPrevention - b.latestPrevention; }).slice(0, 10);
    el.innerHTML = rows.map(function(t) {
      var arrow = t.direction === 'up'
        ? '<span style="color:var(--success);font-weight:700">&#8679; +' + t.preventionDelta.toFixed(1) + '%</span>'
        : t.direction === 'down'
        ? '<span style="color:var(--danger);font-weight:700">&#8681; ' + t.preventionDelta.toFixed(1) + '%</span>'
        : '<span class="u-muted">&#8213;</span>';
      var prevColor = _riskScoreColor(t.latestPrevention);
      return '<tr>' +
        '<td style="font-size:0.8rem;font-weight:600">' + x(t.actorName) + '</td>' +
        '<td style="text-align:right;font-weight:700;color:' + prevColor + '">' + t.latestPrevention.toFixed(0) + '%</td>' +
        '<td style="text-align:right">' + arrow + '</td>' +
        '<td style="text-align:right;font-size:0.75rem;color:var(--muted)">' + t.dataPoints + ' runs</td>' +
        '</tr>';
    }).join('');
  }).catch(function() {});
}
export function cmpAgentOS(a) { var o = (a.osVersion || '').toLowerCase(); return o.indexOf('windows') >= 0 ? 'windows' : (o.indexOf('darwin') >= 0 || o.indexOf('macos') >= 0) ? 'darwin' : 'linux'; }
function cmpFiltered() {
  var os = document.getElementById('cmp-filter-os').value, env = document.getElementById('cmp-filter-env').value;
  return state.agents.filter(function(a) {
    if (a.status === 'offline') return false;
    if (os && cmpAgentOS(a) !== os) return false;
    if (env && a.envLabel !== env) return false;
    return true;
  });
}
export function renderCampaignTargets() {
  var list = cmpFiltered();
  document.getElementById('cmp-targets').innerHTML = list.length ? list.map(function(a) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox" ' + (state._cmpSel[a.agentId] ? 'checked' : '') + ' ' + on('change', 'cmpSelChange', a.agentId) + '>' +
      '<code style="font-size:0.72rem">' + x(a.agentId) + '</code><span class="tiny muted">' + x(a.hostname) + ' · ' + cmpAgentOS(a) + '</span></label>';
  }).join('') : '<div class="empty tiny">No online agents match the filter.</div>';
  cmpUpdateCount();
}
export function cmpSelectAllFiltered() { cmpFiltered().forEach(function(a) { state._cmpSel[a.agentId] = true; }); renderCampaignTargets(); }
export function cmpUpdateCount() {
  var n = Object.keys(state._cmpSel).filter(function(k) { return state._cmpSel[k]; }).length;
  document.getElementById('cmp-target-cnt').textContent = '(' + n + ' selected)';
}
export function submitCampaign() {
  var name = document.getElementById('cmp-name').value.trim();
  var targetType = document.getElementById('cmp-target-type').value;
  if (!name) { showToast('Campaign name required', 'err'); return; }
  // A campaign has exactly one source -- validate against CMP_SOURCE, not
  // whatever happens to be sitting in cmp-scenario, so a stale/leftover
  // value from the other (inactive) source can never slip through.
  if (CMP_SOURCE === 'threat_informed' && !_tiGeneratedScenarioId) {
    showToast('Select a Threat Intel pack and click Generate Campaign first', 'err'); return;
  }
  var scenarioId = CMP_SOURCE === 'threat_informed' ? _tiGeneratedScenarioId : document.getElementById('cmp-scenario').value;
  if (CMP_SOURCE === 'existing_scenario' && !scenarioId) {
    showToast('Select a scenario', 'err'); return;
  }
  var mode = document.getElementById('cmp-mode').value;
  if (mode !== 'posture' && !confirm(mode.toUpperCase() + ' mode runs real techniques and will generate alerts. Continue?')) return;
  var body = {
    name: name, scenarioId: scenarioId, targetType: targetType,
    mode: mode, confirmLive: mode !== 'posture', confirmLab: mode === 'lab',
    notes: document.getElementById('cmp-notes').value.trim()
  };
  if (targetType === 'agents') {
    var agentIds = Object.keys(state._cmpSel).filter(function(k) { return state._cmpSel[k]; });
    if (!agentIds.length) { showToast('Select at least one target agent', 'err'); return; }
    body.agentIds = agentIds;
  } else if (targetType === 'group') {
    var groupId = document.getElementById('cmp-group').value;
    if (!groupId) { showToast('Select an agent group', 'err'); return; }
    body.groupId = Number(groupId);
    var excl = Object.keys(CMP.exclusions);
    if (excl.length) body.excludeAgentIds = excl;
  } else if (targetType === 'all') {
    if (!document.getElementById('cmp-all-confirm').checked) { showToast('Confirm targeting all agents first', 'err'); return; }
  }
  apicall('/api/campaigns', { method: 'POST', body: JSON.stringify(body) }).then(function(res) {
    if (res && res.error) { showToast('Launch failed: ' + res.error, 'err'); return; }
    closeCampaignLaunch();
    showToast('Campaign launched — ' + res.dispatched + ' dispatched, ' + res.skipped + ' skipped', 'ok');
    refreshDashboardCampaigns();
    showTab('campaigns'); loadCampaigns();
  }).catch(function(e) { showToast('Launch failed: ' + e.message, 'err'); });
}