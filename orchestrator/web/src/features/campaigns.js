import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { loadScenarios, showThreatPriorityDetail } from './attack-path.js';
import { refreshDashboardCampaigns } from './compliance.js';
import { findingSevBadge } from './findings.js';
import { viewRunResults } from './reports.js';
import { ROLE, activateTab, showTab } from './shell.js';
import { setDisplay } from '../core/inline-style.js';
import { cssVars } from '../core/css-vars.js';
import { setDashKev, setDashPosture, setDashReadiness } from './dash-rich.js';
import { kpi, grid, bar, pill, seg, empty, icon } from '../core/kit.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './cmp-model.js';


// ── Campaigns ────────────────────────────────────────────────────────────────
// mixBar: the prevented / detected / missed bar of a campaign (an empty track while nothing has been scored).
function mixBar(mx) {
  var segs = mx.segs.filter(function(s) { return s.n > 0; }).map(function(s) { return '<i class="k-' + s.key + '" data-w="' + s.pct.toFixed(1) + '"></i>'; }).join('');
  return '<div class="cmp-mix" title="Prevented ' + mx.prevented + ' · Detected ' + mx.detected + ' · Missed ' + mx.missed + '">' + segs + '</div>';
}
function mixKey(mx) {
  if (!mx.total) return '<div class="cmp-k"><span class="muted">No results yet</span></div>';
  return '<div class="cmp-k"><span class="k-prevented">' + mx.prevented + ' prevented</span><span class="k-detected">' + mx.detected + ' detected</span><span class="k-missed">' + mx.missed + ' missed</span></div>';
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
var CAMPAIGN_Q = '';
export function loadCampaigns() {
  apicall('/api/campaigns').then(function(list) {
    state._campaigns = list || [];
    renderCampaignHero();
    renderCampaignToolbar();
    renderCampaignRows();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
function renderCampaignHero() {
  var h = M.heroStats(state._campaigns || []);
  setHeroStat('campaign-cnt', h.total);
  setHeroStat('campaign-hs-completed', h.completed);
  setHeroStat('campaign-hs-partial', h.partial);
  setHeroStat('campaign-hs-runs', h.runs);
}
function renderCampaignToolbar() {
  var list = state._campaigns || [];
  var chips = M.chipCounts(list);
  if (!chips.some(function(c) { return c.id === CAMPAIGN_TAB; })) CAMPAIGN_TAB = 'all';
  var bar2 = document.getElementById('campaign-filters');
  if (bar2) bar2.hidden = !list.length;
  var el = document.getElementById('campaign-toolbar');
  if (el) el.innerHTML = list.length ? seg(chips, CAMPAIGN_TAB, 'setCampaignTab') : '';
  var clr = document.getElementById('campaign-clear');
  if (clr) clr.hidden = !(CAMPAIGN_Q || CAMPAIGN_TAB !== 'all');
}
export function setCampaignTab(v) { CAMPAIGN_TAB = v; renderCampaignToolbar(); renderCampaignRows(); }
export function campaignSearch(el) { CAMPAIGN_Q = (el && el.value) || ''; renderCampaignToolbar(); renderCampaignRows(); }
export function campaignClearFilters() {
  CAMPAIGN_Q = ''; CAMPAIGN_TAB = 'all';
  var s = document.getElementById('campaign-search'); if (s) s.value = '';
  renderCampaignToolbar(); renderCampaignRows();
}

function campaignCard(c) {
  var s = c.summary || {};
  var st = M.statusInfo(s);
  var mx = M.mix(s);
  var f = M.cardFacts(c);
  var live = s.status === 'running'
    ? '<div class="cmp-live-line"><span>' + (s.paused ? 'Paused' : 'In progress') + '</span><span>' + (s.progress || 0) + '%</span></div>' + bar(s.progress || 0, s.paused ? 'warn' : 'info')
    : '';
  var fact = function(label, value) { return '<div><div class="muted">' + label + '</div><b>' + x(value) + '</b></div>'; };
  return '<div class="rk-card cmp-card"' + on('click', 'openCampaignDetail', c.id) + '>' +
    '<div class="cmp-hd"><h2>' + x(c.name) + '</h2>' + pill(st.label, st.tone) + '</div>' +
    '<p class="cmp-sub muted">' + x(c.scenarioName || '—') + ' · ' + x(M.agentsLine(s)) + '</p>' +
    '<div class="cmp-id mono muted">' + x(c.id) + (c.createdBy ? ' · ' + x(c.createdBy) : '') + '</div>' +
    live + mixBar(mx) + mixKey(mx) +
    '<div class="cmp-facts">' + fact('Runs', f.runs) + fact('Prevented', f.rate == null ? '—' : f.rate + '%') + fact('Started', f.started) + '</div>' +
    '<div><button type="button" class="btn btn-outline btn-sm">View per-agent breakdown</button></div>' +
    '</div>';
}

function renderCampaignRows() {
  var all = state._campaigns || [];
  var list = M.filter(all, CAMPAIGN_TAB, CAMPAIGN_Q);
  var body = document.getElementById('campaigns-body');
  var emp = document.getElementById('campaigns-empty');
  if (!body) return;
  if (!list.length) {
    body.innerHTML = '';
    body.hidden = true;
    if (emp) {
      emp.hidden = false;
      emp.innerHTML = all.length
        ? empty('search', 'No campaigns match', 'Clear the filters to see all campaigns.') + '<div class="init-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'campaignClearFilters') + '>Clear filters</button></div>'
        : empty('campaign', 'No campaigns yet', 'Launch a campaign to fan one scenario out across many agents.');
    }
    return;
  }
  body.hidden = false;
  if (emp) { emp.hidden = true; emp.innerHTML = ''; }
  body.innerHTML = list.map(campaignCard).join('');
}

// closeCampaignDetail closes the drawer and refreshes the list (also what showing the tab calls).
export function closeCampaignDetail() {
  var o = document.getElementById('cmp-drawer-overlay');
  if (o) o.classList.remove('open');
  loadCampaigns();
}
export function closeCampaignDrawerOnBackdrop(el, event) { if (event.target === el) closeCampaignDetail(); }

function runTone(rn) {
  if (rn.status === 'running' && rn.paused) return { label: 'Paused', tone: 'warn' };
  var tone = rn.status === 'completed' ? 'ok' : rn.status === 'failed' ? 'bad' : rn.status === 'running' ? 'info' : 'muted';
  var label = String(rn.status || '—');
  return { label: label.charAt(0).toUpperCase() + label.slice(1), tone: tone };
}

function timelineHtml(steps) {
  return '<div class="cmp-tl">' + steps.map(function(t, i) {
    var dot = t.state === 'done' ? icon('ok') : t.state === 'fail' ? icon('x') : String(i + 1);
    var tag = t.tag ? '<span class="rk-chip tone-' + M.tagTone(t.pct) + '">' + x(t.tag) + '</span>' : '';
    return '<div class="cmp-tl-step ' + t.state + '"><div class="cmp-tl-dot">' + dot + '</div>' +
      '<div class="grow"><div class="t">' + x(t.label) + '</div><div class="d">' + x(t.detail) + '</div></div>' + tag + '</div>';
  }).join('') + '</div>';
}

export function openCampaignDetail(id) {
  apicall('/api/campaigns/' + encodeURIComponent(id)).then(function(c) {
    var s = c.summary || {};
    var st = M.statusInfo(s);
    var mx = M.mix(s);
    var eff = mx.total ? Math.round(((s.prevented || 0) * 100 + (s.detected || 0) * 50) / mx.total) : null;
    document.getElementById('cmp-drawer-title').textContent = c.name || c.id;
    document.getElementById('cmp-drawer-sub').textContent = c.id + ' · ' + (c.scenarioName || '—');

    // ── running banner ──
    var banner = (s.status === 'running')
      ? '<div class="cmp-live"><div class="cmp-live-line"><span>' + (s.paused ? 'Campaign paused — ' : 'Campaign in progress — ') + (s.dispatched || 0) + '/' + (s.targets || 0) + ' agents dispatched</span><span>' + (s.progress || 0) + '%</span></div>' +
        bar(s.progress || 0, s.paused ? 'warn' : 'info', true) + '</div>'
      : '';
    // ── per-agent results table ──
    var rows = (c.runs || []).map(function(rn) {
      var rt = runTone(rn);
      var col = rn.status === 'completed' ? 'var(--success)' : rn.status === 'failed' ? 'var(--danger)' : 'var(--muted)';
      return '<tr><td>' + pill(rt.label, rt.tone) + '</td>' +
        '<td class="g1-s-97a09173">' + x(rn.agentId) + '</td>' +
        '<td class="g1-s-6e8bcfac"' + cssVars(['g1-v-7d75dfc9', col]) + '>' + (rn.preventionScore ? Math.round(rn.preventionScore) + '%' : '—') + '</td>' +
        '<td class="td-r"><button class="btn btn-outline btn-sm"' + on('click', 'openRunFromCampaign', rn.runId) + '>Results &rarr;</button></td></tr>';
    }).join('') || '<tr><td colspan="4" class="empty">No child runs dispatched.</td></tr>';
    var perAgent = '<h4 class="sc-h4">Per-agent results</h4><div class="tbl-wrap init-dr-tbl"><table>' +
      '<thead><tr><th>Status</th><th>Agent</th><th>Prevention</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>';
    // ── skipped targets ──
    var skips = (c.skips || []).length
      ? '<h4 class="sc-h4">Skipped targets (' + c.skips.length + ')</h4><div class="cmp-skips">' +
        c.skips.map(function(k) { return '<div><code>' + x(k.agentId) + '</code><span class="tiny muted">' + x(k.reason) + '</span></div>'; }).join('') + '</div>'
      : '';
    // ── run summary ──
    var kvRow = function(k, v) { return '<dt>' + k + '</dt><dd>' + v + '</dd>'; };
    var targetKv = c.targetType === 'group'
      ? 'Agent Group — ' + x(CMP.groupsById[c.targetGroupId] || ('Group #' + c.targetGroupId))
      : c.targetType === 'all' ? 'All Agents' : (s.targets || 0) + ' agents selected';
    var summary = '<h4 class="sc-h4">Run summary</h4><dl class="rk-kv">' +
      kvRow('Campaign ID', '<code>' + x(c.id) + '</code>') + kvRow('Scenario', x(c.scenarioName)) +
      kvRow('Target', targetKv) +
      kvRow('Targets', (s.dispatched || 0) + ' dispatched · ' + (s.skipped || 0) + ' skipped of ' + (s.targets || 0)) +
      kvRow('Mode', x(c.mode || '—')) + kvRow('Initiated by', x(c.createdBy || '—')) +
      kvRow('Started', x(M.startedStamp(c.startedAt))) +
      kvRow('Result mix', mixBar(mx)) + '</dl>';
    // ── related ──
    var rel = '<h4 class="sc-h4">Related</h4><div class="sc-rel-list">' +
      (s.status === 'running' ? '' :
        '<div class="sc-rel" tabindex="0" role="button"' + on('click', 'openCampaignReport', c.id) + '>' + icon('file') +
          '<div class="grow"><b>Campaign report</b><em>Open the fleet-wide HTML report</em></div>' + icon('chevron') + '</div>') +
      '<div class="sc-rel" tabindex="0" role="button"' + on('click', 'campaignOpenFindings') + '>' + icon('alert') +
        '<div class="grow"><b>Findings from this campaign</b><em id="cmp-rel-findings">Open the findings list</em></div>' + icon('chevron') + '</div></div>';

    document.getElementById('cmp-drawer-body').innerHTML =
      '<div class="k8s-dr-top cmp-dr-top">' + pill(st.label, st.tone) + '<span class="muted">' + x(M.runsLine(c)) + '</span></div>' +
      banner + timelineHtml(M.timeline(c)) +
      '<h4 class="sc-h4">Results</h4>' +
      grid(4, [
        kpi({ label: 'Effectiveness', value: eff == null ? '—' : eff, sub: 'weighted result', icon: 'trend', tone: eff == null ? 'muted' : eff >= 60 ? 'ok' : eff >= 40 ? 'warn' : 'bad' }),
        kpi({ label: 'Prevented', value: s.prevented || 0, sub: 'blocked', icon: 'shield', tone: 'ok' }),
        kpi({ label: 'Detected only', value: s.detected || 0, sub: 'alerted, not blocked', icon: 'eye', tone: 'warn' }),
        kpi({ label: 'Missed', value: s.missed || 0, sub: 'no control response', icon: 'alert', tone: s.missed ? 'bad' : 'muted' }),
      ]) +
      perAgent + skips + summary +
      '<div id="cmp-recs" class="cmp-recs"></div>' + rel;

    // ── actions ──
    var foot = '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'closeCampaignDetail') + '>Close</button><span class="grow"></span>';
    if (s.status === 'running') {
      foot += (s.paused
        ? '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'resumeCampaign', c.id) + ' title="Resume every paused child run">' + icon('play') + 'Resume campaign</button>'
        : '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'pauseCampaign', c.id) + ' title="Pause every running child run">' + icon('pause') + 'Pause campaign</button>') +
        '<button type="button" class="btn btn-outline btn-sm init-del"' + on('click', 'stopCampaign', c.id) + '>Stop campaign</button>';
    } else {
      foot += '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'downloadCampaignReport', c.id) + ' title="Download the fleet-wide report as a PDF file">PDF Report</button>' +
        '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'downloadCampaignCSV', c.id) + ' title="Download the fleet forensic CSV (one row per technique across all agents)">CSV</button>' +
        ((ROLE === 'admin' || ROLE === 'analyst')
          ? '<button type="button" class="btn btn-primary btn-sm"' + on('click', 'openCampaignRerunReview', c) + ' title="Review and re-run this exact campaign configuration">Re-run</button>'
          : '<button type="button" class="btn btn-primary btn-sm" disabled title="Re-run requires the Analyst or Admin role">Re-run</button>');
    }
    document.getElementById('cmp-drawer-foot').innerHTML = foot;

    activateTab('campaigns'); // in case opened from the dashboard
    if (!(state._campaigns || []).length) loadCampaigns();
    document.getElementById('cmp-drawer-overlay').classList.add('open');
    renderCampaignRecs(c.id);
  }).catch(function(e) { showToast(e.message, 'err'); });
}
export function campaignOpenFindings() {
  document.getElementById('cmp-drawer-overlay').classList.remove('open');
  showTab('findings');
}
// renderCampaignRecs shows this campaign's Top Open findings and Top Regressions
// (not the whole fleet) — the actionable next steps for the run.
function renderCampaignRecs(campaignId) {
  apicall('/api/findings').then(function(fs) {
    var el = document.getElementById('cmp-recs');
    if (!el) return;
    var mine = (fs || []).filter(function(f) { return f.lastCampaignId === campaignId; });
    var openAll = mine.filter(function(f) { return f.status === 'open'; });
    var open = openAll.slice(0, 5);
    var regr = mine.filter(function(f) { return f.reopenedCount > 0 && f.status === 'open'; }).slice(0, 3);
    var relEl = document.getElementById('cmp-rel-findings');
    if (relEl) relEl.textContent = openAll.length ? openAll.length + ' open' : 'No open findings';
    var hdr = function(t) { return '<h4 class="sc-h4">' + t + '</h4>'; };
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
    .then(function() { showToast('Campaign stopped', 'ok'); openCampaignDetail(id); loadCampaigns(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}
export function pauseCampaign(id) {
  apicall('/api/campaigns/' + encodeURIComponent(id) + '/pause', { method: 'POST' })
    .then(function(res) { showToast('Pausing ' + ((res && res.pausing) || 0) + ' running child run(s)', 'ok'); openCampaignDetail(id); loadCampaigns(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}
export function resumeCampaign(id) {
  apicall('/api/campaigns/' + encodeURIComponent(id) + '/resume', { method: 'POST' })
    .then(function(res) { showToast('Resuming ' + ((res && res.resuming) || 0) + ' paused child run(s)', 'ok'); openCampaignDetail(id); loadCampaigns(); })
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
  setDisplay(document.getElementById('ti-pack-preview'), 'none');
  setDisplay(document.getElementById('ti-generated-preview'), 'none');
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
  setDisplay(document.getElementById('cmp-target-agents-wrap'), (type === 'agents') ? 'block' : 'none');
  setDisplay(document.getElementById('cmp-target-group-wrap'), (type === 'group') ? 'block' : 'none');
  setDisplay(document.getElementById('cmp-target-all-wrap'), (type === 'all') ? 'block' : 'none');
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
    return '<label class="g1-display-flex g1-s-28328479">' +
      '<input type="checkbox"' + on('change', 'cmpToggleExclusionFromChecked', a.agentId) + '>' +
      '<code class="g1-s-8f55e862">' + x(a.agentId) + '</code><span class="tiny muted">' + x(a.hostname) + '</span></label>';
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
  setDisplay(document.getElementById('cmp-source-ti'), (CMP_SOURCE === 'threat_informed') ? '' : 'none');
  setDisplay(document.getElementById('cmp-source-existing'), (CMP_SOURCE === 'existing_scenario') ? '' : 'none');
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
  setDisplay(document.getElementById('ti-pack-preview'), 'none');
  setDisplay(document.getElementById('ti-generated-preview'), 'none');
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
  setDisplay(preview, 'none');
  info.textContent = 'Loading…';
  // Picking a (possibly different) pack starts over -- any earlier generated
  // campaign from a prior pack in this same session no longer applies.
  _tiGeneratedScenarioId = null;
  setDisplay(document.getElementById('ti-generated-preview'), 'none');
  // Highlight selected button
  document.querySelectorAll('#ti-pack-grid .btn').forEach(function(b) { b.style.borderColor = ''; });
  event && event.target && (event.target.style.borderColor = 'var(--accent)');
  apicall('/api/ti/suggest-pack?type=' + encodeURIComponent(type)).then(function(pack) {
    _tiPackData = pack;
    if (!pack || !pack.hasData) {
      info.innerHTML = '<span class="u-danger">No data available for this pack — run more scenarios or reseed content first.</span>';
      setDisplay(preview, '');
      return;
    }
    var tacticSet = {};
    (pack.techniques || []).forEach(function(t) { if (t.tactic) tacticSet[t.tactic] = true; });
    var tacticCount = Object.keys(tacticSet).length;
    var ransomNote = pack.ransomwareCount > 0 ? ' &middot; <strong class="u-warning">' + pack.ransomwareCount + ' ransomware-linked</strong>' : '';
    var kevNote = pack.totalKevCves > 0 ? ' &middot; ' + pack.totalKevCves + ' KEV CVEs' : '';
    info.innerHTML = (_tiPackIcons[type] || '') + ' <strong>' + x(pack.packName) + '</strong><br>' +
      '<span class="u-muted">' + x(pack.description) + '</span><br>' +
      '<span class="g1-display-inline-block g1-s-ee12b4c2"><strong>' + pack.techniqueCount + '</strong> techniques &middot; <strong>' + tacticCount + '</strong> tactics' + kevNote + ransomNote + '</span>';
    setDisplay(preview, '');
    // Pre-fill campaign name
    var nameEl = document.getElementById('cmp-name');
    if (!nameEl.value) nameEl.value = pack.suggestedName || '';
  }).catch(function() {
    info.innerHTML = '<span class="u-danger">Failed to fetch pack data.</span>';
    setDisplay(preview, '');
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
  setDisplay(el, '');
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
  var tagsLine = (sc.tags || []).length ? '<br><span class="g1-s-62899a0f">' + sc.tags.map(x).join(' &middot; ') + '</span>' : '';
  el.innerHTML = x(desc) + tagsLine;
}

// loadKEVWidget fetches the KEV pack data and the threat-intel summary for the dashboard's Threat
// intelligence row (Top threat actors, KEV exposure). dash-rich.js renders both cards.
export function loadKEVWidget() {
  Promise.all([
    apicall('/api/ti/suggest-pack?type=kev').catch(function() { return null; }),
    apicall('/api/analytics/threat-intel-summary').catch(function() { return null; })
  ]).then(function(res) {
    setDashKev(res[0] || { hasData: false }, res[1] || { topActors: [] });
  });
}

// loadEndpointPostureWidget fetches the fleet-wide endpoint posture summary for the dashboard's
// Endpoint posture row. dash-rich.js renders the cards (and the untrusted / isolated flags).
export function loadEndpointPostureWidget() {
  apicall('/api/analytics/endpoint-posture').then(function(p) {
    setDashPosture(p);
  }).catch(function() { setDashPosture(null); });
}

// loadReadinessTrends fetches the per-actor readiness history for the most recently active agent;
// dash-rich.js renders the trend table, the Prevention by actor bars and the prevention line.
export function loadReadinessTrends() {
  var agentId = state.agents && state.agents.length > 0 ? state.agents[0].agentId : null;
  if (!agentId) { setDashReadiness({ trends: [] }); return; }
  apicall('/api/ti/readiness/history?agentId=' + encodeURIComponent(agentId) + '&limit=6').then(function(data) {
    setDashReadiness(data && data.trends ? data : { trends: [] });
  }).catch(function() { setDashReadiness({ trends: [] }); });
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
    return '<label class="g1-display-flex g1-s-28328479">' +
      '<input type="checkbox" ' + (state._cmpSel[a.agentId] ? 'checked' : '') + ' ' + on('change', 'cmpSelChange', a.agentId) + '>' +
      '<code class="g1-s-8f55e862">' + x(a.agentId) + '</code><span class="tiny muted">' + x(a.hostname) + ' · ' + cmpAgentOS(a) + '</span></label>';
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