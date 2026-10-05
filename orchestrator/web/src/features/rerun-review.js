import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { showToast } from '../core/util.js';
import { CMP, loadCampaigns } from './campaigns.js';
import { refreshDashboardCampaigns } from './compliance.js';
import { closeResults } from './iocs.js';
import { MODE_LABELS, scenarioFramework } from './reports.js';
import { showTab } from './shell.js';


// ── Re-run Review ────────────────────────────────────────────────────────────
// Clones a past run's exact configuration -- agent, mode, privilege, and
// (framework permitting) the exact technique/check subset that ran -- and
// presents it read-only with a single Start button. No wizard, nothing to
// reselect; replaces the earlier "Re-run reopens the full dispatch wizard"
// behavior.
var _rerunReviewRun = null;
// _rerunReviewKind ('run' | 'campaign') lets the one shared drawer route
// Start/Cancel to the right entity -- openCampaignRerunReview below reuses
// this same drawer rather than duplicating its markup.
var _rerunReviewKind = null;
var _rerunReviewCampaign = null;

// rerunSubset returns the exact dispatch-subset (field + ids) a past run
// used. run.dispatchSubset is captured verbatim at dispatch time (see
// dispatchSubsetFromOpts, internal/api/handlers.go) and is exact for every
// framework, including Caldera (ability UUID) and custom steps (step index)
// -- neither is recoverable from results after the fact. Only runs dispatched
// before that field existed fall back to reconstructing from results, which
// is exact for art/posture (result.technique.id / result.checkId IS the
// dispatch id) but not for caldera/steps, so those legacy runs re-run in full.
export function rerunSubset(run, fw) {
  if (run.dispatchSubset && run.dispatchSubset.field && (run.dispatchSubset.ids || []).length) {
    return { field: run.dispatchSubset.field, ids: run.dispatchSubset.ids, exact: true };
  }
  if (fw !== 'art' && fw !== 'posture') return { field: null, ids: [] };
  var seen = {}, ids = [];
  (run.results || []).forEach(function(r) {
    var id = fw === 'art' ? (r.technique && r.technique.id) : r.checkId;
    if (id && !seen[id]) { seen[id] = true; ids.push(id); }
  });
  return { field: fw === 'art' ? 'techniques' : 'checks', ids: ids, exact: true };
}

export function openRerunReview(run) {
  _rerunReviewKind = 'run';
  _rerunReviewRun = run;
  document.getElementById('rerun-review-title').textContent = 'Re-run Review';
  document.getElementById('rerun-review-subtitle').textContent = "Exact clone of the original run's configuration — nothing below is editable.";
  var sc = state.scenarios.find(function(s) { return s.id === run.scenarioId; });
  var fw = scenarioFramework(sc);
  var agent = state.agents.find(function(a) { return a.agentId === run.agentId; });
  var subset = rerunSubset(run, fw);

  var rows = [];
  rows.push(['Scenario', x(sc ? sc.name : run.scenarioId)]);
  rows.push(['Agent', x(agent ? agent.hostname + ' (' + agent.agentId + ')' : run.agentId)]);
  rows.push(['Mode', x(MODE_LABELS[run.mode] || run.mode || 'Posture')]);
  if (run.maxPrivilege) rows.push(['Privilege ceiling', x(run.maxPrivilege.charAt(0).toUpperCase() + run.maxPrivilege.slice(1))]);
  if (subset.field) {
    rows.push(['Techniques', subset.ids.length + ' — ' + subset.ids.slice(0, 6).join(', ') + (subset.ids.length > 6 ? ', …' : '')]);
  } else if (!subset.exact && (fw === 'caldera' || fw === 'steps')) {
    // Only reachable for a run dispatched before dispatch_subset existed --
    // its exact ability/step subset was never recoverable from results alone.
    rows.push(['Techniques', 'All (this run predates exact re-run tracking, so its ' + (fw === 'caldera' ? 'Caldera ability' : 'step') + ' subset can\'t be recovered — re-runs the full scenario)']);
  } else {
    rows.push(['Techniques', 'All']);
  }

  document.getElementById('rerun-review-body').innerHTML = rows.map(function(r) {
    return '<div class="conn-cfg-row"><span class="conn-cfg-label">' + r[0] + '</span><span class="conn-cfg-val">' + r[1] + '</span></div>';
  }).join('');
  document.getElementById('rerun-review-overlay').classList.add('open');
}

export function closeRerunReview() {
  document.getElementById('rerun-review-overlay').classList.remove('open');
  _rerunReviewRun = null;
  _rerunReviewCampaign = null;
  _rerunReviewKind = null;
}

export function startRerunFromReview() {
  if (_rerunReviewKind === 'campaign') { startCampaignRerunFromReview(); return; }
  var run = _rerunReviewRun;
  if (!run) return;
  var sc = state.scenarios.find(function(s) { return s.id === run.scenarioId; });
  var fw = scenarioFramework(sc);
  var mode = run.mode || 'posture';

  // Same safety gate every other live/lab dispatch in this app requires --
  // a review screen skips re-SELECTING anything, it doesn't skip confirming
  // a real-technique execution is intentional.
  if (mode === 'telemetry' && !confirm('TELEMETRY mode runs real, identity-safe techniques and WILL generate EDR/SIEM alerts.\n\nProceed only on an approved, monitored target. Continue?')) return;
  if (mode === 'lab') {
    if (!confirm('LAB mode runs FULL-FIDELITY techniques (LSASS dump, allowlisted spray) and will trigger EDR.\n\nISOLATED AD RANGE ONLY — never production. Continue?')) return;
    if (!confirm('Second confirmation required for LAB mode.\n\nConfirm the target is an isolated lab/range with a snapshot?')) return;
  }

  var body = {
    agentId: run.agentId, mode: mode,
    confirmLive: mode !== 'posture', confirmLab: mode === 'lab',
    reason: mode !== 'posture' ? ('Re-run of run ' + (run.id || '')) : '',
    runLabel: run.name ? (run.name + ' — Re-run') : ''
  };
  if (run.maxPrivilege) body.executionPolicy = { maxPrivilege: run.maxPrivilege };
  var subset = rerunSubset(run, fw);
  // steps is the one subset field the API takes as numeric indices (scenario
  // step-list positions), not string ids -- see dispatchOpts.Steps []int.
  if (subset.field) body[subset.field] = (subset.field === 'steps') ? subset.ids.map(Number) : subset.ids;

  var btn = document.getElementById('rerun-review-start-btn');
  btn.disabled = true; btn.textContent = 'Dispatching…';
  apicall('/api/scenarios/' + encodeURIComponent(run.scenarioId) + '/run', {
    method: 'POST', body: JSON.stringify(body)
  }).then(function(res) {
    btn.disabled = false; btn.innerHTML = '&#9654; Start Re-run';
    if (res && res.error) { showToast(res.error, 'err'); return; }
    showToast('Re-run started', 'ok');
    closeRerunReview();
    closeResults();
    showTab('runs');
  }).catch(function(e) {
    btn.disabled = false; btn.innerHTML = '&#9654; Start Re-run';
    showToast(e.message, 'err');
  });
}

// openCampaignRerunReview mirrors openRerunReview for a whole campaign,
// reusing the same read-only drawer. c is GetCampaign's response (see
// openCampaignDetail) -- it carries targets (the exact agent-id snapshot
// frozen at launch, immune to any group-membership changes since) and
// subset (techniques/abilities/steps/checks/executionPolicy, captured
// verbatim by CreateCampaign). Re-running always redispatches to that exact
// frozen agent list via targetType 'agents', never by re-resolving the
// original group/all target -- a group can be edited or deleted after
// launch, and "clone this campaign" means the same targets, not "whoever is
// in the group now".
export function openCampaignRerunReview(c) {
  _rerunReviewKind = 'campaign';
  _rerunReviewCampaign = c;
  document.getElementById('rerun-review-title').textContent = 'Re-run Campaign Review';
  document.getElementById('rerun-review-subtitle').textContent = "Exact clone of the original campaign's configuration — nothing below is editable.";

  var subset = c.subset || {};
  var targetCount = (c.targets || []).length;
  var targetKv = c.targetType === 'group'
    ? 'Agent Group — ' + x(CMP.groupsById[c.targetGroupId] || ('Group #' + c.targetGroupId)) + ' (' + targetCount + ' agent(s) at launch)'
    : c.targetType === 'all' ? 'All Agents at launch (' + targetCount + ' agent(s))'
    : targetCount + ' agent(s)';

  var rows = [];
  rows.push(['Scenario', x(c.scenarioName || c.scenarioId)]);
  rows.push(['Targets', targetKv]);
  rows.push(['Mode', x(MODE_LABELS[c.mode] || c.mode || 'Posture')]);
  if (subset.executionPolicy && subset.executionPolicy.maxPrivilege) {
    rows.push(['Privilege ceiling', x(subset.executionPolicy.maxPrivilege.charAt(0).toUpperCase() + subset.executionPolicy.maxPrivilege.slice(1))]);
  }
  var subsetField = ['techniques', 'abilities', 'steps', 'checks'].find(function(f) { return subset[f] && subset[f].length; });
  rows.push(['Techniques', subsetField
    ? (subset[subsetField].length + ' — ' + subset[subsetField].slice(0, 6).join(', ') + (subset[subsetField].length > 6 ? ', …' : ''))
    : 'All']);

  document.getElementById('rerun-review-body').innerHTML = rows.map(function(r) {
    return '<div class="conn-cfg-row"><span class="conn-cfg-label">' + r[0] + '</span><span class="conn-cfg-val">' + r[1] + '</span></div>';
  }).join('');
  document.getElementById('rerun-review-overlay').classList.add('open');
}

function startCampaignRerunFromReview() {
  var c = _rerunReviewCampaign;
  if (!c) return;
  var mode = c.mode || 'posture';

  if (mode === 'telemetry' && !confirm('TELEMETRY mode runs real, identity-safe techniques and WILL generate EDR/SIEM alerts across every target.\n\nProceed only on an approved, monitored target set. Continue?')) return;
  if (mode === 'lab') {
    if (!confirm('LAB mode runs FULL-FIDELITY techniques (LSASS dump, allowlisted spray) and will trigger EDR, across every target.\n\nISOLATED AD RANGE ONLY — never production. Continue?')) return;
    if (!confirm('Second confirmation required for LAB mode.\n\nConfirm every target is in an isolated lab/range with a snapshot?')) return;
  }

  var subset = c.subset || {};
  var body = {
    name: (c.name || c.scenarioName || 'Campaign') + ' — Re-run',
    scenarioId: c.scenarioId, mode: mode,
    confirmLive: mode !== 'posture', confirmLab: mode === 'lab',
    reason: c.reason || ('Re-run of campaign ' + (c.id || '')),
    notes: c.notes || '',
    targetType: 'agents', agentIds: c.targets || [],
    techniques: subset.techniques, abilities: subset.abilities,
    steps: subset.steps, checks: subset.checks
  };
  if (subset.executionPolicy && subset.executionPolicy.maxPrivilege) body.executionPolicy = subset.executionPolicy;

  var btn = document.getElementById('rerun-review-start-btn');
  btn.disabled = true; btn.textContent = 'Dispatching…';
  apicall('/api/campaigns', { method: 'POST', body: JSON.stringify(body) }).then(function(res) {
    btn.disabled = false; btn.innerHTML = '&#9654; Start Re-run';
    if (res && res.error) { showToast(res.error, 'err'); return; }
    showToast('Campaign re-run started — ' + res.dispatched + ' dispatched, ' + res.skipped + ' skipped', 'ok');
    closeRerunReview();
    refreshDashboardCampaigns();
    showTab('campaigns'); loadCampaigns();
  }).catch(function(e) {
    btn.disabled = false; btn.innerHTML = '&#9654; Start Re-run';
    showToast(e.message, 'err');
  });
}