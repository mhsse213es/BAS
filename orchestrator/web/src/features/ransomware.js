import { state } from '../core/state.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { ago, showToast } from '../core/util.js';
import { openModal } from './reports.js';
import { _riskScoreColor, showTab } from './shell.js';
import { setDisplay } from '../core/inline-style.js';
import { cssVars } from '../core/css-vars.js';
import { apicall } from '../core/api.js';


// ── Ransomware Readiness Module ───────────────────────────────────────────────
//
// Scoring is computed server-side by internal/rwscore (sub-project #2 of
// the ransomware-mastery roadmap) and fetched from GET
// /api/scenarios/runs/{runId}/rw-score -- this module never recomputes or
// blends a score client-side.

var RR_SCENARIO_IDS = [
  'akira-kill-chain', 'blackcat-kill-chain', 'clop-kill-chain', 'lockbit-kill-chain',
  'play-kill-chain', 'ransomhub-kill-chain', 'ransomware-drill', 'em-07-ransomware-readiness',
  'linux-ransomware-drill', 'black-basta-kill-chain', 'medusa-kill-chain', 'rhysida-kill-chain'
];

// Dimension display config: rwscore.Dimension value → { label, icon }
var RW_DIMENSIONS = {
  prevention:      { label: 'Prevention',      icon: '&#x1F6E1;' },
  detection:        { label: 'Detection',       icon: '&#x1F50D;' },
  containment:      { label: 'Containment',     icon: '&#x1F6A7;' },
  recovery:         { label: 'Recovery',        icon: '&#x1F504;' },
  data_protection:  { label: 'Data Protection', icon: '&#x1F4BE;' }
};

// Rating display config: rwscore.Rating value → { label, bg, color }
var RW_RATING_TIERS = {
  protected:  { label: 'Protected',  bg: 'rgba(35,134,54,0.15)',  color: 'var(--success)' },
  at_risk:    { label: 'At Risk',    bg: 'rgba(210,153,34,0.15)', color: 'var(--warning)' },
  vulnerable: { label: 'Vulnerable', bg: 'rgba(218,54,51,0.15)',  color: 'var(--danger)' }
};

export function loadRansomwareReadiness(runs) {
  var bodyEl = document.getElementById('rr-body');
  var tierEl = document.getElementById('rr-tier');
  var lastEl = document.getElementById('rr-last');
  if (!bodyEl) return;

  // Find the most recent run across the 8 real ransomware scenarios
  // (runs is already ORDER BY started_at DESC, so first match wins).
  var rrRun = null;
  for (var i = 0; i < runs.length; i++) {
    var r = runs[i];
    if (RR_SCENARIO_IDS.indexOf(r.scenarioId) !== -1 && (r.results || []).length) {
      rrRun = r; break;
    }
  }

  if (!rrRun) {
    bodyEl.innerHTML = '<div class="empty g1-s-dab79d7d">Run one of the ransomware scenarios to generate a readiness score.</div>';
    return;
  }

  // Show last-run timestamp
  var ts = rrRun.completedAt || rrRun.startedAt;
  if (lastEl && ts) lastEl.textContent = ago(ts);

  apicall('/api/scenarios/runs/' + encodeURIComponent(rrRun.id) + '/rw-score').then(function(score) {
    renderRansomwareScore(bodyEl, tierEl, rrRun, score);
  }).catch(function() {
    bodyEl.innerHTML = '<div class="empty g1-s-dab79d7d">Score unavailable for the latest run.</div>';
  });
}

function renderRansomwareScore(bodyEl, tierEl, rrRun, score) {
  var tier = RW_RATING_TIERS[score.rating] || { label: score.rating || 'Unknown', bg: 'var(--elevated)', color: 'var(--muted)' };
  if (tierEl) {
    tierEl.textContent = tier.label;
    tierEl.style.background = tier.bg;
    tierEl.style.color = tier.color;
    setDisplay(tierEl, '');
  }

  var overallPct = Math.round(score.overall);
  var scoreHtml = '<div class="g1-display-flex g1-s-73ecc07e"' + cssVars(['g1-v-bd5c5d10', _riskScoreColor(overallPct), overallPct]) + '>' +
      '<div class="g1-display-flex g1-s-cbd566af">' +
        '<span class="g1-s-ddc46798"' + cssVars(['g1-v-7d75dfc9', _riskScoreColor(overallPct)]) + '>' + overallPct + '</span>' +
        '<span class="g1-s-e8485c25">score</span>' +
      '</div>' +
    '</div>';

  var dims = score.dimensions || [];
  var barsHtml = dims.length ? dims.map(function(d) {
    var cfg = RW_DIMENSIONS[d.dimension] || { label: (d.dimension || '').replace(/_/g, ' '), icon: '' };
    var evaluated = (d.pass || 0) + (d.fail || 0) + (d.error || 0) + (d.unknown || 0);
    var pct = evaluated ? Math.round(d.passRate * 100) : null;
    var col = pct === null ? 'var(--muted)' : _riskScoreColor(pct);
    var pctLabel = pct !== null ? pct + '%' : 'no data';
    var unresolved = (d.error || 0) + (d.unknown || 0);
    return '<div class="g1-s-04f181fe">' +
      '<div class="g1-display-flex g1-s-58f2e5c4">' +
        '<span class="u-text">' + cfg.icon + ' ' + x(cfg.label) + '</span>' +
        '<span class="g1-s-6e8bcfac"' + cssVars(['g1-v-7d75dfc9', col]) + '>' + pctLabel + '</span>' +
      '</div>' +
      '<div class="g1-s-abdb10c3">' +
        (pct !== null ? '<div class="g1-s-2cd8e04f"' + cssVars(['g1-v-9b890877', pct], ['g1-v-9ffd39ba', col]) + '></div>' : '') +
      '</div>' +
      '<div class="g1-s-e79e1ce2">' + (d.pass || 0) + ' pass &middot; ' + (d.fail || 0) + ' fail' + (unresolved ? ' &middot; ' + unresolved + ' unresolved' : '') + '</div>' +
    '</div>';
  }).join('') : '<div class="empty g1-s-dab79d7d">No dimension data in this run.</div>';

  var gateHtml = score.gateTriggered && (score.criticalFailures || []).length
    ? '<div class="g1-s-e79e1ce2"' + cssVars(['g1-v-7d75dfc9', 'var(--danger)']) + '>&#x26A0; ' + x(score.criticalFailures.join('; ')) + '</div>'
    : '';

  bodyEl.innerHTML =
    '<div class="g1-display-flex g1-s-d7f84b58">' +
      scoreHtml +
      '<div class="g1-s-28637295">' + barsHtml + '</div>' +
      gateHtml +
      '<div class="g1-display-flex g1-s-7d5960f3">' +
        '<div><span class="g1-s-13457f1d">' + x(rrRun.name || rrRun.scenarioId) + '</span></div>' +
        '<div>' + (rrRun.agentId ? 'Agent: ' + x(rrRun.agentId) : '') + '</div>' +
        '<div class="g1-s-f6c1493f">' +
          '<span class="sbadge s-' + x(rrRun.status) + '">' + x(rrRun.status) + '</span>' +
        '</div>' +
        '<a class="g1-s-9ed2816e"' + on('click', 'viewRunResults', rrRun) + '>View full report →</a>' +
      '</div>' +
    '</div>';
}

export function runRansomwareDrill() {
  // Use globals already loaded; pick ransomware-drill first, fall back to em-07
  var drillId = null;
  for (var i = 0; i < state.scenarios.length; i++) {
    if (state.scenarios[i].id === 'ransomware-drill') { drillId = state.scenarios[i].id; break; }
  }
  if (!drillId) {
    for (var j = 0; j < state.scenarios.length; j++) {
      if (state.scenarios[j].id === 'em-07-ransomware-readiness') { drillId = state.scenarios[j].id; break; }
    }
  }
  if (!drillId) {
    showToast('Ransomware drill scenario not loaded yet. Check scenario library.', 'err');
    showTab('scenarios'); return;
  }
  if (!state.agents.length) {
    showToast('No agents enrolled. Enroll an agent first.', 'err');
    showTab('agents'); return;
  }
  openModal(drillId, state.agents[0].agentId);
}