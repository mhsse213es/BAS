import { state } from '../core/state.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { ago, showToast } from '../core/util.js';
import { openModal } from './reports.js';
import { _riskScoreColor, showTab } from './shell.js';
import { setDisplay } from '../core/inline-style.js';
import { cssVars } from '../core/css-vars.js';


// ── Ransomware Readiness Module ───────────────────────────────────────────────

var RR_SCENARIO_IDS = ['ransomware-drill', 'em-07-ransomware-readiness'];

// Category display config: id → { label, icon }
var RR_CATS = {
  'prevention-posture':  { label: 'Prevention',  icon: '&#x1F6E1;' },
  'backup-resilience':   { label: 'Backup',       icon: '&#x1F4BE;' },
  'recovery-posture':    { label: 'Recovery',     icon: '&#x1F504;' },
  'identity-hardening':  { label: 'Identity',     icon: '&#x1F512;' },
  'detection-posture':   { label: 'Detection',    icon: '&#x1F50D;' },
  'lateral-movement':    { label: 'Lateral Mvmt', icon: '&#x21C4;' }
};

export function loadRansomwareReadiness(runs) {
  var bodyEl = document.getElementById('rr-body');
  var tierEl = document.getElementById('rr-tier');
  var lastEl = document.getElementById('rr-last');
  if (!bodyEl) return;

  // Find the most recent ransomware-drill or em-07 run that has results
  var rrRun = null;
  for (var i = 0; i < runs.length; i++) {
    var r = runs[i];
    if (RR_SCENARIO_IDS.indexOf(r.scenarioId) !== -1 && (r.results || []).length) {
      rrRun = r; break;
    }
  }

  if (!rrRun) {
    bodyEl.innerHTML = '<div class="empty g1-s-dab79d7d">Run the <strong>Ransomware Drill</strong> or <strong>EM-07</strong> scenario to generate a readiness score.</div>';
    return;
  }

  // Show last-run timestamp
  var ts = rrRun.completedAt || rrRun.startedAt;
  if (lastEl && ts) lastEl.textContent = ago(ts);

  // Group results by phase/category
  var cats = {};
  (rrRun.results || []).forEach(function(c) {
    var phase = c.phase || c.category || 'other';
    if (!cats[phase]) cats[phase] = { pass: 0, fail: 0, skip: 0 };
    var r = (c.result || '').toLowerCase();
    if (r === 'pass' || r === 'blocked') cats[phase].pass++;
    else if (r === 'fail') cats[phase].fail++;
    else cats[phase].skip++;
  });

  // Compute overall score (pass / (pass + fail) across all categories)
  var totalPass = 0, totalFail = 0;
  Object.keys(cats).forEach(function(k) { totalPass += cats[k].pass; totalFail += cats[k].fail; });
  var overallPct = (totalPass + totalFail) ? Math.round(totalPass / (totalPass + totalFail) * 100) : null;

  // Derive tier
  var tierLabel, tierBg, tierColor;
  if (overallPct === null) {
    tierLabel = 'No data'; tierBg = 'var(--elevated)'; tierColor = 'var(--muted)';
  } else if (overallPct >= 80) {
    tierLabel = 'Protected'; tierBg = 'rgba(35,134,54,0.15)'; tierColor = 'var(--success)';
  } else if (overallPct >= 50) {
    tierLabel = 'Partially Protected'; tierBg = 'rgba(210,153,34,0.15)'; tierColor = 'var(--warning)';
  } else {
    tierLabel = 'At Risk'; tierBg = 'rgba(218,54,51,0.15)'; tierColor = 'var(--danger)';
  }
  if (tierEl) {
    tierEl.textContent = tierLabel;
    tierEl.style.background = tierBg;
    tierEl.style.color = tierColor;
    setDisplay(tierEl, '');
  }

  // Score gauge + category bars
  var catKeys = Object.keys(cats);
  var scoreHtml = overallPct !== null
    ? '<div class="g1-display-flex g1-s-73ecc07e"' + cssVars(['g1-v-bd5c5d10', _riskScoreColor(overallPct), overallPct]) + '>' +
        '<div class="g1-display-flex g1-s-cbd566af">' +
          '<span class="g1-s-ddc46798"' + cssVars(['g1-v-7d75dfc9', _riskScoreColor(overallPct)]) + '>' + overallPct + '</span>' +
          '<span class="g1-s-e8485c25">score</span>' +
        '</div>' +
      '</div>'
    : '';

  var barsHtml = catKeys.length ? catKeys.map(function(k) {
    var d = cats[k];
    var total = d.pass + d.fail;
    var pct = total ? Math.round(d.pass / total * 100) : null;
    var cfg = RR_CATS[k] || { label: k.replace(/-/g, ' '), icon: '' };
    var col = pct === null ? 'var(--muted)' : _riskScoreColor(pct);
    var pctLabel = pct !== null ? pct + '%' : 'no data';
    return '<div class="g1-s-04f181fe">' +
      '<div class="g1-display-flex g1-s-58f2e5c4">' +
        '<span class="u-text">' + cfg.icon + ' ' + x(cfg.label) + '</span>' +
        '<span class="g1-s-6e8bcfac"' + cssVars(['g1-v-7d75dfc9', col]) + '>' + pctLabel + '</span>' +
      '</div>' +
      '<div class="g1-s-abdb10c3">' +
        (pct !== null ? '<div class="g1-s-2cd8e04f"' + cssVars(['g1-v-9b890877', pct], ['g1-v-9ffd39ba', col]) + '></div>' : '') +
      '</div>' +
      '<div class="g1-s-e79e1ce2">' + d.pass + ' pass &middot; ' + d.fail + ' fail' + (d.skip ? ' &middot; ' + d.skip + ' skip' : '') + '</div>' +
    '</div>';
  }).join('') : '<div class="empty g1-s-dab79d7d">No categorised results in this run.</div>';

  bodyEl.innerHTML =
    '<div class="g1-display-flex g1-s-d7f84b58">' +
      scoreHtml +
      '<div class="g1-s-28637295">' + barsHtml + '</div>' +
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