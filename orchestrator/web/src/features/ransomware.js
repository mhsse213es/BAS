import { state } from '../core/state.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { ago, showToast } from '../core/util.js';
import { openModal } from './reports.js';
import { _riskScoreColor, showTab } from './shell.js';
import { setDisplay } from '../core/inline-style.js';


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
    bodyEl.innerHTML = '<div class="empty" style="padding:0.5rem">Run the <strong>Ransomware Drill</strong> or <strong>EM-07</strong> scenario to generate a readiness score.</div>';
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
    ? '<div style="display:flex;align-items:center;justify-content:center;width:80px;height:80px;border-radius:50%;background:conic-gradient(' + _riskScoreColor(overallPct) + ' ' + overallPct + '%, var(--elevated) 0%);flex-shrink:0">' +
        '<div style="width:58px;height:58px;border-radius:50%;background:var(--surface);display:flex;flex-direction:column;align-items:center;justify-content:center">' +
          '<span style="font-size:1.1rem;font-weight:700;line-height:1;color:' + _riskScoreColor(overallPct) + '">' + overallPct + '</span>' +
          '<span style="font-size:0.55rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em">score</span>' +
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
    return '<div style="margin-bottom:0.5rem">' +
      '<div style="display:flex;justify-content:space-between;font-size:0.76rem;margin-bottom:0.2rem">' +
        '<span class="u-text">' + cfg.icon + ' ' + x(cfg.label) + '</span>' +
        '<span style="font-weight:600;color:' + col + '">' + pctLabel + '</span>' +
      '</div>' +
      '<div style="height:5px;background:var(--elevated);border-radius:3px;overflow:hidden">' +
        (pct !== null ? '<div style="height:100%;width:' + pct + '%;background:' + col + ';border-radius:3px;transition:width .6s ease"></div>' : '') +
      '</div>' +
      '<div style="font-size:0.66rem;color:var(--muted);margin-top:0.15rem">' + d.pass + ' pass &middot; ' + d.fail + ' fail' + (d.skip ? ' &middot; ' + d.skip + ' skip' : '') + '</div>' +
    '</div>';
  }).join('') : '<div class="empty" style="padding:0.5rem">No categorised results in this run.</div>';

  bodyEl.innerHTML =
    '<div style="display:flex;gap:1.5rem;align-items:flex-start">' +
      scoreHtml +
      '<div style="flex:1;min-width:0">' + barsHtml + '</div>' +
      '<div style="flex-shrink:0;display:flex;flex-direction:column;gap:0.4rem;min-width:160px;font-size:0.75rem;color:var(--muted)">' +
        '<div><span style="color:var(--text);font-weight:500">' + x(rrRun.name || rrRun.scenarioId) + '</span></div>' +
        '<div>' + (rrRun.agentId ? 'Agent: ' + x(rrRun.agentId) : '') + '</div>' +
        '<div style="margin-top:0.25rem">' +
          '<span class="sbadge s-' + x(rrRun.status) + '">' + x(rrRun.status) + '</span>' +
        '</div>' +
        '<a style="color:var(--accent);cursor:pointer;margin-top:0.4rem"' + on('click', 'viewRunResults', rrRun) + '>View full report →</a>' +
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