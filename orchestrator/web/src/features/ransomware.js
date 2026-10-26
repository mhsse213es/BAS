import { state } from '../core/state.js';
import { ago, showToast } from '../core/util.js';
import { openModal } from './reports.js';
import { showTab } from './shell.js';
import { apicall } from '../core/api.js';
import { setDashRR } from './dash-rich.js';


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

export function loadRansomwareReadiness(runs) {
  // Find the most recent run across the real ransomware scenarios
  // (runs is already ORDER BY started_at DESC, so first match wins).
  var rrRun = null;
  for (var i = 0; i < runs.length; i++) {
    var r = runs[i];
    if (RR_SCENARIO_IDS.indexOf(r.scenarioId) !== -1 && (r.results || []).length) {
      rrRun = r; break;
    }
  }
  if (!rrRun) { setDashRR({ phase: 'none' }); return; }
  setDashRR({ phase: 'loading' });
  apicall('/api/scenarios/runs/' + encodeURIComponent(rrRun.id) + '/rw-score').then(function(score) {
    setDashRR(ransomwareModel(rrRun, score));
  }).catch(function() { setDashRR({ phase: 'error' }); });
}

// ransomwareModel turns the server's rw-score into what the dashboard card shows. No number is
// recomputed: the overall score and every dimension rate come straight from the response.
export function ransomwareModel(rrRun, score) {
  var TIER = { protected: ['Protected', 'ok'], at_risk: ['At Risk', 'warn'], vulnerable: ['Vulnerable', 'bad'] };
  var tier = TIER[score.rating] || [score.rating || 'Unknown', 'muted'];
  var overall = Math.round(score.overall);
  var weakest = null;
  var rows = (score.dimensions || []).map(function(d) {
    var cfg = RW_DIMENSIONS[d.dimension] || { label: (d.dimension || '').replace(/_/g, ' ') };
    var evaluated = (d.pass || 0) + (d.fail || 0) + (d.error || 0) + (d.unknown || 0);
    var pct = evaluated ? Math.round(d.passRate * 100) : null;
    if (pct !== null && (weakest === null || pct < weakest.pct)) weakest = { pct: pct, label: cfg.label };
    var st = pct === null ? 'muted' : pct >= 80 ? 'ok' : pct >= 50 ? 'warn' : 'bad';
    return { title: cfg.label, state: st, text: pct === null ? 'No data' : pct >= 80 ? 'Passed' : pct >= 50 ? 'Warning' : 'Failed' };
  });
  var ts = rrRun.completedAt || rrRun.startedAt;
  return {
    phase: 'ok', score: overall, tone: overall >= 80 ? 'ok' : overall >= 50 ? 'warn' : 'bad', label: tier[0],
    desc: 'Readiness from the latest ransomware drill (' + (rrRun.name || rrRun.scenarioId) + (ts ? ', ' + ago(ts) : '') + ').' + (weakest ? ' Weakest point: ' + weakest.label + '.' : ''),
    rows: rows,
    gate: score.gateTriggered && (score.criticalFailures || []).length ? score.criticalFailures.join('; ') : ''
  };
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