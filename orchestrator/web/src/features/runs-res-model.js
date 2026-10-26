// Pure helpers for the extra blocks the Results drawer shows above each tab (step strip, tactic heat,
// severity and duration charts, score history ...). Everything is computed from the run object the
// console already holds (results[], score, startedAt/completedAt) plus, for the history chart, the
// other runs of the same scenario from /api/scenarios/runs. No DOM, no network, nothing invented.

export var TACTICS = [
  ['initial-access', 'Initial Access'], ['execution', 'Execution'], ['persistence', 'Persistence'], ['privilege-escalation', 'Privilege Escalation'],
  ['defense-evasion', 'Defense Evasion'], ['credential-access', 'Credential Access'], ['discovery', 'Discovery'], ['lateral-movement', 'Lateral Movement'],
  ['collection', 'Collection'], ['command-and-control', 'Command And Control'], ['exfiltration', 'Exfiltration'], ['impact', 'Impact']
];

export function tacticLabel(slug) {
  slug = String(slug || '');
  for (var i = 0; i < TACTICS.length; i++) if (TACTICS[i][0] === slug) return TACTICS[i][1];
  return slug ? slug.replace(/[-_]+/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); }) : 'Other';
}

// stepsOf: one row per executed step. state is ok (prevented), bad (got through) or na (error / skipped / vetoed).
export function stepsOf(run) {
  return ((run && run.results) || []).map(function(c, i) {
    var res = String((c && c.result) || '').toLowerCase();
    var t = (c && c.technique) || {};
    return {
      n: i + 1, name: t.name || (c && (c.name || c.stepName)) || ('Step ' + (i + 1)), tech: t.id || '', tactic: t.tactic || 'other',
      state: res === 'pass' || res === 'blocked' ? 'ok' : res === 'fail' ? 'bad' : 'na',
      ms: c && typeof c.durationMs === 'number' ? c.durationMs : null, sev: String((c && c.severity) || '').toLowerCase(),
      verdict: String((c && c.detectionVerdict) || '').toLowerCase(), framework: String((c && c.framework) || '').toLowerCase()
    };
  });
}

export function counts(steps) {
  var o = { total: steps.length, ok: 0, bad: 0, na: 0 };
  steps.forEach(function(s) { o[s.state]++; });
  return o;
}

// tacticRows: tactics that have at least one step, in kill-chain order, with measured pass/fail counts.
export function tacticRows(steps) {
  var by = {};
  steps.forEach(function(s) {
    var r = by[s.tactic] || (by[s.tactic] = { key: s.tactic, label: tacticLabel(s.tactic), pass: 0, fail: 0, na: 0 });
    if (s.state === 'ok') r.pass++; else if (s.state === 'bad') r.fail++; else r.na++;
  });
  var order = TACTICS.map(function(t) { return t[0]; });
  var keys = order.filter(function(k) { return by[k]; }).concat(Object.keys(by).filter(function(k) { return order.indexOf(k) < 0; }).sort());
  return keys.map(function(k) {
    var r = by[k], m = r.pass + r.fail;
    r.pct = m ? Math.round(r.pass / m * 100) : 0;
    return r;
  });
}

// heatCells: the 12 kill-chain tactics, each na (not tested), ok (all blocked), mid (partial) or bad (got through).
export function heatCells(steps) {
  var rows = {};
  tacticRows(steps).forEach(function(r) { rows[r.key] = r; });
  return TACTICS.map(function(t) {
    var r = rows[t[0]], m = r ? r.pass + r.fail : 0;
    return { key: t[0], label: t[1], short: t[1].split(' ')[0], pass: r ? r.pass : 0, total: m, cls: !m ? 'na' : r.pass === m ? 'ok' : r.pass === 0 ? 'bad' : 'mid' };
  });
}

// severityCounts: the failing steps by their own severity.
export function severityCounts(steps) {
  var o = { critical: 0, high: 0, medium: 0, low: 0 };
  steps.forEach(function(s) { if (s.state === 'bad' && o[s.sev] != null) o[s.sev]++; });
  return o;
}

export function fmtMs(ms) {
  if (ms == null || isNaN(ms)) return '—';
  if (ms < 1000) return Math.round(ms) + ' ms';
  var s = ms / 1000;
  if (s < 60) return (s < 10 ? s.toFixed(1) : String(Math.round(s))) + ' s';
  var m = Math.floor(s / 60);
  return m + ' m ' + String(Math.round(s - m * 60)).padStart(2, '0') + ' s';
}

// durationStats: wall clock from the run's own start/complete stamps, active time as the sum of timed steps.
export function durationStats(steps, run) {
  var timed = steps.filter(function(s) { return s.ms != null; });
  var active = timed.reduce(function(a, s) { return a + s.ms; }, 0);
  var slow = timed.reduce(function(m, s) { return !m || s.ms > m.ms ? s : m; }, null);
  var a = run && run.startedAt ? new Date(run.startedAt).getTime() : NaN, b = run && run.completedAt ? new Date(run.completedAt).getTime() : NaN;
  return { wallMs: !isNaN(a) && !isNaN(b) && b >= a ? b - a : null, activeMs: timed.length ? active : null, slowest: slow, timed: timed.length };
}

// cumulative: running count of steps that got through.
export function cumulative(steps) {
  var run = 0;
  return steps.map(function(s) { return (run += s.state === 'bad' ? 1 : 0); });
}

// furthestStage: the latest kill-chain tactic where a step got through.
export function furthestStage(rows) {
  var last = null;
  rows.forEach(function(r) { if (r.fail > 0) last = r; });
  return last;
}

// scoreHistory: prevention scores of the scored runs of the same scenario, oldest first, up to `max`, ending
// on the open run (when it is scored). labels are the start dates.
export function scoreHistory(runs, run, max) {
  max = max || 7;
  var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var rows = (runs || []).filter(function(r) {
    return r && r.scenarioId && run && r.scenarioId === run.scenarioId && r.score && typeof r.score.preventionScore === 'number' && r.startedAt && !isNaN(new Date(r.startedAt).getTime());
  }).sort(function(a, b) { return new Date(a.startedAt) - new Date(b.startedAt); });
  var upto = rows.map(function(r) { return r.id; }).indexOf(run && run.id);
  if (upto >= 0) rows = rows.slice(0, upto + 1);
  rows = rows.slice(-max);
  return {
    values: rows.map(function(r) { return Math.round(r.score.preventionScore); }),
    labels: rows.map(function(r) { var d = new Date(r.startedAt); return d.getDate() + ' ' + MON[d.getMonth()]; })
  };
}

// donutOf: [{label, value, color}] without the empty slices.
export function donutOf(parts) { return parts.filter(function(p) { return p.value > 0; }); }
