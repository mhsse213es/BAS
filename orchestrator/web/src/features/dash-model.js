// Pure helpers behind the redesigned Dashboard (operational + executive views).
//
// Every function derives its numbers from rows the dashboard loaders already fetched
// (/api/scenarios/runs, /api/findings, /api/agents, ...). Nothing here invents a value, reads the
// DOM or talks to the server, so it is unit-testable (tests/unit/dash-model.test.mjs).

export var ENTERPRISE_TACTICS = ['reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery',
  'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];

var arr = function(a) { return Array.isArray(a) ? a : []; };
var isPrevented = function(c) { return c && (c.result === 'pass' || c.result === 'blocked'); };

// verdict of one technique result: prevented | detected (failed but the blue team still saw it) | missed | other.
export function verdict(c, detected) {
  if (isPrevented(c)) return 'prevented';
  if (c && c.result === 'fail') {
    var id = c.technique && c.technique.id;
    return (id && detected && detected[id]) ? 'detected' : 'missed';
  }
  return 'other';
}

// effectiveness tallies every technique result across the runs.
export function effectiveness(runs) {
  var e = { prevented: 0, detected: 0, missed: 0, other: 0, total: 0 };
  arr(runs).forEach(function(r) {
    arr(r.results).forEach(function(c) { e[verdict(c, r.detectedTechs)]++; e.total++; });
  });
  return e;
}

// A run counts toward the posture score only when it has at least one scoreable (pass or fail) result.
export function scoredRuns(runs) {
  return arr(runs).filter(function(r) {
    if (!r.score) return false;
    if (r.score.preventionScore == null && r.score.riskScore == null) return false;
    return (r.score.passedTechniques || 0) + (r.score.failedTechniques || 0) > 0;
  });
}
export function prevPctOf(r) {
  return Math.round(r.score.preventionScore != null ? r.score.preventionScore : r.score.preventionEffectiveness || 0);
}
function weightOf(r) { return (r.score.passedTechniques || 0) + (r.score.failedTechniques || 0); }
function aggOf(list) {
  var tw = 0, ws = 0;
  list.forEach(function(r) { var w = weightOf(r); tw += w; ws += prevPctOf(r) * w; });
  return tw > 0 ? ws / tw : null;
}

// postureWindow: prevention score aggregated (weighted by technique count) over the newest `n` scored runs,
// the trend (newer half vs older half) and the series oldest -> newest. runs arrive newest first.
export function postureWindow(runs, n) {
  var scored = scoredRuns(runs);
  if (!scored.length) return null;
  var win = scored.slice(0, n || 8);
  var agg = aggOf(win);
  var pct = Math.round(agg != null ? agg : prevPctOf(scored[0]));
  var mid = Math.ceil(win.length / 2);
  var newer = aggOf(win.slice(0, mid)), older = aggOf(win.slice(mid));
  var trend = 'Stable';
  if (newer != null && older != null) {
    if (newer - older >= 3) trend = 'Improving';
    else if (older - newer >= 3) trend = 'Degrading';
  }
  return { pct: pct, count: win.length, trend: trend, series: win.map(prevPctOf).reverse(), runs: win.slice().reverse() };
}

// testedTactics: how many of the 14 Enterprise tactics any run has exercised.
export function testedTactics(runs) {
  var seen = {};
  arr(runs).forEach(function(r) { arr(r.results).forEach(function(c) {
    var t = c.technique && c.technique.tactic;
    if (t) seen[t] = true;
  }); });
  return ENTERPRISE_TACTICS.filter(function(t) { return seen[t]; }).length;
}

// coverage: share of distinct exercised techniques prevented at least once; series = per-run prevention rate (oldest first).
export function coverage(runs) {
  var tech = {};
  arr(runs).forEach(function(r) { arr(r.results).forEach(function(c) {
    var id = c.technique && c.technique.id;
    if (!id) return;
    if (isPrevented(c)) tech[id] = { prevented: true };
    else if (c.result === 'fail') tech[id] = tech[id] || { prevented: false };
  }); });
  var ids = Object.keys(tech);
  var prev = ids.filter(function(k) { return tech[k].prevented; }).length;
  var series = arr(runs).slice(0, 8).map(function(r) {
    var p = 0, f = 0;
    arr(r.results).forEach(function(c) { if (isPrevented(c)) p++; else if (c.result === 'fail') f++; });
    return (p + f) ? Math.round(p / (p + f) * 100) : 0;
  }).reverse();
  return { pct: ids.length ? Math.round(prev / ids.length * 100) : 0, tested: ids.length, series: series };
}

function techTally(runs) {
  var m = {};
  arr(runs).forEach(function(r) { arr(r.results).forEach(function(c) {
    var id = (c.technique && c.technique.id) || c.name;
    if (!id) return;
    var t = m[id] || (m[id] = { id: id, name: (c.technique && c.technique.name) || c.name || id, fail: 0, prevented: 0 });
    if (c.result === 'fail') t.fail++;
    else if (isPrevented(c)) t.prevented++;
  }); });
  return Object.keys(m).map(function(k) { return m[k]; });
}

// topFailing: techniques with the most failures; pct = share of attempts that were prevented.
export function topFailing(runs, n) {
  return techTally(runs).filter(function(t) { return t.fail > 0; })
    .sort(function(a, b) { return b.fail - a.fail || (a.id < b.id ? -1 : 1); })
    .slice(0, n || 5)
    .map(function(t) { return { id: t.id, name: t.name, fail: t.fail, pct: Math.round(t.prevented / (t.fail + t.prevented) * 100) }; });
}

// coverageGaps: techniques with the lowest prevention rate (only those that failed at least once).
export function coverageGaps(runs, n) {
  return techTally(runs).filter(function(t) { return t.fail > 0; })
    .map(function(t) { return { id: t.id, name: t.name, pct: Math.round(t.prevented / (t.fail + t.prevented) * 100) }; })
    .sort(function(a, b) { return a.pct - b.pct || (a.id < b.id ? -1 : 1); })
    .slice(0, n || 5);
}

function tacticOrder(t) { var i = ENTERPRISE_TACTICS.indexOf(t); return i < 0 ? 99 : i; }
export function tacticLabel(t) { return String(t || 'other').replace(/-/g, ' ').replace(/\b\w/g, function(m) { return m.toUpperCase(); }); }

// tacticRows: prevention rate per tactic (prevented / (prevented + failed)).
export function tacticRows(runs) {
  var m = {};
  arr(runs).forEach(function(r) { arr(r.results).forEach(function(c) {
    var t = (c.technique && c.technique.tactic) || 'other';
    var d = m[t] || (m[t] = { tactic: t, pass: 0, fail: 0 });
    if (isPrevented(c)) d.pass++; else if (c.result === 'fail') d.fail++;
  }); });
  return Object.keys(m).map(function(k) {
    var d = m[k], tot = d.pass + d.fail;
    return { tactic: k, pass: d.pass, fail: d.fail, pct: tot ? Math.round(d.pass / tot * 100) : 0, tested: tot };
  }).filter(function(d) { return d.tested > 0; }).sort(function(a, b) { return tacticOrder(a.tactic) - tacticOrder(b.tactic); });
}

// flowByTactic: prevented / detected-only / missed per tactic, in kill-chain order.
export function flowByTactic(runs) {
  var m = {};
  arr(runs).forEach(function(r) { arr(r.results).forEach(function(c) {
    var v = verdict(c, r.detectedTechs);
    if (v === 'other') return;
    var t = (c.technique && c.technique.tactic) || 'other';
    var d = m[t] || (m[t] = { tactic: t, prevented: 0, detected: 0, missed: 0 });
    d[v]++;
  }); });
  return Object.keys(m).map(function(k) { return m[k]; }).sort(function(a, b) { return tacticOrder(a.tactic) - tacticOrder(b.tactic); });
}

function dayKey(d) { return d.getFullYear() + '-' + (d.getMonth() + 1) + '-' + d.getDate(); }
var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// dailySeries: technique validations per day over the last `days` days (ending at nowMs).
// rate = detection rate (prevented + detected over all scored results) or null on a day with no results.
export function dailySeries(runs, days, nowMs) {
  var end = new Date(nowMs == null ? Date.now() : nowMs);
  var slots = [], idx = {};
  for (var i = days - 1; i >= 0; i--) {
    var d = new Date(end.getFullYear(), end.getMonth(), end.getDate() - i);
    idx[dayKey(d)] = slots.length;
    slots.push({ label: d.getDate() + ' ' + MON[d.getMonth()], prevented: 0, detected: 0, missed: 0 });
  }
  arr(runs).forEach(function(r) {
    var ts = new Date(r.startedAt || r.completedAt);
    if (isNaN(ts)) return;
    var k = idx[dayKey(ts)];
    if (k == null) return;
    arr(r.results).forEach(function(c) {
      var v = verdict(c, r.detectedTechs);
      if (v !== 'other') slots[k][v]++;
    });
  });
  slots.forEach(function(s) {
    var tot = s.prevented + s.detected + s.missed;
    s.total = tot;
    s.rate = tot ? Math.round((s.prevented + s.detected) / tot * 100) : null;
  });
  return slots;
}

// groupHealth: share of each agent group that is online (retired agents are left out).
export function groupHealth(agents) {
  var m = {};
  arr(agents).filter(function(a) { return a.state !== 'retired' && a.status !== 'retired'; }).forEach(function(a) {
    var n = a.groupName || 'Ungrouped';
    var g = m[n] || (m[n] = { name: n, online: 0, total: 0 });
    g.total++;
    if (a.status === 'online') g.online++;
  });
  return Object.keys(m).map(function(k) {
    var g = m[k]; g.pct = g.total ? Math.round(g.online / g.total * 100) : 0; return g;
  }).sort(function(a, b) { return b.total - a.total || (a.name < b.name ? -1 : 1); });
}

export function shortAgo(ms, nowMs) {
  var s = Math.floor(((nowMs == null ? Date.now() : nowMs) - ms) / 1000);
  if (!isFinite(s) || s < 0) return '';
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

// activityFeed: newest run events and newly seen open findings, newest first.
export function activityFeed(runs, findings, n) {
  var items = [];
  arr(runs).forEach(function(r) {
    var ms = new Date(r.completedAt || r.startedAt).getTime();
    if (isNaN(ms)) return;
    var st = r.status || 'completed';
    var tone = st === 'failed' ? 'bad' : st === 'running' ? 'info' : st === 'partial' ? 'warn' : 'ok';
    items.push({ ms: ms, tone: tone, icon: st === 'failed' ? 'alert' : st === 'running' ? 'play' : 'check',
      title: (r.name || r.scenarioId || 'Run') + ' ' + (st === 'running' ? 'started' : st),
      desc: [r.hostname || r.agentId, r.initiatedBy ? 'by ' + r.initiatedBy : ''].filter(Boolean).join(' · '),
      action: 'openDashRun', arg: r.id });
  });
  arr(findings).filter(function(f) { return f.status === 'open'; }).forEach(function(f) {
    var ms = new Date(f.firstSeen).getTime();
    if (isNaN(ms)) return;
    items.push({ ms: ms, tone: 'bad', icon: 'alert', title: 'New finding — ' + (f.techniqueName || f.techniqueId),
      desc: [f.severity, f.hostname || f.agentId].filter(Boolean).join(' · '), action: 'openFindingFromDashboard', arg: f.id });
  });
  return items.sort(function(a, b) { return b.ms - a.ms; }).slice(0, n || 6);
}

export function initials(name) {
  var p = String(name || '?').split(/[\s-]+/).filter(Boolean);
  return (p.length > 1 ? p[0][0] + p[1][0] : String(name || '?').slice(0, 2)).toUpperCase();
}

// preventionSeries: mean prevention per recording day across every actor's history (oldest first).
export function preventionSeries(trends) {
  var byDay = {};
  arr(trends).forEach(function(t) { arr(t.history).forEach(function(h) {
    var d = new Date(h.recordedAt);
    if (isNaN(d)) return;
    var k = d.getFullYear() * 10000 + (d.getMonth() + 1) * 100 + d.getDate();
    var s = byDay[k] || (byDay[k] = { sum: 0, n: 0, d: d });
    s.sum += Number(h.prevention) || 0; s.n++;
  }); });
  var keys = Object.keys(byDay).sort();
  return {
    labels: keys.map(function(k) { var d = byDay[k].d; return d.getDate() + ' ' + MON[d.getMonth()]; }),
    data: keys.map(function(k) { return Math.round(byDay[k].sum / byDay[k].n); }),
  };
}

// actorHistory: one actor's prevention values, oldest -> newest.
export function actorHistory(t) {
  return arr(t && t.history).slice().sort(function(a, b) { return new Date(a.recordedAt) - new Date(b.recordedAt); })
    .map(function(h) { return Number(h.prevention) || 0; });
}

// Counts of open findings per expected control class, largest first.
export function openByControl(findings) {
  var m = {};
  arr(findings).filter(function(f) { return f.status === 'open'; }).forEach(function(f) {
    var k = f.controlClass || 'Unclassified';
    m[k] = (m[k] || 0) + 1;
  });
  return Object.keys(m).map(function(k) { return [k, m[k]]; }).sort(function(a, b) { return b[1] - a[1] || (a[0] < b[0] ? -1 : 1); });
}

// riskBand: presentation band for a 0-100 risk score (higher = worse).
export function riskBand(score) {
  var s = Number(score) || 0;
  return s < 40 ? { label: 'Low', tone: 'ok' } : s < 70 ? { label: 'Moderate', tone: 'warn' } : { label: 'High', tone: 'bad' };
}

// execInsights: "what changed this period" sentences computed from the trend series, the current snapshot
// and the exposure forecast block. Every sentence states numbers that appear in those inputs.
export function execInsights(trends, current, exposure) {
  var out = [];
  var t = arr(trends);
  var first = t[0], last = t[t.length - 1];
  var plural = function(n, w) { return n + ' ' + (n === 1 ? w : w === 'open weakness' ? 'open weaknesses' : w + 's'); };
  if (t.length >= 2 && current && current.hasAttackPathData) {
    var dd = last.detectionCoverage - first.detectionCoverage;
    out.push({ icon: 'trend', tab: 'coverage',
      title: dd === 0 ? 'Detection coverage is unchanged at ' + last.detectionCoverage + '%' : 'Detection coverage ' + (dd > 0 ? 'rose ' : 'fell ') + plural(Math.abs(dd), 'point') + ' over this period',
      desc: 'From ' + first.detectionCoverage + '% to ' + last.detectionCoverage + '% across ' + plural(t.length, 'daily snapshot') + '.' });
  }
  if (t.length >= 2) {
    var dr = last.avgRiskScore - first.avgRiskScore;
    out.push({ icon: dr > 0 ? 'alert' : 'check', tab: 'findings',
      title: dr === 0 ? 'Risk score is unchanged at ' + last.avgRiskScore : 'Risk score ' + (dr > 0 ? 'rose ' : 'fell ') + plural(Math.abs(dr), 'point'),
      desc: 'From ' + first.avgRiskScore + ' to ' + last.avgRiskScore + (dr > 0 ? ' — lower is better.' : '.') });
  }
  if (exposure && exposure.hasData) {
    out.push({ icon: exposure.overThreshold ? 'clock' : 'check', tab: 'findings',
      title: exposure.overThreshold ? plural(exposure.overThreshold, 'open weakness') + ' older than ' + exposure.thresholdDays + ' days' : 'No weakness has been open longer than ' + exposure.thresholdDays + ' days',
      desc: exposure.openCount + ' open · longest ' + exposure.worstDaysOpen + ' days · median ' + exposure.medianDaysOpen + ' days.' });
  }
  if (t.length >= 2 && first.assetCount !== last.assetCount) {
    out.push({ icon: 'agents', tab: 'agents', title: 'Fleet ' + (last.assetCount > first.assetCount ? 'grew' : 'shrank') + ' from ' + first.assetCount + ' to ' + last.assetCount + ' assets',
      desc: 'Assets with an enrolled agent or discovered by the platform.' });
  }
  return out;
}

// Open findings as business risks: critical and high first.
export function topRisks(findings, n) {
  var rank = { critical: 0, high: 1, medium: 2, low: 3 };
  return arr(findings).filter(function(f) { return f.status === 'open' && rank[String(f.severity || '').toLowerCase()] < 2; })
    .sort(function(a, b) { return rank[String(a.severity).toLowerCase()] - rank[String(b.severity).toLowerCase()]; })
    .slice(0, n || 4);
}
