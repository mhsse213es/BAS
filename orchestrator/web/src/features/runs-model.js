// Pure helpers for the redesigned Live Runs page: run buckets, hero chips, in-flight cards, the two
// charts, the status/target filter and the table's CSV. No DOM, no network: everything is computed from
// the rows /api/scenarios/runs already returned (plus the agent list the console already holds).

var LIVE = { running: 1, pending: 1, queued: 1 };

export function statusOf(r) { return String((r && r.status) || '').toLowerCase(); }
export function isLive(r) { return !!LIVE[statusOf(r)]; }

// runBucket maps a run to one filter bucket. Anything that is neither running nor completed
// (failed, partial, cancelled, errored...) needs a human to look at it.
export function runBucket(r) {
  var st = statusOf(r);
  if (LIVE[st]) return 'running';
  if (st === 'completed') return 'completed';
  return 'attention';
}

export function runStats(runs) {
  runs = runs || [];
  var s = { total: runs.length, running: 0, completed: 0, attention: 0, byStatus: {}, scored: 0, prevSum: 0 };
  runs.forEach(function(r) {
    s[runBucket(r)]++;
    var st = String((r && r.status) || 'unknown').toLowerCase();
    s.byStatus[st] = (s.byStatus[st] || 0) + 1;
    if (r && r.score && typeof r.score.preventionScore === 'number' && ((r.score.passedTechniques || 0) + (r.score.failedTechniques || 0)) > 0) {
      s.scored++; s.prevSum += r.score.preventionScore;
    }
  });
  s.avgPrevention = s.scored ? Math.round(s.prevSum / s.scored) : null;
  return s;
}

var DAY = 86400000;
var WEEKDAY = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

function startOf(t) { var d = new Date(t); d.setHours(0, 0, 0, 0); return d; }

// runsPerDay counts runs by start day for the `days` days ending on the newest run.
export function runsPerDay(runs, days) {
  var stamps = (runs || []).map(function(r) { return r && r.startedAt ? new Date(r.startedAt).getTime() : NaN; }).filter(function(t) { return !isNaN(t); });
  if (!stamps.length) return { labels: [], data: [] };
  var end = startOf(Math.max.apply(null, stamps));
  var labels = [], data = [], idx = {};
  for (var i = days - 1; i >= 0; i--) {
    var d = new Date(end.getTime() - i * DAY);
    idx[d.getTime()] = labels.length;
    labels.push((d.getMonth() + 1) + '/' + d.getDate());
    data.push(0);
  }
  stamps.forEach(function(t) { var k = startOf(t).getTime(); if (idx[k] != null) data[idx[k]]++; });
  return { labels: labels, data: data };
}

// weekSeries: the 7 days ending on the newest run, as weekday labels with completed and failed run
// counts. Runs in any other state (running, partial, cancelled) are not drawn on this chart.
export function weekSeries(runs) {
  var stamps = (runs || []).map(function(r) { return r && r.startedAt ? new Date(r.startedAt).getTime() : NaN; }).filter(function(t) { return !isNaN(t); });
  if (!stamps.length) return { labels: [], passed: [], failed: [], total: 0, peak: 0 };
  var end = startOf(Math.max.apply(null, stamps));
  var labels = [], passed = [], failed = [], idx = {};
  for (var i = 6; i >= 0; i--) {
    var d = new Date(end.getTime() - i * DAY);
    idx[d.getTime()] = labels.length;
    labels.push(WEEKDAY[d.getDay()]);
    passed.push(0); failed.push(0);
  }
  var total = 0;
  (runs || []).forEach(function(r) {
    if (!r || !r.startedAt) return;
    var k = startOf(new Date(r.startedAt).getTime()).getTime();
    if (idx[k] == null) return;
    var st = statusOf(r);
    if (st === 'completed') { passed[idx[k]]++; total++; } else if (st === 'failed') { failed[idx[k]]++; total++; }
  });
  return { labels: labels, passed: passed, failed: failed, total: total, peak: Math.max.apply(null, passed.map(function(v, i) { return v + failed[i]; }).concat([0])) };
}

// agentLabel resolves an agent id to its hostname when the console knows the agent.
export function agentLabel(agents, id) {
  var a = (agents || []).filter(function(g) { return g && g.agentId === id; })[0];
  return (a && a.hostname) || id || '';
}

// heroStats: the four chips under the page title.
export function heroStats(runs, agents) {
  runs = runs || [];
  var running = 0, queued = 0, finished = 0, completed = 0, busy = {};
  runs.forEach(function(r) {
    var st = statusOf(r);
    if (LIVE[st]) {
      if (st === 'running') running++; else queued++;
      if (r.agentId) busy[r.agentId] = true;
    } else {
      finished++;
      if (st === 'completed') completed++;
    }
  });
  var nBusy = Object.keys(busy).length;
  return {
    running: running,
    queued: queued,
    passRate: finished ? Math.round(completed / finished * 100) + '%' : '—',
    agentsBusy: agents && agents.length ? nBusy + ' / ' + agents.length : (nBusy ? String(nBusy) : '—')
  };
}

// shortRunId: a UUID shows as its first two groups plus an ellipsis; anything else is cut at 14.
export function shortRunId(id) {
  id = String(id || '');
  if (/^[0-9a-f]{8}-[0-9a-f]{4}/i.test(id) && id.length > 13) return id.slice(0, 13) + '…';
  return id.length > 14 ? id.slice(0, 14) + '…' : id;
}

var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function hm(d) { return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0'); }

// fmtWhen: "14:20" today, "Yesterday 14:20" the day before, "24 Oct 14:20" otherwise.
export function fmtWhen(iso, now) {
  if (!iso) return '—';
  var t = new Date(iso);
  if (isNaN(t.getTime())) return '—';
  var n = now == null ? Date.now() : now;
  var days = Math.round((startOf(n).getTime() - startOf(t.getTime()).getTime()) / DAY);
  if (days === 0) return hm(t);
  if (days === 1) return 'Yesterday ' + hm(t);
  return t.getDate() + ' ' + MON[t.getMonth()] + ' ' + hm(t);
}

// liveRuns: the runs shown as in-flight cards. Children of a sweep are folded into their sweep row.
export function liveRuns(runs) {
  return (runs || []).filter(function(r) { return isLive(r) && !r.sweepId && !r.emSweepId; })
    .sort(function(a, b) { return (new Date(b.startedAt || 0).getTime() || 0) - (new Date(a.startedAt || 0).getTime() || 0); });
}

// liveCard: everything one in-flight card prints.
export function liveCard(r, agents) {
  var p = r.progress || {};
  var total = p.stepsTotal || 0, done = p.stepsDone || 0;
  var pct = total ? Math.max(0, Math.min(100, Math.round(done / total * 100))) : 0;
  var queued = statusOf(r) !== 'running';
  var state = queued ? 'queued' : r.agentDisconnected ? 'disconnected' : r.paused ? 'paused' : 'running';
  var step = state === 'queued' ? 'Waiting to start'
    : state === 'disconnected' ? 'Agent disconnected'
    : state === 'paused' ? (total ? 'Paused at step ' + done + ' of ' + total : 'Paused')
    : total ? 'Step ' + Math.min(done + 1, total) + ' of ' + total : 'Starting…';
  return {
    id: r.id, shortId: shortRunId(r.id), name: r.name || r.scenarioId || '', target: agentLabel(agents, r.agentId), by: r.initiatedBy || '',
    state: state, label: state === 'queued' ? 'Queued' : state === 'disconnected' ? 'Agent Disconnected' : state === 'paused' ? 'Paused' : 'Running',
    pct: pct, step: step, paused: !!r.paused, live: !queued,
    tag: done > 0 ? (p.stepsFailed || 0) + ' fail / ' + (p.stepsPassed || 0) + ' pass' : '',
    steps: total, stepsDone: done, mode: r.mode || '', maxPrivilege: r.maxPrivilege || ''
  };
}

var STATUS_NAME = { running: 'Running', pending: 'Queued', queued: 'Queued', completed: 'Completed', partial: 'Partial', failed: 'Failed', cancelled: 'Cancelled' };
export function statusName(st) { st = String(st || '').toLowerCase(); return STATUS_NAME[st] || (st ? st.charAt(0).toUpperCase() + st.slice(1) : 'Unknown'); }
// filterKey folds pending into queued so the select has one entry for it.
export function filterKey(r) { var st = statusOf(r); return st === 'pending' ? 'queued' : st; }

var STATUS_ORDER = ['running', 'queued', 'completed', 'partial', 'failed', 'cancelled'];
// statusOptions: the statuses that exist in the data, in a fixed order.
export function statusOptions(runs) {
  var seen = {};
  (runs || []).forEach(function(r) { seen[filterKey(r)] = true; });
  var keys = STATUS_ORDER.filter(function(k) { return seen[k]; }).concat(Object.keys(seen).filter(function(k) { return k && STATUS_ORDER.indexOf(k) < 0; }).sort());
  return keys.map(function(k) { return { id: k, label: statusName(k) }; });
}
// targetOptions: one entry per distinct agent label.
export function targetOptions(runs, agents) {
  var seen = {};
  (runs || []).forEach(function(r) { var l = agentLabel(agents, r && r.agentId); if (l) seen[l] = true; });
  return Object.keys(seen).sort().map(function(l) { return { id: l, label: l }; });
}

// matchRun: the page-level search + status + target filter for a run.
export function matchRun(r, f, agents) {
  f = f || {};
  if (f.status && f.status !== 'all' && filterKey(r) !== f.status) return false;
  if (f.target && f.target !== 'all' && agentLabel(agents, r.agentId) !== f.target) return false;
  var q = String(f.q || '').trim().toLowerCase();
  if (!q) return true;
  var hay = [r.id, r.name, r.scenarioId, r.agentId, agentLabel(agents, r.agentId), r.initiatedBy, r.status].join(' ').toLowerCase();
  return hay.indexOf(q) !== -1;
}

// outcomeSegments: donut slices, one per status present, in a fixed order.
export function outcomeSegments(runs) {
  var by = {};
  (runs || []).forEach(function(r) { var k = filterKey(r) || 'unknown'; by[k] = (by[k] || 0) + 1; });
  var keys = STATUS_ORDER.filter(function(k) { return by[k]; }).concat(Object.keys(by).filter(function(k) { return STATUS_ORDER.indexOf(k) < 0; }).sort());
  return keys.map(function(k) { return { key: k, label: statusName(k), value: by[k] }; });
}

// csvText: header + rows as RFC 4180 CSV (every field quoted). A leading = + - @ is neutralised so a
// spreadsheet never evaluates a run name as a formula.
export function csvText(header, rows) {
  var q = function(v) {
    var s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  };
  return [header].concat(rows).map(function(r) { return r.map(q).join(','); }).join('\n');
}

// numeric helpers for sorting a table column read from cell text
export function cellNumber(s) { var m = String(s || '').replace(/,/g, '').match(/-?\d+(\.\d+)?/); return m ? parseFloat(m[0]) : -Infinity; }
export function allNumeric(vals) { return vals.length > 0 && vals.every(function(v) { return v === '' || v === '—' || /^[\s+\-]*\d/.test(v); }); }
// pageCount / pageRange for the footer
export function pageCount(n, per) { return Math.max(1, Math.ceil(n / Math.max(1, per))); }
export function rangeText(n, page, per) {
  if (!n) return 'No rows match the filter';
  var start = page * per;
  return 'Showing ' + (start + 1) + '–' + Math.min(start + per, n) + ' of ' + n;
}
