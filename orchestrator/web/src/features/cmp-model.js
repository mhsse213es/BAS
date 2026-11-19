// Pure helpers for the redesigned Campaigns page: the status pill, the result mix, the card facts, the
// drawer timeline, the chip counts, the search filter and the banner numbers. No DOM, no network.
// Everything is worked out from what GET /api/campaigns returned (id, name, scenarioName, targetType,
// createdBy, startedAt and summary: status, paused, targets, dispatched, skipped, progress, prevented,
// detected, missed) and, for the drawer, GET /api/campaigns/{id} (runs, skips). The design's phases,
// start date and pass/partial/fail per agent have no field in the API: the timeline shows the real
// stages (dispatch, execution, results) and the mix is labelled prevented / detected / missed.

function n(v) { return Number(v) || 0; }

// statusInfo: the pill for a campaign. A paused campaign keeps summary.status 'running'.
export function statusInfo(s) {
  s = s || {};
  var st = String(s.status || '').toLowerCase();
  if (st === 'running' && s.paused) return { key: 'paused', label: 'Paused', tone: 'warn', live: false };
  var map = {
    running: ['Running', 'info'], completed: ['Completed', 'ok'], partial: ['Partial', 'warn'],
    failed: ['Failed', 'bad'], stopped: ['Stopped', 'muted'], empty: ['Empty', 'muted'],
  };
  var m = map[st];
  if (m) return { key: st, label: m[0], tone: m[1], live: st === 'running' };
  return { key: st || 'unknown', label: st ? st.charAt(0).toUpperCase() + st.slice(1) : '—', tone: 'muted', live: false };
}

// mix: the technique results of a campaign and the share of each.
export function mix(s) {
  s = s || {};
  var p = n(s.prevented), d = n(s.detected), m = n(s.missed);
  var total = p + d + m;
  var pct = function(v) { return total ? (v / total) * 100 : 0; };
  return {
    prevented: p, detected: d, missed: m, total: total,
    preventedPct: total ? Math.round(pct(p)) : null,
    segs: [
      { key: 'prevented', n: p, pct: pct(p) },
      { key: 'detected', n: d, pct: pct(d) },
      { key: 'missed', n: m, pct: pct(m) },
    ],
  };
}

var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function two(v) { return v < 10 ? '0' + v : String(v); }

// startedDay: "20/10/2026" in the viewer's zone, or an em dash.
export function startedDay(iso) {
  var t = iso ? new Date(iso) : null;
  if (!t || isNaN(t.getTime())) return '—';
  return two(t.getDate()) + '/' + two(t.getMonth() + 1) + '/' + t.getFullYear();
}

// startedStamp: "20 Oct 2026, 17:30" in the viewer's zone, or an em dash.
export function startedStamp(iso) {
  var t = iso ? new Date(iso) : null;
  if (!t || isNaN(t.getTime())) return '—';
  return t.getDate() + ' ' + MON[t.getMonth()] + ' ' + t.getFullYear() + ', ' + two(t.getHours()) + ':' + two(t.getMinutes());
}

// agentsLine: "5/5 agents", plus the skipped count when some agents were skipped.
export function agentsLine(s) {
  s = s || {};
  return n(s.dispatched) + '/' + n(s.targets) + ' agents' + (n(s.skipped) ? ' · ' + n(s.skipped) + ' skipped' : '');
}

// cardFacts: the three small facts under a card's result bar.
export function cardFacts(c) {
  var s = (c && c.summary) || {};
  var m = mix(s);
  return { runs: n(s.dispatched), rate: m.preventedPct, started: startedDay(c && c.startedAt) };
}

// runsLine: the drawer's right-hand summary next to the status pill.
export function runsLine(c) {
  var s = (c && c.summary) || {};
  var m = mix(s);
  var runs = n(s.dispatched);
  return runs + (runs === 1 ? ' run' : ' runs') + ' · ' + (m.preventedPct == null ? 'no results yet' : m.preventedPct + '% prevented');
}

// timeline: the real stages of a campaign. state is done, run, fail or wait; pct is the share of the stage finished.
export function timeline(c) {
  var s = (c && c.summary) || {};
  var runs = (c && c.runs) || [];
  var live = String(s.status || '') === 'running';
  var targets = n(s.targets), dispatched = n(s.dispatched), skipped = n(s.skipped);
  var finished = runs.filter(function(r) { return r.status === 'completed' || r.status === 'failed' || r.status === 'partial' || r.status === 'cancelled' || r.status === 'stopped'; }).length;
  var failed = runs.filter(function(r) { return r.status === 'failed'; }).length;
  var m = mix(s);

  var dispatchPct = targets ? Math.min(100, Math.round(((dispatched + skipped) / targets) * 100)) : 0;
  var dispatch = {
    label: 'Dispatch', pct: dispatchPct, state: dispatchPct >= 100 ? 'done' : (live ? 'run' : 'wait'),
    detail: dispatched + ' of ' + targets + ' agents dispatched' + (skipped ? ' · ' + skipped + ' skipped' : ''),
  };

  var execPct = runs.length ? Math.round((finished / runs.length) * 100) : 0;
  var execState = !runs.length ? 'wait' : finished >= runs.length ? (failed ? 'fail' : 'done') : (live ? 'run' : 'wait');
  var execution = {
    label: 'Execution', pct: execPct, state: execState,
    detail: runs.length ? finished + ' of ' + runs.length + ' runs finished' + (failed ? ' · ' + failed + ' failed' : '') : 'No runs dispatched yet',
  };

  var results = {
    label: 'Results', pct: m.preventedPct == null ? 0 : m.preventedPct, state: m.total ? (live ? 'run' : 'done') : 'wait',
    detail: m.total ? m.prevented + ' prevented · ' + m.detected + ' detected · ' + m.missed + ' missed' : 'No technique results yet',
    tag: m.preventedPct == null ? null : m.preventedPct + '%',
  };
  return [dispatch, execution, results];
}

// tagTone: the colour of a stage's percentage tag.
export function tagTone(pct) { return pct >= 85 ? 'ok' : 'warn'; }

// chipCounts: "all" plus every status that has at least one campaign, in the usual order.
export var STATUS_ORDER = ['running', 'completed', 'partial', 'failed', 'stopped', 'empty'];
export function chipCounts(list) {
  var by = {};
  (list || []).forEach(function(c) { var k = String(((c && c.summary) || {}).status || '').toLowerCase() || 'unknown'; by[k] = (by[k] || 0) + 1; });
  var out = [{ id: 'all', label: 'All', count: (list || []).length }];
  STATUS_ORDER.concat(Object.keys(by).filter(function(k) { return STATUS_ORDER.indexOf(k) < 0; })).forEach(function(k) {
    if (by[k]) out.push({ id: k, label: k.charAt(0).toUpperCase() + k.slice(1), count: by[k] });
  });
  return out;
}

// filter: the state chip, then the text search over name, scenario, id and creator.
export function filter(list, status, q) {
  var needle = String(q || '').trim().toLowerCase();
  return (list || []).filter(function(c) {
    var st = String(((c && c.summary) || {}).status || '').toLowerCase();
    if (status && status !== 'all' && st !== status) return false;
    if (!needle) return true;
    return [c.name, c.scenarioName, c.id, c.createdBy].some(function(v) { return String(v || '').toLowerCase().indexOf(needle) >= 0; });
  });
}

// heroStats: the four numbers in the banner.
export function heroStats(list) {
  var out = { total: 0, completed: 0, partial: 0, runs: 0 };
  (list || []).forEach(function(c) {
    var s = (c && c.summary) || {};
    out.total++;
    if (s.status === 'completed') out.completed++;
    if (s.status === 'partial') out.partial++;
    out.runs += n(s.dispatched);
  });
  return out;
}
