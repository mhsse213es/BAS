// Live Runs: summary strip, outcome charts and the status/search filter above the runs table.
// Everything is computed from the /api/scenarios/runs rows loadRuns already fetched; the table
// itself (and every per-row action) stays in reports.js.
import { x } from '../core/escape.js';
import { kpi, grid, card, seg, empty } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';

var filter = 'all';
var lastRuns = [];

export var RUN_FILTERS = [
  { id: 'all', label: 'All' }, { id: 'running', label: 'Running' }, { id: 'completed', label: 'Completed' }, { id: 'attention', label: 'Needs attention' }
];

// runBucket maps a run to one filter bucket. Anything that is neither running nor completed
// (failed, partial, cancelled, errored...) needs a human to look at it.
export function runBucket(r) {
  var st = String((r && r.status) || '').toLowerCase();
  if (st === 'running' || st === 'pending' || st === 'queued') return 'running';
  if (st === 'completed') return 'completed';
  return 'attention';
}

export function runStats(runs) {
  runs = runs || [];
  var s = { total: runs.length, running: 0, completed: 0, attention: 0, byStatus: {}, scored: 0, prevSum: 0 };
  runs.forEach(function(r) {
    s[runBucket(r)]++;
    var st = String(r.status || 'unknown').toLowerCase();
    s.byStatus[st] = (s.byStatus[st] || 0) + 1;
    if (r.score && typeof r.score.preventionScore === 'number' && ((r.score.passedTechniques || 0) + (r.score.failedTechniques || 0)) > 0) {
      s.scored++; s.prevSum += r.score.preventionScore;
    }
  });
  s.avgPrevention = s.scored ? Math.round(s.prevSum / s.scored) : null;
  return s;
}

// runsPerDay counts runs by start day for the `days` days ending on the newest run.
export function runsPerDay(runs, days) {
  var stamps = (runs || []).map(function(r) { return r.startedAt ? new Date(r.startedAt).getTime() : NaN; }).filter(function(t) { return !isNaN(t); });
  if (!stamps.length) return { labels: [], data: [] };
  var end = new Date(Math.max.apply(null, stamps)); end.setHours(0, 0, 0, 0);
  var labels = [], data = [], idx = {};
  for (var i = days - 1; i >= 0; i--) {
    var d = new Date(end.getTime() - i * 86400000);
    idx[d.getTime()] = labels.length;
    labels.push((d.getMonth() + 1) + '/' + d.getDate());
    data.push(0);
  }
  stamps.forEach(function(t) { var d = new Date(t); d.setHours(0, 0, 0, 0); if (idx[d.getTime()] != null) data[idx[d.getTime()]]++; });
  return { labels: labels, data: data };
}

var STATUS_TONE = { completed: CHART_COLORS.ok, running: CHART_COLORS.accent, failed: CHART_COLORS.bad, partial: CHART_COLORS.warn, cancelled: CHART_COLORS.muted };

export function runsSummaryHTML(runs) {
  var s = runStats(runs);
  if (!s.total) return '';
  var segs = Object.keys(s.byStatus).sort().map(function(k) { return { label: k.charAt(0).toUpperCase() + k.slice(1), value: s.byStatus[k], color: STATUS_TONE[k] || CHART_COLORS.info }; });
  var per = runsPerDay(runs, 7);
  return grid(4, [
    kpi({ label: 'Runs dispatched', value: s.total, sub: 'every run, sweep variants included', icon: 'runs', tone: 'accent' }),
    kpi({ label: 'Running now', value: s.running, sub: s.running ? 'live, can be paused or stopped' : 'nothing in flight', icon: 'play', tone: s.running ? 'info' : 'muted' }),
    kpi({ label: 'Completed', value: s.completed, sub: s.total ? Math.round(s.completed / s.total * 100) + '% of all runs' : '', icon: 'shield', tone: 'ok' }),
    kpi({ label: 'Avg prevention', value: s.avgPrevention == null ? '—' : s.avgPrevention + '%', sub: s.scored ? 'across ' + s.scored + ' scored run' + (s.scored === 1 ? '' : 's') : 'no scored runs yet', icon: 'mapped', tone: s.avgPrevention == null ? 'muted' : s.avgPrevention >= 70 ? 'ok' : s.avgPrevention >= 40 ? 'warn' : 'bad' })
  ]) + grid(2, [
    card('Run outcomes', chartSlot({ type: 'donut', segments: segs, center: String(s.total), centerSub: 'runs', h: 170, legendRight: true }), { sub: s.attention ? s.attention + ' need attention' : 'nothing needs attention' }),
    card('Runs per day', per.data.length ? chartSlot({ type: 'bar', labels: per.labels, series: [{ name: 'Runs', data: per.data, color: CHART_COLORS.accent }], h: 170, yMax: Math.max(4, Math.ceil(Math.max.apply(null, per.data) / 4) * 4) }) : empty('runs', 'No dated runs'), { sub: 'last 7 days up to the newest run' })
  ]);
}

function counts(runs) {
  var c = { all: runs.length, running: 0, completed: 0, attention: 0 };
  runs.forEach(function(r) { c[runBucket(r)]++; });
  return c;
}

// applyRunsFilter shows/hides the table rows that carry a status; sweep group rows have none and stay visible.
export function applyRunsFilter() {
  var body = document.getElementById('runs-body');
  if (!body) return;
  var qEl = document.getElementById('runs-search');
  var q = qEl ? qEl.value.trim().toLowerCase() : '';
  body.querySelectorAll('tr[data-run-bucket]').forEach(function(tr) {
    var okStatus = filter === 'all' || tr.getAttribute('data-run-bucket') === filter;
    var okText = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
    tr.hidden = !(okStatus && okText);
  });
}

function renderFilterSeg() {
  var el = document.getElementById('runs-seg');
  if (!el) return;
  var c = counts(lastRuns);
  el.innerHTML = seg(RUN_FILTERS.map(function(f) { return { id: f.id, label: f.label, count: c[f.id] }; }), filter, 'setRunsFilter');
}

// filterRuns is the search box's input action.
export function filterRuns() { applyRunsFilter(); }

export function renderRunsSummary(runs) {
  lastRuns = runs || [];
  var el = document.getElementById('runs-summary');
  if (el) el.innerHTML = runsSummaryHTML(lastRuns);
  renderFilterSeg();
  applyRunsFilter();
}

export function setRunsFilter(id) {
  filter = RUN_FILTERS.some(function(f) { return f.id === id; }) ? id : 'all';
  renderFilterSeg();
  applyRunsFilter();
}

export function runsStatusAttr(r) { return ' data-run-bucket="' + x(runBucket(r)) + '"'; }
