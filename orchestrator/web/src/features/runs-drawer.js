// The blocks the redesigned Results drawer puts above each tab: stat tiles, rings, charts, the step strip and
// the tactic heat map. reports.js (viewRunResults) builds the tabs themselves; paintResultsExtras() then
// prepends these from the same run object. A block that has no real data behind it is left out.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { apicall } from '../core/api.js';
import { card, icon } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import * as R from './runs-res-model.js';

var LEGEND = function(items) { return '<div class="legend">' + items.map(function(i) { return '<span><i class="lg-' + i[0] + '"></i>' + x(i[1]) + '</span>'; }).join('') + '</div>'; };

// ── tiles ──────────────────────────────────────────────────────────────────
var TONE = { ok: 1, bad: 1, warn: 1, info: 1, muted: 1, accent: 1 };
var tone = function(t) { return TONE[t] ? t : 'muted'; };

export function numTile(label, value, sub, t) {
  return '<div class="rk-kpi res-t"><div class="rk-kpi-lbl">' + x(label) + '</div><div class="rk-kpi-val tone-' + tone(t) + '">' + x(value) + '</div>' + (sub ? '<div class="rk-kpi-sub">' + x(sub) + '</div>' : '') + '</div>';
}

var RING_COLOR = { ok: 'var(--success)', bad: 'var(--danger)', warn: 'var(--warning)', info: 'var(--info-text)', accent: 'var(--accent)' };
export function ring(pct, t) {
  var v = Math.max(0, Math.min(100, Number(pct) || 0));
  return '<span class="ring-n"><svg viewBox="0 0 60 60" width="60" height="60" class="progress-ring" aria-hidden="true"><circle cx="30" cy="30" r="24" fill="none" class="track" stroke-width="6"/>' +
    '<circle cx="30" cy="30" r="24" fill="none" stroke="' + (RING_COLOR[t] || RING_COLOR.accent) + '" stroke-width="6" stroke-linecap="round" stroke-dasharray="' + (v / 100 * 150.8).toFixed(1) + ' 150.8" transform="rotate(-90 30 30)"/></svg><b>' + Math.round(v) + '%</b></span>';
}
export function ringTile(label, pct, sub, t) {
  return '<div class="rk-kpi res-t res-ring">' + ring(pct, t) + '<div><div class="rk-kpi-lbl">' + x(label) + '</div><div class="rk-kpi-sub">' + x(sub) + '</div></div></div>';
}
var row = function(n, tiles) { return '<div class="rk-grid g' + n + ' res-row">' + tiles.join('') + '</div>'; };
var pair = function(a, b) { return '<div class="rk-grid g2 res-row">' + a + b + '</div>'; };

// ── building blocks ────────────────────────────────────────────────────────
export function stepStrip(steps) {
  if (!steps.length) return '';
  return '<div class="step-strip">' + steps.map(function(s) {
    return '<i class="' + (s.state === 'ok' ? 'ok' : s.state === 'bad' ? 'bad' : 'na') + '" title="' + x('Step ' + s.n + ': ' + s.name + ' — ' + (s.state === 'ok' ? 'pass' : s.state === 'bad' ? 'fail' : 'not measured')) + '"></i>';
  }).join('') + '</div>';
}

export function heatMap(steps) {
  var cells = R.heatCells(steps);
  if (!cells.some(function(c) { return c.total; })) return '';
  return '<div class="tac-heat">' + cells.map(function(c) {
    return '<div class="th ' + c.cls + '" title="' + x(c.label) + '"><b>' + x(c.short) + '</b><span>' + (c.total ? c.pass + '/' + c.total : '—') + '</span></div>';
  }).join('') + '</div>';
}
var HEAT_LEGEND = LEGEND([['ok', 'All blocked'], ['warn', 'Partial'], ['bad', 'Got through']]);

var yMaxFor = function(vals) { return Math.max(4, Math.ceil(Math.max.apply(null, vals.concat([0])) / 4) * 4); };
var short = function(label) { return String(label).split(' ')[0]; };

// ── per-tab blocks (sync, from the run itself) ─────────────────────────────
export function overviewExtra(steps) {
  var c = R.counts(steps);
  if (!c.total) return '';
  var donut = card('Outcome', chartSlot({ type: 'donut', segments: R.donutOf([{ label: 'Prevented / detected', value: c.ok, color: CHART_COLORS.ok }, { label: 'Missed', value: c.bad, color: CHART_COLORS.bad }, { label: 'Not measured', value: c.na, color: CHART_COLORS.muted }]), center: String(c.total), centerSub: 'steps', h: 160, legendRight: true }));
  var hist = card('Score history — this scenario', '<div id="run-ov-hist" class="res-hist"><div class="muted res-note">Loading score history…</div></div>');
  var heat = heatMap(steps);
  return '<div class="res-strip-wrap">' + stepStrip(steps) + '</div>' + pair(donut, hist) +
    (heat ? card('Tactic heat — where the attack got through', heat, { actions: HEAT_LEGEND }) : '');
}

export function historyHtml(h) {
  if (!h || h.values.length < 2) return '<div class="muted res-note">Not enough scored runs of this scenario for a history yet.</div>';
  return chartSlot({ type: 'line', labels: h.labels, series: [{ name: 'Prevention', data: h.values, color: CHART_COLORS.info }], h: 160, suffix: '%', yMax: 100 });
}

export function findingsExtra(steps) {
  var c = R.counts(steps), sev = R.severityCounts(steps), rows = R.tacticRows(steps).filter(function(r) { return r.fail > 0; });
  if (!c.total) return '';
  var breached = R.tacticRows(steps).filter(function(r) { return r.fail > 0; }).length;
  var tiles = row(3, [numTile('Failed steps', c.bad, 'of ' + c.total + ' executed', c.bad ? 'bad' : 'ok'), numTile('Critical / high', sev.critical + sev.high, 'need action first', sev.critical + sev.high ? 'bad' : 'ok'), numTile('Tactics breached', breached, 'of ' + R.tacticRows(steps).length + ' tested', breached ? 'warn' : 'ok')]);
  if (!c.bad) return tiles;
  var donut = card('Findings by severity', chartSlot({ type: 'donut', segments: R.donutOf([{ label: 'Critical', value: sev.critical, color: '#7f1d1d' }, { label: 'High', value: sev.high, color: CHART_COLORS.bad }, { label: 'Medium', value: sev.medium, color: CHART_COLORS.warn }, { label: 'Low', value: sev.low, color: CHART_COLORS.ok }]), center: String(sev.critical + sev.high + sev.medium + sev.low), centerSub: 'findings', h: 160, legendRight: true }));
  var bars = card('Missed steps by tactic', chartSlot({ type: 'bar', labels: rows.map(function(r) { return short(r.label); }), h: 160, yMax: yMaxFor(rows.map(function(r) { return r.fail; })), series: [{ name: 'Missed', color: CHART_COLORS.bad, data: rows.map(function(r) { return r.fail; }) }] }));
  return tiles + pair(donut, bars);
}

export function recommendationExtra(rep, steps) {
  var n = ((rep && rep.recommendations) || []).length;
  var c = R.counts(steps);
  return row(2, [numTile('Recommendations', n, n ? 'from this run\'s failed steps' : 'nothing to fix', n ? 'info' : 'ok'), numTile('Failed steps', c.bad, 'of ' + c.total + ' executed', c.bad ? 'bad' : 'ok')]);
}

export function timelineExtra(steps, run) {
  var d = R.durationStats(steps, run);
  if (!d.timed) return '';
  var tiles = row(4, [numTile('Total runtime', R.fmtMs(d.wallMs), 'wall clock', 'muted'), numTile('Active execution', R.fmtMs(d.activeMs), 'sum of step time', 'muted'),
    numTile('Slowest step', R.fmtMs(d.slowest.ms), String(d.slowest.name).slice(0, 22), 'warn'), numTile('Steps', steps.length, R.counts(steps).ok + ' pass · ' + R.counts(steps).bad + ' fail', 'muted')]);
  var timed = steps.filter(function(s) { return s.ms != null; });
  var secs = function(s) { return Math.round(s.ms / 100) / 10; };
  return tiles + card('Step duration (seconds)', chartSlot({ type: 'bar', stacked: true, labels: timed.map(function(s) { return '#' + s.n; }), h: 190, series: [
    { name: 'Pass', color: CHART_COLORS.ok, data: timed.map(function(s) { return s.state === 'bad' ? 0 : secs(s); }) },
    { name: 'Fail', color: CHART_COLORS.bad, data: timed.map(function(s) { return s.state === 'bad' ? secs(s) : 0; }) }] }), { actions: LEGEND([['ok', 'Pass'], ['bad', 'Fail']]) });
}

export function mitreExtra(steps, run) {
  var c = R.counts(steps), rows = R.tacticRows(steps);
  if (!c.total) return '';
  var m = c.ok + c.bad;
  var cov = run && run.score && typeof run.score.killChainCoverage === 'number' ? Math.round(run.score.killChainCoverage) : Math.round(rows.length / 14 * 100);
  var tiles = row(3, [numTile('Techniques', c.total, rows.length + (rows.length === 1 ? ' tactic' : ' tactics'), 'muted'), ringTile('Prevented', m ? Math.round(c.ok / m * 100) : 0, c.ok + ' techniques', 'ok'), ringTile('Tactic coverage', cov, 'of 14 tactics', 'accent')]);
  return tiles + card('Tactic heat', heatMap(steps), { actions: HEAT_LEGEND }) +
    card('Pass / fail by tactic', chartSlot({ type: 'bar', stacked: true, labels: rows.map(function(r) { return short(r.label); }), h: 170, yMax: yMaxFor(rows.map(function(r) { return r.pass + r.fail; })), series: [{ name: 'Pass', color: CHART_COLORS.ok, data: rows.map(function(r) { return r.pass; }) }, { name: 'Fail', color: CHART_COLORS.bad, data: rows.map(function(r) { return r.fail; }) }] }), { actions: LEGEND([['ok', 'Pass'], ['bad', 'Fail']]) });
}

export function flowExtra(steps) {
  var c = R.counts(steps), rows = R.tacticRows(steps);
  if (!c.total) return '';
  var m = c.ok + c.bad, last = R.furthestStage(rows);
  var tiles = row(3, [numTile('Furthest stage reached', last ? short(last.label) : 'None', 'attacker progress', last ? 'bad' : 'ok'), numTile('Steps that got through', c.bad, (m ? Math.round(c.bad / m * 100) : 0) + '% of chain', c.bad ? 'bad' : 'ok'), ringTile('Chain blocked', m ? Math.round(c.ok / m * 100) : 0, 'by prevention or detection', 'ok')]);
  var cum = R.cumulative(steps);
  return tiles + card('Attack flow by tactic', chartSlot({ type: 'bar', stacked: true, labels: rows.map(function(r) { return short(r.label); }), h: 210, yMax: yMaxFor(rows.map(function(r) { return r.pass + r.fail; })), series: [{ name: 'Prevented', color: CHART_COLORS.ok, data: rows.map(function(r) { return r.pass; }) }, { name: 'Missed', color: CHART_COLORS.bad, data: rows.map(function(r) { return r.fail; }) }] }), { actions: LEGEND([['ok', 'Prevented'], ['bad', 'Missed']]) }) +
    card('Cumulative breakthrough through the kill chain', chartSlot({ type: 'line', labels: steps.map(function(s) { return '#' + s.n; }), series: [{ name: 'Got through', data: cum, color: CHART_COLORS.bad }], h: 170, yMax: Math.max(4, c.bad + 1), area: true }));
}

export function evidenceExtra(steps) {
  var c = R.counts(steps);
  if (!c.total) return '';
  var fw = {};
  steps.forEach(function(s) { var k = s.framework || 'custom'; fw[k] = (fw[k] || 0) + 1; });
  var palette = [CHART_COLORS.info, CHART_COLORS.teal, CHART_COLORS.violet, CHART_COLORS.warn, CHART_COLORS.ok];
  var tiles = row(3, [numTile('Steps recorded', c.total, 'with per-step evidence', 'muted'), numTile('Prevented', c.ok, 'blocked or detected', 'ok'), numTile('Got through', c.bad, 'no blocking control', c.bad ? 'bad' : 'ok')]);
  var timed = steps.filter(function(s) { return s.ms != null; });
  return tiles + pair(
    card('By framework', chartSlot({ type: 'donut', segments: Object.keys(fw).sort().map(function(k, i) { return { label: k.toUpperCase(), value: fw[k], color: palette[i % palette.length] }; }), center: String(c.total), centerSub: 'steps', h: 160, legendRight: true })),
    timed.length ? card('Duration per step (s)', chartSlot({ type: 'bar', labels: timed.map(function(s) { return '#' + s.n; }), h: 160, series: [{ name: 'Seconds', color: CHART_COLORS.info, data: timed.map(function(s) { return Math.round(s.ms / 100) / 10; }) }] })) : '');
}

export function endpointExtra(run) {
  var n = ((run && run.reverted) || []).length;
  if (!n) return '';
  return row(2, [numTile('Changes reverted', n, 'cleaned up by the agent', 'ok'), ringTile('Cleanup', 100, 'every captured change reverted', 'ok')]);
}

export function reportsExtra(run) {
  var id = run && run.id;
  if (!id) return '';
  var b = function(action) { return '<button type="button" class="btn btn-outline btn-sm"' + on('click', action, id) + '>' + icon('download') + 'Download</button>'; };
  var rows = [['Technical results', 'HTML', 'SOC / engineers', 'openRunReport'], ['Executive summary', 'PDF', 'Leadership', 'downloadRunReport'], ['Raw data', 'JSON', 'Integrations', 'exportRunJSON'], ['Findings table', 'CSV', 'Ticketing', 'downloadRunCSV']];
  return row(1, [numTile('Reports available', rows.length, 'generated on demand for this run', 'muted')]) +
    '<div class="rk-card flush res-row"><table><thead><tr><th>Report</th><th>Format</th><th>Audience</th><th></th></tr></thead><tbody>' + rows.map(function(r) {
      return '<tr><td>' + x(r[0]) + '</td><td><span class="rk-chip tone-muted">' + x(r[1]) + '</span></td><td class="muted">' + x(r[2]) + '</td><td class="num">' + b(r[3]) + '</td></tr>';
    }).join('') + '</tbody></table></div>';
}

// ── mount ──────────────────────────────────────────────────────────────────
function prepend(id, html) {
  var el = document.getElementById(id);
  if (el && html) el.insertAdjacentHTML('afterbegin', '<div class="res-extra">' + html + '</div>');
}

// paintResultsExtras: called by viewRunResults once the tab panels exist.
export function paintResultsExtras(run) {
  var steps = R.stepsOf(run);
  prepend('run-tab-findings', findingsExtra(steps));
  prepend('run-tab-timeline', timelineExtra(steps, run));
  prepend('run-tab-mitre', mitreExtra(steps, run));
  prepend('run-tab-flow', flowExtra(steps));
  prepend('run-tab-evidence', evidenceExtra(steps));
  prepend('run-tab-endpoint', endpointExtra(run));
  var reports = document.getElementById('run-tab-reports');
  if (reports && (run.status === 'completed' || run.status === 'partial')) prepend('run-tab-reports', reportsExtra(run));
  // Overview + score history
  var ov = document.getElementById('run-ov-extra');
  if (ov) ov.innerHTML = overviewExtra(steps);
  var hist = document.getElementById('run-ov-hist');
  if (hist && run.scenarioId) {
    apicall('/api/scenarios/runs?scenarioId=' + encodeURIComponent(run.scenarioId)).then(function(runs) {
      var el = document.getElementById('run-ov-hist');
      if (el && Array.isArray(runs)) el.innerHTML = historyHtml(R.scoreHistory(runs, run, 7));
    }).catch(function() { var el = document.getElementById('run-ov-hist'); if (el) el.innerHTML = '<div class="muted res-note">Score history is unavailable.</div>'; });
  }
}

// paintRecommendationExtra: the recommendation tab's tiles, once the report fetch lands.
export function paintRecommendationExtra(rep, run) {
  var el = document.getElementById('run-tab-recommendation');
  if (!el || el.querySelector('.res-extra')) return;
  prepend('run-tab-recommendation', recommendationExtra(rep, R.stepsOf(run)));
}

