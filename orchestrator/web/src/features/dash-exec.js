// Renderers for the Executive view of the Dashboard. Same rule as dash-rich.js: every number comes
// from /api/dashboard/current, /api/dashboard/trends, /api/predict/risk or /api/findings.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { kpi, grid, card, chip, empty, icon, seg } from '../core/kit.js';
import { sevTone } from './rich-g3.js';
import { toneGauge } from './dash-rich.js';
import { execInsights, riskBand, topRisks, trendDelta, riskKpi, exposureKpi, detectionKpi, domainBreakdown } from './dash-model.js';

function cell(id, html) { var el = document.getElementById(id); if (el) el.innerHTML = html; }

export var EXEC_RANGES = [{ id: '30', label: '30 days' }, { id: '90', label: '90 days' }, { id: '365', label: '1 year' }];
export function renderRangeSeg(active) { cell('ed-range-seg', seg(EXEC_RANGES, active, 'setExecRange')); }

// Risk score (higher is worse) and Fleet assets (neutral) keep the generic tile. A score with no data
// behind it is shown as "No data yet", never as a number.
// Each KPI opens the Operational view that holds its evidence (the tab named in `tab`).
function kpiCard(label, current, series, ic, invertGood, tab) {
  var d = trendDelta(series, invertGood);
  return kpi({ label: label, value: current, sub: d.text, icon: ic, tone: d.tone === 'muted' ? 'accent' : d.tone, spark: series, action: 'showTab', args: [tab] });
}
function measuredTile(label, ic, m, tab) {
  return kpi({ label: label, value: m.value, sub: m.sub, icon: ic, tone: m.measurable ? m.tone : 'muted', spark: m.spark, action: 'showTab', args: [tab] });
}

export function renderExecKpis(current, trends) {
  trends = trends || [];
  var pick = function(k) { return trends.map(function(p) { return p[k]; }); };
  var rk = riskKpi(current, trends), ex = exposureKpi(current, trends), det = detectionKpi(current, trends);
  cell('ed-kpi-row', grid(4, [
    measuredTile('Risk score (lower is better)', 'shield', rk, 'runs'),
    measuredTile(ex.label || 'Exposure score', 'alert', ex, 'exposure'),
    measuredTile('Detection coverage', 'mapped', det, 'coverage'),
    kpiCard('Fleet assets', current.assetCount, pick('assetCount'), 'server', false, 'agents'),
  ]));
}

var dirTone = function(d) { return d === 'improving' ? 'ok' : d === 'worsening' ? 'bad' : 'muted'; };
export function renderExecForecast(fc) {
  if (!fc) { cell('ed-forecast', card('Risk-score forecast', empty('trend', 'No forecast data yet'))); return; }
  var hist = fc.history || [], proj = (fc.hasForecast && fc.projected) ? fc.projected : [], all = hist.concat(proj), body;
  var dir = fc.direction || 'unknown';
  if (all.length < 2) {
    body = empty('trend', 'Not enough data to chart yet', fc.note || 'A forecast needs a few daily snapshots.');
  } else {
    var series = [{ name: proj.length ? 'Risk score (history + forecast)' : 'Risk score', data: all.map(function(p) { return p.score; }), color: CHART_COLORS.warn }];
    if (proj.length) series.push({ name: 'Upper bound', data: all.map(function(p) { return typeof p.high === 'number' ? p.high : p.score; }), color: CHART_COLORS.bad, dash: true });
    body = chartSlot({ type: 'line', labels: all.map(function(p) { return 'd' + p.dayIndex; }), series: series, h: 220, area: true }) +
      '<div class="rk-note">' + (proj.length
        ? 'Projected to reach <b>' + x(proj[proj.length - 1].score) + '</b> by day ' + x(proj[proj.length - 1].dayIndex) + ' if the current trend continues' + (fc.confidence && fc.confidence !== 'none' ? '. Confidence: ' + x(fc.confidence) + ' (based on ' + hist.length + ' snapshots).' : '.')
        : x(fc.note || 'Insufficient history for a forecast.')) + '</div>';
  }
  var lg = '<div class="legend"><span class="lg"><i class="dl-sw" data-bg="' + CHART_COLORS.warn + '"></i>Risk</span>' + (proj.length ? '<span class="lg"><i class="dl-sw" data-bg="' + CHART_COLORS.bad + '"></i>Upper bound</span>' : '') + '</div>';
  cell('ed-forecast', '<section class="rk-card"><div class="rk-hd"><h2>Risk-score forecast</h2>' + chip(dir.charAt(0).toUpperCase() + dir.slice(1), dirTone(dir)) + '<div class="rk-hd-actions">' + lg + '</div></div>' + body + '</section>');
}

// Overall posture: the gauge (mean of the last 30 days' scored runs, the backend's avgRiskScore), the daily risk
// trend from the same forecast history the forecast card uses, and open findings per domain (controlClass).
export function renderExecPosture(current, forecast, findings) {
  var title = 'Overall posture', sub = 'Risk score — lower is better';
  if (!current) { cell('ed-posture', card(title, empty('shield', 'No data yet'))); return; }
  if (current.riskMeasurable !== true) { cell('ed-posture', card(title, empty('shield', 'Not measurable', 'No scored runs in the last 30 days.'), { sub: sub })); return; }
  var score = Number(current.avgRiskScore) || 0, band = riskBand(score);
  var hist = ((forecast && forecast.history) || []).slice(-30);
  var trend = hist.length >= 2
    ? chartSlot({ type: 'line', labels: hist.map(function(p) { return 'd' + p.dayIndex; }), series: [{ name: 'Risk score', data: hist.map(function(p) { return p.score; }), color: CHART_COLORS.warn }], h: 150, area: true })
    : empty('trend', 'Not enough history for a trend', 'A trend needs a few daily snapshots.');
  var doms = domainBreakdown(findings), max = doms.reduce(function(m, d) { return Math.max(m, d.open); }, 0);
  var domHtml = !findings ? empty('layers', 'Loading…')
    : !doms.length ? empty('check', 'No open findings', 'Nothing is open in any domain.')
    : doms.map(function(d) {
        return '<div class="dp-dom"><span class="dp-dom-n">' + x(d.domain) + '</span>' +
          '<div class="rk-bar"><i style="width:' + Math.round(100 * d.open / max) + '%"></i></div>' +
          '<span class="dp-dom-c">' + d.open + ' open</span>' + chip(d.worst, sevTone(d.worst)) + '</div>';
      }).join('');
  cell('ed-posture', card(title,
    '<div class="dp-posture"><div class="dp-center dp-risk">' + toneGauge(score, band.tone, band.label + ' risk', 'Risk score, out of 100. Lower is better.') +
    '<p class="muted tiny dp-risk-note">Average risk score over the last 30 days.</p></div>' +
    '<div class="dp-posture-side"><div class="muted tiny">Risk score, last 30 days</div>' + trend +
    '<div class="muted tiny dp-dom-h">Open findings by domain</div>' + domHtml + '</div></div>',
    { sub: sub }));
}

export function renderExecExposure(exp) {
  if (!exp || !exp.hasData) { cell('ed-exposure', card('Open exposure windows', empty('check', 'No open findings', 'Nothing is currently exposed.'))); return; }
  var rows = (exp.worst || []).map(function(it) {
    var over = it.daysOpen > exp.thresholdDays;
    // A row opens the specific finding it describes; without an ID it falls back to the list.
    var click = it.findingId ? on('click', 'openFindingFromDashboard', it.findingId) : on('click', 'showTab', 'findings');
    return '<tr class="rk-click"' + click + '><td><div>' + x(it.techniqueName) + (it.reopenedCount ? ' ' + chip('reopened ×' + it.reopenedCount, 'warn') : '') + '</div><div class="mono muted tiny">' + x(it.techniqueId) + '</div></td>' +
      '<td>' + chip(it.severity || '—', sevTone(it.severity)) + '</td><td>' + chip(it.daysOpen + ' d', over ? 'bad' : 'muted') + '</td>' +
      '<td class="muted">' + x(exp.thresholdDays) + ' d' + (over ? ' · <span class="dp-bad">breached</span>' : '') + '</td><td class="muted">' + x(it.firstSeen) + '</td></tr>';
  }).join('');
  cell('ed-exposure', card('Open exposure windows', '<div class="tbl-wrap"><table><thead><tr><th>Finding</th><th>Severity</th><th>Window open</th><th>SLA</th><th>First seen</th></tr></thead><tbody>' + rows + '</tbody></table></div>',
    { flush: true, sub: exp.openCount + ' open · median ' + exp.medianDaysOpen + ' d · ' + exp.overThreshold + ' over ' + exp.thresholdDays + ' d' }));
}

export function renderExecChanges(trends, current, exposure, days) {
  var items = execInsights(trends, current, exposure);
  var sub = 'over the last ' + (days === '365' ? 'year' : days + ' days');
  if (!items.length) { cell('ed-changes', card('What changed this period', empty('trend', 'No changes to report yet', 'Needs two or more daily snapshots.'), { sub: sub })); return; }
  cell('ed-changes', card('What changed this period', items.map(function(i) {
    return '<a class="dp-insight rk-click"' + on('click', 'showTab', i.tab) + '><span class="dp-fi tone-accent">' + icon(i.icon) + '</span><div><b>' + x(i.title) + '</b><span>' + x(i.desc) + '</span></div>' + icon('chevron') + '</a>';
  }).join(''), { sub: sub }));
}

export function renderExecRisks(findings) {
  var r = topRisks(findings, 4);
  if (!r.length) { cell('ed-risks', card('Top business risks', empty('check', findings ? 'No open critical or high findings' : 'Loading…'))); return; }
  cell('ed-risks', card('Top business risks', r.map(function(f) {
    return '<div class="rk-check rk-click"' + on('click', 'openFindingFromDashboard', f.id) + '>' + chip(f.severity, sevTone(f.severity)) +
      '<div class="rk-check-t"><b>' + x(f.techniqueName || f.techniqueId) + '</b><span>' + x((f.controlClass || 'Unclassified') + ' domain') + '</span></div></div>';
  }).join('')));
}

export function renderExecAll(o) {
  renderExecKpis(o.current, o.trends);
  renderExecForecast(o.predict && o.predict.forecast);
  renderExecPosture(o.current, o.predict && o.predict.forecast, o.findings);
  renderExecExposure(o.predict && o.predict.exposure);
  renderExecChanges(o.trends, o.current, o.predict && o.predict.exposure, o.days);
  renderExecRisks(o.findings);
}
