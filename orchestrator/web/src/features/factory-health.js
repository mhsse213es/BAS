import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate } from '../core/util.js';
import { kpi, grid, card, hbars, chip, empty, kv, icon } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { ringTile } from './runs-drawer.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './fh-model.js';

var minTrendPoints = 3;
var _sources = [];

export function loadFactoryHealth() {
  apicall('/api/analytics/factory-health').then(function(r) {
    if (!r || !r.threatsProcessed || !r.pipeline) {
      var t = document.getElementById('factory-health-tiles');
      if (t) t.innerHTML = empty('factory', 'Factory health is not available right now');
      return;
    }
    renderFactoryHealthHero(r);
    renderFactoryHealthTiles(r);
    renderFactoryHealthIngestion(r);
    renderFactoryHealthFunnel(r);
    renderFactoryHealthDataQuality(r);
    renderFactoryHealthTrends(r);
  });
}

export function metricTile(label, metric, formatter, ic) {
  if (metric.state === 'no_data') {
    return kpi({ label: label, value: 'NO DATA', sub: metric.reason || 'No data yet', icon: ic, tone: 'muted' });
  }
  return kpi({ label: label, value: formatter(metric.value), icon: ic, tone: 'accent' });
}

function formatCount(v) { return String(v); }
function formatDuration(seconds) { return (seconds / 86400).toFixed(1) + 'd'; }
function formatPercent(fraction) { return (fraction * 100).toFixed(0) + '%'; }

// coverageTile: the Source -> Technique coverage as a progress ring (a no-data metric stays a plain NO DATA tile).
function coverageTile(metric, unresolved) {
  if (metric.state === 'no_data') return metricTile('Source→Technique Coverage', metric, formatPercent, 'mapped');
  return ringTile('Source→Technique Coverage', Math.round(metric.value * 100), x(unresolved) + ' unresolved actor candidate(s)', 'ok');
}

function renderFactoryHealthHero(r) {
  var h = M.heroStats(r);
  var dash = function(v) { return v == null ? '—' : v; };
  setHeroStat('fh-hs-threats', dash(h.threats));
  setHeroStat('fh-hs-published', dash(h.published));
  setHeroStat('fh-hs-sources', dash(h.sources));
  setHeroStat('fh-hs-unresolved', dash(h.unresolved));
}

function renderFactoryHealthTiles(r) {
  var el = document.getElementById('factory-health-tiles');
  if (!el) return;
  var unresolved = (r.pipeline && r.pipeline.ingestion && r.pipeline.ingestion.unresolvedCandidates) || 0;
  el.innerHTML = grid(3, [
    metricTile('Threats Processed', r.threatsProcessed, formatCount, 'globe'),
    metricTile('Published Content', r.publishedContent, formatCount, 'file'),
    metricTile('Median Threat→Content TCV', r.medianThreatToContentTcv, formatDuration, 'clock'),
    metricTile('Static Validation Pass Rate', r.staticValidationPassRate, formatPercent, 'shield'),
    metricTile('Duplicate Generation Rate', r.duplicateGenerationRate, formatPercent, 'copy'),
    coverageTile(r.sourceToTechniqueCoverage, unresolved),
  ]);
}

// renderFactoryHealthIngestion lists per-source sync health so a viewer can
// see WHY the other metrics might be stale or missing. A source that has
// never synced successfully is labeled "never synced", never shown as an
// empty/blank timestamp -- distinct from a source that is merely stale.
export function renderFactoryHealthIngestion(r) {
  var el = document.getElementById('factory-health-ingestion');
  if (!el) return;
  _sources = M.sourceRows(r.pipeline.ingestion.sources);
  var ing = r.pipeline.ingestion;
  var body;
  if (!_sources.length) {
    body = empty('plug', 'No sources configured');
  } else {
    body = '<div class="tbl-wrap"><table><thead><tr><th>Source</th><th>State</th><th>Last success</th><th>Failures</th><th>Last diagnostic</th></tr></thead><tbody>' +
      _sources.map(function(s, i) {
        return '<tr class="fh-row" tabindex="0"' + on('click', 'openFactorySource', i) + '><td><b>' + x(s.name) + '</b></td><td>' + chip(s.state.label, s.state.tone) + '</td>' +
          '<td class="muted">' + x(s.lastSuccessAt ? fmtDate(s.lastSuccessAt) : 'never synced') + '</td><td>' + x(s.failures) + '</td><td class="muted fh-diag">' + x(s.diagnostic || '—') + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }
  el.innerHTML = card('Source ingestion', body + '<div class="rg2-note">' + x(ing.unresolvedCandidates) + ' unresolved actor candidate(s)</div>',
    { sub: _sources.length + ' source(s)', flush: true });
}

function renderFactoryHealthDataQuality(r) {
  var el = document.getElementById('factory-health-dataquality');
  if (!el) return;
  var c = M.sourceCounts(r.pipeline.ingestion.sources);
  var pct = function(v) { return c.total ? v / c.total * 100 : 0; };
  el.innerHTML = card('Ingestion summary', c.total
    ? hbars([['Healthy', pct(c.healthy), 'ok', c.healthy], ['Failing', pct(c.failing), 'warn', c.failing], ['Never synced', pct(c.never), 'bad', c.never]])
    : empty('plug', 'No sources configured'), { sub: c.total + ' source(s)' });
}

function renderFactoryHealthFunnel(r) {
  var el = document.getElementById('factory-health-funnel');
  if (!el) return;
  var st = M.funnelStages(r.pipeline.funnel);
  var boxes = st.map(function(s, i) {
    return '<div class="fh-stage tone-' + s.tone + '"><div class="fh-stage-v">' + x(s.value) + '</div><div class="fh-stage-n">' + x(s.label) + '</div></div>' +
      (i < st.length - 1 ? '<span class="fh-arrow" aria-hidden="true">→</span>' : '');
  }).join('');
  var lines = M.qualityLines(r.pipeline.dataQuality).map(function(l) {
    return '<span class="fh-q tone-' + l.tone + '">' + icon(l.tone === 'ok' ? 'ok' : 'alert') + x(l.text) + '</span>';
  }).join('');
  el.innerHTML = card('Content pipeline', '<div class="fh-funnel">' + boxes + '</div><div class="fh-quality">' + lines + '</div>');
}

function trendCard(title, points, suffix) {
  if (!points || points.length < minTrendPoints) return card(title, empty('trend', 'Not enough history yet'));
  return card(title, chartSlot({ type: 'line', h: 190, suffix: suffix || '', labels: points.map(function(p) { return String(p.day).slice(5); }),
    series: [{ name: title, data: points.map(function(p) { return p.value; }), color: CHART_COLORS.accent }] }));
}

function renderFactoryHealthTrends(r) {
  var a = document.getElementById('factory-health-threats-trend');
  var b = document.getElementById('factory-health-tcv-trend');
  if (a) a.innerHTML = trendCard('Threats processed per day', r.trends.threatsProcessedByDay);
  if (b) b.innerHTML = trendCard('Threat to content time per day', r.trends.tcvByDay);
}

// The source drawer: one ingestion source, shown from the response already loaded (no extra request).
export function openFactorySource(i) {
  var s = _sources[i];
  if (!s) return;
  var set = function(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; };
  set('fh-drawer-title', s.name);
  set('fh-drawer-sub', s.id || 'Ingestion source');
  var body = document.getElementById('fh-drawer-body');
  if (body) {
    body.innerHTML = '<div class="fh-dr-state">' + chip(s.state.label, s.state.tone) + '</div>' +
      kv([['Last success', s.lastSuccessAt ? fmtDate(s.lastSuccessAt) : 'never synced'], ['Failures in window', String(s.failures)], ['Last diagnostic', s.diagnostic || 'None reported']]);
  }
  var o = document.getElementById('fh-drawer-overlay');
  if (o) o.classList.add('open');
}
export function closeFactorySource() {
  var o = document.getElementById('fh-drawer-overlay');
  if (o) o.classList.remove('open');
}
export function closeFactoryDrawerOnBackdrop(el, event) { if (event.target === el) closeFactorySource(); }

// renderSparkline draws an inline SVG polyline, matching the existing
// attack-path.js/evidence.js convention -- no charting library. Below
// minTrendPoints (kept in sync with the backend's own threshold), it
// shows an honest empty state instead of a misleading short line.
export function renderSparkline(elementId, points) {
  var el = document.getElementById(elementId);
  if (!el) return;
  if (!points || points.length < minTrendPoints) {
    el.innerHTML = '<div class="kpi-sub" style="color:var(--muted)">Not enough history yet</div>';
    return;
  }
  var w = 240, h = 48, pad = 4;
  var values = points.map(function(p) { return p.value; });
  var min = Math.min.apply(null, values);
  var max = Math.max.apply(null, values);
  var range = max - min || 1;
  var step = (w - pad * 2) / (points.length - 1);
  var coords = values.map(function(v, i) {
    var cx = pad + i * step;
    var cy = h - pad - ((v - min) / range) * (h - pad * 2);
    return cx.toFixed(1) + ',' + cy.toFixed(1);
  }).join(' ');
  el.innerHTML = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">' +
    '<polyline points="' + coords + '" fill="none" stroke="var(--accent)" stroke-width="2"/></svg>';
}
