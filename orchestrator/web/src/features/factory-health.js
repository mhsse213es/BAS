import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { kpi, grid, card, hbars, chip, empty, checkRow } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';

var _loaded = false;
var minTrendPoints = 3;

export function loadFactoryHealth() {
  apicall('/api/analytics/factory-health').then(function(r) {
    _loaded = true;
    if (!r || !r.threatsProcessed || !r.pipeline) {
      var t = document.getElementById('factory-health-tiles');
      if (t) t.innerHTML = empty('factory', 'Factory health is not available right now');
      return;
    }
    renderFactoryHealthTiles(r);
    renderFactoryHealthIngestion(r);
    renderFactoryHealthFunnel(r);
    renderFactoryHealthDataQuality(r);
    renderFactoryHealthTrends(r);
  });
}

export function metricTile(label, metric, formatter, icon) {
  if (metric.state === 'no_data') {
    return kpi({ label: label, value: 'NO DATA', sub: metric.reason || 'No data yet', icon: icon, tone: 'muted' });
  }
  return kpi({ label: label, value: formatter(metric.value), icon: icon, tone: 'accent' });
}

function formatCount(v) { return String(v); }
function formatDuration(seconds) { return (seconds / 86400).toFixed(1) + 'd'; }
function formatPercent(fraction) { return (fraction * 100).toFixed(0) + '%'; }

function renderFactoryHealthTiles(r) {
  var el = document.getElementById('factory-health-tiles');
  if (!el) return;
  el.innerHTML = grid(3, [
    metricTile('Threats Processed', r.threatsProcessed, formatCount, 'globe'),
    metricTile('Published Content', r.publishedContent, formatCount, 'file'),
    metricTile('Median Threat→Content TCV', r.medianThreatToContentTcv, formatDuration, 'clock'),
    metricTile('Static Validation Pass Rate', r.staticValidationPassRate, formatPercent, 'shield'),
    metricTile('Duplicate Generation Rate', r.duplicateGenerationRate, formatPercent, 'copy'),
    metricTile('Source→Technique Coverage', r.sourceToTechniqueCoverage, formatPercent, 'mapped'),
  ]);
}

// renderFactoryHealthIngestion lists per-source sync health so a viewer can
// see WHY the other metrics might be stale or missing. A source that has
// never synced successfully is labeled "never synced", never shown as an
// empty/blank timestamp -- distinct from a source that is merely stale.
export function renderFactoryHealthIngestion(r) {
  var el = document.getElementById('factory-health-ingestion');
  if (!el) return;
  var ing = r.pipeline.ingestion;
  var rows = (ing.sources || []).map(function(s) {
    var never = !s.lastSuccessAt;
    var failing = s.failuresInWindow > 0;
    var sub = 'last success: ' + (never ? 'never synced' : s.lastSuccessAt) +
      (failing ? ' · ' + s.failuresInWindow + ' failure(s) in window' + (s.lastDiagnostic ? ': ' + s.lastDiagnostic : '') : '');
    return checkRow(never ? 'bad' : failing ? 'warn' : 'ok', s.displayName, sub,
      never ? chip('never synced', 'bad') : failing ? chip('failing', 'warn') : chip('healthy', 'ok'));
  }).join('');
  el.innerHTML = card('Source ingestion', (rows || empty('plug', 'No sources configured')) +
    '<div class="rg2-note">' + x(ing.unresolvedCandidates) + ' unresolved actor candidate(s)</div>',
    { sub: (ing.sources || []).length + ' source(s)' });
}

function renderFactoryHealthFunnel(r) {
  var el = document.getElementById('factory-health-funnel');
  if (!el) return;
  var f = r.pipeline.funnel;
  var max = Math.max(f.candidate, f.validated, f.published, f.rejected, 1);
  var pct = function(v) { return v / max * 100; };
  var dq = r.pipeline.dataQuality || {};
  var stale = (dq.staleSources || []).length ? 'Stale sources: ' + dq.staleSources.join(', ') : 'No stale sources';
  el.innerHTML = grid(2, [
    card('Content pipeline', hbars([
      ['Candidate', pct(f.candidate), 'accent', f.candidate],
      ['Validated', pct(f.validated), 'info', f.validated],
      ['Published', pct(f.published), 'ok', f.published],
      ['Rejected', pct(f.rejected), 'bad', f.rejected],
    ])),
    card('Data quality',
      checkRow((dq.staleSources || []).length ? 'warn' : 'ok', stale, null, null) +
      checkRow(dq.staleValidations > 0 ? 'warn' : 'ok', dq.staleValidations + ' stuck in validation', null, null)),
  ]);
}

function renderFactoryHealthDataQuality() {
  // Rendered together with the funnel (see renderFactoryHealthFunnel); the container is kept for compatibility.
  var el = document.getElementById('factory-health-dataquality');
  if (el) el.innerHTML = '';
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
