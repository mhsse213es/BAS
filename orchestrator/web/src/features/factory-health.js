import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';

var _loaded = false;

export function loadFactoryHealth() {
  apicall('/api/analytics/factory-health').then(function(r) {
    _loaded = true;
    if (!r || !r.threatsProcessed || !r.pipeline) {
      var t = document.getElementById('factory-health-tiles');
      if (t) t.innerHTML = '<div class="empty">Factory health is not available right now.</div>';
      return;
    }
    renderFactoryHealthTiles(r);
    renderFactoryHealthIngestion(r);
    renderFactoryHealthFunnel(r);
    renderFactoryHealthDataQuality(r);
    renderFactoryHealthTrends(r);
  });
}

export function metricTile(label, metric, formatter) {
  if (metric.state === 'no_data') {
    return '<div class="kpi-card stat-tile" title="' + x(metric.reason || 'No data yet') + '">' +
      '<div class="kpi-label">' + x(label) + '</div>' +
      '<div class="kpi-value" style="color:var(--muted)">NO DATA</div>' +
      '<div class="kpi-sub">' + x(metric.reason || '') + '</div></div>';
  }
  return '<div class="kpi-card stat-tile">' +
    '<div class="kpi-label">' + x(label) + '</div>' +
    '<div class="kpi-value">' + x(formatter(metric.value)) + '</div></div>';
}

function formatCount(v) { return String(v); }
function formatDuration(seconds) { return (seconds / 86400).toFixed(1) + 'd'; }
function formatPercent(fraction) { return (fraction * 100).toFixed(0) + '%'; }

function renderFactoryHealthTiles(r) {
  var el = document.getElementById('factory-health-tiles');
  if (!el) return;
  el.innerHTML =
    metricTile('Threats Processed', r.threatsProcessed, formatCount) +
    metricTile('Published Content', r.publishedContent, formatCount) +
    metricTile('Median Threat→Content TCV', r.medianThreatToContentTcv, formatDuration) +
    metricTile('Static Validation Pass Rate', r.staticValidationPassRate, formatPercent) +
    metricTile('Duplicate Generation Rate', r.duplicateGenerationRate, formatPercent) +
    metricTile('Source→Technique Coverage', r.sourceToTechniqueCoverage, formatPercent);
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
    var lastSuccess = s.lastSuccessAt ? x(s.lastSuccessAt) : 'never synced';
    var failures = s.failuresInWindow > 0 ?
      ' &middot; ' + s.failuresInWindow + ' failure(s) in window' + (s.lastDiagnostic ? ': ' + x(s.lastDiagnostic) : '') : '';
    return '<div class="kpi-sub"><strong>' + x(s.displayName) + '</strong> &middot; last success: ' + lastSuccess + failures + '</div>';
  }).join('');
  el.innerHTML = rows +
    '<div class="kpi-sub">' + ing.unresolvedCandidates + ' unresolved actor candidate(s)</div>';
}

function renderFactoryHealthFunnel(r) {
  var el = document.getElementById('factory-health-funnel');
  if (!el) return;
  var f = r.pipeline.funnel;
  el.innerHTML =
    '<div class="kpi-card stat-tile"><div class="kpi-label">Candidate</div><div class="kpi-value">' + f.candidate + '</div></div>' +
    '<div class="kpi-card stat-tile"><div class="kpi-label">Validated</div><div class="kpi-value">' + f.validated + '</div></div>' +
    '<div class="kpi-card stat-tile"><div class="kpi-label">Published</div><div class="kpi-value">' + f.published + '</div></div>' +
    '<div class="kpi-card stat-tile"><div class="kpi-label">Rejected</div><div class="kpi-value">' + f.rejected + '</div></div>';
}

function renderFactoryHealthDataQuality(r) {
  var el = document.getElementById('factory-health-dataquality');
  if (!el) return;
  var dq = r.pipeline.dataQuality;
  var stale = (dq.staleSources || []).length ?
    'Stale sources: ' + dq.staleSources.map(x).join(', ') : 'No stale sources';
  el.innerHTML = '<div class="kpi-sub">' + x(stale) + ' &middot; ' + dq.staleValidations + ' stuck in validation</div>';
}

function renderFactoryHealthTrends(r) {
  renderSparkline('factory-health-threats-trend', r.trends.threatsProcessedByDay);
  renderSparkline('factory-health-tcv-trend', r.trends.tcvByDay);
}

// renderSparkline draws an inline SVG polyline, matching the existing
// attack-path.js/evidence.js convention -- no charting library. Below
// minTrendPoints (kept in sync with the backend's own threshold), it
// shows an honest empty state instead of a misleading short line.
var minTrendPoints = 3;
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
