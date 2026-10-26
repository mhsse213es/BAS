// Pure helpers for the redesigned Factory Health page: banner numbers, the source rows and their
// health state, the ingestion summary and the content-pipeline stages. No DOM, no network: everything
// comes from the one GET /api/analytics/factory-health response.

function n(v) { var k = Number(v); return isFinite(k) ? k : 0; }

// sourceState: never synced beats failing beats healthy (same rule the page always used).
export function sourceState(s) {
  s = s || {};
  if (!s.lastSuccessAt) return { key: 'never', label: 'never synced', tone: 'bad' };
  if (n(s.failuresInWindow) > 0) return { key: 'failing', label: 'failing', tone: 'warn' };
  return { key: 'healthy', label: 'healthy', tone: 'ok' };
}

// sourceRows: one row per ingestion source, ready to render.
export function sourceRows(sources) {
  return (sources || []).map(function(s) {
    var st = sourceState(s);
    return {
      name: s.displayName || s.sourceInstanceId || 'Unnamed source',
      id: s.sourceInstanceId || '',
      state: st,
      lastSuccessAt: s.lastSuccessAt || null,
      failures: n(s.failuresInWindow),
      diagnostic: s.lastDiagnostic || '',
    };
  });
}

// sourceCounts: how many sources are healthy, failing or never synced.
export function sourceCounts(sources) {
  var c = { total: 0, healthy: 0, failing: 0, never: 0 };
  (sources || []).forEach(function(s) { c.total++; c[sourceState(s).key]++; });
  return c;
}

// heroStats: the four numbers in the banner. A metric with no data gives null (shown as an em dash).
export function heroStats(r) {
  r = r || {};
  var ing = (r.pipeline && r.pipeline.ingestion) || {};
  var c = sourceCounts(ing.sources);
  var measured = function(m) { return m && m.state !== 'no_data' ? m.value : null; };
  return {
    threats: measured(r.threatsProcessed),
    published: measured(r.publishedContent),
    sources: c.total ? c.healthy + ' / ' + c.total : null,
    unresolved: ing.unresolvedCandidates == null ? null : n(ing.unresolvedCandidates),
  };
}

// funnelStages: the four content-pipeline boxes in order.
export function funnelStages(f) {
  f = f || {};
  return [
    { key: 'candidate', label: 'Candidate', value: n(f.candidate), tone: 'muted' },
    { key: 'validated', label: 'Validated', value: n(f.validated), tone: 'info' },
    { key: 'published', label: 'Published', value: n(f.published), tone: 'ok' },
    { key: 'rejected', label: 'Rejected', value: n(f.rejected), tone: 'bad' },
  ];
}

// qualityLines: the stale-source and stuck-validation lines under the funnel.
export function qualityLines(dq) {
  dq = dq || {};
  var stale = dq.staleSources || [];
  var stuck = n(dq.staleValidations);
  return [
    { tone: stale.length ? 'warn' : 'ok', text: stale.length ? 'Stale sources: ' + stale.join(', ') : 'No stale sources' },
    { tone: stuck > 0 ? 'warn' : 'ok', text: stuck + ' stuck in validation' },
  ];
}

// ── Metric tiles ─────────────────────────────────────────────────────────────

// windowDays: whole days in the lookback window the report covers (windowSince -> now), or null.
export function windowDays(r, nowTs) {
  var t = r && r.windowSince ? Date.parse(r.windowSince) : NaN;
  if (!isFinite(t)) return null;
  var d = Math.round(((nowTs == null ? Date.now() : nowTs) - t) / 86400000);
  return d > 0 ? d : null;
}

// tileCaption: the one line under a tile's value, taken from the response (never invented).
export function tileCaption(key, r, nowTs) {
  r = r || {};
  if (key === 'threats') { var d = windowDays(r, nowTs); return d ? 'last ' + d + (d === 1 ? ' day' : ' days') : 'selected window'; }
  if (key === 'published') return 'scenarios and variants';
  if (key === 'tcv') return 'median TCV';
  if (key === 'validation') {
    var m = r.staticValidationPassRate;
    return m && m.state !== 'no_data' && n(m.value) >= 1 ? 'every build passed' : 'of builds passed validation';
  }
  return '';
}

// ── Source table ─────────────────────────────────────────────────────────────

export var COLUMNS = ['Source', 'State', 'Last success', 'Failures', 'Last diagnostic'];

// cellText: the text of one cell, used for the table filter and the CSV.
export function cellText(row, col) {
  switch (col) {
    case 0: return row.name;
    case 1: return row.state.label;
    case 2: return row.lastSuccessAt ? row.lastSuccessAt : 'never synced';
    case 3: return String(row.failures);
    default: return row.diagnostic || '';
  }
}

export function filterSources(rows, q) {
  var s = String(q || '').trim().toLowerCase();
  if (!s) return rows.slice();
  return rows.filter(function(r) { return (r.name + ' ' + r.id + ' ' + r.state.label + ' ' + r.diagnostic).toLowerCase().indexOf(s) !== -1; });
}

function sortKey(r, col) {
  switch (col) {
    case 0: return r.name;
    case 1: return r.state.label;
    case 2: return r.lastSuccessAt ? Date.parse(r.lastSuccessAt) : null;
    case 3: return r.failures;
    default: return r.diagnostic || null;
  }
}

// sortSources: stable; empty values (never synced, no diagnostic) always sort last.
export function sortSources(rows, col, dir) {
  if (col < 0) return rows.slice();
  var d = dir < 0 ? -1 : 1;
  return rows.map(function(r, i) { return { r: r, i: i }; }).sort(function(a, b) {
    var u = sortKey(a.r, col), v = sortKey(b.r, col);
    var ue = u == null || u === '' || (typeof u === 'number' && isNaN(u)), ve = v == null || v === '' || (typeof v === 'number' && isNaN(v));
    if (ue || ve) return ue && ve ? a.i - b.i : ue ? 1 : -1;
    var c = typeof u === 'number' && typeof v === 'number' ? u - v : String(u).localeCompare(String(v), undefined, { numeric: true });
    return c * d || a.i - b.i;
  }).map(function(o) { return o.r; });
}

export { pageCount, rangeText, csvText } from './runs-model.js';
