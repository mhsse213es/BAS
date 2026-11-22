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
      rel: s.reliability || {},
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
  var lines = [
    { tone: stale.length ? 'warn' : 'ok', text: stale.length ? 'Stale sources: ' + stale.join(', ') : 'No stale sources' },
    { tone: stuck > 0 ? 'warn' : 'ok', text: stuck + ' stuck in validation' },
  ];
  // Scenarios the validation lab gave up on stay DRAFT until someone changes them; say so, because from the
  // outside they look like a slow pipeline. Shown only when there are some, so a healthy factory stays quiet.
  var stalled = dq.stalledValidations || [];
  if (stalled.length) {
    var names = stalled.slice(0, 5).map(function(s) { return s.contentId + ' v' + s.version; }).join(', ');
    var more = stalled.length > 5 ? ' and ' + (stalled.length - 5) + ' more' : '';
    lines.push({ tone: 'warn', text: stalled.length + ' scenario' + (stalled.length === 1 ? '' : 's') + ' stopped after ' +
      stalled[0].attempts + ' failed validation attempts and ' + (stalled.length === 1 ? 'needs' : 'need') + ' editing: ' + names + more });
  }
  return lines;
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

// ── KPI tiles ────────────────────────────────────────────────────────────────

// rateValue: the number of a measured metric, or null when it has no data (or is absent, as from an older server).
export function rateValue(m) { return m && m.state === 'measured' && isFinite(Number(m.value)) ? Number(m.value) : null; }

// rateText: a 0..1 rate as a whole percentage; an em dash when there is no data. A measured zero is "0%".
export function rateText(m) { var v = rateValue(m); return v == null ? '—' : Math.round(v * 100) + '%'; }

function perDayText(m) { var v = rateValue(m); return v == null ? null : v.toFixed(1) + ' / day'; }
function countText(m) { var v = rateValue(m); return v == null ? null : String(Math.round(v)); }
function pctOrNull(m) { var v = rateValue(m); return v == null ? null : Math.round(v * 100) + '%'; }

// freshnessText: how old the published content is, from the four age buckets.
export function freshnessText(f) {
  if (!f || !n(f.total)) return 'Nothing published yet';
  var parts = [];
  if (n(f.under30Days)) parts.push(n(f.under30Days) + ' under 30d');
  if (n(f.days31To90)) parts.push(n(f.days31To90) + ' at 31–90d');
  if (n(f.days91To365)) parts.push(n(f.days91To365) + ' at 91–365d');
  if (n(f.over365Days)) parts.push(n(f.over365Days) + ' over a year');
  return parts.join(' · ');
}

// kpiTiles: the throughput, quality and automation tiles. value is null when the metric has no data, which the
// page shows as NO DATA with the server's reason; nothing is invented. A report from an older server that lacks
// these fields gives all-null tiles rather than an error.
export function kpiTiles(r) {
  r = r || {};
  var errs = rateValue(r.executionValidationErrors);
  var fresh = r.contentFreshness || {};
  return [
    { key: 'ingested', label: 'Threats ingested', value: perDayText(r.threatsIngestedPerDay), m: r.threatsIngestedPerDay, caption: 'average per day', icon: 'layers', tone: 'accent' },
    { key: 'mapped', label: 'Threats mapped', value: countText(r.threatsMapped), m: r.threatsMapped, caption: 'with at least one technique', icon: 'mapped', tone: 'ok' },
    { key: 'generated', label: 'Candidates generated', value: perDayText(r.candidatesGeneratedPerDay), m: r.candidatesGeneratedPerDay, caption: 'average per day', icon: 'refresh', tone: 'accent' },
    { key: 'validated', label: 'Candidates validated', value: countText(r.candidatesValidated), m: r.candidatesValidated, caption: 'in the window', icon: 'check', tone: 'info' },
    { key: 'rejected', label: 'Candidates rejected', value: countText(r.candidatesRejected), m: r.candidatesRejected, caption: rejectedCaption(r.rejectedByReason), icon: 'alert', tone: 'warn' },
    { key: 'published', label: 'Published', value: perDayText(r.publishedPerDay), m: r.publishedPerDay, caption: 'average per day', icon: 'check', tone: 'ok' },
    { key: 'execpass', label: 'Execution validation pass rate', value: pctOrNull(r.executionValidationPassRate), m: r.executionValidationPassRate,
      caption: errs ? 'PASS of PASS+FAIL · ' + errs + (errs === 1 ? ' error' : ' errors') + ' not counted' : 'PASS of PASS+FAIL', icon: 'shield', tone: 'ok' },
    { key: 'handsoff', label: 'Hands-off rate', value: pctOrNull(r.handsOffRate), m: r.handsOffRate, caption: 'published with only the approval gate human', icon: 'bolt', tone: 'cyan' },
    { key: 'stageauto', label: 'Stage automation', value: pctOrNull(r.stageAutomationRate), m: r.stageAutomationRate, caption: 'lifecycle steps done by the system', icon: 'bolt', tone: 'cyan' },
    { key: 'reuse', label: 'Reuse rate', value: pctOrNull(r.reuseRate), m: r.reuseRate, caption: 'built from existing components', icon: 'refresh', tone: 'muted' },
    { key: 'freshness', label: 'Published content age', value: String(n(fresh.total)), m: null, caption: freshnessText(r.contentFreshness), icon: 'clock', tone: 'muted' },
  ];
}

// rejectedCaption: the top rejection reasons, so a count is never shown without its why.
function rejectedCaption(by) {
  var e = Object.keys(by || {}).map(function(k) { return [k, n(by[k])]; }).filter(function(p) { return p[1] > 0; }).sort(function(a, b) { return b[1] - a[1]; });
  if (!e.length) return 'in the window';
  return e.slice(0, 2).map(function(p) { return p[1] + ' ' + p[0].replace(/_/g, ' '); }).join(' · ');
}

// ── Source table ─────────────────────────────────────────────────────────────

export var COLUMNS = ['Source', 'State', 'Last success', 'Failures', 'Sync success', 'Resolution', 'Usefulness', 'Last diagnostic'];

// Columns holding a number, right-aligned by the page.
export var NUM_COLS = [3, 4, 5, 6];

// cellText: the text of one cell, used for the table filter and the CSV.
export function cellText(row, col) {
  switch (col) {
    case 0: return row.name;
    case 1: return row.state.label;
    case 2: return row.lastSuccessAt ? row.lastSuccessAt : 'never synced';
    case 3: return String(row.failures);
    case 4: return rateText(row.rel.syncSuccessRate);
    case 5: return rateText(row.rel.resolutionRate);
    case 6: return rateText(row.rel.usefulnessRate);
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
    case 4: return rateValue(r.rel.syncSuccessRate);
    case 5: return rateValue(r.rel.resolutionRate);
    case 6: return rateValue(r.rel.usefulnessRate);
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
