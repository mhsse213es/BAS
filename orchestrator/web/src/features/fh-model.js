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
