// Variants page: pure helpers (no DOM). Shapes come from GET /api/variants/coverage.

function n(v) { v = Number(v); return isFinite(v) ? v : 0; }

// coverageRows: one normalised row per technique; prevention is a whole percent (0 when nothing was tested).
export function coverageRows(rows) {
  return (rows || []).map(function(r) {
    var total = n(r.totalTested), prevented = n(r.prevented);
    return {
      technique: r.techniqueId || '',
      tactic: r.tactic || '',
      total: total,
      prevented: prevented,
      allowed: n(r.allowed),
      errored: n(r.errored),
      firstBypass: r.firstBypass || '',
      pct: total ? Math.round(prevented / total * 100) : 0,
    };
  });
}

// preventionTone: colour of a prevention-rate bar.
export function preventionTone(pct) {
  return pct >= 75 ? 'ok' : pct >= 40 ? 'warn' : 'bad';
}

// heroStats: the four banner numbers; null (shown as an em dash) when no variant has been run yet.
export function heroStats(rows) {
  var rs = coverageRows(rows);
  if (!rs.length) return { techniques: null, variants: null, prevented: null, bypassed: null };
  var tested = 0, prevented = 0, allowed = 0;
  rs.forEach(function(r) { tested += r.total; prevented += r.prevented; allowed += r.allowed; });
  return {
    techniques: rs.length,
    variants: tested,
    prevented: tested ? Math.round(prevented / tested * 100) + '%' : null,
    bypassed: allowed,
  };
}
