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

// cleanupBanner turns a variant run's recorded cleanup state into what the console shows beside the run's status.
// It reads only the cleanup fields, never the attack verdict. A failed cleanup is never shown as complete.
export function cleanupBanner(run) {
  var r = run || {};
  var status = r.cleanupStatus || '';
  if (status === 'FAILED' || r.remediationRequired) {
    return { tone: 'danger', label: 'Cleanup failed: remediation required', error: r.cleanupError || '' };
  }
  if (status === 'PENDING') return { tone: 'warning', label: 'Cleanup pending', error: '' };
  if (status === 'SUCCEEDED') return { tone: 'success', label: 'Cleanup completed', error: '' };
  if (status === 'NOT_REQUIRED') return { tone: 'muted', label: 'No cleanup needed', error: '' };
  return { tone: 'muted', label: 'Cleanup not recorded for this run', error: '' };
}
