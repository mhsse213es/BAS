// Pure helpers for the Factory Velocity panel: turn the four per-stage SLA
// reports (GET /api/intel/factory/sla?stage=queue|generation|validation|end_to_end)
// into the rows and summary the panel renders. No DOM, no network.
//
// Honesty rule: every P50/P95 shown is a real returned percentile for a real
// (source, content_type) validated segment. Percentiles are never averaged
// across segments — that is statistically meaningless — so a segment that has
// no validated figure for a stage is reported as null, not fabricated.

export var STAGE_ORDER = ['queue', 'generation', 'validation', 'end_to_end'];

function segKey(s) { return (s.source || '') + '\u0000' + (s.content_type || ''); }

// hasSegments: a report we actually received (not null, not an {error:...} body
// that apicall returns verbatim for a non-200). Only such a report may feed the
// summary or count toward availability.
function hasSegments(report) { return !!report && Array.isArray(report.segments); }

// validatedSegments: the validated-cohort segments of one report (or []).
function validatedSegments(report) {
  if (!hasSegments(report)) return [];
  return report.segments.filter(function (s) { return s.cohort === 'validated' && s.p50_seconds != null; });
}

// velocityModel builds the panel's view model from the four stage reports.
// reports: { queue, generation, validation, end_to_end } — each an SLAReport
// or null/absent. Returns { hasData, rows, summary }.
export function velocityModel(reports) {
  reports = reports || {};
  var rowsByKey = {};
  var order = [];

  // Collect validated figures per (source, content_type) across all stages.
  STAGE_ORDER.forEach(function (stage) {
    validatedSegments(reports[stage]).forEach(function (s) {
      var k = segKey(s);
      if (!rowsByKey[k]) {
        rowsByKey[k] = { source: s.source || '', contentType: s.content_type || '', n: 0,
          stages: { queue: null, generation: null, validation: null, end_to_end: null } };
        order.push(k);
      }
      rowsByKey[k].stages[stage] = { p50: s.p50_seconds, p95: s.p95_seconds == null ? null : s.p95_seconds, n: s.n || 0 };
    });
  });

  // Row count n: prefer the end_to_end validated count (fully-through legs),
  // else validation, else the largest stage count seen for the segment.
  var rows = order.map(function (k) {
    var row = rowsByKey[k];
    var st = row.stages;
    row.n = (st.end_to_end && st.end_to_end.n) || (st.validation && st.validation.n) ||
      Math.max(0, (st.queue && st.queue.n) || 0, (st.generation && st.generation.n) || 0);
    return row;
  });

  // Summary: cohort counts + health come from a report we actually received,
  // preferring end_to_end (open_count/oldest_open/bottleneck/incomplete are
  // computed stage-independently server-side, so any received report agrees).
  // An {error:...} body from a failed stage must NOT become the summary, or the
  // chips would read "0 validated" while the rows show real data.
  var base = {};
  for (var i = STAGE_ORDER.length - 1; i >= 0; i--) {
    if (hasSegments(reports[STAGE_ORDER[i]])) { base = reports[STAGE_ORDER[i]]; break; }
  }
  var available = STAGE_ORDER.some(function (s) { return hasSegments(reports[s]); });
  var validatedN = 0, failedN = 0;
  (base.segments || []).forEach(function (s) {
    if (s.cohort === 'validated') validatedN += (s.n || 0);
    else if (s.cohort === 'failed') failedN += (s.n || 0);
  });

  return {
    available: available,
    hasData: rows.length > 0,
    rows: rows,
    summary: {
      validatedN: validatedN,
      failedN: failedN,
      openN: base.open_count || 0,
      oldestOpenSeconds: base.oldest_open_seconds == null ? null : base.oldest_open_seconds,
      bottleneck: base.bottleneck || '',
      incomplete: !!base.incomplete_window,
    },
  };
}

// fmtDuration renders whole seconds as a compact human duration. Validation is
// minutes, end-to-end can be days, so a single days-only format (as the other
// factory tiles use) would read "0.0d" for a fast leg; pick the unit by size.
export function fmtDuration(seconds) {
  if (seconds == null || !isFinite(Number(seconds))) return '—';
  var s = Number(seconds);
  if (s < 90) return Math.round(s) + 's';
  if (s < 5400) return Math.round(s / 60) + 'm';       // under 90 minutes
  if (s < 172800) return (s / 3600).toFixed(1) + 'h';  // under 48 hours
  return (s / 86400).toFixed(1) + 'd';
}
