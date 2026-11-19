// The Overview panel for execution coverage: how many scheduled steps ran to a result, separate from the security
// verdicts shown next to it. Input is the executionCoverage object from the run report (report.json). The labels
// follow the normalised outcomes in internal/models/execution_outcome.go.

var ROWS = [
  ['executed', 'Executed'],
  ['prevented', 'Prevented by a control'],
  ['partiallyExecuted', 'Partially executed'],
  ['notExecuted', 'Not executed'],
  ['unsupported', 'Unsupported on this endpoint'],
  ['timedOut', 'Timed out'],
  ['executionError', 'Execution error'],
  ['cancelled', 'Cancelled'],
  ['skipped', 'Skipped'],
];

function esc(s) {
  return String(s).replace(/[&<>"']/g, function(c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

// Returns '' when there is no coverage object, so an older report shows no panel instead of a false 0%.
export function executionCoverageHtml(c) {
  if (!c) return '';
  var scheduled = Number(c.scheduled) || 0;
  var pct = Number(c.coveragePct) || 0;
  var rows = ROWS.filter(function(r) { return Number(c[r[0]]) > 0; }).map(function(r) {
    return '<div style="display:flex;justify-content:space-between;gap:12px;font-size:0.75rem;padding:2px 0">' +
      '<span style="color:var(--muted)">' + esc(r[1]) + '</span><b>' + esc(c[r[0]]) + '</b></div>';
  }).join('');
  return '<div style="background:var(--elevated);border:1px solid var(--border);border-radius:4px;padding:0.6rem 0.75rem;margin-bottom:0.75rem">' +
    '<div style="font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:0.45rem">Execution coverage</div>' +
    '<div style="display:flex;align-items:baseline;gap:10px;margin-bottom:6px">' +
      '<span style="font-size:1.3rem;font-weight:700">' + Math.round(pct) + '%</span>' +
      '<span style="font-size:0.72rem;color:var(--muted)">' + esc(Number(c.executed || 0) + Number(c.prevented || 0)) + ' of ' + esc(scheduled) + ' scheduled steps produced a security result</span>' +
    '</div>' + rows +
    '<div style="font-size:0.66rem;color:var(--muted);margin-top:6px">Steps that did not run are counted against coverage, not as passes.</div>' +
    '</div>';
}
