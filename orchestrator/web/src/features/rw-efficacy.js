import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';

// ── Ransomware detection and response efficacy panel ───────────────────────
//
// Shows the server's run-level efficacy statement (GET
// /api/scenarios/runs/{runId}/ransomware-efficacy, internal/rwefficacy) on the
// finished-run results view. The status and the overall statement come from
// the server. This module only maps them to labels, colours and text, and it
// never infers a verdict the server did not give.

// Scenarios whose runs carry ransomware capability evidence. The dashboard
// readiness card (ransomware.js) reads the same list.
export const RW_SCENARIO_IDS = [
  'akira-kill-chain', 'blackcat-kill-chain', 'clop-kill-chain', 'lockbit-kill-chain',
  'play-kill-chain', 'ransomhub-kill-chain', 'ransomware-drill', 'em-07-ransomware-readiness',
  'linux-ransomware-drill', 'black-basta-kill-chain', 'medusa-kill-chain', 'rhysida-kill-chain',
  'ransomware-backup-recovery-assurance', 'akira-double-extortion-assessment', 'ransomware-lateral-containment-assessment', 'akira-esxi-assessment'
];

export function isRansomwareRun(scenarioId) {
  return RW_SCENARIO_IDS.indexOf(scenarioId) !== -1;
}

const OVERALL = {
  gaps_found: { label: 'Gaps found', tone: 'bad', summary: 'A control failed to stop or detect part of this behavior.' },
  unproven: { label: 'Unproven', tone: 'warn', summary: 'Nothing failed, but at least one required capability is not proven.' },
  evidenced: { label: 'Evidenced', tone: 'ok', summary: 'Detection, containment and recovery are proven, with no gaps.' }
};

const STATUS = {
  proven: { label: 'Proven', tone: 'ok' },
  partial: { label: 'Partly proven', tone: 'warn' },
  unproven: { label: 'Unproven', tone: 'warn' },
  gap: { label: 'Gap', tone: 'bad' },
  not_applicable: { label: 'Not applicable', tone: 'muted' }
};

const VERDICT_TONE = { PASS: 'ok', FAIL: 'bad', ERROR: 'warn', SKIPPED: 'muted' };

const DIMENSION_LABEL = {
  prevention: 'Prevention',
  detection: 'Detection',
  containment: 'Containment',
  recovery: 'Recovery',
  data_protection: 'Data protection'
};

// The three dimensions the overall statement requires.
const REQUIRED = ['detection', 'containment', 'recovery'];
// Display order: required first, then the two informational dimensions.
const ORDER = ['detection', 'containment', 'recovery', 'prevention', 'data_protection'];

// rwEfficacyModel maps the server report to display data. Pure: no DOM, no fetch.
export function rwEfficacyModel(report) {
  const overall = OVERALL[report.overall] || { label: String(report.overall || 'Unknown'), tone: 'muted', summary: '' };
  const dims = report.dimensions || {};

  const dimensions = ORDER.filter(k => dims[k]).map(k => {
    const d = dims[k];
    const st = STATUS[d.status] || { label: String(d.status || 'Unknown'), tone: 'muted' };
    return {
      key: k,
      label: DIMENSION_LABEL[k] || k,
      status: st.label,
      tone: st.tone,
      counts: { pass: d.pass || 0, fail: d.fail || 0, error: d.error || 0, skipped: d.skipped || 0, notApplicable: d.notApplicable || 0 }
    };
  });

  // Only states the server reported. "Not proven" lists required capabilities
  // with no full proof; a failed capability is a gap, shown in its own row.
  const notProven = [];
  for (const k of REQUIRED) {
    const d = dims[k];
    if (!d) continue;
    if (d.status === 'unproven') notProven.push(DIMENSION_LABEL[k] + ': no evidence was collected.');
    else if (d.status === 'partial') notProven.push(DIMENSION_LABEL[k] + ': some attempts were skipped or errored.');
  }

  const attempts = (report.attempts || []).map(a => ({
    techniqueId: a.techniqueId || '',
    action: a.action || '',
    cells: Object.keys(a.verdicts || {}).sort().map(cap => {
      const v = a.verdicts[cap];
      return { capability: DIMENSION_LABEL[cap] || cap, verdict: v, tone: VERDICT_TONE[v] || 'muted' };
    })
  }));

  // Endpoint-only steps: the step's own check reported this, and no capability
  // observer graded the technique. Shown apart from the statement.
  const endpointOnly = (report.endpointOnly || []).map(s => {
    const r = String(s.result || '').toLowerCase();
    const tone = r === 'pass' || r === 'blocked' ? 'ok' : r === 'fail' ? 'bad' : r === 'error' ? 'warn' : 'muted';
    return { techniqueId: s.techniqueId || '', stepName: s.stepName || '', result: s.result || '', tone };
  });

  return { label: overall.label, tone: overall.tone, summary: overall.summary, dimensions, notProven, attempts, endpointOnly };
}

// rwEfficacyHTML builds the panel markup. Every server string goes through x().
export function rwEfficacyHTML(m) {
  const tone = c => 'var(--' + ({ ok: 'success', bad: 'danger', warn: 'warning', muted: 'muted' }[c] || 'muted') + ')';
  const dimRows = m.dimensions.map(d =>
    '<tr><td>' + x(d.label) + '</td>' +
    '<td style="color:' + tone(d.tone) + ';font-weight:600">' + x(d.status) + '</td>' +
    '<td>' + d.counts.pass + ' pass &middot; ' + d.counts.fail + ' fail &middot; ' + d.counts.error + ' error &middot; ' + d.counts.skipped + ' skipped</td></tr>'
  ).join('');
  const notProven = m.notProven.length
    ? '<div style="margin-top:6px"><strong>Not proven:</strong> ' + m.notProven.map(x).join(' ') + '</div>'
    : '';
  const attemptRows = m.attempts.map(a =>
    '<tr><td><code>' + x(a.techniqueId) + '</code></td><td>' + x(a.action) + '</td><td>' +
    a.cells.map(c => x(c.capability) + ': <span style="color:' + tone(c.tone) + '">' + x(c.verdict) + '</span>').join(' &middot; ') +
    '</td></tr>'
  ).join('');
  const endpointRows = m.endpointOnly.map(s =>
    '<tr><td><code>' + x(s.techniqueId) + '</code></td><td>' + x(s.stepName) + '</td>' +
    '<td style="color:' + tone(s.tone) + ';font-weight:600">' + x(s.result) + '</td></tr>'
  ).join('');
  const endpointSection = m.endpointOnly.length
    ? '<details style="margin-top:8px"><summary>Endpoint result only, no capability evidence (' + m.endpointOnly.length + ')</summary>' +
      '<div class="u-muted" style="margin-top:4px">These are what each step\'s own check reported. Nothing graded them as prevention, detection or containment, so they do not change the statement above.</div>' +
      '<table style="margin-top:6px;width:100%"><tbody>' + endpointRows + '</tbody></table></details>'
    : '';
  return '<div class="rw-efficacy" style="margin:10px 0;padding:10px;border:1px solid var(--border,#ccc);border-radius:6px">' +
    '<div><strong>Detection and response efficacy:</strong> ' +
    '<span style="color:' + tone(m.tone) + ';font-weight:700">' + x(m.label) + '</span></div>' +
    '<div class="u-muted" style="margin-top:2px">' + x(m.summary) + '</div>' +
    '<table style="margin-top:8px;width:100%"><tbody>' + dimRows + '</tbody></table>' +
    notProven +
    (m.attempts.length
      ? '<details style="margin-top:8px"><summary>Attempts (' + m.attempts.length + ')</summary>' +
        '<table style="margin-top:6px;width:100%"><tbody>' + attemptRows + '</tbody></table></details>'
      : '') +
    endpointSection +
    '</div>';
}

// renderRwEfficacyPanel fetches the statement and fills host. A response for a
// run the host no longer shows is dropped.
export function renderRwEfficacyPanel(host, runId) {
  host.dataset.runId = runId;
  host.innerHTML = '<div class="u-muted">Loading efficacy statement…</div>';
  apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/ransomware-efficacy').then(function(report) {
    if (host.dataset.runId !== runId) return;
    host.innerHTML = rwEfficacyHTML(rwEfficacyModel(report));
  }).catch(function() {
    if (host.dataset.runId !== runId) return;
    host.innerHTML = '<div class="u-muted">Efficacy statement unavailable.</div>';
  });
}
