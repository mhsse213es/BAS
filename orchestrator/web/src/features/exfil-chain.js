// Collection → staging → exfiltration chain panel for a finished run. Reads the
// server's /exfil-chain report and shows it as labels only: every string from the
// server goes through x(). "Linked" means the stages' own output shares a run tag,
// not that a SIEM correlated them, and the panel says so.
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';

export const EXFIL_SCENARIO_IDS = [
  'collection-staging-exfil',
  'collection-network-share-exfil',
  'collection-database-export-exfil',
  'collection-pii-financial-exfil',
  'collection-encrypted-archive-exfil',
  'collection-cloud-storage-exfil',
  'collection-low-and-slow-exfil',
  'collection-removable-media-exfil',
  'collection-email-mailbox-exfil',
  'collection-masquerade-cleanup-exfil',
  'collection-sensitive-discovery',
  'collection-source-code-exfil',
  'collection-large-volume-transfer',
  'collection-channel-variants-exfil',
  'collection-archive-split-exfil',
  'collection-browser-cloud-email-discovery',
  'collection-hidden-staging-manifest-exfil',
  'collection-multidir-automated-exfil',
];

export function isExfilChainRun(scenarioId) {
  return EXFIL_SCENARIO_IDS.indexOf(scenarioId) !== -1;
}

const PHASE_LABEL = {
  discovery: 'Discovery', collection: 'Collection', staging: 'Staging',
  archive: 'Archive', transfer: 'Transfer', other: 'Other',
};

const RESULT_TONE = { pass: 'ok', fail: 'bad', skip: 'muted', skipped: 'muted', error: 'warn' };

// exfilChainModel turns the server report into display fields.
export function exfilChainModel(report) {
  const r = report || {};
  const linked = !!r.linked;
  const missing = Array.isArray(r.missing) ? r.missing : [];
  const tone = linked && missing.length === 0 && !(r.findings || []).length ? 'ok'
    : linked ? 'warn' : 'bad';
  const stages = (r.stages || []).map(s => {
    const res = String(s.result || '').toLowerCase();
    return {
      order: s.order,
      phase: PHASE_LABEL[s.phase] || s.phase || 'Other',
      techniqueId: s.techniqueId || '',
      stepName: s.stepName || '',
      result: s.result || '',
      tone: RESULT_TONE[res] || 'muted',
    };
  });
  return {
    summary: r.summary || '',
    tone,
    linked,
    stages,
    missing: missing.map(p => PHASE_LABEL[p] || p),
    findings: Array.isArray(r.findings) ? r.findings : [],
  };
}

// exfilChainHTML builds the panel markup. Every server string goes through x().
export function exfilChainHTML(m) {
  const tone = c => 'var(--' + ({ ok: 'success', bad: 'danger', warn: 'warning', muted: 'muted' }[c] || 'muted') + ')';
  const stageRows = m.stages.map(s =>
    '<tr><td>' + s.order + '</td><td>' + x(s.phase) + '</td><td><code>' + x(s.techniqueId) + '</code></td>' +
    '<td>' + x(s.stepName) + '</td>' +
    '<td style="color:' + tone(s.tone) + ';font-weight:600">' + x(s.result) + '</td></tr>'
  ).join('');
  const missing = m.missing.length
    ? '<div style="margin-top:6px"><strong>Missing phases:</strong> ' + m.missing.map(x).join(', ') + '</div>'
    : '';
  const findings = m.findings.length
    ? '<ul style="margin:6px 0 0 18px">' + m.findings.map(f => '<li>' + x(f) + '</li>').join('') + '</ul>'
    : '';
  return '<div class="exfil-chain" style="margin:10px 0;padding:10px;border:1px solid var(--border,#ccc);border-radius:6px">' +
    '<div><strong>Collection to exfiltration chain:</strong> ' +
    '<span style="color:' + tone(m.tone) + ';font-weight:700">' + x(m.summary) + '</span></div>' +
    '<div class="u-muted" style="margin-top:2px">Linked means the stages print the same run tag. It does not show that the SIEM correlated them.</div>' +
    (m.stages.length
      ? '<table style="margin-top:8px;width:100%"><thead><tr><th>#</th><th>Phase</th><th>Technique</th><th>Step</th><th>Result</th></tr></thead><tbody>' + stageRows + '</tbody></table>'
      : '<div class="u-muted" style="margin-top:6px">No stage results for this run.</div>') +
    missing + findings +
    '</div>';
}

export function renderExfilChainPanel(host, runId) {
  host.dataset.runId = runId;
  host.innerHTML = '<div class="u-muted">Loading chain report…</div>';
  apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/exfil-chain').then(function(report) {
    if (host.dataset.runId !== runId) return;
    host.innerHTML = exfilChainHTML(exfilChainModel(report));
  }).catch(function() {
    if (host.dataset.runId !== runId) return;
    host.innerHTML = '<div class="u-muted">Chain report unavailable.</div>';
  });
}
