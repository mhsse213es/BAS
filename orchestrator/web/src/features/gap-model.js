// Pure rules for the Detection gaps panel on the Detection Verification page: how the five statuses are ordered and
// toned, how a rule or query is described honestly, and the URLs the panel calls. No DOM and no network, so it is
// unit-tested on its own.

export var HELP = 'A detection gap means the technique ran to completion and a reviewed verification found no alert. ' +
  'A technique nobody verified is Unknown, not a gap. A rule being available is not proof it would detect the attack: ' +
  'the rules are not validated against your telemetry.';

// The order the server returns and the page shows: what needs action first.
var STATUSES = ['Detection gap', 'Unknown', 'Execution error', 'Skipped', 'Detected'];

var TONE = { 'Detection gap': 'bad', Detected: 'ok', Unknown: 'warn', 'Execution error': 'muted', Skipped: 'muted' };

export function statusTone(s) { return TONE[s] || 'muted'; }

export function summaryTiles(summary) {
  var s = summary || {};
  return STATUSES.map(function(st) { return { status: st, count: s[st] || 0, tone: statusTone(st) }; });
}

export function availabilityTone(label) {
  return label === 'Rule available' ? 'info' : 'warn';
}

var BACKEND_LABELS = {
  microsoft_sentinel: 'Microsoft Sentinel',
  microsoft_defender: 'Microsoft Defender XDR',
  splunk: 'Splunk',
  qradar: 'IBM QRadar',
  elastic: 'Elastic',
  crowdstrike: 'CrowdStrike LogScale',
};
export var BACKENDS = Object.keys(BACKEND_LABELS);

export function backendLabel(key) { return BACKEND_LABELS[key] || key; }

// What to tell the analyst beside a query. A field-mapped query only matches when its data source is collected; a
// generic one uses Sigma's own field names and has to be adapted: it is never presented as ready to paste.
export function verificationNote(v) {
  if (v === 'validated') return 'Validated: it matched a sample event and did not match a negative one.';
  if (v === 'assumed') return 'The field names are our assumption; test this query on your own data before relying on it.';
  return "The field names come from the product's documentation; this query has not yet been run against real events.";
}

export function backendNote(b) {
  if (b && b.mapping === 'pipeline' && b.dataSource) {
    return 'Field-mapped. This query only matches if you collect: ' + b.dataSource + '. ' + verificationNote(b.verification);
  }
  return 'Generic query with Sigma field names: adapt it to your own schema before use.';
}

export function matchNote(match) {
  return match === 'parent' ? 'Tagged with the parent technique only, so broader than this technique.' : '';
}

export function severityTone(sev) {
  var s = String(sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'bad';
  if (s === 'medium') return 'warn';
  return 'muted';
}

export function canExport(summary) { return !!(summary && summary['Detection gap'] > 0); }

function base(runId) { return '/api/scenarios/runs/' + encodeURIComponent(runId) + '/detection-gaps'; }

export function gapsUrl(runId, backend) {
  return base(runId) + (backend ? '?backend=' + encodeURIComponent(backend) : '');
}

export function exportZipUrl(runId, backend) {
  return base(runId) + '/export' + (backend ? '?backend=' + encodeURIComponent(backend) : '');
}

// ── Deployed rules and re-tests ──────────────────────────────────────────────
// A customer records that they deployed a recommended rule, re-runs the scenario, and the server reports whether the
// gap is closed from the re-test run's own reviewed verifications. Recording a deployment proves nothing by itself.

export function deploymentsUrl(runId) { return base(runId) + '/deployments'; }

export function retestLinkUrl(runId, deploymentId) {
  return base(runId) + '/deployments/' + encodeURIComponent(deploymentId) + '/retest';
}

var DEP_TONE = {
  'Closed on re-test': 'ok',
  'Still a gap': 'bad',
  Deployed: 'info',
  'Re-test running': 'info',
  'Re-test awaiting verification': 'warn',
  'Technique not re-tested': 'warn',
};

export function deploymentTone(status) { return DEP_TONE[status] || 'muted'; }

// Another run can change the answer only when the last one did not settle it.
export function canRetest(status) {
  return status === 'Deployed' || status === 'Still a gap' || status === 'Technique not re-tested';
}

export function deploymentsFor(deployments, techniqueId) {
  return (deployments || []).filter(function(d) { return d.techniqueId === techniqueId; });
}

// What starting the re-test needs: the body for POST /api/scenarios/{id}/run (same scenario, agent and mode as the run
// that found the gap) and the confirmations the console asks before any live run. Null when the run is unknown.
export function retestPlan(retest) {
  if (!retest || !retest.scenarioId || !retest.agentId) return null;
  var mode = retest.mode === 'telemetry' || retest.mode === 'lab' ? retest.mode : 'posture';
  var confirms = [];
  if (mode === 'telemetry') {
    confirms.push('TELEMETRY mode runs real, identity-safe techniques and WILL generate EDR/SIEM alerts.\n\nProceed only on an approved, monitored target. Continue?');
  } else if (mode === 'lab') {
    confirms.push('LAB mode runs FULL-FIDELITY techniques (LSASS dump, allowlisted spray) and will trigger EDR.\n\nISOLATED AD RANGE ONLY — never production. Continue?');
    confirms.push('Second confirmation required for LAB mode.\n\nConfirm the target is an isolated lab/range with a snapshot?');
  }
  return {
    scenarioId: retest.scenarioId,
    confirms: confirms,
    body: {
      agentId: retest.agentId, mode: mode, confirmLive: mode !== 'posture', confirmLab: mode === 'lab',
      reason: 'Re-test after deploying a recommended detection rule',
    },
  };
}
