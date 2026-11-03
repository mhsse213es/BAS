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
export function backendNote(b) {
  if (b && b.mapping === 'pipeline' && b.dataSource) {
    return 'Field-mapped. This query only matches if you collect: ' + b.dataSource + '.';
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
