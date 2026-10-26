// Pure helpers for the redesigned AD Coverage page: banner numbers, the six summary tiles, the
// per-axis labels/tones of each capability row and the filter logic. No DOM, no network: everything
// comes from the /api/ad/coverage report. Nothing is classified or promoted here; an unexpected
// API value is shown verbatim with a neutral tone.

function n(v) { var k = Number(v); return isFinite(k) ? k : 0; }

// axis maps: value -> [label, tone]
var CONTENT = {
  'scenario-composable': ['Scenario-composable', 'ok'],
  'reusable-unmapped': ['Reusable (unmapped)', 'info'],
  'model-only': ['Model-only', 'warn'],
  'missing-executable-content': ['Missing content', 'bad'],
};
var EXEC = {
  'not_executed': ['Not executed', 'muted'],
  'execution_attempted': ['Attempted', 'warn'],
  'execution_completed': ['Completed', 'ok'],
  'postcondition_verified': ['Postcondition verified', 'ok'],
};
var DET = {
  'not_validated': ['Not validated', 'muted'],
  'simulated_evidence_only': ['Simulated only', 'warn'],
  'telemetry_observed': ['Telemetry observed', 'ok'],
};
var RISK = {
  'non_destructive': ['Non-destructive', 'ok'],
  'potentially_destructive': ['Potentially destructive', 'bad'],
  'destructive': ['Destructive', 'bad'],
};

function axis(map, v) {
  var hit = map[v];
  return hit ? { label: hit[0], tone: hit[1] } : { label: v || 'unknown', tone: 'muted' };
}
export function contentAxis(v) { return axis(CONTENT, v); }
export function execAxis(v) { return axis(EXEC, v || 'not_executed'); }
export function detAxis(v) { return axis(DET, v || 'not_validated'); }
export function riskAxis(v) { return axis(RISK, v); }
export function compositionAxis(c) {
  return c && c.scenarioComposed ? { label: 'Composed', tone: 'ok' } : { label: 'Not composed', tone: 'muted' };
}

// heroStats: the four banner numbers. A missing figure gives null (shown as an em dash).
export function heroStats(sum) {
  sum = sum || {};
  var v = function(k) { return sum[k] == null ? null : n(sum[k]); };
  return { capabilities: v('total'), composed: v('scenarioComposed'), executed: n(sum.executed), detected: n(sum.detectionValidated) };
}

// summaryTiles: the six tiles in the order the design shows them.
export function summaryTiles(sum, content) {
  sum = sum || {}; content = content || {};
  var opt = function(v) { return v == null ? '—' : v; };
  return [
    { label: 'Capabilities', value: opt(sum.total), icon: 'shield', tone: 'accent' },
    { label: 'Modeled', value: opt(sum.modeled), icon: 'layers', tone: 'info' },
    { label: 'Scenario-composed', value: opt(sum.scenarioComposed), icon: 'path', tone: 'ok' },
    { label: 'Executed vs real AD', value: n(sum.executed), icon: 'play', tone: 'bad' },
    { label: 'Detection-validated', value: n(sum.detectionValidated), icon: 'eye', tone: 'bad' },
    { label: 'Reusable content', value: opt(content.reusableUnmapped), icon: 'file', tone: 'warn' },
  ];
}

// distribution: how many capabilities fall in each value of one field.
export function distribution(caps, field, dflt) {
  var out = {};
  (caps || []).forEach(function(c) {
    if (!c) return;
    var v = c[field] || dflt || 'unknown';
    out[v] = (out[v] || 0) + 1;
  });
  return out;
}

// familyOptions: [value,label] pairs for the family chips, sorted, with the "all" entry first.
export function familyOptions(caps) {
  var set = {};
  (caps || []).forEach(function(c) { if (c && c.family) set[c.family] = true; });
  return [['all', 'All families']].concat(Object.keys(set).sort().map(function(f) { return [f, f]; }));
}

export var CONTENT_OPTIONS = [['all', 'All content'], ['scenario-composable', 'Composable'], ['reusable-unmapped', 'Reusable'], ['model-only', 'Model-only'], ['missing-executable-content', 'Missing']];
export var EXEC_OPTIONS = [['all', 'All execution'], ['not_executed', 'Not executed'], ['execution_completed', 'Executed'], ['postcondition_verified', 'Verified']];

export function applyFilter(caps, f) {
  f = f || {};
  return (caps || []).filter(function(c) {
    if (!c) return false;
    if (f.family && f.family !== 'all' && c.family !== f.family) return false;
    if (f.content && f.content !== 'all' && c.contentAvailability !== f.content) return false;
    if (f.exec && f.exec !== 'all' && (c.executionValidation || 'not_executed') !== f.exec) return false;
    return true;
  });
}
