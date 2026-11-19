// Pure helpers for the redesigned IOC Registry page: banner numbers, the four ranking tiles, donut and
// bar rows, the sightings bar and the add/import validation. No DOM, no network. Everything comes from
// the responses the page already loads: GET /api/iocs (rows) and GET /api/analytics/iocs (rankings).

function n(v) { var k = Number(v); return isFinite(k) ? k : 0; }

export var TYPE_LABEL = {
  file_hash: 'File hash', domain: 'Domain', url: 'URL', ip: 'IP', registry_key: 'Registry key',
  mutex: 'Mutex', service: 'Service', process: 'Process', command_line: 'Command line',
  ja3: 'JA3', user_agent: 'User agent', email: 'Email', dns_record: 'DNS record', certificate: 'Certificate',
};
export var TYPE_IDS = Object.keys(TYPE_LABEL);

export var SOURCE_LABEL = { detection_alert: 'Detection alert', scenario: 'Scenario', variant: 'Variant', manual: 'Manual', threat_feed: 'Threat feed' };

export function typeLabel(t) { return TYPE_LABEL[t] || t || 'Unknown'; }
export function sourceLabel(s) { return SOURCE_LABEL[s] || s || 'Unknown'; }

// heroStats: the four banner numbers from the rows in view (null until they are loaded).
export function heroStats(rows) {
  if (!Array.isArray(rows)) return { total: null, detected: null, missed: null, observed: null };
  var by = function(st) { return rows.filter(function(r) { return r.status === st; }).length; };
  return { total: rows.length, detected: by('detected'), missed: by('missed'), observed: by('observed') };
}

// statusTone: pill tone for an IOC lifecycle status.
export var STATUS_TONE = { detected: 'ok', missed: 'bad', expired: 'muted', archived: 'muted', draft: 'info', generated: 'info', assigned: 'info', executed: 'accent', observed: 'accent' };
export function statusTone(s) { return STATUS_TONE[s] || 'muted'; }

// tally -> [[label, count]] sorted by count desc then label.
export function tally(rows, keyFn, weightFn) {
  var m = {};
  (rows || []).forEach(function(r) {
    var k = keyFn(r);
    k = (k == null || k === '') ? 'Unknown' : String(k);
    m[k] = (m[k] || 0) + (weightFn ? n(weightFn(r)) : 1);
  });
  return Object.keys(m).map(function(k) { return [k, m[k]]; })
    .sort(function(a, b) { return b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0); });
}

// donutSegments: the largest `max` groups, the remainder folded into "Other". Zero groups are dropped.
export function donutSegments(pairs, palette, max, otherColor) {
  var list = (pairs || []).filter(function(p) { return p[1] > 0; });
  var cap = max || 7;
  var segs = list.slice(0, cap).map(function(p, k) { return { label: p[0], value: p[1], color: palette[k % palette.length] }; });
  var rest = list.slice(cap).reduce(function(a, p) { return a + p[1]; }, 0);
  if (rest) segs.push({ label: 'Other', value: rest, color: otherColor });
  return segs;
}

export function typeCounts(rows) { return tally(rows, function(r) { return typeLabel(r.type); }); }
export function sightingCountsByType(rows) { return tally(rows, function(r) { return typeLabel(r.type); }, function(r) { return r.sightingCount; }); }

// sourceRows: top sources as hbars rows [label, percent, tone, ' · count'], scaled to the largest.
export function sourceRows(rows, limit) {
  var top = tally(rows, function(r) { return sourceLabel(r.source); }).slice(0, limit || 6);
  var max = top.reduce(function(a, p) { return Math.max(a, p[1]); }, 0);
  return top.map(function(p) { return [p[0], max ? p[1] / max * 100 : 0, 'info', ' · ' + p[1]]; });
}

// typeChips: "All types" plus one chip per indicator type, each with its count in the current view.
export function typeChips(rows, active) {
  var counts = {};
  (rows || []).forEach(function(r) { counts[r.type] = (counts[r.type] || 0) + 1; });
  var out = [{ id: '', label: 'All types', on: !active }];
  TYPE_IDS.forEach(function(t) { out.push({ id: t, label: TYPE_LABEL[t], on: active === t, count: counts[t] || 0 }); });
  return out;
}

// sightingPct: a row's sightings relative to the busiest row in view.
export function sightingPct(row, rows) {
  var max = (rows || []).reduce(function(a, r) { return Math.max(a, n(r.sightingCount)); }, 0);
  return max ? Math.round(n(row.sightingCount) / max * 100) : 0;
}

// analyticsTiles: the four ranking tiles from the analytics response. An empty ranking says so.
export function analyticsTiles(result) {
  result = result || {};
  var defs = [
    ['Most detected', result.mostDetected, 'eye', 'bad', 'detections', 'needs detection results'],
    ['Highest bypass rate', result.highestBypassRate, 'alert', 'muted', 'bypasses', 'needs detection results'],
    ['Frequently reused', result.frequentlyReused, 'refresh', 'warn', 'sightings', 'no sightings yet'],
    ['Longest surviving', result.longestSurviving, 'clock', 'violet', 'sightings', 'no sightings yet'],
  ];
  return defs.map(function(d) {
    var top = Array.isArray(d[1]) && d[1].length ? d[1][0] : null;
    if (!top) return { label: d[0], value: 'No data yet', sub: d[5], icon: d[2], tone: 'muted' };
    var c = n(top.sightingCount);
    return { label: d[0], value: String(top.value), sub: c + ' ' + (c === 1 ? d[4].replace(/s$/, '') : d[4]), icon: d[2], tone: d[3] };
  });
}

// parseEntry: validates the Add IOC form. Returns {entry} or {error}.
export function parseEntry(type, value) {
  var v = String(value == null ? '' : value).trim();
  if (!v) return { error: 'Enter an indicator value.' };
  if (!TYPE_LABEL[type]) return { error: 'Choose an indicator type.' };
  return { entry: { type: type, value: v } };
}

// drawerFacts: the label/value pairs for the detail drawer (dates are passed in already formatted).
export function drawerFacts(row, fmt) {
  var d = function(t) { return t ? fmt(t) : '—'; };
  var out = [
    ['Source', sourceLabel(row.source) || '—'],
    ['Origin', row.origin || '—'],
    ['Status', row.status || '—'],
    ['First seen', d(row.firstSeen)],
    ['Last seen', d(row.lastSeen)],
    ['Sightings', String(n(row.sightingCount))],
  ];
  if (row.suppressed) out.push(['Suppressed', row.suppressionReason || 'yes']);
  return out;
}
