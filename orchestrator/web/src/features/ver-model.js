// Pure helpers for the redesigned Verification page: banner numbers, the "result by control" bars, the
// outcome donut, the filtered / sorted table rows and the CSV. No DOM, no network.
// Everything comes from GET /api/scenarios/runs/{id}/verifications (one item per off-host expectation:
// status, techniqueId, provider / providerDisplay, domain, confidence, verifiedBy, evidenceCount,
// workflowState, expectationId, verificationId). The API has no scenario name, observed text, time to
// detect or check time per item, so none is shown.
import { countBy, matchesQuery } from './rich-g3.js';

function n(v) { return Number(v) || 0; }
function cap(s) { s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); }

export var PLAIN = { Detected: 'Detected', NotDetected: 'Silent', NotApplicable: 'N/A', NeedsReview: 'Needs review' };
export var TONE = { Detected: 'ok', NotDetected: 'bad', NotApplicable: 'muted', Approved: 'ok', Rejected: 'bad', NeedsReview: 'warn' };

export function statusText(s) { return PLAIN[s] || String(s || 'Pending'); }
export function isOutstanding(i) { return !!i && (i.status === 'Pending' || i.status === 'NeedsReview' || !i.status); }

function count(items, st) { return items.filter(function(i) { return i.status === st; }).length; }

// heroStats: the banner. With no run loaded every value is null (shown as an em dash).
export function heroStats(items) {
  if (!Array.isArray(items) || !items.length) return { checks: null, detected: null, outstanding: null, silent: null };
  return {
    checks: items.length,
    detected: Math.round(count(items, 'Detected') / items.length * 100) + '%',
    outstanding: items.filter(isOutstanding).length,
    silent: count(items, 'NotDetected'),
  };
}

// domainOptions: the domains present in the loaded items, in alphabetical order.
export function domainOptions(items) {
  return countBy(items, function(i) { return i.domain; }, 'Unknown').map(function(p) { return p[0]; }).sort();
}

// statusOptions: the statuses present, as [value, label].
export function statusOptions(items) {
  return countBy(items, function(i) { return i.status; }, 'Pending').map(function(p) { return [p[0], statusText(p[0])]; });
}

// controlRows: "Result by control" bars: per domain, the share of its expectations attested Detected.
export function controlRows(items) {
  var by = {};
  (items || []).forEach(function(i) {
    var d = String(i.domain || 'Unknown');
    var o = by[d] || (by[d] = { total: 0, det: 0 });
    o.total++;
    if (i.status === 'Detected') o.det++;
  });
  return Object.keys(by).sort().map(function(d) {
    var p = Math.round(by[d].det / by[d].total * 100);
    return { label: cap(d), pct: p, tone: p >= 80 ? 'ok' : p >= 50 ? 'warn' : 'bad', text: p + '%' };
  });
}

// outcomeSegments: donut slices by status (zero slices dropped), in a fixed order.
export var OUTCOME_ORDER = ['Detected', 'NotDetected', 'NeedsReview', 'Pending', 'NotApplicable'];
export function outcomeSegments(items) {
  var c = {};
  (items || []).forEach(function(i) { var k = i.status || 'Pending'; c[k] = (c[k] || 0) + 1; });
  var keys = OUTCOME_ORDER.filter(function(k) { return c[k]; }).concat(Object.keys(c).filter(function(k) { return OUTCOME_ORDER.indexOf(k) < 0; }));
  return keys.map(function(k) { return { key: k, label: statusText(k), value: c[k] }; });
}

// ── Filtering ────────────────────────────────────────────────────────────────
export function filterItems(items, f) {
  f = f || {};
  return (items || []).filter(function(i) {
    if (f.status && (i.status || 'Pending') !== f.status) return false;
    if (f.domain && String(i.domain || 'Unknown') !== f.domain) return false;
    return matchesQuery(f.q, [i.techniqueId, i.providerDisplay, i.provider, i.domain, i.confidence, i.verifiedBy, statusText(i.status)]);
  });
}

export function hasFilter(f) { return !!(f && (f.q || f.status || f.domain)); }

// ── Table ────────────────────────────────────────────────────────────────────
export var COLUMNS = ['Status', 'Technique', 'Expected control', 'Domain', 'Confidence', 'Analyst', 'Evidence'];

export function cellText(i, col) {
  switch (col) {
    case 0: return statusText(i.status);
    case 1: return String(i.techniqueId || '');
    case 2: return String(i.providerDisplay || i.provider || '');
    case 3: return String(i.domain || '');
    case 4: return String(i.confidence || '');
    case 5: return String(i.verifiedBy || '');
    default: return n(i.evidenceCount) ? n(i.evidenceCount) + (n(i.evidenceCount) === 1 ? ' file' : ' files') : '';
  }
}

// tableFilter: the table's own "Filter rows" box (any visible cell text).
export function tableFilter(items, q) {
  var s = String(q || '').trim().toLowerCase();
  if (!s) return items.slice();
  return items.filter(function(i) {
    return COLUMNS.map(function(c, k) { return cellText(i, k); }).join(' ').toLowerCase().indexOf(s) !== -1;
  });
}

function sortKey(i, col) {
  if (col === 6) return n(i.evidenceCount);
  var t = cellText(i, col);
  return t === '' ? null : t;
}

// sortItems: stable; empty values always sort last.
export function sortItems(items, col, dir) {
  if (col < 0) return items.slice();
  var d = dir < 0 ? -1 : 1;
  return items.map(function(r, k) { return { r: r, k: k }; }).sort(function(a, b) {
    var u = sortKey(a.r, col), v = sortKey(b.r, col);
    if (u == null || v == null) return u == null && v == null ? a.k - b.k : u == null ? 1 : -1;
    var c = typeof u === 'number' ? u - v : String(u).localeCompare(String(v), undefined, { numeric: true });
    return c * d || a.k - b.k;
  }).map(function(o) { return o.r; });
}

// summaryText: the card sub-heading.
export function summaryText(total, shown) {
  return shown === total ? total + (total === 1 ? ' expectation' : ' expectations') : shown + ' of ' + total + ' expectations';
}

// drawerRows: the key / value block at the top of the detail drawer.
export function drawerRows(i) {
  i = i || {};
  var ev = n(i.evidenceCount);
  return [
    ['Expected control', String(i.providerDisplay || i.provider || '—')],
    ['Technique', String(i.techniqueId || '—')],
    ['Domain', cap(i.domain) || '—'],
    ['Confidence', cap(i.confidence) || '—'],
    ['Analyst', String(i.verifiedBy || '—')],
    ['Evidence', ev ? ev + (ev === 1 ? ' file' : ' files') : 'None attached'],
  ];
}

export { pageCount, rangeText, csvText } from './runs-model.js';
