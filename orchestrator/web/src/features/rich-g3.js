// Pure helpers for the rich layouts of the Findings / Remediation / IOC / Reports / SLA /
// Compliance / Verification pages. Everything here derives numbers from rows a page loader already
// fetched; nothing invents data. No DOM access, so it is unit-testable.
import { CHART_COLORS } from '../core/charts.js';

export var SEV_ORDER = ['Critical', 'High', 'Medium', 'Low'];
var SEV_COLOR = { Critical: CHART_COLORS.bad, High: '#e0873a', Medium: CHART_COLORS.warn, Low: CHART_COLORS.info };

// normSev maps any casing of a severity name to the canonical one ('' when unknown).
export function normSev(s) {
  var t = String(s == null ? '' : s).toLowerCase();
  for (var i = 0; i < SEV_ORDER.length; i++) if (SEV_ORDER[i].toLowerCase() === t) return SEV_ORDER[i];
  return '';
}
export function sevColor(s) { return SEV_COLOR[normSev(s)] || CHART_COLORS.muted; }
export function sevTone(s) {
  var n = normSev(s);
  return n === 'Critical' ? 'bad' : n === 'High' ? 'warn' : n === 'Medium' ? 'warn' : n === 'Low' ? 'info' : 'muted';
}

// countBy -> [[key, count]] sorted by count desc then key; empty/missing keys are labelled `blank`.
export function countBy(list, keyFn, blank) {
  var m = {};
  (list || []).forEach(function(r) {
    var k = keyFn(r);
    k = (k == null || k === '') ? (blank || 'Unknown') : String(k);
    m[k] = (m[k] || 0) + 1;
  });
  return Object.keys(m).map(function(k) { return [k, m[k]]; }).sort(function(a, b) { return b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0); });
}

// sevSegments -> donut segments in fixed severity order, zero buckets dropped.
export function sevSegments(list, sevFn) {
  var c = {};
  (list || []).forEach(function(r) { var s = normSev(sevFn(r)); if (s) c[s] = (c[s] || 0) + 1; });
  return SEV_ORDER.filter(function(s) { return c[s]; }).map(function(s) { return { label: s, value: c[s], color: SEV_COLOR[s] }; });
}

// hbarRows -> rows for kit.hbars scaled to the largest value: [label, percent, tone, valueText]
export function hbarRows(pairs, tone, n) {
  var top = (pairs || []).slice(0, n || 5);
  var max = 0;
  top.forEach(function(p) { if (p[1] > max) max = p[1]; });
  return top.map(function(p) { return [p[0], max ? p[1] / max * 100 : 0, tone || 'accent', String(p[1])]; });
}

// rateTone: compliance-style percentage -> tone
export function rateTone(rate) { return rate >= 90 ? 'ok' : rate >= 75 ? 'warn' : 'bad'; }
export function pctText(n, d) { return d > 0 ? Math.round(n / d * 100) + '%' : '—'; }

// matchesQuery: case-insensitive substring over several fields
export function matchesQuery(q, fields) {
  var s = String(q == null ? '' : q).trim().toLowerCase();
  if (!s) return true;
  return (fields || []).some(function(f) { return String(f == null ? '' : f).toLowerCase().indexOf(s) !== -1; });
}
