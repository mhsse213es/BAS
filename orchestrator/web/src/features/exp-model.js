// Pure helpers for the redesigned Exposure Explorer: hero stats, the per-asset table (columns, filter,
// sort, CSV), the two host charts and the detail drawer pieces. No DOM, no network.
// Everything comes from what the page already loads: GET /api/exposure/assets (index rows) and
// GET /api/exposure/assets/{hostKey} (full profile). Nothing is derived from data that is not there.

function n(v) { var k = Number(v); return isFinite(k) ? k : 0; }
function has(v) { return v != null && isFinite(Number(v)); }

export var COLUMNS = ['Host', 'Managed', 'Exposure', 'Attack path', 'Detection', 'Crown jewel', 'Open findings', 'KEV'];
// Columns whose every value is a plain number are right-aligned, like the demo's table layer does.
export var NUM_COLS = { 3: true, 4: true, 6: true };

// heroStats: the four banner stats. Internet-facing comes from the asset identity flag the API returns.
export function heroStats(assets) {
  var l = assets || [];
  return {
    assets: l.length,
    internet: l.filter(function(a) { return a.asset && a.asset.internetFacing; }).length,
    kev: l.filter(function(a) { return a.kevExposed; }).length,
    findings: l.reduce(function(s, a) { return s + n(a.openFindingsCount); }, 0),
  };
}

// cellText: the text of one cell, used for the table filter, the sort fallback and the CSV.
export function cellText(a, col) {
  var as = (a && a.asset) || {};
  switch (col) {
    case 0: return String(as.label || as.hostKey || '');
    case 1: return as.managed ? 'Managed' : 'Discovered';
    case 2: return has(a.exposureScore) ? String(a.exposureScore) : '';
    case 3: return has(a.attackPathScore) ? String(a.attackPathScore) : '';
    case 4: return has(a.detectionCoverageScore) ? String(a.detectionCoverageScore) : '';
    case 5: return String(as.crownJewel || '');
    case 6: return String(n(a.openFindingsCount));
    default: return a.kevExposed ? 'KEV' : '';
  }
}

export function rowText(a) {
  var out = [];
  for (var c = 0; c < COLUMNS.length; c++) out.push(cellText(a, c));
  return out.join(' ').toLowerCase();
}

// filterRows: the toolbar "Filter rows..." box searches the text of every column (as the demo does).
export function filterRows(list, q) {
  var s = String(q == null ? '' : q).trim().toLowerCase();
  if (!s) return (list || []).slice();
  return (list || []).filter(function(a) { return rowText(a).indexOf(s) !== -1; });
}

function sortKey(a, col) {
  switch (col) {
    case 0: return cellText(a, 0);
    case 1: return cellText(a, 1);
    case 2: return has(a.exposureScore) ? n(a.exposureScore) : null;
    case 3: return has(a.attackPathScore) ? n(a.attackPathScore) : null;
    case 4: return has(a.detectionCoverageScore) ? n(a.detectionCoverageScore) : null;
    case 5: return cellText(a, 5) || null;
    case 6: return n(a.openFindingsCount);
    default: return a.kevExposed ? 1 : 0;
  }
}

// sortRows: stable; empty values (no score, no crown-jewel tag) always sort last.
export function sortRows(rows, col, dir) {
  if (col < 0) return rows.slice();
  var d = dir < 0 ? -1 : 1;
  return rows.map(function(r, i) { return { r: r, i: i }; }).sort(function(a, b) {
    var u = sortKey(a.r, col), v = sortKey(b.r, col);
    if (u == null || v == null) return u == null && v == null ? a.i - b.i : u == null ? 1 : -1;
    var c = typeof u === 'number' && typeof v === 'number' ? u - v : String(u).localeCompare(String(v), undefined, { numeric: true });
    return c * d || a.i - b.i;
  }).map(function(o) { return o.r; });
}

// Scores here are "higher is safer": the bar tone follows the same bands as the rest of the page.
export function scoreTone(s) {
  s = Number(s);
  return !isFinite(s) ? 'muted' : s >= 80 ? 'ok' : s >= 40 ? 'warn' : 'bad';
}

// hostBars: data for "Exposure by host". Capped so the chart stays readable on a large fleet; the most
// exposed (lowest-scoring) hosts are kept. Returns the cap note only when the list was cut.
export function hostBars(assets, limit) {
  var cap = limit || 14;
  var scored = (assets || []).filter(function(a) { return has(a.exposureScore); });
  var pick = scored.slice().sort(function(a, b) { return n(a.exposureScore) - n(b.exposureScore); }).slice(0, cap);
  return {
    labels: pick.map(function(a) { return cellText(a, 0); }),
    data: pick.map(function(a) { return n(a.exposureScore); }),
    sub: scored.length > cap ? 'lowest ' + cap + ' of ' + scored.length + ' scores' : '',
  };
}

// findingsRows: kit.hbars rows for "Open findings by host" (hosts with at least one open finding).
export function findingsRows(assets, limit) {
  var list = (assets || []).filter(function(a) { return n(a.openFindingsCount) > 0; })
    .sort(function(a, b) { return n(b.openFindingsCount) - n(a.openFindingsCount); }).slice(0, limit || 6);
  var max = list.length ? n(list[0].openFindingsCount) : 0;
  return list.map(function(a) {
    var c = n(a.openFindingsCount);
    return [cellText(a, 0), max ? c / max * 100 : 0, c > 10 ? 'bad' : 'warn', String(c)];
  });
}

export function rangeCounts(list, total) { return list + ' of ' + total + ' rows'; }
export { pageCount, rangeText, csvText } from './runs-model.js';

export function csvHeader(cols) { return cols.map(function(c) { return COLUMNS[c]; }).concat(['Host key']); }
export function csvRows(rows, cols) {
  return rows.map(function(a) {
    return cols.map(function(c) { return cellText(a, c); }).concat([String((a.asset && a.asset.hostKey) || '')]);
  });
}

// ── Detail drawer ───────────────────────────────────────────────────────────

// drawerSub: the grey line under the drawer title.
export function drawerSub(asset) {
  var a = asset || {};
  return [a.managed ? 'Managed' : 'Discovered', a.crownJewel ? 'crown jewel ' + a.crownJewel : '', a.os || '', a.ip || ''].filter(Boolean).join(' · ');
}

// chipRows: the tags row at the top of the drawer, as [text, tone].
export function chipRows(asset) {
  var a = asset || {};
  var out = [[a.managed ? 'Managed' : 'Discovered', a.managed ? 'ok' : 'muted']];
  if (a.internetFacing) out.push(['Internet-facing', 'bad']);
  if (a.crownJewel) out.push([a.crownJewel, 'violet']);
  if (a.criticalityTier) out.push([a.criticalityTier, 'info']);
  return out;
}

// factRows: the key/value block, only from fields the profile carries.
export function factRows(p) {
  p = p || {};
  var a = p.asset || {}, sc = p.scores || {}, f = p.findings || {}, v = p.vulnerabilities || [];
  var rows = [
    ['Vulnerabilities', sc.vulnerabilityMeasurable ? String(v.length) : ''],
    ['KEV-listed', sc.vulnerabilityMeasurable ? String(v.filter(function(c) { return c.kev; }).length) : ''],
    ['Open findings', f.collected ? String(n(f.openCount)) : ''],
    ['Critical findings', f.collected ? String(n(f.criticalCount)) : ''],
    ['Host key', a.hostKey || ''],
    ['Agent', a.agentId || ''],
    ['Operating system', a.os || ''],
    ['IP address', a.ip || ''],
    ['Segment', a.segment || ''],
    ['Criticality tier', a.criticalityTier || ''],
    ['Production', a.production ? 'Yes' : ''],
    ['Identity exposed', a.identityExposed ? 'Yes' : ''],
    ['Compliance scope', (a.complianceScope || []).join(', ')],
  ];
  return rows.filter(function(r) { return r[1] !== ''; });
}

// related: jump links under the drawer body. Each is {icon, label, sub, tab}.
export function related() {
  return [
    { icon: 'alert', label: 'Findings on this asset', sub: 'Open findings', tab: 'findings' },
    { icon: 'path', label: 'Attack paths through this asset', sub: 'Validated chains', tab: 'attackpath' },
  ];
}
