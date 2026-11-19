// Pure helpers for the redesigned Technique Coverage page: banner numbers, the actor card text and chips,
// the table columns, filter / sort / CSV text. No DOM, no network.
// Source: GET /api/coverage/matrix?actor=<name> -> [{techniqueId, simulationExists, detectionProfileExists,
// purpleExerciseExists, complianceMappingExists, responsePlaybookExists (null = N/A)}] and GET /api/coverage/actors.
// The design demo's tactic, per-technique name, test count and last result have no source in that API,
// so none of them is shown; "Coverage" here is the share of applicable dimensions a technique has.
import { COV_DIMS, covHasGap } from './rich-g4.js';

export var COLUMNS = ['Technique', 'Coverage'].concat(COV_DIMS.map(function(d) { return d[1]; }));
export var RESULTS = [['gaps', 'With gaps'], ['covered', 'Fully covered']];
export var ALL_ACTORS = 'All techniques';
export var MAX_CHIPS = 12;

function dimVal(r, i) { var v = r[COV_DIMS[i][0]]; return v === undefined ? null : v; }

// rowCov: how many of the dimensions that apply to this technique it has.
export function rowCov(r) {
  var have = 0, applicable = 0;
  COV_DIMS.forEach(function(d, i) {
    var v = dimVal(r, i);
    if (v === null) return;
    applicable++;
    if (v) have++;
  });
  return { have: have, applicable: applicable, pct: applicable ? Math.round((have / applicable) * 100) : 0 };
}

export function covTone(pct) { return pct >= 70 ? 'ok' : pct >= 40 ? 'warn' : 'bad'; }

// heroStats: the four banner numbers. avg is null when no technique has an applicable dimension.
export function heroStats(rows) {
  var l = Array.isArray(rows) ? rows : [];
  var have = 0, applicable = 0, gaps = 0;
  l.forEach(function(r) {
    var c = rowCov(r);
    have += c.have; applicable += c.applicable;
    if (covHasGap(r)) gaps++;
  });
  return { total: l.length, avg: applicable ? Math.round((have / applicable) * 100) : null, covered: l.length - gaps, gaps: gaps };
}

// actorNote: the muted line next to the actor picker.
export function actorNote(actor, rows) {
  var h = heroStats(rows);
  var n = h.total + ' technique' + (h.total === 1 ? '' : 's');
  var lead = actor ? 'Showing only techniques attributed to ' + actor + ' · ' + n : n + ' across all known groups';
  return lead + ' · ' + h.covered + ' fully covered · ' + h.gaps + ' with gaps';
}

// chipActors: the chip row under the picker -- "All techniques" first, then the first actors in list order,
// always including the selected one. The picker lists every actor.
export function chipActors(actors, selected) {
  var list = (actors || []).slice(0, MAX_CHIPS - 1);
  if (selected && list.indexOf(selected) === -1 && (actors || []).indexOf(selected) !== -1) list.push(selected);
  return list;
}

export function cellText(r, col) {
  if (col === 0) return r.techniqueId || '';
  if (col === 1) { var c = rowCov(r); return c.applicable ? c.pct + '%' : 'N/A'; }
  var v = dimVal(r, col - 2);
  return v === null ? 'N/A' : v ? 'Yes' : 'No';
}

export function filterRows(rows, f) {
  f = f || {};
  var s = String(f.q || '').trim().toLowerCase();
  return (rows || []).filter(function(r) {
    if (f.result === 'gaps' && !covHasGap(r)) return false;
    if (f.result === 'covered' && covHasGap(r)) return false;
    return !s || String(r.techniqueId || '').toLowerCase().indexOf(s) !== -1;
  });
}

// tableFilter: the table's own "Filter rows..." box searches every column's text.
export function tableFilter(rows, q) {
  var s = String(q || '').trim().toLowerCase();
  if (!s) return rows.slice();
  return rows.filter(function(r) {
    return COLUMNS.map(function(c, i) { return cellText(r, i); }).join(' ').toLowerCase().indexOf(s) !== -1;
  });
}

function sortKey(r, col) {
  if (col === 0) return r.techniqueId || null;
  if (col === 1) { var c = rowCov(r); return c.applicable ? c.pct : null; }
  var v = dimVal(r, col - 2);
  return v === null ? null : v ? 1 : 0;
}

// sortRows: stable; N/A values always sort last.
export function sortRows(rows, col, dir) {
  if (col < 0) return rows.slice();
  var d = dir < 0 ? -1 : 1;
  return rows.map(function(r, i) { return { r: r, i: i }; }).sort(function(a, b) {
    var u = sortKey(a.r, col), v = sortKey(b.r, col);
    if (u === null || v === null) return u === null && v === null ? a.i - b.i : u === null ? 1 : -1;
    var c = typeof u === 'number' ? u - v : String(u).localeCompare(String(v), undefined, { numeric: true });
    return c * d || a.i - b.i;
  }).map(function(o) { return o.r; });
}

export function csvRow(r, cols) { return cols.map(function(c) { return cellText(r, c); }); }

export { pageCount, rangeText, csvText } from './runs-model.js';
