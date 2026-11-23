// Pure helpers for the redesigned Technique Coverage page: banner numbers, the actor card text and chips,
// the table columns, filter / sort / CSV text. No DOM, no network.
// Source: GET /api/coverage/matrix?actor=<name> -> [{techniqueId, simulationExists, detectionProfileExists,
// purpleExerciseExists, complianceMappingExists, responsePlaybookExists (null = N/A)}] and GET /api/coverage/actors.
// The design demo's tactic, per-technique name, test count and last result have no source in that API,
// so none of them is shown; "Coverage" here is the share of applicable dimensions a technique has.
import { COV_DIMS, covHasGap } from './rich-g4.js';

export var COLUMNS = ['Technique', 'Name', 'Coverage'].concat(COV_DIMS.map(function(d) { return d[1]; }));
export var RESULTS = [['gaps', 'With gaps'], ['covered', 'Fully covered']];
export var PAGE_SIZES = [10, 25, 50, 100];
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
  if (col === 1) return r.name || '';
  if (col === 2) { var c = rowCov(r); return c.applicable ? c.pct + '%' : 'N/A'; }
  var v = dimVal(r, col - 3);
  return v === null ? 'N/A' : v ? 'Yes' : 'No';
}

export function filterRows(rows, f) {
  f = f || {};
  var s = String(f.q || '').trim().toLowerCase();
  return (rows || []).filter(function(r) {
    if (f.result === 'gaps' && !covHasGap(r)) return false;
    if (f.result === 'covered' && covHasGap(r)) return false;
    return !s || [r.techniqueId, r.name, r.tactic].join(' ').toLowerCase().indexOf(s) !== -1;
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
  if (col === 1) return r.name || null;
  if (col === 2) { var c = rowCov(r); return c.applicable ? c.pct : null; }
  var v = dimVal(r, col - 3);
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

// withNames: copies of the matrix rows with the technique name and tactic added from the unified library (a map
// techniqueId -> { name, tactic }). Rows without an entry keep an empty name; nothing is invented.
export function withNames(rows, lib) {
  lib = lib || {};
  return (Array.isArray(rows) ? rows : []).map(function(r) {
    var n = lib[r.techniqueId];
    return n ? Object.assign({}, r, { name: n.name || '', tactic: n.tactic || '' }) : r;
  });
}

export function prettyTactic(t) {
  return String(t || '').split(/[-_\s]+/).filter(Boolean).map(function(w) { return w.charAt(0).toUpperCase() + w.slice(1); }).join(' ');
}

// bands: how many techniques sit in each coverage band (the share of applicable dimensions they have). Techniques
// with no applicable dimension are left out, since there is nothing to measure.
export var BAND_DEFS = [['Complete', 'ok'], ['Mostly (70-99%)', 'info'], ['Partial (40-69%)', 'warn'], ['Low (under 40%)', 'bad']];
export function bands(rows) {
  var c = [0, 0, 0, 0];
  (Array.isArray(rows) ? rows : []).forEach(function(r) {
    var v = rowCov(r);
    if (!v.applicable) return;
    c[v.pct === 100 ? 0 : v.pct >= 70 ? 1 : v.pct >= 40 ? 2 : 3]++;
  });
  return BAND_DEFS.map(function(d, i) { return { label: d[0], tone: d[1], value: c[i] }; });
}

// DIM_HELP: what each dimension means and what to do when a technique lacks it. Coverage here is whether Audspect has
// the content, not whether a control detected or blocked anything.
export var DIM_HELP = {
  simulationExists: ['Simulation', 'A scenario or atomic test in Audspect can run this technique.', 'No scenario runs this technique yet. Add or import one under Scenarios.'],
  detectionProfileExists: ['Detection profile', 'A detection profile describes what should alert when the technique runs.', 'No detection profile expects an alert for it, so a run cannot be judged as detected or missed.'],
  purpleExerciseExists: ['Purple exercise', 'A built-in purple-team exercise template includes this technique.', 'No exercise template covers it, so a team cannot rehearse the response.'],
  complianceMappingExists: ['Compliance mapping', 'A scenario that runs it is mapped to a compliance control.', 'Nothing maps it to a control, so compliance reports will not show it.'],
  responsePlaybookExists: ['Response playbook', 'A response playbook covers this technique.', 'No playbook covers it yet.'],
};
export function dimRows(r) {
  return COV_DIMS.map(function(d, i) {
    var v = dimVal(r, i), h = DIM_HELP[d[0]];
    return { key: d[0], label: d[1], state: v === null ? 'na' : v ? 'yes' : 'no', meaning: h[1], todo: v === false ? h[2] : '' };
  });
}
