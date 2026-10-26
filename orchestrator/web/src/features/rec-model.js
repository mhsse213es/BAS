// Pure helpers for the redesigned Recommendations page ("What to simulate next"): banner numbers,
// the table columns, filter / sort / CSV text, and the note under the table. No DOM, no network.
// Everything comes from GET /api/recommend/simulations?limit=N (techniques[] with techniqueId, name,
// tactic, score 0-100, tier, coverageState, kev, epssPercentile, threatActors, environmentRisk, reasons
// and suggestedScenario.artTechniques). The demo's "P1", "Effort" and "Est. score gain" have no source in
// that API, so none of them is shown.

export var LIMITS = [10, 20, 50];
export var DEFAULT_LIMIT = 20;

export var COLUMNS = ['Technique', 'Tactic', 'Score', 'Coverage', 'Threat', 'Environment', 'Why'];

function n(v) { return Number(v) || 0; }
function plural(c, one, many) { return c + ' ' + (c === 1 ? one : many); }

export function normLimit(v) {
  var k = Number(v);
  return LIMITS.indexOf(k) !== -1 ? k : DEFAULT_LIMIT;
}
export function limitLabel(k) { return 'Top ' + k; }

export function tierTone(t) { return t === 'Critical' ? 'bad' : t === 'High' ? 'warn' : t === 'Medium' ? 'accent' : 'muted'; }
export function coverageLabel(c) { return c === 'never-tested' ? 'Never tested' : c === 'stale' ? 'Stale' : 'Recent'; }
export function coverageTone(c) { return c === 'never-tested' ? 'bad' : c === 'stale' ? 'warn' : 'muted'; }

// threatBits: the pieces of the Threat column, in display order -> [{text, tone}].
export function threatBits(t) {
  var out = [];
  if (t.kev) out.push({ text: 'KEV', tone: 'bad' });
  if (t.epssPercentile) out.push({ text: 'EPSS ' + Math.round(n(t.epssPercentile)), tone: 'muted' });
  if (t.threatActors) out.push({ text: plural(n(t.threatActors), 'group', 'groups'), tone: 'info' });
  return out;
}

// heroStats: the four banner numbers.
export function heroStats(list) {
  var l = Array.isArray(list) ? list : [];
  var cnt = function(f) { return l.filter(f).length; };
  return {
    ranked: l.length,
    top: cnt(function(t) { return t.tier === 'Critical' || t.tier === 'High'; }),
    never: cnt(function(t) { return t.coverageState === 'never-tested'; }),
    path: cnt(function(t) { return n(t.environmentRisk) > 0; }),
  };
}

// cellText: the text of one cell, used for the filter, the sort fallback and the CSV.
export function cellText(t, col) {
  switch (col) {
    case 0: return (t.name || '') + ' ' + (t.techniqueId || '');
    case 1: return t.tactic || '';
    case 2: return String(n(t.score));
    case 3: return coverageLabel(t.coverageState);
    case 4: return threatBits(t).map(function(b) { return b.text; }).join(' · ');
    case 5: return n(t.environmentRisk) ? String(n(t.environmentRisk)) : '';
    default: return (t.reasons || []).join(' · ');
  }
}

export function filterRows(rows, q) {
  var s = String(q || '').trim().toLowerCase();
  if (!s) return rows.slice();
  return rows.filter(function(t) {
    return COLUMNS.map(function(c, i) { return cellText(t, i); }).join(' ').toLowerCase().indexOf(s) !== -1;
  });
}

function sortKey(t, col) {
  switch (col) {
    case 0: return t.name || t.techniqueId || null;
    case 1: return t.tactic || null;
    case 2: return n(t.score);
    case 3: return { 'never-tested': 0, stale: 1, recent: 2 }[t.coverageState];
    case 4: return n(t.threatActors) + (t.kev ? 1000 : 0);
    case 5: return n(t.environmentRisk);
    default: return (t.reasons || []).join(' · ') || null;
  }
}

// sortRows: stable; empty values always sort last.
export function sortRows(rows, col, dir) {
  if (col < 0) return rows.slice();
  var d = dir < 0 ? -1 : 1;
  return rows.map(function(r, i) { return { r: r, i: i }; }).sort(function(a, b) {
    var u = sortKey(a.r, col), v = sortKey(b.r, col);
    var ue = u == null || u === '', ve = v == null || v === '';
    if (ue || ve) return ue && ve ? a.i - b.i : ue ? 1 : -1;
    var c = typeof u === 'number' && typeof v === 'number' ? u - v : String(u).localeCompare(String(v), undefined, { numeric: true });
    return c * d || a.i - b.i;
  }).map(function(o) { return o.r; });
}

// csvRow: the CSV cells for the visible columns plus the technique ID.
export function csvRow(t, cols) {
  return cols.map(function(c) { return c === 0 ? (t.name || '') : cellText(t, c); }).concat([t.techniqueId || '']);
}

export var NOTE = 'Ranked by threat priority, how overdue the technique is, and whether it traverses a real path in your environment';

// scenarioSub: the caption on the "Suggested scenario" card.
export function scenarioSub(art) {
  var c = (art || []).length;
  return c + ' technique' + (c === 1 ? '' : 's') + ' · use "Copy scenario techniques" above';
}

export { pageCount, rangeText, csvText } from './runs-model.js';
