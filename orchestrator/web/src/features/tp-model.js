// Pure helpers for the redesigned Threat Prioritization page: banner numbers, the tier tiles, the actor
// table (columns, filter, sort, CSV) and the detail drawer pieces. No DOM, no network.
// Everything comes from GET /api/threat-priority/actors (list rows) and
// GET /api/threat-priority/actors/{name} (detail). Nothing is derived from data that is not there.

function n(v) { var k = Number(v); return isFinite(k) ? k : 0; }

export var COLUMNS = ['Actor', 'Tier', 'Score', 'Trend', 'Coverage gap'];

export var TIERS = ['Critical', 'High', 'Medium', 'Low'];

export function tierOf(a) { return (a && a.tier) || 'Low'; }

// tierRank: Critical first. Used for sorting the Tier column.
export function tierRank(t) {
  var i = TIERS.indexOf(t);
  return i < 0 ? TIERS.length : i;
}

// Tier colours follow the design demo: High is red, Medium amber, Low neutral; Critical is red too.
export function tierTone(t) {
  return t === 'Critical' || t === 'High' ? 'bad' : t === 'Medium' ? 'warn' : 'muted';
}

// Score bar: red for the top tiers, amber for the rest (as the demo draws it).
export function barTone(t) { return t === 'Critical' || t === 'High' ? 'bad' : 'warn'; }

// initials: up to two letters, one per word, for the actor avatar.
export function initials(name) {
  return String(name || '').split(/\s+/).filter(Boolean).map(function(w) { return w[0]; }).join('').slice(0, 2).toUpperCase() || '?';
}

// heroStats: the four banner numbers. "High relevance" is the Critical and High tiers together.
export function heroStats(actors) {
  var l = actors || [];
  return {
    actors: l.length,
    high: l.filter(function(a) { return tierOf(a) === 'Critical' || tierOf(a) === 'High'; }).length,
    techniques: l.reduce(function(s, a) { return s + n(a.techniqueCount); }, 0),
    gaps: l.reduce(function(s, a) { return s + n(a.coverageGapCount); }, 0),
  };
}

// tierTiles: one tile per tier (Critical only when an actor is in it). The caption names the top
// actors of that tier by score, or says there are none.
export function tierTiles(actors) {
  var l = actors || [];
  var defs = [
    { tier: 'Critical', label: 'Critical tier', icon: 'warn', tone: 'bad' },
    { tier: 'High', label: 'High tier', icon: 'flag', tone: 'bad' },
    { tier: 'Medium', label: 'Medium tier', icon: 'alert', tone: 'warn' },
    { tier: 'Low', label: 'Low tier', icon: 'eye', tone: 'accent' },
  ];
  var out = [];
  defs.forEach(function(d) {
    var inTier = l.filter(function(a) { return tierOf(a) === d.tier; }).sort(function(a, b) { return n(b.score) - n(a.score); });
    if (d.tier === 'Critical' && !inTier.length) return;
    var names = inTier.map(function(a) { return a.actorName; });
    var cap = !names.length ? 'no actors' : names.slice(0, 2).join(' · ') + (names.length > 2 ? ' +' + (names.length - 2) : '');
    out.push({ tier: d.tier, label: d.label, icon: d.icon, tone: d.tone, value: inTier.length, caption: cap });
  });
  return out;
}

// filterTier: the tier chips above the table ('all' keeps everything).
export function filterTier(actors, tier) {
  return (actors || []).filter(function(a) { return !tier || tier === 'all' || tierOf(a) === tier; });
}

// trendInfo: the Trend cell. up/down carry the signed score change; stable is a dash; no history is "New".
export function trendInfo(a) {
  var t = a && a.trend, d = n(a && a.trendDelta);
  if (t === 'up') return { cls: 'up', text: '▲ +' + Math.abs(d) };
  if (t === 'down') return { cls: 'down', text: '▼ -' + Math.abs(d) };
  if (t === 'stable') return { cls: 'flat', text: '—' };
  return { cls: 'flat', text: 'New' };
}

// cellText: the text of one cell, used for the table filter, the sort fallback and the CSV.
export function cellText(a, col) {
  switch (col) {
    case 0: return String(a.actorName || '');
    case 1: return tierOf(a);
    case 2: return String(n(a.score));
    case 3: return trendInfo(a).text;
    default: return n(a.coverageGapCount) + ' of ' + n(a.techniqueCount) + ' techniques';
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
    case 0: return String(a.actorName || '');
    case 1: return tierRank(tierOf(a));
    case 2: return n(a.score);
    case 3: return a.trend === 'up' || a.trend === 'down' ? n(a.trendDelta) : a.trend === 'stable' ? 0 : null;
    default: return n(a.coverageGapCount);
  }
}

// sortRows: stable; actors with no trend history always sort last on the Trend column.
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

// numericCols: columns whose every value is a plain number are right-aligned, like the demo's table layer
// does (Score always; Trend only while every actor has a trend figure).
export function numericCols(list) {
  var out = { 2: true };
  var l = list || [];
  if (l.length && l.every(function(a) { return a.trend === 'up' || a.trend === 'down'; })) out[3] = true;
  return out;
}

// useLight: a short table in a titled card gets sortable headers only, no toolbar (the demo's rule).
export function useLight(count) { return count < 8; }

export function rangeCounts(list, total) { return list + ' of ' + total + ' rows'; }
export { pageCount, rangeText, csvText } from './runs-model.js';

export function csvHeader(cols) { return cols.map(function(c) { return COLUMNS[c]; }); }
export function csvRows(rows, cols) {
  return rows.map(function(a) { return cols.map(function(c) { return cellText(a, c); }); });
}

// ── Detail drawer ───────────────────────────────────────────────────────────

// drawerSub: the grey line under the drawer title.
export function drawerSub(d) {
  d = d || {};
  return ['Threat actor', 'relevance ' + n(d.score), d.canonicalGroupId ? 'MITRE ' + d.canonicalGroupId : ''].filter(Boolean).join(' · ');
}

// chipRows: the tags row at the top of the drawer, as [text, tone].
export function chipRows(d) {
  d = d || {};
  var out = [[tierOf(d), tierTone(tierOf(d))]];
  if (d.techniqueSource === 'mitre') out.push(['Techniques: MITRE-authoritative', 'info']);
  else if (d.techniqueSource === 'connector') out.push(['Techniques: connector-derived', 'warn']);
  return out;
}

// factRows: the key/value block under the chips; only fields the response carries.
export function factRows(d) {
  d = d || {};
  var rows = [
    ['Score', String(n(d.score))],
    ['Techniques', String(n(d.techniqueCount))],
    ['Coverage gap', n(d.coverageGapCount) + ' of ' + n(d.techniqueCount) + ' not yet validated'],
  ];
  var t = trendInfo(d);
  if (d.trend === 'up' || d.trend === 'down') rows.push(['Trend', t.text]);
  return rows;
}

// related: jump links at the bottom of the drawer. Each is {icon, label, sub, tab}.
export function related() {
  return [
    { icon: 'mapped', label: 'Technique coverage', sub: 'Per-technique content and outcomes', tab: 'attack-coverage' },
    { icon: 'bulb', label: 'Recommendations', sub: 'What to simulate next', tab: 'recommendations' },
    { icon: 'technique', label: 'Scenarios', sub: 'Run a simulation for these techniques', tab: 'scenarios' },
  ];
}
