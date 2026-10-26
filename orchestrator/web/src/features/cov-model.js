// Pure helpers for the redesigned Coverage page: banner numbers, weakest tactics, tracked-threat rows,
// the biggest-gap rows, the technique library filter and summary. No DOM, no network.
// Everything comes from what the page already loads: /api/attack/matrix + /api/scenarios/runs (the
// matrix counts), /api/coverage/analytics, /api/threats/exposure and /api/techniques/unified.

function n(v) { return Number(v) || 0; }

export function rateTone(rate) {
  var r = n(rate);
  return r >= 75 ? 'ok' : r >= 40 ? 'warn' : 'bad';
}

// heroStats: the four banner numbers from the matrix counts {cov, part, gap, none, total}.
// "Validated detected" is the share of TESTED techniques that were prevented or detected.
export function heroStats(c) {
  if (!c) return { covered: null, detected: null, missed: null, untested: null };
  var total = n(c.total) || (n(c.cov) + n(c.part) + n(c.gap) + n(c.none));
  var tested = n(c.cov) + n(c.part) + n(c.gap);
  return {
    covered: total ? n(c.cov) + ' / ' + total : null,
    detected: tested ? Math.round((n(c.cov) + n(c.part)) / tested * 100) + '%' : null,
    missed: total ? n(c.gap) : null,
    untested: total ? n(c.none) : null,
  };
}

// weakestTactics: the tactics with the lowest prevention rate (only tactics that were attempted).
export function weakestTactics(byTactic, limit) {
  var rows = (byTactic || []).map(function(t) {
    var attempted = n(t.attempted) || (n(t.prevented) + n(t.detectedOnly) + n(t.missed));
    return { name: t.tactic, attempted: attempted, pct: attempted ? Math.round(n(t.prevented) / attempted * 100) : null };
  }).filter(function(r) { return r.name && r.attempted > 0; });
  rows.sort(function(a, b) { return a.pct - b.pct || String(a.name).localeCompare(String(b.name)); });
  return rows.slice(0, limit || 5).map(function(r) { r.tone = rateTone(r.pct); return r; });
}

// shortTitle: a threat title cut at a word boundary so it fits a bar label.
export function shortTitle(s, max) {
  s = String(s || '');
  max = max || 24;
  if (s.length <= max) return s;
  var cut = s.slice(0, max);
  var sp = cut.lastIndexOf(' ');
  return (sp > 8 ? cut.slice(0, sp) : cut).replace(/[\s,.;:-]+$/, '') + '…';
}

// threatRows: one row per tracked threat with how many of its techniques have executable content.
export function threatRows(threats) {
  return (Array.isArray(threats) ? threats : []).map(function(t) {
    var techs = t.techniques || [];
    var withContent = techs.filter(function(tc) { return tc.hasExecutableContent; }).length;
    return {
      title: t.title || 'Untitled threat',
      initial: String(t.title || '?').trim().charAt(0).toUpperCase() || '?',
      lastSeenAt: t.lastSeenAt || null,
      techCount: techs.length,
      withContent: withContent,
      pct: techs.length ? Math.round(withContent / techs.length * 100) : 0,
    };
  });
}

// gapRows: techniques whose best verdict is missed or detected-only, worst first.
// Coverage is the share of that technique's runs in which it was prevented.
export function gapRows(byTechnique, limit) {
  var rows = (byTechnique || []).filter(function(t) { return t.bestVerdict === 'missed' || t.bestVerdict === 'detectedOnly'; }).map(function(t) {
    var runs = n(t.runCount);
    return {
      id: t.techniqueId, name: t.name || '', tactic: t.tactic || '', runs: runs,
      pct: runs ? Math.round(n(t.prevented) / runs * 100) : 0,
      verdict: t.bestVerdict,
      label: t.bestVerdict === 'missed' ? 'Missed' : 'Detected only',
      tone: t.bestVerdict === 'missed' ? 'bad' : 'warn',
    };
  });
  rows.sort(function(a, b) { return (a.verdict === b.verdict ? 0 : a.verdict === 'missed' ? -1 : 1) || a.pct - b.pct || b.runs - a.runs; });
  return rows.slice(0, limit || 5);
}

// sourceCount: how many execution sources have variants for a library row.
export function sourceCount(t) {
  return (n(t.basCount) > 0 ? 1 : 0) + (n(t.artCount) > 0 ? 1 : 0) + (n(t.emuCount) > 0 ? 1 : 0) + (n(t.atomicCount) > 0 ? 1 : 0);
}

// libSummary: number of unique techniques and how many have variants per source.
export function libSummary(data) {
  var s = { total: 0, bas: 0, art: 0, emu: 0, atomic: 0 };
  (data || []).forEach(function(t) {
    s.total++;
    if (n(t.basCount)) s.bas++;
    if (n(t.artCount)) s.art++;
    if (n(t.emuCount)) s.emu++;
    if (n(t.atomicCount)) s.atomic++;
  });
  return s;
}

// libFilter: the technique-library rows for a search text, tactic and source filter.
export function libFilter(data, f) {
  f = f || {};
  var q = String(f.q || '').trim().toLowerCase();
  var tactic = f.tactic || 'all', src = f.src || 'all';
  return (data || []).filter(function(t) {
    if (q && (t.techniqueId + ' ' + (t.name || '') + ' ' + (t.tactic || '')).toLowerCase().indexOf(q) === -1) return false;
    if (tactic !== 'all' && (t.tactic || '') !== tactic) return false;
    if (src === 'bas' && !t.basCount) return false;
    if (src === 'art' && !t.artCount) return false;
    if (src === 'emu' && !t.emuCount) return false;
    if (src === 'atomic' && !t.atomicCount) return false;
    if (src === 'multi' && sourceCount(t) < 2) return false;
    return true;
  });
}

// verdictInfo: label and tone for a matrix status key (cov | part | gap | none).
export function verdictInfo(st) {
  var m = { cov: ['Prevented', 'ok'], part: ['Detected only', 'warn'], gap: ['Missed', 'bad'], none: ['Untested', 'muted'] }[st] || ['Untested', 'muted'];
  return { label: m[0], tone: m[1] };
}
