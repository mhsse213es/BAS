// Pure helpers for the redesigned Remediation page: banner numbers, tile numbers, the filtered card
// list and the per-card view. No DOM, no network.
// Everything comes from GET /api/remediations (one row per technique to fix: severity, techniqueId,
// techniqueName, findingCount, agentCount, controlClasses, missed, detectedOnly, mitigations,
// detection, recommendedTargets, findingIds). There is no owner / due date / stage in that API, so
// none is shown.
import { normSev, matchesQuery, sevTone } from './rich-g3.js';

function n(v) { return Number(v) || 0; }
function plural(c, one, many) { return c + ' ' + (c === 1 ? one : many); }

// heroStats: the banner numbers. Open = every remediation returned; critical = the Critical ones.
export function heroStats(list) {
  var l = Array.isArray(list) ? list : [];
  return { open: l.length, critical: l.filter(function(r) { return normSev(r.severity) === 'Critical'; }).length };
}

// tileData: the three tiles under the banner.
export function tileData(list) {
  var l = Array.isArray(list) ? list : [];
  return {
    open: l.length,
    findings: l.reduce(function(s, r) { return s + n(r.findingCount); }, 0),
    critical: heroStats(l).critical,
  };
}

// sevCounts: counts for the severity segmented control, keyed all / Critical / High / Medium / Low.
export function sevCounts(list) {
  var l = Array.isArray(list) ? list : [];
  var c = { all: l.length, Critical: 0, High: 0, Medium: 0, Low: 0 };
  l.forEach(function(r) { var s = normSev(r.severity); if (s) c[s]++; });
  return c;
}

// filterRems: indexes (into the original list, so row actions stay stable) matching severity + search.
export function filterRems(list, sev, q) {
  var out = [];
  (Array.isArray(list) ? list : []).forEach(function(r, i) {
    if (sev && sev !== 'all' && normSev(r.severity) !== sev) return;
    if (!matchesQuery(q, [r.techniqueId, r.techniqueName, (r.controlClasses || []).join(' ')])) return;
    out.push(i);
  });
  return out;
}

// showingText: "Showing 3 of 31" (the number matching the filters out of all remediations).
export function showingText(shown, total) {
  return 'Showing ' + n(shown) + ' of ' + n(total);
}

// cardView: what one prioritized-fix card prints.
export function cardView(r) {
  r = r || {};
  var fc = n(r.findingCount), ac = n(r.agentCount);
  var sev = normSev(r.severity);
  return {
    sev: sev || String(r.severity || ''),
    tone: sevTone(r.severity),
    sevKey: sev.toLowerCase(),
    techniqueId: String(r.techniqueId || ''),
    name: String(r.techniqueName || ''),
    closes: plural(fc, 'finding', 'findings'),
    agents: plural(ac, 'agent', 'agents'),
    controls: (r.controlClasses || []).join(', '),
    missed: n(r.missed),
    detectedOnly: n(r.detectedOnly),
  };
}

// drawerView: the pieces of the detail drawer. Mitigations are the ATT&CK ones the server returned;
// when there are none the drawer says so rather than inventing steps.
export function drawerView(r) {
  r = r || {};
  var v = cardView(r);
  v.summary = 'Closes ' + v.closes + ' on ' + v.agents + ' · Missed ' + v.missed + ' · Detected only ' + v.detectedOnly;
  v.subtitle = v.techniqueId + ' · MITRE ATT&CK mitigation';
  v.steps = (r.mitigations || []).filter(function(m) { return m && m.name; }).map(function(m) { return { name: String(m.name), description: String(m.description || '') }; });
  v.detection = String(r.detection || '');
  v.targets = (r.recommendedTargets || []).map(String);
  return v;
}
