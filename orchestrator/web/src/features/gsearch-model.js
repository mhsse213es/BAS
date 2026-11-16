// Pure model for the global search palette: which scope a result belongs to, how a query matches an item, how matches
// are ranked and highlighted, and how pages, agents, reports and cloud scenarios become searchable items. Nothing here
// touches the DOM or the network, so every rule is tested on its own.

import { escapeHTML as escapeHtml } from '../core/escape.js';

// The scopes offered as chips. 'all' shows every section; the others show one kind of thing.
export var SCOPES = [
  ['all', 'All'], ['pages', 'Pages'], ['scenario', 'Scenarios'], ['technique', 'Techniques'], ['agent', 'Agents'],
  ['run', 'Runs'], ['report', 'Reports'], ['finding', 'Findings'], ['intel', 'Threat intel'], ['other', 'More']
];

// Server results carry a docType; each belongs to one scope and has a human label.
var DOC = {
  scenario: ['scenario', 'Scenario'], run: ['run', 'Run'], finding: ['finding', 'Finding'], technique: ['technique', 'Technique'],
  actor: ['intel', 'Threat actor'], campaign: ['intel', 'Threat campaign'], malware: ['intel', 'Malware'], tool: ['intel', 'Tool'],
  rule: ['other', 'Detection rule'], compliance_control: ['other', 'Compliance control'],
  detection_connector: ['other', 'Detection connector'], action_connector: ['other', 'Response connector']
};
export function scopeOf(docType) { return (DOC[docType] || ['other', 'Result'])[0]; }
export function labelOf(docType) { return (DOC[docType] || ['other', 'Result'])[1]; }

// Section order when more than one scope is shown.
export var SECTION_ORDER = ['pages', 'scenario', 'technique', 'agent', 'run', 'report', 'finding', 'intel', 'other'];
export var SECTION_TITLE = { pages: 'Pages & actions', scenario: 'Scenarios', technique: 'Techniques', agent: 'Agents', run: 'Runs', report: 'Reports', finding: 'Findings', intel: 'Threat intel', other: 'Detections & compliance' };

// A query's words. A word like "type:agent" is a server-side operator, not text to match, so it is dropped here.
export function tokens(q) {
  return String(q == null ? '' : q).toLowerCase().split(/\s+/).filter(function(t) { return t && !/^[a-z_]+:\S*$/.test(t); });
}

// scoreItem: 0 when the item does not match every word; otherwise higher is better. A word counts if it appears in the
// title (best at the start of the title or of a word), the subtitle or the keywords.
export function scoreItem(item, q) {
  var ts = tokens(q);
  if (!ts.length) return 1;
  var title = String(item.title || '').toLowerCase();
  var sub = String(item.sub || '').toLowerCase();
  var kw = String(item.keywords || '').toLowerCase();
  var total = 0;
  for (var i = 0; i < ts.length; i++) {
    var t = ts[i], s = 0;
    if (title.indexOf(t) === 0) s = 100;
    else if (new RegExp('(^|[\\s\\-_/.:(])' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).test(title)) s = 70;
    else if (title.indexOf(t) >= 0) s = 45;
    else if (sub.indexOf(t) >= 0) s = 18;
    else if (kw.indexOf(t) >= 0) s = 10;
    if (!s) return 0;
    total += s;
  }
  return total / ts.length + (item.boost || 0);
}

// highlight: the text escaped, with every matching word wrapped in <mark>. Escapes first, then marks, so a query can
// never inject markup.
export function highlight(text, q) {
  var raw = String(text == null ? '' : text);
  var ts = tokens(q).filter(function(t) { return t.length > 0; });
  if (!ts.length) return escapeHtml(raw);
  var re = new RegExp('(' + ts.map(function(t) { return t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }).join('|') + ')', 'ig');
  var out = '', last = 0, m;
  while ((m = re.exec(raw)) !== null) {
    if (m[0] === '') { re.lastIndex++; continue; }
    out += escapeHtml(raw.slice(last, m.index)) + '<mark>' + escapeHtml(m[0]) + '</mark>';
    last = m.index + m[0].length;
  }
  return out + escapeHtml(raw.slice(last));
}

// ── Building searchable items ──

// pageItems: the navigation entries the user can see, plus pages reachable only from another page.
// nav = [{ tab, title, group }]. Extras are added unless the nav already has them.
var EXTRA_PAGES = [['compliance', 'Compliance Reports', 'Reports & Analytics'], ['sla-report', 'SLA Compliance', 'Reports & Analytics']];
export function pageItems(nav) {
  var seen = {}, out = [];
  (nav || []).concat(EXTRA_PAGES.map(function(p) { return { tab: p[0], title: p[1], group: p[2] }; })).forEach(function(n) {
    if (!n || !n.tab || seen[n.tab]) return;
    seen[n.tab] = 1;
    out.push({ id: 'page:' + n.tab, kind: 'page', scope: 'pages', tab: n.tab, title: n.title, sub: n.group ? 'Go to page · ' + n.group : 'Go to page', badge: 'Page', boost: 4 });
  });
  return out;
}

export function actionItems(actions) {
  return (actions || []).map(function(a, i) {
    return { id: 'action:' + i, kind: 'action', scope: 'pages', title: a.title, sub: 'Action', badge: 'Action', fn: a.fn, boost: 6 };
  });
}

function agentOs(a) { return String(a.osVersion || a.os || '').trim(); }
export function agentItems(agents) {
  return (Array.isArray(agents) ? agents : []).filter(function(a) { return a && a.agentId; }).map(function(a) {
    var host = a.hostname || a.agentId;
    var bits = [agentOs(a), a.status, a.ipAddress].filter(Boolean);
    return { id: 'agent:' + a.agentId, kind: 'agent', scope: 'agent', agentId: a.agentId, title: host, sub: bits.join(' · ') || a.agentId, keywords: [a.agentId, a.username, a.envLabel].filter(Boolean).join(' '), badge: 'Agent' };
  });
}

var REPORT_TYPE = { posture: 'Posture report', audit: 'Audit pack', compliance: 'Compliance evidence' };
export function reportItems(list, hostOf) {
  return (Array.isArray(list) ? list : []).filter(function(r) { return r && r.id; }).map(function(r) {
    var type = REPORT_TYPE[r.reportType] || r.reportType || 'Report';
    var host = (hostOf && hostOf[r.agentId]) || r.agentId || '';
    return { id: 'report:' + r.id, kind: 'report', scope: 'report', reportId: r.id, title: type + (host ? ' — ' + host : ''), sub: [String(r.format || '').toUpperCase(), r.generatedBy, r.generatedAt ? String(r.generatedAt).slice(0, 10) : ''].filter(Boolean).join(' · '), keywords: r.id, badge: 'Report' };
  });
}

export function cloudItems(list) {
  return (Array.isArray(list) ? list : []).filter(function(c) { return c && c.id; }).map(function(c) {
    return { id: 'cloud:' + c.id, kind: 'cloud', scope: 'scenario', cloudId: c.id, title: c.name, sub: [c.providerLabel, c.description].filter(Boolean).join(' · '), keywords: c.provider, badge: 'Cloud scenario' };
  });
}

// phishingItems: phishing scenarios from the scenario library (entries of type "phishing"). They count as Scenarios.
export function phishingItems(entries) {
  return (Array.isArray(entries) ? entries : []).filter(function(e) { return e && e.type === 'phishing' && e.id; }).map(function(e) {
    var state = e.status === 'unavailable' ? 'Unavailable' : e.status === 'catalog_only' ? 'Catalogued only' : e.experimental || e.status === 'experimental' ? 'Experimental' : 'Available';
    return { id: 'phish:' + e.id, kind: 'phish', scope: 'scenario', phishId: e.id, title: e.name || e.id, sub: [e.id, state, e.description].filter(Boolean).join(' · ').slice(0, 140), keywords: ['phishing', 'email', 'social engineering'].concat(e.tags || []).join(' '), badge: 'Phishing' };
  });
}

export function scenarioItems(list) {
  return (Array.isArray(list) ? list : []).filter(function(s) { return s && s.id; }).map(function(s) {
    var tech = (s.steps || []).map(function(p) { return p && p.techniqueId; }).concat(s.artTechniques || []).filter(Boolean);
    return { id: 'scenario:' + s.id, kind: 'scenario', scope: 'scenario', sourceId: s.id, title: s.name || s.id, sub: String(s.description || '').replace(/\s+/g, ' ').slice(0, 120), keywords: [s.id].concat(s.tags || [], tech).join(' '), badge: 'Scenario' };
  });
}

// resultItems: server search results as items (they keep the reference so opening and favouriting still work).
export function resultItems(results) {
  return (Array.isArray(results) ? results : []).map(function(r) {
    return { id: r.docType + ':' + r.sourceId, kind: 'result', scope: scopeOf(r.docType), docType: r.docType, sourceId: r.sourceId, title: r.title, sub: String(r.description || '').replace(/\s+/g, ' ').slice(0, 120), badge: labelOf(r.docType), fav: !!r.favorited, ref: r };
  });
}

// Query results: keep the items that match, rank them, drop duplicates (a local item and a server result for the same
// thing show once, the server's, which can be favourited), and group them by scope.
// opts = { scope, limitPerScope }. Returns { sections: [{ scope, title, items }], counts: { scope: n }, total }.
export function search(items, q, opts) {
  var o = opts || {};
  var want = o.scope && o.scope !== 'all' ? o.scope : null;
  var limit = o.limitPerScope || (want ? 40 : 5);
  var byKey = {};
  items.forEach(function(it) {
    var key = it.kind === 'result' && it.docType === 'scenario' ? 'scenario:' + it.sourceId : it.id;
    var prev = byKey[key];
    if (!prev || (it.kind === 'result' && prev.kind !== 'result')) byKey[key] = it;
  });
  var scored = [];
  Object.keys(byKey).forEach(function(k) {
    var it = byKey[k];
    // A server result already matched on the server, which may match more than this model can (stemming, tags): keep it.
    var s = it.kind === 'result' ? Math.max(scoreItem(it, q), 5) : scoreItem(it, q);
    if (s > 0) scored.push({ it: it, s: s });
  });
  scored.sort(function(a, b) { return b.s - a.s || (a.it.title < b.it.title ? -1 : 1); });
  var counts = {}, groups = {};
  scored.forEach(function(e) {
    counts[e.it.scope] = (counts[e.it.scope] || 0) + 1;
    if (want && e.it.scope !== want) return;
    (groups[e.it.scope] = groups[e.it.scope] || []).push(e.it);
  });
  var sections = SECTION_ORDER.filter(function(s) { return groups[s] && groups[s].length; }).map(function(s) {
    return { scope: s, title: SECTION_TITLE[s], items: groups[s].slice(0, limit), more: Math.max(0, groups[s].length - limit) };
  });
  return { sections: sections, counts: counts, total: scored.length };
}

// nextScope cycles the scope chips (dir +1 or -1).
export function nextScope(cur, dir, available) {
  var ids = SCOPES.map(function(s) { return s[0]; }).filter(function(id) { return id === 'all' || !available || available.indexOf(id) >= 0; });
  var i = ids.indexOf(cur); if (i < 0) i = 0;
  return ids[(i + dir + ids.length) % ids.length];
}
