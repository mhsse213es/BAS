// Pure helpers behind the redesigned Scenarios page (hero stats, sidebar categories, cards, drawer).
//
// Everything is derived from the rows the page already loads (/api/scenarios, /api/scenarios/library,
// /api/adversary-templates, /api/scenarios/runs). Nothing here reads the DOM, talks to the server or
// invents a value, so it is unit-testable (tests/unit/scn-model.test.mjs).

var arr = function(a) { return Array.isArray(a) ? a : []; };

export var SOURCE_LABEL = { builtin: 'Built-in', custom: 'Custom', intel: 'Threat intel' };

// The source a scenario is filed under: any scenario generated from a threat-intel feed is "intel".
export function sourceOf(s) { return s.intelSource ? 'intel' : (s.source || 'builtin'); }

// Distinct ATT&CK technique ids a scenario declares: its steps plus its explicit ART technique list.
// Sweep scenarios resolve their real list on the server, so they report none here.
export function techniquesOf(s) {
  var seen = {}, out = [];
  arr(s.steps).map(function(st) { return st && st.techniqueId; }).concat(arr(s.artTechniques)).forEach(function(t) {
    if (t && !seen[t]) { seen[t] = 1; out.push(t); }
  });
  return out;
}

var OS_NAME = { windows: 'Windows', linux: 'Linux', darwin: 'macOS' };
export function osName(o) { return OS_NAME[String(o).toLowerCase()] || String(o); }
// One or two named platforms are listed; none declared, or all three, reads as cross-platform.
export function osLabel(list) {
  var l = arr(list);
  if (!l.length || l.length >= 3) return 'Cross-Platform';
  return l.map(osName).join(' / ');
}

// How the scenario runs, in words: the same wording the old tile used, minus the markup.
// cat = { art: <ART catalog length or 0>, caldera: <Caldera catalog length or 0> }.
export function modeLabel(s, cat) {
  cat = cat || {};
  var steps = arr(s.steps).length;
  if (s.localCheck) return 'Posture check';
  if (s.artAllWindows) return 'Full ART sweep' + (cat.art ? ' · ' + cat.art + ' techniques' : '');
  if (s.artAllPlatform) return 'Full ART sweep';
  if (s.artSelectiveWindows) return 'Selective ART sweep' + (cat.art ? ' · up to ' + cat.art + ' techniques' : '');
  if (s.artSelectivePlatform) return 'Selective ART sweep';
  if (s.calderaAllWindows) return 'Full Caldera sweep' + (cat.caldera ? ' · ' + cat.caldera + ' abilities' : '');
  if (arr(s.artTechniques).length) return arr(s.artTechniques).length + ' ART techniques';
  if (arr(s.calderaAbilities).length) return arr(s.calderaAbilities).length + ' Caldera abilities';
  if (steps) return steps + (steps === 1 ? ' step' : ' steps');
  return '—';
}

// The two foot items on a card: techniques (or the run mode for sweeps) and the step count.
export function footOf(s, cat) {
  var t = techniquesOf(s).length, steps = arr(s.steps).length;
  return {
    left: t ? '+' + t + (t === 1 ? ' technique' : ' techniques') : modeLabel(s, cat),
    right: steps ? steps + (steps === 1 ? ' step' : ' steps') : '',
  };
}

// Availability pill from the content registry: executable means an approved or signed version exists.
export function availOf(s) {
  var r = s.registry;
  if (!r) return { key: 'none', tone: 'muted', label: 'Unregistered', title: 'Not registered, cannot run' };
  if (r.executableVersion) {
    var t = r.executableTrust === 'VENDOR_SIGNED' ? 'signed' : (r.executableTrust === 'LOCAL_TRUSTED' ? 'approved' : 'dev-unsigned');
    return { key: 'ok', tone: 'ok', label: 'Available', title: 'Executable version v' + r.executableVersion + ' (' + t + ')' };
  }
  var lc = String(r.latestLifecycle || 'draft');
  return { key: 'pending', tone: 'warn', label: lc.charAt(0).toUpperCase() + lc.slice(1).toLowerCase().replace(/_/g, ' '), title: 'Not executable until approved' };
}

// Search text: id, name, description, tags, ATT&CK phases and techniques, emulated actor.
export function matches(s, q) {
  q = String(q || '').trim().toLowerCase();
  if (!q) return true;
  var hay = [s.id, s.name, s.description, arr(s.tags).join(' '), arr(s.mitrePhases).join(' '), techniquesOf(s).join(' '), s.intelActor].join(' ').toLowerCase();
  return hay.indexOf(q) !== -1;
}

// filterList applies the toolbar filters. f = { q, os, source, product }; productOf maps a scenario to its product key.
export function filterList(list, f, productOf) {
  return arr(list).filter(function(s) {
    if (f.os && f.os !== 'all' && arr(s.supportedOs).indexOf(f.os) === -1) return false;
    if (f.source && f.source !== 'all' && sourceOf(s) !== f.source) return false;
    if (f.product && f.product !== 'all' && productOf(s) !== f.product) return false;
    return matches(s, f.q);
  });
}

// sortList: 'default' keeps the server order; 'name' is A-Z; 'tech' is most techniques first. Never mutates.
export function sortList(list, mode) {
  var out = arr(list).slice();
  if (mode === 'name') out.sort(function(a, b) { return String(a.name).localeCompare(String(b.name)); });
  else if (mode === 'tech') out.sort(function(a, b) { return techniquesOf(b).length - techniquesOf(a).length; });
  return out;
}

// Hero figures over the whole catalogue: scenarios, distinct techniques, product families in use.
export function heroStats(list, productOf) {
  var tech = {}, fam = {};
  arr(list).forEach(function(s) {
    techniquesOf(s).forEach(function(t) { tech[t] = 1; });
    fam[productOf(s)] = 1;
  });
  return { total: arr(list).length, techniques: Object.keys(tech).length, families: Object.keys(fam).length };
}

// Sidebar rows: "All Scenarios" first, then every category that has something in it, in the given order.
// cats = [{key,label,icon}], count(key) -> number, subs = { key: 'text' }.
export function categoryRows(cats, total, count, subs) {
  var rows = [{ key: 'all', label: 'All Scenarios', icon: 'layers', n: total, sub: '' }];
  arr(cats).forEach(function(c) {
    var n = count(c.key);
    if (n > 0) rows.push({ key: c.key, label: c.label, icon: c.icon, n: n, sub: (subs && subs[c.key]) || '' });
  });
  return rows;
}

// A page title for the breadcrumb/footer line: "Showing N of M scenarios".
export function showing(n, m) { return 'Showing ' + n + ' of ' + m + ' scenario' + (m === 1 ? '' : 's'); }

// Run history for one scenario, newest first. A run's score is its prevention percentage when it has one.
export function historyOf(runs, scenarioId) {
  var rows = arr(runs).filter(function(r) { return r && r.scenarioId === scenarioId; }).map(function(r) {
    var sc = r.score && typeof r.score === 'object' ? r.score : null;
    var pct = sc && sc.preventionScore != null ? Math.round(sc.preventionScore) : null;
    return { id: r.id, run: r, status: r.status || '', agent: r.hostname || r.agentId || '', startedAt: r.startedAt || r.createdAt || '', pct: pct };
  });
  rows.sort(function(a, b) { return new Date(b.startedAt) - new Date(a.startedAt); });
  return rows;
}

// Prevention percentages oldest -> newest, for the pass-rate sparkline (runs without a score are skipped).
export function historySeries(rows) {
  return arr(rows).filter(function(r) { return r.pct != null; }).map(function(r) { return r.pct; }).reverse();
}
