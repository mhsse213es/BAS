// Pure helpers for the redesigned Agents page: the table (columns, filter, sort, CSV), the three
// distribution cards, the Operational view and the legacy-transport card. No DOM, no network.
// Everything is a count or share over what GET /api/agents already returned (the loaded pages plus the
// server's fleet-wide bucket totals); a figure with no source is left out rather than invented.

function n(v) { var k = Number(v); return isFinite(k) ? k : 0; }

export var COLUMNS = ['Host', 'Group', 'OS', 'Status', 'Last seen', 'Sims'];
// Columns whose every value is a plain number are right-aligned, like the demo's table layer does.
export var NUM_COLS = { 5: true };

export var STATUS_LABEL = { online: 'Online', degraded: 'Degraded', offline: 'Offline', retired: 'Retired' };
export var STATUS_TONE = { online: 'ok', degraded: 'warn', offline: 'bad', retired: 'muted' };
var STATUS_RANK = { online: 0, degraded: 1, offline: 2, retired: 3 };

// bucketOf: retired = uninstalled; offline = no heartbeat; degraded = reachable but not in the active
// lifecycle state (restricted / quarantined / revoked ...); online otherwise. Same rule as the server's buckets.
export function bucketOf(a) {
  a = a || {};
  if (a.state === 'retired' || a.state === 'uninstalled') return 'retired';
  if (a.status === 'offline') return 'offline';
  if (a.state && a.state !== 'active') return 'degraded';
  return 'online';
}

// osFamily collapses an osVersion string to one of the demo's four families (Linux distributions fold
// into "Linux"); anything it cannot place keeps its own first word, and an empty value is "Unknown".
var LINUX = /^(linux|ubuntu|debian|rhel|red hat|centos|rocky|alma|fedora|suse|opensuse|sles|oracle|amazon|arch|kali|mint|alpine)/i;
export function osFamily(osVersion) {
  var s = String(osVersion == null ? '' : osVersion).trim();
  if (!s) return 'Unknown';
  var l = s.toLowerCase();
  if (l.indexOf('windows server') === 0) return 'Windows Server';
  if (l.indexOf('windows') === 0) return 'Windows';
  if (l.indexOf('mac') === 0 || l.indexOf('darwin') === 0) return 'macOS';
  if (LINUX.test(s)) return 'Linux';
  return s.split(/[\s/]+/)[0];
}

export function osOptions(list) {
  var seen = {};
  (list || []).forEach(function(a) { seen[osFamily(a && a.osVersion)] = true; });
  var order = ['Windows', 'Windows Server', 'Linux', 'macOS'];
  var keys = Object.keys(seen);
  return order.filter(function(k) { return seen[k]; }).concat(keys.filter(function(k) { return order.indexOf(k) < 0; }).sort());
}

// ── Table ───────────────────────────────────────────────────────────────────

function hostName(a) { return String((a && (a.hostname || a.agentId)) || ''); }
function seenTs(a) { var t = a && a.lastUpdate ? new Date(a.lastUpdate).getTime() : NaN; return isFinite(t) ? t : null; }

// cellText: the text of one cell, used for the filter, the sort fallback and the CSV.
export function cellText(a, col) {
  a = a || {};
  switch (col) {
    case 0: return hostName(a);
    case 1: return String(a.groupName || 'Ungrouped');
    case 2: return String(a.osVersion || '');
    case 3: return STATUS_LABEL[bucketOf(a)];
    case 4: return a.lastUpdate ? String(a.lastUpdate) : '';
    default: return String(n(a.sims));
  }
}

// rowText: what the toolbar filter searches: every visible column plus the IP address and agent id that
// sit under the host name.
export function rowText(a) {
  var out = [];
  for (var c = 0; c < COLUMNS.length; c++) out.push(cellText(a, c));
  out.push(String((a && a.ipAddress) || ''), String((a && a.agentId) || ''));
  return out.join(' ').toLowerCase();
}

export function filterRows(list, q) {
  var s = String(q == null ? '' : q).trim().toLowerCase();
  if (!s) return (list || []).slice();
  return (list || []).filter(function(a) { return rowText(a).indexOf(s) !== -1; });
}

// byOs: the OS select narrows the loaded rows by family ('' = all).
export function byOs(list, os) {
  if (!os) return (list || []).slice();
  return (list || []).filter(function(a) { return osFamily(a && a.osVersion) === os; });
}

function sortKey(a, col) {
  switch (col) {
    case 0: return cellText(a, 0).toLowerCase();
    case 1: return cellText(a, 1).toLowerCase();
    case 2: return cellText(a, 2) ? cellText(a, 2).toLowerCase() : null;
    case 3: return STATUS_RANK[bucketOf(a)];
    case 4: return seenTs(a);
    default: return n(a.sims);
  }
}

// sortRows: stable; rows with no value in the column (no OS, never seen) always sort last.
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

export function rangeCounts(list, total) { return list + ' of ' + total + ' rows'; }
export { pageCount, rangeText, csvText } from './runs-model.js';

// footNote: the extra footer line when the server holds more pages than the table has loaded.
export function footNote(loaded, hasMore, fleet) {
  if (!hasMore) return '';
  return 'Loaded ' + loaded + (fleet > loaded ? ' of ' + fleet : '') + ' agents so far — load more to see the rest';
}

export function csvHeader(cols) { return cols.map(function(c) { return COLUMNS[c]; }).concat(['IP address', 'Agent ID']); }
export function csvRows(rows, cols) {
  return rows.map(function(a) {
    return cols.map(function(c) { return cellText(a, c); }).concat([String(a.ipAddress || ''), String(a.agentId || '')]);
  });
}

// ── Cards ───────────────────────────────────────────────────────────────────

export function fleetCount(totals) {
  var t = totals || {};
  return n(t.online) + n(t.degraded) + n(t.offline);
}

// statusSegments: the Status donut, from the server's fleet-wide totals. Zero segments are dropped.
export function statusSegments(totals) {
  var t = totals || {};
  return [['online', 'Online'], ['degraded', 'Degraded'], ['offline', 'Offline'], ['retired', 'Retired']]
    .map(function(p) { return { key: p[0], label: p[1], value: n(t[p[0]]) }; })
    .filter(function(s) { return s.value > 0; });
}

// shareRows: [[label, percent, tone, text]] for a list of [label, count] pairs, as a share of the loaded rows.
function shareRows(pairs, total, tone) {
  return pairs.map(function(p) {
    var pct = total ? Math.round(p[1] / total * 100) : 0;
    return [p[0], pct, tone, pct + '%'];
  });
}

function tally(list, fn) {
  var m = {};
  (list || []).forEach(function(a) { var k = fn(a); m[k] = (m[k] || 0) + 1; });
  return Object.keys(m).map(function(k) { return [k, m[k]]; })
    .sort(function(a, b) { return b[1] - a[1] || (a[0] < b[0] ? -1 : 1); });
}

export function osShareRows(list) {
  return shareRows(tally(list, function(a) { return osFamily(a && a.osVersion); }), (list || []).length, 'info');
}
export function groupShareRows(list, top) {
  return shareRows(tally(list, function(a) { return (a && a.groupName) || 'Ungrouped'; }).slice(0, top || 5), (list || []).length, 'info');
}

// osDonut: the Operational view's "Agents by OS" donut over the loaded rows.
export function osDonut(list) {
  return tally(list, function(a) { return osFamily(a && a.osVersion); }).map(function(p) { return { label: p[0], value: p[1] }; });
}

// simsRows: "Simulations per agent": the agents that have run something, busiest first.
export function simsRows(list, limit) {
  var pick = (list || []).filter(function(a) { return n(a && a.sims) > 0; })
    .sort(function(a, b) { return n(b.sims) - n(a.sims); }).slice(0, limit || 6);
  var max = pick.length ? n(pick[0].sims) : 0;
  return pick.map(function(a) { return [hostName(a), max ? n(a.sims) / max * 100 : 0, 'info', String(n(a.sims))]; });
}

// opTiles: the Operational view's four tiles, each with the one-line caption under its value.
export function opTiles(totals) {
  var t = totals || {};
  var fleet = fleetCount(t);
  var pct = function(v) { return fleet ? Math.round(n(v) / fleet * 100) + '%' : ''; };
  return [
    { key: 'total', label: 'Total agents', value: fleet, caption: 'enrolled', tone: 'accent', icon: 'agents' },
    { key: 'online', label: 'Online', value: n(t.online), caption: pct(t.online), tone: 'ok', icon: 'ok' },
    { key: 'degraded', label: 'Degraded', value: n(t.degraded), caption: n(t.degraded) ? 'lifecycle not active' : '', tone: 'warn', icon: 'warn' },
    { key: 'offline', label: 'Offline', value: n(t.offline), caption: n(t.offline) ? 'check connectivity' : '', tone: 'bad', icon: 'bad' },
  ];
}

// ── Legacy transport card ───────────────────────────────────────────────────

export function migrationView(st) {
  st = st || {};
  var req = n(st.daysRequired), clean = n(st.daysClean);
  return {
    clean: clean, required: req,
    pct: req ? Math.min(100, Math.round(clean / req * 100)) : 0,
    eligible: !!st.eligible,
    label: st.eligible ? 'ELIGIBLE FOR REVIEW' : 'NOT YET ELIGIBLE',
    tone: st.eligible ? 'ok' : 'warn',
  };
}

// ── Drawer ──────────────────────────────────────────────────────────────────

export function drawerSub(a) {
  a = a || {};
  return [a.ipAddress, a.agentId].filter(Boolean).join(' · ');
}

// facts: the plain key/value rows of the drawer overview (status, lifecycle and trust are rendered as pills by the view).
export function facts(a) {
  a = a || {};
  var rows = [
    ['Agent ID', a.agentId, 'mono'],
    ['IP address', a.ipAddress],
    ['OS', a.osVersion],
    ['Group', a.groupName || 'Ungrouped'],
    ['Username', a.username],
    ['Environment', a.envLabel],
  ];
  return rows.filter(function(r) { return r[1] != null && String(r[1]) !== ''; });
}
