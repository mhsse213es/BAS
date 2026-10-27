// Pure helpers for the redesigned Settings page: the Users & roles table (column set, filter, sort, CSV text)
// and the labels of the settings rail. No DOM, no network. Data: GET /api/users. The demo's "Email" and "MFA"
// columns have no source in that API (a user has a username, role, active flag, created and last-login
// times), so they are not shown; "Status" and "Created" stand in for them.

// The demo gives a table the full toolbar (filter, count, columns, page size, CSV, selection, pager) from 8
// rows up and only sortable headers below that.
export var FULL_FROM = 8;
export function isFull(n) { return n >= FULL_FROM; }

export var USER_COLUMNS = ['User', 'Role', 'Status', 'Created', 'Last login'];

// The settings rail: [section id, label, icon]. TAXII has its own entry in the demo.
export var NAV = [
  ['users', 'Users & roles', 'key'],
  ['engine', 'Caldera Engine', 'bolt'],
  ['intel', 'Threat Intel Connector', 'hash'],
  ['taxii', 'TAXII Connectors', 'plug'],
  ['art', 'ART Content Library', 'book'],
  ['audit', 'Audit Logs', 'file'],
  ['theme', 'Theme & Display', 'sun'],
  ['dashprefs', 'Dashboard Preferences', 'dash'],
  ['license', 'License', 'shield'],
  ['backup', 'Backup & Recovery', 'archive'],
];

var ROLE_LABELS = { admin: 'Admin', analyst: 'Analyst', viewer: 'Viewer' };
export function roleLabel(r) { return ROLE_LABELS[r] || String(r == null ? '' : r); }
// Admin purple, analyst blue, everything else grey (the demo's role tags).
export function roleTone(r) { return r === 'admin' ? 'violet' : r === 'analyst' ? 'info' : 'muted'; }

// stamp: "2026-10-15T17:30:00Z" -> "2026-10-15 17:30"; anything else is shown as given.
export function stamp(s) {
  var v = String(s == null ? '' : s);
  var m = v.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/);
  return m ? m[1] + ' ' + m[2] : v;
}

export function userStatus(u) { return u && u.isActive ? 'Active' : 'Disabled'; }

export function cellText(u, col) {
  switch (col) {
    case 0: return String(u.username || '');
    case 1: return roleLabel(u.role);
    case 2: return userStatus(u);
    case 3: return stamp(u.createdAt || '');
    default: return u.lastLogin ? stamp(u.lastLogin) : 'Never';
  }
}

export function filterUsers(rows, q) {
  var s = String(q || '').trim().toLowerCase();
  if (!s) return rows.slice();
  return rows.filter(function(u) {
    return USER_COLUMNS.map(function(c, i) { return cellText(u, i); }).join(' ').toLowerCase().indexOf(s) !== -1;
  });
}

// sortUsers: stable; "Never" signed in (no last login) always sorts last.
export function sortUsers(rows, col, dir) {
  if (col < 0) return rows.slice();
  var d = dir < 0 ? -1 : 1;
  var key = function(u) { var t = cellText(u, col); return col === 4 && !u.lastLogin ? null : t === '' ? null : t; };
  return rows.map(function(r, i) { return { r: r, i: i }; }).sort(function(a, b) {
    var u = key(a.r), v = key(b.r);
    var ue = u == null, ve = v == null;
    if (ue || ve) return ue && ve ? a.i - b.i : ue ? 1 : -1;
    return String(u).localeCompare(String(v), undefined, { numeric: true }) * d || a.i - b.i;
  }).map(function(o) { return o.r; });
}

export function csvRow(u, cols) { return cols.map(function(c) { return cellText(u, c); }); }
export function rangeCounts(shown, total) { return shown + ' of ' + total + ' rows'; }

export { pageCount, rangeText, csvText } from './runs-model.js';
