// Pure helpers for the redesigned Findings page: summary tiles, distribution cards, the filter row,
// table cells, CSV export and the detail drawer. No DOM, no network.
// Everything comes from what the page already loads: GET /api/findings (list) and
// GET /api/findings/{id} (detail with ATT&CK enrichment, product snapshot and variant breakdown).

var DAY = 864e5;

export var STATUSES = ['open', 'triaged', 'remediated', 'risk_accepted'];
export var STATUS_LABEL = { open: 'Open', triaged: 'Triaged', remediated: 'Remediated', risk_accepted: 'Risk-accepted' };
export var SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];

// Same palettes as the design demo: the first for the "open by severity" card in the summary row,
// the second for the severity donut under it.
var SEV_PALETTE = {
  row: { Critical: '#ef4444', High: '#f59e0b', Medium: '#3b82f6', Low: '#64748b' },
  card: { Critical: '#7f1d1d', High: '#ef4444', Medium: '#f59e0b', Low: '#10b981' },
};
var STATUS_COLOR = { open: '#f59e0b', triaged: '#3b82f6', remediated: '#10b981', risk_accepted: '#a78bfa' };

function ms(v) { var t = new Date(v).getTime(); return isNaN(t) ? null : t; }

export function normSev(s) {
  var t = String(s == null ? '' : s).toLowerCase();
  for (var i = 0; i < SEVERITIES.length; i++) if (SEVERITIES[i].toLowerCase() === t) return SEVERITIES[i];
  return '';
}
export function statusLabel(s) { return STATUS_LABEL[s] || String(s || '').replace('_', ' '); }
export function statusTone(s) { return s === 'open' ? 'bad' : s === 'remediated' ? 'ok' : s === 'triaged' ? 'warn' : 'muted'; }
export function sevTone(s) {
  var n = normSev(s);
  return n === 'Critical' ? 'bad' : n === 'High' ? 'warn' : n === 'Medium' ? 'info' : 'muted';
}

export function openOf(list) { return (list || []).filter(function(f) { return f.status === 'open'; }); }

// ageDays: whole days a finding has been (or was) exposed. Remediated findings measure first seen -> resolved.
export function ageDays(f, now) {
  var first = ms(f && f.firstSeen);
  if (first == null) return 0;
  var end = f.status === 'remediated' && f.resolvedAt ? ms(f.resolvedAt) : now;
  if (end == null) end = now;
  return Math.max(0, Math.floor((end - first) / DAY));
}
// ageLabel: "2 h" / "3 d" like the demo's Age column; "(fixed)" for remediated findings.
export function ageLabel(f, now) {
  var first = ms(f && f.firstSeen);
  if (first == null) return '—';
  var end = f.status === 'remediated' && f.resolvedAt ? ms(f.resolvedAt) : now;
  if (end == null) end = now;
  var h = Math.max(0, Math.floor((end - first) / 36e5));
  var t = h < 24 ? h + ' h' : Math.floor(h / 24) + ' d';
  return f.status === 'remediated' ? t + ' (fixed)' : t;
}

// tileStats: the five summary tiles.
export function tileStats(list, now) {
  var l = list || [];
  var openL = openOf(l);
  var maxAge = 0;
  openL.forEach(function(f) { var a = ageDays(f, now); if (a > maxAge) maxAge = a; });
  var since = now - 30 * DAY;
  return {
    total: l.length,
    open: openL.length,
    maxAge: maxAge,
    critical: openL.filter(function(f) { return f.severity === 'Critical'; }).length,
    reopened: openL.filter(function(f) { return f.reopenedCount > 0; }).length,
    remediated30: l.filter(function(f) { return f.status === 'remediated' && ms(f.lastSeen) != null && ms(f.lastSeen) >= since; }).length,
  };
}
export function ageTone(maxAge) { return maxAge >= 90 ? 'bad' : maxAge >= 30 ? 'warn' : 'ok'; }

var BUCKETS = [['0–7d', 0, 7], ['8–14d', 8, 14], ['15–30d', 15, 30], ['31–90d', 31, 90], ['90d+', 91, Infinity]];
// ageBuckets: how long the open findings have been open -> [{label, value}] (every bucket kept, zero or not).
export function ageBuckets(openList, now) {
  var out = BUCKETS.map(function(b) { return { label: b[0], value: 0 }; });
  (openList || []).forEach(function(f) {
    var a = ageDays(f, now);
    for (var i = 0; i < BUCKETS.length; i++) if (a >= BUCKETS[i][1] && a <= BUCKETS[i][2]) { out[i].value++; break; }
  });
  return out;
}

// controlRows: where open findings concentrate by expected control class -> kit.hbars rows.
export function controlRows(openList, limit) {
  var m = {};
  (openList || []).forEach(function(f) { var k = f.controlClass || 'Unknown'; m[k] = (m[k] || 0) + 1; });
  var pairs = Object.keys(m).map(function(k) { return [k, m[k]]; })
    .sort(function(a, b) { return b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0); })
    .slice(0, limit || 5);
  var max = pairs.length ? pairs[0][1] : 0;
  return pairs.map(function(p, i) { return [p[0], max ? p[1] / max * 100 : 0, i < 2 ? 'bad' : i < 4 ? 'warn' : 'info', String(p[1])]; });
}

// sevSegments: donut segments in fixed severity order, zero buckets dropped.
export function sevSegments(list, which) {
  var pal = SEV_PALETTE[which] || SEV_PALETTE.row;
  var c = {};
  (list || []).forEach(function(f) { var s = normSev(f.severity); if (s) c[s] = (c[s] || 0) + 1; });
  return SEVERITIES.filter(function(s) { return c[s]; }).map(function(s) { return { label: s, value: c[s], color: pal[s] }; });
}
// statusSegments: donut segments for the status split of every finding.
export function statusSegments(list) {
  var c = {};
  (list || []).forEach(function(f) { var k = f.status || 'unknown'; c[k] = (c[k] || 0) + 1; });
  return STATUSES.filter(function(s) { return c[s]; }).map(function(s) { return { label: STATUS_LABEL[s], value: c[s], color: STATUS_COLOR[s] }; });
}

// statusOptions: status filter chips with counts (All first).
export function statusOptions(list) {
  var l = list || [];
  return [{ id: 'all', label: 'All', count: l.length }].concat(STATUSES.map(function(s) {
    return { id: s, label: STATUS_LABEL[s], count: l.filter(function(f) { return f.status === s; }).length };
  }));
}
// sevOptions: severity filter chips as in the demo (no counts).
export function sevOptions() {
  return [{ id: 'all', label: 'All severities' }].concat(SEVERITIES.map(function(s) { return { id: s, label: s }; }));
}

// filterFindings: status + severity + free text over the demo's searchable fields (title, asset, id) plus technique.
export function filterFindings(list, f) {
  f = f || {};
  var q = String(f.q == null ? '' : f.q).trim().toLowerCase();
  return (list || []).filter(function(r) {
    if (f.status && f.status !== 'all' && r.status !== f.status) return false;
    if (f.sev && f.sev !== 'all' && r.severity !== f.sev) return false;
    if (!q) return true;
    return [r.techniqueName, r.techniqueId, r.agentId, r.controlClass, r.severity, r.id, r.tactic].some(function(v) {
      return String(v == null ? '' : v).toLowerCase().indexOf(q) !== -1;
    });
  });
}

// shortId: long generated ids are cut for the ID column (full id stays in the cell title).
export function shortId(id) {
  var s = String(id == null ? '' : id);
  return s.length > 13 ? s.slice(0, 8) : s;
}
// subline: the grey second line under a finding title (tactic and expected control).
export function subline(f) {
  return [f.tactic, f.controlClass ? f.controlClass + ' control' : ''].filter(Boolean).join(' · ');
}

// csvText: header + rows as RFC 4180 CSV (every field quoted); a leading = + - @ is neutralised.
export function csvText(header, rows) {
  var q = function(v) {
    var s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  };
  return [header].concat(rows).map(function(r) { return r.map(q).join(','); }).join('\n');
}
export var CSV_HEADER = ['ID', 'Finding', 'Severity', 'Agent', 'Technique', 'Tactic', 'Control', 'Status', 'First seen', 'Last seen', 'Age'];
export function csvRows(list, now) {
  return (list || []).map(function(f) {
    return [f.id, f.techniqueName || f.techniqueId, f.severity, f.agentId, f.techniqueId, f.tactic, f.controlClass,
      statusLabel(f.status), f.firstSeen, f.lastSeen, ageLabel(f, now)];
  });
}

// ── Detail drawer ───────────────────────────────────────────────────────────

// factRows: the key/value block under the chips.
export function factRows(f, now) {
  var list = function(a) { return (a || []).join(', '); };
  var rows = [
    ['Technique', [f.techniqueId, f.techniqueName].filter(Boolean).join(' ')],
    ['Tactic', f.tactic || ''],
    ['Expected control', f.controlClass || ''],
    ['Asset', f.agentId || ''],
    ['Installed product', list(f.productSnapshot)],
    ['Source', f.sourceType || ''],
    ['Occurrences', f.occurrenceCount != null ? String(f.occurrenceCount) + (f.reopenedCount > 0 ? ' · reopened ' + f.reopenedCount + '×' : '') : ''],
    ['Age', ageLabel(f, now)],
  ];
  return rows.filter(function(r) { return r[1]; });
}
// evidenceLines: the "validation step output" block, built only from fields the finding carries.
export function evidenceLines(f) {
  var ex = f.exposureState === 'detected_only' ? 'detected only (not prevented)' : f.exposureState === 'missed' ? 'missed (neither prevented nor detected)' : f.exposureState || '';
  var vb = f.variantBreakdown;
  var lines = [
    ['exposure', ex],
    ['technique', f.techniqueId || ''],
    ['control', f.controlClass || ''],
    ['variants', vb && vb.total > 0 ? vb.prevented + ' of ' + vb.total + ' blocked' : ''],
    ['last run', f.lastRunId || ''],
    ['first seen', f.firstSeen || ''],
    ['last seen', f.lastSeen || ''],
  ];
  return lines.filter(function(r) { return r[1]; });
}
// recommendation: mitigations (and detection guidance) from the finding's ATT&CK enrichment.
export function recommendation(f) {
  var e = (f && f.enrichment) || {};
  return {
    mitigations: (e.mitigations || []).slice(0, 3).map(function(m) { return { name: m.name || '', description: m.description || '' }; }).filter(function(m) { return m.name; }),
    detection: e.detection || '',
  };
}
// related: jump links shown under the drawer body. Each is {icon, label, sub, action, args}.
export function related(f) {
  var out = [];
  if (f.techniqueId) out.push({ icon: 'mapped', label: 'Technique ' + f.techniqueId, sub: 'Open coverage detail', action: 'fndTech', args: [f.techniqueId] });
  if (f.agentId) out.push({ icon: 'server', label: 'Asset ' + shortId(f.agentId), sub: 'Open agents', action: 'fndGo', args: ['agents'] });
  out.push({ icon: 'wrench', label: 'Remediation', sub: 'Prioritised fixes for open findings', action: 'fndGo', args: ['remediation'] });
  return out;
}
