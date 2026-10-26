// Settings sub-tabs: KPI strips and small charts built from the data each section's loader already fetched.
//
// Every builder is pure (data in, markup out). Nothing here fetches anything and nothing is invented:
// each figure is a count, share or difference over the rows the section itself shows. The render* helpers
// write into a container that index.html declares inside the section, and do nothing if it is not on screen.
import { kpi, grid, card, hbars } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { x } from '../core/escape.js';

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const put = (id, html) => { var el = document.getElementById(id); if (el) el.innerHTML = html; };
const ROLE_TEXT = {
  admin: 'Full access: manage users, agents and settings; run anything.',
  analyst: 'Launch runs and campaigns, triage findings, author scenarios.',
  viewer: 'Read-only access to results, coverage and reports.',
};

// ── Users & roles ──
export function userStats(users) {
  var list = Array.isArray(users) ? users : [];
  var by = { admin: 0, analyst: 0, viewer: 0 };
  list.forEach(function(u) { if (u && by[u.role] != null) by[u.role]++; });
  return {
    total: list.length,
    active: list.filter(function(u) { return u && u.isActive; }).length,
    disabled: list.filter(function(u) { return u && !u.isActive; }).length,
    pwReset: list.filter(function(u) { return u && u.mustChangePw; }).length,
    neverLoggedIn: list.filter(function(u) { return u && !u.lastLogin; }).length,
    by: by,
  };
}
export function usersInsightsHtml(users) {
  var s = userStats(users);
  var tiles = [
    kpi({ label: 'Users', value: s.total, sub: s.active + ' active', icon: 'users', tone: 'accent' }),
    kpi({ label: 'Administrators', value: s.by.admin, sub: s.by.admin > 3 ? 'consider fewer admin accounts' : 'full-access accounts', icon: 'key', tone: s.by.admin > 3 ? 'warn' : 'info' }),
    kpi({ label: 'Disabled', value: s.disabled, sub: 'cannot sign in', icon: 'x', tone: s.disabled ? 'muted' : 'ok' }),
    kpi({ label: 'Password reset pending', value: s.pwReset, sub: s.neverLoggedIn + ' never signed in', icon: 'alert', tone: s.pwReset ? 'warn' : 'ok' }),
  ];
  var roles = ['admin', 'analyst', 'viewer'].map(function(r) {
    return card(r.charAt(0).toUpperCase() + r.slice(1), '<div class="rk-role-n">' + x(s.by[r]) + ' <span>' + (s.by[r] === 1 ? 'user' : 'users') + '</span></div><p class="rk-role-d">' + x(ROLE_TEXT[r]) + '</p>', { sub: 'role permissions' });
  });
  return grid(4, tiles) + grid(3, roles);
}
export function renderUsersInsights(users) { put('users-insights', usersInsightsHtml(users)); }

// ── Caldera engine ──
export function calderaInsightsHtml(d) {
  d = d || {};
  var state = d.reachable ? ['Connected', 'ok'] : d.httpStatus === 401 ? ['Auth error', 'warn'] : ['Unreachable', 'bad'];
  var tiles = [
    kpi({ label: 'Engine', value: state[0], sub: d.version ? 'version ' + d.version : '', icon: 'server', tone: state[1] }),
    kpi({ label: 'Abilities', value: d.reachable ? num(d.abilityCount).toLocaleString() : 'n/a', sub: d.reachable && d.uniqueTechniques ? num(d.uniqueTechniques) + ' unique techniques' : '', icon: 'play', tone: d.reachable ? 'accent' : 'muted' }),
    kpi({ label: 'Adversary profiles', value: d.reachable ? num(d.adversaryCount) : 'n/a', icon: 'users', tone: d.reachable ? 'info' : 'muted' }),
    kpi({ label: 'Latency', value: d.reachable ? num(d.latencyMs) + ' ms' : 'n/a', sub: 'last status check', icon: 'refresh', tone: d.reachable && num(d.latencyMs) > 1000 ? 'warn' : 'ok' }),
  ];
  var plugins = d.byPlugin ? Object.keys(d.byPlugin).sort(function(a, b) { return num(d.byPlugin[b]) - num(d.byPlugin[a]); }) : [];
  var top = plugins.length ? num(d.byPlugin[plugins[0]]) || 1 : 1;
  var body = d.reachable && plugins.length
    ? card('Abilities by plugin', hbars(plugins.slice(0, 8).map(function(p) { return [p, num(d.byPlugin[p]) / top * 100, 'accent', num(d.byPlugin[p]).toLocaleString()]; })))
    : '';
  return grid(4, tiles) + body;
}
export function renderCalderaInsights(d) { put('caldera-insights', calderaInsightsHtml(d)); }

// ── ART content ──
export function artInsightsHtml(d) {
  d = d || {};
  var loaded = d.techniquesLoaded != null ? num(d.techniquesLoaded) : num(d.techniqueCount);
  var win = num(d.windowsRunnable);
  var missing = num(d.missingPayloadCount);
  var tiles = [
    kpi({ label: 'Techniques loaded', value: loaded.toLocaleString(), sub: d.techniqueCount != null && num(d.techniqueCount) !== loaded ? num(d.techniqueCount) + ' recorded at last seed: mismatch' : (d.seeded ? 'seeded' : 'not seeded'), icon: 'database', tone: d.techniqueCount != null && num(d.techniqueCount) !== loaded ? 'warn' : d.seeded ? 'ok' : 'warn' }),
    kpi({ label: 'Windows atomic tests', value: num(d.testCount).toLocaleString(), sub: win + ' of ' + loaded + ' techniques Windows-runnable', icon: 'play', tone: 'accent' }),
    kpi({ label: 'Payloads indexed', value: num(d.payloadCount).toLocaleString(), sub: missing ? missing + ' referenced but not indexed' : 'none missing', icon: 'file', tone: missing ? 'warn' : 'ok' }),
    kpi({ label: 'Known-exploited CVEs', value: num(d.kevCount).toLocaleString(), sub: 'CISA KEV catalogue', icon: 'alert', tone: 'info' }),
  ];
  var runnable = loaded ? card('Windows coverage of loaded techniques', hbars([['Windows-runnable', win / loaded * 100, 'ok', win + ' / ' + loaded], ['Linux/macOS only', (loaded - win) / loaded * 100, 'muted', String(Math.max(0, loaded - win))]])) : '';
  return grid(4, tiles) + runnable;
}
export function renderArtInsights(d) { put('art-insights', artInsightsHtml(d)); }

// ── Threat intel ──
export function intelInsightsHtml(s) {
  s = s || {};
  var sources = [['MISP', s.mispEnabled], ['OpenCTI', s.openctiEnabled], ['OTX', s.otxEnabled], ['Air-gap bundle', s.bundleEnabled]];
  var on = sources.filter(function(r) { return r[1]; });
  var st = s.lastSyncStatus || 'never';
  var tiles = [
    kpi({ label: 'Sources enabled', value: on.length + ' / ' + sources.length, sub: on.length ? on.map(function(r) { return r[0]; }).join(', ') : 'none configured', icon: 'cloud', tone: on.length ? 'ok' : 'muted' }),
    kpi({ label: 'Last sync', value: st, sub: s.lastSyncAt ? new Date(s.lastSyncAt).toLocaleString() : 'no sync yet', icon: 'refresh', tone: st === 'ok' ? 'ok' : st === 'error' ? 'bad' : 'muted' }),
    kpi({ label: 'Scenarios created', value: num(s.scenariosCreated), sub: 'by the sync scheduler', icon: 'plus', tone: 'accent' }),
    kpi({ label: 'Scenarios updated', value: num(s.scenariosUpdated), sub: s.nextSyncAt ? 'next sync ' + new Date(s.nextSyncAt).toLocaleString() : '', icon: 'file', tone: 'info' }),
  ];
  return grid(4, tiles);
}
export function renderIntelInsights(s) { put('intel-insights', intelInsightsHtml(s)); }

// ── Audit logs (the page of records on screen) ──
export function auditStats(entries) {
  var list = Array.isArray(entries) ? entries : [];
  var actors = {}, actions = {};
  list.forEach(function(e) {
    if (!e) return;
    actors[e.actorName || e.actor || '-'] = true;
    actions[e.action || '-'] = (actions[e.action || '-'] || 0) + 1;
  });
  var top = Object.keys(actions).map(function(k) { return [k, actions[k]]; });
  top.sort(function(a, b) { return b[1] - a[1] || (a[0] < b[0] ? -1 : 1); });
  return {
    total: list.length,
    failed: list.filter(function(e) { return e && e.outcome && e.outcome !== 'ok'; }).length,
    actors: Object.keys(actors).length,
    top: top.slice(0, 5),
  };
}
export function auditInsightsHtml(entries, labels) {
  var s = auditStats(entries);
  if (!s.total) return '';
  var tiles = [
    kpi({ label: 'Records on this page', value: s.total, icon: 'file', tone: 'accent' }),
    kpi({ label: 'Failed outcomes', value: s.failed, sub: s.failed ? 'denied or errored' : 'all succeeded', icon: 'alert', tone: s.failed ? 'bad' : 'ok' }),
    kpi({ label: 'Distinct users', value: s.actors, icon: 'users', tone: 'info' }),
  ];
  var lab = labels || {};
  var top = card('Most frequent actions', hbars(s.top.map(function(r) { return [lab[r[0]] || r[0], r[1] / s.top[0][1] * 100, 'accent', String(r[1])]; })), { sub: 'this page' });
  return grid(3, tiles) + top;
}
export function renderAuditInsights(entries, labels) { put('audit-insights', auditInsightsHtml(entries, labels)); }

// ── License ──
export function daysUntil(dateStr, nowMs) {
  var t = Date.parse(dateStr);
  if (!Number.isFinite(t)) return null;
  return Math.ceil((t - (nowMs == null ? Date.now() : nowMs)) / 86400000);
}
export function licenseInsightsHtml(lic, nowMs) {
  lic = lic || {};
  var tone = lic.status === 'valid' ? 'ok' : lic.status === 'grace' ? 'warn' : lic.status === 'locked' ? 'bad' : 'muted';
  var label = lic.status === 'valid' ? 'Active' : lic.status === 'grace' ? 'Grace period' : lic.status === 'locked' ? 'Locked' : 'Unknown';
  var days = daysUntil(lic.expiresAt, nowMs);
  var products = (lic.productLines || []).length;
  var features = (lic.features || []).length;
  var tiles = [
    kpi({ label: 'Entitlement', value: label, sub: lic.customer || '', icon: 'shield', tone: tone }),
    kpi({ label: days != null && days < 0 ? 'Expired' : 'Days to expiry', value: days == null ? 'n/a' : Math.abs(days), sub: lic.expiresAt || '', icon: 'calendar', tone: days == null ? 'muted' : days < 0 ? 'bad' : days <= 30 ? 'warn' : 'ok' }),
    kpi({ label: 'Tier', value: lic.tier || 'n/a', icon: 'key', tone: lic.tier ? 'accent' : 'muted' }),
    kpi({ label: 'Licensed products', value: products, sub: features + ' feature flag' + (features === 1 ? '' : 's'), icon: 'layers', tone: 'info' }),
  ];
  return grid(4, tiles);
}
export function renderLicenseInsights(lic) { put('license-insights', licenseInsightsHtml(lic)); }

// ── Backup & recovery ──
export function backupStats(jobs) {
  var list = Array.isArray(jobs) ? jobs : [];
  var sized = list.filter(function(j) { return j && num(j.archiveSizeBytes) > 0; });
  return {
    total: list.length,
    protectedN: list.filter(function(j) { return j && j.status === 'protected'; }).length,
    localOnly: list.filter(function(j) { return j && j.status === 'local_success'; }).length,
    failed: list.filter(function(j) { return j && (j.status === 'failed' || j.status === 'remote_failed'); }).length,
    sizesMb: sized.slice(0, 12).reverse().map(function(j) { return Math.round(num(j.archiveSizeBytes) / 1048576 * 10) / 10; }),
    labels: sized.slice(0, 12).reverse().map(function(j) { var d = new Date(j.requestedAt); return Number.isNaN(d.getTime()) ? '?' : (d.getMonth() + 1) + '/' + d.getDate(); }),
    latest: list[0] || null,
  };
}
export function backupInsightsHtml(jobs) {
  var s = backupStats(jobs);
  var latestSize = s.latest && num(s.latest.archiveSizeBytes) ? (num(s.latest.archiveSizeBytes) / 1048576).toFixed(1) + ' MB' : 'n/a';
  var tiles = [
    kpi({ label: 'Backups', value: s.total, sub: s.protectedN + ' protected (local and remote)', icon: 'database', tone: s.total ? 'accent' : 'muted' }),
    kpi({ label: 'Local only', value: s.localOnly, sub: s.localOnly ? 'no remote copy' : 'none', icon: 'cloud', tone: s.localOnly ? 'warn' : 'ok' }),
    kpi({ label: 'Failed', value: s.failed, icon: 'alert', tone: s.failed ? 'bad' : 'ok' }),
    kpi({ label: 'Latest archive', value: latestSize, sub: s.latest ? String(s.latest.trigger || '') : 'no backups yet', icon: 'file', tone: 'info' }),
  ];
  var chart = s.sizesMb.length > 1
    ? card('Archive size, most recent backups', chartSlot({ type: 'bar', labels: s.labels, series: [{ name: 'Size (MB)', data: s.sizesMb, color: CHART_COLORS.accent }], h: 150 }), { sub: 'MB' })
    : '';
  return grid(4, tiles) + chart;
}
export function renderBackupInsights(jobs) { put('backup-insights', backupInsightsHtml(jobs)); }

// ── Simulation coverage card: what the base-simulation total is made of ──
export function simMixHtml(parts) {
  var rows = (parts || []).filter(function(p) { return p && num(p[1]) > 0; });
  var total = rows.reduce(function(a, p) { return a + num(p[1]); }, 0);
  if (!total) return '';
  return hbars(rows.map(function(p) { return [p[0], num(p[1]) / total * 100, 'accent', num(p[1]).toLocaleString()]; }));
}
export function renderSimMix(parts) { put('sim-mix', simMixHtml(parts)); }
