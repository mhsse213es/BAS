// Agents page: the KPI strip, distribution cards and risk summary built from data the page already loads.
//
// Pure builders (no DOM, no network): the page passes in /api/agents items + fleet totals, and the
// /api/agents/risk-summary rows. Nothing is invented: every figure is a count or average over those rows.
import { x } from '../core/escape.js';
import { kpi, grid, card, hbars, empty } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

// osFamily collapses an osVersion string ("Windows 11 23H2", "Ubuntu 22.04") to a short family label.
export function osFamily(osVersion) {
  var s = String(osVersion || '').trim();
  if (!s) return 'Unknown';
  var l = s.toLowerCase();
  if (l.indexOf('windows server') === 0) return 'Windows Server';
  if (l.indexOf('windows') === 0) return 'Windows';
  if (l.indexOf('mac') === 0) return 'macOS';
  return s.split(/[\s/]+/)[0];
}

// tally counts values of fn(item) and returns [[label, count]] sorted high to low, capped at `top`.
export function tally(items, fn, top) {
  var m = {};
  (items || []).forEach(function(it) { var k = fn(it); m[k] = (m[k] || 0) + 1; });
  var out = Object.keys(m).map(function(k) { return [k, m[k]]; });
  out.sort(function(a, b) { return b[1] - a[1] || (a[0] < b[0] ? -1 : 1); });
  return top ? out.slice(0, top) : out;
}

// agentInsightStats derives every number the insight strip shows.
export function agentInsightStats(agents, totals) {
  var t = totals || {};
  var online = num(t.online), degraded = num(t.degraded), offline = num(t.offline), retired = num(t.retired);
  var fleet = online + degraded + offline;
  var list = agents || [];
  var live = list.filter(function(a) { return a && a.status !== 'offline'; });
  return {
    fleet: fleet, online: online, degraded: degraded, offline: offline, retired: retired,
    onlinePct: fleet ? Math.round(online / fleet * 100) : 0,
    attention: degraded + offline,
    channelDown: live.filter(function(a) { return !a.wsConnected; }).length,
    legacy: live.filter(function(a) { return a.transport === 'legacy'; }).length,
    loaded: list.length,
    os: tally(list, function(a) { return osFamily(a.osVersion); }, 5),
    groups: tally(list, function(a) { return a.groupName || 'Ungrouped'; }, 5),
  };
}

function distCard(title, rows, loaded) {
  if (!rows.length) return card(title, empty('server', 'No agents loaded yet'));
  var max = rows[0][1] || 1;
  return card(title, hbars(rows.map(function(r) { return [r[0], r[1] / max * 100, 'accent', String(r[1])]; })), { sub: loaded + ' loaded' });
}

// agentInsightsHtml renders the strip for the System Tree view.
export function agentInsightsHtml(agents, totals) {
  var s = agentInsightStats(agents, totals);
  var tiles = [
    kpi({ label: 'Fleet online', value: s.onlinePct + '%', sub: s.online + ' of ' + s.fleet + ' agents', icon: 'ok', tone: s.fleet && s.onlinePct < 80 ? 'warn' : 'ok', action: 'setAgentFilter', args: ['online'] }),
    kpi({ label: 'Needs attention', value: s.attention, sub: s.degraded + ' degraded, ' + s.offline + ' offline', icon: 'warn', tone: s.attention ? 'bad' : 'ok', action: 'setAgentFilter', args: [s.offline ? 'offline' : 'degraded'] }),
    kpi({ label: 'Task channel down', value: s.channelDown, sub: 'heartbeat reaches server, WebSocket does not', icon: 'alert', tone: s.channelDown ? 'warn' : 'ok' }),
    kpi({ label: 'Legacy transport', value: s.legacy, sub: s.legacy ? 'cannot receive signed commands' : 'all agents on mTLS', icon: 'shield', tone: s.legacy ? 'warn' : 'ok' }),
  ];
  var segs = [
    { label: 'Online', value: s.online, color: CHART_COLORS.ok },
    { label: 'Degraded', value: s.degraded, color: CHART_COLORS.warn },
    { label: 'Offline', value: s.offline, color: CHART_COLORS.bad },
    { label: 'Retired', value: s.retired, color: CHART_COLORS.muted },
  ].filter(function(g) { return g.value > 0; });
  var status = card('Fleet status', segs.length
    ? chartSlot({ type: 'donut', segments: segs, center: String(s.fleet), centerSub: 'agents', h: 150, legend: true })
    : empty('server', 'No agents registered yet'), { sub: 'whole fleet' });
  return grid(4, tiles) + grid(3, [status, distCard('Operating systems', s.os, s.loaded), distCard('Groups', s.groups, s.loaded)]);
}

// riskInsightStats: summary of /api/agents/risk-summary rows. An endpoint with nothing collected has no
// score (its healthScore is a mean over an empty set), so it is counted as "no data", never as a number.
export function riskInsightStats(rows) {
  var list = rows || [];
  var m = list.filter(function(a) { return a && a.measurable; });
  var sum = m.reduce(function(acc, a) { return acc + num(a.healthScore); }, 0);
  return {
    total: list.length,
    measurable: m.length,
    noData: list.length - m.length,
    avg: m.length ? Math.round(sum / m.length) : null,
    healthy: m.filter(function(a) { return num(a.healthScore) >= 80; }).length,
    fair: m.filter(function(a) { return num(a.healthScore) >= 50 && num(a.healthScore) < 80; }).length,
    poor: m.filter(function(a) { return num(a.healthScore) < 50; }).length,
    declining: list.filter(function(a) { return a && a.trend === 'Declining'; }).length,
    findings: list.reduce(function(acc, a) { return acc + num(a && a.openFindingsCount); }, 0),
    topIssues: tally(list.filter(function(a) { return a && a.topDeficitCategory; }), function(a) { return a.topDeficitCategory; }, 5),
  };
}

export function agentRiskInsightsHtml(rows) {
  var s = riskInsightStats(rows);
  if (!s.total) return '';
  var tiles = [
    kpi({ label: 'Average health', value: s.avg == null ? 'n/a' : s.avg, sub: s.measurable + ' endpoints measured', icon: 'shield', tone: s.avg == null ? 'muted' : s.avg >= 80 ? 'ok' : s.avg >= 50 ? 'warn' : 'bad' }),
    kpi({ label: 'Poor health', value: s.poor, sub: 'score below 50', icon: 'alert', tone: s.poor ? 'bad' : 'ok' }),
    kpi({ label: 'Declining', value: s.declining, sub: 'trend getting worse', icon: 'warn', tone: s.declining ? 'warn' : 'ok' }),
    kpi({ label: 'Open findings', value: s.findings, sub: 'across all endpoints', icon: 'file', tone: s.findings ? 'warn' : 'ok' }),
  ];
  var segs = [
    { label: 'Healthy (80+)', value: s.healthy, color: CHART_COLORS.ok },
    { label: 'Fair (50-79)', value: s.fair, color: CHART_COLORS.warn },
    { label: 'Poor (<50)', value: s.poor, color: CHART_COLORS.bad },
    { label: 'No data', value: s.noData, color: CHART_COLORS.muted },
  ].filter(function(g) { return g.value > 0; });
  var dist = card('Health distribution', chartSlot({ type: 'donut', segments: segs, center: String(s.total), centerSub: 'endpoints', h: 150, legend: true }));
  var issues = s.topIssues.length
    ? card('Top issue categories', hbars(s.topIssues.map(function(r) { return [r[0], r[1] / s.topIssues[0][1] * 100, 'warn', String(r[1])]; })), { sub: 'endpoints affected' })
    : card('Top issue categories', empty('shield', 'No deficits recorded'));
  return grid(4, tiles) + grid(2, [dist, issues]);
}

// migrationPanelHtml renders the legacy-transport migration status as a card.
export function migrationPanelHtml(status, fmtTime) {
  var st = status || {};
  var req = num(st.daysRequired), clean = num(st.daysClean);
  var pct = req ? Math.min(100, Math.round(clean / req * 100)) : 0;
  var blocking = (st.blockingAgents || []).map(function(a) {
    return '<div class="legacy-blocking-row"><span>' + x(a.hostname || a.agentId) + '</span><span class="legacy-blocking-time">' + x(fmtTime(a.lastSeen)) + '</span></div>';
  }).join('');
  var unattributed = st.unattributedRequests
    ? '<div class="legacy-unattributed-warning">&#9888; Unattributed legacy activity: ' + x(st.unattributedRequests.count) + ' request(s) — retirement blocked</div>' : '';
  return '<div class="legacy-migration-header">Legacy Transport Migration</div>' +
    '<div class="legacy-migration-days">Days clean: ' + x(clean) + ' / ' + x(req) + '</div>' +
    '<div class="rk-bar thick tone-' + (st.eligible ? 'ok' : 'warn') + ' rich-g5-migbar"><i data-w="' + pct + '"></i></div>' +
    '<div class="legacy-migration-status ' + (st.eligible ? 'eligible' : 'not-eligible') + '">' + (st.eligible ? 'ELIGIBLE FOR REVIEW' : 'NOT YET ELIGIBLE') + '</div>' +
    unattributed + (blocking ? '<div class="legacy-blocking-list">' + blocking + '</div>' : '');
}
