// Agents page: the KPI strip, distribution cards and risk summary built from data the page already loads.
//
// Pure builders (no DOM, no network): the page passes in /api/agents items + fleet totals, and the
// /api/agents/risk-summary rows. Nothing is invented: every figure is a count or average over those rows.
import { x } from '../core/escape.js';
import { kpi, grid, card, hbars, empty, icon } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { ring } from './runs-drawer.js';
import * as M from './agt-model.js';

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

// A metric tile in the demo's style: tinted icon square on the left, small uppercase label, big value,
// one-line caption, coloured top border.
export function tileHtml(o) {
  return '<div class="agt-tile agt-c-' + x(o.tone || 'accent') + '"><span class="agt-ico">' + icon(o.icon) + '</span><div class="agt-tb"><div class="agt-lbl">' + x(o.label) + '</div>' +
    '<div class="agt-val">' + x(o.value) + '</div>' + (o.caption ? '<div class="agt-cap">' + x(o.caption) + '</div>' : '') + '</div></div>';
}

function shareCard(title, rows, loadedNote, emptyText) {
  if (!rows.length) return card(title, empty('server', emptyText || 'No agents loaded yet'));
  return card(title, hbars(rows), loadedNote ? { sub: loadedNote } : undefined);
}

function loadedNote(list, totals) {
  var fleet = M.fleetCount(totals);
  return fleet > list.length ? list.length + ' of ' + fleet + ' loaded' : '';
}

function statusDonut(totals) {
  var tone = { online: CHART_COLORS.ok, degraded: CHART_COLORS.warn, offline: CHART_COLORS.bad, retired: CHART_COLORS.muted };
  var segs = M.statusSegments(totals).map(function(g) { return { label: g.label, value: g.value, color: tone[g.key] }; });
  var total = segs.reduce(function(a, g) { return a + g.value; }, 0);
  return segs.length
    ? chartSlot({ type: 'donut', segments: segs, center: String(total), centerSub: 'agents', h: 150, legend: true })
    : empty('server', 'No agents registered yet');
}

// agentInsightsHtml renders the three distribution cards of the System Tree view.
export function agentInsightsHtml(agents, totals) {
  var list = agents || [];
  var note = loadedNote(list, totals);
  return grid(3, [
    card('Status', statusDonut(totals)),
    shareCard('Operating systems', M.osShareRows(list), note),
    shareCard('Groups', M.groupShareRows(list, 5), note),
  ]);
}

// agentOperationalHtml renders the Operational view's tiles and its two cards.
export function agentOperationalHtml(agents, totals) {
  var list = agents || [];
  var tiles = M.opTiles(totals).map(tileHtml);
  var os = M.osDonut(list);
  var palette = [CHART_COLORS.accent, CHART_COLORS.ok, CHART_COLORS.violet, CHART_COLORS.warn, CHART_COLORS.teal, CHART_COLORS.pink, CHART_COLORS.muted];
  var osCard = card('Agents by OS', os.length
    ? chartSlot({ type: 'donut', segments: os.map(function(g, i) { return { label: g.label, value: g.value, color: palette[i % palette.length] }; }), center: String(list.length), centerSub: 'agents', h: 130, legend: true })
    : empty('server', 'No agents loaded yet'), loadedNote(list, totals) ? { sub: loadedNote(list, totals) } : undefined);
  var sims = M.simsRows(list, 6);
  var simCard = card('Simulations per agent', sims.length ? hbars(sims) : empty('play', 'No simulations dispatched yet', 'Run a scenario on an agent to see it here.'));
  return grid(4, tiles) + grid(2, [osCard, simCard]);
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

// migrationPanelHtml renders the legacy-transport migration status as the demo's card: a progress ring,
// the title with "Days clean: n / m", and the status tag on the right; the unattributed-activity warning
// and the blocking agents (real data the demo has no field for) sit underneath.
export function migrationPanelHtml(status, fmtTime) {
  var v = M.migrationView(status);
  var st = status || {};
  var blocking = (st.blockingAgents || []).map(function(a) {
    return '<div class="legacy-blocking-row"><span>' + x(a.hostname || a.agentId) + '</span><span class="legacy-blocking-time">' + x(fmtTime(a.lastSeen)) + '</span></div>';
  }).join('');
  var unattributed = st.unattributedRequests
    ? '<div class="legacy-unattributed-warning">&#9888; Unattributed legacy activity: ' + x(st.unattributedRequests.count) + ' request(s) — retirement blocked</div>' : '';
  return '<div class="agt-mig tone-' + v.tone + '"><div class="agt-mig-row">' +
    '<div class="agt-mig-l">' + ring(v.pct, v.tone) + '<div><b>Legacy transport migration</b><div class="muted agt-mig-days">Days clean: ' + x(v.clean) + ' / ' + x(v.required) + '</div></div></div>' +
    '<span class="agt-tag tone-' + v.tone + ' ' + (st.eligible ? 'eligible' : 'not-eligible') + '">' + x(v.label) + '</span></div>' +
    unattributed + (blocking ? '<div class="legacy-blocking-list">' + blocking + '</div>' : '') + '</div>';
}
