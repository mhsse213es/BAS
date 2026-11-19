// Campaigns: KPI strip and result charts above the campaigns table, computed from the
// summary objects /api/campaigns already returns for each campaign.
import { kpi, grid, card, empty } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';

export function campaignStats(list) {
  var s = { total: 0, running: 0, paused: 0, byStatus: {}, targets: 0, dispatched: 0, skipped: 0, prevented: 0, detected: 0, missed: 0 };
  (list || []).forEach(function(c) {
    var m = (c && c.summary) || {};
    s.total++;
    var st = String(m.status || 'unknown').toLowerCase();
    if (st === 'running' && m.paused) { s.paused++; st = 'paused'; } else if (st === 'running') s.running++;
    s.byStatus[st] = (s.byStatus[st] || 0) + 1;
    s.targets += Number(m.targets) || 0;
    s.dispatched += Number(m.dispatched) || 0;
    s.skipped += Number(m.skipped) || 0;
    s.prevented += Number(m.prevented) || 0;
    s.detected += Number(m.detected) || 0;
    s.missed += Number(m.missed) || 0;
  });
  var tested = s.prevented + s.detected + s.missed;
  s.tested = tested;
  s.preventedPct = tested ? Math.round(s.prevented / tested * 100) : null;
  return s;
}

var TONE = { running: CHART_COLORS.accent, paused: CHART_COLORS.warn, completed: CHART_COLORS.ok, partial: CHART_COLORS.warn, failed: CHART_COLORS.bad, stopped: CHART_COLORS.muted, empty: CHART_COLORS.muted };

export function campaignSummaryHTML(list) {
  var s = campaignStats(list);
  if (!s.total) return '';
  var statusSegs = Object.keys(s.byStatus).sort().map(function(k) { return { label: k.charAt(0).toUpperCase() + k.slice(1), value: s.byStatus[k], color: TONE[k] || CHART_COLORS.info }; });
  var mixSegs = [
    { label: 'Prevented', value: s.prevented, color: CHART_COLORS.ok },
    { label: 'Detected only', value: s.detected, color: CHART_COLORS.warn },
    { label: 'Missed', value: s.missed, color: CHART_COLORS.bad }
  ];
  return grid(4, [
    kpi({ label: 'Campaigns', value: s.total, sub: s.running ? s.running + ' running now' : 'none running', icon: 'campaign', tone: 'accent' }),
    kpi({ label: 'Agents targeted', value: s.targets, sub: s.dispatched + ' dispatched' + (s.skipped ? ' · ' + s.skipped + ' skipped' : ''), icon: 'agents', tone: 'info' }),
    kpi({ label: 'Prevented', value: s.preventedPct == null ? '—' : s.preventedPct + '%', sub: s.tested ? 'of ' + s.tested + ' tested technique results' : 'no results yet', icon: 'shield', tone: s.preventedPct == null ? 'muted' : s.preventedPct >= 70 ? 'ok' : s.preventedPct >= 40 ? 'warn' : 'bad' }),
    kpi({ label: 'Missed', value: s.missed, sub: s.missed ? 'techniques that got through' : 'nothing missed', icon: 'alert', tone: s.missed ? 'bad' : 'ok' })
  ]) + grid(2, [
    card('Campaigns by status', chartSlot({ type: 'donut', segments: statusSegs, center: String(s.total), centerSub: 'campaigns', h: 170, legendRight: true })),
    card('Result mix across campaigns', s.tested ? chartSlot({ type: 'donut', segments: mixSegs, center: s.preventedPct + '%', centerSub: 'prevented', h: 170, legendRight: true }) : empty('shield', 'No results yet', 'Result mix appears once campaign runs report outcomes.'))
  ]);
}
