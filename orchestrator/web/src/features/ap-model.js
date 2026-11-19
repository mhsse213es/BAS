// Attack Paths page builders that follow the design demo: findings rows with tinted icon squares, the
// centred score card with its "Score breakdown" toggle, the three summary tiles and the graph age chip.
// Pure functions over the /api/attackpath/summary response; nothing is invented (a missing value shows an
// em dash or is left out). Dynamic text is escaped by x() or the kit.
import { x } from '../core/escape.js';
import { kpi, card, hbars, empty, icon } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';

function n0(v) { const n = Number(v); return isFinite(n) ? n : 0; }
export function scoreToneOf(s) {
  s = Number(s);
  return !isFinite(s) ? 'muted' : s >= 80 ? 'ok' : s >= 40 ? 'warn' : 'bad';
}
export function bandToneOf(b) {
  return b === 'Low' ? 'ok' : b === 'Medium' || b === 'High' ? 'warn' : b === 'Critical' ? 'bad' : 'muted';
}

// Graph age -> chip. Under a day is Fresh, under a week Aging, older Stale; unknown shows an em dash.
export function freshness(ageMs) {
  if (ageMs == null || !isFinite(ageMs) || ageMs < 0) return { label: '—', tone: 'muted' };
  const hours = ageMs / 3600000;
  if (hours < 24) return { label: 'Fresh', tone: 'ok' };
  if (hours < 24 * 7) return { label: 'Aging', tone: 'warn' };
  return { label: 'Stale', tone: 'bad' };
}

const HELP = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 015 .5c0 1.7-2.5 2-2.5 3.5M12 17v.01"/></svg>';
const FIND_ICON = { domain: 'alert', lateral: 'path', admin: 'user', ad: null, sessions: 'eye' };
const TONES = { bad: 1, warn: 1, info: 1, ok: 1, muted: 1 };

// items: [{ key, tone, text }]
export function findingRowsHtml(items) {
  return (items || []).map(function(i) {
    const ic = i.key === 'ad' ? HELP : icon(FIND_ICON[i.key] || 'check');
    return '<div class="ap-find"><span class="ap-ico tone-' + (TONES[i.tone] ? i.tone : 'muted') + '">' + ic + '</span><span>' + x(i.text) + '</span></div>';
  }).join('');
}

export function findingsCardHtml(items) {
  return card('Findings', findingRowsHtml(items));
}

// Centred score ring, value, caption and a toggle that reveals what drove the score (server-reported drivers).
export function scoreCardHtml(s) {
  s = s || {};
  const score = s.attackPathScore;
  const has = score != null && isFinite(Number(score));
  const tone = scoreToneOf(score);
  const drivers = s.scoreDrivers || [];
  let maxDef = 0;
  drivers.forEach(function(d) { maxDef = Math.max(maxDef, n0(d.deficit)); });
  const ring = has
    ? '<div class="donut-wrap">' + chartSlot({ type: 'donut', segments: [{ label: 'Score', value: n0(score), color: CHART_COLORS[tone] }, { label: 'Points lost', value: Math.max(0, 100 - n0(score)), color: 'var(--border)' }], center: n0(score) + '%', centerSub: '', h: 110 }) + '</div>'
    : empty('', 'No score yet');
  const breakdown = drivers.length
    ? '<div class="rk-hd-sub ap-bd-cap">Score points lost per driver</div>' + hbars(drivers.map(function(d) {
      const def = n0(d.deficit);
      return [d.label, maxDef ? (def / maxDef) * 100 : 0, def === 0 ? 'ok' : 'warn', def === 0 ? 'none' : '-' + def.toFixed(1)];
    }))
    : '<div class="rk-hd-sub">No score driver detail available.</div>';
  const body = '<div class="ap-score">' + ring +
    (has ? '<div class="ap-score-val tone-' + tone + '">' + x(score) + ' / 100</div>' : '') +
    '<div class="muted ap-score-cap">' + x((s.band || '—') + ' risk · higher is safer') + '</div>' +
    '<button class="btn btn-outline btn-sm ap-score-btn" id="ap-score-toggle" data-on-click="toggleAPScore">Score breakdown ▼</button>' +
    '<div id="ap-score-breakdown" class="ap-bd is-hidden">' + breakdown + '</div></div>';
  return card('Attack path score', body);
}

// Lateral movement, Domain compromise, Graph scope.
export function tileItems(s) {
  s = s || {};
  const status = s.domainCompromiseStatus || (s.domainCompromise ? 'reachable' : 'not-observed');
  const domLabel = status === 'reachable' ? 'Reachable' : status === 'not-observed' ? 'No path observed' : 'Undetermined';
  const domTone = status === 'reachable' ? 'bad' : status === 'not-observed' ? 'ok' : 'muted';
  const domSub = status === 'reachable' ? 'a host can reach Domain Admin' : status === 'not-observed' ? 'no path to Domain Admin in the collected graph' : 'Active Directory relationships were not collected';
  return [
    { label: 'Lateral movement', value: s.lateralMovementBand || '—', sub: 'Avg reach ' + n0(s.avgBlastRadius).toFixed(1) + ' hosts · max ' + n0(s.maxBlastRadius) + ' (from ' + (s.maxBlastEntry || 'entry host') + ')', icon: 'path', tone: bandToneOf(s.lateralMovementBand) },
    { label: 'Domain compromise', value: domLabel, sub: domSub, icon: 'alert', tone: domTone },
    { label: 'Graph scope', value: n0(s.hosts) + ' hosts', sub: n0(s.users) + ' users · ' + n0(s.groups) + ' groups · ' + n0(s.edges) + ' edges', icon: 'layers', tone: 'accent' },
  ];
}
export function tilesHtml(s) {
  return '<div class="rk-grid g3">' + tileItems(s).map(kpi).join('') + '</div>';
}

// Findings card beside the score card.
export function sideHtml(items, s) {
  return '<div class="ap-side">' + findingsCardHtml(items) + scoreCardHtml(s) + '</div>';
}
