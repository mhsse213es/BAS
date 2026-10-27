// Renderers for the redesigned Dashboard (operational view). The page skeleton lives in index.html
// (every card has a fixed cell, in the same order as the design demo); each loader hands its data to
// a setter here, and the setter re-renders only the cells that depend on it. Until a source answers
// (or if it fails) its cells show an honest empty state, never a made-up number.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { kpi, card, chip, pill, bar, hbars, empty, icon, checkRow } from '../core/kit.js';
import { sevTone } from './rich-g3.js';
import * as M from './dash-model.js';

var D = {
  runs: null, findings: null, campaigns: null, agents: null, compliance: null, posture: null,
  kev: null, ti: null, readiness: null, alerts: null, schedules: null, rr: null, itsm: null,
};
var RUN_BY_ID = {};
export function dashRunById(id) { return RUN_BY_ID[id] || null; }

function cell(id, html) { var el = document.getElementById(id); if (el) el.innerHTML = html; }
var link = function(label, action, args) {
  return '<button type="button" class="rk-link"' + on.apply(null, ['click', action].concat(args || [])) + '>' + x(label) + '</button>';
};
var tab = function(label, t) { return link(label, 'showTab', [t]); };
var toneOf = function(p) { return p >= 80 ? 'ok' : p >= 50 ? 'warn' : 'bad'; };
var colorOf = function(t) { return CHART_COLORS[t] || CHART_COLORS.accent; };
var PCT = function(n) { return Math.round(n) + '%'; };
var emptyCard = function(title, ic, msg, sub, o) { return card(title, empty(ic, msg, sub), o); };

function ring(pct, size, stroke, color, big, small) {
  var r = (size - stroke) / 2, c = size / 2, C = 2 * Math.PI * r, len = Math.max(0, Math.min(100, pct)) / 100 * C;
  return '<svg viewBox="0 0 ' + size + ' ' + size + '" width="' + size + '" height="' + size + '" class="chart-svg dp-ring">' +
    '<circle cx="' + c + '" cy="' + c + '" r="' + r + '" fill="none" class="track" stroke-width="' + stroke + '"/>' +
    '<circle cx="' + c + '" cy="' + c + '" r="' + r + '" fill="none" stroke="' + color + '" stroke-width="' + stroke + '" stroke-linecap="round" stroke-dasharray="' + len + ' ' + C + '" transform="rotate(-90 ' + c + ' ' + c + ')"/>' +
    (big != null ? '<text x="' + c + '" y="' + (small ? c : c + 5) + '" text-anchor="middle" class="donut-v dp-ring-v">' + x(big) + '</text>' : '') +
    (small ? '<text x="' + c + '" y="' + (c + 16) + '" text-anchor="middle" class="donut-l">' + x(small) + '</text>' : '') + '</svg>';
}
export function gaugeRing(pct, color, big, small) { return ring(pct, 136, 14, color, big, small); }

function miniLine(vals, color) {
  var v = vals.length > 1 ? vals : (vals.length ? [vals[0], vals[0]] : []);
  if (!v.length) return '<span class="muted tiny">—</span>';
  var lo = Math.min.apply(null, v), hi = Math.max.apply(null, v), rg = hi - lo || 1;
  var xy = v.map(function(n, i) { return [4 + i * (110 / (v.length - 1)), 24 - (n - lo) / rg * 18]; });
  var d = xy.map(function(p, i) { return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join(' ');
  var e = xy[xy.length - 1];
  return '<svg width="118" height="30" viewBox="0 0 118 30" class="dp-mini"><path d="' + d + '" fill="none" stroke="' + color + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><circle cx="' + e[0].toFixed(1) + '" cy="' + e[1].toFixed(1) + '" r="3" fill="' + color + '"/></svg>';
}

// ── KPI row ────────────────────────────────────────────────────────────────
function renderKpis() {
  var runs = D.runs || [], tiles = [];
  var f = D.findings, open = f ? f.filter(function(r) { return r.status === 'open'; }) : null;
  var sevN = function(r, s) { return String(r.severity || '').toLowerCase() === s; };
  tiles.push(kpi({ label: 'Open findings', value: open ? open.length : '—', icon: 'flag', tone: open && open.length ? 'bad' : 'ok', action: 'showTab', args: ['findings'],
    sub: open ? (open.length ? open.filter(function(r) { return sevN(r, 'critical') || sevN(r, 'high'); }).length + ' critical / high' : 'none open') : 'loading',
    spark: f ? M.openFindingsSeries(f, Date.now(), 8) : null }));
  var maxAge = 0, oldest = null;
  (open || []).forEach(function(r) {
    var age = Math.max(0, Math.floor((Date.now() - new Date(r.firstSeen)) / 86400000));
    if (age >= maxAge) { maxAge = age; oldest = r; }
  });
  tiles.push(kpi({ label: 'Attack surface age', value: open ? maxAge + 'd' : '—', icon: 'clock', tone: maxAge >= 90 ? 'bad' : maxAge >= 30 ? 'warn' : 'ok', action: 'showTab', args: ['findings'],
    sub: open ? (open.length && oldest ? 'oldest open weakness: ' + (oldest.techniqueId || 'unknown') : 'no open weaknesses') : 'oldest open weakness',
    spark: f ? M.oldestOpenAgeSeries(f, Date.now(), 8) : null }));
  var pw = M.postureWindow(runs, 8);
  var caveat = pw && M.testedTactics(runs) / M.ENTERPRISE_TACTICS.length < 0.5;
  tiles.push(kpi({ label: 'Prevention score', value: pw ? pw.pct + '%' : '—', icon: 'shield', tone: pw ? toneOf(pw.pct) : 'muted', action: 'showTab', args: ['runs'],
    sub: pw ? (caveat ? 'Based on ' + M.testedTactics(runs) + '/' + M.ENTERPRISE_TACTICS.length + ' ATT&CK tactics tested'
      : (pw.trend === 'Improving' ? '▲ ' : pw.trend === 'Degrading' ? '▼ ' : '— ') + 'across last ' + pw.count + ' run' + (pw.count === 1 ? '' : 's')) : 'no runs yet',
    spark: pw ? pw.series : null }));
  var cv = M.coverage(runs);
  tiles.push(kpi({ label: 'ATT&CK coverage', value: cv.tested ? cv.pct + '%' : '—', icon: 'technique', tone: cv.tested ? toneOf(cv.pct) : 'muted', action: 'showTab', args: ['runs'],
    sub: cv.tested + ' technique' + (cv.tested === 1 ? '' : 's') + ' tested', spark: cv.tested ? cv.series : null }));
  var live = (D.campaigns || []).filter(function(c) { return c.summary && c.summary.status === 'running'; });
  tiles.push(kpi({ label: 'Active campaigns', value: D.campaigns ? live.length : '—', icon: 'campaign', tone: live.length ? 'info' : 'muted', action: 'showTab', args: ['campaigns'],
    sub: live.length ? '● ' + live[0].name + (live.length > 1 ? ' +' + (live.length - 1) : '') + ' running' : 'none running',
    spark: D.campaigns ? M.startedPerWeek(D.campaigns, Date.now(), 8) : null }));
  cell('dop-kpis', tiles.join(''));
}

// ── Regulatory compliance ──────────────────────────────────────────────────
export function complianceCard(fw) {
  var pct = fw.compliancePct || 0, cov = fw.coveragePct || 0, tested = fw.testedControls || 0;
  var passing = fw.passingControls || 0, failing = fw.failingControls || 0;
  var untested = fw.untestedControls != null ? fw.untestedControls : ((fw.testableControls || 0) - tested);
  var has = tested > 0;
  var t = !has ? 'muted' : pct >= 75 ? 'ok' : pct >= 50 ? 'warn' : 'bad';
  var title = fw.frameworkName + '\n' + (has ? pct + '% compliant — ' + passing + ' of ' + tested + ' tested controls passing, ' + failing + ' failing, ' + untested + ' untested.' : 'No controls tested yet.');
  return '<div class="rk-reg rk-click tone-' + t + '"' + on('click', 'openComplianceDetail', fw.frameworkId, fw.agentId) + ' title="' + x(title) + '">' +
    '<div class="rk-reg-h"><b>' + x(String(fw.shortName || '').toUpperCase()) + '</b><span>' + x(fw.regulator) + '</span></div>' +
    '<div class="rk-reg-v">' + (has ? PCT(pct) : '—') + '</div>' +
    (has ? bar(cov, toneOf(cov)) : bar(0, 'muted')) +
    '<div class="rk-reg-m">' + (has ? PCT(cov) + ' coverage · ' + (fw.totalControls || 0) + ' controls' : 'No runs yet') + '</div>' +
    (has ? '<div class="rk-reg-m">' + passing + ' pass · ' + failing + ' fail · ' + untested + ' untested</div>' : '') +
    (has && failing > 0 ? '<div class="rk-reg-n">Any 1 failed test fails the control — see breakdown</div>' : '') +
    (has && cov < 50 ? '<div class="rk-reg-n">Only ' + PCT(cov) + ' of testable controls covered</div>' : '') + '</div>';
}
function renderCompliance() {
  var s = D.compliance;
  if (!s || !s.length) {
    cell('compliance-tiles', card('', empty('shield', s ? 'No compliance data yet' : 'Loading compliance scores…', s ? 'Run a scenario to generate scores.' : ''), { cls: 'dp-wide' }));
    return;
  }
  cell('compliance-tiles', s.slice().sort(function(a, b) { return String(a.shortName).toLowerCase() < String(b.shortName).toLowerCase() ? -1 : 1; }).map(complianceCard).join(''));
}

// ── Threat intelligence ────────────────────────────────────────────────────
var tierTone = function(t) { return t === 'Critical' ? 'bad' : t === 'High' ? 'warn' : t === 'Medium' ? 'info' : 'muted'; };
function renderActors() {
  var ti = D.ti, actors = ti ? (ti.topActors || []).slice(0, 5) : [];
  var head = tab('Prioritization →', 'threat-priority');
  var hist = {};
  ((D.readiness && D.readiness.trends) || []).forEach(function(t) { hist[String(t.actorName).toLowerCase()] = M.actorHistory(t); });
  if (!actors.length) { cell('dop-actors', emptyCard('Top threat actors', 'users', ti ? 'No prioritised threat actors yet' : 'Loading…', ti ? 'Scores appear once threat-intel connectors have synced.' : '', { actions: head })); return; }
  cell('dop-actors', card('Top threat actors', actors.map(function(a, i) {
    var hi = a.tier === 'Critical' || a.tier === 'High';
    var tr = a.trend && a.trend !== 'stable' ? (a.trend === 'rising' || a.trend === 'up' ? '▲ ' : '▼ ') + (a.trendDelta ? Math.abs(a.trendDelta) + ' · ' : '') + a.trend : (a.trend || '');
    return '<div class="ta-row"' + on('click', 'openThreatPriorityActor', a.actorName) + '>' +
      '<span class="ta-rank">' + (i + 1) + '</span><span class="ta-av' + (hi ? ' hi' : '') + '">' + x(M.initials(a.actorName)) + '</span>' +
      '<div class="ta-main"><div class="ta-name"><b>' + x(a.actorName) + '</b>' + chip(a.tier || '—', tierTone(a.tier)) + '</div>' +
      '<div class="muted tiny">' + x(a.canonicalGroupId ? 'MITRE ' + a.canonicalGroupId : 'Prioritised threat actor') + '</div>' +
      '<div class="ta-meta"><span>' + icon('mapped') + ' ' + (a.techniqueCount || 0) + ' techniques</span><span class="ta-gap">' + icon('alert') + ' ' + (a.coverageGapCount || 0) + ' validated gaps</span></div></div>' +
      '<div class="ta-spark">' + (function() {
        var h = hist[String(a.actorName).toLowerCase()] || [];
        if (h.length > 1) return miniLine(h, colorOf(hi ? 'warn' : 'accent')) + '<span class="muted">prevention history</span>';
        return '<span class="muted">' + x(tr ? 'priority trend' : '') + '</span><b class="ta-tr">' + x(tr || '—') + '</b>';
      })() + '</div>' +
      '<div class="ta-score"><div class="ta-bar"><i data-w="' + Math.min(100, Math.round(a.score)) + '" data-bg="' + colorOf(hi ? 'warn' : 'accent') + '"></i></div><b>' + x(a.score) + '</b><span class="muted">relevance</span></div>' +
      icon('chevron') + '</div>';
  }).join(''), { actions: head, cls: 'dp-actors' }));
}
function renderKev() {
  var k = D.kev, ti = D.ti;
  var btn = '<button type="button" class="btn btn-primary btn-sm dp-block"' + on('click', 'loadKEVPack') + '>' + icon('bolt') + ' Create KEV Pack</button>';
  if (!k || !k.hasData) { cell('dop-kev', card('KEV exposure', empty('shield', k ? 'No KEV data yet' : 'Loading…', k ? 'Sync the CISA KEV catalogue in Settings to see exposure.' : '') + btn)); return; }
  var total = k.totalKevCves || 0, rw = Math.min(k.ransomwareCount || 0, total);
  var kevTech = ti && ti.kevExposedTechniques != null ? ti.kevExposedTechniques : k.techniqueCount;
  cell('dop-kev', card('KEV exposure',
    chartSlot({ type: 'donut', h: 150, center: total, centerSub: 'KEV CVEs', segments: [
      { label: 'Ransomware-linked', value: rw, color: CHART_COLORS.bad }, { label: 'Other KEV CVEs', value: total - rw, color: CHART_COLORS.info }] }) +
    '<div class="dp-mini2"><div><span>KEV-linked techniques</span><b>' + x(kevTech) + '</b></div><div><span>Ransomware-linked</span><b>' + x(rw) + '</b></div></div>' + btn));
}
function renderPrevTrend() {
  var r = D.readiness, s = r ? M.preventionSeries(r.trends) : { labels: [], data: [] };
  if (s.data.length < 2) { cell('dop-actprev', emptyCard('Actor activity vs. your prevention', 'trend', r ? 'No data yet' : 'Loading…', r ? 'Needs two or more recorded readiness runs.' : '', {})); return; }
  cell('dop-actprev', card('Actor activity vs. your prevention', chartSlot({ type: 'line', labels: s.labels, h: 130, yMax: 100, suffix: '%', series: [{ name: 'Your prevention', data: s.data, color: CHART_COLORS.ok }] }) +
    '<div class="rk-note">Prevention is the mean across tracked threat actors. The external actor-activity feed is not connected.</div>',
    { actions: '<div class="legend"><span class="lg"><i class="dl-sw" data-bg="' + CHART_COLORS.ok + '"></i>Prevention</span></div>' }));
}

// ── Endpoint posture ───────────────────────────────────────────────────────
function renderEndpoint() {
  var p = D.posture;
  var agentsLink = tab('Open agents →', 'agents');
  cell('dop-ep-link', agentsLink);
  if (!p || !p.totalAgents) {
    var msg = p ? 'No agents enrolled yet' : 'Loading…';
    cell('dop-ep-online', emptyCard('', 'agents', msg));
    cell('dop-ep-life', emptyCard('', 'agents', msg));
  } else {
    var pct = p.totalAgents ? p.onlineAgents / p.totalAgents * 100 : 0;
    var flags = (p.untrustedBinaryCount > 0 ? chip(p.untrustedBinaryCount + ' untrusted binar' + (p.untrustedBinaryCount === 1 ? 'y' : 'ies'), 'bad') + ' ' : '') +
      (p.currentlyIsolated > 0 ? chip(p.currentlyIsolated + ' isolated', 'warn') : '');
    cell('dop-ep-online', '<section class="rk-card dp-ep"><div class="dp-lbl">ONLINE / OFFLINE</div><div class="dp-ep-body">' +
      ring(pct, 76, 7, colorOf(toneOf(pct)), Math.round(pct) + '%') +
      '<div><div class="dp-big"><span class="dp-ok">' + x(p.onlineAgents) + '</span> / <span class="dp-bad">' + x(p.offlineAgents) + '</span></div><div class="muted tiny">' + x(p.totalAgents) + ' total agents</div></div></div>' +
      (flags ? '<div class="dp-flags">' + flags + '</div>' : '') + '</section>');
    cell('dop-ep-life', '<section class="rk-card dp-ep"><div class="dp-lbl">LIFECYCLE</div>' + chartSlot({ type: 'donut', h: 150, center: p.activeAgents, centerSub: 'agents', segments: [
      { label: 'Active', value: p.activeAgents, color: CHART_COLORS.ok }, { label: 'Restricted', value: p.restrictedAgents, color: CHART_COLORS.warn },
      { label: 'Quarantined', value: p.quarantinedAgents, color: CHART_COLORS.bad }, { label: 'Retired', value: p.retiredAgents, color: CHART_COLORS.muted }] }) + '</section>');
  }
  var gh = M.groupHealth(D.agents);
  cell('dop-ep-groups', '<section class="rk-card dp-ep"><div class="dp-lbl">HEALTH BY GROUP</div>' + (gh.length ? '<div class="dp-pad">' + hbars(gh.map(function(g) { return [g.name, g.pct, toneOf(g.pct + 0)]; })) + '</div>' : empty('agents', D.agents ? 'No agents yet' : 'Loading…')) + '</section>');
  renderAgentHealth(gh);
}
function renderAgentHealth(gh) {
  cell('dop-agh', gh.length ? card('Agent health by group', hbars(gh.map(function(g) { return [g.name, g.pct, g.pct >= 90 ? 'ok' : g.pct >= 75 ? 'warn' : 'bad', g.online + '/' + g.total]; })), { sub: 'agents online' })
    : emptyCard('Agent health by group', 'agents', D.agents ? 'No agents yet' : 'Loading…'));
}

// ── Readiness trends ───────────────────────────────────────────────────────
function renderReadiness() {
  var r = D.readiness, tr = r ? r.trends || [] : [];
  var pills = document.getElementById('dop-rt-pills');
  if (pills) {
    var up = tr.filter(function(t) { return t.direction === 'up'; }).length, dn = tr.filter(function(t) { return t.direction === 'down'; }).length;
    pills.innerHTML = tr.length ? '<span class="up">▲ ' + up + ' improved</span><span class="down">▼ ' + dn + ' regressed</span><span class="flat">' + x(r.total != null ? r.total : tr.length) + ' actors tracked</span>' : '';
  }
  if (!tr.length) {
    var m = r ? 'No readiness history yet' : 'Loading…', sub = r ? 'Run a threat-actor scenario to start the trend.' : '';
    cell('dop-rt-table', emptyCard('Threat actor prevention trend', 'trend', m, sub));
    cell('dop-rt-bars', emptyCard('Prevention by actor', 'shield', m, sub));
    return;
  }
  var rows = tr.slice().sort(function(a, b) { return a.latestPrevention - b.latestPrevention; }).slice(0, 10);
  cell('dop-rt-table', card('Threat actor prevention trend', '<div class="tbl-wrap"><table><thead><tr><th>Threat actor</th><th>Prevention</th><th>Trend</th><th>History</th><th class="num">Runs</th></tr></thead><tbody>' +
    rows.map(function(t) {
      var d = Math.round(t.preventionDelta || 0);
      var ch = t.direction === 'up' ? chip('▲ +' + Math.abs(d), 'ok') : t.direction === 'down' ? chip('▼ −' + Math.abs(d), 'bad') : chip('no change', 'muted');
      var hist = M.actorHistory(t);
      return '<tr><td><div class="dp-act"><span class="ta-av sm">' + x(M.initials(t.actorName)) + '</span><b>' + x(t.actorName) + '</b></div></td>' +
        '<td class="dp-prog"><div class="rk-hbar dp-hb">' + bar(t.latestPrevention, toneOf(t.latestPrevention)) + '<span class="rk-hbar-v">' + PCT(t.latestPrevention) + '</span></div></td><td>' + ch + '</td>' +
        '<td>' + miniLine(hist, colorOf(t.direction === 'down' ? 'bad' : t.direction === 'up' ? 'ok' : 'muted')) + '</td><td class="muted num">' + x(t.dataPoints) + ' run' + (t.dataPoints === 1 ? '' : 's') + '</td></tr>';
    }).join('') + '</tbody></table></div>', { flush: true }));
  cell('dop-rt-bars', card('Prevention by actor', hbars(rows.map(function(t) { return [t.actorName, t.latestPrevention, toneOf(t.latestPrevention)]; })) + '<div class="rk-note">Latest validated run per actor.</div>'));
}

// ── Posture score / Control effectiveness ──────────────────────────────────
function runBarsSvg(runs) {
  var n = runs.length, W = 560, H = 100, slot = W / n, bw = Math.min(42, slot - 10), out = '';
  runs.forEach(function(r, i) {
    var v = M.prevPctOf(r), h = Math.max(2, v * 0.7), x0 = i * slot + (slot - bw) / 2, d = new Date(r.completedAt || r.startedAt);
    out += '<rect x="' + x0.toFixed(1) + '" y="' + (78 - h).toFixed(1) + '" width="' + bw.toFixed(1) + '" height="' + h.toFixed(1) + '" rx="3" fill="' + colorOf(toneOf(v)) + '" data-tip="' + x(v + '%') + '"/>' +
      '<text x="' + (x0 + bw / 2).toFixed(1) + '" y="94" text-anchor="middle" class="axis-t">' + (isNaN(d) ? '' : (d.getMonth() + 1) + '/' + d.getDate()) + '</text>';
  });
  return '<svg viewBox="0 0 ' + W + ' ' + H + '" class="chart-svg dp-pbars" role="img" aria-label="Prevention per run">' + out + '</svg>';
}
function renderPosture() {
  var pw = M.postureWindow(D.runs || [], 8), scored = M.scoredRuns(D.runs || []);
  if (!pw) { cell('dop-posture', emptyCard('Posture score', 'shield', D.runs ? 'No scored runs yet' : 'Loading…', D.runs ? 'Run a scenario to compute a prevention score.' : '')); return; }
  var t = toneOf(pw.pct), bars = scored.slice(0, 6).reverse();
  var tt = pw.trend === 'Improving' ? 'ok' : pw.trend === 'Degrading' ? 'warn' : 'muted';
  cell('dop-posture', card('Posture score', '<div class="dp-posture">' + gaugeRing(pw.pct, colorOf(t), pw.pct, 'out of 100') +
    '<div class="dp-posture-r"><div class="dp-two"><div><div class="dp-lbl">TREND</div><b class="dp-tone tone-' + tt + '">' + x(pw.trend) + '</b></div>' +
    '<div class="dp-right"><div class="dp-lbl">VS TARGET</div><b class="dp-tone tone-muted">—</b> <span class="muted tiny">no target set</span></div></div>' +
    runBarsSvg(bars) + '<p class="muted tiny">Prevention across the last ' + bars.length + ' validated run' + (bars.length === 1 ? '' : 's') + '.</p></div></div>'));
}
function renderCE() {
  var e = M.effectiveness(D.runs || []);
  if (!e.total) { cell('dop-ce', emptyCard('Control effectiveness', 'shield', D.runs ? 'No run data yet' : 'Loading…')); return; }
  var base = e.prevented + e.detected + e.missed || 1;
  var segs = [{ label: 'Prevented', value: e.prevented, color: CHART_COLORS.ok }];
  if (e.detected > 0) segs.push({ label: 'Detected only', value: e.detected, color: CHART_COLORS.info });
  segs.push({ label: 'Missed', value: e.missed, color: CHART_COLORS.bad });
  if (e.other > 0) segs.push({ label: 'Not tested', value: e.other, color: CHART_COLORS.muted });
  var oc = M.openByControl(D.findings);
  cell('dop-ce', card('Control effectiveness', chartSlot({ type: 'donut', h: 150, center: Math.round(e.prevented / base * 100) + '%', centerSub: 'PREVENTED', segments: segs }) +
    (e.detected === 0 ? '<div class="rk-note">Detected-only appears once a SIEM/EDR integration is reporting alerts.</div>' : '') +
    (oc.length ? '<div class="dp-sub">Open findings by expected control</div>' + hbars(oc.slice(0, 5).map(function(r) { return [r[0], r[1] / oc[0][1] * 100, 'bad', String(r[1])]; })) : '')));
}

// ── Campaigns / gaps / runs / failing techniques ───────────────────────────
function renderLive() {
  var cs = D.campaigns, live = (cs || []).filter(function(c) { return c.summary && c.summary.status === 'running'; });
  var dot = '<span class="dot-live' + (live.length ? '' : ' idle') + '"></span> ';
  var head = '<span class="rk-hd-t">' + dot + 'Live campaigns</span>';
  var body = !live.length ? '<div class="muted">' + (cs ? 'No campaigns running.' : 'Loading…') + '</div>' : live.map(function(c) {
    var s = c.summary || {};
    return '<div class="rk-check rk-click"' + on('click', 'openCampaignDetail', c.id) + '><div class="rk-check-t"><b>' + x(c.name) + '</b><span>' + x((c.scenarioName || '') + ' · ' + (s.dispatched || 0) + '/' + (s.targets || 0) + ' agents') + '</span>' + bar(s.progress || 0, 'info') + '</div>' +
      '<div class="rk-check-r">' + chip((s.progress || 0) + '%', 'info') + '</div></div>';
  }).join('');
  cell('dop-live', '<section class="rk-card"><div class="rk-hd"><h2>' + head + '</h2><div class="rk-hd-actions">' + tab('View all →', 'campaigns') + '</div></div>' + body + '</section>');
}
function renderGaps() {
  var f = D.findings, open = f ? f.filter(function(r) { return r.status === 'open'; }).slice(0, 5) : [];
  var head = tab('View all →', 'findings');
  if (!open.length) { cell('dop-gaps', emptyCard('Top exposure gaps', 'check', f ? 'No open findings' : 'Loading…', '', { actions: head })); return; }
  cell('dop-gaps', card('Top exposure gaps', open.map(function(r) {
    var age = Math.max(0, Math.floor((Date.now() - new Date(r.firstSeen)) / 86400000));
    return '<div class="rk-check rk-click"' + on('click', 'openFindingFromDashboard', r.id) + '>' + chip(r.severity || '—', sevTone(r.severity)) +
      '<div class="rk-check-t"><b>' + x(r.techniqueName || r.techniqueId) + '</b><span>' + x((r.techniqueId || '') + ' · ' + (r.hostname || r.agentId || '') + ' · open ' + (age ? age + ' d' : 'today')) + '</span></div></div>';
  }).join(''), { actions: head }));
}
var STATUS_TONE = { completed: 'ok', running: 'info', failed: 'bad', partial: 'warn', queued: 'warn', requested: 'warn', cancelled: 'muted', paused: 'warn' };
var cap = function(s) { s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); };
function runTable(id, title, runs, action) {
  var head = tab('View all →', 'runs');
  if (!runs.length) { cell(id, emptyCard(title, 'play', D.runs ? 'No runs yet' : 'Loading…', '', { actions: head })); return; }
  cell(id, card(title, '<div class="tbl-wrap"><table><thead><tr><th>Run</th><th>Target</th><th>Status</th></tr></thead><tbody>' + runs.slice(0, 5).map(function(r) {
    var paused = r.status === 'running' && r.paused;
    return '<tr class="rk-click"' + on('click', action, r.id) + '><td><div>' + x(r.name || r.scenarioId) + '</div><div class="mono muted tiny">' + x(r.id) + '</div></td><td class="muted">' + x(r.hostname || r.agentId || '—') + '</td>' +
      '<td>' + pill(paused ? 'Paused' : cap(r.status), paused ? 'warn' : STATUS_TONE[r.status] || 'muted') + '</td></tr>';
  }).join('') + '</tbody></table></div>', { flush: true, actions: head }));
}
function renderRuns() { var r = D.runs || []; runTable('dop-runs', 'Recent runs', r, 'openDashRun'); runTable('dop-valruns', 'Recent validation runs', r, 'openDashRun'); }
function renderFails() {
  var t = M.topFailing(D.runs || [], 5), head = tab('View all →', 'attack-coverage');
  if (!t.length) { cell('dop-fails', emptyCard('Top failing techniques', 'check', D.runs ? 'No failures recorded' : 'Loading…', D.runs ? 'Every tested technique was prevented.' : '', { actions: head })); return; }
  cell('dop-fails', card('Top failing techniques', '<div class="tbl-wrap"><table><thead><tr><th>Technique</th><th>Failures</th><th>Coverage</th></tr></thead><tbody>' + t.map(function(r) {
    return '<tr><td><div>' + x(r.name) + '</div><div class="mono muted tiny">' + x(r.id) + '</div></td><td>' + chip(r.fail + '×', 'bad') + '</td>' +
      '<td class="dp-prog"><div class="rk-hbar dp-hb">' + bar(r.pct, toneOf(r.pct)) + '<span class="rk-hbar-v">' + PCT(r.pct) + '</span></div></td></tr>';
  }).join('') + '</tbody></table></div>', { flush: true, actions: head }));
}
function renderCovGaps() {
  var g = M.coverageGaps(D.runs || [], 5);
  if (!g.length) { cell('dop-covgaps', emptyCard('Top coverage gaps', 'check', D.runs ? 'No coverage gaps' : 'Loading…', D.runs ? 'No technique failed in any run.' : '')); return; }
  cell('dop-covgaps', card('Top coverage gaps', hbars(g.map(function(r) { return [r.id + ' ' + r.name, r.pct, toneOf(r.pct)]; }))));
}

// ── Attack flow / ransomware / tactics ─────────────────────────────────────
function renderFlow() {
  var f = M.flowByTactic(D.runs || []);
  if (!f.length) { cell('dop-flow', emptyCard('Attack flow', 'path', D.runs ? 'No completed runs yet' : 'Loading…')); return; }
  var lg = '<div class="legend"><span class="lg"><i class="dl-sw" data-bg="' + CHART_COLORS.ok + '"></i>Prevented</span><span class="lg"><i class="dl-sw" data-bg="' + CHART_COLORS.info + '"></i>Detected</span><span class="lg"><i class="dl-sw" data-bg="' + CHART_COLORS.bad + '"></i>Missed</span></div>';
  cell('dop-flow', card('Attack flow', chartSlot({ type: 'bar', stacked: true, h: 210, labels: f.map(function(r) { return M.tacticLabel(r.tactic); }), series: [
    { name: 'Prevented', color: CHART_COLORS.ok, data: f.map(function(r) { return r.prevented; }) },
    { name: 'Detected', color: CHART_COLORS.info, data: f.map(function(r) { return r.detected; }) },
    { name: 'Missed', color: CHART_COLORS.bad, data: f.map(function(r) { return r.missed; }) }] }), { actions: lg }));
}
// m = { phase:'none'|'loading'|'error'|'ok', score, label, tone, desc, rows:[{title,state,text}], gate }
export function renderRansomwareCard(m) {
  var btn = '<button type="button" class="btn btn-primary btn-sm dp-block" id="rr-run-btn"' + on('click', 'runRansomwareDrill') + '>' + icon('play') + ' Run Drill</button>';
  var title = 'Ransomware readiness';
  if (!m || m.phase !== 'ok') {
    var msg = !m || m.phase === 'loading' ? 'Loading…' : m.phase === 'error' ? 'Score unavailable for the latest run' : 'No readiness score yet';
    cell('dop-rr', card(title, empty('shield', msg, !m || m.phase === 'none' ? 'Run the Ransomware Drill to see your readiness score.' : '') + btn));
    return;
  }
  cell('dop-rr', card(title, '<div class="dp-rr"><div class="dp-rr-s tone-' + m.tone + '">' + x(m.score) + '<small>/100</small></div><div class="muted tiny">' + x(m.desc) + '</div></div>' +
    m.rows.map(function(r) { return checkRow(r.state, r.title, '', pill(r.text, r.state)); }).join('') +
    (m.gate ? '<div class="rk-note dp-bad">⚠ ' + x(m.gate) + '</div>' : '') + btn, { actions: m.label ? chip(m.label, m.tone) : '' }));
}
function renderTactics() {
  var t = M.tacticRows(D.runs || []), head = tab('Open matrix →', 'coverage');
  if (!t.length) { cell('dop-tactics', emptyCard('ATT&CK tactic coverage', 'mapped', D.runs ? 'No run data yet' : 'Loading…', '', { actions: head })); return; }
  cell('dop-tactics', card('ATT&CK tactic coverage', '<div class="dp-2col">' + t.map(function(r) { return hbars([[M.tacticLabel(r.tactic), r.pct, toneOf(r.pct)]]); }).join('') + '</div>', { actions: head }));
}

// ── Detection rate / daily validations ─────────────────────────────────────
function renderDetDaily() {
  var days = M.dailySeries(D.runs || [], 30, Date.now());
  var withData = days.filter(function(d) { return d.rate != null; });
  if (withData.length < 2) {
    cell('dop-det', emptyCard('Detection rate — last 30 days', 'trend', D.runs ? 'No data yet' : 'Loading…', D.runs ? 'Needs validations on two or more days.' : ''));
  } else {
    cell('dop-det', card('Detection rate — last 30 days', chartSlot({ type: 'line', h: 190, yMax: 100, suffix: '%', area: true, labels: withData.map(function(d) { return d.label; }),
      series: [{ name: 'Detected', data: withData.map(function(d) { return d.rate; }), color: CHART_COLORS.accent }] }),
      { actions: '<div class="legend"><span class="lg"><i class="dl-sw" data-bg="' + CHART_COLORS.accent + '"></i>Prevented + detected</span></div>' }));
  }
  if (!days.some(function(d) { return d.total; })) { cell('dop-daily', emptyCard('Daily validations', 'play', D.runs ? 'No validations in 30 days' : 'Loading…')); return; }
  var lg = '<div class="legend"><span class="lg"><i class="dl-sw" data-bg="' + CHART_COLORS.ok + '"></i>Prevented</span><span class="lg"><i class="dl-sw" data-bg="' + CHART_COLORS.info + '"></i>Detected</span><span class="lg"><i class="dl-sw" data-bg="' + CHART_COLORS.bad + '"></i>Missed</span></div>';
  cell('dop-daily', card('Daily validations', chartSlot({ type: 'bar', stacked: true, h: 190, labels: days.map(function(d) { return d.label; }), series: [
    { name: 'Prevented', color: CHART_COLORS.ok, data: days.map(function(d) { return d.prevented; }) },
    { name: 'Detected', color: CHART_COLORS.info, data: days.map(function(d) { return d.detected; }) },
    { name: 'Missed', color: CHART_COLORS.bad, data: days.map(function(d) { return d.missed; }) }] }), { actions: lg }));
}

// ── Alerts / activity / up next ────────────────────────────────────────────
var SEV_ICON = { critical: 'alert', error: 'alert', warning: 'alert', info: 'bell' };
function renderAlerts() {
  var a = D.alerts;
  if (!a || !a.length) { cell('dop-alerts', emptyCard('Recent alerts', 'bell', a ? 'No alerts' : 'Loading…', a ? 'Notifications raised by scheduled assessments appear here.' : '')); return; }
  cell('dop-alerts', card('Recent alerts', a.slice(0, 5).map(function(e) {
    var sev = String(e.Severity || e.severity || 'info').toLowerCase(), ts = new Date(e.Timestamp || e.timestamp).getTime();
    var t = sev === 'critical' || sev === 'error' ? 'bad' : sev === 'warning' ? 'warn' : 'info';
    return '<div class="dp-feed"><span class="dp-fi tone-' + t + '">' + icon(SEV_ICON[sev] || 'alert') + '</span><div><b>' + x(e.Message || e.message) + '</b><span>' + x(String(e.Type || e.type || '').replace(/_/g, ' ') + (isNaN(ts) ? '' : ' · ' + M.shortAgo(ts))) + '</span></div></div>';
  }).join('')));
}
function renderActivity() {
  var items = M.activityFeed(D.runs || [], D.findings || [], 6);
  if (!items.length) { cell('dop-activity', emptyCard('Activity', 'clock', D.runs ? 'No activity yet' : 'Loading…')); return; }
  cell('dop-activity', card('Activity', '<div class="dp-feedlist">' + items.map(function(i) {
    return '<a class="dp-feed rk-click"' + on('click', i.action, i.arg) + '><span class="dp-fi tone-' + i.tone + '">' + icon(i.icon) + '</span><div><b>' + x(i.title) + '</b><span>' + x(i.desc) + '</span></div><time>' + x(M.shortAgo(i.ms)) + '</time></a>';
  }).join('') + '</div>', { sub: 'newest first' }));
}
var DOW = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
export function scheduleWhen(s, nowMs) {
  var type = s.RecurrenceType || 'weekly';
  if (type === 'once') { var t = new Date(s.RunAt).getTime(); return isNaN(t) ? '—' : t > nowMs ? 'in ' + durText(t - nowMs) : 'ran ' + M.shortAgo(t, nowMs); }
  if (type === 'daily') return 'Daily · ' + (s.TimeOfDay || '—');
  if (type === 'monthly') return 'Monthly · day ' + s.DayOfMonth + ' · ' + (s.TimeOfDay || '—');
  return 'Weekly · ' + (DOW[s.DayOfWeek] || '—').slice(0, 3) + ' · ' + (s.TimeOfDay || '—');
}
function durText(ms) { var m = Math.floor(ms / 60000), h = Math.floor(m / 60), d = Math.floor(h / 24); return d ? d + ' d ' + (h % 24) + ' h' : h ? h + ' h ' + (m % 60) + ' m' : m + ' m'; }
function renderNext() {
  var s = D.schedules, head = tab('All →', 'scheduled-assessments');
  var act = (s || []).filter(function(r) { return r.Enabled && !(r.RecurrenceType === 'once' && (r.LastOccurrenceAt || new Date(r.RunAt) < Date.now())); });
  if (!act.length) { cell('dop-next', emptyCard('Up next', 'clock', s ? 'Nothing scheduled' : 'Loading…', s ? 'Create a scheduled assessment to see it here.' : '', { actions: head })); return; }
  cell('dop-next', card('Up next', act.slice(0, 5).map(function(r) {
    var gs = (r.GroupIDs || []).length, as = (r.AgentIDs || []).length;
    var tgt = [gs ? gs + ' group' + (gs === 1 ? '' : 's') : '', as ? as + ' agent' + (as === 1 ? '' : 's') : ''].filter(Boolean).join(' + ') || '—';
    return '<div class="dp-feed dp-next"><span class="dp-fi tone-accent">' + icon('clock') + '</span><div><b>' + x((r.Payload && (r.Payload.scenarioName || r.Payload.scenarioId)) || r.ID) + '</b><span>' + x(cap(r.Mode || 'posture') + ' · ' + tgt) + '</span><span class="countdown">' + x(scheduleWhen(r, Date.now())) + '</span></div></div>';
  }).join(''), { actions: head }));
}

// ── ITSM (kept from the earlier dashboard; shown only when connectors report tickets) ──
function renderITSM() {
  var s = D.itsm, sec = document.getElementById('dash-itsm-section');
  if (!sec) return;
  var open = s ? s.openTickets || 0 : 0, res = s ? s.resolvedTickets || 0 : 0, pend = s ? s.pendingRevalidation || 0 : 0;
  if (!s || (open + res + pend === 0 && !(s.byProvider && s.byProvider.length))) { sec.hidden = true; return; }
  sec.hidden = false;
  var tiles = [kpi({ label: 'Open tickets', value: open, tone: open ? 'warn' : 'ok' }), kpi({ label: 'Resolved tickets', value: res, tone: 'ok' }),
    kpi({ label: 'Pending revalidation', value: pend, tone: pend ? 'bad' : 'muted' })];
  (s.byProvider || []).forEach(function(p) { tiles.push(kpi({ label: p.provider, value: p.count, tone: 'accent' })); });
  cell('dash-itsm-tiles', tiles.join(''));
}

// ── Public API ─────────────────────────────────────────────────────────────
export function renderDashAll() {
  renderKpis(); renderCompliance(); renderActors(); renderKev(); renderPrevTrend(); renderEndpoint(); renderReadiness();
  renderPosture(); renderCE(); renderLive(); renderGaps(); renderRuns(); renderFails(); renderFlow(); renderTactics();
  renderDetDaily(); renderCovGaps(); renderAlerts(); renderActivity(); renderNext(); renderITSM();
  if (!D.rr) renderRansomwareCard(null);
}
export function setDashRuns(runs) {
  D.runs = runs || [];
  RUN_BY_ID = {};
  D.runs.forEach(function(r) { RUN_BY_ID[r.id] = r; });
  renderKpis(); renderPosture(); renderCE(); renderRuns(); renderFails(); renderFlow(); renderTactics(); renderDetDaily(); renderCovGaps(); renderActivity();
}
export function setDashFindings(f) { D.findings = f || []; renderKpis(); renderGaps(); renderCE(); renderActivity(); }
export function setDashCampaigns(c) { D.campaigns = c || []; renderKpis(); renderLive(); }
export function setDashAgents(a) { D.agents = a || []; renderEndpoint(); }
export function setDashCompliance(s) { D.compliance = s || []; renderCompliance(); }
export function setDashPosture(p) { D.posture = p || { totalAgents: 0 }; renderEndpoint(); }
export function setDashKev(k, ti) { D.kev = k || { hasData: false }; D.ti = ti || D.ti || { topActors: [] }; renderKev(); renderActors(); }
export function setDashTI(ti) { D.ti = ti || { topActors: [] }; renderActors(); renderKev(); }
export function setDashReadiness(r) { D.readiness = r || { trends: [] }; renderReadiness(); renderPrevTrend(); renderActors(); }
export function setDashAlerts(a) { D.alerts = a || []; renderAlerts(); }
export function setDashSchedules(s) { D.schedules = s || []; renderNext(); }
export function setDashITSM(s) { D.itsm = s; renderITSM(); }
export function setDashRR(m) { D.rr = m; renderRansomwareCard(m); }
