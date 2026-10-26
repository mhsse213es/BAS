// Rich page layouts, group 4: Attack Paths, Exposure Explorer, Recommendations, Exercises,
// Technique Coverage and Threat Prioritization.
//
// Everything here is a pure builder: it takes the response a page's loader already fetched and returns
// an HTML string made of kit pieces (KPI tiles, cards, charts, bars, chips). No number is invented; a
// widget with no data behind it says so or is left out. Dynamic text is escaped here (x() or the kit).
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { kpi, grid, card, bar, hbars, chip, empty, kv, checkRow } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';

var C = CHART_COLORS;

export function n0(v) { var n = Number(v); return isFinite(n) ? n : 0; }
export function pctOf(a, b) { return b > 0 ? Math.round((n0(a) / b) * 100) : 0; }
function count(list, fn) { var n = 0; (list || []).forEach(function(i) { if (fn(i)) n++; }); return n; }

// Scores here are "higher is safer".
export function scoreTone(s) {
  s = Number(s);
  return !isFinite(s) ? 'muted' : s >= 80 ? 'ok' : s >= 40 ? 'warn' : 'bad';
}
export function bandTone(b) {
  return b === 'Low' ? 'ok' : b === 'Medium' || b === 'High' ? 'warn' : b === 'Critical' ? 'bad' : 'muted';
}
export function tierTone(t) {
  return t === 'Critical' ? 'bad' : t === 'High' ? 'warn' : t === 'Medium' ? 'accent' : 'muted';
}

function tbl(cols, rows, cls) {
  return '<div class="tbl-wrap' + (cls ? ' ' + cls : '') + '"><table><thead><tr>' +
    cols.map(function(c) { return '<th>' + x(c) + '</th>'; }).join('') + '</tr></thead><tbody>' +
    rows.map(function(r) { return '<tr>' + r.map(function(c) { return '<td>' + c + '</td>'; }).join('') + '</tr>'; }).join('') +
    '</tbody></table></div>';
}
function tableCard(title, cols, rows, sub) {
  return card(title, tbl(cols, rows), { flush: true, sub: sub });
}
// Score value plus a thin bar, for table cells.
function scoreCell(score, tone) {
  var t = tone || scoreTone(score);
  return '<div class="g4-score"><b class="g4-score-n tone-' + t + '">' + x(score) + '</b>' + bar(score, t) + '</div>';
}
function donut(segments, center, centerSub) {
  var total = segments.reduce(function(a, s) { return a + n0(s.value); }, 0);
  if (!total) return empty('', 'No data yet');
  return '<div class="donut-wrap">' + chartSlot({ type: 'donut', segments: segments, center: center != null ? center : total, centerSub: centerSub || '', h: 150 }) + '</div>';
}
function avgOf(list, fn) {
  var sum = 0, n = 0;
  (list || []).forEach(function(i) { var v = Number(fn(i)); if (isFinite(v)) { sum += v; n++; } });
  return n ? sum / n : null;
}

// ── Attack Paths ─────────────────────────────────────────────────────────────
export var AP_EDGE_KINDS = ['smb', 'winrm', 'rdp', 'admin-to', 'has-session', 'member-of', 'credential'];

export function apFindingItems(s) {
  s = s || {};
  var out = [];
  var status = s.domainCompromiseStatus;
  if (status === 'reachable') out.push({ tone: 'bad', text: 'A path to Domain Admin exists — at least one host can reach a Domain Admin or Crown Jewel target.' });
  else if (status === 'not-observed') out.push({ tone: 'ok', text: 'No Domain Admin path observed in the collected graph.' });
  else out.push({ tone: 'muted', text: 'Domain Admin reachability is undetermined — Active Directory relationships were not collected.' });
  var maxReach = s.maxBlastRadius || 0;
  out.push(maxReach > 0
    ? { tone: 'warn', text: maxReach === 1 ? 'One lateral movement path exists from the highest-risk entry host.' : maxReach + ' lateral movement paths exist from the highest-risk entry host.' }
    : { tone: 'ok', text: 'No lateral movement paths were observed.' });
  var rc = s.relationshipCounts || {};
  var adminEdges = rc['admin-to'] || 0;
  out.push(adminEdges > 0
    ? { tone: 'warn', text: adminEdges === 1 ? 'One local administrator relationship identified.' : adminEdges + ' local administrator relationships identified.' }
    : { tone: 'ok', text: 'No local administrator relationships identified.' });
  var missing = (s.confidence && s.confidence.missing) || [];
  if (missing.indexOf('Active Directory relationships') !== -1) out.push({ tone: 'info', text: 'No AD relationships collected — SharpHound was not run or is unavailable.' });
  var sessionEdges = rc['has-session'] || 0;
  out.push(sessionEdges > 0
    ? { tone: 'info', text: sessionEdges === 1 ? 'One active user session detected.' : sessionEdges + ' active user sessions detected.' }
    : { tone: 'ok', text: 'No active user sessions detected.' });
  return out;
}

function node(name, goal) { return '<span class="g4-node' + (goal ? ' goal' : '') + '">' + x(name) + '</span>'; }
function edge(kind) { return '<span class="g4-edge"><i>' + x(kind) + '</i><span>&rarr;</span></span>'; }
export function edgeChain(from, kind, to) { return '<div class="g4-chain">' + node(from) + edge(kind) + node(to, true) + '</div>'; }

function pathChain(p) {
  var h = '<div class="g4-chain">' + node(p[0].from);
  for (var i = 0; i < p.length; i++) h += edge(p[i].kind) + node(p[i].to, i === p.length - 1);
  return h + '</div>';
}

function apScoreCard(s) {
  var score = s.attackPathScore;
  var tone = scoreTone(score);
  var drivers = s.scoreDrivers || [];
  var maxDef = 0;
  drivers.forEach(function(d) { maxDef = Math.max(maxDef, n0(d.deficit)); });
  var left = score != null && isFinite(Number(score))
    ? donut([{ label: 'Score', value: n0(score), color: C[tone] }, { label: 'Points lost', value: Math.max(0, 100 - n0(score)), color: 'var(--border)' }], n0(score), 'of 100')
    : empty('', 'No score yet');
  var right = drivers.length
    ? '<div class="g4-drivers"><div class="rk-hd-sub g4-cap">Score points lost per driver</div>' + hbars(drivers.map(function(d) {
        var def = n0(d.deficit);
        return [d.label, maxDef ? (def / maxDef) * 100 : 0, def === 0 ? 'ok' : 'warn', def === 0 ? 'none' : '-' + def.toFixed(1)];
      })) + '</div>'
    : '<div class="rk-hd-sub">No score driver detail available.</div>';
  return card('Attack path score', '<div class="g4-split">' + left + right + '</div>', { sub: (s.band || '—') + ' risk · higher is safer' });
}

function apPathCard(s) {
  var p = s.shortestDomainAdminPath;
  if (!(s.domainCompromise && p && p.length)) return '';
  var diff = s.shortestDomainAdminDifficulty;
  return card('Representative path to Domain Admin', pathChain(p), {
    sub: 'Shortest path from the highest-blast-radius entry host',
    actions: diff ? 'Difficulty ' + chip(diff, bandTone(diff)) : '',
  });
}

function apCoverageCards(coverage, confidence) {
  coverage = coverage || {};
  confidence = confidence || { based: [], missing: [] };
  var compTone = coverage.completeness === 'Full' ? 'ok' : coverage.completeness === 'Limited' ? 'warn' : coverage.completeness === 'Minimal' ? 'bad' : 'muted';
  var confTone = confidence.level === 'High' ? 'ok' : confidence.level === 'Medium' ? 'warn' : confidence.level ? 'bad' : 'muted';
  var rep = coverage.targetsRepresented, req = coverage.targetsRequested;
  var haveBoth = rep != null && req != null && req > 0;
  var cov = (haveBoth
    ? '<div class="g4-cov-n"><b>' + x(rep) + '</b> of ' + x(req) + ' requested targets represented in the graph</div>' + bar(pctOf(rep, req), compTone, true)
    : '<div class="rk-hd-sub">' + x((rep != null ? rep : '—') + ' of ' + (req != null ? req : '—')) + ' requested targets represented in the graph</div>') +
    '<div class="g4-gap">' + kv([['SharpHound', coverage.sharpHoundRequested ? (coverage.sharpHoundAvailable ? 'Available' : 'Requested, not available') : 'Not requested']]) + '</div>';
  var based = (confidence.based || []).map(function(b) { return checkRow('ok', b); }).join('');
  var missing = (confidence.missing || []).map(function(m) { return checkRow('muted', m, 'not available'); }).join('');
  return [
    card('Coverage', cov, { actions: chip(coverage.completeness || 'Unknown', compTone) }),
    card('Confidence', (based || missing) ? based + missing : '<div class="rk-hd-sub">No confidence detail returned.</div>', { actions: chip(confidence.level || '—', confTone) }),
  ];
}

function apRelCard(counts) {
  counts = counts || {};
  var max = 0, total = 0;
  AP_EDGE_KINDS.forEach(function(k) { max = Math.max(max, n0(counts[k])); total += n0(counts[k]); });
  var rows = AP_EDGE_KINDS.map(function(k) {
    var n = n0(counts[k]);
    return [k, max ? (n / max) * 100 : 0, n ? 'accent' : 'muted', String(n)];
  });
  return card('Observed relationships', hbars(rows), { sub: total + ' total' });
}

function apLimitations(s, coverage) {
  var items = [];
  var missing = (s.confidence && s.confidence.missing) || [];
  if (missing.indexOf('Active Directory relationships') !== -1) items.push('SharpHound disabled or unavailable — no AD relationships in this graph');
  coverage = coverage || {};
  if (coverage.targetsRequested && coverage.targetsRepresented != null && coverage.targetsRepresented < coverage.targetsRequested) {
    items.push('Only ' + coverage.targetsRepresented + ' of ' + coverage.targetsRequested + ' requested targets are represented in the graph');
  }
  if (!items.length) return '';
  return card('This collection\'s limitations', items.map(function(i) { return checkRow('warn', i); }).join('') +
    '<div class="rk-hd-sub g4-gap">Results may underestimate lateral movement.</div>');
}

function apGapsCard(gaps) {
  if (!gaps || !gaps.length) return '';
  var tone = { Critical: 'bad', High: 'warn', Medium: 'info', Low: 'ok' };
  return tableCard('Priority remediation', ['Priority', 'Path', 'Reason', 'Recommended action'], gaps.slice(0, 10).map(function(g) {
    var e = g.edge || {};
    return [chip(g.priority || '—', tone[g.priority] || 'muted'), edgeChain(e.from, e.kind, e.to), x(g.reason), x(g.remediation)];
  }));
}

export function apRichBody(d, corr) {
  if (!d || !d.collected) {
    return card('', empty('path', 'No attack-path data collected yet', 'Run a collection on an enrolled agent to map lateral-movement reachability, blast radius, segmentation, and crown-jewel exposure across the fleet.') +
      '<div class="g4-center"><button class="btn btn-primary btn-sm" data-on-click="openAPCollect">&#9654; Run Collection</button></div>');
  }
  var s = d.summary || {};
  var status = s.domainCompromiseStatus || (s.domainCompromise ? 'reachable' : 'not-observed');
  var domLabel = status === 'reachable' ? 'Reachable' : status === 'not-observed' ? 'No path observed' : 'Undetermined';
  var domTone = status === 'reachable' ? 'bad' : status === 'not-observed' ? 'ok' : 'muted';
  var domSub = status === 'reachable' ? 'a host can reach Domain Admin' : status === 'not-observed' ? 'no path to Domain Admin in the collected graph' : 'Active Directory relationships were not collected';
  var h = grid(4, [
    kpi({ label: 'Attack path score', value: s.attackPathScore != null ? s.attackPathScore + ' / 100' : '—', sub: (s.band || '—') + ' risk · higher is safer', icon: 'posture', tone: scoreTone(s.attackPathScore) }),
    kpi({ label: 'Lateral movement', value: s.lateralMovementBand || '—', sub: 'Avg reach ' + n0(s.avgBlastRadius).toFixed(1) + ' hosts · max ' + n0(s.maxBlastRadius) + ' (from ' + (s.maxBlastEntry || 'entry host') + ')', icon: 'path', tone: bandTone(s.lateralMovementBand) }),
    kpi({ label: 'Domain compromise', value: domLabel, sub: domSub, icon: 'warn', tone: domTone }),
    kpi({ label: 'Graph scope', value: n0(s.hosts) + ' hosts', sub: n0(s.users) + ' users · ' + n0(s.groups) + ' groups · ' + n0(s.edges) + ' edges', icon: 'agents', tone: 'accent' }),
  ]);
  var findings = apFindingItems(s).map(function(i) { return checkRow(i.tone, i.text); }).join('');
  h += grid(2, [card('Findings', findings, { sub: 'what the collected graph shows' }), apScoreCard(s)]);
  h += apPathCard(s);
  var cc = apCoverageCards(d.coverage, s.confidence);
  h += grid(3, [cc[0], cc[1], apRelCard(s.relationshipCounts)]);
  h += apLimitations(s, d.coverage);
  h += corr ? apGapsCard(corr.gaps) : '';
  var cj = (s.crownJewels || []).filter(function(c) { return c.reachable; });
  var cp = s.chokePoints || [];
  var pair = [];
  if (cj.length) pair.push(tableCard('Crown-jewel exposure', ['Asset', 'Tag', 'Entry hosts', 'Min hops'], cj.map(function(c) {
    return ['<b>' + x(c.node) + '</b>', chip(c.tag || '—', 'warn'), x(c.entryHosts), x(c.minHops)];
  })));
  if (cp.length) pair.push(card('Attack choke points', hbars(cp.slice(0, 10).map(function(c) {
    var cov = Math.round(n0(c.coverage) * 100);
    return [c.label + ' (' + n0(c.onPaths) + ' paths)', cov, cov >= 50 ? 'bad' : 'warn', cov + '%'];
  })), { sub: 'share of paths each node sits on' }));
  h += pair.length === 2 ? grid(2, pair) : pair.join('');
  var sv = s.segmentationViolations || [];
  if (sv.length) h += tableCard('Segmentation violations', ['From', 'Segment', 'Via', 'To', 'Segment'], sv.map(function(v) {
    return ['<b>' + x(v.from) + '</b>', chip(v.fromSegment || '—', 'muted'), chip((v.kind || '').toUpperCase(), 'info'), '<b>' + x(v.to) + '</b>', chip(v.toSegment || '—', 'muted')];
  }));
  return h;
}

// ── Exposure Explorer ────────────────────────────────────────────────────────
export function expFilterOpts(assets) {
  assets = assets || [];
  return [
    { id: 'all', label: 'All', count: assets.length },
    { id: 'managed', label: 'Managed', count: count(assets, function(a) { return a.asset && a.asset.managed; }) },
    { id: 'discovered', label: 'Discovered', count: count(assets, function(a) { return a.asset && !a.asset.managed; }) },
    { id: 'crown', label: 'Crown jewels', count: count(assets, function(a) { return a.asset && a.asset.crownJewel; }) },
    { id: 'kev', label: 'KEV exposed', count: count(assets, function(a) { return a.kevExposed; }) },
  ];
}

export function expFilterAssets(assets, filter, query) {
  var q = String(query || '').trim().toLowerCase();
  return (assets || []).filter(function(a) {
    var as = a.asset || {};
    if (filter === 'managed' && !as.managed) return false;
    if (filter === 'discovered' && as.managed) return false;
    if (filter === 'crown' && !as.crownJewel) return false;
    if (filter === 'kev' && !a.kevExposed) return false;
    if (q && (String(as.label || '') + ' ' + String(as.hostKey || '') + ' ' + String(as.crownJewel || '')).toLowerCase().indexOf(q) === -1) return false;
    return true;
  });
}

export function expRowsHtml(list) {
  return list.map(function(a) {
    var as = a.asset || {};
    return '<tr class="u-pointer"' + on('click', 'openExposureDetail', as.hostKey) + '>' +
      '<td class="u-fw600">' + x(as.label) + '</td>' +
      '<td>' + (as.managed ? chip('Managed', 'ok') : chip('Discovered', 'muted')) + '</td>' +
      '<td class="g4-scorecol">' + scoreCell(a.exposureScore) + '</td>' +
      '<td class="g4-num">' + x(a.attackPathScore) + '</td>' +
      '<td class="g4-num">' + x(a.detectionCoverageScore) + '</td>' +
      '<td>' + (as.crownJewel ? chip(as.crownJewel, 'warn') : '<span class="muted">—</span>') + '</td>' +
      '<td class="g4-num">' + x(a.openFindingsCount) + '</td>' +
      '<td>' + (a.kevExposed ? chip('KEV', 'bad') : '<span class="muted">—</span>') + '</td>' +
      '</tr>';
  }).join('');
}

export function expSummary(assets) {
  assets = assets || [];
  if (!assets.length) return '';
  var managed = count(assets, function(a) { return a.asset && a.asset.managed; });
  var avgExp = avgOf(assets, function(a) { return a.exposureScore; });
  var kev = count(assets, function(a) { return a.kevExposed; });
  var crown = count(assets, function(a) { return a.asset && a.asset.crownJewel; });
  var findings = assets.reduce(function(a, i) { return a + n0(i.openFindingsCount); }, 0);
  var h = grid(4, [
    kpi({ label: 'Assets', value: assets.length, sub: managed + ' managed · ' + (assets.length - managed) + ' discovered', icon: 'agents', tone: 'accent' }),
    kpi({ label: 'Average exposure score', value: avgExp == null ? '—' : Math.round(avgExp), sub: 'higher is safer', icon: 'posture', tone: scoreTone(avgExp) }),
    kpi({ label: 'KEV-exposed hosts', value: kev, sub: crown + ' crown-jewel host' + (crown === 1 ? '' : 's'), icon: 'warn', tone: kev ? 'bad' : 'ok' }),
    kpi({ label: 'Open findings', value: findings, sub: 'across all assets', icon: 'flag', tone: findings ? 'warn' : 'ok' }),
  ]);
  var bands = [
    { label: 'Healthy (80+)', test: function(s) { return s >= 80; }, color: C.ok },
    { label: 'Fair (60-79)', test: function(s) { return s >= 60 && s < 80; }, color: C.info },
    { label: 'Weak (40-59)', test: function(s) { return s >= 40 && s < 60; }, color: C.warn },
    { label: 'Poor (under 40)', test: function(s) { return s < 40; }, color: C.bad },
  ];
  var scored = assets.filter(function(a) { return a.exposureScore != null && isFinite(Number(a.exposureScore)); });
  var segs = bands.map(function(b) { return { label: b.label, value: count(scored, function(a) { return b.test(Number(a.exposureScore)); }), color: b.color }; });
  var lowest = scored.slice().sort(function(a, b) { return a.exposureScore - b.exposureScore; }).slice(0, 6);
  var dims = [['Exposure', avgExp], ['Attack path', avgOf(assets, function(a) { return a.attackPathScore; })], ['Detection', avgOf(assets, function(a) { return a.detectionCoverageScore; })]]
    .filter(function(r) { return r[1] != null; });
  h += grid(3, [
    card('Assets by exposure band', donut(segs, scored.length, 'assets')),
    card('Lowest-scoring assets', lowest.length ? hbars(lowest.map(function(a) { return [(a.asset && a.asset.label) || '—', n0(a.exposureScore), scoreTone(a.exposureScore), String(a.exposureScore)]; })) : empty('', 'No data yet'), { sub: 'most exposed first' }),
    card('Fleet average by dimension', dims.length ? hbars(dims.map(function(r) { return [r[0], r[1], scoreTone(r[1]), String(Math.round(r[1]))]; })) : empty('', 'No data yet'), { sub: 'higher is safer' }),
  ]);
  return h;
}

// Exposure detail drawer pieces
export function expScoreTiles(sc) {
  sc = sc || {};
  function tile(label, val, measurable, sub) {
    return measurable
      ? kpi({ label: label, value: val, sub: sub, tone: scoreTone(val) })
      : kpi({ label: label, value: 'No data', sub: 'not collected yet', tone: 'muted' });
  }
  return grid(2, [
    tile('Exposure score', sc.exposureScore, sc.exposureMeasurable, 'higher is safer'),
    tile('Attack path', sc.attackPathScore, sc.attackPathMeasurable, ''),
    tile('Detection', sc.detectionCoverageScore, sc.detectionMeasurable, ''),
    tile('Vulnerability', sc.vulnerabilityScore, sc.vulnerabilityMeasurable, ''),
  ]);
}
export function sevChip(sev) {
  var s = String(sev || '').toLowerCase();
  return chip(sev || '—', s === 'critical' ? 'bad' : s === 'high' ? 'warn' : s === 'medium' ? 'info' : s === 'low' ? 'ok' : 'muted');
}
export function expSection(title, body) { return '<h3 class="g4-sec">' + x(title) + '</h3>' + body; }

// ── Threat Prioritization ────────────────────────────────────────────────────
export function tpFilterOpts(actors) {
  actors = actors || [];
  var opts = [{ id: 'all', label: 'All', count: actors.length }];
  ['Critical', 'High', 'Medium', 'Low'].forEach(function(t) {
    opts.push({ id: t, label: t, count: count(actors, function(a) { return (a.tier || 'Low') === t; }) });
  });
  return opts;
}

export function tpFilterActors(actors, tier) {
  return (actors || []).filter(function(a) { return !tier || tier === 'all' || (a.tier || 'Low') === tier; });
}

export function tpTrend(trend, delta) {
  if (trend === 'up') return '<span class="g4-trend up">&#9650; +' + x(delta) + '</span>';
  if (trend === 'down') return '<span class="g4-trend down">&#9660; ' + x(delta) + '</span>';
  if (trend === 'stable') return '<span class="muted">&mdash;</span>';
  return chip('New', 'info');
}

export function tpRowsHtml(list) {
  return list.map(function(a) {
    var gap = n0(a.coverageGapCount), tot = n0(a.techniqueCount);
    return '<tr class="u-pointer"' + on('click', 'showThreatPriorityDetail', a.actorName) + '>' +
      '<td class="u-fw600">' + x(a.actorName) + '</td>' +
      '<td>' + chip(a.tier || 'Low', tierTone(a.tier || 'Low')) + '</td>' +
      '<td class="g4-scorecol">' + scoreCell(a.score, tierTone(a.tier || 'Low')) + '</td>' +
      '<td>' + tpTrend(a.trend, a.trendDelta) + '</td>' +
      '<td class="g4-scorecol"><div class="g4-score"><span class="g4-score-n">' + x(gap) + ' of ' + x(tot) + '</span>' + bar(pctOf(gap, tot), gap ? 'warn' : 'ok') + '</div></td>' +
      '</tr>';
  }).join('');
}

export function tpSummary(actors) {
  actors = actors || [];
  if (!actors.length) return '';
  var avg = avgOf(actors, function(a) { return a.score; });
  var crit = count(actors, function(a) { return a.tier === 'Critical'; });
  var high = count(actors, function(a) { return a.tier === 'High'; });
  var gaps = actors.reduce(function(a, i) { return a + n0(i.coverageGapCount); }, 0);
  var rising = count(actors, function(a) { return a.trend === 'up'; });
  var h = grid(4, [
    kpi({ label: 'Actors tracked', value: actors.length, sub: rising + ' with a rising score', icon: 'user', tone: 'accent' }),
    kpi({ label: 'Critical tier', value: crit, sub: high + ' more in the High tier', icon: 'warn', tone: crit ? 'bad' : 'ok' }),
    kpi({ label: 'Average score', value: avg == null ? '—' : Math.round(avg), sub: 'relevance to your environment', icon: 'star', tone: 'accent' }),
    kpi({ label: 'Unvalidated techniques', value: gaps, sub: 'coverage gaps across all actors', icon: 'technique', tone: gaps ? 'warn' : 'ok' }),
  ]);
  var segs = ['Critical', 'High', 'Medium', 'Low'].map(function(t) {
    return { label: t, value: count(actors, function(a) { return (a.tier || 'Low') === t; }), color: C[tierTone(t)] };
  });
  var top = actors.slice().sort(function(a, b) { return n0(b.score) - n0(a.score); }).slice(0, 7);
  var widest = actors.filter(function(a) { return n0(a.coverageGapCount) > 0; }).sort(function(a, b) { return n0(b.coverageGapCount) - n0(a.coverageGapCount); }).slice(0, 7);
  h += grid(3, [
    card('Actors by tier', donut(segs, actors.length, 'actors')),
    card('Top actors by score', hbars(top.map(function(a) { return [a.actorName, n0(a.score), tierTone(a.tier || 'Low'), String(a.score)]; })), { sub: 'most relevant first' }),
    card('Largest coverage gaps', widest.length ? hbars(widest.map(function(a) { return [a.actorName, pctOf(a.coverageGapCount, a.techniqueCount), 'warn', n0(a.coverageGapCount) + ' of ' + n0(a.techniqueCount)]; })) : empty('', 'No coverage gaps', 'Every tracked technique is validated.'), { sub: 'unvalidated techniques' }),
  ]);
  return h;
}

export function tpDetailSummaryHtml(d) {
  var t = tierTone(d.tier || 'Low');
  return grid(4, [
    kpi({ label: 'Score', value: d.score, sub: 'relevance to you', icon: 'star', tone: t }),
    kpi({ label: 'Tier', value: d.tier || 'Low', icon: 'flag', tone: t }),
    kpi({ label: 'Techniques', value: d.techniqueCount, sub: 'attributed to this actor', icon: 'technique', tone: 'accent' }),
    kpi({ label: 'Coverage gap', value: d.coverageGapCount, sub: 'of ' + n0(d.techniqueCount) + ' not yet validated', icon: 'warn', tone: n0(d.coverageGapCount) ? 'warn' : 'ok' }),
  ]);
}

export function tpFactorsHtml(factors) {
  if (!factors || !factors.length) return '<div class="empty">No factor data.</div>';
  return factors.map(function(f) {
    var raw = Number(f.rawScore);
    var ok = f.available && isFinite(raw);
    return '<div class="g4-factor"><div class="g4-factor-t"><b>' + x(f.name) + '</b><span>' + x(f.explanation) + '</span></div>' +
      '<div class="g4-factor-b">' + (ok ? bar(raw, 'accent', true) : '') + '</div>' +
      '<div class="g4-factor-v' + (ok ? '' : ' muted') + '">' + x(ok ? Math.round(raw) + '%' : 'Not yet validated') + '</div></div>';
  }).join('');
}

export function tpHistoryHtml(hist) {
  hist = hist || [];
  if (!hist.length) return '<span class="muted">No history yet.</span>';
  var rows = hist.map(function(h) { return { d: new Date(h.recordedAt), s: n0(h.score) }; });
  var lbl = function(r, short) { return isNaN(r.d.getTime()) ? '—' : (short ? r.d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) : r.d.toLocaleDateString()); };
  var chart = rows.length >= 2
    ? chartSlot({ type: 'line', labels: rows.map(function(r) { return lbl(r, true); }), series: [{ name: 'Score', data: rows.map(function(r) { return r.s; }), color: C.accent }], h: 170 })
    : '';
  return chart + '<table class="u-w100"><thead><tr><th>Date</th><th>Score</th></tr></thead><tbody>' +
    rows.map(function(r) { return '<tr><td>' + x(lbl(r)) + '</td><td>' + x(r.s) + '</td></tr>'; }).join('') + '</tbody></table>';
}

// ── Technique Coverage ───────────────────────────────────────────────────────
export var COV_DIMS = [
  ['simulationExists', 'Simulation'],
  ['detectionProfileExists', 'Detection profile'],
  ['purpleExerciseExists', 'Purple exercise'],
  ['complianceMappingExists', 'Compliance mapping'],
  ['responsePlaybookExists', 'Response playbook'],
];

// A technique has a gap when any dimension it can be measured on is false (null means N/A).
export function covHasGap(r) {
  return COV_DIMS.some(function(d) { return r[d[0]] === false; });
}

export function covStats(rows) {
  rows = rows || [];
  var dims = COV_DIMS.map(function(d) {
    var have = 0, applicable = 0;
    rows.forEach(function(r) { if (r[d[0]] === null || r[d[0]] === undefined) return; applicable++; if (r[d[0]]) have++; });
    return { key: d[0], label: d[1], have: have, applicable: applicable, pct: pctOf(have, applicable) };
  });
  var gaps = count(rows, covHasGap);
  return { total: rows.length, dims: dims, gaps: gaps, covered: rows.length - gaps };
}

export function covFilterOpts(rows) {
  var st = covStats(rows);
  return [{ id: 'all', label: 'All', count: st.total }, { id: 'gaps', label: 'With gaps', count: st.gaps }, { id: 'covered', label: 'Fully covered', count: st.covered }];
}

export function covFilterRows(rows, f) {
  return (rows || []).filter(function(r) { return f === 'gaps' ? covHasGap(r) : f === 'covered' ? !covHasGap(r) : true; });
}

function covCell(val) {
  if (val === null || val === undefined) return '<span class="muted">N/A</span>';
  return val ? '<span class="g4-yes">&#10003; Yes</span>' : '<span class="g4-no">&mdash;</span>';
}

export function covRowsHtml(rows) {
  return rows.map(function(r) {
    return '<tr><td class="u-fw600">' + x(r.techniqueId) + '</td>' + COV_DIMS.map(function(d) { return '<td>' + covCell(r[d[0]]) + '</td>'; }).join('') + '</tr>';
  }).join('');
}

export function covSummary(rows) {
  var st = covStats(rows);
  if (!st.total) return '';
  var dimTone = function(d) { return d.applicable ? (d.pct >= 70 ? 'ok' : d.pct >= 40 ? 'warn' : 'bad') : 'muted'; };
  var tile = function(d, ic) { return kpi({ label: d.label, value: d.applicable ? d.pct + '%' : 'N/A', sub: d.have + ' of ' + d.applicable + ' techniques', icon: ic, tone: dimTone(d) }); };
  var h = grid(4, [
    kpi({ label: 'Techniques', value: st.total, sub: st.covered + ' fully covered · ' + st.gaps + ' with gaps', icon: 'technique', tone: 'accent' }),
    tile(st.dims[0], 'runs'), tile(st.dims[1], 'posture'), tile(st.dims[2], 'flag'),
  ]);
  h += grid(2, [
    card('Coverage by dimension', hbars(st.dims.filter(function(d) { return d.applicable; }).map(function(d) { return [d.label, d.pct, dimTone(d), d.have + ' / ' + d.applicable]; })), { sub: 'N/A techniques are excluded' }),
    card('Technique coverage', donut([{ label: 'Fully covered', value: st.covered, color: C.ok }, { label: 'With gaps', value: st.gaps, color: C.warn }], st.total, 'techniques')),
  ]);
  return h;
}

// ── Recommendations ──────────────────────────────────────────────────────────
export function recCoverageChip(c) {
  return c === 'never-tested' ? chip('Never tested', 'bad') : c === 'stale' ? chip('Stale', 'warn') : chip('Recent', 'muted');
}

export function recRowsHtml(list) {
  return list.map(function(t) {
    var threat = [];
    if (t.kev) threat.push(chip('KEV', 'bad'));
    if (t.epssPercentile) threat.push(chip('EPSS ' + Math.round(n0(t.epssPercentile)), 'muted'));
    if (t.threatActors) threat.push(chip(t.threatActors + ' group' + (t.threatActors === 1 ? '' : 's'), 'info'));
    var tone = tierTone(t.tier);
    return '<tr>' +
      '<td><div class="u-fw600">' + x(t.techniqueId) + '</div><div class="tiny muted">' + x(t.name) + '</div></td>' +
      '<td class="tiny">' + x(t.tactic) + '</td>' +
      '<td class="g4-scorecol"><div class="g4-score"><b class="g4-score-n tone-' + tone + '">' + x(t.score) + ' <small>' + x(t.tier) + '</small></b>' + bar(n0(t.score), tone) + '</div></td>' +
      '<td>' + recCoverageChip(t.coverageState) + '</td>' +
      '<td><div class="g4-chips">' + (threat.join('') || '<span class="muted">—</span>') + '</div></td>' +
      '<td>' + (t.environmentRisk ? chip(t.environmentRisk, 'accent') : '<span class="muted">—</span>') + '</td>' +
      '<td class="tiny muted">' + x((t.reasons || []).join(' · ')) + '</td>' +
      '</tr>';
  }).join('');
}

export function recSummary(list, scenario) {
  list = list || [];
  if (!list.length) return '';
  var never = count(list, function(t) { return t.coverageState === 'never-tested'; });
  var stale = count(list, function(t) { return t.coverageState === 'stale'; });
  var kev = count(list, function(t) { return t.kev; });
  var env = count(list, function(t) { return t.environmentRisk; });
  var crit = count(list, function(t) { return t.tier === 'Critical' || t.tier === 'High'; });
  var h = grid(4, [
    kpi({ label: 'Techniques ranked', value: list.length, sub: crit + ' in the Critical or High tier', icon: 'technique', tone: 'accent' }),
    kpi({ label: 'Never tested', value: never, sub: stale + ' stale', icon: 'warn', tone: never ? 'bad' : 'ok' }),
    kpi({ label: 'KEV-linked', value: kev, sub: 'actively exploited in the wild', icon: 'flag', tone: kev ? 'bad' : 'ok' }),
    kpi({ label: 'On a real path', value: env, sub: 'traverse your environment', icon: 'path', tone: env ? 'warn' : 'muted' }),
  ]);
  var tiers = ['Critical', 'High', 'Medium', 'Low'].map(function(t) { return { label: t, value: count(list, function(i) { return (i.tier || 'Low') === t; }), color: C[tierTone(t)] }; });
  var cov = [
    { label: 'Never tested', value: never, color: C.bad }, { label: 'Stale', value: stale, color: C.warn },
    { label: 'Recent', value: list.length - never - stale, color: C.ok },
  ];
  var tactics = {};
  list.forEach(function(t) { var k = t.tactic || 'Unknown'; tactics[k] = (tactics[k] || 0) + 1; });
  var tk = Object.keys(tactics).sort(function(a, b) { return tactics[b] - tactics[a]; }).slice(0, 6);
  var maxT = tk.length ? tactics[tk[0]] : 0;
  h += grid(3, [
    card('Priority tier', donut(tiers, list.length, 'techniques')),
    card('Test recency', donut(cov, list.length, 'techniques')),
    card('Top tactics', hbars(tk.map(function(k) { return [k, maxT ? (tactics[k] / maxT) * 100 : 0, 'accent', String(tactics[k])]; }))),
  ]);
  var art = scenario && scenario.artTechniques;
  if (art && art.length) {
    h += card('Suggested scenario', '<div class="g4-chips">' + art.map(function(t) { return chip(t, 'accent'); }).join('') + '</div>', { sub: art.length + ' technique' + (art.length === 1 ? '' : 's') + ' · use "Copy scenario techniques" above' });
  }
  return h;
}

// ── Exercises ────────────────────────────────────────────────────────────────
export function exStatusTone(s) {
  return s === 'completed' ? 'ok' : s === 'running' ? 'accent' : s === 'paused' || s === 'waiting' ? 'warn' : s === 'failed' || s === 'aborted' ? 'bad' : 'muted';
}

export function exSummary(st) {
  st = st || {};
  var scen = st.scen, exs = st.exs, plans = st.plans, execs = st.execs;
  if (!scen && !exs && !plans && !execs) return '';
  var live = count(execs, function(e) { return e.status === 'running' || e.status === 'paused'; });
  var done = count(execs, function(e) { return e.status === 'completed'; });
  var h = grid(4, [
    kpi({ label: 'OpenAEV scenarios', value: scen ? scen.length : '—', sub: 'synced content library', icon: 'bolt', tone: 'accent' }),
    kpi({ label: 'OpenAEV exercises', value: exs ? exs.length : '—', sub: 'synced from OpenAEV', icon: 'flag', tone: 'accent' }),
    kpi({ label: 'Exercise plans', value: plans ? plans.length : '—', sub: 'ready to launch', icon: 'campaign', tone: 'info' }),
    kpi({ label: 'Executions', value: execs ? execs.length : '—', sub: live + ' live · ' + done + ' completed', icon: 'runs', tone: live ? 'warn' : 'ok' }),
  ]);
  var statuses = {};
  (execs || []).forEach(function(e) { var k = e.status || 'unknown'; statuses[k] = (statuses[k] || 0) + 1; });
  var execSegs = Object.keys(statuses).map(function(k) { return { label: k, value: statuses[k], color: C[exStatusTone(k)] }; });
  var content = (scen || []).concat(exs || []);
  var sev = {}, cat = {};
  content.forEach(function(s) {
    var k = s.Severity || 'Unspecified';
    sev[k] = (sev[k] || 0) + 1;
    if (s.Category) cat[s.Category] = (cat[s.Category] || 0) + 1;
  });
  var palette = [C.bad, C.warn, C.info, C.ok, C.violet, C.muted];
  var sevSegs = Object.keys(sev).sort(function(a, b) { return sev[b] - sev[a]; }).map(function(k, i) { return { label: k, value: sev[k], color: palette[i % palette.length] }; });
  var ck = Object.keys(cat).sort(function(a, b) { return cat[b] - cat[a]; }).slice(0, 6);
  var maxC = ck.length ? cat[ck[0]] : 0;
  h += grid(3, [
    card('Executions by status', execSegs.length ? donut(execSegs, execs.length, 'executions') : empty('runs', 'No executions yet')),
    card('Content by severity', sevSegs.length ? donut(sevSegs, content.length, 'items') : empty('bolt', 'No content synced yet')),
    card('Content by category', ck.length ? hbars(ck.map(function(k) { return [k, maxC ? (cat[k] / maxC) * 100 : 0, 'accent', String(cat[k])]; })) : empty('bolt', 'No categories yet')),
  ]);
  return h;
}
