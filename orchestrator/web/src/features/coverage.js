import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { covSegHtml } from './attack-path.js';
import { kpi, grid, card, hbars, pill, chip, empty, bar, kv } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { cssVars } from '../core/css-vars.js';


// ── ATT&CK Coverage ──────────────────────────────────────────────────────────
var COV_VIEW = 'all';
// covStatusMap: most-recent verdict per technique → cov | part | gap.
// Runs are newest-first, so the first verdict seen for a technique wins. A fail
// is "part" (detected) when the blue team still caught it, else "gap" (missed) —
// same classification as the dashboard donut.
export function covStatusMap(runs) {
  var st = {};
  (runs || []).forEach(function(r) {
    var det = r.detectedTechs || {};
    (r.results || []).forEach(function(c) {
      var id = c.technique && c.technique.id;
      if (!id || st[id]) return;
      if (c.result === 'pass' || c.result === 'blocked') st[id] = 'cov';
      else if (c.result === 'fail') st[id] = det[id] ? 'part' : 'gap';
    });
  });
  return st;
}

// ── Coverage Analytics ────────────────────────────────────────────────────────
export function loadCoverageAnalytics() {
  var scen  = (document.getElementById('ca-scenario') || {}).value || '';
  var agent = (document.getElementById('ca-agent')    || {}).value || '';
  var qs = '?limit=50' + (scen ? '&scenarioId=' + encodeURIComponent(scen) : '') + (agent ? '&agentId=' + encodeURIComponent(agent) : '');
  apicall('/api/coverage/analytics' + qs).catch(function() { return null; }).then(function(d) {
    if (!d) return;
    populateCoverageFilters(d);
    renderCoverageAnalytics(d);
  });
}

// Populate scenario + agent dropdowns once (preserves selection).
var _caFiltersPopulated = false;
function populateCoverageFilters(d) {
  if (_caFiltersPopulated) return;
  _caFiltersPopulated = true;
  // Scenario dropdown from loaded scenario list.
  var scenSel = document.getElementById('ca-scenario');
  if (scenSel && state.scenarios) {
    var cur = scenSel.value;
    scenSel.innerHTML = '<option value="">All scenarios</option>' +
      (state.scenarios || []).map(function(s) { return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>'; }).join('');
    if (cur) scenSel.value = cur;
  }
  // Agent dropdown.
  var agSel = document.getElementById('ca-agent');
  if (agSel && state.agents) {
    var cur2 = agSel.value;
    agSel.innerHTML = '<option value="">All agents</option>' +
      (state.agents || []).map(function(a) { return '<option value="' + x(a.agentId) + '">' + x(a.hostname || a.agentId) + '</option>'; }).join('');
    if (cur2) agSel.value = cur2;
  }
}

// Pure helpers (unit-tested): tone by prevention rate, donut segments for an analytics summary.
export function covTone(rate) {
  var r = Number(rate) || 0;
  return r >= 75 ? 'ok' : r >= 40 ? 'warn' : 'bad';
}
export function covOutcomeSegments(s) {
  s = s || {};
  return [
    { label: 'Prevented', value: Number(s.prevented) || 0, color: CHART_COLORS.ok },
    { label: 'Detected only', value: Number(s.detectedOnly) || 0, color: CHART_COLORS.warn },
    { label: 'Missed', value: Number(s.missed) || 0, color: CHART_COLORS.bad },
  ].filter(function(g) { return g.value > 0; });
}
var TIER_TONE = { user: 'accent', admin: 'warn', system: 'bad', inherited: 'muted' };
var TIER_LABEL = { user: 'User', admin: 'Admin', system: 'SYSTEM', inherited: 'Inherited' };

function tableWrap(head, rows, emptyHtml, cols) {
  return '<div class="tbl-wrap rg2-tbl"><table><thead><tr>' + head.map(function(h) {
    return '<th' + (h[1] ? ' class="' + h[1] + '"' : '') + '>' + x(h[0]) + '</th>';
  }).join('') + '</tr></thead><tbody>' +
    (rows.length ? rows.join('') : '<tr><td colspan="' + cols + '" class="empty">' + emptyHtml + '</td></tr>') +
    '</tbody></table></div>';
}

function renderCoverageAnalytics(d) {
  var s = d.summary || {};
  var hasData = d.runsAnalyzed > 0 && s.attempted > 0;
  var root = document.getElementById('ca-root');
  if (root) {
    if (!hasData) {
      root.innerHTML = empty('shield', 'No completed runs yet', 'Run a scenario or adversary template to generate analytics.');
    } else {
      var runsTxt = d.runsAnalyzed + ' run' + (d.runsAnalyzed !== 1 ? 's' : '') + ' analysed';
      var tiles = grid(4, [
        kpi({ label: 'Techniques attempted', value: s.attempted, sub: runsTxt, icon: 'technique', tone: 'accent' }),
        kpi({ label: 'Prevented', value: s.prevented, sub: (s.preventionRate || 0) + '% prevention rate', icon: 'ok', tone: 'ok' }),
        kpi({ label: 'Detected only', value: s.detectedOnly, sub: 'EDR/SIEM alerted, not blocked', icon: 'warn', tone: 'warn' }),
        kpi({ label: 'Missed', value: s.missed, sub: 'No prevention, no detection', icon: 'bad', tone: 'bad' }),
      ]);
      var segs = covOutcomeSegments(s);
      var mix = card('Outcome mix',
        chartSlot({ type: 'donut', segments: segs, center: String(s.attempted), centerSub: 'techniques', legend: true, h: 170 }) +
        '<div class="rg2-gap">' + hbars([
          ['Prevention rate', s.preventionRate || 0, 'ok', (s.preventionRate || 0) + '%'],
          ['Detection coverage', s.detectionCoverage || 0, 'warn', (s.detectionCoverage || 0) + '%'],
        ]) + '</div>');
      var tac = d.byTactic || [];
      var byTac = card('Outcomes by tactic', tac.length ? chartSlot({
        type: 'bar', stacked: true, h: 230,
        labels: tac.map(function(t) { return t.tactic; }),
        series: [
          { name: 'Prevented', data: tac.map(function(t) { return t.prevented; }), color: CHART_COLORS.ok },
          { name: 'Detected only', data: tac.map(function(t) { return t.detectedOnly; }), color: CHART_COLORS.warn },
          { name: 'Missed', data: tac.map(function(t) { return t.missed; }), color: CHART_COLORS.bad },
        ],
      }) : empty('technique', 'No tactic data'));
      var tacRows = tac.map(function(t) {
        return '<tr><td>' + x(t.tactic) + '</td><td class="u-center"><span class="rg2-num tone-ok">' + x(t.prevented) + '</span></td>' +
          '<td class="u-center"><span class="rg2-num tone-warn">' + x(t.detectedOnly) + '</span></td>' +
          '<td class="u-center"><span class="rg2-num ' + (t.missed > 0 ? 'tone-bad' : 'tone-muted') + '">' + x(t.missed) + '</span></td></tr>';
      });
      var missed = (d.byTechnique || []).filter(function(t) { return t.bestVerdict === 'missed' || t.bestVerdict === 'detectedOnly'; }).slice(0, 20);
      var missRows = missed.map(function(t) {
        return '<tr><td>' + pill(t.techniqueId, t.bestVerdict === 'missed' ? 'bad' : 'warn') + '</td><td>' + x(t.name || '—') + '</td><td class="u-center">' + x(t.runCount) + '</td></tr>';
      });
      root.innerHTML = tiles + grid(2, [mix, byTac]) + grid(2, [
        card('By tactic', tableWrap([['Tactic'], ['Prevented', 'u-center'], ['Detected', 'u-center'], ['Missed', 'u-center']], tacRows, 'No data', 4), { flush: true }),
        card('Missed techniques, prioritise these', tableWrap([['Technique'], ['Name'], ['Runs', 'u-center']], missRows, '<span class="u-success">No gaps detected</span>', 3), { flush: true, sub: missed.length ? 'top ' + missed.length : '' }),
      ]);
    }
  }
  renderPrivilegeCoverage(d.privilegeCoverage);
}

function renderPrivilegeCoverage(pc) {
  var root = document.getElementById('priv-root');
  if (!root) return;
  var tiers = (pc && pc.byTier) || [];
  var gaps  = (pc && pc.gapTechs) || [];
  if (!tiers.length) {
    root.innerHTML = empty('lock', 'No privilege-annotated runs yet', 'Annotate scenario steps with requires_priv to enable tier tracking.');
    return;
  }
  var tiles = grid(tiers.length >= 4 ? 4 : tiers.length < 2 ? 2 : tiers.length, tiers.map(function(t) {
    var rate = t.attempted > 0 ? t.preventionRate : 0;
    return kpi({ label: TIER_LABEL[t.tier] || t.tier, value: rate + '%', sub: t.prevented + '/' + t.attempted + ' prevented', icon: 'lock', tone: TIER_TONE[t.tier] || 'muted' });
  }));
  var tierRows = tiers.map(function(t) {
    var rate = t.attempted > 0 ? t.preventionRate : 0;
    return '<tr><td>' + pill(TIER_LABEL[t.tier] || t.tier, TIER_TONE[t.tier] || 'muted') + '</td>' +
      '<td class="u-center">' + x(t.attempted) + '</td><td class="u-center"><span class="rg2-num tone-ok">' + x(t.prevented) + '</span></td>' +
      '<td class="u-center"><span class="rg2-num ' + (t.missed > 0 ? 'tone-bad' : 'tone-muted') + '">' + x(t.missed) + '</span></td>' +
      '<td class="rg2-rate">' + bar(rate, covTone(rate)) + '<span>' + x(rate) + '%</span></td></tr>';
  });
  var gapRows = gaps.slice(0, 25).map(function(g) {
    return '<tr><td><span class="rg2-mono">' + x(g.techniqueId) + '</span></td><td title="' + x(g.name || '') + '">' + x(g.name || '—') + '</td><td>' +
      (g.tiers || []).map(function(t) { return chip(TIER_LABEL[t] || t, TIER_TONE[t] || 'muted'); }).join(' ') + '</td></tr>';
  });
  if (gaps.length > 25) gapRows.push('<tr><td colspan="3" class="u-muted">… and ' + (gaps.length - 25) + ' more</td></tr>');
  root.innerHTML = tiles + grid(2, [
    card('Prevention by tier', tableWrap([['Tier'], ['Attempted', 'u-center'], ['Prevented', 'u-center'], ['Missed', 'u-center'], ['Rate']], tierRows, 'No data', 5), { flush: true }),
    card('Privilege coverage gaps', tableWrap([['Technique'], ['Name'], ['Tested at']], gapRows, '<span class="u-success">All annotated techniques tested at user tier</span>', 3) +
      '<p class="rg2-note">Gaps are techniques never run as a standard user. Run these at user tier so controls are not solely relying on privilege barriers.</p>', { flush: true, sub: 'tested elevated only' }),
  ]);
}

// ── Unified Technique Library ─────────────────────────────────────────────────
var _utlData = [];          // raw response from /api/techniques/unified
var _utlFilter = { src: 'all' }; // active source filter

export function loadUnifiedTechniques() {
  apicall('/api/techniques/unified').catch(function() { return []; }).then(function(d) {
    _utlData = Array.isArray(d) ? d : [];
    // Populate tactic dropdown.
    var sel = document.getElementById('utl-tactic');
    if (sel) {
      var tacSet = {};
      _utlData.forEach(function(t) { if (t.tactic) tacSet[t.tactic] = true; });
      sel.innerHTML = '<option value="all">All tactics</option>' +
        Object.keys(tacSet).sort().map(function(t) { return '<option value="' + x(t) + '">' + x(t) + '</option>'; }).join('');
    }
    renderUTL();
  });
}

export function setUTLFilter(dim, val) {
  _utlFilter[dim] = val;
  document.querySelectorAll('.pfbtn[data-uf="' + dim + '"]').forEach(function(b) {
    b.classList.toggle('active', b.getAttribute('data-val') === val);
  });
  renderUTL();
}

function srcCount(t) {
  return (t.basCount > 0 ? 1 : 0) + (t.artCount > 0 ? 1 : 0) +
         (t.emuCount > 0 ? 1 : 0) + (t.atomicCount > 0 ? 1 : 0);
}

export function renderUTL() {
  var q = ((document.getElementById('utl-search') || {}).value || '').trim().toLowerCase();
  var tactic = ((document.getElementById('utl-tactic') || {}).value) || 'all';
  var src = _utlFilter.src;

  var filtered = _utlData.filter(function(t) {
    if (q && (t.techniqueId + ' ' + (t.name || '') + ' ' + (t.tactic || '')).toLowerCase().indexOf(q) === -1) return false;
    if (tactic !== 'all' && (t.tactic || '') !== tactic) return false;
    if (src === 'bas'    && !t.basCount)   return false;
    if (src === 'art'    && !t.artCount)   return false;
    if (src === 'emu'    && !t.emuCount)   return false;
    if (src === 'atomic' && !t.atomicCount) return false;
    if (src === 'multi'  && srcCount(t) < 2) return false;
    return true;
  });

  // Summary header.
  var sumEl = document.getElementById('utl-summary');
  var totBAS = 0, totART = 0, totEmu = 0, totAtomic = 0;
  _utlData.forEach(function(t) {
    if (t.basCount)   totBAS++;
    if (t.artCount)   totART++;
    if (t.emuCount)   totEmu++;
    if (t.atomicCount) totAtomic++;
  });
  if (sumEl) sumEl.textContent = _utlData.length.toLocaleString() + ' unique techniques — ' +
    'BAS ' + totBAS + ' · ART ' + totART + ' · Emu ' + totEmu + ' · Atomic ' + totAtomic;

  var cov = state._covSt || {};
  var rows = filtered.map(function(t, i) {
    var bg = i % 2 === 0 ? '' : 'g1-s-ab376776';
    var verdict = cov[t.techniqueId] || '';
    var vdot = verdict === 'pass'  ? '<span class="u-success">●</span>' :
               verdict === 'fail'  ? '<span class="u-danger">●</span>'  :
               verdict === 'error' ? '<span class="u-muted">●</span>'   : '';
    function cell(n, cls) {
      return '<td class="u-center">' +
        (n > 0 ? '<span class="utl-num"><span class="utl-badge ' + cls + '">' + n + '</span></span>'
               : '<span class="utl-zero">—</span>') + '</td>';
    }
    var nsrc = srcCount(t);
    var srcBadge = '<span class="g1-s-62899a0f"' + cssVars(['g1-v-7d75dfc9', nsrc > 1 ? 'var(--accent)' : 'var(--muted)']) + '>' + nsrc + (nsrc === 1 ? ' src' : ' srcs') + '</span>';
    return '<tr class="' + bg + '">' +
      '<td class="g1-s-2f6cdc06">' + x(t.techniqueId) + ' ' + vdot + '</td>' +
      '<td class="g1-s-21dc2c7f" title="' + x(t.name || '') + '">' + x(t.name || '—') + '</td>' +
      '<td class="g1-s-b80a2c9b">' + x(t.tactic || '—') + '</td>' +
      cell(t.basCount,   'utl-bas') +
      cell(t.artCount,   'utl-art') +
      cell(t.emuCount,   'utl-emu') +
      cell(t.atomicCount,'utl-atomic') +
      '<td class="g1-s-16d97c43">' + t.totalVariants + '</td>' +
      '<td class="u-center">' + srcBadge + '</td>' +
    '</tr>';
  }).join('');

  var body = document.getElementById('utl-body');
  if (body) body.innerHTML = rows || '<tr><td colspan="9" class="empty">No techniques match.</td></tr>';
  var foot = document.getElementById('utl-foot');
  if (foot) foot.textContent = 'Showing ' + filtered.length.toLocaleString() + ' of ' + _utlData.length.toLocaleString() + ' techniques';
}
// ─────────────────────────────────────────────────────────────────────────────

export function loadCoverage() {
  Promise.all([apicall('/api/attack/matrix'), apicall('/api/scenarios/runs')]).then(function(res) {
    var tactics = (res[0] && res[0].tactics) || [];
    var st = covStatusMap(res[1] || []);
    var counts = { cov: 0, part: 0, gap: 0, none: 0, total: 0 }, seen = {};
    tactics.forEach(function(t) {
      (t.techniques || []).forEach(function(c) {
        if (seen[c.id]) return;
        seen[c.id] = true;
        var s = st[c.id] || 'none';
        counts[s]++; counts.total++;
      });
    });
    state._covCounts = counts; state._covTactics = tactics; state._covSt = st;
    renderCovToolbar(); renderCovMatrix();
    document.getElementById('cov-foot').textContent =
      'Showing ' + counts.total + ' techniques across ' + tactics.length +
      ' tactics · coverage = last validated result per technique, not theoretical inventory.';
  }).catch(function(e) {
    document.getElementById('cov-matrix').innerHTML = '<div class="empty g1-s-be6df18e">' + x(e.message) + '</div>';
  });
}

// ── Live Threat Coverage (TCF Phase 10) ──────────────────────────────────────
export function loadThreatExposure() {
  apicall('/api/threats/exposure?limit=50').catch(function() { return null; }).then(function(d) {
    renderThreatExposure(d || []);
  });
}

function renderThreatExposure(threats) {
  var body = document.getElementById('lte-body');
  var foot = document.getElementById('lte-foot');
  if (!body) return;
  if (!threats.length) {
    body.innerHTML = empty('globe', 'No active threats tracked yet', 'Threats appear here once your intelligence sources report them.');
    if (foot) foot.textContent = '';
    return;
  }
  var cards = threats.map(function(t) {
    var techCount = (t.techniques || []).length;
    var withContent = (t.techniques || []).filter(function(tc) { return tc.hasExecutableContent; }).length;
    var pct = techCount ? Math.round(withContent / techCount * 100) : 0;
    var contentRows = (t.content || []).map(function(c) {
      var runInfo = c.runCount > 0 ? c.runCount + ' run(s), last ' + new Date(c.lastRunAt).toLocaleDateString() : 'never run';
      return '<div class="rk-check"><div class="rk-check-t"><b>' + x(c.contentId) + '</b><span>' + x(c.relationshipKind) + ', ' + x(c.validation) + ' · ' + x(runInfo) + '</span></div>' +
        '<div class="rk-check-r">' + (c.isExecutable ? chip('Executable', 'ok') : chip(c.lifecycle || 'n/a', 'muted')) + '</div></div>';
    }).join('') || '<div class="rg2-note">No content available for this threat yet.</div>';
    return card(t.title, '<div class="rg2-gap">' +
      kv([['Last seen', t.lastSeenAt ? new Date(t.lastSeenAt).toLocaleDateString() : 'unknown'], ['Techniques', techCount + ' tracked, ' + withContent + ' with executable content']]) +
      '</div>' + (techCount ? hbars([['Executable content', pct, covTone(pct), withContent + '/' + techCount]]) : '') + contentRows);
  });
  body.innerHTML = grid(2, cards);
  if (foot) foot.textContent = threats.length + ' active threat(s) shown.';
}

function renderCovMatrix() {
  var st = state._covSt || {}, view = COV_VIEW;
  document.getElementById('cov-matrix').innerHTML = '<div class="mx">' + (state._covTactics || []).map(function(t) {
    var techs = t.techniques || [];
    var cov = techs.filter(function(c) { return st[c.id] === 'cov'; }).length;
    var cells = techs.map(function(c) {
      var s = st[c.id] || 'none', dim = view !== 'all' && view !== s;
      return '<div class="mx-cell ' + s + (dim ? ' g1-s-c1f75ce4' : '') + '"' + on('click', 'openTechnique', c.id) + '>' +
        '<span class="mc-id">' + x(c.id) + '</span>' + x(c.name) + '</div>';
    }).join('');
    return '<div class="mx-col"><div class="mx-col-h"><div class="tac-name">' + x(t.name) + '</div>' +
      '<div class="tac-cnt">' + cov + '/' + techs.length + ' prevented</div></div>' + cells + '</div>';
  }).join('') + '</div>';
}
function renderCovToolbar() {
  var c = state._covCounts || { cov: 0, part: 0, gap: 0, none: 0 };
  var seg = covSegHtml([['all', 'All'], ['cov', 'Prevented'], ['part', 'Detected'], ['gap', 'Missed'], ['none', 'Untested']], COV_VIEW, 'setCovView');
  var total = c.total || (c.cov + c.part + c.gap + c.none);
  var share = function(n) { return total ? Math.round(n / total * 100) + '% of techniques' : 'No techniques'; };
  document.getElementById('cov-toolbar').innerHTML =
    grid(4, [
      kpi({ label: 'Prevented', value: c.cov, sub: share(c.cov), tone: 'ok', action: 'setCovView', args: ['cov'] }),
      kpi({ label: 'Detected only', value: c.part, sub: share(c.part), tone: 'warn', action: 'setCovView', args: ['part'] }),
      kpi({ label: 'Missed', value: c.gap, sub: share(c.gap), tone: 'bad', action: 'setCovView', args: ['gap'] }),
      kpi({ label: 'Untested', value: c.none, sub: share(c.none), tone: 'muted', action: 'setCovView', args: ['none'] }),
    ]) + seg;
}
export function setCovView(v) { COV_VIEW = v; renderCovToolbar(); renderCovMatrix(); }
export function openTechnique(id) {
  document.getElementById('results-overlay').classList.remove('run-mode');
  var st = (state._covSt || {})[id] || 'none';
  var meta = { cov: ['Prevented', 'var(--success)'], part: ['Detected only', 'var(--warning)'], gap: ['Missed', 'var(--danger)'], none: ['Untested', 'var(--muted)'] }[st];
  apicall('/api/attack/technique/' + encodeURIComponent(id)).then(function(e) {
    e = e || {};
    document.getElementById('results-title').textContent = id + ' — ' + (e.name || 'Technique');
    document.getElementById('results-export').innerHTML = '';
    var row = function(k, v) { return v && v.length ? '<div class="g1-display-flex g1-s-b60b87ad"><span class="g1-s-485ffd37">' + k + '</span><span class="u-flex1">' + v + '</span></div>' : ''; };
    var list = function(a) { return (a || []).map(x).join(', '); };
    var body = '<div class="g1-s-462c8de6"><span class="sbadge g1-s-e02ce1a7"' + cssVars(['g1-v-97993078', meta[1]], ['g1-v-7d75dfc9', meta[1]]) + '>' + meta[0] + '</span></div>' +
      row('Tactics', list(e.tactics)) + row('Platforms', list(e.platforms)) +
      row('Known actors (ATT&CK reference)', list(e.groups)) + row('Data sources', list(e.dataSources)) +
      (e.description ? '<div class="g1-s-34d69e4c">' + x(e.description) + '</div>' : '') +
      (e.url ? '<div class="g1-s-6695a6e2"><a href="' + x(e.url) + '" target="_blank" rel="noopener" class="g1-s-824141a9">View on attack.mitre.org →</a></div>' : '');
    document.getElementById('results-body').innerHTML = body;
    document.getElementById('results-overlay').classList.add('open');
  }).catch(function(err) { showToast(err.message, 'err'); });
}