import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { kpi, grid, card, hbars, pill, chip, empty, bar, kv, icon } from '../core/kit.js';
import { ring } from './runs-drawer.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './cov-model.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';


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
    state._covAnalytics = d.byTechnique || [];
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

function okState(title, sub) {
  return '<div class="cov-ok">' + icon('ok') + '<b>' + x(title) + '</b>' + (sub ? '<div>' + x(sub) + '</div>' : '') + '</div>';
}
function legendHtml() {
  return '<span class="cov-legend-inline"><span><i class="tone-ok"></i>Prevented</span><span><i class="tone-warn"></i>Detected only</span><span><i class="tone-bad"></i>Missed</span></span>';
}
function ringBlock(label, pct, t) {
  return '<div class="cov-ring">' + ring(pct, t) + '<div class="cov-ring-l">' + x(label) + '</div></div>';
}

function renderCoverageAnalytics(d) {
  var s = d.summary || {};
  var hasData = d.runsAnalyzed > 0 && s.attempted > 0;
  var root = document.getElementById('ca-root');
  var weakest = document.getElementById('cov-weakest');
  var gapsEl = document.getElementById('cov-gaps');
  if (!hasData) {
    if (root) root.innerHTML = empty('shield', 'No completed runs yet', 'Run a scenario or adversary template to generate analytics.');
    if (weakest) weakest.innerHTML = card('Weakest tactics', empty('technique', 'No completed runs yet'));
    if (gapsEl) gapsEl.innerHTML = card('Biggest gaps, fix these first', empty('shield', 'No completed runs yet'));
  } else {
    var runsTxt = d.runsAnalyzed + ' run' + (d.runsAnalyzed !== 1 ? 's' : '') + ' analysed';
    var tiles = grid(4, [
      kpi({ label: 'Techniques attempted', value: s.attempted, sub: runsTxt, icon: 'technique', tone: 'accent' }),
      kpi({ label: 'Prevented', value: s.prevented, sub: (s.preventionRate || 0) + '% prevention rate', icon: 'ok', tone: 'ok' }),
      kpi({ label: 'Detected only', value: s.detectedOnly, sub: 'EDR/SIEM alerted, not blocked', icon: 'warn', tone: 'warn' }),
      kpi({ label: 'Missed', value: s.missed, sub: 'No prevention, no detection', icon: 'bad', tone: 'bad' }),
    ]);
    var tac = d.byTactic || [];
    var byTac = card('By tactic', tac.length ? chartSlot({
      type: 'bar', stacked: true, h: 230,
      labels: tac.map(function(t) { return t.tactic; }),
      series: [
        { name: 'Prevented', data: tac.map(function(t) { return t.prevented; }), color: CHART_COLORS.ok },
        { name: 'Detected only', data: tac.map(function(t) { return t.detectedOnly; }), color: CHART_COLORS.warn },
        { name: 'Missed', data: tac.map(function(t) { return t.missed; }), color: CHART_COLORS.bad },
      ],
    }) : empty('technique', 'No tactic data'), { actions: legendHtml() });
    var rings = card('Prevention vs detection',
      '<div class="cov-rings">' + ringBlock('Prevention rate', s.preventionRate || 0, covTone(s.preventionRate)) + ringBlock('Detection coverage', s.detectionCoverage || 0, covTone(s.detectionCoverage)) + '</div>');
    var missed = (d.byTechnique || []).filter(function(t) { return t.bestVerdict === 'missed' || t.bestVerdict === 'detectedOnly'; }).slice(0, 8);
    var missRows = missed.map(function(t) {
      return '<tr><td>' + pill(t.techniqueId, t.bestVerdict === 'missed' ? 'bad' : 'warn') + '</td><td>' + x(t.name || '—') + '</td><td class="u-center">' + x(t.runCount) + '</td></tr>';
    });
    var missCard = card('Missed techniques, prioritize these', missed.length
      ? tableWrap([['Technique'], ['Name'], ['Runs', 'u-center']], missRows, '', 3)
      : okState('No gaps detected', 'Every attempted technique was prevented or detected.'), { flush: missed.length > 0, sub: missed.length ? 'top ' + missed.length : '' });
    if (root) root.innerHTML = tiles + '<div class="cov-side">' + byTac + '<div class="cov-col">' + rings + missCard + '</div></div>';
    if (weakest) {
      var wk = M.weakestTactics(tac, 5);
      weakest.innerHTML = card('Weakest tactics', wk.length ? hbars(wk.map(function(r) { return [r.name, r.pct, r.tone]; })) : empty('technique', 'No tactic data'));
    }
    if (gapsEl) {
      var gp = M.gapRows(d.byTechnique, 5);
      gapsEl.innerHTML = card('Biggest gaps, fix these first', gp.length ? tableWrap([['Technique'], ['Tactic'], ['Coverage'], ['Result']], gp.map(function(g) {
        return '<tr class="cov-row" tabindex="0"' + on('click', 'openTechnique', g.id) + '><td><div>' + x(g.name || g.id) + '</div><div class="rg2-mono muted">' + x(g.id) + '</div></td>' +
          '<td class="muted">' + x(g.tactic || '—') + '</td><td><div class="rg2-rate">' + bar(g.pct, covTone(g.pct)) + '<span>' + x(g.pct) + '%</span></div></td><td>' + pill(g.label, g.tone) + '</td></tr>';
      }), '', 4) : okState('No gaps detected', 'Every attempted technique was prevented or detected.'), { flush: gp.length > 0 });
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
    root.innerHTML = card('Privilege tier coverage', empty('lock', 'No privilege-annotated runs yet', 'Annotate scenario steps with requires_priv to enable tier tracking.'));
    return;
  }
  var tierRings = tiers.map(function(t) {
    var rate = t.attempted > 0 ? t.preventionRate : 0;
    return '<div class="cov-tier">' + ring(rate, covTone(rate)) + '<div><div class="cov-tier-l">' + x(TIER_LABEL[t.tier] || t.tier) + '</div><div class="cov-tier-v">' + x(t.prevented) + ' / ' + x(t.attempted) + '</div><div class="muted cov-tier-s">prevented · last 50 runs</div></div></div>';
  }).join('');
  var tierRows = tiers.map(function(t) {
    var rate = t.attempted > 0 ? t.preventionRate : 0;
    return '<tr><td>' + pill(TIER_LABEL[t.tier] || t.tier, TIER_TONE[t.tier] || 'muted') + '</td>' +
      '<td class="u-center">' + x(t.attempted) + '</td><td class="u-center"><span class="rg2-num tone-ok">' + x(t.prevented) + '</span></td>' +
      '<td class="u-center"><span class="rg2-num ' + (t.missed > 0 ? 'tone-bad' : 'tone-muted') + '">' + x(t.missed) + '</span></td>' +
      '<td><div class="rg2-rate">' + bar(rate, covTone(rate)) + '<span>' + x(rate) + '%</span></div></td></tr>';
  });
  var gapRowsHtml = gaps.slice(0, 25).map(function(g) {
    return '<tr><td><span class="rg2-mono">' + x(g.techniqueId) + '</span></td><td title="' + x(g.name || '') + '">' + x(g.name || '—') + '</td><td>' +
      (g.tiers || []).map(function(t) { return chip(TIER_LABEL[t] || t, TIER_TONE[t] || 'muted'); }).join(' ') + '</td></tr>';
  });
  if (gaps.length > 25) gapRowsHtml.push('<tr><td colspan="3" class="u-muted">… and ' + (gaps.length - 25) + ' more</td></tr>');
  root.innerHTML = '<div class="rk-grid g2">' +
    card('Privilege tier coverage', '<div class="cov-tiers">' + tierRings + '</div>' +
      tableWrap([['Tier'], ['Attempted', 'u-center'], ['Prevented', 'u-center'], ['Missed', 'u-center'], ['Rate']], tierRows, 'No data', 5), { cls: 'cov-priv' }) +
    card('Privilege coverage gaps, tested elevated only', gaps.length
      ? tableWrap([['Technique'], ['Name'], ['Tested at']], gapRowsHtml, '', 3) +
        '<p class="rg2-note">Gaps are techniques never run as a standard user. Run these at user tier so controls are not solely relying on privilege barriers.</p>'
      : okState('All annotated techniques tested at user tier', 'Gaps are techniques never run as a standard user. Run these at user tier so controls do not rely only on privilege barriers.'), { flush: gaps.length > 0, cls: 'cov-priv' }) +
    '</div>';
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

export function renderUTL() {
  var q = (document.getElementById('utl-search') || {}).value || '';
  var tactic = ((document.getElementById('utl-tactic') || {}).value) || 'all';
  var filtered = M.libFilter(_utlData, { q: q, tactic: tactic, src: _utlFilter.src });

  // Summary line above the table.
  var sumEl = document.getElementById('utl-summary');
  var sm = M.libSummary(_utlData);
  if (sumEl) sumEl.textContent = sm.total.toLocaleString() + ' unique techniques — ' +
    'BAS ' + sm.bas + ' · ART ' + sm.art + ' · Emu ' + sm.emu + ' · Atomic ' + sm.atomic + '.';

  var cov = state._covSt || {};
  var rows = filtered.map(function(t) {
    var verdict = cov[t.techniqueId] || '';
    var vdot = verdict === 'pass'  ? '<span class="u-success">●</span>' :
               verdict === 'fail'  ? '<span class="u-danger">●</span>'  :
               verdict === 'error' ? '<span class="u-muted">●</span>'   : '';
    function cell(v, strong) {
      return '<td class="u-center">' + (v > 0 ? '<span class="' + (strong ? 'cov-n strong' : 'cov-n') + '">' + x(v) + '</span>' : '<span class="utl-zero">—</span>') + '</td>';
    }
    var nsrc = M.sourceCount(t);
    return '<tr class="cov-row" tabindex="0"' + on('click', 'openTechnique', t.techniqueId) + '>' +
      '<td class="rg2-mono">' + x(t.techniqueId) + ' ' + vdot + '</td>' +
      '<td title="' + x(t.name || '') + '">' + x(t.name || '—') + '</td>' +
      '<td>' + (t.tactic ? chip(t.tactic, 'info') : '<span class="muted">—</span>') + '</td>' +
      cell(t.basCount, true) + cell(t.artCount) + cell(t.emuCount) + cell(t.atomicCount) +
      '<td class="u-center"><span class="cov-n">' + x(t.totalVariants) + '</span></td>' +
      '<td class="u-center muted">' + nsrc + (nsrc === 1 ? ' src' : ' srcs') + '</td>' +
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
    var h = M.heroStats(counts), dash = function(v) { return v == null ? '—' : v; };
    setHeroStat('cov-hs-covered', dash(h.covered));
    setHeroStat('cov-hs-detected', dash(h.detected));
    setHeroStat('cov-hs-missed', dash(h.missed));
    setHeroStat('cov-hs-untested', dash(h.untested));
    renderCovToolbar(); renderCovMatrix();
    document.getElementById('cov-foot').textContent =
      'Showing ' + counts.total + ' techniques across ' + tactics.length +
      ' tactics · coverage = last validated result per technique, not theoretical inventory.';
  }).catch(function(e) {
    document.getElementById('cov-matrix').innerHTML = '<div class="empty g1-s-be6df18e">' + x(e.message) + '</div>';
  });
}

// Recalculate (banner button): reload every panel on the page from the server.
export function recalcCoverage() {
  loadCoverage(); loadCoverageAnalytics(); loadUnifiedTechniques(); loadThreatExposure();
}

// ── Live Threat Coverage (TCF Phase 10) ──────────────────────────────────────
export function loadThreatExposure() {
  apicall('/api/threats/exposure?limit=50').catch(function() { return null; }).then(function(d) {
    renderThreatExposure(d || []);
  });
}

function renderThreatExposure(threats) {
  var body = document.getElementById('lte-body');
  var live = document.getElementById('cov-livecov');
  if (!body) return;
  var rows = M.threatRows(threats);
  if (!rows.length) {
    body.innerHTML = card('Tracked threats', empty('globe', 'No active threats tracked yet', 'Threats appear here once your intelligence sources report them.'));
    if (live) live.innerHTML = card('Live Threat Coverage', empty('globe', 'No active threats tracked yet'));
    return;
  }
  var list = rows.map(function(r) {
    var tag = !r.techCount ? chip('No techniques', 'muted') : r.withContent ? chip(r.withContent + '/' + r.techCount + ' executable', 'ok') : chip('No content yet', 'warn');
    return '<div class="cov-thr"><div class="cov-av">' + x(r.initial) + '</div><div class="cov-thr-t"><b>' + x(r.title) + '</b>' +
      '<div class="muted">Last seen ' + x(r.lastSeenAt ? new Date(r.lastSeenAt).toLocaleDateString() : 'unknown') + ' · ' + r.techCount + ' technique' + (r.techCount === 1 ? '' : 's') + ' tracked, ' + r.withContent + ' with executable content</div></div>' + tag + '</div>';
  }).join('');
  body.innerHTML = card('Tracked threats', '<div class="rk-grid g2">' + list + '</div>', { sub: rows.length + ' active threat' + (rows.length === 1 ? '' : 's') + ' shown' });
  if (live) {
    live.innerHTML = card('Live Threat Coverage',
      '<p class="cov-lead">Share of each tracked threat\'s techniques that have executable content.</p>' +
      hbars(rows.filter(function(r) { return r.techCount; }).slice(0, 6).map(function(r) { return [M.shortTitle(r.title, 24), r.pct, covTone(r.pct), r.withContent + '/' + r.techCount]; })));
  }
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
  var chips = [['all', 'All', ''], ['cov', 'Prevented', 'ok'], ['part', 'Detected only', 'warn'], ['gap', 'Missed', 'bad'], ['none', 'Untested', 'muted']];
  document.getElementById('cov-toolbar').innerHTML = '<div class="cov-chips">' + chips.map(function(o) {
    return '<button type="button" class="cov-chip' + (COV_VIEW === o[0] ? ' on' : '') + '"' + on('click', 'setCovView', o[0]) + '>' +
      (o[2] ? '<i class="cov-dot tone-' + o[2] + '"></i>' : '') + x(o[1]) + '</button>';
  }).join('') + '</div>';
}
export function setCovView(v) { COV_VIEW = v; renderCovToolbar(); renderCovMatrix(); }

// The technique drawer: ATT&CK reference for one technique plus what this console knows about it.
export function openTechnique(id) {
  var st = (state._covSt || {})[id] || 'none';
  var vi = M.verdictInfo(st);
  var an = ((state._covAnalytics || []).filter(function(t) { return t.techniqueId === id; })[0]) || null;
  var lib = _utlData.filter(function(t) { return t.techniqueId === id; })[0] || null;
  apicall('/api/attack/technique/' + encodeURIComponent(id)).then(function(e) {
    e = e || {};
    var set = function(eid, t) { var el = document.getElementById(eid); if (el) el.textContent = t; };
    set('cov-drawer-title', e.name || 'Technique');
    set('cov-drawer-sub', id);
    var list = function(a) { return (a || []).join(', '); };
    var facts = [['Tactics', list(e.tactics)], ['Platforms', list(e.platforms)], ['Known actors (ATT&CK reference)', list(e.groups)], ['Data sources', list(e.dataSources)]]
      .filter(function(r) { return r[1]; });
    var link = e.url && /^https?:\/\//i.test(e.url)
      ? '<p class="cov-dr-link"><a href="' + x(e.url) + '" target="_blank" rel="noopener">View on attack.mitre.org →</a></p>' : '';
    var body = document.getElementById('cov-drawer-body');
    if (body) {
      body.innerHTML = grid(3, [
        kpi({ label: 'Result', value: vi.label, sub: 'Last validated', icon: 'shield', tone: vi.tone }),
        kpi({ label: 'Runs', value: an ? an.runCount : '—', sub: an ? 'in the analysed window' : 'not in the analysed window', icon: 'play', tone: 'accent' }),
        kpi({ label: 'Variants', value: lib ? lib.totalVariants : '—', sub: lib ? M.sourceCount(lib) + ' source(s)' : 'not in the library', icon: 'layers', tone: 'muted' }),
      ]) + (facts.length ? '<div class="cov-dr-kv">' + kv(facts) + '</div>' : '') +
        (e.description ? '<p class="cov-dr-desc">' + x(e.description) + '</p>' : '') + link;
    }
    var o = document.getElementById('cov-drawer-overlay');
    if (o) o.classList.add('open');
  }).catch(function(err) { showToast(err.message, 'err'); });
}
export function closeCovDrawer() {
  var o = document.getElementById('cov-drawer-overlay');
  if (o) o.classList.remove('open');
}
export function closeCovDrawerOnBackdrop(el, event) { if (event.target === el) closeCovDrawer(); }
