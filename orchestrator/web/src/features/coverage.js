import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { covSegHtml } from './attack-path.js';
import { setDisplay } from '../core/inline-style.js';
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

function renderCoverageAnalytics(d) {
  var s = d.summary || {};
  var hasData = d.runsAnalyzed > 0 && s.attempted > 0;
  var emEl = document.getElementById('ca-empty');
  var detEl = document.getElementById('ca-detail');
  var ratesEl = document.getElementById('ca-rates');
  if (emEl) setDisplay(emEl, hasData ? 'none' : '');
  if (detEl) setDisplay(detEl, hasData ? '' : 'none');
  if (ratesEl) setDisplay(ratesEl, hasData ? '' : 'none');

  // Scorecards.
  setText('ca-attempted', hasData ? s.attempted : '—');
  setText('ca-prevented', hasData ? s.prevented : '—');
  setText('ca-detected',  hasData ? s.detectedOnly : '—');
  setText('ca-missed',    hasData ? s.missed : '—');
  setText('ca-runs', d.runsAnalyzed + ' run' + (d.runsAnalyzed !== 1 ? 's' : '') + ' analysed');
  setText('ca-prev-pct', hasData ? s.preventionRate + '% prevention rate' : 'Control blocked execution');

  // Rate bars.
  var prevRate = s.preventionRate || 0;
  var detRate  = s.detectionCoverage || 0;
  setText('ca-prev-rate', prevRate + '%');
  setText('ca-det-rate',  detRate + '%');
  setW('ca-prev-bar', prevRate);
  setW('ca-det-bar',  detRate);

  // By-tactic table.
  var tacBody = document.getElementById('ca-tactic-body');
  if (tacBody) {
    tacBody.innerHTML = (d.byTactic || []).map(function(t, i) {
      var bg = i % 2 ? 'g1-s-ab376776' : '';
      var mColor = t.missed > 0 ? 'g1-s-d55cf847' : 'g1-s-c6db10d2';
      return '<tr class="' + bg + '">' +
        '<td>' + x(t.tactic) + '</td>' +
        '<td class="g1-s-ffa42d22">' + t.prevented + '</td>' +
        '<td class="g1-s-08242b1e">' + t.detectedOnly + '</td>' +
        '<td class="' + mColor + '">' + t.missed + '</td>' +
      '</tr>';
    }).join('') || '<tr><td colspan="4" class="empty">No data</td></tr>';
  }

  // Missed techniques table (show top 20 missed or detectedOnly).
  var missedBody = document.getElementById('ca-missed-body');
  if (missedBody) {
    var missed = (d.byTechnique || []).filter(function(t) { return t.bestVerdict === 'missed' || t.bestVerdict === 'detectedOnly'; }).slice(0, 20);
    missedBody.innerHTML = missed.map(function(t, i) {
      var bg = i % 2 ? 'g1-s-ab376776' : '';
      var vColor = t.bestVerdict === 'missed' ? 'g1-s-97b209c3' : 'g1-s-ce668815';
      var vDot   = t.bestVerdict === 'missed' ? '● ' : '◐ ';
      return '<tr class="' + bg + '">' +
        '<td class="' + vColor + '">' + vDot + x(t.techniqueId) + '</td>' +
        '<td class="g1-s-5d164a6d">' + x(t.name || '—') + '</td>' +
        '<td class="g1-s-557a346f">' + t.runCount + '</td>' +
      '</tr>';
    }).join('') || '<tr><td colspan="3" class="empty u-success">✓ No gaps detected</td></tr>';
  }

  // Privilege tier coverage panel.
  renderPrivilegeCoverage(d.privilegeCoverage);
}

function renderPrivilegeCoverage(pc) {
  var empty = document.getElementById('priv-cov-empty');
  var content = document.getElementById('priv-cov-content');
  var tiers = (pc && pc.byTier) || [];
  var gaps  = (pc && pc.gapTechs) || [];
  var hasTiers = tiers.length > 0;
  if (empty)   setDisplay(empty, hasTiers ? 'none' : '');
  if (content) setDisplay(content, hasTiers ? ''     : 'none');
  if (!hasTiers) return;

  // Tier colour map.
  var tierColor = { user: 'var(--accent)', admin: 'var(--warning)', system: 'var(--danger)', inherited: 'var(--muted)' };
  var tierLabel = { user: 'User', admin: 'Admin', system: 'SYSTEM', inherited: 'Inherited' };

  // Scorecard tiles.
  var cards = document.getElementById('priv-tier-cards');
  if (cards) {
    cards.innerHTML = tiers.map(function(t) {
      var col  = tierColor[t.tier] || 'var(--muted)';
      var lbl  = tierLabel[t.tier] || t.tier;
      var rate = t.attempted > 0 ? t.preventionRate : 0;
      var rateColor = rate >= 75 ? 'g1-s-da30d03b' : rate >= 40 ? 'g1-s-c16ccf0e' : 'g1-s-7419514e';
      return '<div class="ca-card"' + cssVars(['g1-v-c3984016', col]) + '>' +
        '<div class="ca-label"' + cssVars(['g1-v-7d75dfc9', col]) + '>' + lbl + '</div>' +
        '<div class="ca-val ' + rateColor + '">' + rate + '%</div>' +
        '<div class="ca-sub">' + t.prevented + '/' + t.attempted + ' prevented</div>' +
      '</div>';
    }).join('');
  }

  // Tier table.
  var tierBody = document.getElementById('priv-tier-body');
  if (tierBody) {
    tierBody.innerHTML = tiers.map(function(t, i) {
      var bg   = i % 2 ? 'g1-s-ab376776' : '';
      var col  = tierColor[t.tier] || 'var(--muted)';
      var lbl  = tierLabel[t.tier] || t.tier;
      var rate = t.attempted > 0 ? t.preventionRate : 0;
      var rateColor = rate >= 75 ? 'g1-s-01465934' : rate >= 40 ? 'g1-s-a21d7ec5' : 'g1-s-1ea0edbe';
      var barW = Math.min(100, rate);
      var missedColor = t.missed > 0 ? 'g1-s-d55cf847' : 'g1-s-1724190c';
      return '<tr class="' + bg + '">' +
        '<td><span class="g1-display-inline-block g1-s-acac4f97"' + cssVars(['g1-v-9ffd39ba', col]) + '></span>' + lbl + '</td>' +
        '<td class="u-center">' + t.attempted + '</td>' +
        '<td class="g1-s-ffa42d22">' + t.prevented + '</td>' +
        '<td class="' + missedColor + '">' + t.missed + '</td>' +
        '<td class="g1-s-229dc0cb">' +
          '<div class="g1-display-flex g1-s-04e50eda">' +
            '<div class="g1-s-8987c970"><div class="g1-s-32cf8ef3"' + cssVars(['g1-v-9b890877', barW], ['g1-v-9ffd39ba', col]) + '></div></div>' +
            '<span class="' + rateColor + '">' + rate + '%</span>' +
          '</div>' +
        '</td>' +
      '</tr>';
    }).join('') || '<tr><td colspan="5" class="empty">No data</td></tr>';
  }

  // Gap table.
  var gapBody = document.getElementById('priv-gap-body');
  if (gapBody) {
    if (gaps.length === 0) {
      gapBody.innerHTML = '<tr><td colspan="3" class="empty u-success">✓ All annotated techniques tested at user tier</td></tr>';
    } else {
      gapBody.innerHTML = gaps.slice(0, 25).map(function(g, i) {
        var bg = i % 2 ? 'g1-s-ab376776' : '';
        var tierBadges = (g.tiers || []).map(function(t) {
          var c = tierColor[t] || 'var(--muted)';
          return '<span class="g1-s-1fd67b02"' + cssVars(['g1-v-97993078', c], ['g1-v-7d75dfc9', c]) + '>' + (tierLabel[t] || t) + '</span>';
        }).join('');
        return '<tr class="' + bg + '">' +
          '<td class="g1-s-ce668815">' + x(g.techniqueId) + '</td>' +
          '<td class="g1-s-20a371c8" title="' + x(g.name || '') + '">' + x(g.name || '—') + '</td>' +
          '<td>' + tierBadges + '</td>' +
        '</tr>';
      }).join('');
      if (gaps.length > 25) {
        gapBody.innerHTML += '<tr><td colspan="3" class="g1-s-f85dc79d">… and ' + (gaps.length - 25) + ' more</td></tr>';
      }
    }
  }
}

function setText(id, v) { var el = document.getElementById(id); if (el) el.textContent = v; }
function setW(id, pct)  { var el = document.getElementById(id); if (el) el.style.width = Math.min(100, pct) + '%'; }
// ─────────────────────────────────────────────────────────────────────────────

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
  var badge = function(col, l, v) { return '<span class="sbadge g1-s-e9d33194"' + cssVars(['g1-v-7d75dfc9', col]) + '>' + v + ' ' + l + '</span>'; };
  document.getElementById('cov-toolbar').innerHTML =
    seg + '<span class="u-flex1"></span>' +
    badge('var(--success)', 'Prevented', c.cov) + badge('var(--warning)', 'Detected', c.part) +
    badge('var(--danger)', 'Missed', c.gap) + badge('var(--muted)', 'Untested', c.none);
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
      row('Known actors', list(e.groups)) + row('Data sources', list(e.dataSources)) +
      (e.description ? '<div class="g1-s-34d69e4c">' + x(e.description) + '</div>' : '') +
      (e.url ? '<div class="g1-s-6695a6e2"><a href="' + x(e.url) + '" target="_blank" rel="noopener" class="g1-s-824141a9">View on attack.mitre.org →</a></div>' : '');
    document.getElementById('results-body').innerHTML = body;
    document.getElementById('results-overlay').classList.add('open');
  }).catch(function(err) { showToast(err.message, 'err'); });
}