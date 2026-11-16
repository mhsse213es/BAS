// Global search palette (Ctrl/Cmd-K). One box that finds pages, actions, scenarios (built-in and cloud), techniques,
// agents, runs, reports, findings and threat intel. Server results come from GET /api/search; pages, agents, reports
// and cloud scenarios are searched here, from data the console already has or fetches once when the palette opens.
// Ranking, scoping and highlighting live in gsearch-model.js.

import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { replaceClasses } from '../core/inline-style.js';
import { openRunReport } from './evidence.js';
import { openTechnique } from './coverage.js';
import { openFinding } from './findings.js';
import { openAgentDetail } from './agent-drawer.js';
import { focusPhishingEntry, renderScenarios, showSettingsSection, showThreatPriorityDetail } from './attack-path.js';
import { openBuilder, openModal } from './reports.js';
import { ROLE, showTab } from './shell.js';
import { cloudFocusScenario } from './cloud-scenarios.js';
import * as M from './gsearch-model.js';

var _open = false;
var RECENT_KEY = 'audspect.gsearch.scope';

function remembered() { try { var v = sessionStorage.getItem(RECENT_KEY); return v || 'all'; } catch (e) { return 'all'; } }
function remember(v) { try { sessionStorage.setItem(RECENT_KEY, v); } catch (e) { /* the scope just is not remembered */ } }

// Navigation entries as the sidebar shows them right now, so a page the user's role cannot see is never offered.
function navEntries() {
  var out = [], group = '';
  var root = document.getElementById('sidebar') || document;
  Array.prototype.forEach.call(root.querySelectorAll('.nav-group-label, .nav-item[data-tab]'), function(n) {
    if (n.classList.contains('nav-group-label')) { group = (n.textContent || '').trim(); return; }
    if (n.style && n.style.display === 'none') return;
    if (n.classList.contains('is-hidden') || n.hidden) return;
    var title = (n.getAttribute('title') || n.textContent || '').replace(/\s+/g, ' ').trim();
    if (title) out.push({ tab: n.getAttribute('data-tab'), title: title, group: group });
  });
  return out;
}

function actionList() {
  var a = [{ title: 'Run simulation', fn: function() { openModal(null, null); } }];
  if (ROLE === 'admin' || ROLE === 'analyst') a.unshift({ title: 'New scenario', fn: function() { openBuilder(); } });
  if (ROLE === 'admin') a.push({ title: 'Users & roles', fn: function() { showTab('settings'); showSettingsSection('users'); } });
  return a;
}

function openReport(item) {
  showTab('reports');
  setTimeout(function() {
    var q = document.getElementById('rpt-q');
    if (q) { q.value = item.reportId; q.dispatchEvent(new window.Event('input', { bubbles: true })); }
  }, 200);
}

function openScenarioByTitle(title) {
  showTab('scenarios');
  setTimeout(function() {
    var box = document.getElementById('sc-search');
    if (box) box.value = title;
    renderScenarios();
  }, 150);
}

// Open whatever the user picked. Server results also report the selection so recents and ranking learn from it.
function openItem(it) {
  if (it.kind === 'page') { showTab(it.tab); return; }
  if (it.kind === 'action') { it.fn(); return; }
  if (it.kind === 'agent') { showTab('agents'); setTimeout(function() { openAgentDetail(it.agentId); }, 150); return; }
  if (it.kind === 'report') { openReport(it); return; }
  if (it.kind === 'cloud') { showTab('cloud-scenarios'); setTimeout(function() { cloudFocusScenario(it.cloudId); }, 250); return; }
  if (it.kind === 'phish') { showTab('scenarios'); setTimeout(function() { focusPhishingEntry(it.phishId); }, 200); return; }
  if (it.kind === 'scenario') { openScenarioByTitle(it.title); return; }
  var r = it.ref;
  apicall('/api/search/select', { method: 'POST', body: JSON.stringify({ docType: r.docType, sourceId: r.sourceId }) }).catch(function() {});
  if (r.docType === 'run') openRunReport(r.sourceId);
  else if (r.docType === 'finding') { showTab('findings'); setTimeout(function() { openFinding(r.sourceId); }, 150); }
  else if (r.docType === 'actor') { showTab('threat-priority'); setTimeout(function() { showThreatPriorityDetail(r.title); }, 150); }
  else if (r.docType === 'technique') { showTab('attack-coverage'); setTimeout(function() { openTechnique(r.sourceId); }, 150); }
  else if (r.docType === 'scenario') openScenarioByTitle(r.title);
  else fallbackDrawer(r);
}

// Entities with no detail page of their own (campaign, malware, tool, rule, ...) show in the results drawer.
function fallbackDrawer(r) {
  document.getElementById('results-overlay').classList.remove('run-mode');
  document.getElementById('results-title').textContent = r.title + ' — ' + M.labelOf(r.docType);
  document.getElementById('results-export').innerHTML = '';
  document.getElementById('results-summary').innerHTML = '';
  document.getElementById('results-body').innerHTML =
    (r.description ? '<p class="gs-fb">' + x(r.description) + '</p>' : '') +
    ((r.tags || []).length ? '<div class="gs-fbtags">' + r.tags.map(function(t) { return '<span class="sbadge">' + x(t) + '</span>'; }).join('') + '</div>' : '');
  document.getElementById('results-overlay').classList.add('open');
}

function toggleFavorite(r, done) {
  apicall('/api/search/favorite', { method: 'POST', body: JSON.stringify({ docType: r.docType, sourceId: r.sourceId }) })
    .then(function(res) { r.favorited = !!(res && res.favorited); done(); }).catch(function() { done(); });
}

var ICON = {
  pages: '<path d="M4 5h16v14H4z"/><path d="M4 9h16"/>', scenario: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/>',
  technique: '<path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/>', agent: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  run: '<path d="M7 5l12 7-12 7z"/>', report: '<path d="M7 3h8l4 4v14H7z"/><path d="M10 12h6M10 16h6"/>',
  finding: '<path d="M12 3l9 16H3z"/><path d="M12 10v4"/>', intel: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
  other: '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>'
};
function icon(scope) { return '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (ICON[scope] || ICON.other) + '</svg>'; }

export function openCmdk() {
  if (_open || !ROLE) return;
  _open = true;
  var scope = remembered();
  var wrap = document.createElement('div');
  replaceClasses(wrap, 'cmdk-scrim');
  wrap.innerHTML =
    '<div class="cmdk gs" role="dialog" aria-label="Global search">' +
      '<div class="cmdk-in"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>' +
      '<input id="cmdk-input" placeholder="Search pages, scenarios, techniques, agents, reports…" autocomplete="off" aria-label="Search"><span class="cmdk-esc">esc</span></div>' +
      '<div class="gs-chips" id="gs-chips" role="tablist" aria-label="Search scope"></div>' +
      '<div class="cmdk-list" id="cmdk-list" role="listbox"></div>' +
      '<div class="gs-foot"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>↵</kbd> open</span><span><kbd>Tab</kbd> next scope</span><span id="gs-tip" class="gs-tip"></span></div>' +
    '</div>';
  document.body.appendChild(wrap);
  var input = wrap.querySelector('#cmdk-input'), list = wrap.querySelector('#cmdk-list'), chipsEl = wrap.querySelector('#gs-chips'), tip = wrap.querySelector('#gs-tip');

  // Local items: built once, from data the console already holds. Slower sources load in the background and the list
  // repaints when they arrive.
  var local = M.pageItems(navEntries()).concat(M.actionItems(actionList()), M.agentItems(state.agents), M.scenarioItems(state.scenarios));
  var recents = [], server = [], serverFailed = false, token = 0, timer = null, flat = [], active = 0;
  var hostOf = {};
  (state.agents || []).forEach(function(a) { if (a && a.agentId) hostOf[a.agentId] = a.hostname || a.agentId; });
  apicall('/api/reports').then(function(l) { local = local.concat(M.reportItems(l, hostOf)); repaint(); }).catch(function() {});
  apicall('/api/cloud-scenarios').then(function(c) {
    var list2 = Array.isArray(c) ? c : ((c && c.scenarios) || []);
    local = local.concat(M.cloudItems(list2.map(function(s) { return { id: s.id, name: s.name || s.id, provider: s.provider, providerLabel: ({ aws: 'AWS', azure: 'Azure', gcp: 'GCP' })[s.provider] || s.provider, description: s.description }; })));
    repaint();
  }).catch(function() {});
  apicall('/api/scenarios/library').then(function(l) { local = local.concat(M.phishingItems(l)); repaint(); }).catch(function() {});
  apicall('/api/search/recents').then(function(r) { recents = M.resultItems(Array.isArray(r) ? r : []); repaint(); }).catch(function() {});
  apicall('/api/search/operators').then(function(r) {
    var ops = (r && Array.isArray(r.operators)) ? r.operators : [];
    var t = ops.filter(function(o) { return o.name === 'type' && Array.isArray(o.values) && o.values.length; })[0];
    if (t) { tip.textContent = 'Tip: type:' + t.values[0] + ' filters by type'; }
  }).catch(function() {});

  function query() { return input.value.trim(); }

  function paintChips(counts, hasQuery) {
    chipsEl.innerHTML = M.SCOPES.map(function(s) {
      var n = hasQuery && s[0] !== 'all' ? (counts[s[0]] || 0) : null;
      if (n === 0 && s[0] !== scope) return '';
      return '<button type="button" role="tab" class="gs-chip' + (scope === s[0] ? ' on' : '') + '" data-scope="' + s[0] + '" aria-selected="' + (scope === s[0]) + '">' + x(s[1]) + (n ? '<em>' + n + '</em>' : '') + '</button>';
    }).join('');
  }

  function repaint() {
    var q = query(), has = q !== '';
    var items = has ? local.concat(M.resultItems(server)) : local.filter(function(i) { return i.scope === 'pages'; }).slice(0, 8);
    var res = has ? M.search(items, q, { scope: scope }) : null;
    flat = [];
    var html = '';
    if (!has) {
      if (recents.length && (scope === 'all')) {
        html += '<div class="cmdk-sec">Recents</div>';
        recents.slice(0, 6).forEach(function(it) { flat.push(it); html += rowHtml(it, flat.length - 1, ''); });
      }
      var pagesToShow = M.search(local.filter(function(i) { return i.scope === 'pages' && (scope === 'all' || scope === 'pages'); }), '', { scope: 'pages', limitPerScope: 12 });
      pagesToShow.sections.forEach(function(sec) {
        html += '<div class="cmdk-sec">' + x(sec.title) + '</div>';
        sec.items.forEach(function(it) { flat.push(it); html += rowHtml(it, flat.length - 1, ''); });
      });
      if (!flat.length) html = '<div class="cmdk-empty">Start typing to search.</div>';
      paintChips({}, false);
    } else {
      paintChips(res.counts, true);
      res.sections.forEach(function(sec) {
        html += '<div class="cmdk-sec">' + x(sec.title) + (sec.more ? '<span class="gs-more">+' + sec.more + ' more — pick the ' + x(sec.title) + ' tab</span>' : '') + '</div>';
        sec.items.forEach(function(it) { flat.push(it); html += rowHtml(it, flat.length - 1, q); });
      });
      if (serverFailed && !flat.length) html = '<div class="cmdk-empty">Search is unavailable right now. Pages and agents above still work.</div>';
      else if (!flat.length) html = '<div class="cmdk-empty">No matches for “' + x(q) + '”' + (scope !== 'all' ? ' in this scope. <button type="button" class="gs-link" data-scope="all">Search everything</button>' : '') + '</div>';
    }
    list.innerHTML = html;
    active = 0;
    wireRows();
    paintActive();
  }

  function rowHtml(it, i, q) {
    var star = it.ref ? '<span class="gs-star' + (it.fav ? ' on' : '') + '" data-fav="' + i + '" title="Favourite" role="button" aria-label="Toggle favourite">★</span>' : '';
    return '<div class="cmdk-item gs-row" role="option" data-ci="' + i + '"><span class="gs-ico gs-' + x(it.scope) + '">' + icon(it.scope) + '</span>' +
      '<span class="gs-main"><span class="gs-t">' + M.highlight(it.title, q) + '</span>' + (it.sub ? '<span class="gs-s">' + M.highlight(it.sub, q) + '</span>' : '') + '</span>' +
      star + '<span class="gs-badge">' + x(it.badge || '') + '</span></div>';
  }

  function wireRows() {
    Array.prototype.forEach.call(list.querySelectorAll('[data-ci]'), function(n) {
      n.onmousemove = function() { active = +n.dataset.ci; paintActive(); };
      n.onclick = function() { choose(+n.dataset.ci); };
    });
    Array.prototype.forEach.call(list.querySelectorAll('[data-fav]'), function(n) {
      n.onclick = function(e) {
        e.stopPropagation();
        var it = flat[+n.dataset.fav];
        if (it && it.ref) toggleFavorite(it.ref, function() { it.fav = !!it.ref.favorited; n.classList.toggle('on', it.fav); });
      };
    });
    Array.prototype.forEach.call(list.querySelectorAll('.gs-link[data-scope]'), function(n) { n.onclick = function() { setScope(n.dataset.scope); input.focus(); }; });
  }

  function paintActive() {
    Array.prototype.forEach.call(list.querySelectorAll('[data-ci]'), function(n) { n.classList.toggle('active', +n.dataset.ci === active); n.setAttribute('aria-selected', +n.dataset.ci === active ? 'true' : 'false'); });
    var n = list.querySelector('[data-ci="' + active + '"]');
    if (n && n.scrollIntoView) n.scrollIntoView({ block: 'nearest' });
  }

  function setScope(s) { scope = s; remember(s); repaint(); }

  function fetchServer() {
    clearTimeout(timer);
    var q = query();
    if (!q) { server = []; serverFailed = false; repaint(); return; }
    timer = setTimeout(function() {
      var mine = ++token;
      apicall('/api/search?q=' + encodeURIComponent(q) + '&limit=30').then(function(r) {
        if (mine !== token) return;
        server = Array.isArray(r) ? r : []; serverFailed = !Array.isArray(r); repaint();
      }).catch(function() { if (mine !== token) return; server = []; serverFailed = true; repaint(); });
    }, 150);
  }

  function choose(i) { var it = flat[i]; if (!it) return; close(); openItem(it); }
  function move(d) { if (!flat.length) return; active = (active + d + flat.length) % flat.length; paintActive(); }
  function close() { _open = false; document.removeEventListener('keydown', onKey, true); clearTimeout(timer); wrap.remove(); }
  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
    else if (e.key === 'Enter') { e.preventDefault(); choose(active); }
    else if (e.key === 'Tab') {
      e.preventDefault();
      var res = query() ? M.search(local.concat(M.resultItems(server)), query(), {}) : { counts: {} };
      var avail = query() ? Object.keys(res.counts) : null;
      setScope(M.nextScope(scope, e.shiftKey ? -1 : 1, avail));
    }
  }
  wrap.addEventListener('mousedown', function(e) { if (e.target === wrap) close(); });
  chipsEl.addEventListener('click', function(e) { var b = e.target.closest ? e.target.closest('[data-scope]') : null; if (b) { setScope(b.dataset.scope); input.focus(); } });
  document.addEventListener('keydown', onKey, true);
  input.addEventListener('input', function() { repaint(); fetchServer(); });
  repaint();
  setTimeout(function() { input.focus(); }, 20);
}
