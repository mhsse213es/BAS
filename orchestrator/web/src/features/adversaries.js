import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { showToast } from '../core/util.js';
import { agentGroupTree, gpFlattenGroups, renderScenarios, resolveGroupTargetAgents } from './attack-path.js';
import { loadRuns } from './reports.js';
import { schedAgentCompatible } from './scheduled.js';
import { ROLE, showTab } from './shell.js';

// ── Threat Actor Library (Caldera emu adversary profiles) ──────────────────────

// ── Adversary Templates ───────────────────────────────────────────────────────
export var _templates = [];
var _tmplFilter = { cat: 'all' };
var _tmplRunID = null;  // template ID being launched
var _tmplCalderaID = ''; // resolved caldera adversary ID for current modal

export function loadAdversaryTemplates() {
  apicall('/api/adversary-templates').catch(function() { return []; }).then(function(d) {
    _templates = Array.isArray(d) ? d : [];
    renderTemplateGrid();
    if (state.scenarios.length) renderScenarios();
  });
}

export function setTmplFilter(dim, val) {
  _tmplFilter[dim] = val;
  document.querySelectorAll('.pfbtn[data-tf="' + dim + '"]').forEach(function(b) {
    b.classList.toggle('active', b.getAttribute('data-val') === val);
  });
  renderTemplateGrid();
}

export function renderTemplateGrid() {
  if (state.scenarioView !== 'templates') return; // #sc-tile-grid is shared across categories — only paint when this one is active
  var cat = _tmplFilter.cat;
  var filtered = _templates.filter(function(t) {
    return cat === 'all' || t.category === cat;
  });
  var catCls = { apt: 'tmpl-cat-apt', ransomware: 'tmpl-cat-ransomware', technique: 'tmpl-cat-technique', insider: 'tmpl-cat-insider' };
  var riskLabel = { critical: '● Critical', high: '● High', medium: '● Medium' };
  var riskColor = { critical: 'var(--danger)', high: 'var(--warning)', medium: 'var(--accent)' };

  var html = filtered.map(function(t) {
    var stripeClass = 'tmpl-stripe-' + (t.risk || 'high');
    var actorCls = catCls[t.category] || 'tmpl-cat-technique';
    var tactics = (t.tactics || []).slice(0, 4).map(function(tac) {
      return '<span style="font-size:0.65rem;padding:1px 6px;border-radius:7px;background:var(--elevated);border:1px solid var(--border);color:var(--muted)">' + x(tac) + '</span>';
    }).join('');
    var keyTechs = (t.keyTechniques || []).slice(0, 4).map(function(tid) {
      return '<span style="font-size:0.65rem;font-family:var(--font-mono);color:var(--accent)">' + x(tid) + '</span>';
    }).join(' ');
    // Source availability badges.
    var srcBAS    = t.basScenarioId    ? '<span class="utl-badge utl-bas">BAS</span>' : '';
    var srcART    = (t.artTechniques && t.artTechniques.length) ? '<span class="utl-badge utl-art">ART&nbsp;' + t.artTechniques.length + '</span>' : '';
    var srcCaldera = t.calderaAdversaryName ? '<span class="utl-badge utl-emu">Emu</span>' : '';

    return '<div class="tmpl-card ' + stripeClass + '">' +
      '<div style="padding:0.9rem 1rem 0.75rem">' +
        '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:0.5rem;margin-bottom:0.6rem">' +
          '<div>' +
            '<span class="tmpl-actor ' + actorCls + '">' + x(t.shortName || t.category) + '</span>' +
          '</div>' +
          '<span style="font-size:0.7rem;font-weight:700;color:' + (riskColor[t.risk] || 'var(--muted)') + '">' + (riskLabel[t.risk] || '') + '</span>' +
        '</div>' +
        '<div style="font-size:0.9rem;font-weight:700;color:var(--text);margin-bottom:0.3rem">' + x(t.name) + '</div>' +
        '<div style="font-size:0.75rem;color:var(--muted);line-height:1.45;margin-bottom:0.65rem;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden">' + x(t.description) + '</div>' +
        '<div style="display:flex;flex-wrap:wrap;gap:0.3rem;margin-bottom:0.55rem">' + tactics + '</div>' +
        '<div style="display:flex;flex-wrap:wrap;gap:0.3rem;margin-bottom:0.5rem">' + keyTechs + '</div>' +
        '<div style="display:flex;gap:0.3rem;flex-wrap:wrap;align-items:center;justify-content:space-between">' +
          '<div style="display:flex;gap:0.3rem">' + srcBAS + srcART + srcCaldera + '</div>' +
          '<span style="font-size:0.7rem;color:var(--muted)">' + x(t.estDuration || '') + '</span>' +
        '</div>' +
      '</div>' +
      '<div style="border-top:1px solid var(--border);padding:0.55rem 1rem;display:flex;gap:0.4rem;justify-content:flex-end">' +
        '<button class="btn btn-primary btn-sm" onclick="openTmplRun(\'' + x(t.id) + '\')">&#9654; Launch</button>' +
      '</div>' +
    '</div>';
  }).join('');

  var grid = document.getElementById('sc-tile-grid');
  if (grid) {
    grid.innerHTML = html
      ? '<div class="sc-fade" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:0.85rem">' + html + '</div>'
      : '<div class="empty" style="padding:1.5rem">No templates in this category.</div>';
  }
  var titleEl = document.getElementById('sc-backbar-title');
  if (titleEl) titleEl.textContent = 'Adversary Templates (' + filtered.length + ')';
}

export function openTmplRun(templateId) {
  var tmpl = null;
  for (var i = 0; i < _templates.length; i++) { if (_templates[i].id === templateId) { tmpl = _templates[i]; break; } }
  if (!tmpl) return;
  _tmplRunID = templateId;
  _tmplCalderaID = '';

  document.getElementById('tmpl-run-title').textContent = 'Launch — ' + tmpl.name;
  document.getElementById('tmpl-run-desc').textContent = tmpl.description;

  // Resolve Caldera adversary name → UUID using loaded adversary list.
  if (tmpl.calderaAdversaryName) {
    var name = tmpl.calderaAdversaryName.toLowerCase();
    for (var j = 0; j < _adversaries.length; j++) {
      if ((_adversaries[j].name || '').toLowerCase().indexOf(name) !== -1) {
        _tmplCalderaID = _adversaries[j].id;
        break;
      }
    }
  }

  // Build source checkboxes.
  var srcsEl = document.getElementById('tmpl-run-sources');
  var srcRows = '';
  if (tmpl.basScenarioId) {
    srcRows += '<label style="display:flex;align-items:flex-start;gap:0.6rem;cursor:pointer;font-size:0.82rem">' +
      '<input type="checkbox" id="tmpl-src-bas" checked onchange="renderTmplOSCompat()" style="margin-top:2px">' +
      '<span><span class="utl-badge utl-bas" style="margin-right:4px">BAS</span>' +
      '<strong>' + x(tmpl.basScenarioId) + '</strong> — native scenario</span></label>';
  }
  if (tmpl.artTechniques && tmpl.artTechniques.length) {
    srcRows += '<label style="display:flex;align-items:flex-start;gap:0.6rem;cursor:pointer;font-size:0.82rem">' +
      '<input type="checkbox" id="tmpl-src-art" checked onchange="renderTmplOSCompat()" style="margin-top:2px">' +
      '<span><span class="utl-badge utl-art" style="margin-right:4px">ART</span>' +
      tmpl.artTechniques.length + ' techniques — ' + tmpl.artTechniques.slice(0,3).join(', ') + (tmpl.artTechniques.length > 3 ? '…' : '') + '</span></label>';
  }
  if (tmpl.calderaAdversaryName) {
    var calLabel = _tmplCalderaID
      ? '<span class="utl-badge utl-emu" style="margin-right:4px">Emu</span>' + x(tmpl.calderaAdversaryName) + ' adversary'
      : '<span class="utl-badge" style="background:var(--elevated);border-color:var(--border);color:var(--muted);margin-right:4px">Emu</span>' +
        x(tmpl.calderaAdversaryName) + ' <em class="u-muted">(not found in Caldera — unchecked)</em>';
    srcRows += '<label style="display:flex;align-items:flex-start;gap:0.6rem;cursor:pointer;font-size:0.82rem">' +
      '<input type="checkbox" id="tmpl-src-caldera"' + (_tmplCalderaID ? ' checked' : '') + ' onchange="renderTmplOSCompat()" style="margin-top:2px">' +
      '<span>' + calLabel + '</span></label>';
  }
  if (srcsEl) srcsEl.innerHTML = srcRows || '<span style="color:var(--muted);font-size:0.8rem">No sources configured for this template.</span>';

  // Reset target selection state and (re)render whichever mode is active.
  state._tmplSelAgents = {};
  state._tmplGroupSel = {};
  _tmplTargetMode = 'individual';
  var allLabel = document.getElementById('tmpl-run-all-label');
  if (allLabel) allLabel.style.display = (ROLE === 'admin') ? 'flex' : 'none';
  var indRadio = document.querySelector('input[name="tmpl-run-target-mode"][value="individual"]');
  if (indRadio) indRadio.checked = true;
  setTmplTargetMode('individual');

  document.getElementById('tmpl-run-mode').value = 'telemetry';
  document.getElementById('tmpl-run-reason').value = '';
  renderTmplWarn();
  renderTmplOSCompat();
  var overlay = document.getElementById('tmpl-run-overlay');
  if (overlay) { overlay.style.display = 'flex'; }
}

export function closeTmplRun() {
  var overlay = document.getElementById('tmpl-run-overlay');
  if (overlay) overlay.style.display = 'none';
  _tmplRunID = null; _tmplCalderaID = '';
}

var _tmplTargetMode = 'individual'; // 'individual' | 'group' | 'all'
 // { [agentId]: true } for checked agents in Individual mode
  // { [groupId]: true } for checked groups in Group(s) mode

// setTmplTargetMode switches the run modal between its individual-agent
// checkbox list, the group checkbox list, and the All Agents notice,
// clearing the OTHER modes' selection state so a stale pick can't silently
// leak into a dispatch. Mirrors setVexRunTargetMode's exact pattern.
export function setTmplTargetMode(mode) {
  _tmplTargetMode = mode;
  if (mode !== 'individual') state._tmplSelAgents = {};
  if (mode !== 'group') state._tmplGroupSel = {};
  var indWrap = document.getElementById('tmpl-run-individual-wrap');
  var grpWrap = document.getElementById('tmpl-run-group-wrap');
  var allWrap = document.getElementById('tmpl-run-all-wrap');
  if (indWrap) indWrap.style.display = mode === 'individual' ? 'block' : 'none';
  if (grpWrap) grpWrap.style.display = mode === 'group' ? 'block' : 'none';
  if (allWrap) allWrap.style.display = mode === 'all' ? 'block' : 'none';
  if (mode === 'individual') renderTmplAgentList();
  if (mode === 'group') renderTmplGroupList();
  renderTmplOSCompat();
}

function renderTmplAgentList() {
  var list = document.getElementById('tmpl-run-agent-list');
  if (!list) return;
  var online = (state.agents || []).filter(function(a) { return a.status !== 'offline'; });
  if (!online.length) {
    list.innerHTML = '<p class="tiny muted" style="margin:0">No online agents.</p>';
  } else {
    list.innerHTML = online.map(function(a) {
      return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
        '<input type="checkbox" ' + (state._tmplSelAgents[a.agentId] ? 'checked' : '') +
        ' onchange="_tmplSelAgents[\'' + x(a.agentId) + '\']=this.checked;renderTmplAgentCount();renderTmplOSCompat()">' +
        '<code style="font-size:0.72rem">' + x(a.agentId) + '</code>' +
        '<span class="tiny muted">' + x(a.hostname) + ' — ' + x(a.osVersion || 'Unknown OS') + '</span></label>';
    }).join('');
  }
  renderTmplAgentCount();
}

export function renderTmplAgentCount() {
  var el = document.getElementById('tmpl-run-agent-cnt');
  if (!el) return;
  var n = Object.keys(state._tmplSelAgents).filter(function(k) { return state._tmplSelAgents[k]; }).length;
  el.textContent = n + ' selected';
}

// renderGroupCheckboxList is the shared shape behind renderTmplGroupList,
// renderGroupTargetList, renderVexGroupList, and renderVexRunGroupList
// (all previously hand-mirrored copies -- see the old comment this
// replaces: "renderTmplGroupList mirrors renderVexRunGroupList's exact
// pattern"): flatten the agent-group tree into a checkbox list showing
// each group's total agent count. stateVarName names the global
// {groupId: bool} selection map (read live via window[] so the render
// always reflects current state); summaryFnName is called after every
// render, empty or not; onchangeFnNames lists every function (by name,
// in order) a checkbox's own onchange should call after updating the
// selection map -- this is NOT always just [summaryFnName]
// (renderGroupTargetList's checkboxes call renderRunMode() instead, and
// renderTmplGroupList's call renderTmplGroupSummary() *and*
// renderTmplOSCompat()), so it's passed explicitly rather than assumed.
// renderEMSweepGroupList has a genuinely simpler shape (no count badge,
// no summary callback at all) and is intentionally not covered here.
export function renderGroupCheckboxList(listElId, emptyClass, stateVarName, summaryFnName, onchangeFnNames) {
  var list = document.getElementById(listElId);
  if (!list) return;
  var stateVar = window[stateVarName];
  var options = gpFlattenGroups(agentGroupTree, 0, null, []);
  if (!options.length) {
    list.innerHTML = '<p class="' + emptyClass + '" style="margin:0">No agent groups have been created yet.</p>';
    window[summaryFnName]();
    return;
  }
  var countMap = {};
  (function walk(nodes) {
    (nodes || []).forEach(function(n) { countMap[n.id] = n.totalAgentCount; walk(n.children); });
  })(agentGroupTree);
  var onchange = onchangeFnNames.map(function(fn) { return fn + '()'; }).join(';');
  list.innerHTML = options.map(function(o) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox" ' + (stateVar[o.id] ? 'checked' : '') +
      ' onchange="' + stateVarName + '[' + o.id + ']=this.checked;' + onchange + '">' +
      '<span style="font-size:0.8rem">' + x(o.label) + '</span>' +
      '<span class="tiny muted">(' + (countMap[o.id] || 0) + ' agents)</span></label>';
  }).join('');
  window[summaryFnName]();
}
function renderTmplGroupList() {
  renderGroupCheckboxList('tmpl-run-group-list', 'tiny muted', '_tmplGroupSel', 'renderTmplGroupSummary', ['renderTmplGroupSummary', 'renderTmplOSCompat']);
}

function tmplResolvedGroupAgents() {
  var selectedGroupIds = Object.keys(state._tmplGroupSel).filter(function(k) { return state._tmplGroupSel[k]; }).map(Number);
  return resolveGroupTargetAgents(selectedGroupIds);
}

export function renderTmplGroupSummary() {
  var el = document.getElementById('tmpl-run-group-summary');
  if (!el) return;
  var selectedCount = Object.keys(state._tmplGroupSel).filter(function(k) { return state._tmplGroupSel[k]; }).length;
  if (!selectedCount) { el.textContent = 'No groups selected.'; return; }
  el.textContent = tmplResolvedGroupAgents().length + ' agent(s) across ' + selectedCount + ' group(s).';
}

// tmplResolvedTargetAgents returns the full agent objects currently
// targeted, whichever mode is active -- the single source of truth both
// renderTmplOSCompat (preview) and confirmTmplRun (submit) resolve against,
// so they can never disagree about who's targeted.
function tmplResolvedTargetAgents() {
  if (_tmplTargetMode === 'group') return tmplResolvedGroupAgents();
  if (_tmplTargetMode === 'all') return (state.agents || []).filter(function(a) { return a.status !== 'offline'; });
  var selectedIds = Object.keys(state._tmplSelAgents).filter(function(k) { return state._tmplSelAgents[k]; });
  return (state.agents || []).filter(function(a) { return selectedIds.indexOf(a.agentId) !== -1; });
}

export function renderTmplWarn() {
  var mode = document.getElementById('tmpl-run-mode').value;
  var warn = document.getElementById('tmpl-run-warn');
  if (!warn) return;
  if (mode === 'telemetry') {
    warn.innerHTML = '<div style="padding:0.55rem 0.75rem;background:rgba(35,134,54,.1);border:1px solid rgba(35,134,54,.3);border-radius:var(--radius);color:#56d364">Telemetry mode — real techniques executed with production-safe guards. All cleanup steps run automatically.</div>';
  } else if (mode === 'lab') {
    warn.innerHTML = '<div style="padding:0.55rem 0.75rem;background:rgba(218,54,51,.1);border:1px solid rgba(218,54,51,.3);border-radius:var(--radius);color:#f85149">Lab mode — full fidelity. Run ONLY in isolated lab range. High-risk techniques will execute without production-safe guards.</div>';
  } else {
    warn.innerHTML = '';
  }
}

// renderTmplOSCompat shows a live warning when one or more CHECKED sources
// won't run on some of the currently targeted agents -- ART and Caldera are
// always Windows-only (hardcoded server-side, see RunAdversaryTemplate's
// synthSc literals); BAS inherits whatever supportedOs the referenced
// scenario itself declares. Unlike Scheduled Assessments/Variant Executor,
// this is informational, not a hard filter: dispatchRun evaluates each
// (agent, source) pair independently, so a Linux agent can legitimately
// still run a Linux-compatible BAS source while ART/Caldera get skipped on
// it -- excluding it from the target list outright would incorrectly block
// that partial run. Only warns in telemetry/lab mode, matching
// dispatchRun's own OS gate exactly (posture mode never blocks on OS).
// Aggregates across every agent tmplResolvedTargetAgents() currently
// returns, whichever target mode (individual/group/all) is active.
export function renderTmplOSCompat() {
  var warnEl = document.getElementById('tmpl-run-os-warn');
  var btn = document.getElementById('tmpl-run-confirm-btn');
  if (!warnEl) return;

  var tmpl = _templates.find(function(t) { return t.id === _tmplRunID; });
  var mode = (document.getElementById('tmpl-run-mode') || {}).value;
  var targets = tmpl ? tmplResolvedTargetAgents() : [];

  if (!tmpl || !targets.length || mode === 'posture') {
    warnEl.innerHTML = '';
    if (btn) btn.disabled = false;
    return;
  }

  var checkedSources = [];
  if ((document.getElementById('tmpl-src-bas') || {}).checked) {
    var basSc = state.scenarios.find(function(s) { return s.id === tmpl.basScenarioId; });
    checkedSources.push({ label: 'BAS', supportedOS: (basSc && basSc.supportedOs) || [] });
  }
  if ((document.getElementById('tmpl-src-art') || {}).checked) {
    checkedSources.push({ label: 'ART', supportedOS: ['windows'] });
  }
  if ((document.getElementById('tmpl-src-caldera') || {}).checked) {
    checkedSources.push({ label: 'Caldera', supportedOS: ['windows'] });
  }

  if (!checkedSources.length) {
    warnEl.innerHTML = '';
    if (btn) btn.disabled = false;
    return;
  }

  // Per-source: how many targeted agents can't run it.
  var skipCounts = checkedSources.map(function(src) {
    var n = targets.filter(function(a) { return !schedAgentCompatible(a, src.supportedOS); }).length;
    return { label: src.label, count: n };
  }).filter(function(s) { return s.count > 0; });

  // Agents with zero viable checked sources -- entirely excluded from this run.
  var deadAgents = targets.filter(function(a) {
    return checkedSources.every(function(src) { return !schedAgentCompatible(a, src.supportedOS); });
  });

  if (!skipCounts.length) {
    warnEl.innerHTML = '';
    if (btn) btn.disabled = false;
    return;
  }

  var skipLines = skipCounts.map(function(s) {
    return x(s.label) + ' skipped on ' + s.count + '/' + targets.length + ' agent(s)';
  }).join(' · ');

  if (deadAgents.length === targets.length) {
    warnEl.innerHTML = '<div style="padding:0.5rem 0.65rem;background:rgba(218,54,51,.1);border:1px solid rgba(218,54,51,.3);border-radius:var(--radius);color:#f85149">' +
      'No selected source can run on any targeted agent — ' + x(skipLines) + '.</div>';
    if (btn) btn.disabled = true;
    return;
  }

  var deadNote = deadAgents.length
    ? ' ' + deadAgents.length + '/' + targets.length + ' targeted agent(s) can run none of the selected sources and will be entirely skipped.'
    : '';
  warnEl.innerHTML = '<div style="padding:0.5rem 0.65rem;background:rgba(210,153,34,.1);border:1px solid rgba(210,153,34,.3);border-radius:var(--radius);color:var(--warning)">' +
    x(skipLines) + ' (require Windows).' + x(deadNote) + '</div>';
  if (btn) btn.disabled = false;
}
export function tmplRunModeChange() { renderTmplWarn(); renderTmplOSCompat(); }

export function confirmTmplRun() {
  var targets = tmplResolvedTargetAgents();
  if (!targets.length) { showToast('Select at least one target agent or group', 'err'); return; }
  var mode    = document.getElementById('tmpl-run-mode').value;
  var reason  = (document.getElementById('tmpl-run-reason').value || '').trim();
  var useBAS  = !!(document.getElementById('tmpl-src-bas') || {}).checked;
  var useART  = !!(document.getElementById('tmpl-src-art') || {}).checked;
  var calderaId = (document.getElementById('tmpl-src-caldera') || {}).checked ? _tmplCalderaID : '';

  if (!useBAS && !useART && !calderaId) {
    showToast('Select at least one execution source', 'err');
    return;
  }
  if (targets.length > 1 && !confirm('Launch this template on ' + targets.length + ' agent(s)?')) return;

  var btn = document.getElementById('tmpl-run-confirm-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Launching…'; }

  apicall('/api/adversary-templates/' + encodeURIComponent(_tmplRunID) + '/run', {
    method: 'POST',
    body: JSON.stringify({
      agentIds: targets.map(function(a) { return a.agentId; }),
      mode: mode, confirmLive: true, confirmLab: mode === 'lab',
      reason: reason || ('Template: ' + _tmplRunID),
      useBas: useBAS, useArt: useART,
      calderaAdversaryId: calderaId
    })
  }).then(function(r) {
    closeTmplRun();
    var dispatched = r.dispatched || [], skippedList = r.skipped || [];
    var agentsDispatched = {};
    dispatched.forEach(function(d) { agentsDispatched[d.agentId] = true; });
    var msg = dispatched.length + ' run' + (dispatched.length !== 1 ? 's' : '') + ' dispatched' +
      (targets.length > 1 ? ' across ' + Object.keys(agentsDispatched).length + ' agent(s)' : '');
    if (skippedList.length) msg += ' (' + skippedList.length + ' skipped)';
    showToast(msg, dispatched.length ? 'ok' : 'err');
    loadRuns();
    showTab('runs');
  }).catch(function(e) {
    showToast('Launch failed: ' + (e.message || 'unknown error'), 'err');
  }).finally(function() {
    if (btn) { btn.disabled = false; btn.textContent = 'Launch'; }
  });
}
// ─────────────────────────────────────────────────────────────────────────────

var _adversaries = [];
var _advDrawerID = null;
var _adversaryCollapsed = false;

// toggleAdversarySection collapses/expands the Threat Actor Library, mirroring
// the chevron/collapse pattern the scenario source groups above it already use
// (.sc-src-hdr/.collapsed) — this section previously had no way to collapse at
// all. renderAdversaryLibrary() (called on every search keystroke and refresh)
// never touches #adversary-hdr/#adversary-body, so this state survives re-renders.
export function toggleAdversarySection() {
  _adversaryCollapsed = !_adversaryCollapsed;
  var hdr = document.getElementById('adversary-hdr');
  var body = document.getElementById('adversary-body');
  if (hdr) hdr.classList.toggle('collapsed', _adversaryCollapsed);
  if (body) body.style.display = _adversaryCollapsed ? 'none' : '';
}

export function loadAdversaries() {
  apicall('/api/caldera/adversaries').then(function(data) {
    _adversaries = (data || []).filter(function(a) { return a.name; });
    renderAdversaryLibrary();
  }).catch(function() { /* Caldera not configured — silently skip */ });
}
export function loadAdversariesStop(el, event) { event.stopPropagation(); loadAdversaries(); }

export function renderAdversaryLibrary() {
  var grid = document.getElementById('adv-grid');
  var section = document.getElementById('adversary-section');
  var cnt = document.getElementById('adversary-cnt');
  if (!grid || !section) return;

  var q = (document.getElementById('adv-search') || {value:''}).value.trim().toLowerCase();
  var filtered = _adversaries.filter(function(a) {
    if (!q) return true;
    return (a.name || '').toLowerCase().indexOf(q) !== -1 ||
           (a.description || '').toLowerCase().indexOf(q) !== -1 ||
           (a.tactics || []).some(function(t) { return t.toLowerCase().indexOf(q) !== -1; });
  });

  section.style.display = _adversaries.length ? '' : 'none';
  if (cnt) cnt.textContent = _adversaries.length;

  if (!filtered.length) {
    grid.innerHTML = '<div style="color:var(--muted);font-size:0.82rem;padding:0.5rem 0">No threat actors match your search.</div>';
    return;
  }

  var tacticColors = {
    'initial-access':'#2f81f7','execution':'#f0883e','persistence':'#d29922',
    'privilege-escalation':'#f85149','defense-evasion':'#a371f7','credential-access':'#da3633',
    'discovery':'#9aa9bc','lateral-movement':'#0d9488','collection':'#56d364',
    'command-and-control':'#f0883e','exfiltration':'#da3633','impact':'#f85149'
  };
  function tacticChip(t) {
    var col = tacticColors[t] || 'var(--muted)';
    return '<span style="display:inline-block;padding:1px 7px;border-radius:9px;font-size:0.68rem;font-weight:600;background:' + col + '22;color:' + col + ';border:1px solid ' + col + '44;white-space:nowrap">' + x(t) + '</span>';
  }

  grid.innerHTML = filtered.map(function(a) {
    var tactics = (a.tactics || []).slice(0, 4).map(tacticChip).join(' ');
    var moreT = a.tactics && a.tactics.length > 4 ? ' <span style="color:var(--muted);font-size:0.68rem">+' + (a.tactics.length - 4) + '</span>' : '';
    var desc = (a.description || '').length > 100 ? a.description.substring(0, 97) + '…' : (a.description || 'MITRE CTID adversary emulation profile');
    var canRun = ROLE === 'admin' || ROLE === 'analyst';
    return '<div class="card" style="cursor:pointer;display:flex;flex-direction:column;gap:0.5rem;border-left:3px solid var(--accent)" onclick="openAdvDrawer(\'' + x(a.id) + '\')">' +
      '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:0.5rem">' +
        '<div style="font-size:0.9rem;font-weight:700;color:var(--text)">' + x(a.name) + '</div>' +
        '<span style="flex-shrink:0;font-size:0.72rem;color:var(--muted);background:var(--elevated);padding:2px 7px;border-radius:9px;border:1px solid var(--border)">' + (a.abilityCount || 0) + ' abilities</span>' +
      '</div>' +
      '<div style="font-size:0.78rem;color:var(--muted);line-height:1.45">' + x(desc) + '</div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:0.25rem">' + tactics + moreT + '</div>' +
      (canRun ? '<div style="margin-top:0.25rem" onclick="event.stopPropagation()">' +
        '<button class="btn btn-primary btn-sm u-w100" onclick="openAdvRunModal(\'' + x(a.id) + '\',\'' + x(a.name).replace(/'/g,'\\\'') + '\')">&#9654; Run</button>' +
      '</div>' : '') +
    '</div>';
  }).join('');
}

export function openAdvDrawer(adversaryId) {
  _advDrawerID = adversaryId;
  var adv = _adversaries.find(function(a) { return a.id === adversaryId; });
  var nameEl = document.getElementById('adv-drawer-name');
  var descEl = document.getElementById('adv-drawer-desc');
  var abEl   = document.getElementById('adv-drawer-abilities');
  var runWrap = document.getElementById('adv-drawer-run-wrap');
  if (!nameEl) return;
  nameEl.textContent = adv ? adv.name : adversaryId;
  descEl.textContent = adv ? (adv.description || '') : '';
  abEl.innerHTML = '<div style="color:var(--muted);font-size:0.78rem">Loading…</div>';
  if (runWrap) {
    var canRun = ROLE === 'admin' || ROLE === 'analyst';
    runWrap.innerHTML = canRun
      ? '<button class="btn btn-primary btn-sm u-w100" onclick="openAdvRunModal(\'' + x(adversaryId) + '\',\'' + (adv ? x(adv.name).replace(/'/g,'\\\'') : x(adversaryId).replace(/'/g,'\\\'')) + '\')">&#9654; Run this adversary</button>'
      : '';
  }
  document.getElementById('adv-drawer-overlay').style.display = '';
  document.getElementById('adv-drawer').style.display = '';

  apicall('/api/caldera/adversaries/' + encodeURIComponent(adversaryId)).then(function(d) {
    var abs = (d && d.abilities) || [];
    if (!abs.length) { abEl.innerHTML = '<div style="color:var(--muted);font-size:0.78rem">No abilities found.</div>'; return; }
    var tacticColors = {'discovery':'#9aa9bc','execution':'#f0883e','persistence':'#d29922',
      'privilege-escalation':'#f85149','defense-evasion':'#a371f7','credential-access':'#da3633',
      'lateral-movement':'#0d9488','collection':'#56d364','command-and-control':'#f0883e',
      'exfiltration':'#da3633','impact':'#f85149','initial-access':'#2f81f7'};
    abEl.innerHTML = abs.map(function(ab, i) {
      var col = tacticColors[ab.tactic] || 'var(--muted)';
      var badges = '';
      if ((ab.platforms || []).length) badges += '<span style="font-size:0.65rem;padding:1px 5px;border-radius:7px;background:var(--surface);border:1px solid var(--border);color:var(--muted)">' + x(ab.platforms.join('/')) + '</span>';
      if (ab.requiresPayload) badges += '<span style="font-size:0.65rem;padding:1px 5px;border-radius:7px;background:rgba(218,54,51,0.12);border:1px solid rgba(218,54,51,0.3);color:#da3633">payload</span>';
      if (ab.requiresAdmin)   badges += '<span style="font-size:0.65rem;padding:1px 5px;border-radius:7px;background:rgba(240,136,62,0.12);border:1px solid rgba(240,136,62,0.3);color:#f0883e">admin</span>';
      return '<div style="display:flex;align-items:flex-start;gap:0.5rem;padding:0.4rem 0.5rem;background:var(--elevated);border-radius:var(--radius);border:1px solid var(--border)">' +
        '<span style="flex-shrink:0;font-size:0.68rem;font-weight:700;color:var(--muted);padding-top:1px;min-width:20px">' + (i+1) + '</span>' +
        '<div style="flex:1;min-width:0">' +
          '<div style="font-size:0.8rem;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + x(ab.name || ab.id) + '</div>' +
          '<div style="display:flex;gap:0.35rem;margin-top:0.25rem;flex-wrap:wrap;align-items:center">' +
            (ab.technique ? '<span style="font-size:0.68rem;color:var(--accent);font-family:monospace">' + x(ab.technique) + '</span>' : '') +
            (ab.tactic ? '<span style="font-size:0.68rem;color:' + col + '">' + x(ab.tactic) + '</span>' : '') +
            badges +
          '</div>' +
        '</div>' +
      '</div>';
    }).join('');
  }).catch(function() {
    abEl.innerHTML = '<div style="color:var(--muted);font-size:0.78rem">Could not load ability chain.</div>';
  });
}

export function closeAdvDrawer() {
  document.getElementById('adv-drawer-overlay').style.display = 'none';
  document.getElementById('adv-drawer').style.display = 'none';
  _advDrawerID = null;
}

var _advRunID = null, _advRunName = null;

export function openAdvRunModal(adversaryId, adversaryName) {
  _advRunID = adversaryId; _advRunName = adversaryName;
  var overlay = document.getElementById('adv-run-overlay');
  var title   = document.getElementById('adv-run-title');
  var agSel   = document.getElementById('adv-run-agent');
  if (!overlay) return;
  title.textContent = adversaryName;
  agSel.innerHTML = state.agents.map(function(a) {
    var os = a.osVersion ? ' [' + (a.osVersion.toLowerCase().indexOf('windows') !== -1 ? 'Win' : 'Other') + ']' : '';
    return '<option value="' + x(a.agentId) + '">' + x(a.agentId) + ' — ' + x(a.hostname) + os + '</option>';
  }).join('');
  document.getElementById('adv-run-mode').value = 'telemetry';
  document.getElementById('adv-run-reason').value = '';
  renderAdvRunWarn();
  overlay.style.display = 'flex';
}

export function closeAdvRunModal() {
  var overlay = document.getElementById('adv-run-overlay');
  if (overlay) overlay.style.display = 'none';
  _advRunID = null; _advRunName = null;
}

export function renderAdvRunWarn() {
  var mode = document.getElementById('adv-run-mode').value;
  var warn = document.getElementById('adv-run-warn');
  if (!warn) return;
  if (mode === 'telemetry') {
    warn.style.display = '';
    warn.style.background = 'rgba(210,153,34,0.12)';
    warn.style.border = '1px solid rgba(210,153,34,0.35)';
    warn.style.color = '#d29922';
    warn.innerHTML = '&#9888; <strong>TELEMETRY mode</strong> — runs real, identity-safe ATT&amp;CK techniques and <strong>will generate EDR/SIEM alerts</strong>. Only proceed on an approved, monitored endpoint.';
  } else if (mode === 'lab') {
    warn.style.display = '';
    warn.style.background = 'rgba(218,54,51,0.10)';
    warn.style.border = '1px solid rgba(218,54,51,0.35)';
    warn.style.color = '#da3633';
    warn.innerHTML = '&#9888; <strong>LAB mode — FULL FIDELITY</strong>. Payload-bearing abilities (credential tools, lateral movement payloads) will execute. <strong>ISOLATED AD RANGE ONLY — NEVER PRODUCTION.</strong>';
  } else {
    warn.style.display = 'none';
  }
}

export function confirmAdversaryRun() {
  if (!_advRunID) return;
  var agentId = document.getElementById('adv-run-agent').value;
  var mode    = document.getElementById('adv-run-mode').value;
  var reason  = document.getElementById('adv-run-reason').value.trim();
  if (!agentId) { showToast('Select an agent', 'err'); return; }
  if (mode === 'telemetry') {
    if (!confirm('TELEMETRY mode will run real ATT&CK techniques and generate EDR/SIEM alerts.\n\nProceed only on an approved, monitored endpoint. Continue?')) return;
  } else if (mode === 'lab') {
    if (!confirm('LAB mode runs FULL-FIDELITY emulation (credential dumps, lateral movement payloads).\n\nISOLATED AD RANGE ONLY — never production. Continue?')) return;
    if (!confirm('Second confirmation required for LAB mode.\n\nConfirm the target is an isolated lab environment with a clean snapshot?')) return;
  }
  var btn = document.getElementById('adv-run-confirm-btn');
  if (btn) btn.disabled = true;
  apicall('/api/caldera/adversaries/' + encodeURIComponent(_advRunID) + '/run', {
    method: 'POST',
    body: JSON.stringify({ agentId: agentId, mode: mode, confirmLive: true, confirmLab: mode === 'lab', reason: reason })
  }).then(function(res) {
    closeAdvRunModal();
    showToast('Dispatched (' + mode + ') — Run ID: ' + res.runId, 'ok');
    showTab('runs'); loadRuns();
  }).catch(function(e) {
    showToast('Run failed: ' + e.message, 'err');
  }).finally(function() {
    if (btn) btn.disabled = false;
  });
}