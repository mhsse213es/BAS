import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { renderGroupCheckboxList } from './adversaries.js';
import { resolveGroupTargetAgents } from './attack-path.js';
import { openSweepPreview } from './endpoint-mastery.js';
import { schedClassifyOS, vexFilterWindowsAgents } from './scheduled.js';
import { ROLE } from './shell.js';
import { VEX_POLL_MAX_FAILURES } from './variant-executor.js';


// ── Run Variants reload-survival ────────────────────────────────────────────
// A Run Variants dispatch (single technique, or a queued multi-technique
// batch) only ever tracked its live state in JS variables -- a page reload
// wiped them, leaving the result panel blank forever even though the
// dispatched run itself kept going server-side. Worse for a queued batch:
// nothing but this tab's own JS loop (_vexWaitAndNext -> _vexRunVariantQueue)
// ever dispatches the NEXT technique, so a reload didn't just blank the
// panel, it silently stopped the rest of the queue from running at all.
// _vexSaveActiveState/_vexLoadActiveState/_vexClearActiveState persist just
// enough (which run to reconnect to, and the queue's remaining work) in
// localStorage to survive a reload; _vexResumeActiveRun reconnects on load.
var VEX_ACTIVE_KEY = 'bas_vex_active_run';
function _vexSaveActiveState(active) {
  try { localStorage.setItem(VEX_ACTIVE_KEY, JSON.stringify(active)); } catch (e) {}
}
function _vexLoadActiveState() {
  try {
    var raw = localStorage.getItem(VEX_ACTIVE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) { return null; }
}
function _vexClearActiveState() {
  try { localStorage.removeItem(VEX_ACTIVE_KEY); } catch (e) {}
}

export function _vexResumeActiveRun() {
  if (state._vexRunPoll || state._vexActivePoll) return; // already polling something this session
  var st = _vexLoadActiveState();
  if (!st || !st.vrId) return;
  apicall('/api/variants/run/' + st.vrId).then(function(detail) {
    var s = detail.run && detail.run.status;
    if (!s || s === 'completed' || s === 'failed' || s === 'partial') {
      // The in-flight technique already finished while nobody was watching.
      // For a queue, pick up right where it left off rather than silently
      // abandoning the remaining techniques.
      if (st.techniques.length > 1 && st.idx + 1 < st.techniques.length) {
        state._vexAbortRequested = false;
        var btn = document.getElementById('vex-run-btn');
        if (btn) btn.disabled = true;
        _vexRunVariantQueue(st.agentId, st.techniques, st.mode, st.advanced, st.baseType, st.idx + 1);
      } else {
        _vexClearActiveState();
      }
      return;
    }
    // Still running -- reconnect the live panel/polling exactly as if this
    // tab had never left.
    state._vexAbortRequested = false;
    state._vexActiveScenarioRunId = detail.run.scenarioRunId || null;
    var btn2 = document.getElementById('vex-run-btn');
    if (btn2) { btn2.disabled = true; btn2.textContent = st.techniques.length > 1 ? (st.idx + 1) + '/' + st.techniques.length + ' Running…' : 'Dispatching…'; }
    if (st.techniques.length > 1) {
      _vexRenderQueuePanel(st.techniques[st.idx], st.idx, st.techniques);
      _vexWaitAndNext(st.vrId, st.agentId, st.techniques, st.mode, st.advanced, st.baseType, st.idx);
    } else {
      pollVariantRun(st.vrId);
    }
  }).catch(function() { _vexClearActiveState(); });
}

// _vexAvailableVariants caches the server-computed real variant total (ART
// atomic tests x encoding/privilege/context) once loadVariantStats resolves,
// so the Full Sweep confirm dialog can quote the same number shown in the
// "Total Variants" stat card instead of a separate rough guess.
export var _vexAvailableVariants = 0;

export function loadVariantStats() {
  apicall('/api/variants/stats').then(function(s) {
    var el = document.getElementById('vex-stats');
    if (!el) return;
    var artTech = s.artTechniqueCount || 0;
    var artAtomic = s.artAtomicCount || 0;
    var perFamily = s.variantsPerFamily || 56;
    _vexAvailableVariants = s.availableVariants || 0;
    el.innerHTML =
      vexStatCard('Executed Variants',     s.executedVariants,       'var(--accent)', null,
        'How many individual variant executions (encoding \xd7 privilege \xd7 context combinations) have actually completed so far, summed across every finished variant run — not the total available.') +
      vexStatCard('Total Variants',        s.availableVariants,      'var(--text)',   artAtomic.toLocaleString() + ' ART tests across ' + artTech + ' techniques \xd7 encoding/privilege/context',
        'The full combinatorial test space: every one of the ' + artAtomic.toLocaleString() + ' ART atomic tests (across ' + artTech + ' techniques) multiplied by the encoding, privilege, and execution-context variations BAS can generate for it. This is what a Full Sweep dispatches in total, not what has run yet.') +
      vexStatCard('Custom Payload Families', s.payloadFamilyCount,   'var(--text)',   s.payloadFamilyCount + ' families \xd7 ' + perFamily + ' variants = ' + (s.payloadFamilyVariants || 0).toLocaleString(),
        'Custom (non-ART) payload families you’ve authored yourself. Each one expands into ' + perFamily + ' variants (encoding/obfuscation/delivery combinations) — counted separately from, and in addition to, the ART-derived Total Variants figure.') +
      vexStatCard('Custom-Enhanced Techniques', s.techniquesWithFamilies, 'var(--text)', 'of ' + artTech + ' ART techniques have custom payload families',
        'How many of the ' + artTech + ' ART techniques have at least one custom payload family attached, giving them extra variant coverage beyond their standard ART atomic tests.');
    _updateSweepVariantCount(s.availableVariants);
  }).catch(function() {});
}

export function vexStatCard(label, val, col, sub, help) {
  return '<div class="kpi-card" style="position:relative">' +
    (help ? '<button type="button" class="btn btn-sm"' + on('click', 'showVexStatHelp', label, help) + ' title="What does this number mean?" style="position:absolute;top:0.5rem;right:0.5rem;width:18px;height:18px;padding:0;line-height:16px;text-align:center;border-radius:50%;font-size:0.68rem;font-weight:700;color:var(--muted);background:transparent;border:1px solid var(--border)">?</button>' : '') +
    '<div class="kpi-label">' + label + '</div>' +
    '<div class="kpi-value" style="color:' + col + '">' + (val || 0).toLocaleString() + '</div>' +
    (sub ? '<div style="font-size:0.65rem;color:var(--muted);margin-top:0.15rem">' + sub + '</div>' : '') +
    '</div>';
}

// showVexStatHelp explains what a Variant Executor stat card's number means —
// each card has a small "?" button since the always-visible caption under the
// number isn't always enough context on its own for a first-time viewer.
export function showVexStatHelp(label, help) {
  showToast(label + ': ' + help, 'ok');
}

export function populateVexAgents() {
  apicall('/api/agents').then(function(agents) {
    // Every variant Template the generator produces is Windows-only
    // PowerShell (internal/variant/generator.go), so a non-Windows agent
    // can never run anything dispatched from this panel -- excluded
    // outright rather than shown-disabled, since there's no per-technique
    // variability like Scheduled Assessments' per-scenario SupportedOS.
    var online = (agents || []).filter(function(a) { return a.status !== 'offline' && schedClassifyOS(a.osVersion) !== 'linux' && schedClassifyOS(a.osVersion) !== 'darwin'; });
    var opts = '<option value="">Select agent…</option>' +
      online.map(function(a) {
        return '<option value="' + x(a.agentId) + '">' + x(a.hostname || a.agentId) + '</option>';
      }).join('');
    var sel = document.getElementById('vex-agent');
    if (sel) sel.innerHTML = opts;
    var sweepSel = document.getElementById('vex-sweep-agent');
    if (sweepSel) sweepSel.innerHTML = opts;
    var allLabel = document.getElementById('vex-run-all-label');
    if (allLabel) allLabel.style.display = (ROLE === 'admin') ? 'flex' : 'none';
  }).catch(function(e) { showToast('Failed to load agents: ' + (e.message || 'error'), 'err'); });
}

export var _vexAllTechniques = [];
// _vexCalderaTechniques mirrors _vexAllTechniques but for Caldera's ability
// catalog -- populated alongside it so the Full Sweep preview can show both
// sources without a second round-trip. Empty when Caldera isn't configured.
export var _vexCalderaTechniques = [];

export function populateVexTechniques() {
  apicall('/api/caldera/techniques').then(function(techs) {
    _vexCalderaTechniques = (techs || []).filter(function(t) { return t.id; });
    var calderaEl = document.getElementById('vex-sweep-caldera-count');
    if (calderaEl) calderaEl.textContent = _vexCalderaTechniques.length ? (' + ' + _vexCalderaTechniques.length + ' Caldera') : '';
  }).catch(function() { _vexCalderaTechniques = []; });

  apicall('/api/art/techniques').then(function(techs) {
    _vexAllTechniques = (techs || []).filter(function(t) { return t.id; });
    // Update sweep card counts
    var n = _vexAllTechniques.length;
    var techCountEl = document.getElementById('vex-sweep-tech-count');
    if (techCountEl) techCountEl.textContent = n;
    // Populate tactic dropdown
    var tactics = {};
    _vexAllTechniques.forEach(function(t) { if (t.tactic) tactics[t.tactic] = true; });
    var tacSel = document.getElementById('vex-tactic');
    if (tacSel) {
      var tacOpts = '<option value="">All tactics (' + n + ' techniques)</option>';
      Object.keys(tactics).sort().forEach(function(tc) {
        var label = tc.replace(/-/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });
        tacOpts += '<option value="' + x(tc) + '">' + x(label) + '</option>';
      });
      tacSel.innerHTML = tacOpts;
    }
    filterVexTechniques();
  }).catch(function() {
    var el = document.getElementById('vex-technique-list');
    if (el) el.innerHTML = '<div style="color:var(--danger);font-size:0.75rem;padding:0.4rem">Failed to load techniques</div>';
  });
}

// Update the sweep card "N total variants" once stats load.
// Called from loadVariantStats after the API responds.
function _updateSweepVariantCount(availableVariants) {
  var el = document.getElementById('vex-sweep-total-variants');
  if (el && availableVariants) el.textContent = availableVariants.toLocaleString() + '+ variants';
}

// _vexFormatDuration renders a millisecond duration as e.g. "2m 14s" or "1h 05m 30s".
function _vexFormatDuration(ms) {
  var totalSec = Math.max(0, Math.round(ms / 1000));
  var h = Math.floor(totalSec / 3600);
  var m = Math.floor((totalSec % 3600) / 60);
  var s = totalSec % 60;
  if (h > 0) return h + 'h ' + (m < 10 ? '0' : '') + m + 'm ' + (s < 10 ? '0' : '') + s + 's';
  if (m > 0) return m + 'm ' + (s < 10 ? '0' : '') + s + 's';
  return s + 's';
}


var _vexSweepPollTimer = null;
var _vexKnownRunningSweepIds = []; // sweep IDs seen in the previous tick, for completion-diffing
var _vexSweepPollFailing = false;  // true while pollVexSweeps' fetch is failing -- avoids
                                    // re-toasting every 3s for the same outage (see pollVexSweeps)

// startVexSweepPolling begins the 3s poll loop against the server-owned
// sweep API. Idempotent -- safe to call more than once (e.g. if
// loadVariantTab() runs again after a tab re-visit).
export function startVexSweepPolling() {
  if (_vexSweepPollTimer) return;
  pollVexSweeps();
  _vexSweepPollTimer = setInterval(pollVexSweeps, 3000);
}

function pollVexSweeps() {
  // Also fetch agent_disconnected sweeps -- otherwise a paused sweep
  // vanishes from this list entirely (the endpoint only ever returns one
  // status per call) and reportVexSweepFinished's completion-detection
  // logic below would misreport it as finished.
  Promise.all([
    apicall('/api/vex/sweeps?status=running'),
    apicall('/api/vex/sweeps?status=agent_disconnected')
  ]).then(function(results) {
    _vexSweepPollFailing = false;
    var sweeps = (results[0] || []).concat(results[1] || []);
    var currentIds = sweeps.map(function(s) { return s.id; });

    // Completion detection: any previously-tracked ID missing from this
    // tick's list just finished (completed/stopped/failed) -- fetch its
    // final state once for the toast, since the running-list endpoint no
    // longer includes it.
    _vexKnownRunningSweepIds.forEach(function(id) {
      if (currentIds.indexOf(id) === -1) reportVexSweepFinished(id);
    });
    _vexKnownRunningSweepIds = currentIds;

    renderVexSweepList(sweeps);
  }).catch(function() {
    // This 3s poll runs indefinitely for the life of the tab (by design --
    // any operator can dispatch a new sweep at any time) and previously
    // failed completely silently: an outage here meant the sweep list went
    // stale forever with zero indication anything was wrong. One toast per
    // failure episode (not one every 3s) balances visibility against spam;
    // it clears itself via the success path above once the poll recovers.
    if (!_vexSweepPollFailing) {
      _vexSweepPollFailing = true;
      showToast('Sweep list refresh failing — will keep retrying', 'err');
    }
  });
}

function reportVexSweepFinished(sweepId) {
  apicall('/api/vex/sweeps/' + sweepId).then(function(sw) {
    if (sw.status === 'completed') {
      showToast('Full sweep complete — ' + sw.totalTechniques + ' atomic tests (' + sw.agentId + ')', 'ok');
      loadVariantStats();
      loadVariantCoverage();
    } else if (sw.status === 'stopped') {
      showToast('Sweep stopped (' + sw.agentId + ')', 'warn');
    } else if (sw.status === 'failed') {
      showToast('Sweep failed on ' + sw.agentId + ': ' + (sw.error || 'unknown error'), 'err');
    }
  }).catch(function() {});
}

function renderVexSweepList(sweeps) {
  var el = document.getElementById('vex-sweep-list');
  if (!el) return;
  if (!sweeps.length) { el.innerHTML = ''; return; }

  el.innerHTML = sweeps.map(function(sw) {
    // A full sweep can have thousands of total variants, so a handful of
    // real completions can round down to a misleading "0%" -- floor any
    // nonzero progress at 1% so the bar never looks stuck when it isn't.
    var rawPct = sw.totalVariants > 0 ? (sw.completedVariants / sw.totalVariants) * 100 : 0;
    var pct = rawPct > 0 && rawPct < 1 ? 1 : Math.round(rawPct);
    var disconnected = sw.status === 'agent_disconnected';
    return '<div class="card" style="margin-top:0.5rem;padding:0.75rem 1rem" id="vex-sweep-card-' + x(sw.id) + '">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;font-size:0.78rem;margin-bottom:0.3rem">' +
        '<span class="u-fw600">' + x(sw.agentId) +
          (disconnected ? ' <span class="sbadge s-agent_disconnected">Agent Disconnected</span>' : '') + '</span>' +
        '<span style="display:flex;align-items:center;gap:0.6rem">' +
          (disconnected ? '' : '<span style="font-weight:700;color:var(--accent)">' + pct + '%</span>') +
          '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger);padding:2px 8px;font-size:0.7rem"' + on('click', 'stopVexSweep', sw.id) + '>&#9632; Stop</button>' +
        '</span>' +
      '</div>' +
      '<div style="height:5px;background:var(--border);border-radius:3px;overflow:hidden">' +
        '<div style="height:5px;background:var(--accent);border-radius:3px;width:' + pct + '%;transition:width 0.5s ease"></div>' +
      '</div>' +
      '<div class="tiny muted" style="margin-top:0.35rem">Atomic test ' + (sw.currentIndex + 1) + '/' + sw.totalTechniques + ': ' + x(sw.currentTechnique) + '</div>' +
      '<div class="tiny muted" id="vex-sweep-variant-' + x(sw.id) + '">Loading current variant…</div>' +
    '</div>';
  }).join('');

  sweeps.forEach(function(sw) {
    if (sw.currentVariantRunId) loadVexSweepVariantDetail(sw.id, sw.currentVariantRunId);
  });
}

// loadVexSweepVariantDetail fetches the current technique's own variant
// run (the same endpoint the ad-hoc single-run view already polls) purely
// to derive "variant N/M: <what's running>" -- the sweep-list endpoint
// itself only tracks per-technique progress, not per-variant.
function loadVexSweepVariantDetail(sweepId, variantRunId) {
  apicall('/api/variants/run/' + variantRunId).then(function(detail) {
    var el = document.getElementById('vex-sweep-variant-' + sweepId);
    if (!el) return; // card was removed by a later tick before this resolved
    var results = detail.results || [];
    // stepsDone is live (incremented per completed step as the agent
    // executes) -- per-item verdicts only resolve once the whole run submits
    // its complete final results snapshot, so counting non-PENDING verdicts
    // stays at 0 for the run's entire in-flight duration.
    var doneCount = Math.min(detail.stepsDone || 0, results.length);
    var current = results[doneCount]; // next un-run entry, in dispatch order
    if (current) {
      el.textContent = 'Variant ' + (doneCount + 1) + '/' + results.length + ': ' +
        current.encoding + ' / ' + current.execContext + ' / ' + current.evasion;
    } else {
      el.textContent = 'Variant ' + results.length + '/' + results.length + ' — finishing…';
    }
  }).catch(function() {});
}

var _vexTargetMode = 'individual'; // 'individual' | 'group'
 // { [groupId]: true } for checked groups in the Full Sweep card's Group(s) mode

// setVexTargetMode switches the Full Sweep card between its single-agent
// select and the group checkbox list, clearing the OTHER mode's selection
// state so a stale pick can't silently leak into a dispatch.
export function setVexTargetMode(mode) {
  _vexTargetMode = mode;
  if (mode !== 'group') state._vexGroupSel = {};
  var indWrap = document.getElementById('vex-sweep-individual-wrap');
  var grpWrap = document.getElementById('vex-sweep-group-wrap');
  if (indWrap) indWrap.style.display = mode === 'individual' ? 'flex' : 'none';
  if (grpWrap) grpWrap.style.display = mode === 'group' ? 'block' : 'none';
  if (mode === 'group') renderVexGroupList();

  // Start Sweep stays inline in Individual mode (compact, single row) but
  // moves below the group checklist in Group mode, so picking groups never
  // requires scrolling past the action button to see what you're about to
  // run against.
  var btn = document.getElementById('vex-sweep-btn');
  var inlineSlot = document.getElementById('vex-sweep-btn-inline-slot');
  var groupSlot = document.getElementById('vex-sweep-btn-group-slot');
  if (btn) {
    if (mode === 'group' && groupSlot) groupSlot.appendChild(btn);
    else if (inlineSlot) inlineSlot.appendChild(btn);
  }
}

// renderVexGroupList renders the checkbox list of every group, flattened by
// gpFlattenGroups (the same helper the Run Scenario wizard's own Group(s)
// mode already uses), each row showing that group's own totalAgentCount.
function renderVexGroupList() {
  renderGroupCheckboxList('vex-sweep-group-list', 'tiny muted', '_vexGroupSel', 'renderVexGroupSummary', ['renderVexGroupSummary']);
}

// vexResolvedGroupAgents resolves the currently-checked groups to their
// member agents via the pre-existing resolveGroupTargetAgents helper.
// Deliberately NOT run through osEligibleAgents -- Full Sweep has no
// scenario/supportedOs concept, so every resolved agent is targeted as-is.
function vexResolvedGroupAgents() {
  var selectedGroupIds = Object.keys(state._vexGroupSel).filter(function(k) { return state._vexGroupSel[k]; }).map(Number);
  return resolveGroupTargetAgents(selectedGroupIds);
}

export function renderVexGroupSummary() {
  var el = document.getElementById('vex-sweep-group-summary');
  if (!el) return;
  var selectedCount = Object.keys(state._vexGroupSel).filter(function(k) { return state._vexGroupSel[k]; }).length;
  if (!selectedCount) { el.textContent = 'No groups selected.'; return; }
  var resolved = vexResolvedGroupAgents();
  el.textContent = resolved.length + ' agent(s) across ' + selectedCount + ' group(s).';
}

// vexRunFullSweep validates the current target selection (the existing
// individual/group panel, entirely unchanged) and opens the Preview &
// Confirm overlay -- it no longer dispatches directly. Actual dispatch
// lives solely in _vexDispatchFullSweep, called only from the preview's
// Start Full Sweep button, so there is exactly one dispatch implementation.
export function vexRunFullSweep() {
  var mode = (document.getElementById('vex-sweep-mode') || {}).value || 'sequential';
  var advanced = document.getElementById('vex-sweep-advanced') ? document.getElementById('vex-sweep-advanced').checked : false;

  if (_vexTargetMode === 'group') {
    var beforeOSFilter = vexResolvedGroupAgents();
    var resolved = vexFilterWindowsAgents(beforeOSFilter);
    if (!resolved.length) { showToast('Select at least one group with a Windows agent — every variant technique requires Windows', 'err'); return; }
    if (resolved.length < beforeOSFilter.length) {
      showToast((beforeOSFilter.length - resolved.length) + ' non-Windows agent(s) in the selected group(s) were skipped.', 'ok');
    }
    openSweepPreview('variant', { targetMode: 'group', agents: resolved, mode: mode, advanced: advanced });
    return;
  }

  var agentId = (document.getElementById('vex-sweep-agent') || {}).value || '';
  if (!agentId) { showToast('Select an agent in the Full Sweep panel first', 'err'); return; }
  openSweepPreview('variant', { targetMode: 'individual', agents: [{ agentId: agentId }], mode: mode, advanced: advanced });
}

// _vexDispatchFullSweep is the single source of truth for actually starting
// a Variant Full Sweep. n/variantTotal are a pre-flight estimate only (from
// the ad-hoc picker's already-loaded technique list, shown in the preview's
// summary line) -- the server independently and authoritatively resolves
// the real technique list and count at creation time; that's what actually
// gets dispatched.
export function _vexDispatchFullSweep(targets) {
  var resolved = targets.agents;
  var mode = targets.mode, advanced = targets.advanced;

  if (targets.targetMode === 'group') {
    // Each dispatch is independent: a rejected promise or a {error:...}
    // response body is normalized into a resolved {ok:false} result so one
    // agent's failure (already sweeping, offline, etc.) can never abort or
    // block the others -- same isolation pattern confirmRun() already uses
    // for the Run Scenario wizard's multi-agent dispatch.
    var dispatches = resolved.map(function(a) {
      return apicall('/api/vex/sweeps', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId: a.agentId, mode: mode, includeAdvanced: advanced })
      }).then(function(res) {
        if (res && res.error) return { agentId: a.agentId, ok: false, error: res.error };
        return { agentId: a.agentId, ok: true };
      }).catch(function(e) {
        return { agentId: a.agentId, ok: false, error: e.message };
      });
    });

    Promise.all(dispatches).then(function(results) {
      var ok = results.filter(function(r) { return r.ok; });
      var failed = results.filter(function(r) { return !r.ok; });
      if (!failed.length) {
        showToast('Started ' + ok.length + ' sweep(s).', 'ok');
      } else if (ok.length) {
        showToast('Started ' + ok.length + '/' + results.length + ' sweeps. Failed: ' +
          failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
      } else {
        showToast('All ' + results.length + ' sweep dispatches failed. ' +
          failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
      }
      pollVexSweeps();
    });
    return;
  }

  var agentId = resolved[0].agentId;
  apicall('/api/vex/sweeps', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId: agentId, mode: mode, includeAdvanced: advanced })
  }).then(function(res) {
    // apicall() only rejects on 401 -- every other status (including a 409
    // conflict) resolves with the {error:...} body, so that shape must be
    // checked explicitly or a rejected dispatch silently does nothing.
    if (res && res.error) { showToast(res.error, 'err'); return; }
    pollVexSweeps(); // render the new sweep immediately instead of waiting up to 3s for the next tick
  }).catch(function(e) {
    showToast(e.message || 'Failed to start sweep', 'err');
  });
}

export function stopVexSweep(sweepId) {
  if (!confirm('Stop this sweep? The current technique finishes or is cancelled; no further techniques will be dispatched.')) return;
  apicall('/api/vex/sweeps/' + sweepId + '/cancel', { method: 'POST' })
    .then(function() { pollVexSweeps(); })
    .catch(function(e) { showToast(e.message || 'Failed to stop sweep', 'err'); });
}

export function _vexCheckAgentSweepConflict() {
  var agentId = (document.getElementById('vex-sweep-agent') || {}).value || '';
  var hint = document.getElementById('vex-sweep-agent-hint');
  if (!hint) return;
  if (!agentId) { hint.textContent = ''; return; }
  // apicall() only rejects on 401 -- every other status (400/404/500) still
  // resolves .then() with whatever JSON body came back. jsonError() always
  // includes an "error" field and success payloads never do, so that's the
  // real signal here, not promise rejection.
  apicall('/api/vex/sweeps/active?agentId=' + encodeURIComponent(agentId)).then(function(res) {
    hint.textContent = (res && !res.error) ? 'This agent already has a sweep running.' : '';
  }).catch(function() {
    hint.textContent = '';
  });
}

// filterVexTechniqueList is the single filtering predicate shared by the
// technique picker (filterVexTechniques) and the Full Sweep preview
// (_renderVexPreviewList), so the two can never drift apart.
export function filterVexTechniqueList(techniques, tactic, search) {
  search = (search || '').toLowerCase().trim();
  return techniques.filter(function(t) {
    if (tactic && t.tactic !== tactic) return false;
    if (search && t.id.toLowerCase().indexOf(search) < 0 && (t.name || '').toLowerCase().indexOf(search) < 0) return false;
    return true;
  });
}

export function filterVexTechniques() {
  var tactic = document.getElementById('vex-tactic') ? document.getElementById('vex-tactic').value : '';
  var search = document.getElementById('vex-tech-search') ? document.getElementById('vex-tech-search').value : '';
  var filtered = filterVexTechniqueList(_vexAllTechniques, tactic, search);
  var el = document.getElementById('vex-technique-list');
  if (!el) return;
  var countEl = document.getElementById('vex-tech-count');
  if (countEl) countEl.textContent = '(' + filtered.length + ')';
  if (!filtered.length) {
    el.innerHTML = '<div style="color:var(--muted);font-size:0.75rem;padding:0.4rem">No techniques match</div>';
    return;
  }
  el.innerHTML = filtered.map(function(t) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:2px 4px;cursor:pointer;border-radius:3px">' +
      '<input type="checkbox" class="vex-tech-cb" value="' + x(t.id) + '" style="accent-color:var(--accent);flex-shrink:0">' +
      '<span style="font-family:var(--font-mono);font-size:0.76rem;flex-shrink:0">' + x(t.id) + '</span>' +
      (t.name ? '<span style="color:var(--muted);font-size:0.71rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + x(t.name) + '</span>' : '') +
      '</label>';
  }).join('');
}

export function vexSelectAll() {
  document.querySelectorAll('#vex-technique-list .vex-tech-cb').forEach(function(cb) { cb.checked = true; });
}

export function vexClearAll() {
  document.querySelectorAll('#vex-technique-list .vex-tech-cb').forEach(function(cb) { cb.checked = false; });
}

function vexSelectedTechniques() {
  return Array.from(document.querySelectorAll('#vex-technique-list .vex-tech-cb:checked')).map(function(cb) { return cb.value; });
}

export function loadVariantCoverage() {
  var el = document.getElementById('vex-coverage');
  if (!el) return;
  el.innerHTML = '<div class="empty" style="padding:1.5rem">Loading…</div>';
  apicall('/api/variants/coverage').then(function(rows) {
    if (!rows || !rows.length) {
      el.innerHTML = '<div class="empty" style="padding:1.5rem">No variant runs yet. Run variants on a technique to see coverage here.</div>';
      return;
    }
    var html = '<div class="tbl-wrap"><table><thead><tr>' +
      '<th>Technique</th><th>Tactic</th><th>Total</th>' +
      '<th class="u-success">Prevented</th>' +
      '<th class="u-danger">Allowed</th>' +
      '<th class="u-muted">Errors</th>' +
      '<th>First Bypass</th>' +
      '</tr></thead><tbody>';
    rows.forEach(function(row) {
      var fp = row.firstBypass
        ? '<span style="font-family:var(--font-mono);color:var(--warning);font-size:0.74rem">' + x(row.firstBypass) + '</span>'
        : '<span class="u-success">None</span>';
      html += '<tr>' +
        '<td><span class="badge badge-mono" style="font-family:var(--font-mono)">' + x(row.techniqueId) + '</span></td>' +
        '<td style="color:var(--muted);font-size:0.8rem">' + x(row.tactic || '—') + '</td>' +
        '<td class="u-center">' + (row.totalTested || 0) + '</td>' +
        '<td style="text-align:center;color:var(--success);font-weight:600">' + (row.prevented || 0) + '</td>' +
        '<td style="text-align:center;color:var(--danger);font-weight:600">' + (row.allowed || 0) + '</td>' +
        '<td style="text-align:center;color:var(--muted)">' + (row.errored || 0) + '</td>' +
        '<td>' + fp + '</td>' +
        '</tr>';
    });
    html += '</tbody></table></div>';
    el.innerHTML = html;
  }).catch(function(e) {
    el.innerHTML = '<div class="empty" style="color:var(--danger);padding:1rem">' + x(e.message || 'Error loading coverage') + '</div>';
  });
}

var _vexRunTargetMode = 'individual'; // 'individual' | 'group' | 'all'
 // { [groupId]: true } for checked groups in the Run Variants card's Group(s) mode

// setVexRunTargetMode switches the Run Variants card between its
// single-agent select, the group checkbox list, and the All Agents notice,
// clearing the OTHER modes' selection state so a stale pick can't silently
// leak into a dispatch.
export function setVexRunTargetMode(mode) {
  _vexRunTargetMode = mode;
  if (mode !== 'group') state._vexRunGroupSel = {};
  var indWrap = document.getElementById('vex-run-individual-wrap');
  var grpWrap = document.getElementById('vex-run-group-wrap');
  var allWrap = document.getElementById('vex-run-all-wrap');
  if (indWrap) indWrap.style.display = mode === 'individual' ? 'block' : 'none';
  if (grpWrap) grpWrap.style.display = mode === 'group' ? 'block' : 'none';
  if (allWrap) allWrap.style.display = mode === 'all' ? 'block' : 'none';
  if (mode === 'group') renderVexRunGroupList();
}

// renderVexRunGroupList renders the checkbox list of every group, flattened
// by gpFlattenGroups (the same helper both the Run Scenario wizard's and
// Full Sweep's own Group(s) modes already use), each row showing that
// group's own totalAgentCount.
function renderVexRunGroupList() {
  renderGroupCheckboxList('vex-run-group-list', 'tiny muted', '_vexRunGroupSel', 'renderVexRunGroupSummary', ['renderVexRunGroupSummary']);
}

// vexRunResolvedGroupAgents resolves the currently-checked groups to their
// member agents via the pre-existing resolveGroupTargetAgents helper.
// Deliberately NOT run through osEligibleAgents -- this flow has no
// scenario/supportedOs concept, so every resolved agent is targeted as-is.
function vexRunResolvedGroupAgents() {
  var selectedGroupIds = Object.keys(state._vexRunGroupSel).filter(function(k) { return state._vexRunGroupSel[k]; }).map(Number);
  return resolveGroupTargetAgents(selectedGroupIds);
}

export function renderVexRunGroupSummary() {
  var el = document.getElementById('vex-run-group-summary');
  if (!el) return;
  var selectedCount = Object.keys(state._vexRunGroupSel).filter(function(k) { return state._vexRunGroupSel[k]; }).length;
  if (!selectedCount) { el.textContent = 'No groups selected.'; return; }
  var resolved = vexRunResolvedGroupAgents();
  el.textContent = resolved.length + ' agent(s) across ' + selectedCount + ' group(s).';
}

export function runVariants() {
  var techniques = vexSelectedTechniques();
  var mode = document.getElementById('vex-mode') ? document.getElementById('vex-mode').value : 'sequential';
  var advanced = document.getElementById('vex-advanced') ? document.getElementById('vex-advanced').checked : false;
  var baseType = document.getElementById('vex-base-type') ? document.getElementById('vex-base-type').value : 'art';
  if (!techniques.length) { showToast('Check at least one technique', 'err'); return; }

  if (_vexRunTargetMode === 'group' || _vexRunTargetMode === 'all') {
    if (techniques.length > 1) {
      showToast('Group/All-Agent targeting requires exactly one technique — uncheck the rest, or switch to Individual for a multi-technique run.', 'err');
      return;
    }
    var beforeOSFilter = _vexRunTargetMode === 'group' ? vexRunResolvedGroupAgents() : state.agents.slice();
    var resolved = vexFilterWindowsAgents(beforeOSFilter);
    if (!resolved.length) { showToast('Select at least one group with a Windows agent — every variant technique requires Windows', 'err'); return; }
    var skipped = beforeOSFilter.length - resolved.length;
    var techId = techniques[0];

    if (resolved.length > 1 || skipped > 0) {
      var msg = 'Run ' + techId + ' on ' + resolved.length + ' agent(s)?';
      if (skipped > 0) msg += ' (' + skipped + ' non-Windows agent(s) skipped)';
      if (!confirm(msg)) return;
    }

    // Each dispatch is independent: a rejected promise or a {error:...}
    // response body is normalized into a resolved {ok:false} result so one
    // agent's failure (offline, conflict, etc.) can never abort or block
    // the others -- same isolation pattern used for Full Sweep's group
    // targeting and the Run Scenario wizard's multi-agent dispatch.
    var dispatches = resolved.map(function(a) {
      return apicall('/api/variants/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId: a.agentId, techniqueId: techId, baseType: baseType, executionMode: mode, includeAdvanced: advanced })
      }).then(function(res) {
        if (res && res.error) return { agentId: a.agentId, ok: false, error: res.error };
        return { agentId: a.agentId, ok: true };
      }).catch(function(e) {
        return { agentId: a.agentId, ok: false, error: e.message };
      });
    });

    Promise.all(dispatches).then(function(results) {
      var ok = results.filter(function(r) { return r.ok; });
      var failed = results.filter(function(r) { return !r.ok; });
      if (!failed.length) {
        showToast('Dispatched to ' + ok.length + ' agent(s).', 'ok');
      } else if (ok.length) {
        showToast('Dispatched to ' + ok.length + '/' + results.length + ' agents. Failed: ' +
          failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
      } else {
        showToast('All ' + results.length + ' dispatches failed. ' +
          failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
      }
      loadVariantCoverage();
      loadVariantStats();
    });
    return;
  }

  var agentId = document.getElementById('vex-agent') ? document.getElementById('vex-agent').value : '';
  if (!agentId) { showToast('Select an agent first', 'err'); return; }
  state._vexAbortRequested = false; state._vexActiveScenarioRunId = null;
  var btn = document.getElementById('vex-run-btn');
  if (btn) { btn.disabled = true; }
  _vexRunVariantQueue(agentId, techniques, mode, advanced, baseType, 0);
}

function _vexRenderQueuePanel(tid, idx, techniques) {
  var panel = document.getElementById('vex-result-panel');
  if (!panel) return;
  var pct = Math.round((idx / techniques.length) * 100);
  panel.innerHTML = '<div class="card" style="padding:1.5rem">' +
    '<div class="card-title" style="margin-bottom:0.75rem">Queue Progress</div>' +
    '<div style="font-size:0.83rem;color:var(--muted);margin-bottom:0.6rem">Running <span style="font-family:var(--font-mono);color:var(--text)">' + x(tid) + '</span> — <span style="color:var(--accent);font-weight:600">' + (idx + 1) + ' / ' + techniques.length + '</span></div>' +
    '<div style="height:4px;background:var(--border);border-radius:2px;overflow:hidden;margin-bottom:0.75rem">' +
      '<div style="height:4px;background:var(--accent);border-radius:2px;width:' + pct + '%;transition:width 0.4s"></div>' +
    '</div>' +
    (idx > 0 ? '<div style="margin-bottom:0.6rem;font-size:0.74rem;color:var(--muted)">' + idx + ' completed</div>' : '') +
    '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger)"' + on('click', 'stopVex') + '>&#9632; Stop</button>' +
  '</div>';
}

function _vexRunVariantQueue(agentId, techniques, mode, advanced, baseType, idx) {
  var btn = document.getElementById('vex-run-btn');
  if (state._vexAbortRequested) { if (btn) { btn.disabled = false; btn.textContent = 'Run'; } _vexClearActiveState(); return; }
  if (idx >= techniques.length) {
    if (btn) { btn.disabled = false; btn.textContent = 'Run'; }
    if (techniques.length > 1) showToast('All ' + techniques.length + ' techniques queued', 'ok');
    _vexClearActiveState();
    loadVariantCoverage();
    loadVariantStats();
    return;
  }
  var tid = techniques[idx];
  if (btn) btn.textContent = techniques.length > 1 ? (idx + 1) + '/' + techniques.length + ' Running…' : 'Dispatching…';

  if (techniques.length > 1) _vexRenderQueuePanel(tid, idx, techniques);

  apicall('/api/variants/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId: agentId, techniqueId: tid, baseType: baseType, executionMode: mode, includeAdvanced: advanced })
  }).then(function(resp) {
    state._vexActiveScenarioRunId = resp.scenarioRunId;
    var vrId = resp.variantRunId;
    // Persist so a page reload can reconnect to this run instead of the
    // panel just going blank -- and, for a queue, so the remaining
    // techniques still get dispatched (see _vexResumeActiveRun above).
    _vexSaveActiveState({ vrId: vrId, agentId: agentId, techniques: techniques, mode: mode, advanced: advanced, baseType: baseType, idx: idx });
    if (techniques.length === 1) {
      if (btn) { btn.disabled = false; btn.textContent = 'Run'; }
      showToast('Dispatched ' + (resp.totalVariants || 0) + ' variants', 'ok');
      pollVariantRun(vrId);
      return;
    }
    // Multi: wait for this run to finish, then dispatch next
    _vexWaitAndNext(vrId, agentId, techniques, mode, advanced, baseType, idx);
  }).catch(function(e) {
    if (btn) { btn.disabled = false; btn.textContent = 'Run'; }
    showToast('Failed on ' + tid + ': ' + (e.message || 'error'), 'err');
  });
}

function _vexWaitAndNext(vrId, agentId, techniques, mode, advanced, baseType, idx) {
  if (state._vexActivePoll) clearInterval(state._vexActivePoll);
  state._vexActivePoll = setInterval(function() {
    if (state._vexAbortRequested) { clearInterval(state._vexActivePoll); state._vexActivePoll = null; return; }
    apicall('/api/variants/run/' + vrId).then(function(detail) {
      var s = detail.run && detail.run.status;
      if (s === 'completed' || s === 'failed' || s === 'partial') {
        clearInterval(state._vexActivePoll); state._vexActivePoll = null;
        _vexRunVariantQueue(agentId, techniques, mode, advanced, baseType, idx + 1);
      }
    }).catch(function() { clearInterval(state._vexActivePoll); state._vexActivePoll = null; _vexRunVariantQueue(agentId, techniques, mode, advanced, baseType, idx + 1); });
  }, 3000);
}

export function pollVariantRun(vrId) {
  clearInterval(state._vexRunPoll);
  state._vexPollFailCount = 0;
  var panel = document.getElementById('vex-result-panel');
  if (panel) panel.innerHTML =
    '<div class="card" style="padding:1.5rem;text-align:center;color:var(--muted)">' +
    '<div style="margin-bottom:0.5rem;font-size:0.9rem">Executing variants…</div>' +
    '<div class="tiny" style="font-family:var(--font-mono);margin-bottom:0.75rem">' + x(vrId) + '</div>' +
    '<div id="vex-poll-status" class="tiny" style="min-height:1em;margin-bottom:0.5rem"></div>' +
    '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger)"' + on('click', 'stopVex') + '>&#9632; Stop</button></div>';
  state._vexRunPoll = setInterval(function() {
    apicall('/api/variants/run/' + vrId).then(function(detail) {
      state._vexPollFailCount = 0;
      if (detail.run && detail.run.scenarioRunId) state._vexActiveScenarioRunId = detail.run.scenarioRunId;
      renderVariantRun(detail);
      var s = detail.run && detail.run.status;
      if (s === 'completed' || s === 'failed' || s === 'partial') {
        clearInterval(state._vexRunPoll);
        _vexClearActiveState();
        loadVariantCoverage();
        loadVariantStats();
      }
    }).catch(function() {
      // A single failed status check does NOT mean the run itself failed --
      // it's still executing server-side regardless of whether this poll
      // succeeded. Retry silently up to VEX_POLL_MAX_FAILURES times (with a
      // visible "retrying" indicator so a stalled poll doesn't look
      // identical to a healthy one), then give up with a recoverable
      // message instead of leaving "Executing variants..." showing forever.
      state._vexPollFailCount++;
      if (state._vexPollFailCount >= VEX_POLL_MAX_FAILURES) {
        clearInterval(state._vexRunPoll);
        var p = document.getElementById('vex-result-panel');
        if (p) p.innerHTML =
          '<div class="card" style="padding:1.5rem;text-align:center;color:var(--muted)">' +
          '<div style="margin-bottom:0.5rem;font-size:0.9rem;color:var(--danger)">Unable to retrieve execution status</div>' +
          '<div class="tiny" style="font-family:var(--font-mono);margin-bottom:0.75rem">' + x(vrId) + '</div>' +
          '<div class="tiny muted" style="margin-bottom:0.75rem">The run may still be executing on the server — this only means status updates stopped arriving. Retry, or check Live Runs.</div>' +
          '<button class="btn btn-outline btn-sm"' + on('click', 'pollVariantRun', vrId) + '>&#8635; Retry</button> ' +
          '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger)"' + on('click', 'stopVex') + '>&#9632; Stop</button></div>';
      } else {
        var statusEl = document.getElementById('vex-poll-status');
        if (statusEl) statusEl.textContent = 'Status temporarily unavailable — retrying (' + state._vexPollFailCount + '/' + VEX_POLL_MAX_FAILURES + ')';
      }
    });
  }, 3000);
}

// stopVex() cancels the single ad-hoc variant run in progress (the
// vex-run-btn / vex-result-panel flow). The Full Sweep panel has its own
// independent stopVexSweep(sweepId), which calls the server-owned sweep
// cancel endpoint directly -- the two flows no longer share any state or
// UI, since the sweep no longer runs its own client-side polling loop.
export function stopVex() {
  state._vexAbortRequested = true;
  if (state._vexActivePoll) { clearInterval(state._vexActivePoll); state._vexActivePoll = null; }
  clearInterval(state._vexRunPoll); state._vexRunPoll = null;
  _vexClearActiveState();
  if (state._vexActiveScenarioRunId) {
    apicall('/api/scenarios/runs/' + encodeURIComponent(state._vexActiveScenarioRunId) + '/cancel', { method: 'POST' }).catch(function(){});
  }
  var btn = document.getElementById('vex-run-btn');
  if (btn) { btn.disabled = false; btn.textContent = 'Run'; }

  var panel = document.getElementById('vex-result-panel');
  if (panel) panel.innerHTML = '<div class="card" style="padding:1.25rem;color:var(--warning);text-align:center">&#9632; Variant run stopped</div>';
  showToast('Variant run stopped', 'warn');
}

function _vexVerdictColor(verdict) {
  return verdict === 'PREVENTED' ? 'var(--success)' :
         verdict === 'ALLOWED' ? 'var(--danger)' :
         verdict === 'ERROR' ? 'var(--muted)' : 'var(--warning)';
}
function _vexResultRowHtml(r) {
  return '<tr data-task-id="' + x(r.taskId) + '">' +
    '<td style="font-family:var(--font-mono)">' + x(r.encoding) + '</td>' +
    '<td style="font-family:var(--font-mono)">' + x(r.execContext) + '</td>' +
    '<td style="font-family:var(--font-mono)">' + x(r.evasion) + '</td>' +
    '<td><span class="badge" style="font-size:0.68rem;border-color:transparent">' + x(r.riskLevel) + '</span></td>' +
    '<td data-verdict-cell data-verdict="' + x(r.verdict) + '"><span style="color:' + _vexVerdictColor(r.verdict) + ';font-weight:600;font-size:0.78rem">' + x(r.verdict) + '</span></td>' +
    '</tr>';
}

// renderVariantRun previously rebuilt the ENTIRE results panel -- including
// the whole results table -- from a fresh HTML string on every 3s poll
// tick, for the run's full duration. For a run with dozens of variant
// combinations, that meant discarding and recreating the whole <table>
// every tick even though typically only one or two rows' verdicts actually
// changed. The backend guarantees results.length and each row's
// taskId/encoding/execContext/evasion/riskLevel never change once a run
// starts (variant_handlers.go's GetVariantRun always returns every
// dispatched step, PENDING or not, in the same stable stepRows-insertion
// order) -- only verdict (and the cell it renders into) ever changes. So
// once a table for THIS run already exists with the expected row count and
// taskIds, only the verdict cells that actually changed get touched.
// Everything else (header/actions/summary tiles/bypass banner -- a handful
// of small elements, not "dozens+" rows) is still cheaply rebuilt wholesale
// every tick, per the explicit guidance not to over-engineer this further.
//
// Every element inside the wrapper originally had its own margin-bottom
// PLUS .card's flex gap (0.45rem) between it and the next flex sibling --
// 0.75rem + 0.45rem = 1.2rem total, confirmed by measuring the original
// rendering. .card's gap only applies between its own direct children, so
// wrapping title/actions/summary/banner inside one div (now grandchildren
// of .card) would silently shrink those internal gaps to just 0.75rem.
// The wrapper reproduces the original 1.2rem via its own
// `gap:1.2rem` between its direct children (title/actions/summary/banner,
// each with no margin-bottom of its own anymore) and its own
// `margin-bottom:0.75rem`, which combines with .card's still-active
// 0.45rem gap to the table for that same 1.2rem total.
function renderVariantRun(detail) {
  var run = detail.run || {};
  var results = detail.results || [];
  var summary = detail.summary || {};
  var statusCol = run.status === 'completed' ? 'var(--success)' :
                  run.status === 'failed' ? 'var(--danger)' : 'var(--warning)';

  var panel = document.getElementById('vex-result-panel');
  if (!panel) return;

  var wrapperHtml = '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">';
  wrapperHtml += '<span>Results — <span style="font-family:var(--font-mono)">' + x(run.techniqueId || '') + '</span></span>';
  wrapperHtml += '<span style="display:flex;align-items:center;gap:0.5rem">';
  wrapperHtml += '<span class="badge" style="background:' + statusCol + '22;color:' + statusCol + ';border:1px solid ' + statusCol + '44">' + x(run.status || 'running') + '</span>';
  if (run.status === 'running') {
    wrapperHtml += '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger)"' + on('click', 'stopVex') + '>&#9632; Stop</button>';
  }
  wrapperHtml += '</span>';
  wrapperHtml += '</div>';

  // Report actions -- this variant run is a real scenario_runs row underneath
  // (see dispatchVariantRun), so it already has full report data behind it
  // via the same per-run endpoints a regular scenario run uses. Only shown
  // once the run reaches a terminal state -- a running run's report would
  // just be an incomplete snapshot.
  if (run.scenarioRunId && run.status !== 'running') {
    wrapperHtml += '<div style="display:flex;gap:0.4rem;flex-wrap:wrap">';
    wrapperHtml += '<button class="btn btn-outline btn-sm"' + on('click', 'openRunReport', run.scenarioRunId) + ' title="Open the HTML report">&#8599; HTML Report</button>';
    wrapperHtml += '<button class="btn btn-outline btn-sm"' + on('click', 'downloadRunReport', run.scenarioRunId) + ' title="Download the report as a PDF file">&#8595; PDF</button>';
    wrapperHtml += '<button class="btn btn-outline btn-sm"' + on('click', 'downloadRunCSV', run.scenarioRunId) + ' title="Download the forensic CSV (one row per variant)">&#8595; CSV</button>';
    wrapperHtml += '<button class="btn btn-outline btn-sm"' + on('click', 'exportRunJSON', run.scenarioRunId) + ' title="Download the raw run data as JSON">&#8595; JSON</button>';
    wrapperHtml += '</div>';
  }

  wrapperHtml += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:0.5rem">';
  wrapperHtml += vexMini('Total', summary.total, 'var(--text)');
  wrapperHtml += vexMini('Prevented', summary.prevented, 'var(--success)');
  wrapperHtml += vexMini('Allowed', summary.allowed, 'var(--danger)');
  wrapperHtml += vexMini('Pending', summary.pending, 'var(--muted)');
  wrapperHtml += '</div>';

  if (summary.firstBypass) {
    wrapperHtml += '<div style="background:rgba(218,54,51,0.08);border:1px solid rgba(218,54,51,0.3);border-radius:6px;padding:0.55rem 0.8rem;font-size:0.82rem">';
    wrapperHtml += '<span style="color:var(--danger);font-weight:600">First bypass: </span>';
    wrapperHtml += '<span style="font-family:var(--font-mono);color:var(--text)">' + x(summary.firstBypass) + '</span>';
    if (summary.firstBypassRisk) {
      wrapperHtml += ' <span class="badge" style="background:rgba(218,54,51,0.15);color:#f85149;font-size:0.68rem;border-color:transparent">' + x(summary.firstBypassRisk) + '</span>';
    }
    wrapperHtml += '</div>';
  }

  // Try an incremental update: only valid when a table from a PRIOR render
  // of this exact run already exists with the same row count and the same
  // taskId in the same position for every row (both guaranteed by the
  // backend for a given run, but checked explicitly rather than assumed --
  // any mismatch falls back to the full rebuild below, never a silently
  // wrong table).
  var existingTbody = panel.querySelector('tbody[data-vex-results]');
  var incremental = !!existingTbody && existingTbody.children.length === results.length;
  if (incremental) {
    for (var i = 0; i < results.length; i++) {
      if (existingTbody.children[i].getAttribute('data-task-id') !== results[i].taskId) { incremental = false; break; }
    }
  }

  if (incremental) {
    var wrapperEl = panel.querySelector('[data-vex-wrapper]');
    if (wrapperEl) wrapperEl.innerHTML = wrapperHtml;
    results.forEach(function(r, idx) {
      var cell = existingTbody.children[idx].querySelector('[data-verdict-cell]');
      if (cell && cell.getAttribute('data-verdict') !== r.verdict) {
        cell.setAttribute('data-verdict', r.verdict);
        cell.innerHTML = '<span style="color:' + _vexVerdictColor(r.verdict) + ';font-weight:600;font-size:0.78rem">' + x(r.verdict) + '</span>';
      }
    });
    return;
  }

  var tableHtml = '';
  if (results.length > 0) {
    tableHtml = '<div class="tbl-wrap" style="max-height:300px;overflow-y:auto"><table style="font-size:0.77rem">' +
      '<thead><tr><th>Encoding</th><th>Context</th><th>Evasion</th><th>Risk</th><th>Verdict</th></tr></thead>' +
      '<tbody data-vex-results>' + results.map(_vexResultRowHtml).join('') + '</tbody></table></div>';
  }
  panel.innerHTML = '<div class="card"><div data-vex-wrapper style="display:flex;flex-direction:column;gap:1.2rem;margin-bottom:0.75rem">' + wrapperHtml + '</div>' + tableHtml + '</div>';
}

function vexMini(label, val, col) {
  return '<div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:0.45rem;text-align:center">' +
    '<div style="font-size:0.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:0.15rem">' + label + '</div>' +
    '<div style="font-size:1.15rem;font-weight:700;color:' + col + '">' + (val || 0) + '</div>' +
    '</div>';
}