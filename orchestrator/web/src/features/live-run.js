// Aliased: the Live Run IIFE below keeps its own per-run `state`, which would
// otherwise shadow the shared one (G1c final review, Critical 1).
import { state as appState } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { MODE_LABELS, verdictBadge, verdictCounts } from './reports.js';
import { cssVars } from '../core/css-vars.js';


// ── Live Run Panel ────────────────────────────────────────────────────────────
// Streams run-event frames over the shared browser WS and renders live progress
// (done/total · failed · running) + a per-step timeline. On open it first replays
// persisted events (GET .../events) so a late-joining or reconnecting browser
// reconstructs the same state, then live frames take over. Each step row shows
// the technique ID, human-readable step name, tactic badge, state, verdict, and
// duration. Click a row to expand full detail (ATT&CK link, exit code, etc.).
// Assigned by the Live Run IIFE below (__init_L16159) and called through the
// module-level exports at the bottom; never published on window.
let _toggleLiveStep, _openRunPanel, _onRunEvent;
export function __init_L16159() {
(function () {
  var state = { runId: null, steps: new Map(), total: 0, done: 0, failed: 0, running: 0 };

  var STEP_COLOR = {
    queued:  'var(--muted)',
    running: 'var(--accent)',
    done:    'var(--success)',
    timeout: 'var(--danger)',
    killed:  'var(--danger)',
    blocked: 'var(--warning)'
  };

  // vetoed: agent.go emits exactly {"verdict":"vetoed"} on a step's
  // 'completed' event when B5's agent-side destructive-action guardrail
  // refused to execute it -- without an entry here the live drawer showed
  // the step with an undefined fallback color and a blank label, giving no
  // indication the step never actually ran (final whole-branch review I3).
  var VERDICT_COLOR = { pass: 'var(--success)', fail: 'var(--danger)', blocked: 'var(--warning)', error: 'var(--danger)', vetoed: 'var(--warning)' };
  var VERDICT_LABEL = { pass: 'Prevented', fail: 'Not Prevented', blocked: 'Blocked (AV)', error: 'Error', schedule: 'Timeout', execute: 'Timeout', skipped: 'Skipped (Scheduler)', vetoed: 'Vetoed (Policy)' };

  // Looks up ATT&CK technique name + tactic from the ART catalog. Falls back
  // gracefully when artCatalog hasn't loaded yet (e.g. technique picker not opened).
  function lookupTech(id) {
    if (!id || !appState.artCatalog.length) return null;
    var up = id.toUpperCase();
    for (var i = 0; i < appState.artCatalog.length; i++) {
      if (appState.artCatalog[i].id && appState.artCatalog[i].id.toUpperCase() === up) {
        return { name: appState.artCatalog[i].name || '', tactic: appState.artCatalog[i].tactic || '' };
      }
    }
    return null;
  }

  function humanTactic(t) {
    return t ? t.replace(/-/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); }) : '';
  }

  function attackUrl(id) {
    if (!id) return '';
    return 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/';
  }

  function statCell(value, label, color) {
    return '<div class="g1-s-f89e8d63">' +
      '<div class="g1-s-3c237332"' + cssVars(['g1-v-7d75dfc9', color]) + '>' + value + '</div>' +
      '<div class="g1-s-1dbe5979">' + label + '</div>' +
    '</div>';
  }

  function render() {
    var pct = state.total ? Math.round((state.done / state.total) * 100) : 0;
    document.getElementById('run-live-progress').innerHTML =
      '<div class="g1-display-flex g1-s-d3e598d0">' +
        statCell(state.done + '/' + state.total, 'completed', 'var(--accent)') +
        statCell(state.failed, 'failed', state.failed ? 'var(--danger)' : 'var(--muted)') +
        statCell(state.running, 'running', state.running ? 'var(--accent)' : 'var(--muted)') +
      '</div>' +
      '<div class="g1-s-e6e1105c">' +
        '<div class="g1-s-1f095c2b"' + cssVars(['g1-v-9b890877', pct]) + '></div>' +
      '</div>';

    var ul = document.getElementById('run-live-timeline');
    if (!state.steps.size) {
      ul.innerHTML = '<li class="g1-s-b32f8255">Waiting for the first step…</li>';
      return;
    }

    // Sort running/finished steps above still-queued ones. state.steps is a
    // Map in first-event-seen (dispatch) order -- with concurrency-limited
    // execution and hundreds of steps in a full sweep, that order does NOT
    // match completion order, so the unsorted list could show a screen full
    // of QUEUED rows above the fold indefinitely even as the counters ticked
    // up elsewhere further down. STATE_PRIORITY surfaces what's actually
    // happening (running, then done/failed) first; Array.prototype.sort is
    // stable in every engine we target (ES2019+), so same-priority rows keep
    // their original relative order.
    var STATE_PRIORITY = { running: 0, done: 1, timeout: 1, killed: 1, blocked: 1, queued: 2 };
    var entries = [];
    state.steps.forEach(function (s, task) { entries.push([task, s]); });
    entries.sort(function (a, b) {
      return (STATE_PRIORITY[a[1].state] ?? 1) - (STATE_PRIORITY[b[1].state] ?? 1);
    });

    var rows = [];
    entries.forEach(function (entry) {
      var task = entry[0], s = entry[1];
      var color  = STEP_COLOR[s.state] || 'var(--muted)';
      var blink  = s.state === 'running' ? ';animation:blink 1.5s infinite' : '';
      var techId = s.tech || task;

      // s.techName (from lookupTech/artCatalog) is deliberately NOT used for
      // display here. It's a technique-level "representative name" --
      // ListTechniqueMeta picks steps[0].Name to label a whole technique in
      // pickers/dropdowns, e.g. one row for "T1003" standing in for all 7 of
      // its atomic tests. A technique with multiple tests dispatches one
      // event per test though, each with its own real name in s.stepName --
      // showing techName per-event mislabels every test that isn't the
      // technique's first with that first test's name (every T1003 event
      // reading "Test 1: Gsecdump" regardless of which of the 7 it actually
      // is). s.stepName is what the agent actually reported running.

      // Verdict badge
      var vColor = (s.verdict && VERDICT_COLOR[s.verdict]) || color;
      var vLabel = (s.verdict && VERDICT_LABEL[s.verdict]) || '';
      var verdictHtml = vLabel
        ? ' <span class="g1-s-e493f968"' + cssVars(['g1-v-9a515764', vColor], ['g1-v-7d75dfc9', vColor], ['g1-v-1978c967', vColor]) + '>' + x(vLabel) + '</span>'
        : '';

      // Tactic badge
      var tacticHtml = s.tactic
        ? '<span class="g1-s-203779fe">' + x(humanTactic(s.tactic)) + '</span>'
        : '';

      // Duration (only when completed)
      var durHtml = (s.durationMs != null && (s.state === 'done' || s.state === 'timeout'))
        ? '<span class="g1-s-a9b4215f">∼' + s.durationMs + ' ms</span>'
        : '';

      // Expandable detail block
      var detailHtml = '';
      if (s.expanded) {
        var dl = [];
        if (s.stepName) dl.push('<b>Test:</b> ' + x(s.stepName));
        if (s.tactic)   dl.push('<b>Tactic:</b> ' + x(humanTactic(s.tactic)));
        if (vLabel)     dl.push('<b>Verdict:</b> <span' + cssVars(['g1-v-7d75dfc9', vColor]) + '>' + x(vLabel) + '</span>');
        if (s.durationMs != null) dl.push('<b>Duration:</b> ' + s.durationMs + ' ms');
        if (s.exitCode  != null)  dl.push('<b>Exit&nbsp;code:</b> ' + s.exitCode);
        if (s.tech)     dl.push('<b>ATT&amp;CK:</b> <a href="' + attackUrl(s.tech) + '" target="_blank" class="g1-s-097ae647">' + x(s.tech) + ' &#8599;</a>');
        detailHtml = '<div class="g1-s-9111be16">' +
          dl.join('<br>') + '</div>';
      }

      rows.push(
        '<li class="g1-s-bb89a7c6"' + on('click', 'toggleLiveStepAction', task) + '>' +
          // Main line: dot · ID · name · state. name wraps onto additional
          // lines rather than truncating with an ellipsis, so the complete
          // title (including its own technique-ID prefix, when the real ART
          // atomic name has one) is always fully visible.
          '<div class="g1-display-flex g1-s-3e257d5f">' +
            '<span class="g1-s-59566913' + (blink ? ' g1-s-5302a419' : '') + '"' + cssVars(['g1-v-9ffd39ba', color]) + '></span>' +
            '<span class="g1-s-f5447c1a">' + x(techId) + '</span>' +
            '<span class="g1-s-7158533f">' + x(s.stepName || techId) + '</span>' +
            '<span class="g1-s-bacb7a09"' + cssVars(['g1-v-7d75dfc9', color]) + '>' + x(s.state === 'done' ? 'done' : s.state) + '</span>' +
            verdictHtml +
          '</div>' +
          // Sub-line: tactic badge · duration (step name is already the main-line title above)
          (s.tactic || durHtml
            ? '<div class="g1-display-flex g1-s-5282dde1">' +
                tacticHtml +
                '<span class="u-flex1"></span>' +
                durHtml +
              '</div>'
            : '') +
          detailHtml +
        '</li>');
    });
    ul.innerHTML = rows.join('');
  }

  // Toggle expanded detail for a step row (click handler).
  _toggleLiveStep = function (taskId) {
    var s = state.steps.get(taskId);
    if (!s) return;
    s.expanded = !s.expanded;
    state.steps.set(taskId, s);
    render();
  };

  function applyEvent(e) {
    if (e.type === 'run_started') {
      state.total = (e.payload && e.payload.stepsTotal) || state.total;
    } else if (e.type === 'queued') {
      var meta = lookupTech(e.techniqueId);
      state.steps.set(e.taskId, {
        tech:     e.techniqueId,
        stepName: e.stepName || '',
        techName: (meta && meta.name)   || '',
        tactic:   (meta && meta.tactic) || '',
        state:    'queued'
      });
    } else if (e.type === 'started') {
      var s = state.steps.get(e.taskId) || {};
      s.tech = e.techniqueId || s.tech;
      if (e.stepName && !s.stepName) s.stepName = e.stepName;
      if (!s.techName || !s.tactic) {
        var meta = lookupTech(s.tech);
        if (meta) { s.techName = s.techName || meta.name; s.tactic = s.tactic || meta.tactic; }
      }
      s.state = 'running';
      state.steps.set(e.taskId, s);
    } else if (e.type === 'completed' || e.type === 'timeout' || e.type === 'killed') {
      var st = state.steps.get(e.taskId) || {};
      st.tech = e.techniqueId || st.tech;
      if (e.stepName && !st.stepName) st.stepName = e.stepName;
      st.state   = e.type === 'completed' ? 'done' : e.type;
      st.verdict = e.payload && (e.payload.verdict || e.payload.reason);
      if (e.payload && e.payload.durationMs != null) st.durationMs = e.payload.durationMs;
      if (e.payload && e.payload.exitCode   != null) st.exitCode   = e.payload.exitCode;
      state.steps.set(e.taskId, st);
    }
    var done = 0, failed = 0, running = 0;
    state.steps.forEach(function (s) {
      if (s.state === 'done' || s.state === 'timeout' || s.state === 'killed') done++;
      if (s.verdict === 'fail' || s.verdict === 'blocked' || s.state === 'timeout') failed++;
      if (s.state === 'running') running++;
    });
    state.done = done; state.failed = failed; state.running = running;
  }

  // Opened from a run row. Replays persisted events first (reconnect-safe), then
  // live frames arrive via onRunEvent().
  //
  // knownStepsTotal seeds state.total directly from the run row's own
  // progress summary (scenario_runs.steps_total, always populated once any
  // step event has landed) instead of relying solely on finding a
  // 'run_started' event in the replay below. For a large sweep (hundreds+
  // steps, thousands of events) that replay can legitimately not include it
  // -- e.g. the panel is opened well after the run started, or the event
  // arrives in a later page/batch than assumed -- which previously left
  // state.total stuck at 0 ("264/0") even though steps were clearly
  // completing. The 'run_started' event, when found during replay, still
  // overwrites this via applyEvent's own assignment -- harmless, since both
  // sources should always agree once it's found.
  // mode/maxPrivilege are passed as plain strings (not a JSON object) since
  // this is invoked from data-args action attributes elsewhere —
  // an embedded JSON.stringify object's double quotes would terminate the
  // attribute early.
  _openRunPanel = async function (runId, name, knownStepsTotal, mode, maxPrivilege) {
    state.runId = runId; state.steps = new Map(); state.total = knownStepsTotal || 0;
    state.done = 0; state.failed = 0; state.running = 0;
    document.getElementById('run-live-title').textContent = (name || 'Run') + ' — Live';
    // Run Settings subtitle — same "what was selected" answer the Results
    // drawer shows post-completion, so an in-flight run isn't a blind spot.
    document.getElementById('run-live-subtitle').textContent = mode
      ? 'Mode: ' + (MODE_LABELS[mode] || mode) + '  ·  Privilege: ' + (maxPrivilege ? (maxPrivilege.charAt(0).toUpperCase() + maxPrivilege.slice(1)) : 'No limit')
      : '';
    document.getElementById('run-live-overlay').classList.add('open');
    render();
    try {
      var r = await fetch('/api/scenarios/runs/' + encodeURIComponent(runId) + '/events', { credentials: 'include' });
      if (r.ok) (await r.json()).forEach(applyEvent);
    } catch (_) {}
    render();
  };

  // Called from the shared browser-WS onmessage handler for run_event frames.
  _onRunEvent = function (msg) {
    if (!msg || msg.type !== 'run_event' || !msg.data) return;
    if (msg.data.runId !== state.runId) return;
    (msg.data.events || []).forEach(applyEvent);
    render();
  };
})();
}


export function toggleLiveStep(taskId) { return _toggleLiveStep(taskId); }
export function openRunPanel(runId, name, knownStepsTotal, mode, maxPrivilege) { return _openRunPanel(runId, name, knownStepsTotal, mode, maxPrivilege); }
// Called from the shared browser-WS onmessage handler (features/evidence.js).
export function onRunEvent(msg) { return _onRunEvent(msg); }
export function toggleLiveStepAction(taskId) { toggleLiveStep(taskId); }
export function openRunPanelAction(runId, name, knownStepsTotal, mode, maxPrivilege) { return openRunPanel(runId, name, knownStepsTotal, mode, maxPrivilege); }
export function openSweepReport(sweepId) { window.open('/api/vex/sweeps/' + encodeURIComponent(sweepId) + '/report', '_blank'); }

export function closeRunLive() { document.getElementById('run-live-overlay').classList.remove('open'); }
export function closeRunLiveOnBackdrop(el, event) { if (event.target === el) closeRunLive(); }

// openSweepDrilldown lists every technique a Full Variant Sweep dispatched --
// each list item reuses the EXISTING, unmodified openRunPanel/viewRunResults
// for that specific run, matching how loadRuns() already opens them for a
// normal individual run.
export function openSweepDrilldown(sweepId) {
  document.getElementById('sweep-drilldown-title').textContent = 'Full Variant Sweep';
  document.getElementById('sweep-drilldown-summary').textContent = 'Loading…';
  document.getElementById('sweep-drilldown-actions').innerHTML = '';
  document.getElementById('sweep-drilldown-list').innerHTML = '';
  document.getElementById('sweep-drilldown-overlay').classList.add('open');
  apicall('/api/vex/sweeps/' + sweepId + '/runs').then(function(payload) {
    var sw = payload.sweep, childRuns = payload.runs || [];
    document.getElementById('sweep-drilldown-title').textContent = 'Full Variant Sweep — ' + (sw.agentId || '');
    document.getElementById('sweep-drilldown-summary').textContent =
      sw.status + ' · ' + childRuns.length + ' technique(s) dispatched';
    document.getElementById('sweep-drilldown-actions').innerHTML =
      '<button class="btn btn-outline btn-sm"' + on('click', 'openSweepReport', sweepId) + ' title="Open the combined sweep report">&#8599; HTML Report</button> ' +
      '<button class="btn btn-outline btn-sm"' + on('click', 'downloadSweepReport', sweepId) + ' title="Download the combined sweep report as a PDF file">&#8595; PDF Report</button>';
    document.getElementById('sweep-drilldown-list').innerHTML = childRuns.map(function(r) {
      var badge = verdictBadge(r, r.status);
      var liveBtn = (r.id && r.status === 'running')
        ? '<button class="btn btn-outline btn-sm" ' + on('click', 'openRunPanelAction', r.id, r.name, (r.progress && r.progress.stepsTotal) || 0, r.mode || '', r.maxPrivilege || '') + '>&#9673; Live</button> '
        : '';
      // A cancelled/partial technique run never gets the agent's one atomic
      // `results` write, so verdictCounts(r).total is always 0 -- but its per-step pass/fail
      // counts already streamed in live (r.progress) and the same detail is
      // still queryable from run_events via openRunPanel, so this reuses
      // that real data instead of a plain, unclickable status label.
      var resultBtn;
      if (verdictCounts(r).total) {
        resultBtn = '<button class="btn btn-outline btn-sm" ' + on('click', 'viewRunResults', r) + '>' + badge + '</button>';
      } else if (r.id && r.status !== 'running' && r.progress) {
        var pr = r.progress;
        var toBadge = pr.stepsFailed + ' fail / ' + pr.stepsPassed + ' pass' + (pr.stepsTimeout ? ' / ' + pr.stepsTimeout + ' timeout' : '');
        resultBtn = '<button class="btn btn-outline btn-sm"' + on('click', 'openRunPanelAction', r.id, r.name, pr.stepsTotal || 0, r.mode || '', r.maxPrivilege || '') + '>' + toBadge + '</button>';
      } else {
        resultBtn = '<span class="tiny muted">' + x(badge) + '</span>';
      }
      return '<li class="g1-display-flex g1-s-7ac8d119">' +
        '<span>' + x(r.name) + '</span>' +
        '<span class="g1-s-eb99a4c1">' + liveBtn + resultBtn + '</span></li>';
    }).join('');
  }).catch(function(e) { showToast(e.message, 'err'); closeSweepDrilldown(); });
}

export function closeSweepDrilldown() { document.getElementById('sweep-drilldown-overlay').classList.remove('open'); }
export function closeSweepDrilldownOnBackdrop(el, event) { if (event.target === el) closeSweepDrilldown(); }