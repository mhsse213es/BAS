import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { ago, fmtDate, fmtRunIdCode, showToast } from '../core/util.js';
import { renderGroupCheckboxList } from './adversaries.js';
import { agentBucket, loadScenarios, renderScenarios, resolveGroupTargetAgents } from './attack-path.js';
import { cmpAgentOS } from './campaigns.js';
import { covStatusMap } from './coverage.js';
import { vfStatusColor } from './detection-verification.js';
import { gaugeSVG, showDownloadOptions, triggerDownload } from './evidence.js';
import { renderRunIOCList, renderRunIOCToolbar } from './iocs.js';
import { rerunSubset } from './rerun-review.js';
import { ROLE, _artCatalogByPlatform, _riskScoreColor } from './shell.js';
import { renderAttackFlow, renderRunFindings, renderRunRecommendations, renderRunReportExtra, renderVariantCoverage } from './variant-report.js';


// ── Reports ──────────────────────────────────────────────────────────────────
var REPORT_TYPE = 'posture';
export function loadReports() {
  renderRepHistory();
  // Per-agent launcher: which agents have run data we can report on.
  apicall('/api/scenarios/runs').then(function(runs) {
    var byAgent = {};
    (runs || []).forEach(function(r) {
      if (r.status !== 'completed' && r.status !== 'partial') return;
      var id = r.agentId; if (!id) return;
      if (!byAgent[id]) byAgent[id] = { runs: 0, last: r.completedAt || r.startedAt, lastName: r.name };
      byAgent[id].runs++;
    });
    var hostOf = {};
    (state.agents || []).forEach(function(a) { hostOf[a.agentId] = a.hostname || a.agentId; });
    var ids = Object.keys(byAgent);
    var el = document.getElementById('rep-available');
    if (!ids.length) {
      el.innerHTML = '<div class="empty" style="padding:1.25rem">No agents with completed runs yet. Run a scenario, then generate its report here.</div>';
      return;
    }
    var d = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M4 1.5h6l3 3V14.5H4z"/><path d="M9.5 1.5v3.5H13M6 8h4M6 10.5h4"/></svg>';
    el.innerHTML = ids.map(function(id) {
      var host = hostOf[id] || id, n = byAgent[id].runs, lastName = byAgent[id].lastName;
      return '<div class="rep-row">' +
        '<div class="rep-ic">' + d + '</div>' +
        '<div class="rep-main"><div class="rep-host">' + x(host) + '</div>' +
          '<div class="rep-sub">Reports on: <strong class="u-text">' + x(lastName || 'unnamed scenario') + '</strong> (latest run) · ' + n + ' run' + (n === 1 ? '' : 's') + ' total · last ' + ago(byAgent[id].last) + '</div></div>' +
        '<div class="rep-acts">' +
          '<button class="btn btn-outline btn-sm" onclick="genAgentReport(\'' + x(id) + '\',\'posture\',\'pdf\')">PDF Report</button>' +
          '<button class="btn btn-outline btn-sm" onclick="genAgentReport(\'' + x(id) + '\',\'posture\',\'csv\')">CSV</button>' +
          '<button class="btn btn-outline btn-sm" onclick="genAgentReport(\'' + x(id) + '\',\'audit\',\'\')">Audit pack</button>' +
        '</div></div>';
    }).join('');
  }).catch(function() {
    document.getElementById('rep-available').innerHTML = '<div class="empty" style="padding:1.25rem">Could not load agents.</div>';
  });
}
function renderRepHistory() {
  apicall('/api/reports').then(function(list) {
    var tb = document.getElementById('reports-body');
    list = list || [];
    if (!list.length) {
      tb.innerHTML = '<tr><td colspan="7" class="empty" style="padding:1.5rem;line-height:1.6">No reports generated yet — this log fills when you generate one (from a tile above or the per-agent buttons). Test runs don\'t create reports automatically.</td></tr>';
      return;
    }
    var label = { posture: 'Posture report', audit: 'Audit pack', compliance: 'Compliance evidence' };
    tb.innerHTML = list.map(function(r) {
      var st = r.status === 'failed' ? 's-failed' : 's-completed';
      return '<tr>' +
        '<td class="cell-main">' + x(label[r.reportType] || r.reportType) + '</td>' +
        '<td class="tiny muted">' + x(r.scopeLabel) + '</td>' +
        '<td class="tiny">' + x((r.format || '—').toUpperCase()) + '</td>' +
        '<td class="tiny muted">' + x(r.generatedBy || '—') + '</td>' +
        '<td class="tiny muted">' + fmtDate(r.generatedAt) + '</td>' +
        '<td><span class="sbadge ' + st + '">' + x(r.status) + '</span></td>' +
        '<td class="td-r"><a class="btn btn-outline btn-sm" href="' + x(r.downloadPath) + '" target="_blank" rel="noopener">&#9660; Download</a></td></tr>';
    }).join('');
  }).catch(function(e) { showToast(e.message, 'err'); });
}
// genAgentReport logs the generation to history (report_log) and opens the
// download — the same path the modal uses, so the per-agent launcher and the
// tiles share one history.
export function genAgentReport(agentId, type, format) {
  if (type === 'audit') {
    apicall('/api/reports', { method: 'POST', body: JSON.stringify({ reportType: type, agentId: agentId, format: format, filter: 'all' }) })
      .then(function(res) {
        if (res && res.error) { showToast('Generate failed: ' + res.error, 'err'); return; }
        window.open(res.downloadPath, '_blank');
        showToast('Report generating — download opened', 'ok');
        renderRepHistory();
      }).catch(function(e) { showToast('Generate failed: ' + e.message, 'err'); });
  } else {
    showDownloadOptions('Report Options', function(filter) {
      apicall('/api/reports', { method: 'POST', body: JSON.stringify({ reportType: type, agentId: agentId, format: format, filter: filter }) })
        .then(function(res) {
          if (res && res.error) { showToast('Generate failed: ' + res.error, 'err'); return; }
          window.open(res.downloadPath, '_blank');
          showToast('Report generating — download opened', 'ok');
          renderRepHistory();
        }).catch(function(e) { showToast('Generate failed: ' + e.message, 'err'); });
    });
  }
}
export function openReportGen(type) {
  REPORT_TYPE = type;
  if (!state.agents.length) { showToast('No agents registered yet', 'err'); return; }
  var label = { posture: 'Posture report', audit: 'Audit pack', compliance: 'Compliance evidence' };
  document.getElementById('report-modal-title').textContent = 'Generate — ' + label[type];
  document.getElementById('rep-agent').innerHTML = state.agents.map(function(a) {
    return '<option value="' + x(a.agentId) + '">' + x(a.agentId) + ' — ' + x(a.hostname) + '</option>';
  }).join('');
  var fmts = type === 'compliance' ? ['html', 'csv'] : type === 'audit' ? [''] : ['html', 'csv'];
  document.getElementById('rep-format').innerHTML = fmts.map(function(f) {
    var lbl = f ? f.toUpperCase() : 'Package';
    if (type === 'posture' && f === 'csv') lbl = 'CSV (forensic)';
    return '<option value="' + f + '">' + lbl + '</option>';
  }).join('');
  var fwWrap = document.getElementById('rep-fw-wrap');
  if (type === 'compliance') {
    fwWrap.style.display = '';
    apicall('/api/compliance/frameworks').then(function(fws) {
      document.getElementById('rep-fw').innerHTML = (fws || []).map(function(f) {
        return '<option value="' + x(f.id) + '">' + x(f.name || f.id) + '</option>';
      }).join('');
    });
  } else {
    fwWrap.style.display = 'none';
  }
  var filterWrap = document.getElementById('rep-filter-wrap');
  if (type === 'audit') {
    if (filterWrap) filterWrap.style.display = 'none';
  } else {
    if (filterWrap) filterWrap.style.display = '';
  }
  document.getElementById('report-overlay').classList.add('open');
}
export function closeReportGen() { document.getElementById('report-overlay').classList.remove('open'); }
export function submitReport() {
  var body = {
    reportType: REPORT_TYPE,
    agentId: document.getElementById('rep-agent').value,
    format: document.getElementById('rep-format').value,
    filter: (REPORT_TYPE !== 'audit') ? document.getElementById('rep-filter').value : 'all',
    framework: REPORT_TYPE === 'compliance' ? document.getElementById('rep-fw').value : ''
  };
  apicall('/api/reports', { method: 'POST', body: JSON.stringify(body) }).then(function(res) {
    if (res && res.error) { showToast('Generate failed: ' + res.error, 'err'); return; }
    closeReportGen();
    window.open(res.downloadPath, '_blank');
    showToast('Report generating — download opened', 'ok');
    loadReports();
  }).catch(function(e) { showToast('Generate failed: ' + e.message, 'err'); });
}

// verdictCounts is the single source of truth for turning a run into
// pass/fail/not-measured counts, so every view that shows them agrees.
//
// ERROR and SKIPPED are neither pass nor fail: internal/models/score.go
// excludes them from the security score entirely, because they answer "did the
// BAS hit a problem", not "did a control allow the technique". Several views
// used to derive passes by subtraction (total - fail), which silently reported
// every errored step as a control success -- a run whose detail read
// "Total 29, Pass 0, Fail 9, Skipped 1, Errored 19" was listed as
// "9 fail / 20 pass".
//
// Prefers the server-computed score; falls back to counting verdicts directly
// for a run that has no score yet. The fallback mirrors score.go, where
// 'blocked' counts as passed.
export function verdictCounts(r) {
  var sc = r && r.score;
  if (sc && typeof sc.totalTechniques !== 'undefined') {
    return {
      total:       sc.totalTechniques || 0,
      pass:        sc.passedTechniques || 0,
      fail:        sc.failedTechniques || 0,
      // VETOED (B5's agent-side destructive-action guardrail) counts toward
      // sc.totalTechniques same as error/skipped, so it must be folded into
      // notMeasured here too -- otherwise the displayed fail+pass+notMeasured
      // sum silently undercounts the total (final whole-branch review I3).
      notMeasured: (sc.erroredTechniques || 0) + (sc.skippedTechniques || 0) + (sc.vetoedTechniques || 0)
    };
  }
  var results = (r && r.results) || [];
  var by = function(fn) { return results.filter(fn).length; };
  return {
    total:       results.length,
    pass:        by(function(c) { return c.result === 'pass' || c.result === 'blocked'; }),
    fail:        by(function(c) { return c.result === 'fail'; }),
    notMeasured: by(function(c) { return c.result === 'error' || c.result === 'skipped' || c.result === 'vetoed'; })
  };
}

// verdictBadge renders the compact "N fail / N pass / N n/a" summary. The
// not-measured segment is shown, never folded away, so a reader can account for
// every technique in the total.
export function verdictBadge(r, emptyLabel) {
  var v = verdictCounts(r);
  if (!v.total) return emptyLabel;
  return v.fail + ' fail / ' + v.pass + ' pass' + (v.notMeasured ? ' / ' + v.notMeasured + ' n/a' : '');
}

// runRowHtml renders one individual (non-sweep-collapsed) run's <tr> --
// extracted unchanged from loadRuns() so it can also be reused for a sweep
// row's per-sweep fetch-failure fallback (see loadRuns() below).
function runRowHtml(r) {
  var badge = verdictBadge(r, '—');
  var scoreHtml = '—';
  if (r.score && typeof r.score.preventionScore !== 'undefined') {
    var prevPct = Math.round(r.score.preventionScore || 0);
    var expVal  = Math.round(r.score.exposureScore || 0);
    var cls     = r.score.classification || '';
    var prevCol = prevPct >= 80 ? 'var(--teal)' : prevPct >= 50 ? 'var(--warning)' : 'var(--danger)';
    var expCol  = expVal  <= 20 ? 'var(--success)' : expVal  <= 50 ? 'var(--warning)' : 'var(--danger)';
    var trend   = r.score.trend || '';
    var trendBadge = trend === 'Improving' ? '<span style="color:var(--success);font-size:0.65rem;margin-left:0.3rem">↑</span>' :
                     trend === 'Degrading' ? '<span style="color:var(--danger);font-size:0.65rem;margin-left:0.3rem">↓</span>' : '';
    scoreHtml = '<span style="font-weight:600;color:' + prevCol + '">' + prevPct + '%</span>' +
                '<span style="color:var(--muted);font-size:0.65rem;margin-left:0.2rem">prev</span>' +
                '<span style="color:' + expCol + ';font-size:0.72rem;margin-left:0.45rem">exp:' + expVal + '</span>' +
                trendBadge;
  } else if (r.score && typeof r.score.riskScore !== 'undefined') {
    var cls2 = r.score.classification || '';
    var col2 = cls2 === 'Protected' ? 'var(--success)' : cls2 === 'Medium Risk' ? 'var(--warning)' : 'var(--danger)';
    scoreHtml = '<span style="font-weight:600;color:' + col2 + '">' + r.score.riskScore + '</span>' +
                '<span style="color:var(--muted);font-size:0.72rem;margin-left:0.3rem">' + x(cls2) + '</span>';
  } else if (r.progress && r.progress.stepsDone > 0) {
    var pr = r.progress;
    scoreHtml = '<span style="color:var(--success);font-weight:600">' + pr.stepsPassed + '</span>' +
                '<span style="color:var(--muted);font-size:0.6rem">pass</span> / ' +
                '<span style="color:var(--danger);font-weight:600">' + pr.stepsFailed + '</span>' +
                '<span style="color:var(--muted);font-size:0.6rem">fail</span>' +
                (pr.stepsTimeout ? ' / <span style="color:var(--warning);font-weight:600">' + pr.stepsTimeout + '</span><span style="color:var(--muted);font-size:0.6rem">timeout</span>' : '') +
                // "live" -- this is the best-effort per-step event snapshot
                // (steps_done/steps_total from SubmitRunEvents), not the
                // authoritative run status. It can legitimately show N/N
                // while the run itself is still 'running' if the agent's
                // final result submission hasn't landed yet -- "partial"
                // previously appeared here unconditionally, which read as
                // the run having ended incomplete even at N/N.
                '<span style="color:var(--muted);font-size:0.65rem;margin-left:0.35rem">' + pr.stepsDone + '/' + pr.stepsTotal + ' live</span>';
  }
  return '<tr>' +
    '<td>' + fmtRunIdCode(r.id) + '</td>' +
    '<td style="font-weight:500">' + x(r.name) + '</td>' +
    '<td><code>' + x(r.agentId) + '</code></td>' +
    '<td><span class="sbadge ' + (r.agentDisconnected && r.status === 'running' ? 's-agent_disconnected' : (r.status === 'running' && r.paused ? 's-paused' : 's-' + x(r.status))) + '">' +
        (r.agentDisconnected && r.status === 'running' ? 'Agent Disconnected' : (r.status === 'running' && r.paused ? 'Paused' : x(r.status))) + '</span></td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + x(r.initiatedBy || '—') + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + fmtDate(r.startedAt) + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + (r.completedAt ? fmtDate(r.completedAt) : '—') + '</td>' +
    '<td>' + (function() {
      var acts = '';
      // Live is only meaningful while the run is actually running -- once
      // it's terminal (partial/completed), the same underlying data (see
      // below) is history, not a live stream, so it gets the results-style
      // pass/fail label instead of "Live".
      if (r.id && r.status === 'running') acts += '<button class="btn btn-outline btn-sm" onclick="openRunPanel(\'' + x(r.id) + '\',\'' + x(r.name).replace(/'/g,'&#39;') + '\',' + ((r.progress && r.progress.stepsTotal) || 0) + ',\'' + x(r.mode||'') + '\',\'' + x(r.maxPrivilege||'') + '\')" title="Live run timeline + progress">&#9673; Live</button> ';
      if (r.id && r.status === 'running') acts += '<button class="btn btn-outline-red btn-sm" onclick="stopRun(\'' + x(r.id) + '\')" title="Stop this run — keeps completed steps, marks the run partial">&#9632; Stop</button> ';
      // Pause/Resume works for every run mode now -- both the ART/Custom step
      // scheduler (runScenario) and the posture local-check path (runLocalScan)
      // share the same agent-side gate/emit wiring.
      if (r.id && r.status === 'running') {
        acts += r.paused
          ? '<button class="btn btn-outline btn-sm" id="pause-btn-' + x(r.id) + '" onclick="resumeRun(\'' + x(r.id) + '\')">&#9654; Resume</button> '
          : '<button class="btn btn-outline btn-sm" id="pause-btn-' + x(r.id) + '" onclick="pauseRun(\'' + x(r.id) + '\')">&#10073;&#10073; Pause</button> ';
      }
      if (verdictCounts(r).total) {
        acts += '<button class="btn btn-outline btn-sm" onclick=\'viewRunResults(' + JSON.stringify(r).replace(/'/g,"&#39;") + ')\'>' + badge + '</button>';
      } else if (r.id && r.status !== 'running' && r.progress) {
        // A cancelled/partial run never gets the agent's one atomic
        // `results` write (see cancelScenarioRun/forceCancelAfterGracePeriod
        // in internal/api/handlers.go), so verdictCounts(r).total is always 0 here -- but the
        // per-step pass/fail counts already streamed in live via
        // SubmitRunEvents (r.progress) and the same per-step detail is
        // still queryable from run_events, so openRunPanel's timeline is
        // real data, not empty. This is that same panel, just correctly
        // labeled as a completed (partial) run's results instead of "Live".
        var pr = r.progress;
        var toBadge = pr.stepsFailed + ' fail / ' + pr.stepsPassed + ' pass' + (pr.stepsTimeout ? ' / ' + pr.stepsTimeout + ' timeout' : '');
        acts += '<button class="btn btn-outline btn-sm" onclick="openRunPanel(\'' + x(r.id) + '\',\'' + x(r.name).replace(/'/g,'&#39;') + '\',' + (pr.stepsTotal || 0) + ',\'' + x(r.mode||'') + '\',\'' + x(r.maxPrivilege||'') + '\')" title="Per-step results for this partial run">' + toBadge + '</button>';
      } else if (r.failReason) {
        // A run that failed before any step produced results/progress (e.g.
        // dispatch-time failure -- agent offline, no matching agent, etc.)
        // has nothing for the two branches above to render, but the API
        // already returns exactly why (r.failReason) -- it was simply never
        // surfaced here, leaving the cell a dead "—" with no way to see it.
        acts += '<span style="color:var(--danger);font-size:0.78rem" title="' + x(r.failReason) + '">' + x(r.failReason) + '</span>';
      }
      return acts || '—';
    })() + '</td>' +
    '<td>' + scoreHtml + '</td></tr>';
}

function renderRunRows(list) {
  return list.map(runRowHtml).join('');
}

// sweepStatusLabel maps a sweep's raw status to display text. Every status
// except agent_disconnected already reads fine verbatim (CSS capitalizes
// the first letter) -- agent_disconnected needs an explicit mapping since
// its underscore would otherwise render literally ("Agent_disconnected").
export function sweepStatusLabel(status) {
  return status === 'agent_disconnected' ? 'Agent Disconnected' : status;
}

// sweepAggregateScoreHtml averages the per-child-run score across every run
// a sweep dispatched, mirroring runRowHtml's own preventionScore/riskScore
// branch selection so a sweep's Score column reads the same way an
// individual run's does. Previously the sweep rows never computed this at
// all -- their last <td> (under the "Score" header) was actually the Stop
// button, which always renders "—" once the sweep is no longer running,
// making a completed sweep's score permanently blank.
function sweepAggregateScoreHtml(childRuns) {
  var withPrevention = childRuns.filter(function(r) { return r.score && typeof r.score.preventionScore !== 'undefined'; });
  var withRisk = childRuns.filter(function(r) { return r.score && typeof r.score.riskScore !== 'undefined'; });
  if (withPrevention.length) {
    var avgPrev = withPrevention.reduce(function(s, r) { return s + (r.score.preventionScore || 0); }, 0) / withPrevention.length;
    var avgExp  = withPrevention.reduce(function(s, r) { return s + (r.score.exposureScore || 0); }, 0) / withPrevention.length;
    var prevPct = Math.round(avgPrev);
    var expVal  = Math.round(avgExp);
    var prevCol = prevPct >= 80 ? 'var(--teal)' : prevPct >= 50 ? 'var(--warning)' : 'var(--danger)';
    var expCol  = expVal  <= 20 ? 'var(--success)' : expVal  <= 50 ? 'var(--warning)' : 'var(--danger)';
    return '<span style="font-weight:600;color:' + prevCol + '">' + prevPct + '%</span>' +
           '<span style="color:var(--muted);font-size:0.65rem;margin-left:0.2rem">avg prev</span>' +
           '<span style="color:' + expCol + ';font-size:0.72rem;margin-left:0.45rem">exp:' + expVal + '</span>';
  }
  if (withRisk.length) {
    var avgRisk = withRisk.reduce(function(s, r) { return s + (r.score.riskScore || 0); }, 0) / withRisk.length;
    var riskPct = Math.round(avgRisk);
    var riskCol = riskPct <= 20 ? 'var(--success)' : riskPct <= 50 ? 'var(--warning)' : 'var(--danger)';
    return '<span style="font-weight:600;color:' + riskCol + '">' + riskPct + '</span>' +
           '<span style="color:var(--muted);font-size:0.72rem;margin-left:0.3rem">avg risk</span>';
  }
  return '—';
}

// renderSweepRow builds one collapsed "Full Variant Sweep" <tr> from a
// GET /api/vex/sweeps/{id}/runs response ({sweep, runs}). The badge sums
// each child run's own fail/pass counts (same per-run counting runRowHtml
// already uses) across the WHOLE sweep, not a per-technique pass/fail --
// i.e. total variants failed vs. passed across every technique dispatched.
// _sweepRowHtml is the shared shape behind renderSweepRow (VEX Full Variant
// Sweep) and renderEMSweepRow (Endpoint Mastery Full Sweep) below -- the two
// were previously hand-mirrored copies of the same <tr> (see the old comment
// on renderEMSweepRow: "mirrors renderSweepRow above"). opts carries every
// point where the two actually differ: label prefix, drilldown handler +
// its title text, the progress-label text, and the stop handler.
function _sweepRowHtml(payload, opts) {
  var sw = payload.sweep, childRuns = payload.runs || [];
  var totalCnt = 0, totalFail = 0;
  childRuns.forEach(function(r) {
    var cnt = (r.results || []).length;
    var fail = (r.results || []).filter(function(c) { return c.result === 'fail'; }).length;
    totalCnt += cnt; totalFail += fail;
  });
  var badge = totalCnt ? (totalFail + ' fail / ' + (totalCnt - totalFail) + ' pass') : '—';
  var agent = state.agents.find(function(a) { return a.agentId === sw.agentId; });
  var agentLabel = agent ? agent.hostname : sw.agentId;
  return '<tr>' +
    '<td>' + fmtRunIdCode(sw.id) + '</td>' +
    '<td style="font-weight:500">' + opts.labelPrefix + ' — ' + x(agentLabel) + '</td>' +
    '<td><code>' + x(sw.agentId) + '</code></td>' +
    '<td><span class="sbadge s-' + x(sw.status) + '">' + x(sweepStatusLabel(sw.status)) + '</span></td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + x(sw.createdBy || '—') + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + fmtDate(sw.startedAt) + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + (sw.completedAt ? fmtDate(sw.completedAt) : '—') + '</td>' +
    '<td><button class="btn btn-outline btn-sm" onclick="' + opts.drilldownFn + '(\'' + x(sw.id) + '\')" title="' + opts.drilldownTitle + '">' +
        x(opts.progressLabel(sw)) + ' — ' + badge + '</button>' +
        ((sw.status === 'running' || sw.status === 'agent_disconnected')
          ? ' <button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger)" onclick="' + opts.stopFn + '(\'' + x(sw.id) + '\')">&#9632; Stop</button>'
          : '') + '</td>' +
    '<td>' + sweepAggregateScoreHtml(childRuns) + '</td></tr>';
}

function renderSweepRow(payload) {
  return _sweepRowHtml(payload, {
    labelPrefix: 'Full Variant Sweep',
    drilldownFn: 'openSweepDrilldown',
    drilldownTitle: 'View every technique this sweep dispatched',
    progressLabel: function(sw) {
      return sw.status === 'running'
        ? sw.completedVariants + '/' + sw.totalVariants + ' variants'
        : sw.totalTechniques + ' atomic test(s)';
    },
    stopFn: 'stopVexSweep'
  });
}

// renderEMSweepRow builds one collapsed "Endpoint Mastery Full Sweep" <tr>
// from a GET /api/em/sweeps/{id}/runs response ({sweep, runs}) -- mirrors
// renderSweepRow above, reusing the same drawer (openEMSweepProgress) that
// already shows live per-layer status when a sweep is first dispatched.
function renderEMSweepRow(payload) {
  return _sweepRowHtml(payload, {
    labelPrefix: 'Endpoint Mastery Full Sweep',
    drilldownFn: 'openEMSweepProgress',
    drilldownTitle: 'View every EM layer this sweep dispatched',
    progressLabel: function(sw) { return sw.completedLayers + '/' + sw.totalLayers + ' layers'; },
    stopFn: 'stopEMSweep'
  });
}

// Sweep-grouping kinds Live Runs collapses into one row: field is the
// runRow property carrying the group id, api builds the {sweep,runs}
// fetch URL, render builds the collapsed <tr>. Add an entry here for any
// future sweep type instead of duplicating loadRuns' grouping logic.
var SWEEP_GROUP_KINDS = [
  { field: 'sweepId',   api: function(id) { return '/api/vex/sweeps/' + id + '/runs'; }, render: renderSweepRow },
  { field: 'emSweepId', api: function(id) { return '/api/em/sweeps/' + id + '/runs'; },  render: renderEMSweepRow }
];

export function loadRuns() {
  apicall('/api/scenarios/runs').then(function(runs) {
    // Group sweep-dispatched rows (non-null sweepId/emSweepId) so Live Runs
    // shows one row per sweep instead of one row per technique/layer it
    // dispatched. Every OTHER consumer of this same endpoint (Dashboard,
    // Coverage matrix, etc.) ignores these fields entirely and is
    // completely unaffected.
    var groups = SWEEP_GROUP_KINDS.map(function(kind) {
      return { kind: kind, ids: [], seen: {} };
    });
    var individualRuns = [];
    runs.forEach(function(r) {
      var group = groups.find(function(g) { return r[g.kind.field]; });
      if (!group) { individualRuns.push(r); return; }
      var id = r[group.kind.field];
      if (!group.seen[id]) { group.seen[id] = true; group.ids.push(id); }
    });

    var tbody = document.getElementById('runs-body');
    if (!runs.length) {
      document.getElementById('runs-cnt').textContent = '0';
      tbody.innerHTML = '<tr><td colspan="9" class="empty">No runs yet. Go to Scenarios and run one.</td></tr>';
      return;
    }

    // Sort by real recency (most recently started first), never by
    // insertion/grouping order -- a currently-running sweep is the most
    // recent thing happening and belongs at the top, not stuck at the
    // bottom just because it's rendered as a collapsed group row.
    function byStartedAtDesc(a, b) {
      var ta = a.startedAt ? new Date(a.startedAt).getTime() : 0;
      var tb = b.startedAt ? new Date(b.startedAt).getTime() : 0;
      return tb - ta;
    }

    var totalGroupIds = groups.reduce(function(n, g) { return n + g.ids.length; }, 0);
    if (!totalGroupIds) {
      document.getElementById('runs-cnt').textContent = individualRuns.length;
      tbody.innerHTML = individualRuns.slice().sort(byStartedAtDesc).map(runRowHtml).join('');
      return;
    }

    var fetches = [];
    groups.forEach(function(g) {
      g.ids.forEach(function(id) {
        fetches.push(
          apicall(g.kind.api(id)).then(function(res) {
            return { field: g.kind.field, id: id, ok: true, data: res, render: g.kind.render };
          }).catch(function() {
            return { field: g.kind.field, id: id, ok: false };
          })
        );
      });
    });

    Promise.all(fetches).then(function(groupResults) {
      var rowsToRenderIndividually = individualRuns.slice();
      var groupEntries = []; // {startedAt, html} -- merged with individual rows below, not appended after them
      groupResults.forEach(function(gr) {
        if (!gr.ok) {
          // The per-sweep fetch failed -- fall back to rendering this sweep's
          // rows individually rather than silently hiding runs that genuinely
          // exist. Never show fewer runs than actually exist.
          rowsToRenderIndividually = rowsToRenderIndividually.concat(
            runs.filter(function(r) { return r[gr.field] === gr.id; })
          );
          return;
        }
        groupEntries.push({ startedAt: gr.data.sweep && gr.data.sweep.startedAt, html: gr.render(gr.data) });
      });
      var allEntries = rowsToRenderIndividually.map(function(r) {
        return { startedAt: r.startedAt, html: runRowHtml(r) };
      }).concat(groupEntries).sort(byStartedAtDesc);
      document.getElementById('runs-cnt').textContent = allEntries.length;
      tbody.innerHTML = allEntries.map(function(e) { return e.html; }).join('');
    });
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function openModal(scenarioId, preAgent, lockAgent) {
  state._modalScId = scenarioId;
  if (state.scenarios.length === 0) { showToast('Scenarios not loaded yet', 'err'); return; }
  if (state.agents.length === 0)    { showToast('No agents registered yet', 'err'); return; }
  var scSel = document.getElementById('modal-sc');
  var scWrap = document.getElementById('modal-sc-wrap');
  scSel.innerHTML = state.scenarios.map(function(s) {
    var desc = s.description ? ' — ' + (s.description.length > 90 ? s.description.substring(0, 87) + '...' : s.description) : '';
    return '<option value="' + x(s.id) + '"' + (s.id === scenarioId ? ' selected' : '') + '>' + x(s.name) + x(desc) + '</option>';
  }).join('');
  scWrap.style.display = scenarioId ? 'none' : 'block';
  var sc = scenarioId ? state.scenarios.find(function(s) { return s.id === scenarioId; }) : null;
  if (lockAgent) {
    document.getElementById('modal-title').textContent = 'Safe Scan' + (sc ? ': ' + sc.name : '');
  } else {
    document.getElementById('modal-title').textContent = sc ? 'Run: ' + sc.name : 'Run Scenario';
  }
  document.getElementById('modal-agent').innerHTML = state.agents.map(function(a) {
    var osLabel = '';
    if (a.osVersion) {
      var ov = a.osVersion.toLowerCase();
      osLabel = ov.indexOf('windows') !== -1 ? ' [Win]' : ov.indexOf('darwin') !== -1 || ov.indexOf('macos') !== -1 ? ' [macOS]' : ' [Linux]';
    }
    return '<option value="' + x(a.agentId) + '"' + (a.agentId === preAgent ? ' selected' : '') + '>' +
           x(a.agentId) + ' — ' + x(a.hostname) + osLabel + '</option>';
  }).join('');
  document.getElementById('modal-mode').value = 'posture'; // always default to safe
  document.getElementById('modal-max-privilege').value = ''; // always default to no limit
  state._addlSel = {};
  state._groupSel = {};
  state._targetMode = 'individual';
  var indRadio = document.querySelector('input[name="modal-target-mode"][value="individual"]');
  if (indRadio) indRadio.checked = true;
  document.getElementById('modal-individual-wrap').style.display = 'block';
  document.getElementById('modal-group-wrap').style.display = 'none';
  document.getElementById('modal-all-wrap').style.display = 'none';
  var allLabel = document.getElementById('modal-target-all-label');
  if (allLabel) allLabel.style.display = (ROLE === 'admin') ? 'flex' : 'none';
  renderRunMode();
  document.getElementById('run-overlay').classList.add('open');
  // Wizard: skip Scenario step when scenarioId fixed; skip Target step when agent is
  // locked (safe scan from agent row — endpoint already known). Jump straight to
  // Options after a picker selection so the chosen subset shows in context.
  var pip1 = document.querySelector('[data-pip="1"]');
  if (pip1) pip1.style.display = scenarioId ? 'none' : '';
  var pip2 = document.querySelector('[data-pip="2"]');
  if (pip2) pip2.style.display = lockAgent ? 'none' : '';
  _wzMin = lockAgent ? 3 : (scenarioId ? 2 : 1);
  var effId = scenarioId || document.getElementById('modal-sc').value;
  var start = (state._runSelection && state._runSelection.scId === effId && state._runSelection.ids && state._runSelection.ids.length)
              ? (state._runSelection.locked ? 4 : 3) : _wzMin;
  wizardSet(start);
}

// renderRunMode shows the Posture/Live selector only for executable (hybrid)
// scenarios, and toggles the live-execution warning.
export function renderRunMode() {
  renderModalSelection();
  renderAdditionalAgents();
  if (state._targetMode === 'group') renderGroupTargetSummary();
  if (state._targetMode === 'all') renderAllTargetSummary();
  var id = state._modalScId || document.getElementById('modal-sc').value;
  var sc = state.scenarios.find(function(s) { return s.id === id; });
  var wrap = document.getElementById('modal-mode-wrap');
  var modeSel = document.getElementById('modal-mode');
  var warn = document.getElementById('modal-mode-warn');
  var btn = document.getElementById('modal-run-btn');

  // Group/All targeting: eligibility is evaluated across the whole resolved set,
  // not one primary agent's OS, so it takes a simpler path than the per-agent
  // mismatch check below (which only applies in Individual mode). Agents were
  // already OS-filtered when the set was resolved, so the only remaining
  // question here is whether ANY eligible agent survived that filter.
  if (state._targetMode === 'group' || state._targetMode === 'all') {
    var resolved = state._targetMode === 'group' ? resolvedGroupTargetIds() : resolvedAllTargetIds();
    if (!resolved.eligible.length) {
      wrap.style.display = 'none';
      warn.style.display = 'none';
      btn.disabled = true;
      btn.innerHTML = '&#9888; No Eligible Agents';
      return;
    }
  }

  // OS compatibility check (Individual mode's primary agent only — Group/All
  // targeting has no single "the selected agent", eligibility is handled above).
  var osMismatch = false;
  var osMismatchMsg = '';
  if (state._targetMode === 'individual') {
    var agentId = document.getElementById('modal-agent').value;
    var agent = state.agents.find(function(a) { return a.agentId === agentId; });
    var agentOSClass = '';
    if (agent && agent.osVersion) {
      var ov = agent.osVersion.toLowerCase();
      if (ov.indexOf('windows') !== -1) agentOSClass = 'windows';
      else if (ov.indexOf('darwin') !== -1 || ov.indexOf('macos') !== -1) agentOSClass = 'darwin';
      else agentOSClass = 'linux';
    }
    if (sc && (sc.supportedOs || []).length > 0 && agentOSClass) {
      var supported = (sc.supportedOs || []).some(function(o) { return o.toLowerCase() === agentOSClass; });
      if (!supported) {
        osMismatch = true;
        var targetOS = (sc.supportedOs || []).join(' / ');
        osMismatchMsg = '&#9888; <strong>OS mismatch:</strong> this scenario targets <strong>' + x(targetOS) +
          '</strong> but the selected agent is <strong>' + x(agent.osVersion) + '</strong>. ' +
          'Posture checks will return "not applicable". Live execution will be blocked by the server.';
      }
    }
  }
  btn.disabled = false;

  if (!sc || !sc.executable) {
    wrap.style.display = 'none';
    modeSel.value = 'posture';
    if (osMismatch) {
      warn.style.display = 'block';
      warn.style.border = '1px solid rgba(218,54,51,0.5)';
      warn.style.background = 'rgba(218,54,51,0.08)';
      warn.style.color = '#f85149';
      warn.innerHTML = osMismatchMsg;
    } else {
      warn.style.display = 'none';
    }
    btn.innerHTML = '&#9654; Run';
    return;
  }
  wrap.style.display = 'block';
  var mode = modeSel.value;
  var reasonWrap = document.getElementById('modal-reason-wrap');
  reasonWrap.style.display = (mode === 'posture') ? 'none' : 'block';

  // OS mismatch overrides mode warnings for live modes
  if (osMismatch && (mode === 'telemetry' || mode === 'lab')) {
    warn.style.display = 'block';
    warn.style.border = '1px solid rgba(218,54,51,0.5)';
    warn.style.background = 'rgba(218,54,51,0.08)';
    warn.style.color = '#f85149';
    warn.innerHTML = osMismatchMsg + ' <strong>Cannot run ' + mode + ' mode on this agent.</strong>';
    btn.disabled = true;
    btn.innerHTML = '&#9888; OS Mismatch';
    return;
  }
  btn.disabled = false;

  if (mode === 'telemetry') {
    warn.style.display = 'block';
    warn.style.border = '1px solid rgba(210,153,34,0.5)';
    warn.style.background = 'rgba(210,153,34,0.12)';
    warn.style.color = '#d29922';
    var warnText = '&#9888; <strong>Telemetry mode</strong> runs real, identity-safe techniques (no credential access, cracking, or persistence) and <strong>will generate EDR/SIEM alerts</strong>. Production-safe only under an approved window.';
    if (osMismatch) warnText = osMismatchMsg + '<br>' + warnText;
    warn.innerHTML = warnText;
    btn.innerHTML = '&#9654; Run Telemetry';
  } else if (mode === 'lab') {
    warn.style.display = 'block';
    warn.style.border = '1px solid rgba(218,54,51,0.5)';
    warn.style.background = 'rgba(218,54,51,0.12)';
    warn.style.color = '#f85149';
    warn.innerHTML = '&#9888; <strong>LAB MODE — full-fidelity emulation.</strong> Runs LSASS memory dump and allowlisted password spray. <strong>Isolated AD range only, never production.</strong> Triggers EDR by design; requires a second confirmation.';
    btn.innerHTML = '&#9654; Run LAB';
  } else {
    if (osMismatch) {
      warn.style.display = 'block';
      warn.style.border = '1px solid rgba(218,54,51,0.4)';
      warn.style.background = 'rgba(218,54,51,0.08)';
      warn.style.color = '#f85149';
      warn.innerHTML = osMismatchMsg;
    } else {
      warn.style.display = 'none';
    }
    btn.innerHTML = '&#9654; Run';
  }

  // Show variant depth selector for live ART runs only (posture has no variant value).
  var fw = scenarioFramework(sc);
  var variantWrap = document.getElementById('modal-variant-wrap');
  var showVariant = (mode === 'telemetry' || mode === 'lab') && (fw === 'art');
  if (variantWrap) {
    variantWrap.style.display = showVariant ? 'block' : 'none';
    if (showVariant) updateVariantDepthNote();
  }
}

// additionalAgentIds returns checked, OS-eligible, non-primary agent IDs in
// `agents` array order — this ordering is load-bearing: the review list and
// dispatch order both rely on it matching render order exactly.
export function additionalAgentIds() {
  var primaryId = document.getElementById('modal-agent').value;
  return state.agents.filter(function(a) { return a.agentId !== primaryId && state._addlSel[a.agentId]; })
               .map(function(a) { return a.agentId; });
}

// osEligibleAgents filters `list` down to agents whose OS matches sc.supportedOs
// (case-insensitive). An empty/absent supportedOs means "any OS" — used by every
// agent-targeting path in the Run Scenario wizard (individual, group, all) so OS
// compatibility is defined in exactly one place.
function osEligibleAgents(list, sc) {
  var supported = ((sc && sc.supportedOs) || []).map(function(o) { return o.toLowerCase(); });
  if (!supported.length) return list;
  return list.filter(function(a) { return supported.indexOf(cmpAgentOS(a)) !== -1; });
}

function eligibleAdditionalAgents() {
  var primaryId = document.getElementById('modal-agent').value;
  var scId = state._modalScId || document.getElementById('modal-sc').value;
  var sc = state.scenarios.find(function(s) { return s.id === scId; });
  return osEligibleAgents(state.agents.filter(function(a) { return a.agentId !== primaryId; }), sc);
}

function renderAdditionalAgents() {
  var wrap = document.getElementById('modal-addl-wrap');
  var list = document.getElementById('modal-addl-list');
  if (!wrap || !list) return;
  var eligible = eligibleAdditionalAgents();
  // Prune selections for agents that just became ineligible (scenario or primary
  // agent changed) so additionalAgentIds() never returns a hidden/stale checkbox.
  var eligibleIds = {};
  eligible.forEach(function(a) { eligibleIds[a.agentId] = true; });
  Object.keys(state._addlSel).forEach(function(k) { if (!eligibleIds[k]) delete state._addlSel[k]; });
  if (!eligible.length) { wrap.style.display = 'none'; return; }
  wrap.style.display = 'block';
  list.innerHTML = eligible.map(function(a) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox" ' + (state._addlSel[a.agentId] ? 'checked' : '') +
      ' onchange="_addlSel[\'' + x(a.agentId) + '\']=this.checked;renderAdditionalAgentsCount()">' +
      '<code style="font-size:0.72rem">' + x(a.agentId) + '</code><span class="tiny muted">' + x(a.hostname) + ' · ' + cmpAgentOS(a) + '</span></label>';
  }).join('');
  renderAdditionalAgentsCount();
}

export function renderAdditionalAgentsCount() {
  var n = additionalAgentIds().length;
  var el = document.getElementById('modal-addl-cnt');
  if (el) el.textContent = '(' + n + ' selected)';
}

export function selectAllAdditionalAgents() {
  eligibleAdditionalAgents().forEach(function(a) { state._addlSel[a.agentId] = true; });
  renderAdditionalAgents();
}

// setTargetMode switches which Target-step sub-panel is visible and clears the
// OTHER modes' selection state so a stale pick from a previous mode can never
// silently leak into a dispatch (e.g. switching from Group back to Individual
// must not leave old group checkboxes still "selected" underneath).
export function setTargetMode(mode) {
  state._targetMode = mode;
  if (mode !== 'group') state._groupSel = {};
  if (mode !== 'individual') state._addlSel = {};
  document.getElementById('modal-individual-wrap').style.display = mode === 'individual' ? 'block' : 'none';
  document.getElementById('modal-group-wrap').style.display = mode === 'group' ? 'block' : 'none';
  document.getElementById('modal-all-wrap').style.display = mode === 'all' ? 'block' : 'none';
  if (mode === 'group') renderGroupTargetList();
  renderRunMode();
}

// resolvedGroupTargetIds/resolvedAllTargetIds both return {eligible, total} so
// callers can show "X of Y eligible" without a second pass over the data.
export function resolvedGroupTargetIds() {
  var scId = state._modalScId || document.getElementById('modal-sc').value;
  var sc = state.scenarios.find(function(s) { return s.id === scId; });
  var selectedGroupIds = Object.keys(state._groupSel).filter(function(k) { return state._groupSel[k]; }).map(Number);
  var candidates = resolveGroupTargetAgents(selectedGroupIds);
  return { eligible: osEligibleAgents(candidates, sc), total: candidates.length };
}

export function resolvedAllTargetIds() {
  var scId = state._modalScId || document.getElementById('modal-sc').value;
  var sc = state.scenarios.find(function(s) { return s.id === scId; });
  return { eligible: osEligibleAgents(state.agents, sc), total: state.agents.length };
}

// renderGroupTargetList renders the checkbox list of every group, flattened by
// gpFlattenGroups (same helper the Move-to-Group picker uses), each row also
// showing that group's own totalAgentCount as a quick-glance hint before any
// OS filtering is applied.
function renderGroupTargetList() {
  renderGroupCheckboxList('modal-group-list', 'sub2', '_groupSel', 'renderGroupTargetSummary', ['renderRunMode']);
}

// renderGroupTargetSummary/renderAllTargetSummary only update their own summary
// text -- they do NOT call renderRunMode() themselves. renderRunMode() is the
// single top-level orchestrator that calls these (see renderRunMode below): if
// these called renderRunMode() too, a checkbox's onchange -> renderRunMode() ->
// (mode === 'group') -> renderGroupTargetSummary() -> renderRunMode() chain
// would recurse forever. renderGroupTargetList() (which runs once per mode
// switch, not per render) is the one place that calls renderGroupTargetSummary()
// directly for its initial paint, and that call site does not sit inside
// renderRunMode().
export function renderGroupTargetSummary() {
  var el = document.getElementById('modal-group-summary');
  if (!el) return;
  var r = resolvedGroupTargetIds();
  if (r.total === 0) { el.textContent = 'No groups selected.'; return; }
  var skipped = r.total - r.eligible.length;
  el.textContent = r.eligible.length + ' of ' + r.total + ' group agent(s) eligible' +
    (skipped ? ' (' + skipped + ' skipped: OS mismatch)' : '') + '.';
}

function renderAllTargetSummary() {
  var el = document.getElementById('modal-all-summary');
  if (!el) return;
  var r = resolvedAllTargetIds();
  var skipped = r.total - r.eligible.length;
  el.textContent = r.eligible.length + ' of ' + r.total + ' agent(s) eligible' +
    (skipped ? ' (' + skipped + ' skipped: OS mismatch)' : '') + '.';
}

// updateVariantDepthNote updates the helper text below the variant depth selector
// showing the estimated total steps so operators don't accidentally queue 3300 runs.
export function updateVariantDepthNote() {
  var noteEl = document.getElementById('modal-variant-note');
  if (!noteEl) return;
  var sel = document.getElementById('modal-variant-depth');
  var depth = sel ? sel.value : 'none';
  var scId = state._modalScId || document.getElementById('modal-sc').value;
  var sc = state.scenarios.find(function(s) { return s.id === scId; });
  // Full-sweep-style scenarios (Full Sweep and its Selective siblings, when
  // left uncustomized) dispatch against the entire technique catalog --
  // hundreds of techniques, always well over the warning threshold below.
  // No exact count is needed (and none was reliably available here even
  // before this fix -- the old '3,467' was a stale snapshot, and being a
  // string it silently never triggered the typeof === 'number' check that
  // was supposed to color this warning red).
  var isFullSweepFlag = sc && (sc.artAllWindows || sc.artAllPlatform || sc.artSelectiveWindows || sc.artSelectivePlatform);
  var baseSteps = sc ? ((sc.artTechniques || []).length || (isFullSweepFlag ? Infinity : 0)) : '?';
  var mult = { none: '1', quick: '~5', standard: '~15', full: '33' }[depth] || '1';
  var notes = {
    none: 'One test per step — base command only. Fast, low noise.',
    quick: '~5 tests per PS step: base64 / charcode encoding + admin privilege + WMI proxy (T1047). Best for a first pass.',
    standard: '~15 tests per PS step. Covers all dimensions and key cross-products. Recommended for detection-gap validation.',
    full: 'Every valid variant (33 per PS step, 11 per CMD step). Use on a single technique or small step subset — not a 100-step scenario.'
  };
  noteEl.textContent = mult + ' tests per step. ' + (notes[depth] || '');
  if (depth === 'full' && baseSteps !== '?') {
    noteEl.style.color = typeof baseSteps === 'number' && baseSteps > 50 ? 'var(--danger)' : 'var(--muted)';
  } else {
    noteEl.style.color = 'var(--muted)';
  }
}

export function closeModal() {
  document.getElementById('run-overlay').classList.remove('open');
  state._modalScId = null; state._runSelection = null;
  // Restore pip visibility so next open() always starts clean
  var p2 = document.querySelector('[data-pip="2"]');
  if (p2) p2.style.display = '';
  var p1 = document.querySelector('[data-pip="1"]');
  if (p1) p1.style.display = '';
}

/* ── Run wizard navigation ─────────────────────────────────────────────────
   Pure presentational layer over the existing run-modal controls — every element
   ID and the renderRunMode / renderModalSelection / confirmRun logic is unchanged.
   Steps: 1 Scenario · 2 Target · 3 Options (customize + mode) · 4 Review. */
var _wzStep = 1, _wzMin = 1;
function wizardSet(step) {
  if (step < _wzMin) step = _wzMin;
  if (step > 4) step = 4;
  _wzStep = step;
  [1, 2, 3, 4].forEach(function(n) {
    var pane = document.querySelector('[data-pane="' + n + '"]');
    if (pane) pane.style.display = (n === step) ? 'block' : 'none';
    var pip = document.querySelector('[data-pip="' + n + '"]');
    if (pip) { pip.classList.toggle('active', n === step); pip.classList.toggle('done', n < step); }
  });
  document.getElementById('wz-back').style.display = (step > _wzMin) ? '' : 'none';
  document.getElementById('wz-next').style.display = (step < 4) ? '' : 'none';
  document.getElementById('modal-run-btn').style.display = (step === 4) ? '' : 'none';
  if (step === 3) {
    renderRunMode();
    var mw = document.getElementById('modal-mode-wrap');
    document.getElementById('wz-mode-note').style.display = (mw.style.display === 'none') ? 'block' : 'none';
  }
  if (step === 4) renderWizardReview();
}
export function wizardNav(dir) { wizardSet(_wzStep + dir); }
function renderWizardReview() {
  renderRunMode(); // refresh the OS-mismatch / mode warning + Run button state
  var scId = state._modalScId || document.getElementById('modal-sc').value;
  var sc = state.scenarios.find(function(s) { return s.id === scId; });
  var agSel = document.getElementById('modal-agent');
  var agTxt = (agSel.options[agSel.selectedIndex] || {}).text || agSel.value;
  var modeWrap = document.getElementById('modal-mode-wrap');
  var mode = (modeWrap.style.display !== 'none') ? document.getElementById('modal-mode').value : 'posture';
  var modeLabel = { posture: 'Posture — read-only', telemetry: 'Telemetry — identity-safe', lab: 'Lab — full-fidelity' }[mode] || mode;
  var fw = scenarioFramework(sc);
  var noun = (fw === 'art') ? 'techniques' : (fw === 'caldera') ? 'abilities' : (fw === 'posture') ? 'checks' : 'steps';
  var sel = state._runSelection && state._runSelection.scId === scId && state._runSelection.ids.length;
  var subset = sel
    ? ((state._runSelection.locked && state._runSelection.ids.length === 1)
        ? state._runSelection.ids[0] + ' (targeted re-validate)'
        : state._runSelection.ids.length + ' ' + noun + ' (subset)')
    : 'All ' + noun;
  var reasonEl = document.getElementById('modal-reason');
  var reason = (mode !== 'posture' && reasonEl && reasonEl.value.trim()) ? reasonEl.value.trim() : '';
  var row = function(k, v) { return '<div class="wz-rev-row"><span>' + k + '</span><span>' + v + '</span></div>'; };
  var variantDepthEl2 = document.getElementById('modal-variant-depth');
  var variantWrap2 = document.getElementById('modal-variant-wrap');
  var variantLabel = '';
  if (variantDepthEl2 && variantWrap2 && variantWrap2.style.display !== 'none') {
    var vd = variantDepthEl2.value || 'none';
    variantLabel = { none: 'None (base only)', quick: 'Quick (~5 per PS step)', standard: 'Standard (~15 per PS step)', full: 'Full (33 per PS step)' }[vd] || vd;
  }
  var maxPrivEl = document.getElementById('modal-max-privilege');
  var maxPrivLabel = maxPrivEl && maxPrivEl.value ?
    { user: 'User (skips admin/system steps)', admin: 'Admin (skips system steps)' }[maxPrivEl.value] || maxPrivEl.value : '';
  // Group/All targeting resolves to a completely different agent set than the
  // Individual-mode primary-agent dropdown (modal-agent) -- reading agSel/
  // additionalAgentIds() unconditionally here (as this used to) shows a stale
  // single-agent line left over from before Group/All targeting existed, even
  // though confirmRun() dispatches to the correct resolved set. Mirror
  // confirmRun()'s own _targetMode branch so Review shows what will actually
  // run, not what the (hidden, in this mode) Individual-mode dropdown holds.
  var addlIds = additionalAgentIds();
  var agentsRow, blastRow = '', offlineWarnRow = '';
  // Dispatch succeeds server-side (a runId comes back, the modal shows
  // "Dispatched") even when the target agent is offline -- the run then
  // fails moments later on delivery, previously with no visible reason at
  // all (see Live Runs failReason fix). Warning here, before the operator
  // clicks Run, catches the common case up front instead of only after the
  // fact. This is advisory, not a hard block -- the agent can reconnect
  // between Review and the actual dispatch, and a stale status shouldn't
  // prevent a legitimate run.
  var offlineNames = [];
  if (state._targetMode !== 'group' && state._targetMode !== 'all') {
    [agSel.value].concat(addlIds).forEach(function(id) {
      var a = state.agents.find(function(ag) { return ag.agentId === id; });
      if (a && agentBucket(a) === 'offline') offlineNames.push(x(a.hostname || a.agentId));
    });
  }
  if (offlineNames.length) {
    offlineWarnRow = '<div class="wz-rev-warn">&#9888; Currently offline: ' + offlineNames.join(', ') +
      '. The run will likely fail to reach ' + (offlineNames.length > 1 ? 'these agents' : 'this agent') + '.</div>';
  }
  if (state._targetMode === 'group' || state._targetMode === 'all') {
    var resolved = state._targetMode === 'group' ? resolvedGroupTargetIds() : resolvedAllTargetIds();
    var eligible = resolved.eligible;
    var groupCount = state._targetMode === 'group'
      ? Object.keys(state._groupSel).filter(function(k) { return state._groupSel[k]; }).length : 0;
    var names2 = eligible.map(function(a) { return x(a.agentId + ' — ' + a.hostname); });
    agentsRow = '<div class="wz-rev-row"><span>Agents (' + eligible.length + ')</span><span>' +
      (names2.length ? names2.join('<br>') : '<span class="muted">No eligible agents</span>') + '</span></div>';
    var blastMsg = state._targetMode === 'all'
      ? 'This will run on all ' + eligible.length + ' eligible agent(s).'
      : 'This will run on ' + eligible.length + ' agent(s) across ' + groupCount + ' group(s).';
    blastRow = '<div class="wz-rev-warn">' + x(blastMsg) + '</div>';
  } else if (addlIds.length) {
    var allIds = [agSel.value].concat(addlIds);
    var names = allIds.map(function(id) {
      var a = state.agents.find(function(ag) { return ag.agentId === id; });
      return x(a ? (a.agentId + ' — ' + a.hostname) : id);
    });
    agentsRow = '<div class="wz-rev-row"><span>Agents (' + allIds.length + ')</span><span>' + names.join('<br>') + '</span></div>';
  } else {
    agentsRow = row('Target agent', x(agTxt));
  }
  var html = row('Scenario', x(sc ? sc.name : scId)) +
             agentsRow +
             blastRow +
             offlineWarnRow +
             row('Mode', x(modeLabel)) +
             row('Scope', x(subset)) +
             (variantLabel ? row('Variant depth', x(variantLabel)) : '') +
             (maxPrivLabel ? row('Max privilege', x(maxPrivLabel)) : '') +
             (reason ? row('Reason', x(reason)) : '');
  var warnEl = document.getElementById('modal-mode-warn');
  if (warnEl.style.display !== 'none' && warnEl.innerHTML.trim()) {
    html += '<div class="wz-rev-warn">' + warnEl.innerHTML + '</div>';
  }
  if (fw === 'posture' && sel && addlIds.length) {
    html += '<div class="wz-rev-warn">This check subset was built from ' + x(agTxt) +
      '\'s catalog — any check not present on other selected agents will report not applicable.</div>';
  }
  document.getElementById('wz-review').innerHTML = html;
}

/* ── Technique / Ability Picker ────────────────────────────── */
// scenarioFramework returns 'art' | 'caldera' | 'steps' | 'posture' | '' for a scenario object.
export function scenarioFramework(sc) {
  if (!sc) return '';
  if (sc.localCheck) return 'posture';
  if (sc.artAllWindows || sc.artAllPlatform || sc.artSelectiveWindows || sc.artSelectivePlatform || (sc.artTechniques || []).length) return 'art';
  if (sc.calderaAllWindows || (sc.calderaAbilities || []).length) return 'caldera';
  if ((sc.steps || []).length) return 'steps';
  return '';
}

var _pickerScId = null, _pickerFw = '', _pickerItems = [], _pickerSel = {}, _pickerFiltered = [];
// _pickerReadOnly: true only for the "Detailed view" opened via
// openDetailedView (art_all_windows scenarios, which run every atomic and
// so have no selectable subset) -- suppresses checkboxes, Select all/None,
// and the Apply footer, leaving only search/browse.
var _pickerReadOnly = false;
// Caldera picker filter state
var _pf = { plugin: 'all', payload: 'all', admin: 'all', platform: 'all', tactic: 'all' };

export function openPicker(scId, fw) {
  var sc = state.scenarios.find(function(s) { return s.id === scId; });
  if (!sc) { showToast('Scenario not found', 'err'); return; }
  fw = fw || scenarioFramework(sc);
  if (!fw) { showToast('This scenario has no selectable items', 'err'); return; }
  // Step-based scenarios carry their full step list in the loaded scenario
  // object (parsed from the YAML) — no server catalog needed. Build the picker
  // items straight from sc.steps, indexed by position so the run request can map
  // each selection back to its step.
  if (fw === 'steps') {
    var items = (sc.steps || []).map(function(st, i) {
      return { id: String(i), name: st.name || ('Step ' + (i + 1)), technique: st.techniqueId || '', tactic: '' };
    });
    if (!items.length) { showToast('This scenario has no steps', 'err'); return; }
    openPickerWith(scId, fw, sc, items);
    return;
  }
  if (fw === 'posture') {
    var agentId = document.getElementById('modal-agent').value;
    if (!agentId) { showToast('Select a target agent first', 'err'); return; }
    var url = '/api/posture/catalog?agentId=' + encodeURIComponent(agentId) +
              '&scenario=' + encodeURIComponent(scId);
    apicall(url).then(function(d) {
      if (!Array.isArray(d)) { showToast((d && d.error) ? d.error : 'Posture catalog unavailable', 'err'); return; }
      if (!d.length) { showToast('This agent reported no posture checks for this scenario (it may need to re-enroll)', 'err'); return; }
      openPickerWith(scId, 'posture', sc, d);
    }).catch(function(e) { showToast('Posture catalog request failed: ' + (e && e.message ? e.message : e), 'err'); });
    return;
  }
  // Any scenario whose supportedOs names only non-Windows platforms (the
  // art_selective_platform/art_all_platform sweeps, but also curated
  // Linux/macOS scenarios with their own sc.artTechniques list) needs its
  // own platform's catalog, not the Windows-only one 'art' scenarios use by
  // default -- GetARTTechniques defaults to windows, so only override when
  // Windows genuinely isn't one of the scenario's supported platforms.
  // Without this, a curated Linux/macOS scenario's Customize picker showed
  // Windows-only atomic tests (e.g. "findstr") scoped by technique ID from
  // the wrong catalog, inflating the displayed test count above what the
  // run actually executes.
  var nonWindowsOnly = (sc.supportedOs || []).length > 0 &&
    sc.supportedOs.every(function(p) { return String(p).toLowerCase() !== 'windows'; });
  var artPlatform = (sc.artSelectivePlatform || nonWindowsOnly)
    ? ((sc.supportedOs && sc.supportedOs[0]) || 'windows')
    : 'windows';
  var artCache = (artPlatform === 'windows') ? state.artCatalog : (_artCatalogByPlatform[artPlatform] || []);
  var have = (fw === 'art') ? scopeArtItems(sc, artCache) : state.calderaCatalog;
  if (have.length) { openPickerWith(scId, fw, sc, have); return; }
  // Catalog not loaded (or a prior fetch failed silently) — fetch on demand and
  // surface the actual reason instead of a generic "unavailable" message.
  var url = (fw === 'art')
    ? ('/api/art/techniques' + (artPlatform !== 'windows' ? '?platform=' + encodeURIComponent(artPlatform) : ''))
    : '/api/caldera/abilities';
  apicall(url).then(function(d) {
    if (!Array.isArray(d)) {
      showToast((d && d.error) ? d.error : 'Catalog unavailable', 'err');
      return;
    }
    if (fw === 'art') {
      if (artPlatform === 'windows') state.artCatalog = d; else _artCatalogByPlatform[artPlatform] = d;
    } else state.calderaCatalog = d;
    if (state.scenarios.length) renderScenarios();
    var items = (fw === 'art') ? scopeArtItems(sc, d) : d;
    if (!items.length) {
      showToast(fw === 'art' ? 'ART catalog is empty — reseed ART content' : 'Caldera returned no abilities', 'err');
      return;
    }
    openPickerWith(scId, fw, sc, items);
  }).catch(function(e) {
    showToast('Catalog request failed: ' + (e && e.message ? e.message : e), 'err');
  });
}

// scopeArtItems narrows the full ART catalog down to a scenario's own
// curated technique list, when it has one. Only a blanket art_all_windows
// sweep scenario is meant to expose the entire catalog in Customize -- a
// scenario with its own sc.artTechniques (e.g. threat-intel-generated from
// a real actor's ATT&CK profile) should only ever offer what it actually
// curated, matching what its preview card already promised. Without this,
// every ART-framework scenario's Customize picker showed the identical
// full catalog regardless of which scenario was opened.
function scopeArtItems(sc, items) {
  if (sc.artAllWindows || sc.artAllPlatform || sc.artSelectiveWindows || sc.artSelectivePlatform || !(sc.artTechniques || []).length) return items;
  var wanted = {};
  sc.artTechniques.forEach(function(t) { wanted[String(t).toUpperCase()] = true; });
  return items.filter(function(item) { return item.id && wanted[item.id.toUpperCase()]; });
}

function openPickerWith(scId, fw, sc, items) {
  // Always reset read-only state here -- the only entry point into
  // read-only mode is openDetailedView, which sets _pickerReadOnly itself
  // right after calling this. Any other picker open (the normal selectable
  // flow) must never inherit read-only from a previous Detailed-view visit.
  _pickerReadOnly = false;
  var selAllWrap = document.getElementById('picker-selectall-wrap');
  if (selAllWrap) selAllWrap.style.display = '';
  var applyBtn = document.getElementById('picker-apply');
  if (applyBtn) applyBtn.style.display = '';
  var cancelBtn = document.getElementById('picker-cancel-btn');
  if (cancelBtn) cancelBtn.textContent = 'Cancel';
  _pickerItems = items;
  _pickerScId = scId; _pickerFw = fw; _pickerSel = {};
  // Pre-check ONLY a genuine pending selection the operator already made in
  // this session for this exact scenario+framework. A freshly-opened picker
  // starts with nothing checked -- the scenario's own curated list (if any)
  // is what the run falls back to server-side when nothing is customized;
  // the picker pre-ticking it (or everything) on open is surprising, not
  // helpful. IDs are kept exactly as selected -- Caldera ability ids are
  // lowercase UUIDs matched case-sensitively against the catalog, so
  // uppercasing them here (as this used to do, uniformly for every
  // framework) silently broke the match: the count included them but no
  // checkbox ever showed checked, and neither "None" nor "Select all"
  // could ever fully agree with the real total again.
  if (state._runSelection && state._runSelection.scId === scId && state._runSelection.fw === fw) {
    state._runSelection.ids.forEach(function(id) { _pickerSel[id] = true; });
  }
  var titleNoun = fw === 'art' ? 'Select ART techniques'
                : fw === 'caldera' ? 'Select Caldera abilities'
                : fw === 'posture' ? 'Select posture checks'
                : 'Select steps';
  document.getElementById('picker-title').textContent = titleNoun + ' — ' + sc.name;
  document.getElementById('picker-sub').textContent =
      fw === 'art'     ? 'Tick the ATT&CK techniques to run. Search by ID or atomic name.'
    : fw === 'caldera' ? 'Tick the Caldera abilities to run. Search by name, tactic, or technique.'
    : fw === 'posture' ? 'Tick the posture checks to run. Search by name, technique, or phase.'
    :                    'Tick the steps to run. Steps run in the order shown. Search by name or technique.';
  document.getElementById('picker-search').value = '';
  // Show / hide metadata filters and populate tactic dropdown for Caldera.
  var filtersEl = document.getElementById('picker-caldera-filters');
  if (filtersEl) filtersEl.style.display = fw === 'caldera' ? '' : 'none';
  if (fw === 'caldera') {
    // Reset all filter chips to 'all'.
    _pf = { plugin: 'all', payload: 'all', admin: 'all', platform: 'all', tactic: 'all' };
    document.querySelectorAll('.pfbtn').forEach(function(b) {
      b.classList.toggle('active', b.getAttribute('data-val') === 'all');
    });
    // Populate tactic dropdown from the items list.
    var tacticSel = document.getElementById('picker-tactic-sel');
    if (tacticSel) {
      var tacticSet = {};
      items.forEach(function(it) { if (it.tactic) tacticSet[it.tactic] = true; });
      var tacticOpts = Object.keys(tacticSet).sort().map(function(t) {
        return '<option value="' + x(t) + '">' + x(t) + '</option>';
      }).join('');
      tacticSel.innerHTML = '<option value="all">All tactics</option>' + tacticOpts;
      tacticSel.value = 'all';
    }
  }
  ensureCovStatus(renderPickerList);
  document.getElementById('picker-overlay').classList.add('open');
}

// setPF updates one Caldera picker filter dimension and refreshes the list.
export function setPF(dim, val) {
  _pf[dim] = val;
  // Toggle active class on buttons for this dimension.
  document.querySelectorAll('.pfbtn[data-pf="' + dim + '"]').forEach(function(b) {
    b.classList.toggle('active', b.getAttribute('data-val') === val);
  });
  renderPickerList();
}

export function openPickerFromModal() {
  openPicker(state._modalScId || document.getElementById('modal-sc').value);
}

// openDetailedViewForScenario opens the read-only "Detailed view" for an
// art_all_windows/art_all_platform Full Sweep scenario -- every atomic
// test that will actually run for its target platform, browsable but not
// selectable, since these scenarios always run everything and have no
// subset to choose from. Shared by the Run modal's Customize replacement
// (openDetailedViewFromModal) and the scenario tile's own hover-detail
// Customize replacement (scenarioDetailHTML).
export function openDetailedViewForScenario(scId) {
  var sc = state.scenarios.find(function(s) { return s.id === scId; });
  if (!sc) return;
  // Each art_all_windows/art_all_platform scenario targets exactly one
  // platform (supportedOs is single-element for these) -- fetch that
  // platform's atomics, not always "windows", so the Linux/macOS sweeps
  // show their own real atomic list instead of the Windows one.
  var platform = (sc.supportedOs && sc.supportedOs[0]) || 'windows';
  apicall('/api/art/atomics?platform=' + encodeURIComponent(platform)).then(function(atoms) {
    if (!atoms || !atoms.length) {
      showToast('ART catalog is empty — reseed ART content', 'err');
      return;
    }
    var items = atoms.map(function(a, i) {
      return { id: a.techniqueId + '#' + i, techniqueId: a.techniqueId, name: a.name, executor: a.executor };
    });
    openDetailedView(sc, items);
  }).catch(function(e) {
    showToast('Catalog request failed: ' + (e && e.message ? e.message : e), 'err');
  });
}

function openDetailedViewFromModal() {
  openDetailedViewForScenario(state._modalScId || document.getElementById('modal-sc').value);
}

function openDetailedView(sc, items) {
  _pickerItems = items;
  _pickerScId = sc.id; _pickerFw = 'art-atomics'; _pickerSel = {};
  _pickerReadOnly = true;
  var platform = (sc.supportedOs && sc.supportedOs[0]) || 'windows';
  var platformLabel = platform === 'darwin' ? 'macOS' : platform.charAt(0).toUpperCase() + platform.slice(1);
  document.getElementById('picker-title').textContent = 'Every atomic test — ' + sc.name;
  document.getElementById('picker-sub').textContent =
    items.length + ' atomic test' + (items.length === 1 ? '' : 's') + ' across every ' + platformLabel + '-runnable technique will run. Search by technique ID or atomic name — this list is not selectable.';
  document.getElementById('picker-search').value = '';
  var filtersEl = document.getElementById('picker-caldera-filters');
  if (filtersEl) filtersEl.style.display = 'none';
  var selAllWrap = document.getElementById('picker-selectall-wrap');
  if (selAllWrap) selAllWrap.style.display = 'none';
  var applyBtn = document.getElementById('picker-apply');
  if (applyBtn) applyBtn.style.display = 'none';
  var cancelBtn = document.getElementById('picker-cancel-btn');
  if (cancelBtn) cancelBtn.textContent = 'Close';
  renderPickerList();
  document.getElementById('picker-overlay').classList.add('open');
}

// ensureCovStatus populates window._covSt (technique→last-verdict) once, so the
// picker can show coverage badges even if the Coverage tab was never opened.
function ensureCovStatus(cb) {
  if (window._covSt) { cb(); return; }
  apicall('/api/scenarios/runs').then(function(runs) {
    window._covSt = covStatusMap(runs || []);
  }).catch(function() {
    window._covSt = window._covSt || {};
  }).then(cb, cb);
}
// pickerTechId resolves the ATT&CK technique id for a picker item per framework.
function pickerTechId(it, fw) {
  if (fw === 'art') return it.id;
  if (fw === 'caldera' || fw === 'steps') return it.technique || it.techniqueId || '';
  return '';
}
// covBadge renders this technique's last validated result (none for untested).
function covBadge(techId) {
  if (!techId) return '';
  var m = { cov: ['Prevented', 'var(--success)'], part: ['Detected', 'var(--warning)'], gap: ['Missed', 'var(--danger)'] }[(window._covSt || {})[techId]];
  if (!m) return '';
  return ' <span class="sbadge" style="background:transparent;border:1px solid ' + m[1] + ';color:' + m[1] + ';font-size:0.55rem;padding:1px 5px">' + m[0] + '</span>';
}

export function renderPickerList() {
  var q = (document.getElementById('picker-search').value || '').trim().toLowerCase();
  var fw = _pickerFw;
  // Read tactic dropdown value (can't store in _pf because it changes independently).
  var tacticSel = document.getElementById('picker-tactic-sel');
  var pfTactic = (fw === 'caldera' && tacticSel) ? (tacticSel.value || 'all') : 'all';
  _pickerFiltered = _pickerItems.filter(function(it) {
    if (q && (it.id + ' ' + (it.name || '') + ' ' + (it.tactic || '') + ' ' + (it.technique || '') + ' ' + (it.phase || '') + ' ' + (it.techniqueId || '')).toLowerCase().indexOf(q) === -1) return false;
    if (fw === 'caldera') {
      if (_pf.plugin   !== 'all' && (it.plugin || '') !== _pf.plugin) return false;
      if (pfTactic     !== 'all' && (it.tactic || '') !== pfTactic)   return false;
      if (_pf.platform !== 'all' && !(it.platforms || []).some(function(p) { return p === _pf.platform; })) return false;
      if (_pf.payload  === 'yes' && !it.requiresPayload)  return false;
      if (_pf.payload  === 'no'  && it.requiresPayload)   return false;
      if (_pf.admin    === 'yes' && !it.requiresAdmin)    return false;
      if (_pf.admin    === 'no'  && it.requiresAdmin)     return false;
    }
    return true;
  });
  var rows = _pickerFiltered.map(function(it) {
    var checked = _pickerSel[it.id] ? ' checked' : '';
    // Steps are index-keyed (id = "0","1",…), so show a 1-based step number as
    // the prominent label and the technique ID as meta, not the raw index.
    var label = (fw === 'steps') ? ('Step ' + (Number(it.id) + 1))
              : (fw === 'posture') ? (it.techniqueId || it.name || it.id)
              : (fw === 'art-atomics') ? it.techniqueId
              : it.id;
    var meta = (fw === 'art')
      ? (it.tests ? (it.tests + (it.tests === 1 ? ' test' : ' tests')) : '')
      : (fw === 'art-atomics')
      ? (it.executor || '')
      : (fw === 'steps')
      ? (it.technique || '')
      : (fw === 'posture')
      ? [it.phase, it.severity].filter(Boolean).join(' · ')
      : [it.tactic, it.technique].filter(Boolean).join(' · ');
    var cbadge = covBadge(pickerTechId(it, fw));
    // Extra metadata badges for Caldera abilities.
    var extraBadges = '';
    if (fw === 'caldera') {
      if (it.plugin) extraBadges += ' <span style="font-size:0.65rem;padding:1px 5px;border-radius:7px;background:var(--elevated);border:1px solid var(--border);color:var(--muted)">' + x(it.plugin) + '</span>';
      if ((it.platforms || []).length) extraBadges += ' <span style="font-size:0.65rem;padding:1px 5px;border-radius:7px;background:var(--elevated);border:1px solid var(--border);color:var(--muted)">' + x(it.platforms.join('/')) + '</span>';
      if (it.requiresPayload) extraBadges += ' <span style="font-size:0.65rem;padding:1px 5px;border-radius:7px;background:rgba(218,54,51,0.12);border:1px solid rgba(218,54,51,0.3);color:#da3633">payload</span>';
      if (it.requiresAdmin)   extraBadges += ' <span style="font-size:0.65rem;padding:1px 5px;border-radius:7px;background:rgba(240,136,62,0.12);border:1px solid rgba(240,136,62,0.3);color:#f0883e">admin</span>';
    }
    var checkbox = _pickerReadOnly ? '' :
      '<input type="checkbox" data-id="' + x(it.id) + '"' + checked + ' onchange="pickerToggle(this)" style="margin-top:2px">';
    return '<label style="display:flex;align-items:flex-start;gap:0.55rem;padding:0.4rem 0.5rem;border-bottom:1px solid var(--border);' +
      (_pickerReadOnly ? '' : 'cursor:pointer;') + 'font-size:0.8rem">' +
      checkbox +
      '<span class="u-flex1">' +
        '<span style="font-weight:600;color:var(--accent)">' + x(label) + '</span>' +
        (it.name ? ' <span>' + x(it.name) + '</span>' : '') + cbadge + extraBadges +
        (meta ? '<br><span class="card-meta">' + x(meta) + '</span>' : '') +
      '</span></label>';
  }).join('');
  document.getElementById('picker-list').innerHTML = rows || '<p class="empty" style="padding:1rem">No matches.</p>';
  updatePickerCount();
}

export function pickerToggle(el) {
  var id = el.getAttribute('data-id');
  if (el.checked) _pickerSel[id] = true; else delete _pickerSel[id];
  updatePickerCount();
}

export function pickerSelectAll(on) {
  if (on) {
    // Scoped to the currently filtered/visible items -- lets an operator
    // narrow with the search/filter chips and bulk-check just that subset.
    _pickerFiltered.forEach(function(it) { _pickerSel[it.id] = true; });
  } else {
    // "None" is an unambiguous global reset, not "deselect what's currently
    // visible" -- clear every selection regardless of any active filter, so
    // the count always actually drops to 0.
    _pickerSel = {};
  }
  renderPickerList();
}

function pickerSelectedIds() { return Object.keys(_pickerSel); }

function updatePickerCount() {
  var total = _pickerItems.length;
  var shown = _pickerFiltered.length;
  if (_pickerReadOnly) {
    document.getElementById('picker-count').textContent =
      total + ' atomic test' + (total === 1 ? '' : 's') + (shown !== total ? ' · ' + shown + ' shown' : '');
    return;
  }
  var selectedIds = pickerSelectedIds();
  var n = selectedIds.length;
  var txt = n + ' of ' + total + ' selected';
  if (shown !== total) txt += ' · ' + shown + ' shown';
  // "N selected" counts techniques, but each technique expands to a
  // different number of underlying tests (it.tests, shown per-row -- see
  // the item caption above) -- surface the real execution volume, not
  // just how many technique checkboxes are ticked. Only ART items carry
  // .tests (Caldera abilities/adversaries don't), so this silently adds
  // nothing when it's not applicable rather than showing a misleading 0.
  var totalTests = 0, anyHasTests = false;
  selectedIds.forEach(function(id) {
    var it = _pickerItems.find(function(item) { return item.id === id; });
    if (it && it.tests) { anyHasTests = true; totalTests += it.tests; }
  });
  if (anyHasTests) txt += ' · ' + totalTests + ' test' + (totalTests === 1 ? '' : 's');
  document.getElementById('picker-count').textContent = txt;
  var btn = document.getElementById('picker-apply');
  btn.disabled = (n === 0);
  btn.textContent = '▶ Use selection (' + n + ')';
}

export function applyPicker() {
  var ids = pickerSelectedIds();
  if (!ids.length) { showToast('Select at least one item', 'err'); return; }
  if (_pickerBuilderMode) {
    _pickerBuilderMode = false;
    var targetId = (_pickerFw === 'caldera') ? 'bld-caldera-list' : 'bld-art-list';
    document.getElementById(targetId).value = ids.join('\n');
    closePicker();
    return;
  }
  // Preserve the agent chosen in the Run modal. For posture the catalog (and its
  // check IDs) is per-agent/per-OS, so reopening the modal must NOT reset to the
  // first agent — otherwise the selection would dispatch to the wrong endpoint.
  var agEl = document.getElementById('modal-agent');
  var ag = agEl ? agEl.value : '';
  state._runSelection = { scId: _pickerScId, fw: _pickerFw, ids: ids, agentId: ag };
  closePicker();
  openModal(_pickerScId, ag || null);
}

export function closePicker() { _pickerBuilderMode = false; document.getElementById('picker-overlay').classList.remove('open'); }

export function clearSelection() { state._runSelection = null; renderModalSelection(); }

// _postureSummaryCache holds the rendered "N checks across M categories" HTML
// per scId|agentId, so re-renders (agent/mode changes) don't refetch. Values:
// undefined = never fetched, 'pending' = fetch in flight, '' = fetched but
// empty (hide the note), non-empty string = ready to show.
var _postureSummaryCache = {};

// renderModalSelection shows the Customize link + a note of the chosen subset
// inside the Run modal, reflecting the current scenario and pending selection.
function renderModalSelection() {
  var cw = document.getElementById('modal-customize-wrap');
  var note = document.getElementById('modal-selection');
  var link = document.getElementById('modal-customize-link');
  if (!cw || !note || !link) return;
  var id = state._modalScId || document.getElementById('modal-sc').value;
  var sc = state.scenarios.find(function(s) { return s.id === id; });
  var fw = scenarioFramework(sc);
  if (!sc || !fw) { cw.style.display = 'none'; note.style.display = 'none'; return; }
  // art_all_windows/art_all_platform scenarios always run every atomic for
  // every technique their target platform supports -- there is no subset
  // to choose, so "Customize" would be misleading here. Show a read-only
  // "Detailed view" instead (see openDetailedViewFromModal) and skip the
  // rest of this function entirely, since none of the selection/subset
  // logic below applies to a scenario that has nothing to select.
  if (sc.artAllWindows || sc.artAllPlatform) {
    cw.style.display = 'block';
    link.innerHTML = '&#128269; Detailed view — every atomic test that will run';
    link.style.opacity = '';
    link.style.pointerEvents = '';
    link.onclick = function() { openDetailedViewFromModal(); return false; };
    note.style.display = 'none';
    return;
  }
  link.onclick = function() { openPickerFromModal(); return false; };
  // A posture selection is tied to the agent whose catalog produced it (check IDs
  // are per-OS). If the operator switched agents, the stale subset would no longer
  // match — drop it so the run reverts to "all checks" rather than an empty run.
  if (fw === 'posture' && state._runSelection && state._runSelection.scId === id &&
      state._runSelection.agentId && state._runSelection.agentId !== document.getElementById('modal-agent').value) {
    state._runSelection = null;
  }
  var noun = (fw === 'art') ? 'techniques' : (fw === 'caldera') ? 'abilities' : (fw === 'posture') ? 'checks' : 'steps';
  var has = state._runSelection && state._runSelection.scId === id && state._runSelection.fw === fw && state._runSelection.ids.length > 0;
  cw.style.display = 'block';
  if (fw === 'posture' && !document.getElementById('modal-agent').value) {
    link.innerHTML = '&#9881; Customize — select a target agent first';
    link.style.opacity = '0.5';
    link.style.pointerEvents = 'none';
  } else if (has && state._runSelection.locked) {
    link.textContent = '🔒 Locked — re-validating ' + state._runSelection.ids.join(', ') + ' only';
    link.style.opacity = '0.6';
    link.style.pointerEvents = 'none';
  } else {
    link.style.opacity = '';
    link.style.pointerEvents = '';
    link.textContent = '⚙ ' + (has ? 'Change selection' : 'Customize — select ' + noun + ' to run');
  }
  if (has) {
    note.style.display = 'block';
    note.innerHTML = '&#9989; Running a selected subset: <strong>' + state._runSelection.ids.length + '</strong> ' + noun +
      (state._runSelection.locked ? ' (targeted re-validate)' :
       ' <a href="javascript:void(0)" class="desc-toggle" style="margin-left:8px" onclick="clearSelection();return false;">Clear</a>');
  } else if (fw === 'posture' && document.getElementById('modal-agent').value) {
    // No explicit subset chosen — show what "run everything" actually means
    // instead of leaving the operator to guess or dig into Customize. Uses
    // the same per-agent catalog Customize itself fetches (GetPostureCatalog
    // falls back to the agent's default RunAllChecks() set for a custom
    // scenario ID, so this is accurate even before anyone re-enrolls it
    // under a known name).
    var agentId = document.getElementById('modal-agent').value;
    var cacheKey = id + '|' + agentId;
    var cached = _postureSummaryCache[cacheKey];
    if (cached === undefined) {
      _postureSummaryCache[cacheKey] = 'pending';
      note.style.display = 'block';
      note.innerHTML = '<span class="u-muted">Loading check catalog…</span>';
      apicall('/api/posture/catalog?agentId=' + encodeURIComponent(agentId) + '&scenario=' + encodeURIComponent(id))
        .then(function(d) {
          var html = '';
          if (Array.isArray(d) && d.length) {
            var byPhase = {};
            d.forEach(function(c) { var p = c.phase || 'other'; byPhase[p] = (byPhase[p] || 0) + 1; });
            var catNames = Object.keys(byPhase).map(function(p) {
              return p.replace(/-/g, ' ').replace(/\b\w/g, function(ch) { return ch.toUpperCase(); });
            });
            html = '&#9432; <strong>' + d.length + '</strong> check' + (d.length === 1 ? '' : 's') +
              ' will run across ' + catNames.length + ' categor' + (catNames.length === 1 ? 'y' : 'ies') +
              ': ' + x(catNames.join(', ')) + '.';
          }
          _postureSummaryCache[cacheKey] = html;
          // Only repaint if the modal is still on this exact scenario+agent —
          // the operator may have navigated elsewhere while the fetch was in flight.
          if (document.getElementById('modal-agent').value === agentId &&
              (state._modalScId || document.getElementById('modal-sc').value) === id) {
            renderModalSelection();
          }
        }).catch(function() {
          _postureSummaryCache[cacheKey] = '';
          if (document.getElementById('modal-agent').value === agentId &&
              (state._modalScId || document.getElementById('modal-sc').value) === id) {
            renderModalSelection();
          }
        });
    } else if (cached === 'pending') {
      note.style.display = 'block';
      note.innerHTML = '<span class="u-muted">Loading check catalog…</span>';
    } else if (cached) {
      note.style.display = 'block';
      note.innerHTML = cached;
    } else {
      note.style.display = 'none';
    }
  } else {
    note.style.display = 'none';
  }
}

/* ── Scenario Builder ──────────────────────────────────────── */
var _bldEditId = null;
var _pickerBuilderMode = false;

export function openBuilderARTPicker() {
  var existing = (document.getElementById('bld-art-list').value || '')
    .split(/[\n,]+/).map(function(s) { return s.trim().toUpperCase(); }).filter(Boolean);
  function doOpen(catalog) {
    if (!catalog.length) { showToast('ART catalog is empty — reseed ART content', 'err'); return; }
    _pickerBuilderMode = true;
    _pickerItems = catalog;
    _pickerScId = null; _pickerFw = 'art'; _pickerSel = {};
    if (existing.length) {
      existing.forEach(function(id) { _pickerSel[id] = true; });
    } else {
      catalog.forEach(function(t) { _pickerSel[t.id] = true; });
    }
    document.getElementById('picker-title').textContent = 'Select ART techniques';
    document.getElementById('picker-sub').textContent = 'Tick the ATT&CK techniques to include. Search by ID or atomic name.';
    document.getElementById('picker-search').value = '';
    var filtersEl = document.getElementById('picker-caldera-filters');
    if (filtersEl) filtersEl.style.display = 'none';
    ensureCovStatus(renderPickerList);
    document.getElementById('picker-overlay').classList.add('open');
  }
  if (state.artCatalog.length) { doOpen(state.artCatalog); return; }
  apicall('/api/art/techniques').then(function(d) {
    if (Array.isArray(d) && d.length) { state.artCatalog = d; }
    doOpen(state.artCatalog);
  }).catch(function(e) { showToast('Catalog request failed: ' + (e && e.message ? e.message : e), 'err'); });
}

export function openBuilderCalderaPicker() {
  var existing = (document.getElementById('bld-caldera-list').value || '')
    .split(/[\n,]+/).map(function(s) { return s.trim(); }).filter(Boolean);
  function doOpen(catalog) {
    if (!catalog.length) { showToast('Caldera catalog is empty or Caldera is offline', 'err'); return; }
    _pickerBuilderMode = true;
    _pickerItems = catalog;
    _pickerScId = null; _pickerFw = 'caldera'; _pickerSel = {};
    if (existing.length) {
      existing.forEach(function(id) { _pickerSel[id] = true; });
    } else {
      catalog.forEach(function(t) { _pickerSel[t.id] = true; });
    }
    document.getElementById('picker-title').textContent = 'Select Caldera abilities';
    document.getElementById('picker-sub').textContent = 'Tick the abilities to include. Search by name, tactic, or technique.';
    document.getElementById('picker-search').value = '';
    // Show Caldera metadata filters and reset them.
    var filtersEl = document.getElementById('picker-caldera-filters');
    if (filtersEl) filtersEl.style.display = '';
    _pf = { plugin: 'all', payload: 'all', admin: 'all', platform: 'all', tactic: 'all' };
    document.querySelectorAll('.pfbtn').forEach(function(b) {
      b.classList.toggle('active', b.getAttribute('data-val') === 'all');
    });
    var tacticSel = document.getElementById('picker-tactic-sel');
    if (tacticSel) {
      var tacticSet = {};
      catalog.forEach(function(it) { if (it.tactic) tacticSet[it.tactic] = true; });
      tacticSel.innerHTML = '<option value="all">All tactics</option>' +
        Object.keys(tacticSet).sort().map(function(t) {
          return '<option value="' + x(t) + '">' + x(t) + '</option>';
        }).join('');
      tacticSel.value = 'all';
    }
    ensureCovStatus(renderPickerList);
    document.getElementById('picker-overlay').classList.add('open');
  }
  if (state.calderaCatalog.length) { doOpen(state.calderaCatalog); return; }
  apicall('/api/caldera/abilities').then(function(d) {
    if (Array.isArray(d) && d.length) state.calderaCatalog = d;
    doOpen(state.calderaCatalog);
  }).catch(function(e) { showToast('Catalog request failed: ' + (e && e.message ? e.message : e), 'err'); });
}

export function openBuilder(id) {
  _bldEditId = id;
  document.getElementById('bld-err').textContent = '';
  document.getElementById('builder-title').textContent = id ? 'Edit Scenario' : 'New Scenario';
  if (id) {
    // Fetch the full, fresh scenario so we edit complete data.
    apicall('/api/scenarios/' + encodeURIComponent(id)).then(function(s) {
      fillBuilder(s);
      document.getElementById('builder-overlay').classList.add('open');
    }).catch(function(e) { showToast(e.message, 'err'); });
  } else {
    fillBuilder(null);
    document.getElementById('builder-overlay').classList.add('open');
  }
}

function fillBuilder(s) {
  s = s || {};
  var idIn = document.getElementById('bld-id');
  idIn.value = s.id || '';
  idIn.disabled = !!_bldEditId; // ID is immutable once created
  document.getElementById('bld-name').value   = s.name || '';
  document.getElementById('bld-desc').value   = s.description || '';
  document.getElementById('bld-tags').value   = (s.tags || []).join(', ');
  document.getElementById('bld-phases').value = (s.mitrePhases || []).join(', ');

  // Determine mode
  var mode = 'custom';
  if (s.localCheck) mode = 'local';
  else if ((s.artTechniques || []).length) mode = 'art';
  else if ((s.calderaAbilities || []).length) mode = 'caldera';
  document.getElementById('bld-mode').value = mode;

  document.getElementById('bld-art-list').value     = (s.artTechniques || []).join('\n');
  document.getElementById('bld-caldera-list').value = (s.calderaAbilities || []).join('\n');

  var steps = document.getElementById('bld-steps');
  steps.innerHTML = '';
  ((s.steps) || []).forEach(function(st) { addStep(st); });
  if (mode === 'custom' && !steps.children.length) addStep(null);
  ensureTechniqueCatalog(techRefreshAllTechCards);

  renderBuilderMode();
}

export function closeBuilder() {
  document.getElementById('builder-overlay').classList.remove('open');
  _bldEditId = null;
}
export function closeBuilderOnBackdrop(el, event) { if (event.target === el) closeBuilder(); }

export function renderBuilderMode() {
  var mode = document.getElementById('bld-mode').value;
  document.getElementById('bld-custom').style.display  = mode === 'custom'  ? 'block' : 'none';
  document.getElementById('bld-art').style.display     = mode === 'art'     ? 'block' : 'none';
  document.getElementById('bld-caldera').style.display = mode === 'caldera' ? 'block' : 'none';
  document.getElementById('bld-local').style.display   = mode === 'local'   ? 'block' : 'none';
  if (mode === 'custom' && !document.getElementById('bld-steps').children.length) addStep(null);
}

/* ── Technique Selector: matching engine ─────────────────────────────────
   Pure functions, no DOM access — kept together so they can be verified
   standalone before being wired into the combobox UI. */

function techNormalize(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function techTokenize(s) {
  return String(s || '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function techBuildIndex(catalog) {
  return (catalog || []).map(function(t) {
    return {
      raw: t,
      idNorm: techNormalize(t.id),
      nameNorm: techNormalize(t.name),
      nameTokens: techTokenize(t.name),
      tacticNorms: (t.tactics || []).map(techNormalize),
      aliasTokens: (t.aliases || []).reduce(function(acc, a) {
        return acc.concat(techTokenize(a));
      }, []),
      descNorm: techNormalize(t.description)
    };
  });
}

// techEditDistance computes Levenshtein edit distance. Only ever called on
// short tokens (technique-name words), so the O(m*n) DP table is cheap.
function techEditDistance(a, b) {
  var m = a.length, n = b.length;
  if (Math.abs(m - n) > 2) return 99; // cheap short-circuit for the fuzzy threshold
  var dp = [], i, j;
  for (i = 0; i <= m; i++) dp[i] = [i];
  for (j = 0; j <= n; j++) dp[0][j] = j;
  for (i = 1; i <= m; i++) {
    for (j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

// techScore ranks one index entry against a query. Higher is better; 0 means
// no match. Tiers match the design spec's priority order exactly.
function techScore(entry, queryNorm, queryTokens) {
  if (!queryNorm) return 0;
  if (entry.idNorm === queryNorm) return 1000;                              // exact ID
  if (entry.nameNorm === queryNorm) return 900;                             // exact name
  if (entry.idNorm.indexOf(queryNorm) === 0) return 800;                    // ID prefix
  if (entry.idNorm.indexOf(queryNorm) !== -1) return 750;                   // ID substring
  if (entry.nameNorm.indexOf(queryNorm) === 0) return 700;                  // name prefix
  if (queryTokens.length && queryTokens.every(function(qt) {
    return entry.nameTokens.some(function(nt) { return nt.indexOf(qt) === 0 || nt.indexOf(qt) !== -1; });
  })) return 650;                                                           // broken-word name match
  if (entry.tacticNorms.some(function(tn) { return tn === queryNorm || tn.indexOf(queryNorm) === 0; })) return 550; // tactic
  if (queryTokens.length && entry.aliasTokens.length && queryTokens.every(function(qt) {
    return entry.aliasTokens.some(function(at) { return at.indexOf(qt) === 0 || at.indexOf(qt) !== -1; });
  })) return 500;                                                           // synonym
  if (queryTokens.length && queryTokens.every(function(qt) { return entry.descNorm.indexOf(qt) !== -1; })) return 400; // description keyword
  var fuzzyHit = queryTokens.some(function(qt) {
    return entry.nameTokens.some(function(nt) {
      var threshold = qt.length <= 5 ? 1 : 2;
      return Math.abs(nt.length - qt.length) <= threshold && techEditDistance(qt, nt) <= threshold;
    });
  });
  return fuzzyHit ? 200 : 0;                                                // fuzzy fallback
}

// techSearch runs a query against a prebuilt index and returns up to 20
// matching catalog entries (the original `raw` objects), best match first.
function techSearch(index, query) {
  var queryNorm = techNormalize(query);
  var queryTokens = techTokenize(query);
  if (!queryNorm) return [];
  return index
    .map(function(e) { return { entry: e, score: techScore(e, queryNorm, queryTokens) }; })
    .filter(function(s) { return s.score > 0; })
    .sort(function(a, b) { return b.score - a.score || (a.entry.idNorm < b.entry.idNorm ? -1 : 1); })
    .slice(0, 20)
    .map(function(s) { return s.entry.raw; });
}

/* ── /Technique Selector: matching engine ────────────────────────────── */

/* ── Technique Selector: combobox UI ─────────────────────────────────── */

var techniqueCatalog = null; // null = not yet fetched; [] = fetched but empty/failed
var techniqueIndex = null;
var _techSearchTimer = null;

function ensureTechniqueCatalog(cb) {
  if (techniqueCatalog !== null) { cb(); return; }
  apicall('/api/techniques/catalog').then(function(list) {
    techniqueCatalog = Array.isArray(list) ? list : [];
    techniqueIndex = techBuildIndex(techniqueCatalog);
    cb();
  }).catch(function() {
    techniqueCatalog = [];
    techniqueIndex = [];
    cb();
  });
}

function techFindById(id) {
  if (!techniqueCatalog) return null;
  var norm = techNormalize(id);
  for (var i = 0; i < techniqueCatalog.length; i++) {
    if (techNormalize(techniqueCatalog[i].id) === norm) return techniqueCatalog[i];
  }
  return null;
}

function techFieldHTML(st) {
  var techId = (st && st.techniqueId) || '';
  var hasSelection = !!techId;
  return '<div class="bld-field full st-tech-wrap">' +
      '<label>Technique</label>' +
      '<input class="st-tech" type="hidden" value="' + x(techId) + '">' +
      '<div class="st-tech-selected" style="display:' + (hasSelection ? '' : 'none') + '"></div>' +
      '<input class="st-tech-search" type="text" placeholder="Search ATT&amp;CK technique (ID, name, keyword...)" autocomplete="off" ' +
        'style="display:' + (hasSelection ? 'none' : '') + '" ' +
        'oninput="techOnInput(this)" onkeydown="techOnKeydown(event,this)" onblur="techOnBlur(this)">' +
      '<div class="bld-mode-help" style="margin:0.3rem 0 0">Examples: T1055 &middot; credential dumping &middot; lsass &middot; powershell &middot; registry run</div>' +
      '<div class="st-tech-panel"></div>' +
    '</div>';
}

// techInitField renders the initial selected-card state for a freshly-added
// step row that already has a techniqueId (edit mode). Called right after
// the row is appended to the DOM.
function techInitField(wrap, techId) {
  if (!techId) return;
  techRenderSelected(wrap, techId);
}

function techRenderSelected(wrap, id) {
  var box = wrap.querySelector('.st-tech-selected');
  var search = wrap.querySelector('.st-tech-search');
  var hidden = wrap.querySelector('.st-tech');
  hidden.value = id;
  search.style.display = 'none';
  box.style.display = '';
  var t = techFindById(id);
  if (!t) {
    box.className = 'st-tech-selected unresolved';
    box.innerHTML =
      '<div><span class="st-tech-sel-id">' + x(id) + '</span>' +
        '<span class="tiny muted" style="margin-left:0.4rem">' +
        (techniqueCatalog === null ? 'resolving…' : 'not recognized') + '</span></div>' +
      '<span class="st-tech-sel-actions"><a href="javascript:void(0)" onclick="techChangeSelection(this)">&#10005; change</a></span>';
    return;
  }
  box.className = 'st-tech-selected';
  var tactics = (t.tactics || []).join(', ');
  var subText = t.subCount ? (t.subCount + (t.subCount === 1 ? ' sub-technique' : ' sub-techniques')) : '';
  box.innerHTML =
    '<div><span class="st-tech-sel-id">' + x(t.id) + '</span> <span class="st-tech-sel-name">' + x(t.name) + '</span>' +
      (tactics ? '<div class="st-tech-row-meta">' + x(tactics) + '</div>' : '') +
      (subText ? '<div class="st-tech-row-meta">' + x(subText) + '</div>' : '') +
    '</div>' +
    '<span class="st-tech-sel-actions">' +
      (t.url ? '<a href="' + x(t.url) + '" target="_blank" rel="noopener">View ATT&amp;CK</a> ' : '') +
      '<a href="javascript:void(0)" onclick="techCopyId(this)" data-id="' + x(t.id) + '">Copy ID</a> ' +
      '<a href="javascript:void(0)" onclick="techChangeSelection(this)">&#10005; change</a>' +
    '</span>';
}

function techRefreshAllTechCards() {
  document.querySelectorAll('.st-tech-wrap').forEach(function(wrap) {
    var hidden = wrap.querySelector('.st-tech');
    if (hidden.value) techRenderSelected(wrap, hidden.value);
  });
}

export function techChangeSelection(el) {
  var wrap = el.closest('.st-tech-wrap');
  wrap.querySelector('.st-tech').value = '';
  wrap.querySelector('.st-tech-selected').style.display = 'none';
  var search = wrap.querySelector('.st-tech-search');
  search.style.display = '';
  search.value = '';
  search.focus();
}

export function techCopyId(el) {
  var id = el.getAttribute('data-id');
  if (navigator.clipboard && id) {
    navigator.clipboard.writeText(id).then(function() { showToast('Copied ' + id, 'ok'); });
  }
}

function techOnInput(input) {
  var wrap = input.closest('.st-tech-wrap');
  var panel = wrap.querySelector('.st-tech-panel');
  if (_techSearchTimer) clearTimeout(_techSearchTimer);
  if (!input.value) { panel.classList.remove('show'); panel.innerHTML = ''; return; }
  _techSearchTimer = setTimeout(function() {
    ensureTechniqueCatalog(function() { techRenderResults(wrap, input.value); });
  }, 150);
}

function techRenderResults(wrap, query) {
  var panel = wrap.querySelector('.st-tech-panel');
  var results = techSearch(techniqueIndex || [], query);
  if (!results.length) {
    panel.innerHTML = '<div class="st-tech-row" style="cursor:default;color:var(--muted)">No matching technique.</div>';
    panel.classList.add('show');
    return;
  }
  panel.innerHTML = results.map(function(t, i) {
    var tactics = (t.tactics || []).join(', ');
    var platforms = (t.platforms || []).join(', ');
    return '<div class="st-tech-row' + (i === 0 ? ' active' : '') + '" data-id="' + x(t.id) + '" onmousedown="techSelectRow(this)">' +
      '<span class="st-tech-row-id">' + x(t.id) + '</span><span class="st-tech-row-name">' + x(t.name) + '</span>' +
      (tactics ? '<div class="st-tech-row-meta">' + x(tactics) + '</div>' : '') +
      (platforms ? '<div class="st-tech-row-meta">' + x(platforms) + '</div>' : '') +
    '</div>';
  }).join('');
  panel.classList.add('show');
}

export function techSelectRow(row) {
  var wrap = row.closest('.st-tech-wrap');
  techRenderSelected(wrap, row.getAttribute('data-id'));
  var panel = wrap.querySelector('.st-tech-panel');
  panel.classList.remove('show');
  panel.innerHTML = '';
}

export function techOnKeydown(ev, input) {
  var wrap = input.closest('.st-tech-wrap');
  var panel = wrap.querySelector('.st-tech-panel');
  if (!panel.classList.contains('show')) return;
  var rows = panel.querySelectorAll('.st-tech-row[data-id]');
  if (!rows.length) return;
  var activeIdx = -1;
  rows.forEach(function(r, i) { if (r.classList.contains('active')) activeIdx = i; });
  if (ev.key === 'ArrowDown') {
    ev.preventDefault();
    activeIdx = (activeIdx + 1) % rows.length;
    rows.forEach(function(r, i) { r.classList.toggle('active', i === activeIdx); });
  } else if (ev.key === 'ArrowUp') {
    ev.preventDefault();
    activeIdx = (activeIdx - 1 + rows.length) % rows.length;
    rows.forEach(function(r, i) { r.classList.toggle('active', i === activeIdx); });
  } else if (ev.key === 'Enter') {
    ev.preventDefault();
    techSelectRow(activeIdx >= 0 ? rows[activeIdx] : rows[0]);
  } else if (ev.key === 'Escape') {
    panel.classList.remove('show');
    panel.innerHTML = '';
  } else if (ev.key === 'Tab') {
    techSelectRow(rows[0]); // selection completes; default Tab behavior still advances focus
  }
}

export function techOnBlur(input) {
  var wrap = input.closest('.st-tech-wrap');
  setTimeout(function() {
    var panel = wrap.querySelector('.st-tech-panel');
    panel.classList.remove('show');
    panel.innerHTML = '';
  }, 150); // delay so a row's onmousedown fires before the panel is cleared
}

/* ── /Technique Selector: combobox UI ────────────────────────────────── */

export function addStep(st) {
  st = st || {};
  var execs = ['powershell','cmd','bash','sh','wmi','mshta','rundll32','cscript','wscript','regsvr32','schtasks'];
  var cur = st.executor || 'powershell';
  var execOpts = execs.map(function(e) {
    return '<option value="' + e + '"' + (e === cur ? ' selected' : '') + '>' + e + '</option>';
  }).join('');
  var privTiers = [['', 'No requirement'], ['user', 'User'], ['admin', 'Admin'], ['system', 'System']];
  var curPriv = (st.requiresPriv && st.requiresPriv.minimum) || '';
  var privOpts = privTiers.map(function(t) {
    return '<option value="' + t[0] + '"' + (t[0] === curPriv ? ' selected' : '') + '>' + t[1] + '</option>';
  }).join('');
  var div = document.createElement('div');
  div.className = 'bld-step';
  div.innerHTML =
    '<div class="bld-step-hdr"><span class="bld-step-num">Step</span>' +
      '<span class="bld-actions">' +
        '<button type="button" onclick="moveStep(this,-1)" title="Move up">&#9650;</button>' +
        '<button type="button" onclick="moveStep(this,1)" title="Move down">&#9660;</button>' +
        '<button type="button" onclick="removeStep(this)" title="Remove">&#10005;</button>' +
      '</span></div>' +
    '<div class="bld-grid">' +
      techFieldHTML(st) +
      '<div class="bld-field"><label>Name</label><input class="st-name" type="text" value="' + x(st.name || '') + '" placeholder="e.g. Dump LSASS"></div>' +
      '<div class="bld-field"><label>Executor</label><select class="st-exec">' + execOpts + '</select></div>' +
      '<div class="bld-field"><label>Timeout (sec)</label><input class="st-timeout" type="number" min="0" value="' + (st.timeoutSec || 60) + '"></div>' +
      '<div class="bld-field"><label>Requires privilege</label><select class="st-priv">' + privOpts + '</select></div>' +
      '<div class="bld-field full"><label>Command</label><textarea class="st-cmd" rows="2" placeholder="command to run on the endpoint">' + x(st.command || '') + '</textarea></div>' +
      '<div class="bld-field full"><label>Cleanup (optional)</label><textarea class="st-cleanup" rows="1" placeholder="command run after the step">' + x(st.cleanup || '') + '</textarea></div>' +
    '</div>' +
    '<div class="bld-mode-help">Steps requiring higher privilege than a run\'s Max Privilege ceiling are skipped, not dispatched.</div>';
  document.getElementById('bld-steps').appendChild(div);
  techInitField(div, st.techniqueId);
  renumberSteps();
}

export function removeStep(btn) { btn.closest('.bld-step').remove(); renumberSteps(); }

export function moveStep(btn, dir) {
  var el = btn.closest('.bld-step');
  if (dir < 0 && el.previousElementSibling) el.parentNode.insertBefore(el, el.previousElementSibling);
  if (dir > 0 && el.nextElementSibling) el.parentNode.insertBefore(el.nextElementSibling, el);
  renumberSteps();
}

function renumberSteps() {
  var steps = document.querySelectorAll('#bld-steps .bld-step');
  steps.forEach(function(s, i) { s.querySelector('.bld-step-num').textContent = 'Step ' + (i + 1); });
}

// splitList parses a comma- or newline-separated textbox into a trimmed array.
function splitList(val) {
  return (val || '').split(/[\n,]+/).map(function(s) { return s.trim(); }).filter(Boolean);
}

// collectBuilder reads the form into a scenario object, or returns null + shows an error.
function collectBuilder() {
  var err = document.getElementById('bld-err');
  err.textContent = '';
  var id = document.getElementById('bld-id').value.trim();
  var name = document.getElementById('bld-name').value.trim();
  if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(id)) {
    err.textContent = 'ID must be 2-64 chars: lowercase letters, digits, hyphens.'; return null;
  }
  if (!name) { err.textContent = 'Name is required.'; return null; }

  var sc = {
    id: id, name: name,
    description: document.getElementById('bld-desc').value.trim(),
    tags: splitList(document.getElementById('bld-tags').value),
    mitrePhases: splitList(document.getElementById('bld-phases').value),
    steps: [], artTechniques: [], calderaAbilities: [], localCheck: false
  };

  var mode = document.getElementById('bld-mode').value;
  if (mode === 'local') {
    sc.localCheck = true;
  } else if (mode === 'art') {
    sc.artTechniques = splitList(document.getElementById('bld-art-list').value);
    if (!sc.artTechniques.length) { err.textContent = 'Add at least one ATT&CK technique ID.'; return null; }
  } else if (mode === 'caldera') {
    sc.calderaAbilities = splitList(document.getElementById('bld-caldera-list').value);
    if (!sc.calderaAbilities.length) { err.textContent = 'Add at least one Caldera ability ID.'; return null; }
  } else {
    var rows = document.querySelectorAll('#bld-steps .bld-step');
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var tech = r.querySelector('.st-tech').value.trim();
      if (!tech) {
        var searchVal = (r.querySelector('.st-tech-search').value || '').trim();
        err.textContent = 'Step ' + (i + 1) + ': ' +
          (searchVal ? 'select a technique from the search results.' : 'a technique is required.');
        return null;
      }
      var newStep = {
        name: r.querySelector('.st-name').value.trim() || ('Step ' + (i + 1)),
        techniqueId: tech,
        framework: 'custom',
        executor: r.querySelector('.st-exec').value,
        command: r.querySelector('.st-cmd').value,
        timeoutSec: parseInt(r.querySelector('.st-timeout').value, 10) || 60,
        cleanup: r.querySelector('.st-cleanup').value.trim()
      };
      var privVal = r.querySelector('.st-priv').value;
      if (privVal) newStep.requiresPriv = privVal;
      sc.steps.push(newStep);
    }
    if (!sc.steps.length) { err.textContent = 'Add at least one step.'; return null; }
  }
  return sc;
}

export function saveScenario(runAfter) {
  var sc = collectBuilder();
  if (!sc) return;
  var editing = !!_bldEditId;
  var path = editing ? '/api/scenarios/' + encodeURIComponent(_bldEditId) : '/api/scenarios';
  var method = editing ? 'PUT' : 'POST';
  apicall(path, { method: method, body: JSON.stringify(sc) }).then(function(res) {
    if (res && res.error) { document.getElementById('bld-err').textContent = res.error; return; }
    showToast('Scenario ' + (editing ? 'updated' : 'created'), 'ok');
    closeBuilder();
    loadScenarios();
    if (runAfter) { setTimeout(function() { openModal(sc.id, null); }, 250); }
  }).catch(function(e) { document.getElementById('bld-err').textContent = e.message; });
}

export function cloneScenario(id) {
  var newId = prompt('New scenario ID for the clone:', id + '-copy');
  if (!newId) return;
  apicall('/api/scenarios/' + encodeURIComponent(id) + '/clone', {
    method: 'POST', body: JSON.stringify({ newId: newId.trim() })
  }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    showToast('Cloned to ' + newId, 'ok');
    loadScenarios();
    setTimeout(function() { openBuilder(newId.trim()); }, 250);
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function deleteCustomScenario(id) {
  if (!confirm('Delete custom scenario "' + id + '"? This removes its YAML file.')) return;
  fetch('/api/scenarios/' + encodeURIComponent(id), { method: 'DELETE', credentials: 'same-origin' })
    .then(function(r) {
      if (r.status === 204) { showToast('Scenario deleted', 'ok'); loadScenarios(); }
      else { r.json().then(function(j) { showToast(j.error || 'Delete failed', 'err'); }); }
    }).catch(function(e) { showToast(e.message, 'err'); });
}

export function uploadScenarioFile(input) {
  var file = input.files && input.files[0];
  input.value = ''; // reset so the same file can be re-picked
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function() {
    fetch('/api/scenarios/upload', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-yaml' },
      body: reader.result
    }).then(function(r) { return r.json().then(function(j) { return { ok: r.ok, j: j }; }); })
      .then(function(res) {
        if (!res.ok) { showToast(res.j.error || 'Upload failed', 'err'); return; }
        showToast('Uploaded ' + (res.j.id || 'scenario'), 'ok');
        loadScenarios();
      }).catch(function(e) { showToast(e.message, 'err'); });
  };
  reader.readAsText(file);
}

export function downloadBuilderYaml() {
  var sc = collectBuilder();
  if (!sc) return;
  var yaml = scenarioToYaml(sc);
  var blob = new Blob([yaml], { type: 'text/yaml' });
  var href = URL.createObjectURL(blob);
  triggerDownload(href, sc.id + '.yaml');
  URL.revokeObjectURL(href);
}

// scenarioToYaml emits a YAML file the server can re-import (snake_case keys).
function scenarioToYaml(sc) {
  function q(s) { return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; }
  function block(s, indent) {
    var pad = new Array(indent + 1).join(' ');
    return '|\n' + String(s).split('\n').map(function(l) { return pad + l; }).join('\n');
  }
  var out = 'id: ' + q(sc.id) + '\n';
  out += 'name: ' + q(sc.name) + '\n';
  if (sc.description) out += 'description: ' + q(sc.description) + '\n';
  if (sc.tags.length) out += 'tags: [' + sc.tags.map(q).join(', ') + ']\n';
  if (sc.mitrePhases.length) out += 'mitre_phases: [' + sc.mitrePhases.map(q).join(', ') + ']\n';
  if (sc.localCheck) out += 'local_check: true\n';
  if (sc.artTechniques.length) out += 'art_techniques: [' + sc.artTechniques.map(q).join(', ') + ']\n';
  if (sc.calderaAbilities.length) out += 'caldera_abilities: [' + sc.calderaAbilities.map(q).join(', ') + ']\n';
  if (sc.steps.length) {
    out += 'steps:\n';
    sc.steps.forEach(function(st) {
      out += '  - name: ' + q(st.name) + '\n';
      out += '    technique_id: ' + q(st.techniqueId) + '\n';
      out += '    framework: ' + q(st.framework || 'custom') + '\n';
      out += '    executor: ' + q(st.executor) + '\n';
      out += '    timeout_sec: ' + (st.timeoutSec || 60) + '\n';
      if (st.requiresPriv) out += '    requires_priv: ' + q(st.requiresPriv) + '\n';
      if (st.command) out += '    command: ' + block(st.command, 6) + '\n';
      if (st.cleanup) out += '    cleanup: ' + block(st.cleanup, 6) + '\n';
    });
  }
  return out;
}

// MODE_LABELS maps a run/campaign's dispatch mode to its display label --
// shared by every "what was selected at dispatch" subtitle below (Results
// drawer, rerun review x2, live run subtitle), which previously each
// declared their own identical local copy of this map.
export var MODE_LABELS = { posture: 'Posture', telemetry: 'Telemetry', lab: 'Lab' };

export function viewRunResults(run) {
  document.getElementById('results-overlay').classList.add('run-mode');
  document.getElementById('results-title').textContent = run.name + ' — Results';
  var results = run.results || [];
  // Counted, not derived by subtraction: `results.length - fail - skipped` folded
  // every ERRORED step into pass, which drove both the summary line and the
  // Detection Rate card (a run with 0 real passes and 19 errors showed 66%).
  var _v = verdictCounts(run);
  var skipped = results.filter(function(c) { return c.result === 'skipped'; }).length;
  var fail = _v.fail;
  var pass = _v.pass;

  var alertText = "";
  if (typeof run.alertsTotal !== 'undefined' && run.alertsTotal > 0) {
    if (run.alertsHighFidelity > 0) {
      alertText = ' &nbsp;&middot;&nbsp; Simulation generated <strong class="u-warning">' + run.alertsTotal + ' alerts</strong> (<strong style="color:var(--accent)">' + run.alertsHighFidelity + ' high-fidelity</strong>)';
    } else {
      alertText = ' &nbsp;&middot;&nbsp; Simulation generated <strong class="u-warning">' + run.alertsTotal + ' alerts</strong>';
    }
  } else if (typeof run.alertsTotal !== 'undefined' && run.alertsTotal === 0 && (run.status === 'completed' || run.status === 'partial')) {
    alertText = ' &nbsp;&middot;&nbsp; No alerts generated';
  }

  // Run Settings — what was actually selected at dispatch (mode / privilege
  // ceiling). Previously only inferable after the fact from per-step
  // evidence (ExecutedAs / a policy-privilege skip, if any); this makes the
  // question "was this the admin run or the no-limit run?" answerable at a
  // glance instead. Absent on older runs / non-configurable dispatch paths
  // (full-scan, safe-scan) — render nothing rather than a misleading blank.
  var modeText = run.mode ? (MODE_LABELS[run.mode] || x(run.mode)) : '';
  var privText = run.mode ? (run.maxPrivilege ? x(run.maxPrivilege.charAt(0).toUpperCase() + run.maxPrivilege.slice(1)) : 'No limit') : '';
  var runSettingsText = modeText
    ? ' &nbsp;&middot;&nbsp; Mode: <strong>' + modeText + '</strong> &nbsp;&middot;&nbsp; Privilege: <strong>' + privText + '</strong>'
    : '';

  // Selection — which techniques/checks/steps/abilities were actually
  // dispatched, same data Re-run Review already shows, surfaced here too so
  // it's a glance instead of a click. Only shown for a real subset (a full
  // scenario run is the common case and would just be noise here); "All" is
  // the implicit default when this is absent.
  var sc = state.scenarios.find(function(s) { return s.id === run.scenarioId; });
  var subset = rerunSubset(run, scenarioFramework(sc));
  var subsetFieldLabels = { techniques: 'Techniques', abilities: 'Abilities', steps: 'Steps', checks: 'Checks' };
  var subsetText = '';
  if (subset.field && subset.ids.length) {
    subsetText = ' &nbsp;&middot;&nbsp; ' + x(subsetFieldLabels[subset.field] || subset.field) + ': <strong>' +
      subset.ids.length + '</strong> — ' + x(subset.ids.slice(0, 4).join(', ')) + (subset.ids.length > 4 ? ', …' : '');
  }

  // A dispatch-time failure (status='failed') never reached execution, so
  // "0 fail / 0 pass · 0 total" is meaningless noise here -- show the genuine
  // persisted reason instead (run.failReason, from scenario_runs.fail_reason)
  // so it's clear e.g. "agent was offline" vs. "scenario content is broken",
  // not just a bare red badge with nothing to explain it.
  if (run.status === 'failed') {
    document.getElementById('results-summary').innerHTML =
      '<span style="color:var(--danger);font-weight:600">Run failed to start</span>' +
      ' &nbsp;&middot;&nbsp; ' + x(run.failReason || 'No reason recorded for this failure.') +
      ' &nbsp;&middot;&nbsp; Agent: <code>' + x(run.agentId) + '</code>';
  } else {
    document.getElementById('results-summary').innerHTML =
      '<span style="color:var(--danger);font-weight:600">' + fail + ' fail</span>' +
      ' &nbsp;/&nbsp; <span style="color:var(--success);font-weight:600">' + pass + ' pass</span>' +
      (skipped ? ' &nbsp;/&nbsp; <span class="u-muted">' + skipped + ' skipped</span>' : '') +
      ' &nbsp;&middot;&nbsp; ' + results.length + ' total &nbsp;&middot;&nbsp; Agent: <code>' + x(run.agentId) + '</code>' +
      runSettingsText +
      subsetText +
      alertText;
  }

  var runId = run.id || '';
  var hasOutput = runId && (run.status === 'completed' || run.status === 'partial');
  document.getElementById('results-export').innerHTML = '';

  // Header status pill -- reuses the exact status->color mapping the Live
  // Runs table already applies (index.html:13171), and the .sbadge pill
  // pattern already used for license/status badges elsewhere (index.html:12905).
  var runStatusColor = { completed: 'var(--success)', running: 'var(--accent)', partial: 'var(--warning)', failed: 'var(--danger)' }[run.status] || 'var(--muted)';
  document.getElementById('results-title').innerHTML =
    x(run.name) + ' — Results ' +
    '<span class="sbadge" style="background:' + runStatusColor + '22;color:' + runStatusColor + ';border:1px solid ' + runStatusColor + '44;font-size:0.65rem;margin-left:0.4rem;vertical-align:middle">' + x(run.status || '') + '</span>';

  // Header toolbar -- real export actions relocated verbatim from the old
  // inline export bar. Compare is not a real feature anywhere in this app
  // today, so it stays disabled. Re-run opens a read-only review (see
  // openRerunReview) that clones this exact run's configuration -- no
  // wizard, nothing to reselect.
  var actionsHtml = '';
  if (hasOutput) {
    var canRerun = ROLE === 'admin' || ROLE === 'analyst';
    actionsHtml =
      '<button class="btn btn-sm btn-outline" onclick="exportRunJSON(\'' + runId + '\')" title="Download full run data as JSON">&#8595; JSON</button>' +
      '<button class="btn btn-sm btn-outline" onclick="openRunReport(\'' + runId + '\')" title="Open self-contained HTML report in new tab">&#8599; HTML Report</button>' +
      '<button class="btn btn-sm btn-outline" onclick="downloadRunReport(\'' + runId + '\')" title="Download the report as a PDF file">&#8595; PDF Report</button>' +
      '<button class="btn btn-sm btn-outline" onclick="downloadRunCSV(\'' + runId + '\')" title="Download forensic CSV (one row per technique)">&#8595; CSV</button>' +
      '<button class="btn btn-outline btn-sm" disabled style="opacity:0.5;cursor:not-allowed" title="Compare against another run — coming soon">Compare</button>' +
      (canRerun
        ? '<button class="btn btn-outline btn-sm" onclick=\'openRerunReview(' + JSON.stringify(run).replace(/'/g,"&#39;") + ')\' title="Review and re-run this exact configuration">Re-run</button>'
        : '<button class="btn btn-outline btn-sm" disabled style="opacity:0.5;cursor:not-allowed" title="Re-run requires the Analyst or Admin role">Re-run</button>');
  }
  document.getElementById('results-header-actions').innerHTML = actionsHtml;

  var scorePanel = '';
  if (run.score && typeof run.score.preventionScore !== 'undefined') {
    var s = run.score;
    var prevPct = Math.round(s.preventionScore || 0);
    var expVal  = Math.round(s.exposureScore || 0);
    var covPct  = Math.round(s.killChainCoverage || 0);
    var amp     = (s.killChainAmplifier || 1).toFixed(1);
    var trend   = s.trend || 'Baseline';
    var cls     = s.classification || '';

    var prevCol = _riskScoreColor(prevPct);
    var expCol  = expVal  <= 20 ? 'var(--success)' : expVal  <= 50 ? 'var(--warning)' : 'var(--danger)';
    var covCol  = 'var(--accent)'; // breadth metric — neutral; low single-run coverage is expected, not "bad"
    var trendCol = trend === 'Improving' ? 'var(--success)' :
                   trend === 'Degrading' ? 'var(--danger)' :
                   trend === 'Stable'    ? 'var(--warning)' : 'var(--muted)';
    var trendIcon = trend === 'Improving' ? '↑' : trend === 'Degrading' ? '↓' : trend === 'Stable' ? '→' : '◎';

    // KPI strip -- reuses the exact gaugeSVG/sparkSVG helpers and .kpi-card
    // CSS the main Dashboard already uses (index.html:12041-12063, :670-697).
    // Detection Rate is derived the same way the existing summary line
    // above already computes pass/fail; every other value comes straight
    // off run.score, already confirmed real during brainstorming. No card
    // here is backed by fabricated data -- a missing value renders '—'.
    (function() {
      var detRate = results.length ? Math.round(pass * 100 / results.length) : 0;
      // Gate on trend, not on previousPreventionScore. That field is documented
      // as "0 if Baseline", so a run with no prior is indistinguishable from one
      // whose prior genuinely scored 0% -- and the card announced
      // "→ 0 pts vs last run" on a first-ever run, right beside a RISK LEVEL
      // card correctly reading "Baseline". score.go sets Trend to "Baseline"
      // exactly when prev == nil, so it is the honest signal.
      var deltaHtml = (s.trend && s.trend !== 'Baseline' &&
                       typeof s.previousPreventionScore !== 'undefined' && s.previousPreventionScore !== null)
        ? (function() {
            var delta = Math.round(prevPct - s.previousPreventionScore);
            var arrow = delta > 0 ? '↑' : delta < 0 ? '↓' : '→';
            var col = delta > 0 ? 'var(--success)' : delta < 0 ? 'var(--danger)' : 'var(--muted)';
            return '<span style="color:' + col + '">' + arrow + ' ' + Math.abs(delta) + ' pts vs last run</span>';
          })()
        : '<span class="u-muted">baseline — no prior run</span>';
      function kpiGaugeCard(label, value, sub) {
        return '<div class="kpi-card" style="display:flex;align-items:center;gap:0.75rem">' +
          '<div class="ring" style="width:64px;height:64px">' + gaugeSVG(value, 64, 8) +
            '<div class="ring-c"><div class="rv" style="font-size:0.95rem">' + value + '%</div></div></div>' +
          '<div><div class="kpi-label">' + label + '</div><div class="kpi-sub">' + sub + '</div></div>' +
        '</div>';
      }
      document.getElementById('run-kpi-strip').innerHTML =
        '<div class="kpi-row" style="grid-template-columns:repeat(6,1fr)">' +
          '<div class="kpi-card"><div class="kpi-label">Overall Security Score</div><div class="kpi-value">' + prevPct + '<span style="font-size:0.9rem;color:var(--muted)">/100</span></div><div class="kpi-sub">' + (deltaHtml || '—') + '</div></div>' +
          kpiGaugeCard('Detection Rate', detRate, pass + ' / ' + results.length + ' techniques') +
          kpiGaugeCard('Prevention Rate', prevPct, x(cls) || '—') +
          '<div class="kpi-card"><div class="kpi-label">Exposure Score</div><div class="kpi-value" style="color:' + expCol + '">' + expVal + '</div><div class="kpi-sub">×' + amp + ' kill-chain</div></div>' +
          kpiGaugeCard('Tactic Coverage', covPct, 'of 14 ATT&CK tactics') +
          '<div class="kpi-card"><div class="kpi-label">Risk Level</div><div class="kpi-value" style="color:' + trendCol + '">' + trendIcon + ' ' + x(trend) + '</div><div class="kpi-sub">vs prior run</div></div>' +
        '</div>';
    })();

    var dimStyle = 'background:var(--elevated);border:1px solid var(--border);border-radius:4px;padding:0.6rem 0.75rem;';
    var labelStyle = 'color:var(--muted);font-size:0.6rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:0.2rem';
    var bigStyle = 'font-size:1.4rem;font-weight:700;line-height:1.1';
    var subStyle = 'font-size:0.68rem;color:var(--muted);margin-top:0.1rem';

    scorePanel =
      '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:0.5rem;margin-bottom:0.75rem">' +
        '<div style="' + dimStyle + '">' +
          '<div style="' + labelStyle + '">Prevention</div>' +
          '<div style="' + bigStyle + ';color:' + prevCol + '">' + prevPct + '%</div>' +
          '<div style="' + subStyle + '">' + x(cls) + '</div>' +
        '</div>' +
        '<div style="' + dimStyle + '">' +
          '<div style="' + labelStyle + '">Exposure</div>' +
          '<div style="' + bigStyle + ';color:' + expCol + '">' + expVal + '</div>' +
          '<div style="' + subStyle + '">×' + amp + ' kill-chain</div>' +
        '</div>' +
        '<div style="' + dimStyle + '">' +
          '<div style="' + labelStyle + '">Tactic Coverage</div>' +
          '<div style="' + bigStyle + ';color:' + covCol + '">' + covPct + '%</div>' +
          '<div style="' + subStyle + '">of 14 ATT&CK tactics</div>' +
        '</div>' +
        '<div style="' + dimStyle + '">' +
          '<div style="' + labelStyle + '">Trend</div>' +
          '<div style="' + bigStyle + ';color:' + trendCol + '">' + trendIcon + ' ' + trend + '</div>' +
          '<div style="' + subStyle + '">vs prior run</div>' +
        '</div>' +
      '</div>' +
      '<div style="background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:0.4rem 0.75rem;margin-bottom:0.75rem;font-size:0.72rem;color:var(--muted);display:flex;gap:1.25rem;flex-wrap:wrap">' +
        '<span>Total: <strong class="u-text">' + (s.totalTechniques || 0) + '</strong></span>' +
        '<span class="u-success">Pass: <strong>' + (s.passedTechniques || 0) + '</strong></span>' +
        '<span class="u-danger">Fail: <strong>' + (s.failedTechniques || 0) + '</strong></span>' +
        (s.skippedTechniques ? '<span>Skipped: <strong class="u-muted">' + s.skippedTechniques + '</strong></span>' : '') +
        (s.erroredTechniques ? '<span>Errored: <strong class="u-warning">' + s.erroredTechniques + '</strong></span>' : '') +
        '<span>Confidence: <strong class="u-text">' + (s.confidence || 0) + '%</strong></span>' +
        (s.previousPreventionScore ? '<span>Prev Prevention: <strong>' + Math.round(s.previousPreventionScore) + '%</strong></span>' : '') +
      '</div>';

    // Critical failures alert
    var cf = s.criticalFailures || [];
    if (cf.length > 0) {
      scorePanel +=
        '<div style="background:rgba(218,54,51,0.08);border:1px solid rgba(218,54,51,0.35);border-radius:3px;padding:0.5rem 0.75rem;margin-bottom:0.75rem">' +
          '<div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--danger);margin-bottom:0.35rem">⚠ ' + cf.length + ' Critical Failure' + (cf.length > 1 ? 's' : '') + '</div>' +
          cf.map(function(f) {
            var sc = f.severity === 'Critical' ? 'var(--danger)' : '#e5534b';
            return '<div style="display:flex;align-items:baseline;gap:0.5rem;padding:0.2rem 0;font-size:0.75rem;border-bottom:1px solid rgba(218,54,51,0.15)">' +
              '<span style="color:' + sc + ';font-weight:700;font-size:0.65rem;min-width:50px">' + x(f.severity) + '</span>' +
              (f.techniqueId ? '<code style="font-size:0.65rem;color:var(--muted)">' + x(f.techniqueId) + '</code>' : '') +
              '<span>' + x(f.name || '') + '</span>' +
              '<span style="color:var(--muted);font-size:0.68rem;margin-left:auto">' + x(f.tactic || '') + '</span>' +
            '</div>';
          }).join('') +
        '</div>';
    }

    // ATT&CK Tactic Breakdown — aggregate pass rate per tactic (mirrors the PDF
    // report's section 4). Sourced from the score.tacticBreakdown field; ordered
    // by kill-chain phase, colored with the same >=80/>=50 thresholds as the bars
    // elsewhere. Complements the per-check list below (aggregate vs itemized).
    var tb = s.tacticBreakdown || {};
    var tbKeys = Object.keys(tb);
    if (tbKeys.length > 0) {
      var tacticOrder = ['initial-access','execution','persistence','privilege-escalation',
        'defense-evasion','credential-access','discovery','lateral-movement','collection',
        'exfiltration','command-and-control','impact'];
      var ordered = tacticOrder.filter(function(t) { return tb[t]; })
        .concat(tbKeys.filter(function(t) { return tacticOrder.indexOf(t) < 0; }));
      var tbRows = ordered.map(function(t) {
        var e = tb[t];
        var pct = e.passPct || 0;
        var barCol = _riskScoreColor(pct);
        return '<div style="display:flex;align-items:center;gap:0.6rem;padding:0.28rem 0">' +
          '<span style="min-width:135px;font-size:0.72rem;text-transform:capitalize">' + x(t.replace(/-/g, ' ')) + '</span>' +
          '<div style="flex:1;height:7px;background:var(--bg);border-radius:4px;overflow:hidden">' +
            '<div style="height:100%;width:' + pct + '%;background:' + barCol + '"></div>' +
          '</div>' +
          '<span style="min-width:34px;text-align:right;font-size:0.72rem;font-weight:600;color:' + barCol + '">' + pct + '%</span>' +
          '<span style="min-width:92px;text-align:right;font-size:0.66rem;color:var(--muted)">' + (e.passed || 0) + ' pass · ' + (e.failed || 0) + ' fail</span>' +
        '</div>';
      }).join('');
      scorePanel +=
        '<div style="background:var(--elevated);border:1px solid var(--border);border-radius:4px;padding:0.6rem 0.75rem;margin-bottom:0.75rem">' +
          '<div style="' + labelStyle + ';margin-bottom:0.4rem">ATT&CK Tactic Breakdown</div>' +
          tbRows +
        '</div>';
    }
  }

  // Privilege-tier breakdown — always shown; shows "inherited" for unannotated steps
  (function() {
    var tiers = ['user', 'admin', 'system', 'user→admin', 'inherited'];
    var tierLabel  = { 'user': 'User', 'admin': 'Admin', 'system': 'SYSTEM', 'user→admin': 'User→Admin (fallback)', 'inherited': 'Inherited (unannotated)' };
    var tierColor  = { 'user': 'var(--accent)', 'admin': 'var(--warning)', 'system': 'var(--danger)', 'user→admin': 'var(--warning)', 'inherited': 'var(--muted)' };
    var counts = {};
    tiers.forEach(function(t) { counts[t] = { pass:0, fail:0, error:0, total:0 }; });
    results.forEach(function(c) {
      var tier = c.executedAs || 'inherited';
      if (!counts[tier]) counts[tier] = { pass:0, fail:0, error:0, total:0 };
      counts[tier].total++;
      if (c.result === 'pass') counts[tier].pass++;
      else if (c.result === 'fail') counts[tier].fail++;
      else if (c.result === 'error') counts[tier].error++;
    });
    var used = tiers.filter(function(t) { return counts[t] && counts[t].total > 0; });
    if (!used.length) return;
    var rows = used.map(function(t) {
      var tc = counts[t];
      var col = tierColor[t] || 'var(--muted)';
      // Bar shows the tier's whole pass/fail/error mix (stacked), not just
      // the fail share -- a fail-only bar renders identically empty for "0
      // failures out of many, all clean" and "nothing tested here," giving a
      // fully-passing tier zero visual signal even though real data exists.
      // failPct/errPct are rounded independently; passPct absorbs the
      // remainder so the three segments always sum to exactly 100% width
      // (no rounding-error gap in the track) whenever tc.total > 0.
      var failPct = tc.total ? Math.round(tc.fail * 100 / tc.total) : 0;
      var errPct  = tc.total ? Math.round(tc.error * 100 / tc.total) : 0;
      var passPct = tc.total ? Math.max(0, 100 - failPct - errPct) : 0;
      var failLabelPct = tc.total ? Math.round(tc.fail * 100 / tc.total) : 0;
      return '<div style="display:flex;align-items:center;gap:0.6rem;padding:0.28rem 0">' +
        '<span style="min-width:12px;height:12px;border-radius:2px;background:' + col + ';display:inline-block;flex-shrink:0"></span>' +
        '<span style="min-width:155px;font-size:0.72rem;color:' + col + '">' + x(tierLabel[t] || t) + '</span>' +
        '<div style="flex:1;height:7px;background:var(--bg);border-radius:4px;overflow:hidden;display:flex">' +
          (passPct ? '<div style="height:100%;width:' + passPct + '%;background:var(--success)"></div>' : '') +
          (failPct ? '<div style="height:100%;width:' + failPct + '%;background:var(--danger)"></div>' : '') +
          (errPct  ? '<div style="height:100%;width:' + errPct  + '%;background:var(--warning)"></div>' : '') +
        '</div>' +
        '<span style="min-width:40px;text-align:right;font-size:0.72rem;font-weight:600;color:var(--danger)">' + (failLabelPct ? failLabelPct + '%' : '—') + '</span>' +
        '<span style="min-width:110px;text-align:right;font-size:0.66rem;color:var(--muted)">' +
          tc.pass + ' pass · ' + tc.fail + ' fail' + (tc.error ? ' · ' + tc.error + ' err' : '') +
        '</span>' +
      '</div>';
    }).join('');
    var dimStyle2 = 'background:var(--elevated);border:1px solid var(--border);border-radius:4px;padding:0.6rem 0.75rem;margin-bottom:0.75rem';
    var labelStyle2 = 'color:var(--muted);font-size:0.6rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:0.4rem';
    scorePanel += '<div style="' + dimStyle2 + '"><div style="' + labelStyle2 + '">Privilege Tier Breakdown</div>' + rows + '</div>';
  })();

  window._evidenceResults = results;
  results.forEach(function(c, i) { c._eidx = i; });

  function resultColor(c) {
    // vetoed: B5's agent-side guardrail refused the step, a policy
    // decision -- not a defense failure, so it must not read as danger
    // (fix-pass's own scoped re-review of I3, which fixed this same
    // pattern elsewhere but missed this list).
    if (c.result === 'vetoed') return 'var(--warning)';
    return c.result === 'pass' ? 'var(--success)' : c.result === 'skipped' ? 'var(--muted)' : 'var(--danger)';
  }

  var byTactic = {};
  results.forEach(function(c) {
    var tactic = (c.technique && c.technique.tactic) || 'other';
    if (!byTactic[tactic]) byTactic[tactic] = [];
    byTactic[tactic].push(c);
  });

  var checksHtml = Object.keys(byTactic).map(function(tactic) {
    var checks = byTactic[tactic].map(function(c) {
      var col = resultColor(c);
      var fw = (c.framework || 'custom').toLowerCase();
      var fwColor = fw === 'art' ? 'var(--accent)' : fw === 'caldera' ? '#bc8cff' : 'var(--muted)';
      var fwBadge = '<span style="font-size:0.6rem;font-weight:700;text-transform:uppercase;background:rgba(255,255,255,0.06);color:' + fwColor + ';border-radius:2px;padding:1px 5px;margin-left:3px">' + x(fw) + '</span>';
      var privBadge = '';
      if (c.executedAs) {
        // "user→admin" = fallback (requested user, ran as admin — amber + tooltip explains)
        // "user" = blue, "system" = red, "admin" = amber
        var isFallback = c.executedAs.indexOf('→') !== -1;
        var privCol = c.executedAs === 'user' ? 'var(--accent)' : c.executedAs === 'system' ? 'var(--danger)' : 'var(--warning)';
        var privTitle = isFallback
          ? 'Requested: ' + x(c.requestedPriv || 'user') + ' — fell back to: admin (no interactive session)'
          : 'Executed as: ' + x(c.executedAs);
        privBadge = '<span style="font-size:0.6rem;font-weight:600;text-transform:uppercase;background:rgba(255,255,255,0.04);color:' + privCol + ';border-radius:2px;padding:1px 5px;margin-left:2px;border:1px solid ' + privCol + '33' + (isFallback ? ';text-decoration:line-through' : '') + '" title="' + privTitle + '">' + x(c.executedAs) + '</span>';
      } else {
        // Unannotated step — ran in agent's own security context (requires_priv not set in YAML)
        privBadge = '<span style="font-size:0.6rem;font-weight:500;text-transform:uppercase;background:rgba(255,255,255,0.02);color:var(--muted);border-radius:2px;padding:1px 5px;margin-left:2px;border:1px solid rgba(154,169,188,0.2)" title="Privilege tier not annotated — technique ran in the agent\'s own security context. Add requires_priv: user|admin|system to the scenario step YAML for explicit tracking.">inherited</span>';
      }
      var techId = (c.technique && c.technique.id) ? '<code style="font-size:0.68rem;color:var(--muted)">' + x(c.technique.id) + '</code> ' : '';
      var evidenceBtn = '<button onclick="openEvidence('+c._eidx+')" style="background:none;border:1px solid var(--border);border-radius:3px;color:var(--accent);cursor:pointer;font-size:0.6rem;padding:0.18rem 0.45rem;flex-shrink:0;margin-left:0.35rem;white-space:nowrap" title="View execution evidence">&#128269; Evidence</button>';
      return '<div style="padding:0.32rem 0;border-bottom:1px solid rgba(34,50,74,0.45)">' +
        '<div style="display:flex;align-items:center;gap:0.45rem;flex-wrap:wrap">' +
          '<span style="color:' + col + ';font-size:0.7rem;font-weight:600;min-width:46px">' + x(c.result) + '</span>' +
          techId + '<span style="font-size:0.8rem">' + x((c.technique && c.technique.name) || c.name || '') + '</span>' +
          fwBadge + privBadge + '<span style="color:var(--muted);font-size:0.68rem;margin-left:auto">' + x(c.severity || '') + '</span>' + evidenceBtn +
        '</div>' +
        (c.stepName && c.stepName !== ((c.technique && c.technique.name) || c.name) ? '<div style="color:var(--muted);font-size:0.7rem;padding-left:52px;margin-top:0.1rem">' + x(c.stepName) + '</div>' : '') +
        (c.details ? '<div style="color:var(--muted);font-size:0.72rem;padding-left:52px;margin-top:0.1rem">' + x(c.details) + '</div>' : '') +
        (c.result === 'fail' && c.threatImpact ? '<div style="color:var(--muted);font-size:0.7rem;padding-left:52px;margin-top:0.1rem">' + x(c.threatImpact) + '</div>' : '') +
        (c.result === 'fail' && c.remediation ? '<div style="color:var(--warning);font-size:0.7rem;padding-left:52px;margin-top:0.1rem;white-space:pre-wrap">' + x(c.remediation) + '</div>' : '') +
        '</div>';
    }).join('');
    return '<div style="margin-bottom:1.25rem">' +
      '<div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--accent);margin-bottom:0.45rem;padding-bottom:0.3rem;border-bottom:1px solid var(--border)">' + x(tactic) + '</div>' +
      checks + '</div>';
  }).join('');

  // Execution Timeline — chronological view of results[], sourced entirely
  // from data already fetched for this run (startedAt/executedAt/durationMs
  // already exist on every SimulationResult, models/schema.go:56-88). Steps
  // synthesized server-side without ever dispatching to the agent (e.g.
  // SkipReasonPolicyPrivilege) carry a zero-value time and are excluded --
  // an execution timeline for something that never executed is meaningless.
  // bestTime: StartedAt arrives straight from the agent's raw ExecResult
  // with no server-side fallback (unlike ExecutedAt, which defaults to
  // time.Now() when zero -- see scenario.Interpret), so an agent that
  // never populates it leaves a Go zero-value time.Time, which marshals to
  // "0001-01-01T00:00:00Z" -- a non-empty, truthy string, so a plain
  // `c.startedAt || c.executedAt` never actually falls through to the good
  // value. Same fix already applied to the Evidence panel's "Started at" /
  // Detection Timeline (see buildEvidenceHtml-equivalent code below).
  function bestTime(c) {
    if (c.startedAt && (new Date(c.startedAt)).getFullYear() > 2000) return new Date(c.startedAt);
    if (c.executedAt && (new Date(c.executedAt)).getFullYear() > 2000) return new Date(c.executedAt);
    return null;
  }
  var timelineHtml = (function() {
    var events = results.filter(function(c) {
      return bestTime(c) !== null;
    }).slice().sort(function(a, b) {
      return bestTime(a) - bestTime(b);
    });
    if (!events.length) {
      return '<div class="dash-panel dash-soon" style="padding:2rem;text-align:center;color:var(--muted);font-size:0.8rem">No timed execution data available for this run.</div>';
    }
    var rows = events.map(function(c) {
      var t = bestTime(c);
      var col = resultColor(c);
      var techId = (c.technique && c.technique.id) ? '<code style="font-size:0.68rem;color:var(--muted)">' + x(c.technique.id) + '</code> ' : '';
      var detBadge = c.detectionVerdict
        ? '<span style="font-size:0.6rem;font-weight:600;text-transform:uppercase;background:rgba(255,255,255,0.04);color:var(--accent);border-radius:2px;padding:1px 5px;margin-left:0.35rem">' + x(c.detectionVerdict) + '</span>'
        : '';
      var dur = c.durationMs ? (c.durationMs >= 1000 ? (c.durationMs / 1000).toFixed(1) + 's' : c.durationMs + 'ms') : '—';
      return '<div style="display:flex;align-items:baseline;gap:0.6rem;padding:0.4rem 0;border-bottom:1px solid rgba(34,50,74,0.45)">' +
        '<span style="min-width:78px;font-size:0.68rem;color:var(--muted);font-variant-numeric:tabular-nums">' + x(t.toLocaleTimeString()) + '</span>' +
        '<span style="min-width:56px;text-align:right;font-size:0.65rem;color:var(--muted);font-variant-numeric:tabular-nums">' + x(dur) + '</span>' +
        '<span style="color:' + col + ';font-size:0.7rem;font-weight:600;min-width:46px">' + x(c.result) + '</span>' +
        techId + '<span style="font-size:0.8rem;flex:1">' + x((c.technique && c.technique.name) || c.name || c.command || '') +
          (c.stepName && c.stepName !== ((c.technique && c.technique.name) || c.name) ? '<span style="color:var(--muted);font-size:0.7rem"> — ' + x(c.stepName) + '</span>' : '') + '</span>' +
        detBadge +
      '</div>';
    }).join('');
    return '<div style="padding:0.5rem 0">' + rows + '</div>';
  })();

  // MITRE ATT&CK tab — the full-tab version of the Overview's compact
  // "ATT&CK Tactic Breakdown" mini-panel (run.score.tacticBreakdown, already
  // computed per-run by models.ComputeScore), enriched with each tactic's
  // technique roll-up from byTactic (already grouped above for the Evidence
  // tab) so a tactic's aggregate bar and its individual techniques sit
  // together. No new backend call — both inputs already exist in this scope.
  var mitreHtml = (function() {
    var tb = (run.score && run.score.tacticBreakdown) || {};
    var tbKeys = Object.keys(tb);
    if (!tbKeys.length) {
      // Not a "coming soon" placeholder -- this tab is fully built, this run
      // just has no tactic breakdown to show. dash-soon's CSS stamps a
      // "Coming Soon" badge that would misleadingly say otherwise.
      return '<div class="dash-panel" style="padding:2rem;text-align:center;color:var(--muted);font-size:0.8rem">No ATT&CK tactic data available for this run.</div>';
    }
    var tacticOrder = ['initial-access','execution','persistence','privilege-escalation',
      'defense-evasion','credential-access','discovery','lateral-movement','collection',
      'exfiltration','command-and-control','impact'];
    var ordered = tacticOrder.filter(function(t) { return tb[t]; })
      .concat(tbKeys.filter(function(t) { return tacticOrder.indexOf(t) < 0; }));
    return ordered.map(function(t) {
      var e = tb[t];
      var pct = e.passPct || 0;
      var barCol = _riskScoreColor(pct);
      var techs = (byTactic[t] || []).map(function(c) {
        var col = resultColor(c);
        var techId = (c.technique && c.technique.id) ? '<code style="font-size:0.65rem;color:var(--muted)">' + x(c.technique.id) + '</code> ' : '';
        var detBadge = c.detectionVerdict
          ? '<span style="font-size:0.58rem;font-weight:600;text-transform:uppercase;color:var(--accent);margin-left:0.4rem">' + x(c.detectionVerdict) + '</span>'
          : '';
        return '<div style="display:flex;align-items:center;gap:0.4rem;padding:0.22rem 0;font-size:0.74rem">' +
          '<span style="color:' + col + ';font-weight:600;min-width:44px;font-size:0.65rem">' + x(c.result) + '</span>' +
          techId + '<span>' + x((c.technique && c.technique.name) || c.name || '') +
            (c.stepName && c.stepName !== ((c.technique && c.technique.name) || c.name) ? '<span style="color:var(--muted);font-size:0.68rem"> — ' + x(c.stepName) + '</span>' : '') + '</span>' + detBadge +
        '</div>';
      }).join('');
      return '<div class="dash-panel" style="margin-bottom:0.85rem"><div class="dash-panel-body" style="padding:0.75rem 0.9rem">' +
        '<div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.5rem">' +
          '<span style="font-size:0.8rem;font-weight:600;text-transform:capitalize;flex:1">' + x(t.replace(/-/g, ' ')) + '</span>' +
          '<span style="font-size:0.72rem;font-weight:700;color:' + barCol + '">' + pct + '%</span>' +
          '<span style="font-size:0.66rem;color:var(--muted)">' + (e.passed || 0) + ' pass &middot; ' + (e.failed || 0) + ' fail</span>' +
        '</div>' +
        '<div style="height:6px;background:var(--bg);border-radius:3px;overflow:hidden;margin-bottom:0.5rem">' +
          '<div style="height:100%;width:' + pct + '%;background:' + barCol + '"></div>' +
        '</div>' +
        (techs ? '<div style="border-top:1px solid var(--border);padding-top:0.4rem">' + techs + '</div>' : '') +
      '</div></div>';
    }).join('');
  })();

  // Endpoint Changes tab -- the agent already runs a whole-run before/after
  // snapshot (agent/snapshot_windows.go's captureSnapshot/revertFromSnapshot,
  // called once per run) and reverts anything new it finds (registry keys,
  // services, scheduled tasks, temp files, hosts file, startup entries),
  // returning one human-readable line per successfully-reverted item. That
  // list is already stored on every run (scenario_runs.reverted) and already
  // rendered in the PDF report (internal/reporting/pdf.go) -- this mirrors
  // the exact same framing text so the two surfaces agree. Changes that were
  // detected but FAILED to revert are not included here -- see
  // docs/superpowers/specs/2026-08-06-endpoint-changes-tab-design.md.
  var endpointHtml = (function() {
    var items = run.reverted || [];
    if (!items.length) {
      return '<div class="dash-panel dash-soon" style="padding:2rem;text-align:center;color:var(--muted);font-size:0.8rem">No endpoint changes were captured for reversal during this run.</div>';
    }
    var rows = items.map(function(item) {
      return '<div style="display:flex;align-items:baseline;gap:0.5rem;padding:0.3rem 0;border-bottom:1px solid rgba(34,50,74,0.45);font-size:0.78rem">' +
        '<span class="u-muted">&bull;</span><span>' + x(item) + '</span>' +
      '</div>';
    }).join('');
    return '<div style="padding:0.5rem 0">' +
      '<div style="color:var(--muted);font-size:0.78rem;margin-bottom:0.6rem">The agent reverted ' + items.length + ' endpoint change(s) made during the run.</div>' +
      rows +
    '</div>';
  })();

  // Overview keeps scorePanel + run-report-extra (findings/recommendations/
  // alert-fatigue/attack-surface-age/readiness); the per-technique checks
  // move to their own Evidence tab -- previously both lived in one "Results"
  // view together. rv-flow/rv-coverage/rv-siem keep their exact existing
  // IDs and lazy-load logic (see the apicall() calls right below this
  // block) -- only their container changed, from flat siblings behind a
  // 3-button switcher to named panels behind the new tab bar.
  var soonPanel = function(label) {
    return '<div class="dash-panel dash-soon" style="padding:2rem;text-align:center;color:var(--muted);font-size:0.8rem">' + x(label) + ' — real data not available for this run yet.</div>';
  };
  document.getElementById('run-tab-content').innerHTML =
    '<div id="run-tab-overview" class="run-tab-panel">' +
      '<div class="run-tab-grid">' +
        '<div>' + scorePanel + '</div>' +
        '<div id="run-report-extra"></div>' +
      '</div>' +
    '</div>' +
    '<div id="run-tab-findings" class="run-tab-panel" style="display:none">' +
      '<div id="run-report-findings"><div style="color:var(--muted);font-size:0.72rem;padding:1.5rem 0;text-align:center">Loading findings&#8230;</div></div>' +
    '</div>' +
    '<div id="run-tab-recommendation" class="run-tab-panel" style="display:none">' +
      '<div id="run-report-recommendation"><div style="color:var(--muted);font-size:0.72rem;padding:1.5rem 0;text-align:center">Loading recommendations&#8230;</div></div>' +
    '</div>' +
    '<div id="run-tab-flow" class="run-tab-panel" style="display:none">' +
      '<div id="rv-flow"><div style="color:var(--muted);font-size:0.72rem;padding:1.5rem 0;text-align:center">Loading attack flow…</div></div>' +
    '</div>' +
    '<div id="run-tab-variant" class="run-tab-panel" style="display:none">' +
      '<div id="rv-coverage"><div style="color:var(--muted);font-size:0.72rem;padding:1.5rem 0;text-align:center">Loading variant coverage&#8230;</div></div>' +
    '</div>' +
    '<div id="run-tab-detection" class="run-tab-panel" style="display:none"><div id="rv-siem"></div></div>' +
    '<div id="run-tab-evidence" class="run-tab-panel" style="display:none">' + checksHtml + '</div>' +
    '<div id="run-tab-reports" class="run-tab-panel" style="display:none"></div>' +
    '<div id="run-tab-timeline" class="run-tab-panel" style="display:none">' + timelineHtml + '</div>' +
    '<div id="run-tab-mitre" class="run-tab-panel" style="display:none">' + mitreHtml + '</div>' +
    '<div id="run-tab-iocs" class="run-tab-panel" style="display:none">' +
      '<div id="run-ioc-toolbar" style="display:flex;gap:0.6rem;align-items:center;margin-bottom:0.85rem;flex-wrap:wrap"></div>' +
      '<div id="run-ioc-list"><div style="color:var(--muted);font-size:0.72rem;padding:1.5rem 0;text-align:center">Loading indicators&#8230;</div></div>' +
    '</div>' +
    '<div id="run-tab-endpoint" class="run-tab-panel" style="display:none">' + endpointHtml + '</div>';

  var RUN_TABS = [
    ['overview', 'Overview'], ['findings', 'Key Findings'], ['recommendation', 'Recommendation'],
    ['timeline', 'Execution Timeline'], ['mitre', 'MITRE ATT&CK'],
    ['detection', 'Detection Validation'], ['flow', 'Attack Flow'], ['variant', 'Variant Analysis'],
    ['evidence', 'Evidence'], ['iocs', 'Indicators (IOCs)'], ['endpoint', 'Endpoint Changes'],
    ['reports', 'Reports']
  ];
  document.getElementById('run-tabbar').innerHTML = RUN_TABS.map(function(t, i) {
    return '<button class="run-tab-btn' + (i === 0 ? ' active' : '') + '" id="run-tabbtn-' + t[0] + '" onclick="switchRunTab(\'' + t[0] + '\')">' + x(t[1]) + '</button>';
  }).join('');

  document.getElementById('results-summary').style.display = 'none';
  document.getElementById('results-body').style.display = 'none';
  document.getElementById('run-kpi-strip').style.display = '';
  document.getElementById('run-tabbar').style.display = '';
  document.getElementById('run-tab-content').style.display = '';
  document.getElementById('results-overlay').classList.add('open');

  var reportsEl = document.getElementById('run-tab-reports');
  if (reportsEl) {
    if (hasOutput) {
      reportsEl.innerHTML =
        '<div class="dash-panel u-mb-1"><div class="dash-panel-hdr">Run Metadata</div><div class="dash-panel-body">' +
          '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:0.75rem;font-size:0.78rem">' +
            '<div><div class="kpi-label">Run ID</div><div>' + x(runId) + '</div></div>' +
            '<div><div class="kpi-label">Agent</div><div>' + x(run.agentId || '') + '</div></div>' +
            '<div><div class="kpi-label">Status</div><div>' + x(run.status || '') + '</div></div>' +
          '</div>' +
        '</div></div>' +
        '<div class="dash-panel"><div class="dash-panel-hdr">Export</div><div class="dash-panel-body" style="display:flex;gap:0.5rem;flex-wrap:wrap">' +
          '<button class="btn btn-sm btn-outline" onclick="exportRunJSON(\'' + runId + '\')">&#8595; JSON</button>' +
          '<button class="btn btn-sm btn-outline" onclick="openRunReport(\'' + runId + '\')">&#8599; HTML Report</button>' +
          '<button class="btn btn-sm btn-outline" onclick="downloadRunReport(\'' + runId + '\')">&#8595; PDF Report</button>' +
          '<button class="btn btn-sm btn-outline" onclick="downloadRunCSV(\'' + runId + '\')">&#8595; CSV</button>' +
        '</div></div>';
    } else {
      reportsEl.innerHTML = '<div style="color:var(--muted);font-size:0.8rem;padding:1rem 0">No exportable output yet — this run hasn\'t completed.</div>';
    }
  }

  // Overview dashboard panels + Key Findings + Prioritised Recommendations —
  // all fetched from the report engine (BuildFromRun, the same source as the
  // HTML/PDF report) so the drawer matches the formal report exactly. Each
  // renders into its own tab's placeholder once the single shared fetch loads.
  if (runId && (run.status === 'completed' || run.status === 'partial')) {
    var extraEl = document.getElementById('run-report-extra');
    extraEl.innerHTML = '<div style="color:var(--muted);font-size:0.72rem;padding:0.4rem 0">Loading&#8230;</div>';
    apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/report.json').then(function(rep) {
      // Guard: a different run may have been opened while this was in flight.
      if (document.getElementById('run-report-extra') === extraEl) {
        extraEl.innerHTML = renderRunReportExtra(rep);
        var findingsEl = document.getElementById('run-report-findings');
        if (findingsEl) findingsEl.innerHTML = renderRunFindings(rep);
        var recEl = document.getElementById('run-report-recommendation');
        if (recEl) recEl.innerHTML = renderRunRecommendations(rep);
        renderDetectionValidationTab(rep, run);
      }
    }).catch(function() {
      extraEl.innerHTML = '';
      var findingsEl = document.getElementById('run-report-findings');
      if (findingsEl) findingsEl.innerHTML = '<div style="color:var(--muted);font-size:0.8rem;padding:2.5rem 0;text-align:center">Findings unavailable.</div>';
      var recEl = document.getElementById('run-report-recommendation');
      if (recEl) recEl.innerHTML = '<div style="color:var(--muted);font-size:0.8rem;padding:2.5rem 0;text-align:center">Recommendations unavailable.</div>';
    });

    // Preload attack flow into rv-flow so the tab is ready when clicked.
    apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/attackflow').then(function(af) {
      var el = document.getElementById('rv-flow');
      if (el) el.innerHTML = renderAttackFlow(af.nodes || [], af.summary || {});
    }).catch(function() {
      var el = document.getElementById('rv-flow');
      if (el) el.innerHTML = '<div style="color:var(--muted);font-size:0.72rem;padding:1.5rem 0;text-align:center">Attack flow unavailable.</div>';
    });

    // Preload variant coverage into rv-coverage (no-op for runs with depth=none).
    apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/variant-coverage').then(function(cov) {
      var el = document.getElementById('rv-coverage');
      if (el) el.innerHTML = renderVariantCoverage(cov);
    }).catch(function() {
      var el = document.getElementById('rv-coverage');
      if (el) el.innerHTML = '<div style="color:var(--muted);font-size:0.72rem;padding:1.5rem 0;text-align:center">Variant coverage unavailable.</div>';
    });

    // Detection Validation tab is populated by renderDetectionValidationTab
    // above, as part of the shared report.json fetch -- it calls
    // loadSIEMCorrelationPanel itself as its own fallback branch when
    // detectionValidation.hasData is false, so no separate call here.

    // Indicators (IOCs) — extraction runs for every completed run regardless
    // of whether a threat-intel provider is configured (see GetRunIOCsEnriched);
    // fetch once, unfiltered, and filter/group client-side from then on.
    apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/iocs').then(function(iocs) {
      state._runIOCsAll = iocs || [];
      renderRunIOCToolbar();
      renderRunIOCList();
    }).catch(function() {
      state._runIOCsAll = [];
      var el = document.getElementById('run-ioc-list');
      if (el) el.innerHTML = '<div style="color:var(--muted);font-size:0.8rem;padding:2.5rem 0;text-align:center">Indicators unavailable.</div>';
    });
  } else {
    // Run hasn't completed -- nothing to fetch, so replace the "Loading…"
    // skeleton with an explicit not-yet-available state instead of leaving
    // it looking permanently stuck.
    var notReady = '<div style="color:var(--muted);font-size:0.8rem;padding:2.5rem 0;text-align:center">Available once this run completes.</div>';
    var findingsElEarly = document.getElementById('run-report-findings');
    if (findingsElEarly) findingsElEarly.innerHTML = notReady;
    var recElEarly = document.getElementById('run-report-recommendation');
    if (recElEarly) recElEarly.innerHTML = notReady;
    var iocElEarly = document.getElementById('run-ioc-list');
    if (iocElEarly) iocElEarly.innerHTML = notReady;
  }
}

// switchRunTab replaces switchResultsView: shows exactly one of RUN_TABS's
// panels and updates the active tab button, matching the same
// show/hide-by-id mechanism switchResultsView used, generalized to 11
// tabs instead of a hardcoded 3-4.
export function switchRunTab(tabId) {
  var content = document.getElementById('run-tab-content');
  if (!content) return;
  Array.prototype.forEach.call(content.querySelectorAll('.run-tab-panel'), function(panel) {
    panel.style.display = (panel.id === 'run-tab-' + tabId) ? '' : 'none';
  });
  Array.prototype.forEach.call(document.getElementById('run-tabbar').querySelectorAll('.run-tab-btn'), function(btn) {
    btn.classList.toggle('active', btn.id === 'run-tabbtn-' + tabId);
  });
}

// Status label map for the unified Detection Validation tab. Deliberately
// separate from vfStatusLabel (used by the analyst verification-review
// queue elsewhere in this file) -- that one says "SILENT" for NotDetected,
// a wording choice specific to that different audience. This tab uses the
// generic DETECTED/MISSED/NOT RUN wording the user explicitly requested,
// since this platform supports 6+ detection providers and "SIEM
// DETECTED/MISSED" is too narrow now that detectverify's connectors
// (Sentinel, Defender, Splunk, QRadar, CrowdStrike, Trellix) all feed in.
var DV_STATUS_LABEL = {
  Detected: 'DETECTED',
  NotDetected: 'MISSED',
  Pending: 'NOT RUN',
  Unknown: 'NOT RUN'
  // NotApplicable rows are filtered out before reaching this map -- see
  // renderDetectionValidationTab's .filter() call below.
};

// renderDetectionValidationTab renders internal/reporting.DetectionValidationSection
// (fetched as part of the shared report.json call) into the Detection
// Validation tab. This section already overlays detectverify's Verification
// Store attestations (Source=api, Provider=<connector>) on top of automatic
// on-host verdicts server-side (internal/reporting/detection_validation.go)
// -- this function only renders what's already been merged, it does not
// merge anything itself.
//
// Falls back to the legacy per-run SIEM bulk-correlation panel
// (loadSIEMCorrelationPanel, unchanged) when dv.hasData is false -- true for
// roughly 3/4 of runs today, since most scenarios don't yet declare
// detection_profiles. That fallback stays in place; this is additive, not
// a replacement.
function renderDetectionValidationTab(rep, run) {
  var el = document.getElementById('rv-siem');
  if (!el) return;
  var runId = (run && run.id) || '';
  var dv = rep && rep.detectionValidation;
  if (!dv || !dv.hasData) {
    loadSIEMCorrelationPanel(runId);
    return;
  }

  var coverage = dv.coverage || 0;
  var covColor = coverage >= 70 ? 'var(--success)' : coverage >= 40 ? 'var(--warning)' : 'var(--danger)';
  // Miss rate: percentage of *resolved* (Detected or NotDetected) expectations
  // that were NotDetected. Using dv.verified (not dv.expected) as the
  // denominator so an in-flight run with many still-Pending expectations
  // doesn't show an inflated miss rate for expectations nobody has checked
  // yet -- Pending rows are "not run", not "missed".
  var missRate = dv.verified > 0 ? Math.round(((dv.verified - dv.detected) / dv.verified) * 1000) / 10 : 0;
  // "Verified Findings" = dv.detected: a technique-scoped count of
  // expectations independently confirmed Detected, backed by connector/
  // on-host evidence -- not a raw alert tally, which the user explicitly
  // said not to present as if it were a detection-rate statistic.
  var verifiedFindings = dv.detected || 0;

  var sources = (rep.detectionSources || []).map(function(s) {
    return '<span style="display:inline-flex;align-items:center;gap:0.3rem;background:var(--elevated);border:1px solid var(--border);border-radius:999px;padding:0.15rem 0.6rem;font-size:0.72rem;color:var(--text)">' +
      '<span class="u-success">&#10003;</span>' + x(s.product) + '</span>';
  }).join(' ');

  var runTs = run && (run.completedAt || run.startedAt);
  var metaParts = [];
  if (runTs) metaParts.push('Verified: ' + new Date(runTs).toLocaleString());
  if (run && run.agentId) metaParts.push('Agent: <code>' + x(run.agentId) + '</code>');

  var rows = (dv.rows || [])
    .filter(function(row) { return row.status !== 'NotApplicable'; })
    .map(function(row) {
      var label = DV_STATUS_LABEL[row.status] || (row.status || 'NOT RUN').toUpperCase();
      var color = vfStatusColor(row.status);
      var badge = '<span style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '55;border-radius:3px;font-size:0.67rem;font-weight:700;padding:0.1rem 0.4rem">' + x(label) + '</span>';
      var providerBadge = row.provider
        ? '<span style="font-size:0.68rem;color:var(--muted);background:var(--elevated);border:1px solid var(--border);border-radius:3px;padding:0.03rem 0.3rem">' + x(row.provider) + '</span>'
        : '<span class="u-muted">&mdash;</span>';
      return '<tr><td style="font-family:monospace;font-size:0.72rem;padding:0.3rem 0.5rem">' + x(row.techniqueId) + '</td>' +
             '<td style="padding:0.3rem 0.5rem">' + badge + '</td>' +
             '<td style="padding:0.3rem 0.5rem">' + providerBadge + '</td>' +
             '<td style="font-size:0.72rem;color:var(--muted);text-transform:capitalize;padding:0.3rem 0.5rem">' + x(row.domain || '') + '</td></tr>';
    }).join('');

  el.innerHTML =
    '<div style="padding:1rem 0 0.5rem">' +
      '<div style="display:flex;gap:1.5rem;margin-bottom:0.75rem;flex-wrap:wrap">' +
        '<div class="u-center">' +
          '<div style="font-size:1.7rem;font-weight:700;color:' + covColor + '">' + coverage + '%</div>' +
          '<div style="font-size:0.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">Detection Coverage</div>' +
        '</div>' +
        '<div class="u-center">' +
          '<div style="font-size:1.7rem;font-weight:700;color:var(--danger)">' + missRate + '%</div>' +
          '<div style="font-size:0.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">Detection Miss Rate</div>' +
        '</div>' +
        '<div class="u-center">' +
          '<div style="font-size:1.7rem;font-weight:700">' + verifiedFindings + '</div>' +
          '<div style="font-size:0.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">Verified Findings</div>' +
        '</div>' +
      '</div>' +
      (sources ? '<div style="margin-bottom:0.5rem;font-size:0.7rem;color:var(--muted)">Verification source:</div><div style="display:flex;gap:0.4rem;flex-wrap:wrap;margin-bottom:0.75rem">' + sources + '</div>' : '') +
      (metaParts.length ? '<div style="font-size:0.68rem;color:var(--muted);margin-bottom:0.75rem">' + metaParts.join(' &nbsp;|&nbsp; ') + '</div>' : '') +
      '<table style="width:100%;border-collapse:collapse;font-size:0.73rem">' +
        '<thead><tr style="border-bottom:1px solid var(--border);color:var(--muted);font-size:0.67rem;text-align:left">' +
          '<th style="padding:0.3rem 0.5rem">Technique</th>' +
          '<th style="padding:0.3rem 0.5rem">Detection</th>' +
          '<th style="padding:0.3rem 0.5rem">Source</th>' +
          '<th style="padding:0.3rem 0.5rem">Domain</th>' +
        '</tr></thead>' +
        '<tbody>' + (rows || '<tr><td colspan="4" style="color:var(--muted);padding:1rem 0;text-align:center">No technique details available</td></tr>') + '</tbody>' +
      '</table>' +
    '</div>';
}

export function loadSIEMCorrelationPanel(runId) {
  apicall('/api/siem/correlations/' + encodeURIComponent(runId)).then(function(corrs) {
    var el = document.getElementById('rv-siem');
    if (!el) return;
    if (!corrs || corrs.length === 0) return; // no correlation yet — Detection Validation tab stays empty
    var c = corrs[0]; // most recent correlation
    var detRate = c.detectionRate || 0;
    var undetRate = c.undetectedRate || 0;
    var color = detRate >= 70 ? 'var(--success)' : detRate >= 40 ? 'var(--warning)' : 'var(--danger)';
    var rows = '';
    if (c.report && c.report.techniques) {
      c.report.techniques.forEach(function(t) {
        if (t.siemVerdict === 'not_applicable') return;
        var badge = '';
        if (t.siemVerdict === 'detected') badge = '<span style="background:var(--success);color:#fff;padding:0.12rem 0.45rem;border-radius:4px;font-size:0.67rem;font-weight:600">SIEM DETECTED</span>';
        else if (t.siemVerdict === 'undetected') badge = '<span style="background:var(--danger);color:#fff;padding:0.12rem 0.45rem;border-radius:4px;font-size:0.67rem;font-weight:600">SIEM MISSED</span>';
        else badge = '<span style="background:var(--muted);color:#fff;padding:0.12rem 0.45rem;border-radius:4px;font-size:0.67rem;font-weight:600">NOT RUN</span>';
        var alerts = t.alertCount ? (' <span style="color:var(--muted);font-size:0.67rem">(' + t.alertCount + ' alert' + (t.alertCount > 1 ? 's' : '') + ')</span>') : '';
        rows += '<tr><td style="font-family:monospace;font-size:0.72rem">' + x(t.techniqueId) + '</td>' +
                '<td style="font-size:0.73rem">' + x(t.techniqueName || '') + '</td>' +
                '<td>' + badge + alerts + '</td>' +
                '<td style="font-size:0.72rem;color:var(--muted)">' + x(t.basVerdict || '') + '</td></tr>';
      });
    }
    el.innerHTML =
      '<div style="padding:1rem 0 0.5rem">' +
        '<div style="display:flex;gap:1.5rem;margin-bottom:1rem;flex-wrap:wrap">' +
          '<div class="u-center">' +
            '<div style="font-size:1.7rem;font-weight:700;color:' + color + '">' + detRate + '%</div>' +
            '<div style="font-size:0.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">SIEM Detection Rate</div>' +
          '</div>' +
          '<div class="u-center">' +
            '<div style="font-size:1.7rem;font-weight:700;color:var(--danger)">' + undetRate + '%</div>' +
            '<div style="font-size:0.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">SIEM Miss Rate</div>' +
          '</div>' +
          '<div class="u-center">' +
            '<div style="font-size:1.7rem;font-weight:700">' + (c.totalAlerts || 0) + '</div>' +
            '<div style="font-size:0.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">Total Alerts</div>' +
          '</div>' +
          '<div style="font-size:0.68rem;color:var(--muted);align-self:center">' +
            'Source: <b>' + x(c.provider || '') + '</b> &nbsp;|&nbsp; ' +
            'Agent IP: <code>' + x(c.agentIp || '') + '</code> &nbsp;|&nbsp; ' +
            'Correlated: ' + new Date(c.correlatedAt).toLocaleString() +
          '</div>' +
        '</div>' +
        '<table style="width:100%;border-collapse:collapse;font-size:0.73rem">' +
          '<thead><tr style="border-bottom:1px solid var(--border);color:var(--muted);font-size:0.67rem">' +
            '<th style="text-align:left;padding:0.3rem 0">Tech ID</th>' +
            '<th style="text-align:left;padding:0.3rem 0.5rem">Name</th>' +
            '<th style="text-align:left;padding:0.3rem 0.5rem">SIEM</th>' +
            '<th style="text-align:left;padding:0.3rem 0">BAS</th>' +
          '</tr></thead>' +
          '<tbody>' + (rows || '<tr><td colspan="4" style="color:var(--muted);padding:1rem 0;text-align:center">No technique details available</td></tr>') + '</tbody>' +
        '</table>' +
      '</div>';
  }).catch(function() {}); // silent — SIEM correlation is optional
}