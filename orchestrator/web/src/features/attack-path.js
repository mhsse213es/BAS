import { state } from '../core/state.js';
import { on } from '../core/actions.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { ago, fmtDate, showToast } from '../core/util.js';
import { _templates, renderTemplateGrid } from './adversaries.js';
import { _agtDetailId, loadAgtAttackPath } from './agent-drawer.js';
import { loadAuditLogs, loadBackups, loadLicenseInfo } from './audit-logs.js';
import { loadCalderaStatus } from './compliance.js';
import { loadUsers } from './evidence.js';
import { loadOpenAEVConfig, renderAttackPath } from './openaev.js';
import { loadRuns, loadSIEMCorrelationPanel } from './reports.js';
import { SCHED, renderScheduledAssessmentsList } from './scheduled.js';
import { ROLE, STRIPE_COLORS, scenarioSrcCollapsed, setAgentsView } from './shell.js';
import { loadARTContentStatus, loadConnectorStatus, loadTAXIIConnectors, loadThreatIntelConfig } from './threat-intel.js';


// ── Attack Path Validation ─────────────────────────────────────────────────
export function loadAttackPath() {
  var body = document.getElementById('ap-body');
  if (body) body.innerHTML = '<div class="empty" style="padding:2rem">Loading…</div>';
  Promise.all([
    apicall('/api/attackpath/summary'),
    apicall('/api/attackpath/correlation').catch(function() { return null; })
  ]).then(function(res) {
    var d = res[0], corr = res[1];
    // Restore in-flight job state from server after a page reload.
    var saved = _apLoadJobId();
    if (saved && saved.jobId && !_apCurrentJobId) {
      apicall('/api/attackpath/jobs/' + saved.jobId).then(function(job) {
        var terminal = ['completed','failed','timed_out','delivery_failed','cancelled'];
        if (terminal.indexOf(job.status) === -1) {
          // Job still active — restore progress panel so the user can watch it.
          _apCurrentJobId = job.id;
          _apCollectAgentId = job.agentId;
          var panel = document.getElementById('ap-collect');
          if (panel) {
            panel.style.display = '';
            document.getElementById('ap-form').style.display = 'none';
            document.getElementById('ap-progress').style.display = '';
            _apRenderJobState(job);
          }
        } else if (job.status === 'completed') {
          _apClearJobId();
          showToast('Attack-path collection completed while you were away — results ready.', 'ok');
        } else {
          _apClearJobId();
          showToast('Attack-path job ended with status: ' + job.status, 'warn');
        }
      }).catch(function() { _apClearJobId(); });
    }
    renderAttackPath(d, corr);
  }).catch(function(e) { showToast(e.message, 'err'); });
}
export function apColor(score) {
  return score >= 80 ? 'var(--success)' : score >= 60 ? 'var(--warning)' : score >= 40 ? '#f0883e' : 'var(--danger)';
}
export function apBandColor(band) {
  return band === 'Low' ? 'var(--success)' : band === 'Medium' ? 'var(--warning)' : band === 'High' ? '#f0883e' : 'var(--danger)';
}
export function apFreshness(ageMs) {
  if (ageMs == null || ageMs < 0) return { label: '—', color: 'var(--muted)' };
  var hours = ageMs / 3600000;
  if (hours < 24) return { label: 'Fresh', color: 'var(--success)' };
  if (hours < 24 * 7) return { label: 'Aging', color: 'var(--warning)' };
  return { label: 'Stale', color: 'var(--danger)' };
}
export function apCard(label, val, col, sub) {
  return '<div class="kpi-card"><div class="kpi-label">' + label + '</div>' +
    '<div class="kpi-value" style="color:' + col + '">' + val + '</div>' +
    '<div class="tiny muted">' + (sub || '') + '</div></div>';
}

export function loadExposureAssets() {
  var body = document.getElementById('exp-table-body');
  body.innerHTML = '<tr><td colspan="8" class="empty">Loading…</td></tr>';
  apicall('/api/exposure/assets').then(function(assets) {
    if (!assets || !assets.length) {
      body.innerHTML = '<tr><td colspan="8" class="empty">No assets found — enroll an agent or run attack-path collection.</td></tr>';
      return;
    }
    body.innerHTML = assets.map(function(a) {
      return '<tr class="u-pointer" onclick="openExposureDetail(\'' + x(a.asset.hostKey) + '\')">' +
        '<td class="u-fw600">' + x(a.asset.label) + '</td>' +
        '<td>' + (a.asset.managed ? '<span class="badge">Managed</span>' : '<span class="badge u-muted">Discovered</span>') + '</td>' +
        '<td style="color:' + apColor(a.exposureScore) + ';font-weight:700">' + a.exposureScore + '</td>' +
        '<td>' + a.attackPathScore + '</td>' +
        '<td>' + a.detectionCoverageScore + '</td>' +
        '<td>' + (a.asset.crownJewel ? '<span class="badge" style="color:var(--warning);border-color:var(--warning)">' + x(a.asset.crownJewel) + '</span>' : '') + '</td>' +
        '<td>' + a.openFindingsCount + '</td>' +
        '<td>' + (a.kevExposed ? '<span class="badge" style="color:var(--danger);border-color:var(--danger)">KEV</span>' : '') + '</td>' +
        '</tr>';
    }).join('');
  }).catch(function(e) {
    body.innerHTML = '<tr><td colspan="8" class="empty u-danger">Failed to load: ' + x(e.message) + '</td></tr>';
  });
}

export function loadExecDashboard() {
  var rangeEl = document.getElementById('ed-range');
  var days = rangeEl ? rangeEl.value : '90';
  Promise.all([
    apicall('/api/dashboard/current'),
    apicall('/api/dashboard/trends?days=' + encodeURIComponent(days)),
    apicall('/api/predict/risk')
  ]).then(function(res) {
    renderExecDashboard(res[0], res[1]);
    renderForecast(res[2] && res[2].forecast);
    renderExposure(res[2] && res[2].exposure);
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function edSparkline(values) {
  if (!values.length) return '';
  var w = 140, h = 32;
  var min = Math.min.apply(null, values), max = Math.max.apply(null, values);
  var range = (max - min) || 1;
  var pts = values.map(function(v, i) {
    var px = values.length > 1 ? (i / (values.length - 1)) * w : w;
    var y = h - ((v - min) / range) * h;
    return px.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
  return '<svg class="stat-spark" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">' +
    '<polyline points="' + pts + '" fill="none" stroke="var(--accent)" stroke-width="1.6"/></svg>';
}

function edTrendChip(values) {
  if (values.length < 2) return '';
  var cur = values[values.length - 1];
  var priorIdx = Math.max(0, values.length - 8); // ~7 data points back
  var delta = cur - values[priorIdx];
  if (delta === 0) return '<span class="tiny muted">flat</span>';
  var up = delta > 0;
  var col = up ? 'var(--success)' : 'var(--danger)';
  return '<span class="tiny" style="color:' + col + '">' + (up ? '▲' : '▼') + ' ' + Math.abs(delta) + '</span>';
}

// noDataYet suppresses the number/trend/sparkline in favor of a "No data
// yet" note -- used for Exposure Score/Detection Coverage when
// !hasAttackPathData, where the underlying computation reads a vacuous 100
// (see dashboard.Snapshot.HasAttackPathData's doc comment) rather than a
// real score, so showing that 100 as-is would misrepresent an unscanned
// fleet as a perfectly-defended one.
function edKpiCard(label, current, trendSeries, noDataYet) {
  var valueBlock = noDataYet
    ? '<div class="kpi-value u-muted">—</div><span class="tiny muted">No data yet</span>'
    : '<div class="kpi-value">' + current + '</div>' + edTrendChip(trendSeries);
  return '<div class="kpi-card stat-tile">' +
    '<div class="stat-top"><div>' +
      '<div class="kpi-label">' + label + '</div>' +
      valueBlock +
    '</div></div>' +
    (noDataYet ? '' : edSparkline(trendSeries)) +
  '</div>';
}

function renderExecDashboard(current, trends) {
  var el = document.getElementById('ed-kpi-row');
  if (!el) return;
  var risk = trends.map(function(p) { return p.avgRiskScore; });
  var exp = trends.map(function(p) { return p.exposureScore; });
  var det = trends.map(function(p) { return p.detectionCoverage; });
  var cnt = trends.map(function(p) { return p.assetCount; });
  var noAttackPathData = !current.hasAttackPathData;
  el.innerHTML =
    edKpiCard('Risk Score', current.avgRiskScore, risk) +
    edKpiCard('Exposure Score', current.exposureScore, exp, noAttackPathData) +
    edKpiCard('Detection Coverage', current.detectionCoverage, det, noAttackPathData) +
    edKpiCard('Fleet Assets', current.assetCount, cnt);
}

function edForecastChart(fc) {
  var hist = (fc && fc.history) || [];
  var proj = (fc && fc.hasForecast && fc.projected) ? fc.projected : [];
  var all = hist.concat(proj);
  if (all.length < 2) return '';
  var w = 520, h = 120, pad = 10;
  var xs = all.map(function(p) { return p.dayIndex; });
  var minX = Math.min.apply(null, xs), maxX = Math.max.apply(null, xs);
  var rangeX = (maxX - minX) || 1;
  var vals = [];
  all.forEach(function(p) {
    vals.push(p.score);
    if (typeof p.high === 'number') vals.push(p.high);
    if (typeof p.low === 'number') vals.push(p.low);
  });
  var minY = Math.min.apply(null, vals), maxY = Math.max.apply(null, vals);
  var rangeY = (maxY - minY) || 1;
  function sx(dx) { return pad + ((dx - minX) / rangeX) * (w - 2 * pad); }
  function sy(v) { return (h - pad) - ((v - minY) / rangeY) * (h - 2 * pad); }
  var svg = '<svg width="100%" height="' + h + '" viewBox="0 0 ' + w + ' ' + h +
    '" preserveAspectRatio="none" style="max-width:100%;margin-top:0.5rem">';
  if (proj.length) {
    var top = proj.map(function(p) { return sx(p.dayIndex).toFixed(1) + ',' + sy(p.high).toFixed(1); });
    var bot = proj.slice().reverse().map(function(p) { return sx(p.dayIndex).toFixed(1) + ',' + sy(p.low).toFixed(1); });
    svg += '<polygon points="' + top.concat(bot).join(' ') + '" fill="var(--accent)" opacity="0.12"/>';
  }
  var histPts = hist.map(function(p) { return sx(p.dayIndex).toFixed(1) + ',' + sy(p.score).toFixed(1); }).join(' ');
  svg += '<polyline points="' + histPts + '" fill="none" stroke="var(--accent)" stroke-width="1.8"/>';
  if (proj.length && hist.length) {
    var last = hist[hist.length - 1];
    var projPts = [sx(last.dayIndex).toFixed(1) + ',' + sy(last.score).toFixed(1)]
      .concat(proj.map(function(p) { return sx(p.dayIndex).toFixed(1) + ',' + sy(p.score).toFixed(1); })).join(' ');
    svg += '<polyline points="' + projPts + '" fill="none" stroke="var(--accent)" stroke-width="1.6" stroke-dasharray="4 3"/>';
  }
  svg += '</svg>';
  return svg;
}

function edDirectionLabel(fc) {
  var d = (fc && fc.direction) || 'unknown';
  var col = 'var(--muted)';
  if (d === 'improving') col = 'var(--success)';
  else if (d === 'worsening') col = 'var(--danger)';
  return '<span style="color:' + col + ';font-weight:700;text-transform:capitalize">' + x(d) + '</span>';
}

function renderForecast(fc) {
  var el = document.getElementById('ed-forecast');
  if (!el) return;
  if (!fc) { el.innerHTML = ''; return; }
  var conf = (fc.confidence && fc.confidence !== 'none')
    ? '<span class="badge">' + x(fc.confidence) + ' confidence</span>' : '';
  var chart = edForecastChart(fc);
  var note = !fc.hasForecast
    ? '<div class="tiny muted" style="margin-top:0.4rem">' + x(fc.note || 'Insufficient history for a forecast.') + '</div>'
    : '';
  el.innerHTML = '<div class="card" style="margin-top:1rem;padding:1rem">' +
    '<div style="display:flex;justify-content:space-between;align-items:center">' +
      '<div><span class="kpi-label">Risk-score forecast</span> &nbsp;' + edDirectionLabel(fc) + '</div>' +
      conf +
    '</div>' +
    (chart || '<div class="tiny muted" style="margin-top:0.4rem">Not enough data to chart yet.</div>') +
    note +
  '</div>';
}

function renderExposure(exp) {
  var el = document.getElementById('ed-exposure');
  if (!el) return;
  if (!exp || !exp.hasData) {
    el.innerHTML = '<div class="card" style="margin-top:1rem;padding:1rem">' +
      '<span class="kpi-label">Open exposure windows</span>' +
      '<div class="tiny muted" style="margin-top:0.4rem">No open findings.</div></div>';
    return;
  }
  function stat(l, v) { return '<div><div class="kpi-label">' + l + '</div><div class="kpi-value">' + v + '</div></div>'; }
  var strip = '<div style="display:flex;gap:1.75rem;margin:0.5rem 0 0.75rem">' +
    stat('Open', exp.openCount) + stat('Worst days', exp.worstDaysOpen) +
    stat('Median days', exp.medianDaysOpen) + stat('Over ' + exp.thresholdDays + 'd', exp.overThreshold) + '</div>';
  var rows = (exp.worst || []).map(function(it) {
    var over = it.daysOpen > exp.thresholdDays;
    return '<tr>' +
      '<td><div class="u-fw600">' + x(it.techniqueId) + '</div>' +
        '<div class="tiny muted">' + x(it.techniqueName) + '</div></td>' +
      '<td class="tiny">' + x(it.severity) + '</td>' +
      '<td style="' + (over ? 'color:var(--danger);font-weight:700' : '') + '">' + it.daysOpen + '</td>' +
      '<td class="tiny">' + x(it.firstSeen) + '</td>' +
      '<td>' + (it.reopenedCount
        ? '<span class="badge" style="color:var(--warning);border-color:var(--warning)">&times;' + it.reopenedCount + '</span>'
        : '<span class="tiny muted">&mdash;</span>') + '</td>' +
      '</tr>';
  }).join('');
  el.innerHTML = '<div class="card" style="margin-top:1rem;padding:1rem">' +
    '<span class="kpi-label">Open exposure windows</span>' + strip +
    '<div class="tbl-wrap"><table><thead><tr>' +
      '<th>Technique</th><th>Severity</th><th>Days open</th><th>First seen</th><th>Reopened</th>' +
    '</tr></thead><tbody>' + rows + '</tbody></table></div>' +
  '</div>';
}

var REC_SCENARIO = null;

function recTierColor(tier) {
  return tier === 'Critical' ? 'var(--danger)'
       : tier === 'High'     ? '#f0883e'
       : tier === 'Medium'   ? 'var(--warning)'
       : 'var(--muted)';
}

function recCoverageBadge(coverage) {
  if (coverage === 'never-tested') return '<span class="badge" style="color:var(--danger);border-color:var(--danger)">Never tested</span>';
  if (coverage === 'stale')        return '<span class="badge" style="color:var(--warning);border-color:var(--warning)">Stale</span>';
  return '<span class="badge u-muted">Recent</span>';
}

function covStatusCell(val) {
  if (val === null) return '<span class="tiny muted">N/A</span>';
  return val ? '<span class="u-success">&#10003;</span>' : '<span class="tiny muted">&mdash;</span>';
}

export function loadCoverageActors() {
  var sel = document.getElementById('cov-actor-select');
  apicall('/api/coverage/actors')
    .then(function(data) {
      var actors = (data && data.actors) || [];
      actors.forEach(function(name) {
        var opt = document.createElement('option');
        opt.value = name;
        opt.textContent = name;
        sel.appendChild(opt);
      });
    })
    .catch(function(e) { console.error('loadCoverageActors failed', e); });
}

export function loadCoverageMatrix() {
  var sel = document.getElementById('cov-actor-select');
  var actor = sel ? sel.value : '';
  var body = document.getElementById('cov-matrix-body');
  var empty = document.getElementById('cov-matrix-empty');
  body.innerHTML = '<tr><td colspan="6" class="empty">Loading&hellip;</td></tr>';
  var url = '/api/coverage/matrix' + (actor ? '?actor=' + encodeURIComponent(actor) : '');
  apicall(url)
    .then(function(rows) {
      rows = rows || [];
      if (!rows.length) {
        body.innerHTML = '';
        empty.style.display = '';
        return;
      }
      empty.style.display = 'none';
      body.innerHTML = rows.map(function(r) {
        return '<tr>' +
          '<td class="u-fw600">' + x(r.techniqueId) + '</td>' +
          '<td>' + covStatusCell(r.simulationExists) + '</td>' +
          '<td>' + covStatusCell(r.detectionProfileExists) + '</td>' +
          '<td>' + covStatusCell(r.purpleExerciseExists) + '</td>' +
          '<td>' + covStatusCell(r.complianceMappingExists) + '</td>' +
          '<td>' + covStatusCell(r.responsePlaybookExists) + '</td>' +
          '</tr>';
      }).join('');
    })
    .catch(function(e) {
      body.innerHTML = '<tr><td colspan="6" class="empty u-danger">Failed to load: ' + x(e.message) + '</td></tr>';
    });
}

var TP_ACTOR_CACHE = [];

export function showThreatPriorityList() {
  document.getElementById('tp-list-view').style.display = '';
  document.getElementById('tp-detail-view').style.display = 'none';
}

export function tpTierBadge(tier) {
  var color = tier === 'Critical' ? 'var(--danger)' : tier === 'High' ? 'var(--warning)' : tier === 'Medium' ? 'var(--accent)' : 'var(--muted)';
  return '<span class="badge" style="color:' + color + ';border-color:' + color + '">' + x(tier || 'Low') + '</span>';
}

function tpTrendCell(trend, delta) {
  if (trend === 'up') return '<span class="u-success">&#9650; +' + delta + '</span>';
  if (trend === 'down') return '<span class="u-danger">&#9660; ' + delta + '</span>';
  if (trend === 'stable') return '<span class="tiny muted">&mdash;</span>';
  return '<span class="tiny muted">New</span>';
}

export function loadThreatPriorityActors() {
  var body = document.getElementById('tp-list-body');
  var empty = document.getElementById('tp-list-empty');
  body.innerHTML = '<tr><td colspan="5" class="empty">Loading&hellip;</td></tr>';
  apicall('/api/threat-priority/actors')
    .then(function(actors) {
      TP_ACTOR_CACHE = actors || [];
      if (!TP_ACTOR_CACHE.length) {
        body.innerHTML = '';
        empty.style.display = '';
        return;
      }
      empty.style.display = 'none';
      body.innerHTML = TP_ACTOR_CACHE.map(function(a) {
        return '<tr class="u-pointer" onclick=\'showThreatPriorityDetail(' + JSON.stringify(a.actorName).replace(/'/g, "&#39;") + ')\'>' +
          '<td class="u-fw600">' + x(a.actorName) + '</td>' +
          '<td>' + tpTierBadge(a.tier) + '</td>' +
          '<td>' + x(a.score) + '</td>' +
          '<td>' + tpTrendCell(a.trend, a.trendDelta) + '</td>' +
          '<td>' + x(a.coverageGapCount) + ' of ' + x(a.techniqueCount) + '</td>' +
          '</tr>';
      }).join('');
    })
    .catch(function(e) {
      body.innerHTML = '<tr><td colspan="5" class="empty u-danger">Failed to load: ' + x(e.message) + '</td></tr>';
    });
}

export function showThreatPriorityDetail(actorName) {
  document.getElementById('tp-list-view').style.display = 'none';
  document.getElementById('tp-detail-view').style.display = '';
  document.getElementById('tp-detail-title').textContent = actorName;

  apicall('/api/threat-priority/actors/' + encodeURIComponent(actorName))
    .then(function(d) { renderThreatPriorityDetail(d); })
    .catch(function(e) {
      document.getElementById('tp-detail-factors').innerHTML = '<div class="empty u-danger">Failed to load: ' + x(e.message) + '</div>';
    });
}

function renderThreatPriorityDetail(d) {
  document.getElementById('tp-detail-title').innerHTML = x(d.actorName) +
    (d.canonicalGroupId ? '  <span class="tiny muted" style="font-weight:400">&middot; MITRE ' + x(d.canonicalGroupId) + '</span>' : '');

  document.getElementById('tp-detail-summary').innerHTML =
    '<div class="kpi-card"><div class="kpi-label">Score</div><div class="kpi-value">' + x(d.score) + '</div></div>' +
    '<div class="kpi-card"><div class="kpi-label">Tier</div><div class="kpi-value">' + tpTierBadge(d.tier) + '</div></div>' +
    '<div class="kpi-card"><div class="kpi-label">Techniques</div><div class="kpi-value">' + x(d.techniqueCount) + '</div></div>' +
    '<div class="kpi-card"><div class="kpi-label">Coverage Gap</div><div class="kpi-value">' + x(d.coverageGapCount) + '</div></div>';

  var factors = (d.factors || []).map(function(f) {
    var val = f.available ? f.rawScore.toFixed(0) + '%' : 'Not yet validated';
    return '<div style="display:flex;justify-content:space-between;padding:0.4rem 0;border-bottom:1px solid var(--border)">' +
      '<div><div class="u-fw600">' + x(f.name) + '</div><div class="tiny muted">' + x(f.explanation) + '</div></div>' +
      '<div style="font-weight:700">' + x(val) + '</div>' +
      '</div>';
  }).join('');
  document.getElementById('tp-detail-factors').innerHTML = factors || '<div class="empty">No factor data.</div>';

  var uncovered = (d.uncoveredTechniques || []);
  document.getElementById('tp-detail-uncovered').innerHTML = uncovered.length
    ? uncovered.map(function(t) { return '<span class="tool-tag">' + x(t) + '</span>'; }).join(' ')
    : '<span class="muted">No coverage gaps.</span>';

  var techSourceLabel = {
    mitre: 'Techniques: MITRE-authoritative',
    connector: 'Techniques: connector-derived (not yet MITRE-confirmed)'
  }[d.techniqueSource] || '';
  document.getElementById('tp-detail-technique-source').textContent = techSourceLabel;

  var techCoverage = (d.techniqueCoverage || []);
  document.getElementById('tp-detail-coverage').innerHTML = techCoverage.length
    ? '<table class="u-w100"><thead><tr><th>Technique</th><th>Content</th><th>Prevention</th><th>Detection</th></tr></thead><tbody>' +
      techCoverage.map(function(tc) {
        var content = [
          tc.hasSimulation ? '<span class="tool-tag">Sim</span>' : '',
          tc.hasDetection ? '<span class="tool-tag">Detect</span>' : '',
          tc.hasCompliance ? '<span class="tool-tag">Compliance</span>' : ''
        ].filter(Boolean).join(' ') || '<span class="muted">&mdash;</span>';
        var label = tc.techniqueName ? tc.techniqueName + ' (' + tc.techniqueId + ')' : tc.techniqueId;
        var prevention = tc.preventionVerdict ? x(tc.preventionVerdict) : '<span class="muted">&mdash;</span>';
        var detection = tc.detectionVerdict ? x(tc.detectionVerdict) : '<span class="muted">&mdash;</span>';
        return '<tr><td>' + x(label) + '</td><td>' + content + '</td><td>' + prevention + '</td><td>' + detection + '</td></tr>';
      }).join('') +
      '</tbody></table>'
    : '<span class="muted">No technique data.</span>';

  var sources = (d.sources || []);
  document.getElementById('tp-detail-sources').innerHTML = sources.length
    ? '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:0.75rem">' +
      sources.map(function(s) {
        // "Unknown" (never "None"): an empty field here means this source
        // never supplied it -- e.g. OpenCTI never reports sectors/regions,
        // MISP never reports aliases. Rendering it as "None" would read as
        // a positive assertion the source never made.
        var unknown = '<span class="muted">Unknown</span>';
        function list(arr) {
          return (arr && arr.length)
            ? arr.map(function(v) { return '<span class="tool-tag">' + x(v) + '</span>'; }).join(' ')
            : unknown;
        }
        function row(label, val) {
          return '<div style="display:flex;gap:0.5rem;padding:0.14rem 0">' +
            '<span style="min-width:5.5rem;color:var(--muted);flex-shrink:0">' + label + '</span>' +
            '<span class="u-flex1">' + val + '</span></div>';
        }
        return '<div style="border:1px solid var(--border);border-radius:var(--radius);padding:0.6rem 0.75rem">' +
          '<div style="font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--accent);margin-bottom:0.4rem">' + x(s.source) + '</div>' +
          row('Name', x(s.name)) +
          row('Aliases', list(s.aliases)) +
          row('Sectors', list(s.sectors)) +
          row('Regions', list(s.regions)) +
          row('Confidence', s.confidence ? x(s.confidence) : unknown) +
          row('Techniques', x(s.techniqueCount)) +
          row('Last seen', s.lastSeen ? x(fmtDate(s.lastSeen)) : unknown) +
          '</div>';
      }).join('') + '</div>'
    : '<span class="muted">No per-source records yet — populated by the next threat-intel sync.</span>';

  var techEvidence = (d.techniqueEvidence || []);
  var evidenceCard = document.getElementById('tp-detail-evidence-card');
  if (techEvidence.length) {
    evidenceCard.style.display = '';
    document.getElementById('tp-detail-evidence').innerHTML =
      '<table class="u-w100"><thead><tr><th>Technique</th><th>Via</th><th>Confidence</th><th>Since</th></tr></thead><tbody>' +
      techEvidence.map(function(e) {
        var via = e.via ? (e.via + (e.viaName ? ' (' + x(e.viaName) + ')' : '')) : '<span class="muted">direct</span>';
        var since = e.startTime ? x(fmtDate(e.startTime)) : '<span class="muted">&mdash;</span>';
        return '<tr><td>' + x(e.techniqueId) + '</td><td>' + via + '</td><td>' + x(e.confidence) + '%</td><td>' + since + '</td></tr>';
      }).join('') +
      '</tbody></table>';
  } else {
    evidenceCard.style.display = 'none';
  }

  var hist = (d.history || []);
  document.getElementById('tp-detail-history').innerHTML = hist.length
    ? '<table class="u-w100"><thead><tr><th>Date</th><th>Score</th></tr></thead><tbody>' +
      hist.map(function(h) { return '<tr><td>' + x(new Date(h.recordedAt).toLocaleDateString()) + '</td><td>' + x(h.score) + '</td></tr>'; }).join('') +
      '</tbody></table>'
    : '<span class="muted">No history yet.</span>';

  var techSet = {};
  (d.techniqueIds || []).forEach(function(t) { techSet[t] = true; });
  apicall('/api/recommend/simulations?limit=100').then(function(recData) {
    var matches = ((recData && recData.techniques) || []).filter(function(t) { return techSet[t.techniqueId]; });
    document.getElementById('tp-detail-recs').innerHTML = matches.length
      ? matches.map(function(t) { return '<div style="padding:0.3rem 0">' + x(t.techniqueId) + ' — ' + x(t.name) + ' <span class="tiny muted">(score ' + x(t.score) + ')</span></div>'; }).join('')
      : '<span class="muted">No open recommendations for this actor\'s techniques.</span>';
  }).catch(function() {
    document.getElementById('tp-detail-recs').innerHTML = '<span class="muted">Could not load recommendations.</span>';
  });
}

export function loadRecommendations() {
  var limEl = document.getElementById('rec-limit');
  var limit = limEl ? limEl.value : '20';
  var body = document.getElementById('rec-table-body');
  body.innerHTML = '<tr><td colspan="7" class="empty">Loading…</td></tr>';
  apicall('/api/recommend/simulations?limit=' + encodeURIComponent(limit))
    .then(function(data) { renderRecommendations(data); })
    .catch(function(e) {
      body.innerHTML = '<tr><td colspan="7" class="empty u-danger">Failed to load: ' + x(e.message) + '</td></tr>';
    });
}

function renderRecommendations(data) {
  var body = document.getElementById('rec-table-body');
  REC_SCENARIO = data.suggestedScenario || null;
  var list = (data && data.techniques) || [];
  if (!list.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No recommendations yet — seed ATT&CK/ART content to rank techniques.</td></tr>';
    return;
  }
  body.innerHTML = list.map(function(t) {
    var threat = [];
    if (t.kev) threat.push('<span class="badge" style="color:var(--danger);border-color:var(--danger)">KEV</span>');
    if (t.epssPercentile) threat.push('<span class="badge">EPSS ' + Math.round(t.epssPercentile) + '</span>');
    if (t.threatActors) threat.push('<span class="badge">' + t.threatActors + ' group' + (t.threatActors === 1 ? '' : 's') + '</span>');
    return '<tr>' +
      '<td><div class="u-fw600">' + x(t.techniqueId) + '</div>' +
        '<div class="tiny muted">' + x(t.name) + '</div></td>' +
      '<td class="tiny">' + x(t.tactic) + '</td>' +
      '<td><span style="color:' + recTierColor(t.tier) + ';font-weight:700">' + t.score + '</span>' +
        '<div class="tiny" style="color:' + recTierColor(t.tier) + '">' + x(t.tier) + '</div></td>' +
      '<td>' + recCoverageBadge(t.coverageState) + '</td>' +
      '<td>' + (threat.join(' ') || '<span class="tiny muted">—</span>') + '</td>' +
      '<td>' + (t.environmentRisk ? '<span class="badge" style="color:var(--accent);border-color:var(--accent)">' + t.environmentRisk + '</span>'
                                  : '<span class="tiny muted">—</span>') + '</td>' +
      '<td class="tiny muted">' + x((t.reasons || []).join(' · ')) + '</td>' +
      '</tr>';
  }).join('');
}

export function copyRecommendedScenario() {
  if (!REC_SCENARIO || !REC_SCENARIO.artTechniques || !REC_SCENARIO.artTechniques.length) {
    showToast('Nothing to copy yet — load recommendations first.', 'err');
    return;
  }
  var text = REC_SCENARIO.artTechniques.join(', ');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function() {
      showToast('Copied ' + REC_SCENARIO.artTechniques.length + ' technique IDs — paste into the scenario builder.');
    }).catch(function() { showToast(text); });
  } else {
    showToast(text);
  }
}

function _expGapPriorityColor(p) {
  return p === 'Critical' ? 'var(--danger)' : p === 'High' ? '#f0883e' : p === 'Medium' ? 'var(--warning)' : 'var(--success)';
}

export function openExposureDetail(hostKey) {
  document.getElementById('exp-detail-title').textContent = hostKey;
  var body = document.getElementById('exp-detail-body');
  body.innerHTML = '<div class="empty" style="padding:2rem">Loading…</div>';
  document.getElementById('exposure-detail-overlay').classList.add('open');
  apicall('/api/exposure/assets/' + encodeURIComponent(hostKey)).then(function(p) {
    // Each of these is a pure-deficit score (100 - risk), so an asset with
    // nothing collected scores a flawless 100 across the board. Show "no
    // data" instead when the backend says it wasn't measurable — on a
    // "higher is safer" card, an unmeasured 100 is the most misleading
    // value we could print.
    var sc = p.scores || {};
    function expCard(label, val, measurable, note) {
      return measurable
        ? apCard(label, val, apColor(typeof val === 'number' ? val : parseInt(val, 10)), note)
        : apCard(label, '<span style="color:var(--muted);font-size:1.1rem">— no data</span>', 'var(--muted)', 'not collected yet');
    }
    var h = '<div class="kpi-row u-mb-1">' +
      expCard('Exposure Score', sc.exposureScore + '<span style="font-size:0.9rem;color:var(--muted)">/100</span>', sc.exposureMeasurable, 'higher is safer') +
      expCard('Attack Path', sc.attackPathScore, sc.attackPathMeasurable, '') +
      expCard('Detection', sc.detectionCoverageScore, sc.detectionMeasurable, '') +
      expCard('Vulnerability', sc.vulnerabilityScore, sc.vulnerabilityMeasurable, '') +
      '</div>';

    h += '<div style="font-weight:700;color:var(--text);margin-bottom:0.4rem">Prioritized Recommendations</div>';
    if (p.recommendations && p.recommendations.length) {
      h += '<div class="tbl-wrap u-mb-1"><table><thead><tr><th>From</th><th>Via</th><th>To</th><th>Priority</th><th>Reason</th></tr></thead><tbody>';
      p.recommendations.forEach(function(g) {
        h += '<tr><td>' + x(g.edge.from) + '</td><td>' + x(g.edge.kind) + '</td><td>' + x(g.edge.to) + '</td>' +
          '<td style="font-weight:700;color:' + _expGapPriorityColor(g.priority) + '">' + x(g.priority) + '</td>' +
          '<td style="color:var(--muted);font-size:0.8rem">' + x(g.reason) + '</td></tr>';
      });
      h += '</tbody></table></div>';
    } else {
      h += '<div class="tiny muted u-mb-1">No gaps on this asset&apos;s attack paths.</div>';
    }

    h += '<div style="font-weight:700;color:var(--text);margin-bottom:0.4rem">Vulnerabilities</div>';
    if (p.vulnerabilities && p.vulnerabilities.length) {
      h += '<div class="tbl-wrap u-mb-1"><table><thead><tr><th>CVE</th><th>CVSS</th><th>KEV</th><th>EPSS</th><th>Technique</th></tr></thead><tbody>';
      p.vulnerabilities.forEach(function(v) {
        h += '<tr><td>' + x(v.cveId) + '</td><td>' + (v.cvss || '—') + '</td><td>' + (v.kev ? 'Yes' : '') + '</td>' +
          '<td>' + (v.epssScore || '—') + '</td><td>' + x(v.techniqueId) + '</td></tr>';
      });
      h += '</tbody></table></div>';
    } else {
      h += '<div class="tiny muted u-mb-1">No mapped CVEs.</div>';
    }

    h += '<div style="font-weight:700;color:var(--text);margin-bottom:0.4rem">Findings</div>';
    if (!p.findings.collected) {
      h += '<div class="tiny muted u-mb-1">Not enrolled — no scan history.</div>';
    } else if (p.findings.findings && p.findings.findings.length) {
      h += '<div class="tbl-wrap u-mb-1"><table><thead><tr><th>Technique</th><th>Severity</th><th>State</th></tr></thead><tbody>';
      p.findings.findings.forEach(function(f) {
        h += '<tr><td>' + x(f.techniqueName || f.techniqueId) + '</td><td>' + x(f.severity) + '</td><td>' + x(f.exposureState) + '</td></tr>';
      });
      h += '</tbody></table></div>';
    } else {
      h += '<div class="tiny muted u-mb-1">No open findings.</div>';
    }

    h += '<div style="font-weight:700;color:var(--text);margin-bottom:0.4rem">Threat Groups</div>';
    if (p.threatIntel && p.threatIntel.length) {
      h += p.threatIntel.map(function(g) { return '<span class="badge" style="margin:2px">' + x(g.groupName) + '</span>'; }).join('');
    } else {
      h += '<div class="tiny muted">No attributed threat groups.</div>';
    }

    body.innerHTML = h;
  }).catch(function(e) {
    body.innerHTML = '<div class="empty u-danger">Failed to load: ' + x(e.message) + '</div>';
  });
}

export function closeExposureDetail() {
  document.getElementById('exposure-detail-overlay').classList.remove('open');
}
export function closeExposureDetailOnBackdrop(el, event) { if (event.target === el) closeExposureDetail(); }
// ── Attack Path Collection — job-based execution with full state machine ────────

var _apCollectAgentId = null; // agentId currently being collected (for WS matching)
var _apCurrentJobId   = null; // current job ID for WS event matching
var apActiveJobs      = {};   // agentId → {jobId,status} for agent-table badge

// Persist just the current job ID across page reloads so we can restore state from the server.
function _apSaveJobId(jobId, agentId) {
  try { localStorage.setItem('_apCurrentJob', JSON.stringify({jobId: jobId, agentId: agentId})); } catch(e) {}
}
function _apClearJobId() {
  try { localStorage.removeItem('_apCurrentJob'); } catch(e) {}
}
function _apLoadJobId() {
  try { return JSON.parse(localStorage.getItem('_apCurrentJob') || 'null'); } catch(e) { return null; }
}

// Legacy helpers kept for backward compat with loadAttackPath
function _apSavePending(agentId, agentLabel, targets, shEnabled, sharpHoundDelivered) {}
function _apClearPending() { _apClearJobId(); }
function _apLoadPending() { return null; }

export function apCollectClose() {
  document.getElementById('ap-collect').style.display = 'none';
  _apCollectAgentId = null;
  _apCurrentJobId = null;
  _apClearJobId();
  // reset to form mode for next open
  document.getElementById('ap-form').style.display = '';
  document.getElementById('ap-progress').style.display = 'none';
  document.getElementById('ap-done-actions').style.display = 'none';
}

export function openAPCollect() {
  var sel = document.getElementById('ap-agent');
  var panel = document.getElementById('ap-collect');
  // reset to configure mode
  document.getElementById('ap-form').style.display = '';
  document.getElementById('ap-progress').style.display = 'none';
  document.getElementById('ap-done-actions').style.display = 'none';
  document.getElementById('ap-targets').value = '';
  document.getElementById('ap-target-count').textContent = '';

  // Show neutral current-graph context note if we have metadata
  var ctxEl = document.getElementById('ap-current-ctx');
  var ctxTs = document.getElementById('ap-current-ctx-ts');
  var metaTs = document.getElementById('ap-meta-ts');
  if (metaTs && metaTs.textContent && metaTs.textContent !== '—') {
    if (ctxTs) ctxTs.textContent = metaTs.textContent;
    if (ctxEl) ctxEl.style.display = '';
  } else {
    if (ctxEl) ctxEl.style.display = 'none';
  }

  function fill() {
    sel.innerHTML = (state.agents || []).map(function(a) {
      return '<option value="' + x(a.agentId) + '">' + x(a.hostname || a.agentId) + (a.status === 'offline' ? ' (offline)' : '') + '</option>';
    }).join('') || '<option value="">No agents enrolled</option>';
    panel.style.display = '';
  }
  if (!state.agents || !state.agents.length) {
    apicall('/api/agents').then(function(d) { state.agents = d || []; fill(); }).catch(function(e) { showToast(e.message, 'err'); });
  } else fill();
}

export function apCountTargets() {
  var lines = document.getElementById('ap-targets').value.split('\n').map(function(t) { return t.trim(); }).filter(Boolean);
  var el = document.getElementById('ap-target-count');
  el.textContent = lines.length ? lines.length + ' host' + (lines.length === 1 ? '' : 's') : '';
}

export function apDiscoverSubnet() {
  var agentId = document.getElementById('ap-agent').value;
  if (!agentId) { showToast('Select an agent first', 'err'); return; }
  var btn = document.getElementById('ap-discover-btn');
  btn.disabled = true;
  btn.textContent = 'Discovering…';
  apicall('/api/attackpath/subnet/' + encodeURIComponent(agentId)).then(function(r) {
    btn.disabled = false;
    btn.innerHTML = '&#128270; Discover Subnet';
    if (!r.targets || !r.targets.length) {
      showToast('No subnet info available for this agent yet — try heartbeating first.', 'err');
      return;
    }
    document.getElementById('ap-targets').value = r.targets.join('\n');
    apCountTargets();
    showToast('Populated ' + r.targets.length + ' hosts from ' + r.subnet + ' — review and edit before dispatching.', 'ok');
  }).catch(function(e) {
    btn.disabled = false;
    btn.innerHTML = '&#128270; Discover Subnet';
    showToast(e.message, 'err');
  });
}

// Renders a timeline step. state: 'done' | 'active' | 'pending' | 'warn'
function _apStep(stepState, title, detail) {
  var icon = stepState === 'done' ? '<span class="u-success">&#10003;</span>'
    : stepState === 'active' ? '<span style="animation:spin 1s linear infinite;display:inline-block">&#9696;</span>'
    : stepState === 'warn' ? '<span class="u-warning">&#9888;</span>'
    : '<span class="u-muted">&#9675;</span>';
  var titleColor = stepState === 'pending' ? 'var(--muted)' : 'var(--text)';
  return '<div style="display:flex;gap:0.7rem;align-items:flex-start;padding:0.55rem 0;border-bottom:1px solid var(--border)">' +
    '<div style="width:1.2rem;text-align:center;flex-shrink:0;margin-top:0.05rem;font-size:0.9rem">' + icon + '</div>' +
    '<div><div style="font-size:0.82rem;font-weight:600;color:' + titleColor + '">' + title + '</div>' +
    (detail ? '<div class="tiny muted" style="margin-top:0.2rem">' + detail + '</div>' : '') +
    '</div></div>';
}

function _apTimestamp() {
  return new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

export function dispatchAPCollect() {
  var agentId = document.getElementById('ap-agent').value;
  if (!agentId) { showToast('Select an agent', 'err'); return; }
  var targets = document.getElementById('ap-targets').value.split('\n').map(function(t) { return t.trim(); }).filter(Boolean);
  var agentLabel = document.getElementById('ap-agent').options[document.getElementById('ap-agent').selectedIndex].text;
  var payload = { agentId: agentId, targets: targets, segment: document.getElementById('ap-segment').value.trim(), runSharpHound: document.getElementById('ap-sharphound').checked };
  var shEnabled = payload.runSharpHound;

  apicall('/api/attackpath/jobs', { method: 'POST', body: JSON.stringify(payload) }).then(function(r) {
    _apCollectAgentId = agentId;
    _apCurrentJobId = r.job && r.job.id;
    if (_apCurrentJobId) _apSaveJobId(_apCurrentJobId, agentId);

    // Switch panel to progress timeline
    document.getElementById('ap-form').style.display = 'none';
    document.getElementById('ap-progress').style.display = '';

    var tl = document.getElementById('ap-timeline');
    var shNote = shEnabled ? (r.sharpHoundDelivered ? ' + SharpHound domain mapping' : ' (SharpHound binary not configured server-side — skipping)') : '';
    var shDetail = shEnabled && !r.sharpHoundDelivered ? 'SharpHound was requested but the binary is not configured on the server. TCP-only collection will proceed.' : '';

    var jobStatus = r.job && r.job.status;
    tl.innerHTML =
      _apStep('done', 'Collection started for ' + x(agentLabel) + ' at ' + _apTimestamp(),
        targets.length + ' target' + (targets.length === 1 ? '' : 's') + ' queued — job ' + (r.job ? r.job.id.slice(0,8) : '')) +
      (shDetail ? _apStep('warn', 'SharpHound notice', shDetail) : '') +
      _apStep(jobStatus === 'dispatched' || jobStatus === 'running' ? 'done' : 'active',
        jobStatus === 'dispatched' ? 'WS command sent — waiting for agent ACK…'
          : jobStatus === 'running' ? 'Agent acknowledged — probing the network…'
          : 'Dispatching to agent…',
        'TCP connect on SMB (445), WinRM (5985), RDP (3389)' + shNote) +
      _apStep('pending', 'Agent acknowledged (running)', '') +
      _apStep('pending', 'Collection received by server', '') +
      _apStep('pending', 'Graph built &amp; analysis complete', '');

    // Wire retry button if it exists in the panel
    var retryBtn = document.getElementById('ap-retry-btn');
    if (retryBtn) { retryBtn.onclick = function() { _apRetryJob(r.job && r.job.id); }; }
  }).catch(function(e) {
    showToast('Dispatch failed: ' + e.message, 'err');
  });
}

// Retry a failed or timed-out job by creating a new one from the same payload.
function _apRetryJob(jobId) {
  if (!jobId) return;
  apicall('/api/attackpath/jobs/' + jobId + '/retry', { method: 'POST' }).then(function(r) {
    _apCurrentJobId = r.id;
    if (r.id) _apSaveJobId(r.id, _apCollectAgentId);
    showToast('Retry job created — ' + r.id.slice(0,8), 'ok');
    _apRenderJobState(r);
  }).catch(function(e) { showToast('Retry failed: ' + e.message, 'err'); });
}

var _apStageLabels = {
  initializing:          'Initializing…',
  probing:               'Probing targets',
  enumerating_admins:    'Enumerating local admins',
  enumerating_sessions:  'Enumerating active sessions',
  running_sharphound:    'Running SharpHound',
  building_graph:        'Building graph',
  uploading:             'Uploading results'
};

// Render the timeline from a job object (status, progress, error).
function _apRenderJobState(job) {
  if (!job) return;
  var tl = document.getElementById('ap-timeline');
  if (!tl) return;
  var s = job.status;
  var prog = job.progress;

  var stageLabel = prog && prog.stage ? (_apStageLabels[prog.stage] || x(prog.stage)) : '';
  var pct = prog && prog.progressPercent > 0 ? prog.progressPercent : 0;
  var pctBar = (pct > 0 && pct < 100)
    ? '<div style="margin-top:0.3rem;width:100%;max-width:220px;background:var(--border);border-radius:4px;height:6px;overflow:hidden">' +
      '<div style="width:' + pct + '%;background:var(--accent);height:100%;border-radius:4px;transition:width 0.4s"></div></div>' +
      '<span style="font-size:0.72rem;color:var(--muted)">' + pct + '%</span>'
    : '';
  var progDetail = stageLabel
    + (prog && prog.targetsTotal > 0 ? ' — ' + prog.targetsCompleted + '/' + prog.targetsTotal + ' targets' : '')
    + (pctBar ? '<br>' + pctBar : '');

  var isTerminal = (s === 'completed' || s === 'failed' || s === 'timed_out' || s === 'delivery_failed' || s === 'cancelled');

  // Cancel button: visible while job is active (dispatched or running), hidden once terminal.
  var cancelEl = document.getElementById('ap-cancel-action');
  if (cancelEl) cancelEl.style.display = (!isTerminal && s !== 'queued') ? '' : 'none';

  // Step states by job status
  var dispatchState = (s === 'queued') ? 'active' : 'done';
  var ackState = s === 'queued' ? 'pending' : s === 'dispatched' ? 'active' : 'done';
  var probeState = (s === 'queued' || s === 'dispatched') ? 'pending' : (s === 'running') ? 'active' : 'done';
  var uploadState = (s === 'running' && prog && prog.stage === 'uploading') ? 'active' : (s === 'completed') ? 'done' : 'pending';
  var graphState  = s === 'completed' ? 'done' : 'pending';

  if (s === 'failed' || s === 'timed_out' || s === 'delivery_failed' || s === 'cancelled') {
    ackState = probeState = uploadState = graphState = 'warn';
  }

  var failReasonMap = {
    delivery_failed: 'Agent did not ACK the command — check agent connectivity.',
    timeout: 'Execution exceeded the allocated time window.',
    agent_offline: 'Agent went offline during collection.',
    upload_failed: 'Results upload failed.',
    cancelled: 'Cancelled by operator.',
    network_error: 'Network error during collection.',
    authentication_failed: 'Agent authentication failed.',
    permission_denied: 'Permission denied on the agent.'
  };
  var errorDisplay = failReasonMap[job.error] || (job.error ? x(job.error) : '');

  var statusLabel = {
    queued: 'Queued — waiting for agent to connect',
    dispatched: 'Command delivered — waiting for agent ACK…',
    running: stageLabel ? stageLabel : 'Execution in progress…',
    completed: 'Done',
    failed: 'Failed — ' + errorDisplay,
    timed_out: 'Timed out — ' + errorDisplay,
    delivery_failed: 'Delivery failed — ' + errorDisplay,
    cancelled: 'Cancelled — ' + (errorDisplay || 'by operator')
  }[s] || s;

  tl.innerHTML =
    _apStep(dispatchState, 'Job dispatched — ' + job.id.slice(0,8),
      job.targetCount > 0 ? job.targetCount + ' target' + (job.targetCount === 1 ? '' : 's') + ' queued' : '') +
    _apStep(ackState, statusLabel, '') +
    _apStep(probeState, 'Executing on agent', progDetail) +
    _apStep(uploadState, 'Uploading results…', '') +
    _apStep(graphState, 'Graph built &amp; analysis complete',
      job.metrics ? job.metrics.nodeCount + ' nodes · ' + job.metrics.edgeCount + ' edges' : '');

  if (isTerminal) {
    if (cancelEl) cancelEl.style.display = 'none';
    var doneDiv = document.getElementById('ap-done-actions');
    if (doneDiv) doneDiv.style.display = 'flex';
    var retryBtn2 = document.getElementById('ap-retry-btn');
    if (retryBtn2) retryBtn2.style.display = (s === 'completed') ? 'none' : '';
    var viewBtn = doneDiv && doneDiv.querySelector('button.btn-primary');
    if (viewBtn) viewBtn.style.display = (s === 'completed') ? '' : 'none';
  }
}

export function _apCancelJob() {
  if (!_apCurrentJobId) return;
  if (!confirm('Cancel this collection? The agent will complete any in-progress probe but no results will be stored.')) return;
  apicall('/api/attackpath/jobs/' + _apCurrentJobId + '/cancel', {method:'POST'})
    .then(function(r) { if (r && r.job) _apRenderJobState(r.job); })
    .catch(function(e) { showToast('Cancel failed: ' + e.message, 'err'); });
}

// Called from the WS onmessage handler for job lifecycle changes.
export function _apOnJobUpdate(msg) {
  if (!msg || !msg.data) return;
  var job = msg.data;
  var agentId = job.agentId || msg.agentId;
  // Update per-agent badge in the agents table regardless of panel state.
  var terminalStates = ['completed','failed','timed_out','delivery_failed','cancelled'];
  if (terminalStates.indexOf(job.status) !== -1) {
    delete apActiveJobs[agentId];
  } else if (agentId) {
    apActiveJobs[agentId] = { jobId: job.id, status: job.status };
  }
  renderAgentRows();
  // Refresh Attack Path tab in the agent detail drawer if it's showing this agent.
  if (_agtDetailId && _agtDetailId === agentId) {
    var apPane = document.getElementById('agt-tab-attackpath');
    if (apPane && apPane.style.display !== 'none') loadAgtAttackPath(agentId);
  }
  // Only update the progress panel if this is the panel's current job.
  if (_apCurrentJobId && job.id !== _apCurrentJobId) return;
  if (!_apCurrentJobId && job.id) {
    // Restore from WS if page was reloaded — only if panel is showing progress
    var saved = _apLoadJobId();
    if (!saved || saved.jobId !== job.id) return;
    _apCurrentJobId = job.id;
    _apCollectAgentId = agentId;
    document.getElementById('ap-form').style.display = 'none';
    document.getElementById('ap-progress').style.display = '';
  }
  _apRenderJobState(job);
  if (job.status === 'completed') {
    loadAttackPath();
    _apClearJobId();
    var da = document.getElementById('ap-done-actions');
    if (da) { da.style.display = 'flex'; var rb = document.getElementById('ap-retry-btn'); if (rb) rb.style.display = 'none'; }
    showToast('Attack-path collection complete — graph updated.', 'ok');
  } else if (job.status === 'timed_out') {
    showToast('Attack-path job timed out — agent did not complete in time.', 'warn');
  } else if (job.status === 'delivery_failed') {
    showToast('Attack-path delivery failed — check agent connectivity.', 'err');
  }
}

// Called from WS for real-time progress updates from agent heartbeats.
export function _apOnProgress(msg) {
  if (!msg || !msg.data) return;
  var d = msg.data;
  if (_apCurrentJobId && d.jobId !== _apCurrentJobId) return;
  if (document.getElementById('ap-progress').style.display === 'none') return;
  // Synthesise a minimal job object so _apRenderJobState can re-render fully.
  _apRenderJobState({
    id: d.jobId || _apCurrentJobId || '',
    agentId: d.agentId || _apCollectAgentId || '',
    status: 'running',
    targetCount: 0,
    progress: d.progress || {}
  });
}

// Called from the WS handler when the server confirms a collection is stored (legacy event).
export function _apOnCollected(msg) {
  if (!msg || !msg.data) return;
  _apClearJobId();
  var d = msg.data;
  var tl = document.getElementById('ap-timeline');
  if (!tl) return;
  // If the job update already rendered completion, skip double-render.
  if (document.getElementById('ap-done-actions').style.display !== 'none') return;

  var label = d.hostname || msg.agentId || 'agent';
  var nodes = d.nodes || 0;
  var edges = d.edges || 0;
  var step1Html = tl.children.length > 0 ? tl.children[0].outerHTML : _apStep('done', 'Command dispatched', '');
  step1Html = step1Html.replace(/animation:spin[^"]+/g, '').replace(/<span[^>]*>&#9696;<\/span>/, '<span class="u-success">&#10003;</span>').replace(/<span[^>]*>&#9675;<\/span>/, '<span class="u-success">&#10003;</span>');
  tl.innerHTML =
    step1Html +
    _apStep('done', 'Agent finished probing at ' + _apTimestamp(), x(label) + ' completed TCP probes across all targets.') +
    _apStep('done', 'Collection received — ' + nodes + ' node' + (nodes === 1 ? '' : 's') + ', ' + edges + ' lateral edge' + (edges === 1 ? '' : 's') + ' mapped',
      'The server has built the updated graph. Previous collection (if any) has been superseded by this result.') +
    _apStep('done', 'Graph analysis complete — results are ready', 'Attack path score, lateral movement risk, and domain reachability have been recalculated. Click View Results to review.');

  var doneDiv2 = document.getElementById('ap-done-actions');
  if (doneDiv2) { doneDiv2.style.display = 'flex'; var rb = document.getElementById('ap-retry-btn'); if (rb) rb.style.display = 'none'; }
  loadAttackPath();
  showToast(label + ': ' + nodes + ' nodes collected — attack path updated.', 'ok');
}

export function _onSIEMCorrelationComplete(msg) {
  if (!msg || !msg.data) return;
  var d = msg.data;
  var rate = d.detectionRate || 0;
  showToast('SIEM (' + (d.provider || 'qradar') + '): ' + rate + '% detection rate — ' +
    (d.detected || 0) + ' detected, ' + (d.undetected || 0) + ' missed.', rate >= 50 ? 'ok' : 'warn');
  if (d.runId) loadSIEMCorrelationPanel(d.runId);
}

export function _onRevalidationStarted(msg) {
  if (!msg || !msg.data) return;
  var d = msg.data;
  var status = d.status || '';
  var tech = d.techniqueId || '';
  var name = d.techniqueName ? (' — ' + d.techniqueName) : '';
  if (status === 'dispatched') {
    showToast('Auto-revalidation started: ' + tech + name + '. Check Live Runs for progress.', 'ok');
    loadRuns();
  } else if (status === 'no_scenario') {
    showToast('Auto-revalidation: no scenario for ' + tech + ' — re-validate manually via Remediations.', 'warn');
  }
}

var AP_ASSETS = [];
var AP_INPUT_STYLE = 'width:100%;padding:0.35rem 0.5rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:5px;font-size:0.78rem';
export function openAPAssets() {
  document.getElementById('ap-assets').style.display = '';
  document.getElementById('ap-assets-body').innerHTML = '<tr><td colspan="5" class="empty">Loading…</td></tr>';
  apicall('/api/attackpath/assets').then(function(d) {
    AP_ASSETS = (d && d.assets) || [];
    renderAPAssets();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
var AP_CRIT_TIERS = ['', 'low', 'medium', 'high', 'critical'];
function renderAPAssets() {
  var tb = document.getElementById('ap-assets-body');
  if (!AP_ASSETS.length) {
    tb.innerHTML = '<tr><td colspan="7" class="empty">No hosts discovered yet — run a collection first.</td></tr>';
    return;
  }
  tb.innerHTML = AP_ASSETS.map(function(a, i) {
    var tierOpts = AP_CRIT_TIERS.map(function(t) {
      return '<option value="' + t + '"' + (a.criticalityTier === t ? ' selected' : '') + '>' + (t || '—') + '</option>';
    }).join('');
    return '<tr>' +
      '<td style="font-family:var(--font-mono);font-size:0.76rem">' + x(a.label || a.hostKey) +
        (a.label && a.label.toUpperCase() !== (a.hostKey || '').toUpperCase() ? '<div class="tiny muted">' + x(a.hostKey) + '</div>' : '') + '</td>' +
      '<td><input id="apt-cj-' + i + '" value="' + x(a.crownJewel || '') + '" placeholder="e.g. ERP, FileServer" style="' + AP_INPUT_STYLE + '"></td>' +
      '<td><input id="apt-seg-' + i + '" value="' + x(a.segment || '') + '" placeholder="e.g. server-vlan" style="' + AP_INPUT_STYLE + '"></td>' +
      '<td class="u-center"><input type="checkbox" id="apt-hv-' + i + '"' + (a.highValue ? ' checked' : '') + '></td>' +
      '<td><select id="apt-crit-' + i + '" style="' + AP_INPUT_STYLE + '">' + tierOpts + '</select></td>' +
      '<td style="font-size:0.72rem;white-space:nowrap">' +
        '<label style="margin-right:0.4rem"><input type="checkbox" id="apt-if-' + i + '"' + (a.internetFacing ? ' checked' : '') + '> Internet</label>' +
        '<label style="margin-right:0.4rem"><input type="checkbox" id="apt-ie-' + i + '"' + (a.identityExposed ? ' checked' : '') + '> Identity</label>' +
        '<label style="margin-right:0.4rem"><input type="checkbox" id="apt-prod-' + i + '"' + (a.production ? ' checked' : '') + '> Prod</label>' +
        '<input id="apt-cs-' + i + '" value="' + x((a.complianceScope || []).join(', ')) + '" placeholder="compliance scope, comma-sep" style="' + AP_INPUT_STYLE + ';margin-top:0.2rem;display:block;width:160px">' +
      '</td>' +
      '<td><button class="btn btn-outline btn-sm" onclick="saveAPAsset(' + i + ')">Save</button></td>' +
    '</tr>';
  }).join('');
}
export function saveAPAsset(i) {
  var a = AP_ASSETS[i];
  if (!a) return;
  var cs = document.getElementById('apt-cs-' + i).value.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
  var payload = {
    hostKey: a.hostKey, label: a.label || '',
    crownJewel: document.getElementById('apt-cj-' + i).value.trim(),
    segment: document.getElementById('apt-seg-' + i).value.trim(),
    highValue: document.getElementById('apt-hv-' + i).checked,
    criticalityTier: document.getElementById('apt-crit-' + i).value,
    internetFacing: document.getElementById('apt-if-' + i).checked,
    identityExposed: document.getElementById('apt-ie-' + i).checked,
    production: document.getElementById('apt-prod-' + i).checked,
    complianceScope: cs
  };
  apicall('/api/attackpath/assets', { method: 'POST', body: JSON.stringify(payload) }).then(function() {
    a.crownJewel = payload.crownJewel; a.segment = payload.segment; a.highValue = payload.highValue;
    a.criticalityTier = payload.criticalityTier; a.internetFacing = payload.internetFacing;
    a.identityExposed = payload.identityExposed; a.production = payload.production; a.complianceScope = payload.complianceScope;
    showToast('Saved ' + (a.label || a.hostKey), 'ok');
    loadAttackPath();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function openAPAbout() {
  document.getElementById('ap-about-backdrop').style.display = '';
  document.getElementById('ap-about-modal').style.display = '';
  document.getElementById('ap-about-modal').scrollTop = 0;
}
export function closeAPAbout() {
  document.getElementById('ap-about-backdrop').style.display = 'none';
  document.getElementById('ap-about-modal').style.display = 'none';
}

export function openAPSchedule() {
  var panel = document.getElementById('ap-schedule');
  panel.style.display = '';
  document.getElementById('ap-sched-last').textContent = '';
  apicall('/api/attackpath/schedule').then(function(s) {
    document.getElementById('ap-sched-enabled').checked = !!s.enabled;
    document.getElementById('ap-sched-interval').value = s.intervalMinutes || 1440;
    document.getElementById('ap-sched-targets').value = (s.targets || []).join('\n');
    document.getElementById('ap-sched-segment').value = s.segment || '';
    document.getElementById('ap-sched-sharphound').checked = !!s.runSharpHound;
    document.getElementById('ap-sched-last').textContent =
      s.lastRunAt ? 'Last run: ' + new Date(s.lastRunAt).toLocaleString() : 'Never run';
  }).catch(function(e) { showToast(e.message, 'err'); });
}
export function saveAPSchedule() {
  var interval = parseInt(document.getElementById('ap-sched-interval').value, 10);
  if (!interval || interval < 60) { showToast('Minimum interval is 60 minutes', 'err'); return; }
  var payload = {
    enabled: document.getElementById('ap-sched-enabled').checked,
    intervalMinutes: interval,
    targets: document.getElementById('ap-sched-targets').value.split('\n').map(function(t) { return t.trim(); }).filter(Boolean),
    segment: document.getElementById('ap-sched-segment').value.trim(),
    runSharpHound: document.getElementById('ap-sched-sharphound').checked
  };
  apicall('/api/attackpath/schedule', { method: 'POST', body: JSON.stringify(payload) }).then(function(r) {
    document.getElementById('ap-schedule').style.display = 'none';
    showToast(r.enabled ? 'Scheduled collection enabled (every ' + r.intervalMinutes + ' min)' : 'Scheduled collection disabled', 'ok');
  }).catch(function(e) { showToast(e.message, 'err'); });
}


// Settings sub-section switcher — toggles the body panels + lazily loads each.
export function showSettingsSection(name) {
  state.SETTINGS_SECTION = name;
  ['users', 'engine', 'intel', 'art', 'audit', 'theme', 'dashprefs', 'license', 'backup'].forEach(function(s) {
    var el = document.getElementById('set-' + s);
    if (el) el.style.display = s === name ? '' : 'none';
    var nav = document.querySelector('[data-set="' + s + '"]');
    if (nav) nav.classList.toggle('active', s === name);
  });
  if (name === 'users') loadUsers();
  else if (name === 'engine') loadCalderaStatus();
  else if (name === 'intel') { loadConnectorStatus(); loadThreatIntelConfig('misp'); loadThreatIntelConfig('opencti'); loadThreatIntelConfig('otx'); loadTAXIIConnectors(); loadOpenAEVConfig(); }
  else if (name === 'art') loadARTContentStatus();
  else if (name === 'audit') loadAuditLogs();
  else if (name === 'license') loadLicenseInfo();
  else if (name === 'dashprefs') syncDashPrefCards();
  else if (name === 'backup') loadBackups();
}

export function selectDashPref(pref) {
  localStorage.setItem('bas_dash_pref', pref);
  syncDashPrefCards();
}

function syncDashPrefCards() {
  var pref = localStorage.getItem('bas_dash_pref') || 'operational';
  ['operational', 'executive', 'last'].forEach(function(p) {
    var el = document.getElementById('dashpref-card-' + p);
    if (el) el.classList.toggle('active', p === pref);
  });
}

export function selectTheme(themeName) {
  document.body.classList.remove('theme-light', 'theme-cyberpunk', 'theme-slate');
  if (themeName !== 'dark') {
    document.body.classList.add('theme-' + themeName);
  }
  localStorage.setItem('audspect_theme', themeName);
  document.querySelectorAll('.theme-card').forEach(function(c) {
    c.classList.toggle('active', c.id === 'theme-card-' + themeName);
  });
}

var AGENT_FILTER = 'all';
// agentBucket: retired = uninstalled (see POST /api/agents/unenroll), excluded
// from every other bucket and from the default "All" list -- reachable only
// via the explicit Retired filter, so audit history stays visible without
// cluttering the live endpoint list; online = reachable + active; degraded =
// reachable but lifecycle state != active (quarantined/restricted); offline =
// no heartbeat.
export function agentBucket(a) {
  if (a.state === 'retired' || a.state === 'uninstalled') return 'retired';
  if (a.status === 'offline') return 'offline';
  if (a.state && a.state !== 'active') return 'degraded';
  return 'online';
}
function agentDotColor(b) { return b === 'online' ? 'var(--success)' : b === 'degraded' ? 'var(--warning)' : 'var(--muted)'; }

export var agentGroupTree = [];
var activeAgentGroupId = null; // null = "All" (no filter), otherwise a group id

export function loadAgentGroupTree() {
  apicall('/api/agent-groups').then(function(tree) {
    agentGroupTree = Array.isArray(tree) ? tree : [];
    renderAgentGroupTree();
  }).catch(function() { agentGroupTree = []; renderAgentGroupTree(); });
}

function renderAgentGroupTree() {
  var root = document.getElementById('agent-tree-root');
  if (!root) return;
  var allRow = '<div class="at-node' + (activeAgentGroupId === null ? ' active' : '') + '" onclick="selectAgentGroup(null)">' +
    '<span class="at-caret"></span><span class="at-name">All</span></div>';
  root.innerHTML = allRow + agentGroupTree.map(renderAgentGroupNode).join('');
}

function renderAgentGroupNode(node) {
  var hasChildren = node.children && node.children.length;
  var caret = hasChildren ? '&#9662;' : '';
  var active = activeAgentGroupId === node.id ? ' active' : '';
  var html = '<div class="at-node' + active + '" onclick="selectAgentGroup(' + node.id + ')">' +
    '<span class="at-caret">' + caret + '</span>' +
    '<span class="at-name">' + x(node.name) + '</span>' +
    '<span class="at-count">' + node.totalAgentCount + '</span>' +
    '<span class="at-menu" onclick="event.stopPropagation();openAgentGroupMenu(event,' + node.id + ')">&#8942;</span>' +
    '</div>';
  if (hasChildren) {
    html += '<div class="at-children">' + node.children.map(renderAgentGroupNode).join('') + '</div>';
  }
  return html;
}

export function selectAgentGroup(groupId) {
  activeAgentGroupId = groupId;
  renderAgentGroupTree();
  loadAgents();
}

export function openAgentGroupMenu(ev, groupId) {
  var action = prompt('Type: rename / new / move / delete');
  if (action === 'rename') renameAgentGroupPrompt(groupId);
  else if (action === 'new') createAgentGroupPrompt(groupId);
  else if (action === 'move') moveAgentGroupPrompt(groupId);
  else if (action === 'delete') deleteAgentGroupConfirm(groupId);
}

export function createAgentGroupPrompt(parentId) {
  var name = prompt('New group name:');
  if (!name) return;
  apicall('/api/agent-groups', { method: 'POST', body: JSON.stringify({ name: name, parentId: parentId }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgentGroupTree(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

function renameAgentGroupPrompt(groupId) {
  var name = prompt('New name:');
  if (!name) return;
  apicall('/api/agent-groups/' + groupId, { method: 'PATCH', body: JSON.stringify({ name: name }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgentGroupTree(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// gpFlattenGroups walks the nested group tree depth-first into a flat list
// of {id, label} entries for the picker's <select>, indenting each label by
// its depth so the hierarchy stays legible in a flat list. excludeId (used
// only for the group-reparent flow) skips that one node's own entry -- its
// children are still included, since the backend's existing cycle check
// (agent_groups_handlers.go's UpdateAgentGroup) is the real guard against
// picking a deeper invalid target, not this client-side list.
export function gpFlattenGroups(nodes, depth, excludeId, out) {
  (nodes || []).forEach(function(n) {
    if (n.id !== excludeId) {
      out.push({ id: n.id, label: (depth > 0 ? '— '.repeat(depth) : '') + n.name });
    }
    if (n.children && n.children.length) gpFlattenGroups(n.children, depth + 1, excludeId, out);
  });
  return out;
}

// buildGroupDescendantMap walks the group tree once and returns, for every
// group id, the list of that group's own id plus every descendant group's id
// (post-order: children are resolved before their parent so parents can just
// concatenate their already-computed children's lists). Mirrors the same
// "selecting a parent surfaces its children's agents too" rule the backend
// applies in GET /api/agents?groupId= and jobs.Store.ResolveGroupAgentIDs.
function buildGroupDescendantMap(nodes) {
  var map = {};
  function walk(list) {
    (list || []).forEach(function(n) {
      var ids = [n.id];
      if (n.children && n.children.length) {
        walk(n.children);
        n.children.forEach(function(c) { ids = ids.concat(map[c.id]); });
      }
      map[n.id] = ids;
    });
  }
  walk(nodes);
  return map;
}

// resolveGroupTargetAgents returns every agent (from the global `agents` array)
// belonging to any of selectedGroupIds or their descendant groups. Pure client-side
// set math over already-loaded data -- no API call. Does not apply OS filtering;
// callers run the result through osEligibleAgents separately.
export function resolveGroupTargetAgents(selectedGroupIds) {
  if (!selectedGroupIds.length) return [];
  var map = buildGroupDescendantMap(agentGroupTree);
  var idSet = {};
  selectedGroupIds.forEach(function(gid) {
    (map[gid] || [gid]).forEach(function(id) { idSet[id] = true; });
  });
  return state.agents.filter(function(a) { return a.groupId != null && idSet[a.groupId]; });
}

var _gpMode = null, _gpContextId = null;

function openGroupPicker(mode, contextId) {
  _gpMode = mode;
  _gpContextId = contextId;
  document.getElementById('gp-title').textContent = mode === 'agent' ? 'Move Agent to Group' : 'Move Group to New Parent';
  var excludeId = mode === 'group' ? contextId : null;
  var options = gpFlattenGroups(agentGroupTree, 0, excludeId, []);
  var topLabel = mode === 'agent' ? '— Ungrouped —' : '— Root (no parent) —';
  document.getElementById('gp-select').innerHTML = '<option value="">' + topLabel + '</option>' +
    options.map(function(o) { return '<option value="' + x(o.id) + '">' + x(o.label) + '</option>'; }).join('');
  document.getElementById('group-picker-overlay').classList.add('open');
}

export function closeGroupPicker() {
  document.getElementById('group-picker-overlay').classList.remove('open');
  _gpMode = null;
  _gpContextId = null;
}

export function submitGroupPicker() {
  var selected = document.getElementById('gp-select').value;
  var groupId = selected === '' ? null : parseInt(selected, 10);
  var mode = _gpMode, contextId = _gpContextId;
  var url, body, onSuccess;
  if (mode === 'agent') {
    url = '/api/agents/' + encodeURIComponent(contextId) + '/group';
    body = { groupId: groupId };
    onSuccess = function() { loadAgents(); };
  } else {
    url = '/api/agent-groups/' + contextId;
    body = { parentId: groupId };
    onSuccess = function() { loadAgentGroupTree(); };
  }
  apicall(url, { method: 'PATCH', body: JSON.stringify(body) }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    closeGroupPicker();
    showToast('Moved', 'ok');
    onSuccess();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function moveAgentGroupPrompt(groupId) {
  openGroupPicker('group', groupId);
}

function deleteAgentGroupConfirm(groupId) {
  if (!confirm('Delete this group?')) return;
  fetch('/api/agent-groups/' + groupId, { method: 'DELETE', credentials: 'same-origin' })
    .then(function(r) {
      if (r.status === 204) { showToast('Group deleted', 'ok'); loadAgentGroupTree(); return; }
      r.json().then(function(j) { showToast(j.error || 'Delete failed', 'err'); });
    }).catch(function(e) { showToast(e.message, 'err'); });
}

export function moveAgentToGroupPrompt(agentId) {
  openGroupPicker('agent', agentId);
}

export function loadAgents() {
  var url = '/api/agents?limit=100' + (activeAgentGroupId !== null ? '&groupId=' + activeAgentGroupId : '');
  var searchEl = document.getElementById('agent-search');
  var q = searchEl ? searchEl.value.trim() : '';
  if (q) url += '&q=' + encodeURIComponent(q);
  if (AGENT_FILTER !== 'all') url += '&bucket=' + encodeURIComponent(AGENT_FILTER);
  return apicall(url).then(function(page) {
    state.agents = (page && page.items) || [];
    state.agentsNextCursor = (page && page.next_cursor) || '';
    state.agentsHasMore = !!(page && page.has_more);
    state.agentsPagesLoaded = 1;
    state.agentTotals = (page && page.totals) || { online: 0, degraded: 0, offline: 0, retired: 0 };
    document.getElementById('agent-cnt').textContent = state.agentTotals.online + state.agentTotals.degraded + state.agentTotals.offline;
    renderAgentTiles(); renderAgentToolbar(); renderAgentRows();
    renderLegacyMigrationPanel();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
function renderLegacyMigrationPanel() {
  var el = document.getElementById('legacy-migration-panel');
  if (!el) return;
  apicall('/api/agents/legacy-migration-status').then(function(status) {
    var blockingHtml = (status.blockingAgents || []).map(function(a) {
      return '<div class="legacy-blocking-row"><span>' + x(a.hostname || a.agentId) + '</span>' +
             '<span class="legacy-blocking-time">' + new Date(a.lastSeen).toLocaleString() + '</span></div>';
    }).join('');
    var unattributedHtml = status.unattributedRequests
      ? '<div class="legacy-unattributed-warning">&#9888; Unattributed legacy activity: ' +
        status.unattributedRequests.count + ' request(s) — retirement blocked</div>'
      : '';
    el.innerHTML =
      '<div class="legacy-migration-header">Legacy Transport Migration</div>' +
      '<div class="legacy-migration-days">Days clean: ' + status.daysClean + ' / ' + status.daysRequired + '</div>' +
      '<div class="legacy-migration-status ' + (status.eligible ? 'eligible' : 'not-eligible') + '">' +
        (status.eligible ? 'ELIGIBLE FOR REVIEW' : 'NOT YET ELIGIBLE') +
      '</div>' +
      unattributedHtml +
      (blockingHtml ? '<div class="legacy-blocking-list">' + blockingHtml + '</div>' : '');
  }).catch(function(e) { showToast(e.message, 'err'); });
}
export function loadMoreAgents() {
  if (!state.agentsHasMore || !state.agentsNextCursor) return;
  var url = '/api/agents?limit=100&cursor=' + encodeURIComponent(state.agentsNextCursor) +
    (activeAgentGroupId !== null ? '&groupId=' + activeAgentGroupId : '');
  var searchEl = document.getElementById('agent-search');
  var q = searchEl ? searchEl.value.trim() : '';
  if (q) url += '&q=' + encodeURIComponent(q);
  if (AGENT_FILTER !== 'all') url += '&bucket=' + encodeURIComponent(AGENT_FILTER);
  return apicall(url).then(function(page) {
    state.agents = state.agents.concat((page && page.items) || []);
    state.agentsNextCursor = (page && page.next_cursor) || '';
    state.agentsHasMore = !!(page && page.has_more);
    state.agentsPagesLoaded++;
    // totals intentionally NOT updated here -- they were already
    // fleet-wide-accurate from the first page's response, and appending
    // more rows to `agents` doesn't change the true totals.
    renderAgentRows();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
export function onAgentSearchInput() {
  clearTimeout(state.agentSearchDebounceTimer);
  state.agentSearchDebounceTimer = setTimeout(loadAgents, 300);
}
// Live WS pushes (agentUpdate/scenario_result) arrive per-agent -- on a large
// fleet, dozens can fire in a burst. Calling loadAgents() directly on each one
// would both hammer the API and silently collapse any "Load more" pages the
// operator had loaded back down to page 1. This debounces the burst into one
// refresh and re-walks back to the same page depth via loadMoreAgents().
export function requestAgentsLiveRefresh() {
  clearTimeout(state.agentLiveRefreshTimer);
  state.agentLiveRefreshTimer = setTimeout(function() {
    var targetDepth = state.agentsPagesLoaded;
    var chain = loadAgents();
    for (var i = 1; i < targetDepth; i++) chain = chain.then(loadMoreAgents);
  }, 800);
}
// statTileCard renders one label/value KPI tile (no footer line) -- the
// plain "kpi-card stat-tile" shape shared by the agent, SLA, and findings
// tile rows. Distinct from apCard (always shows a sub-line) and the
// footer/icon-bearing tile() variants defined locally where they're used.
export function statTileCard(lbl, val, col) {
  return '<div class="kpi-card stat-tile"><div class="stat-top"><div><div class="kpi-label">' + lbl +
    '</div><div class="kpi-value" style="color:' + col + '">' + val + '</div></div></div></div>';
}
function renderAgentTiles() {
  var b = state.agentTotals;
  var tile = statTileCard;
  var el = document.getElementById('agent-tiles');
  if (el) el.innerHTML =
    tile('Total agents', b.online + b.degraded + b.offline, 'var(--text)') +
    tile('Online', b.online, b.online ? 'var(--success)' : 'var(--muted)') +
    tile('Degraded', b.degraded, b.degraded ? 'var(--warning)' : 'var(--muted)') +
    tile('Offline', b.offline, b.offline ? 'var(--danger)' : 'var(--muted)') +
    tile('Retired', b.retired, 'var(--muted)');
}
// covSegHtml renders the shared "cov-seg" toggle-button-group shape used by
// several toolbars below (agent/campaign/coverage/findings/run-IOC
// filters): one button per [value, label] item, 'on' when it matches
// activeVal, calling setterFnName(value) on click. countFn is optional --
// when given, each button also shows a dimmed count badge (countFn(value)).
export function covSegHtml(items, activeVal, setterFnName, countFn) {
  return '<div class="cov-seg">' + items.map(function(o) {
    var label = o[1] + (countFn ? ' <span style="opacity:.6">' + countFn(o[0]) + '</span>' : '');
    return '<button class="' + (activeVal === o[0] ? 'on' : '') + '"' + on('click', setterFnName, o[0]) + '>' + label + '</button>';
  }).join('') + '</div>';
}
function renderAgentToolbar() {
  var c = function(k) {
    if (k === 'all') return state.agentTotals.online + state.agentTotals.degraded + state.agentTotals.offline;
    return state.agentTotals[k] || 0;
  };
  var el = document.getElementById('agent-toolbar');
  if (el) el.innerHTML = covSegHtml(
    [['all', 'All'], ['online', 'Online'], ['degraded', 'Degraded'], ['offline', 'Offline'], ['retired', 'Retired']],
    AGENT_FILTER, 'setAgentFilter', c
  );
}
export function setAgentFilter(v) { AGENT_FILTER = v; loadAgents(); }
function renderAgentRows() {
  // Server already scopes `agents` by bucket/search/group -- nothing left
  // to filter client-side.
  var list = state.agents;
  var searchEl = document.getElementById('agent-search');
  var q = searchEl ? searchEl.value.trim() : '';
  var tbody = document.getElementById('agents-body');
  var loadMoreWrap = document.getElementById('agent-load-more-wrap');
  if (loadMoreWrap) loadMoreWrap.style.display = state.agentsHasMore ? '' : 'none';
  if (!list.length) {
    var emptyMsg = q ? 'No agents match "' + x(q) + '".' : ('No agents' + (AGENT_FILTER === 'all' ? ' registered yet.' : ' in this state.'));
    tbody.innerHTML = '<tr><td colspan="8" class="empty">' + emptyMsg + '</td></tr>';
    return;
  }
  tbody.innerHTML = list.map(function(a, idx) {
    var dot = agentDotColor(agentBucket(a));
    var menuId = 'agent-menu-' + idx;
    return '<tr>' +
      '<td style="max-width:180px"><div style="display:flex;align-items:center;gap:0.5rem"><span style="width:8px;height:8px;border-radius:50%;flex-shrink:0;background:' + dot + '"></span>' +
        '<div style="min-width:0"><div class="cell-main" style="font-family:var(--font-mono);font-size:0.78rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:140px" title="' + x(a.hostname || a.agentId) + '">' + x(a.hostname || a.agentId) + '</div>' +
        '<div class="tiny muted" style="font-family:var(--font-mono);font-size:0.6rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:140px" title="' + x(a.agentId) + '">' + x(a.agentId) + '</div></div></div></td>' +
      '<td style="color:var(--muted);font-size:0.78rem;max-width:100px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="' + x(a.osVersion || '') + '">' + x(a.osVersion || '—') + '</td>' +
      '<td class="tiny muted" style="font-family:var(--font-mono);white-space:nowrap">' + x(a.ipAddress || '—') + '</td>' +
      '<td><span class="tag">' + x(a.groupName || 'Ungrouped') + '</span></td>' +
      '<td>' +
        '<span class="sbadge s-' + x(a.status || 'idle') + '">' + x(a.status || 'idle') + '</span>' +
        (a.state && a.state !== 'active' ? ' <span class="sbadge s-' + x(a.state) + '" title="Lifecycle state">' + x(a.state) + '</span>' : '') +
        // Heartbeat (HTTP, every 30s) and the WebSocket task-delivery channel
        // are separate connections -- a proxy/firewall can pass one and block
        // the other, so a fresh heartbeat alone doesn't mean a run can reach
        // this agent. Only shown when that gap is real: status already reads
        // offline covers the "nothing at all" case on its own.
        (a.status !== 'offline' && !a.wsConnected ? ' <span class="sbadge s-paused" title="Heartbeat is reaching the server, but the WebSocket task channel is down -- dispatching a run to this agent will fail until it reconnects. Often a proxy/firewall blocking the WS Upgrade handshake.">&#9888; Task channel down</span>' : '') +
        // transport reflects what the agent's own heartbeat reports (see
        // models.Agent.Transport). An agent stuck on 'legacy' past its
        // first heartbeat never completed mTLS bootstrap -- it enrolls and
        // heartbeats normally, so nothing else here signals a problem, but
        // it silently rejects every scenario dispatch because it never
        // received the command-signing trust cert. Usually means it was
        // installed without --ca-root.
        (a.status !== 'offline' && a.transport === 'legacy' ? ' <span class="sbadge s-paused" title="This agent is on legacy transport -- it never completed mTLS bootstrap and cannot receive signed commands. Scenario dispatch will fail. Usually means it was installed without --ca-root; see the Deploy agent page for the current install command, or fetch the CA root manually from /api/config/ca-root.">&#9888; Legacy transport</span>' : '') +
        (apActiveJobs[a.agentId] ? ' <span class="sbadge s-running" title="Attack-path collection: ' + x(apActiveJobs[a.agentId].status) + '">&#128202; AP</span>' : '') +
      '</td>' +
      '<td style="color:var(--muted);font-size:0.78rem;white-space:nowrap">' + ago(a.lastUpdate) + '</td>' +
      '<td class="tiny" style="font-family:var(--font-mono)">' + (a.sims || 0) + '</td>' +
      '<td>' +
        '<div class="row-menu-wrap">' +
        '<button class="btn btn-outline btn-sm row-menu-btn" onclick="toggleRowMenu(event,\'' + menuId + '\')" title="Actions" aria-haspopup="true">&#8942;</button>' +
        '<div class="row-menu-panel" id="' + menuId + '">' +
          '<button class="row-menu-item" onclick="closeAllRowMenus();openAgentDetail(\'' + x(a.agentId) + '\')">&#128269; Detail</button>' +
          '<button class="row-menu-item" onclick="closeAllRowMenus();openModal(null,\'' + x(a.agentId) + '\')">&#9654; Run simulation</button>' +
          '<button class="row-menu-item" onclick="closeAllRowMenus();safeScan(\'' + x(a.agentId) + '\')">&#128737; Safe Scan</button>' +
          '<button class="row-menu-item" onclick="closeAllRowMenus();openFullReport(\'' + x(a.agentId) + '\')">&#128196; Report (HTML)</button>' +
          '<button class="row-menu-item" onclick="closeAllRowMenus();downloadFullReportPDF(\'' + x(a.agentId) + '\')">&#8595; Report (PDF)</button>' +
          '<button class="row-menu-item" onclick="closeAllRowMenus();downloadFullReportCSV(\'' + x(a.agentId) + '\')">&#8595; Report (CSV)</button>' +
          '<button class="row-menu-item" onclick="closeAllRowMenus();downloadFullReportJSON(\'' + x(a.agentId) + '\')">&#8595; Report (JSON)</button>' +
          '<button class="row-menu-item" onclick="closeAllRowMenus();downloadAuditPack(\'' + x(a.agentId) + '\')">&#8659; Download audit pack</button>' +
          (ROLE === 'admin' ?
            '<button class="row-menu-item" onclick="closeAllRowMenus();moveAgentToGroupPrompt(\'' + x(a.agentId) + '\')">&#128193; Move to group…</button>' : '') +
          (ROLE === 'admin' && a.status !== 'offline' ?
            '<button class="row-menu-item row-menu-item-danger" onclick="closeAllRowMenus();openStopAgentModal(\'' + x(a.agentId) + '\',\'' + x(a.hostname || a.agentId) + '\')">&#9209; Stop agent</button>' : '') +
          (ROLE === 'admin' ?
            '<button class="row-menu-item row-menu-item-danger" onclick="closeAllRowMenus();openUninstallAgentModal(\'' + x(a.agentId) + '\',\'' + x(a.hostname || a.agentId) + '\')">&#128465; Uninstall Agent</button>' : '') +
          (ROLE === 'admin' ?
            '<button class="row-menu-item row-menu-item-danger" onclick="closeAllRowMenus();openRemoveAgentModal(\'' + x(a.agentId) + '\',\'' + x(a.hostname || a.agentId) + '\')">&#9888; Force Remove…</button>' : '') +
        '</div>' +
        '</div>' +
      '</td></tr>';
  }).join('');
}
// Row action menus (the "⋮" dropdown in the Agents table Actions column).
// Only one panel is ever open at a time; toggling re-closes any other open
// panel first so stale menus never linger behind a newly opened one.
export function toggleRowMenu(ev, id) {
  ev.stopPropagation();
  var panel = document.getElementById(id);
  if (!panel) return;
  var wasOpen = panel.classList.contains('open');
  closeAllRowMenus();
  if (wasOpen) return;
  // Position as fixed viewport coordinates from the trigger button's own
  // rect (see the .row-menu-panel CSS comment for why fixed instead of
  // absolute), right-aligned under the button like a standard menu.
  var btnRect = ev.currentTarget.getBoundingClientRect();
  panel.style.right = (window.innerWidth - btnRect.right) + 'px';
  panel.style.left = 'auto';
  panel.style.top = (btnRect.bottom + 4) + 'px';
  panel.style.bottom = 'auto';
  panel.style.maxHeight = 'none';
  panel.classList.add('open');
  // Now that it's rendered, clamp it to the viewport -- a menu opened near
  // the bottom of the screen would otherwise extend past the bottom edge
  // with no way to reach the remaining items.
  var margin = 8;
  var panelRect = panel.getBoundingClientRect();
  if (panelRect.bottom > window.innerHeight - margin) {
    var spaceBelow = window.innerHeight - btnRect.bottom - 4 - margin;
    var spaceAbove = btnRect.top - 4 - margin;
    if (spaceAbove > spaceBelow) {
      panel.style.top = 'auto';
      panel.style.bottom = (window.innerHeight - btnRect.top + 4) + 'px';
      panel.style.maxHeight = Math.max(spaceAbove, 80) + 'px';
    } else {
      panel.style.maxHeight = Math.max(spaceBelow, 80) + 'px';
    }
  }
}
export function closeAllRowMenus() {
  document.querySelectorAll('.row-menu-panel.open').forEach(function(p) { p.classList.remove('open'); });
}
export function __init_L8485() {
document.addEventListener('click', function(e) {
  if (!e.target.closest('.row-menu-wrap')) closeAllRowMenus();
});
}

// A fixed-position panel doesn't track its trigger button on scroll -- close
// it instead of letting it visually drift away from the row it belongs to.
export function __init_L8490() {
window.addEventListener('scroll', closeAllRowMenus, true);
}

// Deploy agent → reveal the in-page Connection Config / download section.
export function showAgentDownload() {
  setAgentsView('operational');
  var w = document.getElementById('conn-cfg-wrap');
  if (!w) return;
  w.style.display = '';
  if (typeof loadConnectionConfig === 'function') loadConnectionConfig();
  w.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// injectServerURL builds the copy-paste install commands. Both fetch the
// deployment CA root first (via the unauthenticated GET /api/config/ca-root
// -- the target machine has no browser session to call the admin-only
// /api/config/connection with) and pass it as --ca-root. Omitting this step
// strands the new agent on legacy transport: it never receives the
// command-signing trust cert, enrolls but shows no visible error, and every
// scenario dispatched to it silently fails at the WS command-envelope check.
export function injectServerURL() {
  var url = window.location.origin;
  var winUrl  = document.getElementById('win-server-url');
  var winCli  = document.getElementById('win-cli-cmd');
  var macCmd  = document.getElementById('mac-cmd');
  if (winUrl)  winUrl.textContent = url;
  if (winCli)  winCli.textContent = 'Invoke-WebRequest -Uri "' + url + '/api/config/ca-root" -OutFile deployment-ca.pem; .\\bas-agent-windows-amd64.exe --install --server ' + url + ' --secret <AGENT_SECRET> --ca-root .\\deployment-ca.pem --env Production';
  if (macCmd)  macCmd.textContent = 'chmod +x bas-agent-darwin-* && curl -sf -o deployment-ca.pem ' + url + '/api/config/ca-root && sudo ./bas-agent-darwin-* --install --server ' + url + ' --ca-root ./deployment-ca.pem --env Production';
}

export function loadConnectionConfig() {
  apicall('/api/config/connection').then(function(data) {
    var wrap = document.getElementById('conn-cfg-wrap');
    if (!wrap) return;
    wrap.style.display = '';
    document.getElementById('cfg-server-url').textContent = window.location.origin;
    var secretEl = document.getElementById('cfg-agent-secret');
    secretEl.dataset.value = data.agentSecret || '';
    // keep masked until user clicks Show
  }).catch(function(e) { showToast('Failed to load connection config: ' + (e.message || 'error'), 'err'); });
}

export function toggleSecret(btn) {
  var el = document.getElementById('cfg-agent-secret');
  var hidden = el.classList.contains('secret-hidden');
  if (hidden) {
    el.textContent = el.dataset.value || '(not configured)';
    el.classList.remove('secret-hidden');
    btn.textContent = 'Hide';
  } else {
    el.textContent = '••••••••••••••••••••••••';
    el.classList.add('secret-hidden');
    btn.textContent = 'Show';
  }
}

export function copyText(elId, btn) {
  var el = document.getElementById(elId);
  // Use data-value when the attribute exists (even if empty string) so masked
  // elements like the agent secret copy the real value, not the bullet placeholder.
  var text = el.hasAttribute('data-value') ? el.dataset.value : el.textContent;
  function onSuccess() {
    var orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(function() { btn.textContent = orig; }, 1500);
  }
  function onFail() { showToast('Copy failed', 'err'); }
  // navigator.clipboard requires a secure context (HTTPS/localhost).
  // Fall back to execCommand for plain-HTTP deployments.
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(onSuccess).catch(onFail);
  } else {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy') ? onSuccess() : onFail(); } catch(e) { onFail(); }
    document.body.removeChild(ta);
  }
}

function stripeColor(id) {
  var h = 0;
  for (var i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) & 0xffff;
  return STRIPE_COLORS[h % STRIPE_COLORS.length];
}

// loadCatalogs fetches the live ART + Caldera catalogs so sweep cards show a
// real technique/ability count and the picker has data. Best-effort: a failure
// (e.g. Caldera offline) just leaves that count blank — it never blocks the UI.
// Re-renders the scenario grid once loaded so counts appear without a refresh.
export function loadCatalogs() {
  // apicall resolves even on HTTP errors (the body is the JSON error object), so
  // guard with Array.isArray — an error body must not be mistaken for a catalog.
  apicall('/api/art/techniques').then(function(d) {
    state.artCatalog = Array.isArray(d) ? d : [];
    if (state.scenarios.length) renderScenarios();
  }).catch(function() {});
  apicall('/api/caldera/abilities').then(function(d) {
    state.calderaCatalog = Array.isArray(d) ? d : [];
    if (state.scenarios.length) renderScenarios();
  }).catch(function() {});
}

export function loadScenarios() {
  apicall('/api/scenarios').then(function(data) {
    state.scenarios = (data || []).map(function(s) {
      return {
        id:                 s.id                 || '',
        name:               s.name               || '',
        description:        s.description         || '',
        author:             s.author              || '',
        tags:               s.tags               || [],
        steps:              s.steps              || [],
        mitrePhases:        s.mitrePhases        || [],
        source:             s.source             || 'builtin',
        executable:         !!s.executable,
        localCheck:         !!s.localCheck,
        calderaAllWindows:  !!s.calderaAllWindows,
        calderaAbilities:   s.calderaAbilities   || [],
        calderaAdversaryId: s.calderaAdversaryId || '',
        artAllWindows:      !!s.artAllWindows,
        artAllPlatform:     !!s.artAllPlatform,
        artSelectiveWindows:  !!s.artSelectiveWindows,
        artSelectivePlatform: !!s.artSelectivePlatform,
        intelSource:        s.intelSource         || '',
        intelActor:         s.intelActor          || '',
        intelConfidence:    s.intelConfidence      || '',
        artTechniques:      s.artTechniques       || [],
        supportedOs:        s.supportedOs         || []
      };
    });
    renderScenarios();
    // renderScheduledAssessmentsList() looks up each schedule's human name
    // from this scenarios array client-side, falling back to the raw
    // scenario ID when not found. loadScenarios() and
    // loadScheduledAssessments() fire independently at boot with no
    // ordering guarantee -- on a fresh page load, if the schedules list
    // rendered first, it's stuck showing the raw ID until something
    // re-renders it. Re-render now that scenarios is actually populated.
    if (SCHED.schedules.length) renderScheduledAssessmentsList();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

var SCENARIO_CATEGORIES = {
  em:    { label: 'Endpoint Mastery',
           icon: '<svg style="width:18px;height:18px;stroke:var(--accent)" viewBox="0 0 24 24" fill="none"><path d="M12 2L4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3z" stroke-width="2" fill="none"/></svg>' },
  intel: { label: 'Threat-Intel',
           icon: '<svg style="width:18px;height:18px;stroke:var(--accent)" viewBox="0 0 24 24" fill="none"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-width="2"/><path d="M9 12l2 2 4-4" stroke-width="2"/></svg>' },
  other: { label: 'Standard & Custom',
           icon: '<svg style="width:18px;height:18px;stroke:var(--muted)" viewBox="0 0 24 24" fill="none"><rect x="3" y="3" width="18" height="18" rx="2" stroke-width="2"/><path d="M3 9h18M9 21V9" stroke-width="2"/></svg>' }
};

// Threat-intel-sourced scenarios (one auto-generated per tracked threat
// actor -- can number in the hundreds) get their own top-level category
// rather than being folded into "Standard & Custom", where a handful of
// real built-in/custom scenarios would otherwise be buried under a huge
// Threat-Intel sub-group. EM still takes priority for the rare case a
// scenario is somehow both (Endpoint Mastery has its own dedicated
// dashboard elsewhere).
export function scenarioCategoryOf(s) {
  if ((s.id || '').indexOf('em-') === 0 || (s.tags || []).indexOf('endpoint-mastery') !== -1) return 'em';
  if (scenarioSourceOf(s) === 'intel') return 'intel';
  return 'other';
}

function scenarioCategoryCounts(list, key) {
  var inCat = list.filter(function(s) { return scenarioCategoryOf(s) === key; });
  var counts = { total: inCat.length, builtin: 0, custom: 0, intel: 0 };
  inCat.forEach(function(s) { counts[scenarioSourceOf(s)]++; });
  return counts;
}

var TMPL_ICON = '<svg style="width:18px;height:18px;stroke:var(--accent)" viewBox="0 0 24 24" fill="none"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" stroke-width="2" stroke-linejoin="round"/></svg>';

function renderScenarioLanding(list, src) {
  var el = document.getElementById('sc-landing');
  if (!el) return;
  var html = ['em', 'intel', 'other'].map(function(key) {
    var cat = SCENARIO_CATEGORIES[key];
    var c = scenarioCategoryCounts(list, key);
    if (c.total === 0) return '';
    // The intel category is single-source by construction (scenarioCategoryOf
    // routes every threat-intel scenario here) -- a Built-in/Custom/Intel
    // breakdown would just repeat "N Intel" next to the count above it.
    var breakdown = key === 'intel' ? '' :
      [c.builtin ? c.builtin + ' Built-in' : '', c.custom ? c.custom + ' Custom' : '', c.intel ? c.intel + ' Intel' : '']
      .filter(Boolean).join(' · ');
    return '<div class="sc-cat-card sc-fade" tabindex="0" role="button" ' +
      'onclick="openScenarioCategory(\'' + key + '\')" ' +
      'onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();openScenarioCategory(\'' + key + '\');}">' +
      '<h3>' + cat.icon + x(cat.label) + '</h3>' +
      '<div class="sc-cat-count">' + c.total + ' scenario' + (c.total === 1 ? '' : 's') + '</div>' +
      '<div class="sc-cat-breakdown">' + x(breakdown) + '</div>' +
    '</div>';
  }).join('');
  // The source filter (Threat intel / Custom) only narrows `list` -- it has
  // no bearing on Adversary Templates below, which aren't drawn from
  // `scenarios` at all (see the sc-filter-source display-toggle comment
  // above). Without this message, filtering to a source with zero real
  // scenarios left "BFSI Scenarios (0)" sitting directly above the
  // Adversary Templates card with no explanation -- reading as if the
  // filter had matched templates instead of correctly matching nothing.
  if (!list.length && src && src !== 'all') {
    var emptySrcLabel = { builtin: 'Built-in', custom: 'Custom', intel: 'Threat Intel' }[src] || src;
    html = '<div class="tiny muted" style="width:100%;padding:0.5rem 0.1rem">There is no Scenarios for ' + x(emptySrcLabel) + ' yet</div>' + html;
  }
  if (_templates.length) {
    html += '<div class="sc-cat-card sc-fade" tabindex="0" role="button" ' +
      'onclick="openScenarioCategory(\'templates\')" ' +
      'onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();openScenarioCategory(\'templates\');}">' +
      '<h3>' + TMPL_ICON + 'Adversary Templates</h3>' +
      '<div class="sc-cat-count">' + _templates.length + ' template' + (_templates.length === 1 ? '' : 's') + '</div>' +
    '</div>';
  }
  el.innerHTML = html || '<p class="empty">No scenarios loaded.</p>';
}

function openScenarioCategory(key) {
  state.scenarioView = key;
  closeScenarioOverlay();
  history.pushState({ scenarioView: key }, '', '#tab-scenarios/' + key);
  renderScenarios();
}
export function closeScenarioCategoryView() {
  if (state.scenarioView === 'search') {
    var se = document.getElementById('sc-search');
    if (se) se.value = '';
  }
  state.scenarioView = 'landing';
  closeScenarioOverlay();
  history.pushState({ scenarioView: 'landing' }, '', '#tab-scenarios');
  renderScenarios();
}
export function __init_L8723() {
window.addEventListener('popstate', function(e) {
  var tab = document.getElementById('tab-scenarios');
  if (!tab || tab.style.display === 'none') return;
  var view = (e.state && e.state.scenarioView) || 'landing';
  if (view === 'landing') {
    var se = document.getElementById('sc-search');
    if (se) se.value = '';
  }
  state.scenarioView = view;
  closeScenarioOverlay();
  renderScenarios();
});
}


// renderScenarios filters the loaded scenarios by the search box + source/OS
// filters, then dispatches to either the category landing or a drilled-in
// category's tile grid depending on scenarioView.
export function renderScenarios() {
  var landingEl = document.getElementById('sc-landing');
  var catEl = document.getElementById('sc-category-view');
  if (!landingEl || !catEl) return;

  if (!state.scenarios.length) {
    catEl.style.display = 'none';
    landingEl.style.display = 'block';
    landingEl.innerHTML = '<p class="empty">No scenarios loaded.</p>';
    document.getElementById('sc-cnt').textContent = 0;
    return;
  }

  var searchEl = document.getElementById('sc-search');
  var srcEl = document.getElementById('sc-filter-source');
  var osEl = document.getElementById('sc-filter-os');
  var q = (searchEl ? searchEl.value : '').trim().toLowerCase();
  var src = srcEl ? srcEl.value : 'all';
  var osFilter = osEl ? osEl.value : 'all';

  var filtered = state.scenarios.filter(function(s) {
    // Endpoint Mastery scenarios live exclusively on the Endpoint Mastery
    // dashboard (its own section below the 14 layer cards) now, not here.
    if (scenarioCategoryOf(s) === 'em') return false;
    if (osFilter !== 'all' && (s.supportedOs || []).indexOf(osFilter) === -1) return false;
    if (src !== 'all' && scenarioSourceOf(s) !== src) return false;
    return true;
  });
  document.getElementById('sc-cnt').textContent = filtered.length;
  document.getElementById('sc-tmpl-filters').style.display = 'none';
  // Adversary Templates aren't drawn from `scenarios` and carry no
  // builtin/custom/intel source field, so this dropdown can't filter them --
  // hide it in template view rather than let it show a stale/irrelevant
  // count for an unrelated array. See sc-tmpl-filters above for the
  // filter that actually applies to templates (category, not source).
  document.getElementById('sc-filter-source').style.display = '';
  // Same reasoning as sc-filter-source above -- renderTemplateGrid() never
  // reads this either, and templates carry no supportedOs field.
  document.getElementById('sc-filter-os').style.display = '';

  if (q) { state.scenarioView = 'search'; }

  if (state.scenarioView === 'search') {
    landingEl.style.display = 'none';
    catEl.style.display = 'block';
    var results = filtered.filter(function(s) {
      var hay = [s.id, s.name, s.description, (s.tags || []).join(' '),
                 (s.mitrePhases || []).join(' '), (s.artTechniques || []).join(' '),
                 s.intelActor].join(' ').toLowerCase();
      return hay.indexOf(q) !== -1;
    });
    document.getElementById('sc-backbar-title').textContent = 'Search results for: "' + x(searchEl.value.trim()) + '" (' + results.length + ')';
    var sgrid = document.getElementById('sc-tile-grid');
    sgrid.innerHTML = results.length
      ? '<div class="sc-fade">' + renderScenarioTileGroup('search', results) + '</div>'
      : '<p class="empty">No scenarios match your search.</p>';
    return;
  }

  if (state.scenarioView === 'landing') {
    catEl.style.display = 'none';
    landingEl.style.display = 'block';
    renderScenarioLanding(filtered, src);
    return;
  }

  if (state.scenarioView === 'templates') {
    landingEl.style.display = 'none';
    catEl.style.display = 'block';
    document.getElementById('sc-tmpl-filters').style.display = 'flex';
    document.getElementById('sc-filter-source').style.display = 'none';
    document.getElementById('sc-filter-os').style.display = 'none';
    renderTemplateGrid();
    return;
  }

  landingEl.style.display = 'none';
  catEl.style.display = 'block';
  var cat = SCENARIO_CATEGORIES[state.scenarioView];
  var inCat = filtered.filter(function(s) { return scenarioCategoryOf(s) === state.scenarioView; });
  document.getElementById('sc-backbar-title').textContent = cat.label + ' (' + inCat.length + ')';
  var grid = document.getElementById('sc-tile-grid');
  grid.innerHTML = inCat.length
    ? '<div class="sc-fade">' + renderScenarioTileGroup(state.scenarioView, inCat) + '</div>'
    : '<p class="empty">No scenarios match your filter.</p>';
}
export function scenarioSearchClear() {
  if (!this.value.trim() && state.scenarioView === 'search') { state.scenarioView = 'landing'; }
  renderScenarios();
}

// Collapsible description: shows a short preview with a "Read more" / "Read less"
// toggle (WhatsApp style) so long scenario paragraphs don't bloat the cards.
var descSeq = 0;
function descHtml(desc, sid, opts) {
  desc = (desc || '').trim();
  opts = opts || {};
  var limit = opts.limit || 140;
  var style = opts.style || '';
  if (desc.length <= limit) {
    return '<p style="' + style + '">' + x(desc) + '</p>';
  }
  // trim the preview back to the last whole word so we don't cut mid-word
  var preview = desc.substring(0, limit).replace(/\s+\S*$/, '');
  var id = 'desc-' + String(sid || 'x').replace(/[^a-zA-Z0-9_-]/g, '') + '-' + (descSeq++);
  return '<p style="' + style + '">' +
    '<span id="' + id + '-s">' + x(preview) + '&hellip; </span>' +
    '<span id="' + id + '-f" style="display:none">' + x(desc) + ' </span>' +
    '<a href="javascript:void(0)" class="desc-toggle" ' +
      'onclick="toggleDesc(\'' + id + '\',this);return false;">Read more</a>' +
    '</p>';
}
function toggleDesc(id, el) {
  var sEl = document.getElementById(id + '-s');
  var fEl = document.getElementById(id + '-f');
  if (!sEl || !fEl) return;
  var expanded = (fEl.style.display !== 'none');
  sEl.style.display = expanded ? 'inline' : 'none';
  fEl.style.display = expanded ? 'none' : 'inline';
  el.textContent = expanded ? 'Read more' : 'Read less';
}

function scenarioSourceOf(s) {
  return s.intelSource ? 'intel' : (s.source || 'builtin');
}
var SCENARIO_SOURCE_LABELS = { builtin: 'Built-in', custom: 'Custom', intel: 'Threat-Intel' };
var SCENARIO_SOURCE_ORDER = ['builtin', 'custom', 'intel'];

function scenarioTileOSBadges(s) {
  var osArr = s.supportedOs || [];
  if (!osArr.length) return '';
  var osIcons = { windows: '<svg viewBox="0 0 24 24" fill="currentColor" width="10" height="10"><path d="M3 3h8.5v8.5H3V3zm10.5 0H22v8.5h-8.5V3zM3 13.5h8.5V22H3v-8.5zm10.5 0H22V22h-8.5v-8.5z"/></svg>', linux: '🐧', darwin: '⌘' };
  var osColors = {
    windows: 'rgba(47,129,247,0.15);color:#58a6ff;border-color:rgba(47,129,247,0.4)',
    linux:   'rgba(47,216,195,0.15);color:#5cead8;border-color:rgba(47,216,195,0.4)',
    darwin:  'rgba(154,169,188,0.15);color:#9aa9bc;border-color:rgba(154,169,188,0.35)'
  };
  return osArr.map(function(os) {
    var lc = os.toLowerCase();
    var col = osColors[lc] || 'rgba(154,169,188,0.12);color:#9aa9bc;border-color:rgba(154,169,188,0.35)';
    return '<span class="tag" style="background:' + col + ';font-size:0.6rem;padding:1px 5px" title="Supported OS: ' + x(os) + '">' + (osIcons[lc] || x(os)) + '</span>';
  }).join('');
}

function scenarioTileMitreBadge(s) {
  var phases = s.mitrePhases || [];
  if (!phases.length) return '';
  var extra = phases.length > 1 ? ' <span style="opacity:0.7">+' + (phases.length - 1) + '</span>' : '';
  return '<span class="tag" style="font-size:0.6rem;padding:1px 5px" title="' + x(phases.join(', ')) + '">' + x(phases[0]) + extra + '</span>';
}

function scenarioTileHTML(s) {
  var color = s.intelSource ? '#2f81f7' : stripeColor(s.id);
  var sid = x(s.id);
  return '<div class="sc-tile" tabindex="0" role="button" aria-expanded="false" data-sid="' + sid + '" ' +
    'onmouseenter="previewScenarioOverlay(\'' + sid + '\')" onmouseleave="unpreviewScenarioOverlay(\'' + sid + '\')" ' +
    'onclick="toggleScenarioPin(event,\'' + sid + '\')" ' +
    'onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();toggleScenarioPin(event,\'' + sid + '\');}">' +
    '<div class="sc-tile-stripe" style="background:' + color + '"></div>' +
    '<div class="sc-tile-name">' + x(s.name) + '</div>' +
    '<div class="sc-tile-badges">' + scenarioTileOSBadges(s) + scenarioTileMitreBadge(s) + '</div>' +
    '<div class="sc-tile-detail" id="scd-' + sid + '">' + scenarioDetailHTML(s) + '</div>' +
  '</div>';
}

function renderScenarioTileGroup(viewKey, list) {
  var bySrc = { builtin: [], custom: [], intel: [] };
  list.forEach(function(s) { bySrc[scenarioSourceOf(s)].push(s); });
  var activeSources = SCENARIO_SOURCE_ORDER.filter(function(k) { return bySrc[k].length; });
  // A single active source (e.g. the Threat-Intel category, which is
  // single-source by construction) would just repeat "X (N)" as a
  // sub-header directly under the backbar title that already says the
  // same thing -- render those tiles flat instead. Mixed-source views
  // (search results, or a category that legitimately spans sources) keep
  // the per-source grouping.
  if (activeSources.length <= 1) {
    return list.map(scenarioTileHTML).join('');
  }
  return activeSources.map(function(k) {
    var collapsed = !!(scenarioSrcCollapsed[viewKey] && scenarioSrcCollapsed[viewKey][k]);
    return '<div class="sc-src-group">' +
      '<div class="sc-src-hdr' + (collapsed ? ' collapsed' : '') + '" onclick="toggleScenarioSrcGroup(\'' + viewKey + '\',\'' + k + '\')">' +
        '<span class="chev">&#9660;</span>' + x(SCENARIO_SOURCE_LABELS[k]) + ' (' + bySrc[k].length + ')' +
      '</div>' +
      '<div class="sc-src-body' + (collapsed ? ' collapsed' : '') + '">' + bySrc[k].map(scenarioTileHTML).join('') + '</div>' +
    '</div>';
  }).join('');
}

export function toggleScenarioSrcGroup(viewKey, srcKey) {
  if (!scenarioSrcCollapsed[viewKey]) scenarioSrcCollapsed[viewKey] = {};
  scenarioSrcCollapsed[viewKey][srcKey] = !scenarioSrcCollapsed[viewKey][srcKey];
  renderScenarios();
}

function _scOverlayEl(id) { return document.getElementById('scd-' + id); }
function _scTileEl(id) {
  var d = _scOverlayEl(id);
  return d ? d.parentElement : null;
}

// Keeps the 420px overlay from clipping past the right edge of the viewport
// for tiles that aren't in the leftmost grid column.
function _scPositionOverlay(id) {
  var detail = _scOverlayEl(id);
  var tile = _scTileEl(id);
  if (!detail || !tile) return;
  detail.style.left = '';
  detail.style.right = '';
  var rect = tile.getBoundingClientRect();
  if (rect.left + 420 > window.innerWidth - 16) {
    detail.style.left = 'auto';
    detail.style.right = '0';
  }
}

function previewScenarioOverlay(id) {
  if (state.overlayPinned) return; // a pinned overlay is never disturbed by hovering elsewhere
  var detail = _scOverlayEl(id);
  if (!detail) return;
  _scPositionOverlay(id);
  detail.classList.add('show');
}
export function unpreviewScenarioOverlay(id) {
  if (state.overlayPinned === id) return; // pinned overlays only close via toggle/ESC/outside-click
  var detail = _scOverlayEl(id);
  if (detail) detail.classList.remove('show');
}
function toggleScenarioPin(event, id) {
  // A click on a button/link inside the already-open detail panel must not
  // re-toggle the tile's own pin state — the panel is a DOM child of the
  // tile, so such clicks bubble up to this same handler.
  if (event.target.closest && event.target.closest('.sc-tile-detail')) return;
  event.stopPropagation();
  if (state.overlayPinned === id) { closeScenarioOverlay(); return; }
  closeScenarioOverlay();
  state.overlayPinned = id;
  var tile = _scTileEl(id);
  var detail = _scOverlayEl(id);
  if (tile) { tile.classList.add('pinned'); tile.setAttribute('aria-expanded', 'true'); }
  if (detail) { _scPositionOverlay(id); detail.classList.add('show'); }
}
export function closeScenarioOverlay() {
  if (!state.overlayPinned) return;
  var tile = _scTileEl(state.overlayPinned);
  var detail = _scOverlayEl(state.overlayPinned);
  if (tile) { tile.classList.remove('pinned'); tile.setAttribute('aria-expanded', 'false'); }
  if (detail) detail.classList.remove('show');
  state.overlayPinned = null;
}
export function __init_L8985() {
document.addEventListener('click', function(e) {
  if (!state.overlayPinned) return;
  var detail = _scOverlayEl(state.overlayPinned);
  var tile = _scTileEl(state.overlayPinned);
  if ((detail && detail.contains(e.target)) || (tile && tile.contains(e.target))) return;
  closeScenarioOverlay();
});
}

export function __init_L8992() {
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape' && state.overlayPinned) {
    var tile = _scTileEl(state.overlayPinned);
    closeScenarioOverlay();
    if (tile) tile.focus();
  }
});
}


function scenarioDetailHTML(s) {
      var visibleTags = (s.tags || []).filter(function(t) {
        return t !== 'intel' && t !== 'auto-generated';
      });
      var tags = visibleTags.map(function(t) { return '<span class="tag">' + x(t) + '</span>'; }).join('');
      var intelBadge = '';
      if (s.intelSource) {
        var confColor = s.intelConfidence === 'high' ? '#5cead8' : s.intelConfidence === 'medium' ? '#d29922' : '#9aa9bc';
        intelBadge = '<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(47,129,247,0.12);' +
          'border:1px solid rgba(47,129,247,0.35);border-radius:4px;padding:2px 7px;font-size:0.72rem;color:#58a6ff;font-weight:600;margin-bottom:6px">' +
          '&#128268; Intel &nbsp;·&nbsp; ' + x(s.intelActor) +
          ' &nbsp;<span style="color:' + confColor + '">' + x(s.intelConfidence) + '</span>' +
          ' &nbsp;·&nbsp; ' + x(s.intelSource.toUpperCase()) + '</span><br>';
        var techCount = (s.artTechniques || []).length;
        // No delete action here, deliberately -- auto-generated intel
        // scenarios cannot be deleted by anyone, through any path (the
        // backend enforces this too; see Engine.Delete's intel-source guard).
        var footerMeta = techCount + ' techniques';
        return '<div>' + intelBadge + '</div>' +
          '<h3>' + x(s.name) + '</h3>' +
          descHtml(s.description, s.id, {limit:120, style:'font-size:0.78rem;color:var(--muted)'}) +
          '<div class="tags">' + tags + '</div>' +
          '<div class="card-footer">' +
            '<div class="card-meta">' + footerMeta + '</div>' +
            '<button class="btn btn-outline-green btn-sm" onclick="openModal(\'' + x(s.id) + '\',null)">&#9654; Run</button>' +
          '</div>';
      }
      var canEdit = (ROLE === 'admin' || ROLE === 'analyst');
      var customBadge = s.source === 'custom'
        ? '<span class="tag" style="background:rgba(47,216,195,0.15);color:#5cead8;border-color:rgba(47,216,195,0.4)">custom</span> '
        : '';
      var editBtns = '';
      if (canEdit) {
        editBtns += '<button class="btn btn-outline btn-sm" onclick="cloneScenario(\'' + x(s.id) + '\')" title="Clone into an editable custom scenario">&#9112; Clone</button> ';
        if (s.source === 'custom') {
          editBtns += '<button class="btn btn-outline btn-sm" onclick="openBuilder(\'' + x(s.id) + '\')" title="Edit">&#9998; Edit</button> ';
          editBtns += '<button class="btn btn-sm" style="background:rgba(218,54,51,0.12);color:#f85149" onclick="deleteCustomScenario(\'' + x(s.id) + '\')" title="Delete">&#10005;</button> ';
        }
      }
      // Mode label — describe what the scenario actually runs. Sweep scenarios
      // carry an empty technique/ability list (the real set is resolved live on
      // the server), so they must be detected by their flags, not list length —
      // otherwise they fall through to a meaningless "0 steps". Live catalog
      // counts get appended in Phase B.
      var modeMeta;
      var stepN = (s.steps || []).length;
      if (s.localCheck) {
        modeMeta = '<a href="javascript:void(0)" class="desc-toggle" title="Choose which posture checks to run" ' +
          'onclick="openModal(\'' + x(s.id) + '\',null);return false;">Posture check &#9881;</a>';
      } else if (s.artAllWindows) {
        modeMeta = 'Full ART sweep' + (state.artCatalog.length ? ' · ' + state.artCatalog.length + ' techniques' : '');
      } else if (s.artAllPlatform) {
        // artCatalog is the Windows-scoped catalog count -- not meaningful
        // for a Linux/macOS full sweep, so no count is shown here (the
        // read-only Detailed view has the real per-platform number).
        modeMeta = 'Full ART sweep';
      } else if (s.artSelectiveWindows) {
        modeMeta = 'Selective ART sweep' + (state.artCatalog.length ? ' · up to ' + state.artCatalog.length + ' techniques' : '');
      } else if (s.artSelectivePlatform) {
        modeMeta = 'Selective ART sweep';
      } else if (s.calderaAllWindows) {
        modeMeta = 'Full Caldera sweep' + (state.calderaCatalog.length ? ' · ' + state.calderaCatalog.length + ' abilities' : '');
      } else if ((s.artTechniques || []).length) {
        modeMeta = s.artTechniques.length + ' ART techniques';
      } else if ((s.calderaAbilities || []).length) {
        modeMeta = s.calderaAbilities.length + ' Caldera abilities';
      } else if (stepN) {
        // The step count is a live entry point to the step picker — operators can
        // click it to choose which steps to run (steps come straight from the YAML).
        modeMeta = '<a href="javascript:void(0)" class="desc-toggle" title="Choose which steps to run" ' +
          'onclick="openPicker(\'' + x(s.id) + '\',\'steps\');return false;">' +
          stepN + (stepN === 1 ? ' step' : ' steps') + '</a>';
      } else {
        modeMeta = '—';
      }

      // OS platform badge
      var osArr = s.supportedOs || [];
      var osBadge = '';
      if (osArr.length > 0) {
        var osIcons = { windows: '<svg viewBox="0 0 24 24" fill="currentColor" width="10" height="10"><path d="M3 3h8.5v8.5H3V3zm10.5 0H22v8.5h-8.5V3zM3 13.5h8.5V22H3v-8.5zm10.5 0H22V22h-8.5v-8.5z"/></svg>', linux: '🐧', darwin: '⌘' };
        var osColors = {
          windows: 'rgba(47,129,247,0.15);color:#58a6ff;border-color:rgba(47,129,247,0.4)',
          linux:   'rgba(47,216,195,0.15);color:#5cead8;border-color:rgba(47,216,195,0.4)',
          darwin:  'rgba(154,169,188,0.15);color:#9aa9bc;border-color:rgba(154,169,188,0.4)'
        };
        var osOnly = (osArr.length === 1);
        osBadge = osArr.map(function(os) {
          var lc = os.toLowerCase();
          var col = osColors[lc] || 'rgba(154,169,188,0.12);color:#9aa9bc;border-color:rgba(154,169,188,0.35)';
          var label = osOnly ? (os === 'darwin' ? 'macOS' : os.charAt(0).toUpperCase() + os.slice(1)) : (osIcons[lc] || os);
          return '<span class="tag" style="background:' + col + ';font-size:0.62rem;padding:1px 6px" title="Supported OS: ' + os + '">' + label + '</span>';
        }).join('') + ' ';
      }

      // Customize: ART/Caldera scenarios can be narrowed to a chosen subset of
      // techniques/abilities before running. Detect the framework from the flags
      // or the explicit list.
      var fw = (s.artAllWindows || s.artAllPlatform || s.artSelectiveWindows || s.artSelectivePlatform || (s.artTechniques || []).length) ? 'art'
             : (s.calderaAllWindows || (s.calderaAbilities || []).length) ? 'caldera'
             : (!s.localCheck && stepN) ? 'steps'
             : '';
      var fwNoun = fw === 'art' ? 'techniques' : fw === 'caldera' ? 'abilities' : 'steps';
      // art_all_windows/art_all_platform always run every atomic for every
      // technique their platform supports -- no subset to choose, so a
      // read-only Detailed view replaces the selectable Customize button
      // here too (same reasoning as renderModalSelection for the Run modal).
      var customizeBtn = (s.artAllWindows || s.artAllPlatform)
        ? '<button class="btn btn-outline btn-sm" onclick="openDetailedViewForScenario(\'' + x(s.id) + '\')" ' +
          'title="Every atomic test that will run">&#128269; Detailed view</button> '
        : fw
        ? '<button class="btn btn-outline btn-sm" onclick="openPicker(\'' + x(s.id) + '\',\'' + fw + '\')" ' +
          'title="Choose which ' + fwNoun + ' to run">&#9881; Customize</button> '
        : '';

      return '<div>' + customBadge + '</div>' +
        '<h3>' + x(s.name) + '</h3>' +
        descHtml(s.description, s.id, {limit:140}) +
        '<div class="tags">' + osBadge + tags + '</div>' +
        '<div class="card-footer">' +
          '<div class="card-meta">' + modeMeta + '</div>' +
          '<div style="display:flex;gap:0.3rem;flex-wrap:wrap;justify-content:flex-end">' +
            editBtns + customizeBtn +
            '<button class="btn btn-outline-green btn-sm" onclick="openModal(\'' + x(s.id) + '\',null)">&#9654; Run</button>' +
          '</div>' +
        '</div>';
}