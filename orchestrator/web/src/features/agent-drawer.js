import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { ago, showToast } from '../core/util.js';
import { loadAgents } from './attack-path.js';
import { buildReportFilename, showDownloadOptions, triggerDownload } from './evidence.js';
import { apArrow, apNodePill } from './openaev.js';
import { openModal } from './reports.js';
import { _riskScoreColor, _riskTrendBadge } from './shell.js';


/* ═══════════════════════════════════════════════════════════════════════════
   REPORTING MODULE
   ═══════════════════════════════════════════════════════════════════════════ */

// ── Agent Detail Drawer ───────────────────────────────────────────────────────

export var _agtDetailId = null;
var _agtLogTier = 'operational';
var _agtLogRefresh = null;
 // '' = All Metrics

export function updateLinuxDownloadCmd(arch, type) {
  // Update Linux installation commands based on selected architecture and package type
  // arch: 'amd64' or 'arm64'
  // type: 'deb' or 'rpm'
  if (type === 'deb') {
    document.getElementById('linux-deb-cmd').textContent = 'sudo dpkg -i bas-agent-linux-' + arch + '.deb && sudo systemctl start bas-agent';
  } else if (type === 'rpm') {
    document.getElementById('linux-rpm-cmd').textContent = 'sudo rpm -i bas-agent-linux-' + arch + '.rpm && sudo systemctl start bas-agent';
  }
}

export function openAgentDetail(agentId) {
  _agtDetailId = agentId;
  document.getElementById('agt-detail-title').textContent = 'Agent: ' + agentId.substring(0,12) + '…';
  document.getElementById('agent-detail-overlay').classList.add('open');
  showAgentTab('overview');
}
export function closeAgentDetail() {
  document.getElementById('agent-detail-overlay').classList.remove('open');
  if (_agtLogRefresh) { clearInterval(_agtLogRefresh); _agtLogRefresh = null; }
  _agtDetailId = null;
}
export function closeAgentDetailOnBackdrop(el, event) { if (event.target === el) closeAgentDetail(); }
export function showAgentTab(tab) {
  ['overview','scenarios','logs','health','attackpath','risk'].forEach(function(t) {
    document.getElementById('agt-tab-' + t).style.display = (t === tab ? '' : 'none');
  });
  document.querySelectorAll('#agt-tab-bar .tab-btn').forEach(function(btn, i) {
    var tabs = ['overview','scenarios','logs','health','attackpath','risk'];
    btn.classList.toggle('active', tabs[i] === tab);
  });
  if (_agtLogRefresh) { clearInterval(_agtLogRefresh); _agtLogRefresh = null; }
  var id = _agtDetailId;
  if (!id) return;
  if (tab === 'overview')   loadAgtOverview(id);
  if (tab === 'scenarios')  loadAgtScenarios(id);
  if (tab === 'logs')       { _agtLogTier = 'operational'; loadAgtLogs(id, _agtLogTier); _agtLogRefresh = setInterval(function(){ loadAgtLogs(_agtDetailId, _agtLogTier); }, 15000); }
  if (tab === 'health')     loadAgtHealth(id);
  if (tab === 'attackpath') loadAgtAttackPath(id);
  if (tab === 'risk')       loadAgtRisk(id);
}

// ── Overview tab ──────────────────────────────────────────────────────────────
function loadAgtOverview(agentId) {
  var pane = document.getElementById('agt-tab-overview');
  pane.innerHTML = '<div style="color:var(--muted);padding:1rem">Loading…</div>';
  apicall('/api/agents').then(function(data) {
    var a = (data || []).find(function(ag) { return ag.agentId === agentId; });
    if (!a) { pane.innerHTML = '<div style="padding:1rem;color:var(--danger)">Agent not found</div>'; return; }
    document.getElementById('agt-detail-title').textContent = 'Agent: ' + x(a.hostname || agentId);
    var stateColor = {active:'var(--success)',enrolling:'var(--accent)',restricted:'var(--warning)',quarantined:'var(--danger)',retired:'var(--muted)',uninstalling:'var(--accent)',uninstalled:'var(--muted)'}[a.state] || 'var(--muted)';
    var policy = a.policy || {};
    pane.innerHTML =
      '<div style="padding:1rem 1.25rem">' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem 1.5rem;margin-bottom:1rem">' +
      kv('Hostname',     x(a.hostname))    + kv('Agent ID', '<code style="font-size:0.75rem">' + x(a.agentId) + '</code>') +
      kv('IP Address',   x(a.ipAddress))   + kv('OS', x(a.osVersion || '—')) +
      kv('Username',     x(a.username))    + kv('Environment', x(a.envLabel || '—')) +
      kv('Connectivity', '<span class="sbadge s-' + x(a.status||'idle') + '">' + x(a.status||'idle') + '</span>' +
        // Same gap the System Tree table row already guards against (see
        // renderAgentRows): heartbeat (HTTP, every 30s) and the WebSocket
        // task-delivery channel are separate connections, and a fresh
        // heartbeat alone doesn't mean a run/sweep can actually reach this
        // agent. Previously this drawer showed only the heartbeat status,
        // so an agent could read "idle" here while genuinely unable to
        // receive any dispatch -- exactly what caused a stuck EM sweep to
        // look like nothing was wrong from this view.
        (a.status !== 'offline' && !a.wsConnected ? ' <span class="sbadge s-paused" title="Heartbeat is reaching the server, but the WebSocket task channel is down -- dispatching a run to this agent will fail until it reconnects. Often a proxy/firewall blocking the WS Upgrade handshake.">&#9888; Task channel down</span>' : '') +
        // Same class of silent gap as Task channel down, but for mTLS: this
        // agent's own heartbeat reports it never completed certificate
        // bootstrap, so it can't receive signed commands even though it
        // looks perfectly healthy otherwise. See renderAgentRows' matching
        // badge and models.Agent.Transport's doc comment.
        (a.status !== 'offline' && a.transport === 'legacy' ? ' <span class="sbadge s-paused" title="This agent is on legacy transport -- it never completed mTLS bootstrap and cannot receive signed commands. Scenario dispatch will fail. Usually means it was installed without --ca-root; see the Deploy agent page for the current install command.">&#9888; Legacy transport</span>' : '')) +
      kv('Lifecycle',    '<span class="sbadge s-' + x(a.state||'active') + '" style="color:' + stateColor + '">' + x(a.state||'active') + '</span>') +
      kv('Last Seen',    ago(a.lastUpdate)) + kv('Enrolled', a.enrolledAt ? ago(a.enrolledAt) : '—') +
      kv('Binary Trusted', a.binaryTrusted ? '<span class="u-success">&#10003; Verified</span>' : '<span class="u-warning">&#9888; Unverified</span>') +
      '</div>' +
      (a.state === 'quarantined' ? '<div style="background:rgba(218,54,51,.12);border:1px solid var(--danger);border-radius:4px;padding:0.6rem 0.85rem;color:var(--danger);font-size:0.78rem;margin-bottom:0.75rem">&#9888; Agent is QUARANTINED — binary hash mismatch detected. Scenario dispatch is blocked. Restore to Active once the issue is resolved.</div>' : '') +
      (a.state === 'restricted'  ? '<div style="background:rgba(210,153,34,.12);border:1px solid var(--warning);border-radius:4px;padding:0.6rem 0.85rem;color:var(--warning);font-size:0.78rem;margin-bottom:0.75rem">&#9888; Agent is RESTRICTED — scenario dispatch is blocked by policy. Restore to Active to re-enable.</div>' : '') +
      (a.state === 'retired'     ? '<div style="background:rgba(100,116,139,.12);border:1px solid rgba(100,116,139,.4);border-radius:4px;padding:0.6rem 0.85rem;color:#94a3b8;font-size:0.78rem;margin-bottom:0.75rem">&#128683; Agent is RETIRED — decommissioned and blocked from running scenarios. Restore to Active to re-enable.</div>' : '') +
      (a.state === 'uninstalling' ? '<div style="background:rgba(47,129,247,.12);border:1px solid rgba(47,129,247,.4);border-radius:4px;padding:0.6rem 0.85rem;color:var(--accent);font-size:0.78rem;margin-bottom:0.75rem">&#8987; Uninstall in progress — waiting for the endpoint to confirm.</div>' : '') +
      (a.state === 'uninstalled'  ? '<div style="background:rgba(100,116,139,.12);border:1px solid rgba(100,116,139,.4);border-radius:4px;padding:0.6rem 0.85rem;color:#94a3b8;font-size:0.78rem;margin-bottom:0.75rem">&#10003; Agent confirmed it uninstalled itself.</div>' : '') +
      (a.uninstallError ? '<div style="background:rgba(218,54,51,.12);border:1px solid var(--danger);border-radius:4px;padding:0.6rem 0.85rem;color:var(--danger);font-size:0.78rem;margin-bottom:0.75rem">&#9888; Uninstall failed: ' + x(a.uninstallError) + (a.uninstallErrorAt ? ' (' + x(new Date(a.uninstallErrorAt).toLocaleString()) + ')' : '') + '</div>' : '') +
      (a.stoppedBy ? '<div style="background:rgba(218,54,51,.12);border:1px solid var(--danger);border-radius:4px;padding:0.6rem 0.85rem;color:var(--danger);font-size:0.78rem;margin-bottom:0.75rem">&#9209; Agent was stopped by ' + x(a.stoppedByName || a.stoppedBy) + ' on ' + x(new Date(a.stoppedAt).toLocaleString()) + ': ' + x(a.stopReason || '') + '. It will not restart automatically. Physical/console access to the endpoint is required to bring it back.</div>' : '') +
      (Object.keys(policy).length ? '<div style="background:var(--elevated);border:1px solid var(--border);border-radius:4px;padding:0.7rem 0.9rem;margin-bottom:0.75rem">' +
        '<div style="font-weight:600;font-size:0.78rem;margin-bottom:0.4rem;color:var(--muted)">POLICY BUNDLE</div>' +
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:0.3rem 1rem;font-size:0.77rem">' +
        kv('Log Level', x(policy.logLevel || 'info')) +
        kv('Max Concurrent', policy.maxConcurrentRuns || 'unlimited') +
        kv('Heartbeat Interval', (policy.heartbeatIntervalS || 30) + 's') +
        kv('Exec Window', x(policy.executionWindow || 'unrestricted')) +
        '</div>' +
      '</div>' : '') +
      '<div style="border-top:1px solid var(--border);padding-top:0.85rem;margin-top:0.25rem">' +
        '<div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:0.55rem">Lifecycle Controls</div>' +
        '<div style="display:flex;gap:0.5rem;flex-wrap:wrap">' +
          (a.state !== 'active' ?
            '<button class="btn btn-primary btn-sm" onclick="setAgentState(\'' + x(a.agentId) + '\',\'active\')">&#10003; Restore to Active</button>' : '') +
          (a.state !== 'quarantined' ?
            '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger-border)" onclick="setAgentState(\'' + x(a.agentId) + '\',\'quarantined\')">&#9888; Quarantine</button>' : '') +
          (a.state !== 'restricted' ?
            '<button class="btn btn-outline btn-sm" style="color:var(--warning);border-color:var(--warning-border)" onclick="setAgentState(\'' + x(a.agentId) + '\',\'restricted\')">&#128274; Restrict</button>' : '') +
          (a.state !== 'retired' ?
            '<button class="btn btn-outline btn-sm u-muted" onclick="setAgentState(\'' + x(a.agentId) + '\',\'retired\')">&#128683; Retire</button>' : '') +
        '</div>' +
        '<div style="font-size:0.7rem;color:var(--muted);margin-top:0.45rem">Quarantine / Restrict / Retire all block scenario dispatch. Only <strong>Restore to Active</strong> re-enables the agent.</div>' +
      '</div>' +
      '</div>';
  }).catch(function(e) { pane.innerHTML = '<div style="padding:1rem;color:var(--danger)">' + x(e.message) + '</div>'; });
}
function kv(label, val) {
  return '<div><div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:0.1rem">' + label + '</div>' +
         '<div style="font-size:0.82rem">' + val + '</div></div>';
}

export function setAgentState(agentId, newState) {
  var labels = { quarantined: 'Quarantine', restricted: 'Restrict', retired: 'Retire', active: 'Restore to Active' };
  var warn = {
    quarantined: 'Quarantine blocks ALL scenario dispatch from this agent. Are you sure?',
    restricted:  'Restrict blocks ALL scenario dispatch from this agent. Are you sure?',
    retired:     'Retire decommissions this agent and blocks all scenario dispatch. Are you sure?',
    active:      'Restore this agent to active and re-enable scenario dispatch?'
  };
  if (!confirm(warn[newState] || 'Set agent state to ' + newState + '?')) return;
  apicall('/api/agents/' + encodeURIComponent(agentId) + '/state', {
    method: 'PUT', body: JSON.stringify({ state: newState })
  }).then(function() {
    showToast('Agent state set to ' + newState, newState === 'active' ? 'ok' : 'warn');
    loadAgents();
    loadAgtOverview(agentId);
  }).catch(function(e) { showToast(e.message, 'err'); });
}

// ── Scenarios tab ─────────────────────────────────────────────────────────────
function loadAgtScenarios(agentId) {
  var pane = document.getElementById('agt-tab-scenarios');
  pane.innerHTML = '<div style="color:var(--muted);padding:1rem">Loading…</div>';
  apicall('/api/scenarios/runs?agentId=' + encodeURIComponent(agentId)).then(function(runs) {
    if (!runs || !runs.length) {
      pane.innerHTML = '<div style="padding:1rem;color:var(--muted)">No scenario runs found for this agent.</div>';
      return;
    }
    var rows = runs.map(function(r) {
      var score = r.score ? Math.round(r.score.preventionScore || 0) : null;
      var scoreHtml = score !== null
        ? '<span style="color:' + (score>=70?'var(--success)':score>=40?'var(--warning)':'var(--danger)') + '">' + score + '%</span>'
        : '<span class="u-muted">—</span>';
      var statusColor = {completed:'var(--success)',running:'var(--accent)',partial:'var(--warning)',failed:'var(--danger)'}[r.status] || 'var(--muted)';
      return '<tr>' +
        '<td>' + x(r.name||r.scenarioId) + '</td>' +
        '<td style="color:var(--muted);font-size:0.75rem">' + ago(r.startedAt) + '</td>' +
        '<td>' + scoreHtml + '</td>' +
        '<td><span style="color:' + statusColor + '">' + x(r.status) + '</span></td>' +
        '<td><button class="btn btn-outline btn-sm" onclick=\'viewRunResults(' + JSON.stringify(r).replace(/'/g,"&#39;") + ')\'>&#128202; Results</button></td>' +
        '</tr>';
    }).join('');
    pane.innerHTML =
      '<div style="padding:1rem 1.25rem">' +
      '<table style="width:100%;border-collapse:collapse;font-size:0.8rem">' +
      '<thead><tr style="color:var(--muted);font-size:0.7rem;text-transform:uppercase;border-bottom:1px solid var(--border)">' +
      '<th style="padding:0.4rem 0.5rem 0.4rem 0;text-align:left">Scenario</th>' +
      '<th style="padding:0.4rem 0.5rem;text-align:left">When</th>' +
      '<th style="padding:0.4rem 0.5rem;text-align:left">Score</th>' +
      '<th style="padding:0.4rem 0.5rem;text-align:left">Status</th>' +
      '<th style="padding:0.4rem 0;text-align:left"></th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table></div>';
  }).catch(function(e) { pane.innerHTML = '<div style="padding:1rem;color:var(--danger)">' + x(e.message) + '</div>'; });
}

// _AGT_TELEMETRY_METRICS groups every metric name the agent actually emits
// (see agent/agent.go and agent/sched_metrics.go's logger.Metric(...) call
// sites) so the Telemetry filter dropdown never lists a metric that can't
// appear in the data -- and so a newly-added logger.Metric(...) call is a
// one-line addition here, not a guess.
var _AGT_TELEMETRY_METRICS = [
  { group: 'Health',       metrics: ['heartbeat_latency_ms', 'scenario_duration_ms'] },
  { group: 'Connectivity', metrics: ['ws_reconnect_attempts', 'ws_connection_duration_seconds'] },
  { group: 'Scheduler',    metrics: ['sched_jobs_total', 'sched_timeout_count', 'sched_panic_count',
                                      'sched_queue_wait_avg_ms', 'sched_queue_wait_max_ms',
                                      'sched_lock_wait_avg_ms', 'sched_lock_wait_max_ms',
                                      'sched_execution_avg_ms', 'sched_execution_max_ms',
                                      'sched_active_jobs', 'sched_queued_jobs',
                                      'sched_retry_count', 'sched_breaker_open_count',
                                      'sched_breaker_suppressed_count'] }
];

// ── Logs tab ──────────────────────────────────────────────────────────────────
export function loadAgtLogs(agentId, tier) {
  _agtLogTier = tier;
  if (tier !== 'telemetry') state._agtLogTelemetryMetric = '';
  var pane = document.getElementById('agt-tab-logs');
  var url = tier === 'security'  ? '/api/agents/' + encodeURIComponent(agentId) + '/logs/security' :
            tier === 'telemetry' ? '/api/agents/' + encodeURIComponent(agentId) + '/telemetry' :
                                   '/api/agents/' + encodeURIComponent(agentId) + '/logs/operational';
  if (tier === 'telemetry' && state._agtLogTelemetryMetric) {
    url += '?metric=' + encodeURIComponent(state._agtLogTelemetryMetric);
  }
  var tierBtns =
    '<div style="display:flex;gap:0.4rem;align-items:center;padding:0.75rem 1.25rem;border-bottom:1px solid var(--border);flex-shrink:0">' +
    ['operational','security','telemetry'].map(function(t) {
      return '<button class="tier-btn' + (t===tier?' active':'') + '" onclick="loadAgtLogs(\'' + x(agentId) + '\',\'' + t + '\')">' + t.charAt(0).toUpperCase()+t.slice(1) + '</button>';
    }).join('') +
    (tier === 'telemetry'
      ? '<select onchange="_agtLogTelemetryMetric=this.value;loadAgtLogs(\'' + x(agentId) + '\',\'telemetry\')" ' +
        'style="margin-left:0.5rem;background:var(--elevated);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:0.25rem 0.4rem;font-size:0.78rem">' +
        '<option value=""' + (state._agtLogTelemetryMetric===''?' selected':'') + '>All Metrics</option>' +
        _AGT_TELEMETRY_METRICS.map(function(g) {
          return '<optgroup label="' + x(g.group) + '">' + g.metrics.map(function(m) {
            return '<option value="' + x(m) + '"' + (state._agtLogTelemetryMetric===m?' selected':'') + '>' + x(m) + '</option>';
          }).join('') + '</optgroup>';
        }).join('') +
        '</select>'
      : '') +
    '</div>';

  apicall(url + (url.indexOf('?')>=0 ? '&' : '?') + 'limit=100').then(function(rows) {
    var tbody = '';
    if (!rows || !rows.length) {
      tbody = '<tr><td colspan="4" style="padding:0.8rem;color:var(--muted);text-align:center">No ' + tier + ' logs yet</td></tr>';
    } else if (tier === 'telemetry') {
      tbody = rows.map(function(r) {
        return '<tr style="border-bottom:1px solid rgba(34,50,74,.4)">' +
          '<td style="padding:0.3rem 0.5rem;color:var(--muted);font-size:0.72rem;white-space:nowrap">' + fmtTs(r.createdAt) + '</td>' +
          '<td style="padding:0.3rem 0.5rem;font-weight:500">' + x(r.metric) + '</td>' +
          '<td style="padding:0.3rem 0.5rem;color:var(--accent)">' + (Math.round(r.value*100)/100) + ' ' + x(r.unit||'') + '</td>' +
          '</tr>';
      }).join('');
    } else if (tier === 'security') {
      tbody = rows.map(function(r) {
        var lvlColor = {error:'var(--danger)',warn:'var(--warning)',info:'var(--success)'}[r.level] || 'var(--muted)';
        return '<tr style="border-bottom:1px solid rgba(34,50,74,.4)">' +
          '<td style="padding:0.3rem 0.5rem;color:var(--muted);font-size:0.72rem;white-space:nowrap">' + fmtTs(r.createdAt) + '</td>' +
          '<td style="padding:0.3rem 0.5rem"><span style="color:' + lvlColor + ';font-size:0.72rem">' + x(r.level||'info') + '</span></td>' +
          '<td style="padding:0.3rem 0.5rem;color:var(--muted);font-size:0.75rem">' + x(r.category||'') + '</td>' +
          '<td style="padding:0.3rem 0.5rem">' + x(r.message) + '</td>' +
          '</tr>';
      }).join('');
    } else {
      tbody = rows.map(function(r) {
        var lvlColor = {error:'var(--danger)',warn:'var(--warning)',info:'var(--muted)',debug:'var(--muted)'}[r.level] || 'var(--muted)';
        return '<tr style="border-bottom:1px solid rgba(34,50,74,.4)">' +
          '<td style="padding:0.3rem 0.5rem;color:var(--muted);font-size:0.72rem;white-space:nowrap">' + fmtTs(r.createdAt) + '</td>' +
          '<td style="padding:0.3rem 0.5rem"><span style="color:' + lvlColor + ';font-size:0.72rem">' + x(r.level||'info') + '</span></td>' +
          '<td style="padding:0.3rem 0.5rem;color:var(--muted);font-size:0.75rem">' + x(r.category||'') + '</td>' +
          '<td style="padding:0.3rem 0.5rem">' + x(r.message) + '</td>' +
          '</tr>';
      }).join('');
    }
    pane.innerHTML = tierBtns +
      '<div style="overflow-y:auto;padding:0 1.25rem 1rem">' +
      '<table style="width:100%;border-collapse:collapse;font-size:0.79rem">' +
      '<tbody>' + tbody + '</tbody></table></div>';
  }).catch(function(e) {
    pane.innerHTML = tierBtns + '<div style="padding:1rem;color:var(--danger)">' + x(e.message) + '</div>';
  });
}

// ── Health tab ────────────────────────────────────────────────────────────────
// metricSparklineCard renders one metric's stat row + SVG trend line from
// already-fetched telemetry rows (as returned by GET .../telemetry, newest
// first). Generalized from the original heartbeat-only chart below so every
// tile on the Agent Health grid shares one rendering path instead of each
// metric growing its own copy.
//
// opts: { title, unit ('ms'/'' etc), data (raw API rows or null/[]),
//         decimals (rounding, default 0), thresholds ({warn,danger}, values
//         above tint amber/red -- omit for metrics with no natural danger
//         level, e.g. a plain count), footnote (optional caption) }
function metricSparklineCard(opts) {
  var title = opts.title, unit = opts.unit || '', decimals = opts.decimals || 0;
  var open = '<div style="background:var(--elevated);border:1px solid var(--border);border-radius:6px;padding:0.85rem">' +
    '<div style="font-size:0.72rem;color:var(--muted);text-transform:uppercase;margin-bottom:0.5rem">' + x(title) + '</div>';
  var data = opts.data;
  if (!data || data.length < 2) {
    return open + '<div style="color:var(--muted);font-size:0.78rem;padding:0.5rem 0 0.25rem">Not enough data yet</div></div>';
  }
  var points = data.slice().reverse(); // oldest first
  var values = points.map(function(p) { return p.value; });
  var maxVal = Math.max.apply(null, values) || 1;
  var minVal = Math.min.apply(null, values);
  var avg = values.reduce(function(a,b){return a+b;},0)/values.length;
  var mul = Math.pow(10, decimals);
  var fmt = function(v) { return Math.round(v*mul)/mul; };
  var colorFor = function(v) {
    if (!opts.thresholds) return '#2fd8c3';
    if (v > opts.thresholds.danger) return '#da3633';
    if (v > opts.thresholds.warn) return '#d29922';
    return '#2fd8c3';
  };
  var svgW = 280, svgH = 90, pad = 10;
  var scaleX = (svgW - pad*2) / (points.length - 1);
  var scaleY = (svgH - pad*2) / (maxVal - minVal || 1);
  var pathD = points.map(function(p, i) {
    var px = pad + i * scaleX, py = svgH - pad - (p.value - minVal) * scaleY;
    return (i===0?'M':'L') + px.toFixed(1) + ',' + py.toFixed(1);
  }).join(' ');
  var dots = points.map(function(p, i) {
    var px = pad + i * scaleX, py = svgH - pad - (p.value - minVal) * scaleY;
    return '<circle cx="' + px.toFixed(1) + '" cy="' + py.toFixed(1) + '" r="2.5" fill="' + colorFor(p.value) + '" opacity="0.85"><title>' + fmt(p.value) + unit + ' · ' + fmtTs(p.createdAt) + '</title></circle>';
  }).join('');
  var latest = values[values.length - 1];
  return open +
    '<div style="display:flex;gap:0.9rem;margin-bottom:0.5rem;font-size:0.74rem">' +
    '<div><span class="u-muted">latest</span> <strong style="color:' + colorFor(latest) + '">' + fmt(latest) + unit + '</strong></div>' +
    '<div><span class="u-muted">avg</span> <strong>' + fmt(avg) + unit + '</strong></div>' +
    '<div><span class="u-muted">max</span> <strong>' + fmt(maxVal) + unit + '</strong></div>' +
    '</div>' +
    '<svg viewBox="0 0 ' + svgW + ' ' + svgH + '" style="width:100%;height:90px;display:block">' +
    '<path d="' + pathD + '" fill="none" stroke="var(--accent)" stroke-width="1.5" opacity="0.8"/>' +
    dots +
    '</svg>' +
    (opts.footnote ? '<div style="margin-top:0.4rem;color:var(--muted);font-size:0.66rem">' + x(opts.footnote) + '</div>' : '') +
    '</div>';
}

// _AGT_HEALTH_CHARTS is the curated diagnostic set: not every emitted metric
// (see _AGT_TELEMETRY_METRICS for the full list, browsable via the Telemetry
// tab's dropdown) earns a permanent chart -- these are the ones an operator
// actually needs trend visibility on at a glance.
var _AGT_HEALTH_CHARTS = [
  { metric: 'heartbeat_latency_ms',    title: 'Heartbeat Latency',     unit: 'ms', thresholds: {warn:150, danger:500}, footnote: 'Red >500ms, amber >150ms' },
  { metric: 'ws_reconnect_attempts',   title: 'WS Reconnect Attempts', unit: '' },
  { metric: 'sched_queued_jobs',       title: 'Queue Depth',           unit: '' },
  { metric: 'sched_lock_wait_avg_ms',  title: 'Lock Wait (avg)',       unit: 'ms', decimals: 1 },
  { metric: 'sched_execution_avg_ms',  title: 'Execution Time (avg)',  unit: 'ms', decimals: 1 },
  { metric: 'sched_active_jobs',       title: 'Active Jobs',           unit: '' }
];

function loadAgtHealth(agentId) {
  var pane = document.getElementById('agt-tab-health');
  pane.innerHTML = '<div style="color:var(--muted);padding:1rem">Loading…</div>';

  Promise.all(_AGT_HEALTH_CHARTS.map(function(c) {
    // Each metric fetched independently, with its own fallback: one metric
    // having no data yet (e.g. a freshly-enrolled agent with no scenario
    // runs) must not blank the whole grid.
    return apicall('/api/agents/' + encodeURIComponent(agentId) + '/telemetry?metric=' + encodeURIComponent(c.metric) + '&limit=100')
      .catch(function() { return []; });
  })).then(function(results) {
    var cards = _AGT_HEALTH_CHARTS.map(function(c, i) {
      return metricSparklineCard({ title: c.title, unit: c.unit, data: results[i], decimals: c.decimals, thresholds: c.thresholds, footnote: c.footnote });
    }).join('');
    pane.innerHTML = '<div style="padding:1rem 1.25rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:0.85rem">' + cards + '</div>';
  }).catch(function(e) {
    pane.innerHTML = '<div style="padding:1rem;color:var(--danger)">' + x(e.message) + '</div>';
  });
}

// ── Risk tab ──────────────────────────────────────────────────────────────────
function loadAgtRisk(agentId) {
  var panel = document.getElementById('agt-tab-risk');
  if (panel) panel.innerHTML = '<div class="empty" style="padding:2rem">Loading…</div>';
  apicall('/api/agents/' + encodeURIComponent(agentId) + '/risk').then(function(d) {
    renderAgtRisk(d);
  }).catch(function(e) { if (panel) panel.innerHTML = '<div class="empty">' + x(e.message) + '</div>'; });
}
function _riskCategoryCard(c) {
  if (!c.collected) {
    return '<div class="dash-panel" style="margin-bottom:0.75rem;opacity:0.6"><div class="dash-panel-body" style="padding:0.85rem">' +
      '<div style="font-weight:700;color:var(--text)">' + x(c.name) + '</div>' +
      '<div class="tiny muted">Not yet collected</div></div></div>';
  }
  var findingsHtml = (c.findings || []).map(function(f) {
    return '<li><strong>' + x(f.title) + '</strong> (' + x(f.severity) + ') — ' + x(f.risk) +
      (f.expected || f.observed ? '<div class="tiny muted">Expected: ' + x(f.expected || '—') + ' · Observed: ' + x(f.observed || '—') + '</div>' : '') +
      (f.affectedStandard ? '<div class="tiny muted">Affected standard: ' + x(f.affectedStandard) + '</div>' : '') +
      (f.reference ? '<div class="tiny muted">Reference: ' + x(f.reference) + '</div>' : '') +
      (f.lastObserved ? '<div class="tiny muted">Last observed: ' + new Date(f.lastObserved).toLocaleString() + '</div>' : '') +
      '<div class="tiny" style="color:var(--accent)">Remediation: ' + x(f.remediation) + '</div></li>';
  }).join('');
  return '<div class="dash-panel" style="margin-bottom:0.75rem"><div class="dash-panel-body" style="padding:0.85rem">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.4rem">' +
    '<div style="font-weight:700;color:var(--text)">' + x(c.name) + '</div>' +
    '<div style="color:' + _riskScoreColor(c.score) + ';font-weight:700">' + c.score + '</div></div>' +
    (findingsHtml ? '<ul style="margin:0;padding-left:1.1rem;color:var(--muted);display:flex;flex-direction:column;gap:0.3rem">' + findingsHtml + '</ul>' : '<div class="tiny muted">No open findings.</div>') +
    '</div></div>';
}
function renderAgtRisk(health) {
  var panel = document.getElementById('agt-tab-risk');
  if (!panel) return;
  // health.measurable is false when not one category was collected. The score
  // is a mean over an empty set then, so showing any number is a fabrication:
  // a 0 reads as "catastrophically insecure" and the pre-fix 100 read as
  // "flawless", both invented from the same absence of data.
  var healthScoreCard = health.measurable
    ? '<div class="kpi-card"><div class="kpi-label">Health Score</div><div class="kpi-value" style="color:' + _riskScoreColor(health.healthScore) + '">' + health.healthScore + '</div><div class="tiny muted">' + _riskTrendBadge(health.trend.direction) + '</div></div>'
    : '<div class="kpi-card"><div class="kpi-label">Health Score</div><div class="kpi-value u-muted">—</div><div class="tiny muted">No data collected yet</div></div>';
  var h = '<div class="kpi-row u-mb-1">' +
    healthScoreCard +
    '<div class="kpi-card"><div class="kpi-label">Criticality</div><div class="kpi-value">' + health.criticalityRisk + '</div><div class="tiny muted">sort/priority signal, not part of Health Score</div></div>' +
    '</div>' +
    (health.measurable ? '' :
      '<div style="margin-bottom:1rem;padding:0.6rem 0.75rem;border:1px solid var(--border);border-left:3px solid var(--warning);border-radius:4px;background:var(--elevated)">' +
        '<div style="font-size:0.8rem;font-weight:600;color:var(--warning)">Nothing collected for this endpoint yet</div>' +
        '<div class="tiny muted" style="margin-top:0.25rem;line-height:1.6">No health score is shown because no category has any data. ' +
        'Run a posture scan, an attack-path collection, or a BAS scenario against this agent to populate it. ' +
        'An absent score is not a safe score.</div>' +
      '</div>');

  if ((health.trend.newFindings || []).length || (health.trend.resolvedFindings || []).length) {
    h += '<div class="tiny muted u-mb-1">' +
      (health.trend.newFindings.length ? '<span class="u-danger">' + health.trend.newFindings.length + ' new</span>' : '') +
      (health.trend.newFindings.length && health.trend.resolvedFindings.length ? ', ' : '') +
      (health.trend.resolvedFindings.length ? '<span class="u-success">' + health.trend.resolvedFindings.length + ' resolved</span>' : '') +
      ' since 7 days ago</div>';
  }

  if ((health.actionPlan || []).length) {
    h += '<div class="dash-panel u-mb-1"><div class="dash-panel-body" style="padding:0.85rem">' +
      '<div style="font-weight:700;color:var(--text);margin-bottom:0.5rem">Recommended Action Plan</div>' +
      '<ol style="margin:0;padding-left:1.1rem;display:flex;flex-direction:column;gap:0.4rem">' +
      health.actionPlan.map(function(a) {
        return '<li><strong>' + x(a.categoryName) + '</strong> (−' + a.deficit + ' pts) — ' + x(a.finding.title) + '<div class="tiny" style="color:var(--accent)">' + x(a.finding.remediation) + '</div></li>';
      }).join('') + '</ol></div></div>';
  }

  if ((health.attackPathChain || []).length) {
    h += '<div class="dash-panel u-mb-1"><div class="dash-panel-body" style="padding:0.85rem">' +
      '<div style="font-weight:700;color:var(--text);margin-bottom:0.5rem">Attack Path Chain</div>' +
      '<div style="display:flex;align-items:center;flex-wrap:wrap;gap:0.25rem">' + apNodePill(health.attackPathChain[0].from);
    for (var i = 0; i < health.attackPathChain.length; i++) {
      h += apArrow(health.attackPathChain[i].kind) + apNodePill(health.attackPathChain[i].to, i === health.attackPathChain.length - 1);
    }
    h += '</div></div></div>';
  }

  h += (health.categories || []).map(_riskCategoryCard).join('');
  panel.innerHTML = h;
}

// ── Attack Path tab ───────────────────────────────────────────────────────────
export function loadAgtAttackPath(agentId) {
  var pane = document.getElementById('agt-tab-attackpath');
  pane.innerHTML = '<div style="color:var(--muted);padding:1rem">Loading…</div>';
  apicall('/api/attackpath/jobs?agentId=' + encodeURIComponent(agentId) + '&limit=10').then(function(jobs) {
    if (!jobs || !jobs.length) {
      pane.innerHTML = '<div style="padding:1rem;color:var(--muted)">No attack-path jobs found for this agent.</div>';
      return;
    }
    var statusColor = {
      completed: 'var(--success)', running: 'var(--accent)', dispatched: 'var(--accent)',
      queued: 'var(--muted)', failed: 'var(--danger)', timed_out: 'var(--danger)',
      delivery_failed: 'var(--danger)', cancelled: 'var(--muted)'
    };
    var stageLabels = {
      initializing: 'Initializing', probing: 'Probing targets',
      enumerating_admins: 'Enumerating admins', enumerating_sessions: 'Enumerating sessions',
      running_sharphound: 'Running SharpHound', building_graph: 'Building graph', uploading: 'Uploading'
    };
    var rows = jobs.map(function(j) {
      var sc = statusColor[j.status] || 'var(--muted)';
      var prog = j.progress;
      var detail = prog && prog.stage ? (stageLabels[prog.stage] || prog.stage) : '';
      if (prog && prog.targetsTotal > 0) detail += ' — ' + prog.targetsCompleted + '/' + prog.targetsTotal;
      if (j.status === 'completed' && j.metrics) detail = j.metrics.nodeCount + ' nodes, ' + j.metrics.edgeCount + ' edges';
      if (j.error) detail = j.error;
      var pct = prog && prog.progressPercent > 0 ? prog.progressPercent : 0;
      var bar = (j.status === 'running' && pct > 0)
        ? '<div style="margin-top:0.25rem;width:100%;max-width:200px;background:var(--border);border-radius:3px;height:4px;overflow:hidden">' +
          '<div style="width:' + pct + '%;background:var(--accent);height:100%;border-radius:3px"></div></div>' : '';
      return '<tr style="border-bottom:1px solid rgba(34,50,74,.4)">' +
        '<td style="padding:0.35rem 0.5rem;color:var(--muted);font-size:0.72rem;white-space:nowrap">' + fmtTs(j.createdAt) + '</td>' +
        '<td style="padding:0.35rem 0.5rem"><span style="color:' + sc + ';font-size:0.75rem;font-weight:600">' + x(j.status) + '</span></td>' +
        '<td style="padding:0.35rem 0.5rem;font-size:0.75rem;color:var(--muted)">' + (j.targetCount || '—') + ' targets</td>' +
        '<td style="padding:0.35rem 0.5rem;font-size:0.75rem;color:var(--muted)">' + x(detail) + bar + '</td>' +
        '</tr>';
    }).join('');
    pane.innerHTML = '<div style="padding:0.75rem 1.25rem 0">' +
      '<table style="width:100%;border-collapse:collapse;font-size:0.79rem">' +
      '<thead><tr style="border-bottom:1px solid var(--border)">' +
      '<th style="padding:0.3rem 0.5rem;font-weight:600;font-size:0.7rem;color:var(--muted);text-align:left">Time</th>' +
      '<th style="padding:0.3rem 0.5rem;font-weight:600;font-size:0.7rem;color:var(--muted);text-align:left">Status</th>' +
      '<th style="padding:0.3rem 0.5rem;font-weight:600;font-size:0.7rem;color:var(--muted);text-align:left">Scope</th>' +
      '<th style="padding:0.3rem 0.5rem;font-weight:600;font-size:0.7rem;color:var(--muted);text-align:left">Detail</th>' +
      '</tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>';
  }).catch(function(e) {
    pane.innerHTML = '<div style="padding:1rem;color:var(--danger)">' + x(e.message) + '</div>';
  });
}

function fmtTs(ts) {
  if (!ts) return '—';
  var d = new Date(ts);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

export function safeScan(agentId) {
  openModal('safe-simulation', agentId, true);
}

export function openFullReport(agentId) {
  showDownloadOptions('Agent Posture HTML Report', function(filter) {
    var query = filter ? '&filter=' + encodeURIComponent(filter) : '';
    window.open('/api/report/full/html?agentId=' + encodeURIComponent(agentId) + query, '_blank');
  });
}
// downloadFullReportPDF/CSV/JSON mirror downloadRunReport's save-as-file
// pattern (an <a download> click, not window.open) for the agent-level Full
// Report's other three formats -- previously only the HTML variant
// (openFullReport above) was reachable from the UI at all, even though the
// backend has had PDF/CSV endpoints all along and JSON is new.
export function downloadFullReportPDF(agentId) {
  showDownloadOptions('Agent Posture PDF Report', function(filter) {
    var query = filter ? '?filter=' + encodeURIComponent(filter) : '';
    triggerDownload(
      '/api/report/full/pdf?agentId=' + encodeURIComponent(agentId) + (query ? '&' + query.slice(1) : ''),
      buildReportFilename('BAS_Report', agentId, 'pdf')
    );
  });
}
export function downloadFullReportCSV(agentId) {
  showDownloadOptions('Agent Posture Forensic CSV', function(filter) {
    var query = filter ? '?filter=' + encodeURIComponent(filter) : '';
    triggerDownload(
      '/api/report/full/csv?agentId=' + encodeURIComponent(agentId) + (query ? '&' + query.slice(1) : ''),
      buildReportFilename('BAS_Forensic', agentId, 'csv')
    );
  });
}
export function downloadFullReportJSON(agentId) {
  showDownloadOptions('Agent Posture JSON Report', function(filter) {
    var query = filter ? '?filter=' + encodeURIComponent(filter) : '';
    triggerDownload(
      '/api/report/full/json?agentId=' + encodeURIComponent(agentId) + (query ? '&' + query.slice(1) : ''),
      buildReportFilename('BAS_Report', agentId, 'json')
    );
  });
}

export function downloadAuditPack(agentId) {
  showToast('Preparing audit pack…', 'ok');
  fetch('/api/report/audit-pack?agentId=' + encodeURIComponent(agentId), {
    credentials: 'same-origin'
  }).then(function(resp) {
    if (!resp.ok) {
      return resp.json().then(function(j) {
        showToast(j.error || 'Audit pack failed', 'err');
      }).catch(function() {
        showToast('Audit pack failed (' + resp.status + ')', 'err');
      });
    }
    return resp.blob().then(function(blob) {
      var url = URL.createObjectURL(blob);
      triggerDownload(url, buildReportFilename('Audit_Pack', agentId, 'zip'));
      setTimeout(function() { URL.revokeObjectURL(url); }, 10000);
    });
  }).catch(function(e) { showToast('Audit pack failed: ' + e.message, 'err'); });
}

/* ═══════════════════════════════════════════════════════════════════════════
   COMPLIANCE MODULE
   ═══════════════════════════════════════════════════════════════════════════ */

var _cmpReport = null;
var _cmpFrameworks = [];
var _cmpFilter = '';

export function initComplianceTab() {
  var fwSel = document.getElementById('cmp-fw-sel');
  if (_cmpFrameworks.length === 0) {
    apicall('/api/compliance/frameworks').then(function(fws) {
      _cmpFrameworks = fws || [];
      fwSel.innerHTML = _cmpFrameworks.map(function(f) {
        return '<option value="' + f.id + '">' + f.name + ' ' + f.version + '</option>';
      }).join('');
    }).catch(function() {
      fwSel.innerHTML = '<option value="">Error loading frameworks</option>';
    });
  }
  // Populate agent selector from already-loaded agents array
  var agSel = document.getElementById('cmp-agent-sel');
  if (agSel.options.length <= 1) {
    agSel.innerHTML = '<option value="">— Select Agent —</option>' +
      (state.agents || []).map(function(a) {
        return '<option value="' + x(a.agentId) + '">' + x(a.hostname || a.agentId) + '</option>';
      }).join('');
  }
}

export function loadComplianceReport() {
  var agentId = document.getElementById('cmp-agent-sel').value;
  var framework = document.getElementById('cmp-fw-sel').value;
  if (!agentId) { showToast('Select an agent first', 'warn'); return; }
  if (!framework) { showToast('Select a framework first', 'warn'); return; }

  document.getElementById('cmp-placeholder').textContent = 'Generating report…';
  document.getElementById('cmp-placeholder').style.display = '';
  document.getElementById('cmp-report').style.display = 'none';
  ['cmp-export-json','cmp-export-csv'].forEach(function(id) {
    document.getElementById(id).style.display = 'none';
  });

  apicall('/api/compliance/report?agentId=' + encodeURIComponent(agentId) + '&framework=' + encodeURIComponent(framework))
    .then(function(report) {
      _cmpReport = report;
      _cmpFilter = '';
      renderComplianceReport(report);
      document.getElementById('cmp-placeholder').style.display = 'none';
      document.getElementById('cmp-report').style.display = '';
      ['cmp-export-json','cmp-export-csv'].forEach(function(id) {
        document.getElementById(id).style.display = '';
      });
    })
    .catch(function(e) {
      document.getElementById('cmp-placeholder').textContent = 'Error: ' + (e.message || 'Could not generate report. Run a scenario first.');
    });
}

function renderComplianceReport(r) {
  var s = r.summary || {};
  var pct = +(s.compliancePct || 0);
  var cvr = +(s.coveragePct || 0);
  var pctColor = pct >= 70 ? '#22d3a6' : pct >= 40 ? '#f59e0b' : '#ef4444';
  var radius = 54, circ = 2 * Math.PI * radius;
  var dash = circ * pct / 100, gap = circ - dash;
  var fwId = (r.framework.id || '').toLowerCase();
  var fwColorMap = {'sebi-cscrf':'#4f8ef7','sebi':'#4f8ef7','rbi':'#22d3a6','irdai':'#a78bfa','cert-in':'#f59e0b','cert_in':'#f59e0b','iso27001':'#ef4444','iso-27001':'#ef4444','nist-csf':'#2fd8c3','nist':'#2fd8c3'};
  var fwColor = fwColorMap[fwId] || '#4f8ef7';
  var totalControls = s.totalControls || ((s.passing||0)+(s.failing||0)+(s.partial||0)+(s.untested||0)+(s.manual||0));

  // Header card with ring gauge
  document.getElementById('cmp-header-area').innerHTML =
    '<div class="cmp-header-card" style="border-top:3px solid ' + fwColor + '">' +
      '<div class="cmp-header-left">' +
        '<div class="cmp-fw-badge" style="color:' + fwColor + ';background:' + fwColor + '22;border-color:' + fwColor + '44">' + x(r.framework.id || '') + '</div>' +
        '<div class="cmp-fw-name">' + x(r.framework.name || '') + '</div>' +
        '<div class="cmp-fw-version">' + x(r.framework.version || '') + '</div>' +
        '<div class="cmp-header-narrative" style="margin-top:0.5rem;font-size:0.85rem;line-height:1.5;color:var(--text-dim);max-width:520px">' +
          x(r.narrative || '') +
        '</div>' +
      '</div>' +
      '<div class="cmp-header-gauge">' +
        '<svg width="128" height="128" viewBox="0 0 130 130">' +
          '<circle cx="65" cy="65" r="' + radius + '" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10"/>' +
          '<circle cx="65" cy="65" r="' + radius + '" fill="none" stroke="' + pctColor + '" stroke-width="10"' +
            ' stroke-dasharray="' + dash.toFixed(1) + ' ' + gap.toFixed(1) + '"' +
            ' stroke-dashoffset="' + (circ * 0.25).toFixed(1) + '"' +
            ' stroke-linecap="round" style="transition:stroke-dasharray 0.8s ease"/>' +
          '<text x="65" y="59" text-anchor="middle" fill="' + pctColor + '" font-family="Space Grotesk,sans-serif" font-size="22" font-weight="700">' + pct.toFixed(0) + '%</text>' +
          '<text x="65" y="75" text-anchor="middle" fill="rgba(154,169,188,0.9)" font-family="Inter,sans-serif" font-size="9" letter-spacing="1.2">COMPLIANT</text>' +
          '<text x="65" y="91" text-anchor="middle" fill="rgba(154,169,188,0.6)" font-family="Inter,sans-serif" font-size="8">' + cvr.toFixed(0) + '% coverage</text>' +
        '</svg>' +
      '</div>' +
      '<div class="cmp-header-right">' +
        '<div class="cmp-hdr-meta-row"><span class="cmp-hdr-meta-lbl">Agent</span><span class="cmp-hdr-meta-val">' + x(r.agentId || '') + '</span></div>' +
        '<div class="cmp-hdr-meta-row"><span class="cmp-hdr-meta-lbl">Generated</span><span class="cmp-hdr-meta-val">' + new Date(r.generatedAt).toLocaleDateString('en-IN',{day:'numeric',month:'short',year:'numeric'}) + '</span></div>' +
        '<div class="cmp-hdr-meta-row"><span class="cmp-hdr-meta-lbl">Total Controls</span><span class="cmp-hdr-meta-val">' + totalControls + '</span></div>' +
        '<div class="cmp-hdr-meta-row"><span class="cmp-hdr-meta-lbl">Scope</span><span class="cmp-hdr-meta-val" style="font-size:0.7rem;color:var(--muted)">' + x((r.scenarioName || r.runId || 'Aggregated').substring(0,40)) + '</span></div>' +
      '</div>' +
    '</div>';

  // KPI row
  var kpis = [
    {label:'Compliant',     val:s.passing||0,                    color:'#22d3a6', dim:'rgba(34,211,166,0.1)',  border:'rgba(34,211,166,0.3)',  icon:'✓', sub:(s.passing||0)+' controls passing'},
    {label:'Non-Compliant', val:s.failing||0,                    color:'#ef4444', dim:'rgba(239,68,68,0.1)',   border:'rgba(239,68,68,0.3)',   icon:'✗', sub:(s.failing||0)+' controls failing'},
    {label:'Partial',       val:s.partial||0,                    color:'#f59e0b', dim:'rgba(245,158,11,0.1)',  border:'rgba(245,158,11,0.3)',  icon:'◑', sub:'Mixed pass/fail evidence'},
    {label:'Not Tested',    val:(s.untested||0)+(s.manual||0),  color:'var(--muted)', dim:'rgba(122,148,176,0.08)', border:'var(--border)', icon:'○', sub:(s.manual||0)+' manual attestation'},
  ];
  document.getElementById('cmp-kpi-area').innerHTML =
    '<div class="cmp-kpi-row">' +
    kpis.map(function(k) {
      return '<div class="cmp-kpi-card" style="border-left:3px solid ' + k.border + '">' +
        '<div class="cmp-kpi-icon" style="color:' + k.color + ';background:' + k.dim + '">' + k.icon + '</div>' +
        '<div class="cmp-kpi-value" style="color:' + k.color + '">' + k.val + '</div>' +
        '<div class="cmp-kpi-label">' + k.label + '</div>' +
        '<div class="cmp-kpi-sub">' + k.sub + '</div>' +
      '</div>';
    }).join('') + '</div>';

  // Domain grid
  document.getElementById('cmp-domain-area').innerHTML =
    '<div class="cmp-section-hdr">Domain Breakdown</div>' +
    '<div class="cmp-domain-grid">' +
    (r.domains || []).map(function(d) {
      var tested = (d.passing||0) + (d.failing||0) + (d.partial||0);
      var p = tested > 0 ? +(d.compliancePct||0) : null;
      var barColor = p === null ? 'rgba(122,148,176,0.3)' : p >= 70 ? '#22d3a6' : p >= 40 ? '#f59e0b' : '#ef4444';
      return '<div class="cmp-domain-card" style="border-left:3px solid ' + barColor + '">' +
        '<div class="cmp-dc-header">' +
          '<span class="cmp-dc-name">' + x(d.name) + '</span>' +
          '<span class="cmp-dc-pct" style="color:' + barColor + '">' + (p !== null ? p.toFixed(0) + '%' : '—') + '</span>' +
        '</div>' +
        '<div class="cmp-dc-bar-wrap"><div class="cmp-dc-bar" style="width:' + (p||0) + '%;background:' + barColor + '"></div></div>' +
        '<div class="cmp-dc-stats">' +
          '<span class="cmp-dc-stat" style="color:#22d3a6">' + (d.passing||0) + ' Pass</span>' +
          '<span class="cmp-dc-stat" style="color:#ef4444">' + (d.failing||0) + ' Fail</span>' +
          '<span class="cmp-dc-stat u-muted">' + (d.untested||0) + ' Untested</span>' +
        '</div>' +
      '</div>';
    }).join('') + '</div>';

  renderControlsTable(r.controls, _cmpFilter);
}

function renderControlsTable(controls, filter) {
  // Sync filter tab active state
  document.querySelectorAll('.cmp-ftab').forEach(function(b) {
    b.classList.toggle('active', (b.dataset.filter || '') === (filter || ''));
  });

  var statusLabel = {pass:'✓ Compliant', fail:'✗ Non-Compliant', partial:'◑ Partial', untested:'○ Untested', manual:'✎ Manual'};
  var rows = (controls || []).filter(function(c) { return !filter || c.status === filter; });
  document.getElementById('cmp-controls-body').innerHTML = rows.map(function(c, i) {
    var badge = '<span class="cmp-badge ' + c.status + '">' + (statusLabel[c.status] || c.status) + '</span>';
    if (c.status === 'manual') {
      return '<tr><td>' + badge + '</td>' +
        '<td><span class="cmp-ctrl-id">' + x(c.id) + '</span></td>' +
        '<td>' + x(c.name) + ' <span class="cmp-manual-tag">manual attestation</span></td>' +
        '<td><span class="cmp-domain-chip">' + x(c.domain||'') + '</span></td>' +
        '<td colspan="3" style="font-size:0.72rem;color:var(--muted)">Verify via policy / audit evidence</td></tr>';
    }
    var evId = 'cmp-ev-' + i;
    var hasEv = c.evidence && c.evidence.length > 0;
    var evHtml = hasEv ? '<div class="cmp-evidence" id="' + evId + '">' +
      (c.evidence || []).map(function(ev) {
        var rc = (ev.result === 'pass' || ev.result === 'blocked') ? 'pass' : 'fail';
        return '<div class="cmp-ev-row">' +
          '<span class="cmp-ev-tech">' + x(ev.techniqueId || '') + '</span>' +
          '<span class="cmp-ev-badge ' + rc + '">' + x((ev.result || '').toUpperCase()) + '</span>' +
          '<span class="cmp-ev-detail">' + x((ev.details || '').substring(0, 120)) + '</span>' +
        '</div>';
      }).join('') + '</div>' : '';
    var expandBtn = hasEv ? '<span class="cmp-expand-btn" onclick="toggleEvidence(\'' + evId + '\',this)">&#9658; ' + c.evidence.length + ' tests</span>' : '';
    return '<tr><td>' + badge + '</td>' +
      '<td><span class="cmp-ctrl-id">' + x(c.id) + '</span></td>' +
      '<td>' + x(c.name) + expandBtn + evHtml + '</td>' +
      '<td><span class="cmp-domain-chip">' + x(c.domain||'') + '</span></td>' +
      '<td style="text-align:center;color:var(--text-dim)">' + (c.tested||0) + '</td>' +
      '<td style="text-align:center;color:#22d3a6;font-weight:600">' + (c.passed||0) + '</td>' +
      '<td style="text-align:center;font-weight:600;color:' + ((c.failed||0) > 0 ? '#ef4444' : 'var(--muted)') + '">' + (c.failed||0) + '</td>' +
    '</tr>';
  }).join('');
  if (!rows.length) {
    document.getElementById('cmp-controls-body').innerHTML =
      '<tr><td colspan="7" class="empty">No controls match this filter.</td></tr>';
  }
}

export function toggleEvidence(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('open');
  var count = el.querySelectorAll('.cmp-ev-row').length;
  if (btn) btn.textContent = el.classList.contains('open') ? '▼ ' + count + ' tests' : '► ' + count + ' tests';
}

export function filterControls(status) {
  _cmpFilter = status;
  if (_cmpReport) renderControlsTable(_cmpReport.controls, status);
}

export function exportCompliance(format) {
  var agentId = document.getElementById('cmp-agent-sel').value;
  var framework = document.getElementById('cmp-fw-sel').value;
  if (!agentId || !framework) return;
  // Log to the Reports history (report_log) and download via the reconstructed
  // path the server returns — keeps compliance exports in the unified Reports
  // history alongside posture/audit packs.
  showDownloadOptions('Compliance Evidence Options', function(filter) {
    apicall('/api/reports', { method: 'POST', body: JSON.stringify({
      reportType: 'compliance', format: format, agentId: agentId, framework: framework, filter: filter
    }) }).then(function(res) {
      if (res && res.error) { showToast('Export failed: ' + res.error, 'err'); return; }
      window.open(res.downloadPath, '_blank');
      showToast('Compliance ' + format.toUpperCase() + ' exported', 'ok');
    }).catch(function(e) { showToast('Export failed: ' + e.message, 'err'); });
  });
}