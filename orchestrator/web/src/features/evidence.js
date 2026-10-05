import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { ago, daysAgo, fmtDate, showToast } from '../core/util.js';
import { _apOnCollected, _apOnJobUpdate, _apOnProgress, _onRevalidationStarted, _onSIEMCorrelationComplete, renderScenarios, requestAgentsLiveRefresh, showSettingsSection, showThreatPriorityDetail } from './attack-path.js';
import { loadEndpointPostureWidget, loadKEVWidget, loadReadinessTrends } from './campaigns.js';
import { loadComplianceScores, refreshDashboardCampaigns } from './compliance.js';
import { openTechnique } from './coverage.js';
import { findingSevBadge, loadDashboardITSM, openFinding } from './findings.js';
import { loadRansomwareReadiness } from './ransomware.js';
import { additionalAgentIds, closeModal, loadRuns, openBuilder, openModal, resolvedAllTargetIds, resolvedGroupTargetIds, scenarioFramework, viewRunResults } from './reports.js';
import { ROLE, _riskScoreColor, showTab, showTamperBanner } from './shell.js';
import { killChainNodes } from './variant-report.js';


// ── Evidence Panel ────────────────────────────────────────────────────────────

var WIN_EVENT_NAMES = {
  '1':    'Sysmon — Process Create',
  '3':    'Sysmon — Network Connection',
  '7':    'Sysmon — Image Loaded',
  '10':   'Sysmon — Process Access',
  '11':   'Sysmon — File Create',
  '12':   'Sysmon — Registry Add/Delete',
  '13':   'Sysmon — Registry Set',
  '15':   'Sysmon — Alternate Data Stream',
  '17':   'Sysmon — Named Pipe Created',
  '22':   'Sysmon — DNS Query',
  '4103': 'PowerShell — Module Logging',
  '4104': 'PowerShell — Script Block Logging',
  '4624': 'Security — Logon Success',
  '4625': 'Security — Logon Failure',
  '4648': 'Security — Explicit Logon',
  '4656': 'Security — Object Handle Requested',
  '4657': 'Security — Registry Value Modified',
  '4660': 'Security — Object Deleted',
  '4663': 'Security — Object Access Attempt',
  '4688': 'Security — Process Creation',
  '4689': 'Security — Process Exit',
  '4698': 'Security — Scheduled Task Created',
  '4702': 'Security — Scheduled Task Updated',
  '4719': 'Security — Audit Policy Changed',
  '4720': 'Security — User Account Created',
  '4722': 'Security — Account Enabled',
  '4724': 'Security — Password Reset Attempt',
  '4725': 'Security — Account Disabled',
  '4726': 'Security — User Account Deleted',
  '4768': 'Security — Kerberos TGT Request',
  '4769': 'Security — Kerberos Service Ticket',
  '4776': 'Security — NTLM Credential Validation',
  '7045': 'System — New Service Installed',
  '7036': 'System — Service State Change',
  '1102': 'Security — Audit Log Cleared',
  '8004': 'AppLocker — Execution Blocked',
};

export function copyRaw(text) {
  navigator.clipboard.writeText(text).catch(function() { showToast('Copy failed', 'err'); });
}

export function openEvidence(idx) {
  var results = window._evidenceResults || [];
  var c = results[idx];
  if (!c) return;
  var techName = (c.technique && c.technique.name) || c.name || 'Technique';
  var techId   = (c.technique && c.technique.id)   ? c.technique.id + ' — ' : '';
  var stepSuffix = (c.stepName && c.stepName !== techName) ? ' (' + c.stepName + ')' : '';
  document.getElementById('evidence-title').textContent = techId + techName + stepSuffix;
  renderEvidencePanel(c);
  document.getElementById('evidence-overlay').style.display = 'block';
}

export function closeEvidence() {
  document.getElementById('evidence-overlay').style.display = 'none';
}

function renderEvidencePanel(c) {
  var da       = c.detectionAlert || null;
  // A vetoed step was never attempted (B5's agent-side guardrail refused
  // it) -- neither "Verified"/"Successful" (claims it ran) nor "Failed"
  // (implies an attempt that didn't work) is accurate, so it's excluded
  // from execOk and given its own label below (fix-pass's own scoped
  // re-review of I3, which fixed this same misrepresentation pattern
  // elsewhere but missed this panel).
  var execOk   = c.result !== 'error' && c.result !== 'skipped' && c.result !== 'vetoed';
  var execText = c.result === 'vetoed' ? 'Vetoed (Policy)' : (execOk ? 'Verified' : 'Failed');
  var execTextShort = c.result === 'vetoed' ? 'Vetoed (Policy)' : (execOk ? 'Successful' : 'Failed');
  var detOk    = !!(c.detectionVerdict === 'detected' || c.detectionVerdict === 'prevented' || da);
  var prevOk   = c.detectionVerdict === 'prevented' || c.result === 'pass';
  var cleanOk  = c.cleanupVerdict === 'reverted';

  // confidence
  var cScore = 1 + (detOk ? 1 : 0) + (c.events && c.events.length > 0 ? 1 : 0) + (cleanOk ? 1 : 0);
  var conf = cScore >= 4 ? {l:'High',   col:'var(--success)'}
           : cScore >= 2 ? {l:'Medium', col:'var(--warning)'}
                         : {l:'Low',    col:'var(--muted)'};

  function secRow(label, ok, text) {
    return '<div style="display:flex;align-items:center;gap:0.6rem;padding:0.22rem 0">'
      + '<span style="width:5.8rem;font-size:0.72rem;color:var(--muted);flex-shrink:0">' + label + '</span>'
      + '<span style="font-size:0.72rem;color:' + (ok ? 'var(--success)' : 'var(--muted)') + ';font-weight:600">'
      + (ok ? '&#10003; ' : '&#8212; ') + x(text) + '</span>'
      + '</div>';
  }
  function section(title, badge, content) {
    return '<div style="margin-bottom:0.9rem">'
      + '<div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.4rem">'
      + '<div style="font-size:0.61rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)">' + title + '</div>'
      + (badge ? '<span style="font-size:0.58rem;font-weight:700;text-transform:uppercase;background:rgba(35,134,54,0.15);color:var(--success);border-radius:3px;padding:1px 6px;border:1px solid rgba(35,134,54,0.3)">' + x(badge) + '</span>' : '')
      + '</div>'
      + '<div style="background:var(--elevated);border:1px solid var(--border);border-radius:6px;padding:0.7rem 0.85rem;font-size:0.74rem">'
      + content
      + '</div></div>';
  }
  function kv(label, valueHtml) {
    return '<div style="display:flex;gap:0.75rem;padding:0.18rem 0;border-bottom:1px solid rgba(34,50,74,0.4);min-height:1.6rem;align-items:flex-start">'
      + '<span style="min-width:6.5rem;color:var(--muted);font-size:0.69rem;flex-shrink:0;padding-top:0.05rem">' + label + '</span>'
      + '<span class="u-text">' + valueHtml + '</span>'
      + '</div>';
  }

  var html = '';

  // ── 1. Evidence Summary ──
  var detText  = detOk  ? (da && da.provider ? x(da.provider) : 'Detected') : 'No detection correlated';
  var prevText = prevOk ? 'Blocked' : 'Not prevented';
  var cvText   = cleanOk ? 'Environment restored'
               : (c.cleanupVerdict === 'partial' ? 'Partial cleanup'
               : (c.cleanupVerdict === 'leaked'  ? 'Leaked — artifacts remain'
               : 'No cleanup defined'));

  html += '<div style="background:var(--elevated);border:1px solid var(--border);border-radius:6px;padding:0.8rem 1rem;margin-bottom:1rem">';
  html += '<div style="font-size:0.6rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:0.45rem;font-weight:700">Evidence Summary</div>';
  html += secRow('Execution', execOk, execText);
  html += secRow('Detection', detOk,  detText);
  html += secRow('Prevention', prevOk, prevText);
  html += secRow('Cleanup', cleanOk, cvText);
  html += '<div style="display:flex;align-items:center;gap:0.6rem;padding:0.22rem 0;margin-top:0.3rem;border-top:1px solid var(--border)">'
       + '<span style="width:5.8rem;font-size:0.72rem;color:var(--muted);flex-shrink:0">Confidence</span>'
       + '<span style="font-size:0.72rem;color:' + conf.col + ';font-weight:700">' + conf.l + '</span>'
       + '</div>';
  html += '</div>';

  // ── 2. Security Response ──
  var srHtml = '';
  srHtml += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;margin-bottom:0.6rem">';
  var card = function(label, ok, sub, bg) {
    return '<div style="text-align:center;padding:0.45rem 0.3rem;background:' + bg + ';border-radius:4px">'
      + '<div style="font-size:0.64rem;color:var(--muted);margin-bottom:0.15rem">' + label + '</div>'
      + '<div style="font-size:0.95rem;margin:0.08rem 0;color:' + (ok ? 'var(--success)' : 'var(--muted)') + '">' + (ok ? '&#10003;' : '&#8212;') + '</div>'
      + '<div style="font-size:0.67rem;color:var(--text)">' + x(sub) + '</div>'
      + '</div>';
  };
  var resultVerdict = c.detectionVerdict || c.result || '—';
  var resultCol = c.result === 'vetoed' ? 'var(--warning)' : prevOk ? 'var(--success)' : (detOk ? 'var(--warning)' : 'var(--danger)');
  srHtml += card('Execution', execOk, execTextShort, 'rgba(47,129,247,0.07)');
  srHtml += card('Detection', detOk,  detOk  ? (da && da.provider ? x(da.provider) : 'Detected') : 'No detection', 'rgba(210,153,34,0.07)');
  srHtml += card('Prevention', prevOk, prevOk ? 'Blocked' : 'Not blocked', 'rgba(35,134,54,0.07)');
  srHtml += '<div style="text-align:center;padding:0.45rem 0.3rem;background:var(--bg);border-radius:4px">'
         + '<div style="font-size:0.64rem;color:var(--muted);margin-bottom:0.15rem">Result</div>'
         + '<div style="font-size:0.67rem;font-weight:700;color:' + resultCol + ';text-transform:uppercase;margin-top:0.6rem">' + x(resultVerdict) + '</div>'
         + '</div>';
  srHtml += '</div>';
  if (da) {
    srHtml += '<div style="background:rgba(210,153,34,0.08);border:1px solid rgba(210,153,34,0.25);border-radius:4px;padding:0.5rem 0.65rem;margin-bottom:0.4rem">';
    srHtml += '<div style="font-size:0.61rem;color:var(--warning);font-weight:700;margin-bottom:0.2rem">' + x(da.provider||'EDR') + ' Alert</div>';
    if (da.threatName) srHtml += '<div style="font-size:0.72rem;color:var(--text);margin-bottom:0.12rem">' + x(da.threatName) + '</div>';
    if (da.mttdMs != null) srHtml += '<div style="font-size:0.67rem;color:var(--muted)">MTTD: ' + (da.mttdMs < 1000 ? da.mttdMs + ' ms' : (da.mttdMs/1000).toFixed(1) + ' s') + '</div>';
    srHtml += '</div>';
  }
  if (c.blockingControl) {
    srHtml += '<div style="background:rgba(35,134,54,0.08);border:1px solid rgba(35,134,54,0.25);border-radius:4px;padding:0.5rem 0.65rem;margin-bottom:0.4rem">';
    srHtml += '<div style="font-size:0.61rem;color:var(--success);font-weight:700;margin-bottom:0.12rem">Blocking Control</div>';
    srHtml += '<div style="font-size:0.72rem;color:var(--text)">' + x((c.blockingControl && c.blockingControl.name) || 'Security Control') + '</div>';
    srHtml += '</div>';
  }
  if (c.events && c.events.length > 0) {
    srHtml += '<div style="margin-top:0.5rem"><div style="font-size:0.61rem;color:var(--muted);margin-bottom:0.22rem;font-weight:600">Windows Events</div>';
    srHtml += c.events.map(function(evId) {
      var evName = WIN_EVENT_NAMES[String(evId)] || 'Security Event';
      var evIdStr = x(String(evId));
      return '<div style="display:flex;align-items:center;gap:0.5rem;padding:0.16rem 0">'
        + '<code style="font-size:0.64rem;color:var(--accent);min-width:2.8rem">' + evIdStr + '</code>'
        + '<span style="font-size:0.69rem;color:var(--text);flex:1">' + x(evName) + '</span>'
        + '<button onclick="copyRaw(\'' + evIdStr + '\')" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:0.63rem;padding:0" title="Copy ID">&#128203;</button>'
        + '</div>';
    }).join('');
    srHtml += '</div>';
  }
  var srBadge = da ? 'EDR Verified ✓' : (c.events && c.events.length > 0 ? 'Event Log Verified ✓' : null);
  html += section('Security Response', srBadge, srHtml);

  // ── 3. Execution ──
  var cmd = c.command || '';
  var cmdMethod = 'Custom';
  if (cmd.indexOf('-EncodedCommand') !== -1 || cmd.indexOf(' -enc ') !== -1) { cmdMethod = 'PowerShell (Encoded)'; }
  else if (cmd.toLowerCase().indexOf('powershell') !== -1 || cmd.toLowerCase().indexOf('pwsh') !== -1) { cmdMethod = 'PowerShell'; }
  else if (cmd.toLowerCase().indexOf('cmd.exe') !== -1 || /^cmd\s/i.test(cmd)) { cmdMethod = 'CMD.exe'; }
  else if (cmd.toLowerCase().indexOf('wmic') !== -1) { cmdMethod = 'WMI (wmic.exe)'; }
  else if (cmd.toLowerCase().indexOf('schtasks') !== -1) { cmdMethod = 'Scheduled Task'; }
  else if (c.framework === 'caldera') { cmdMethod = 'Caldera Ability'; }
  else if (cmd) { cmdMethod = cmd.split(/[\s/\\]/)[0]; }

  var durMs = c.durationMs || 0;
  var durLabel = durMs < 1000 ? durMs + ' ms' : durMs < 60000 ? (durMs/1000).toFixed(1) + ' s' : Math.round(durMs/60000) + ' m ' + Math.round((durMs%60000)/1000) + ' s';
  var durCol = durMs < 1000 ? 'var(--success)' : durMs < 8000 ? 'var(--text)' : durMs < 30000 ? 'var(--warning)' : 'var(--danger)';

  var exHtml = kv('Method', x(cmdMethod));
  if (cmd) {
    var cmdJson = JSON.stringify(cmd);
    exHtml += '<div style="display:flex;gap:0.75rem;padding:0.18rem 0;border-bottom:1px solid rgba(34,50,74,0.4)">'
      + '<span style="min-width:6.5rem;color:var(--muted);font-size:0.69rem;flex-shrink:0;padding-top:0.05rem">Command</span>'
      + '<details style="flex:1;cursor:pointer"><summary style="list-style:none;color:var(--accent);font-size:0.68rem">View Full Command &#9660;</summary>'
      + '<div style="margin-top:0.4rem;display:flex;gap:0.4rem;align-items:flex-start">'
      + '<code style="font-size:0.62rem;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:0.35rem 0.5rem;display:block;word-break:break-all;flex:1;color:var(--text);line-height:1.5">' + x(cmd) + '</code>'
      + '<button onclick="copyRaw(' + cmdJson + ')" style="background:none;border:1px solid var(--border);border-radius:3px;color:var(--muted);cursor:pointer;font-size:0.63rem;padding:0.2rem 0.35rem;flex-shrink:0" title="Copy">&#128203;</button>'
      + '</div></details></div>';
  }
  if (c.pid) exHtml += kv('PID', x(String(c.pid)));
  exHtml += kv('Executed as', x(c.executedAs || c.requestedPriv || 'agent context'));
  exHtml += kv('Exit code', c.exitCode != null ? x(String(c.exitCode)) : '&#8212;');
  if (c.startedAt && (new Date(c.startedAt)).getFullYear() > 2000) {
    exHtml += kv('Started at', x(new Date(c.startedAt).toISOString().replace('T',' ').slice(0,23) + ' UTC'));
  } else if (c.executedAt) {
    exHtml += kv('Completed at', x(new Date(c.executedAt).toISOString().replace('T',' ').slice(0,23) + ' UTC'));
  }
  exHtml += kv('Duration', '<span style="font-weight:600;color:' + durCol + '">' + durLabel + '</span>');
  if (c.timedOut) exHtml += kv('Timed out', '<span style="color:var(--danger);font-weight:700">Yes — exceeded timeout</span>');
  html += section('Execution', 'Agent Verified ✓', exHtml);

  // ── 4. Detection Timeline (always visible) ──
  var t0 = (c.startedAt && (new Date(c.startedAt)).getFullYear() > 2000) ? new Date(c.startedAt)
         : (c.executedAt ? new Date(new Date(c.executedAt).getTime() - (c.durationMs||0)) : null);
  var t1 = c.executedAt ? new Date(c.executedAt) : null;
  var fmt = function(d) { return d ? d.toISOString().replace('T',' ').slice(11,19) + ' UTC' : ''; };

  var tlNodes = [
    { label: 'Started', sub: fmt(t0), col: 'var(--accent)' },
    { label: 'Payload Executed', sub: '', col: 'var(--text)' },
  ];
  if (detOk) {
    var alertTime = (da && da.timestamp) ? new Date(da.timestamp) : null;
    var mttdLabel = (da && da.mttdMs != null) ? ' +' + (da.mttdMs < 1000 ? da.mttdMs+'ms' : (da.mttdMs/1000).toFixed(1)+'s') : '';
    tlNodes.push({ label: prevOk ? 'Blocked' : 'Detected', sub: (alertTime ? fmt(alertTime) : '') + mttdLabel, col: prevOk ? 'var(--success)' : 'var(--warning)' });
  } else {
    tlNodes.push({ label: 'No Detection', sub: 'Controls did not alert', col: 'var(--muted)' });
  }
  if (c.cleanupVerdict) {
    var cleanCol2 = cleanOk ? 'var(--success)' : c.cleanupVerdict === 'leaked' ? 'var(--danger)' : 'var(--warning)';
    tlNodes.push({ label: 'Cleanup', sub: x(c.cleanupVerdict), col: cleanCol2 });
  }
  tlNodes.push({ label: 'Completed', sub: fmt(t1), col: 'var(--text)' });

  var tlHtml = '<div style="position:relative;padding-left:1.4rem">';
  tlNodes.forEach(function(n, i) {
    var last = i === tlNodes.length - 1;
    tlHtml += '<div style="position:relative;padding-bottom:' + (last ? '0' : '0.85rem') + '">'
      + (!last ? '<div style="position:absolute;left:-0.65rem;top:0.55rem;bottom:0;width:1px;background:var(--border)"></div>' : '')
      + '<div style="position:absolute;left:-0.87rem;top:0.12rem;width:0.42rem;height:0.42rem;border-radius:50%;background:' + n.col + '"></div>'
      + '<div style="font-size:0.74rem;font-weight:600;color:' + n.col + '">' + x(n.label) + '</div>'
      + (n.sub ? '<div style="font-size:0.64rem;color:var(--muted);margin-top:0.04rem">' + x(n.sub) + '</div>' : '')
      + '</div>';
  });
  tlHtml += '</div>';
  html += section('Detection Timeline', null, tlHtml);

  // ── 5. Cleanup (only if cleanup verdict exists) ──
  if (c.cleanupVerdict) {
    var cv   = c.cleanupVerdict;
    var cvIcon = cv === 'reverted' ? '&#10003;' : cv === 'partial' ? '&#9888;' : cv === 'leaked' ? '&#10007;' : '&#8212;';
    var cvCol2 = cv === 'reverted' ? 'var(--success)' : cv === 'partial' ? 'var(--warning)' : cv === 'leaked' ? 'var(--danger)' : 'var(--muted)';
    var cvDesc = cv === 'reverted' ? 'All artifacts removed, environment restored'
               : cv === 'partial'  ? 'Cleanup ran but had errors — some artifacts may remain'
               : cv === 'leaked'   ? 'Cleanup timed out or failed — artifacts remain on host'
               : 'No cleanup step defined';
    var clFlow = cv === 'reverted' ? ['Payload Executed', 'Cleanup Started', 'Cleanup Complete']
               : cv === 'partial'  ? ['Payload Executed', 'Cleanup Started', 'Partial Complete']
               :                     ['Payload Executed', 'Cleanup Timed Out'];
    var clHtml = '<div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.5rem">'
      + '<span style="font-size:1rem;color:' + cvCol2 + ';flex-shrink:0">' + cvIcon + '</span>'
      + '<div><div style="font-weight:600;color:' + cvCol2 + ';font-size:0.77rem">' + x(cv.charAt(0).toUpperCase()+cv.slice(1)) + '</div>'
      + '<div style="font-size:0.67rem;color:var(--muted)">' + x(cvDesc) + '</div></div></div>';
    clHtml += '<div style="display:flex;align-items:center;flex-wrap:wrap;gap:0">';
    clFlow.forEach(function(step, i) {
      var last = i === clFlow.length-1;
      var sc = last ? cvCol2 : 'var(--muted)';
      clHtml += '<span style="font-size:0.65rem;color:' + sc + '">' + x(step) + '</span>';
      if (!last) clHtml += '<span style="color:var(--border);margin:0 0.3rem">&rsaquo;</span>';
    });
    clHtml += '</div>';
    html += section('Cleanup', cv === 'reverted' ? 'Agent Verified ✓' : null, clHtml);
  }

  // ── 6. MITRE ATT&CK ──
  if (c.technique && c.technique.id) {
    var tid = c.technique.id.replace('.', '/');
    var miHtml = kv('Technique',
      '<a href="https://attack.mitre.org/techniques/' + x(tid) + '" target="_blank" style="color:var(--accent);text-decoration:none">'
      + x(c.technique.id) + ' &#8212; ' + x(c.technique.name||'') + ' &#8599;</a>');
    if (c.stepName && c.stepName !== c.technique.name) miHtml += kv('Test', x(c.stepName));
    if (c.technique.tactic) miHtml += kv('Tactic', x(c.technique.tactic.replace(/-/g,' ')));
    var fw2 = (c.framework||'custom').toLowerCase();
    var fw2col = fw2 === 'art' ? 'var(--accent)' : fw2 === 'caldera' ? '#bc8cff' : 'var(--muted)';
    miHtml += kv('Framework', '<span style="color:' + fw2col + ';font-weight:700;text-transform:uppercase;font-size:0.68rem">' + x(fw2) + '</span>');
    html += section('MITRE ATT&CK', null, miHtml);
  }

  // ── 7. Execution Logs ──
  if (c.rawOutput) {
    var rawJson = JSON.stringify(c.rawOutput);
    var logsHtml = '<details><summary style="cursor:pointer;list-style:none;display:flex;align-items:center;gap:0.5rem;color:var(--muted);font-size:0.72rem">'
      + '<span style="color:var(--accent)">&#9658;</span> View Execution Logs</summary>'
      + '<div style="margin-top:0.5rem">'
      + '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.3rem">'
      + '<span style="font-size:0.62rem;color:var(--muted)">stdout / stderr</span>'
      + '<button onclick="copyRaw(' + rawJson + ')" style="background:none;border:1px solid var(--border);border-radius:3px;color:var(--muted);cursor:pointer;font-size:0.62rem;padding:0.15rem 0.4rem">&#128203; Copy</button>'
      + '</div>'
      + '<pre style="background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:0.6rem;font-size:0.64rem;color:var(--text);overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:180px;overflow-y:auto;margin:0">'
      + x(c.rawOutput) + '</pre></div></details>';
    html += section('Execution Logs', null, logsHtml);
  }

  document.getElementById('evidence-content').innerHTML = html;
}

// Stop an in-flight run. The agent cancels gracefully (completed steps are kept;
// the run is marked partial). If the agent is offline the server marks it partial.
export function stopRun(runId) {
  if (!confirm('Stop this run?\n\nCompleted steps are kept and the run is marked partial. Remaining steps will not execute.')) return;
  apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/cancel', { method: 'POST' })
    .then(function(res) {
      showToast('Run ' + (res && res.status === 'partial' ? 'stopped (agent offline)' : 'stopping…'), 'ok');
      loadRuns();
    })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// _pausePending tracks runIds with an outstanding pause/resume click still
// awaiting confirmation, so armPauseConfirmFallback's timeout can tell
// whether loadRuns() already resolved it (see that function below).
var _pausePending = {};

export function pauseRun(runId) {
  apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/pause', { method: 'POST' })
    .then(function() {
      showToast('Pausing…', 'ok');
      armPauseConfirmFallback(runId, 'Pause');
    })
    .catch(function(e) { showToast(e.message, 'err'); });
}

export function resumeRun(runId) {
  apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/resume', { method: 'POST' })
    .then(function() {
      showToast('Resuming…', 'ok');
      armPauseConfirmFallback(runId, 'Resume');
    })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// Disables the clicked button immediately with a transient label, then
// reverts it after 20s IF no confirmation (a 'paused'/'resumed' run_event,
// see the run_event WS handler below) triggered a loadRuns() re-render in
// the meantime -- loadRuns() fully replaces this row's DOM from fresh
// server data when it does fire, so the only case this guards is a lost WS
// frame or an agent that never actually applied the pause/resume.
function armPauseConfirmFallback(runId, priorLabel) {
  _pausePending[runId] = true;
  var btn = document.getElementById('pause-btn-' + runId);
  if (btn) {
    btn.disabled = true;
    btn.textContent = priorLabel === 'Pause' ? 'Pausing…' : 'Resuming…';
  }
  setTimeout(function() {
    if (!_pausePending[runId]) return; // already resolved by a real confirmation
    delete _pausePending[runId];
    var stillThere = document.getElementById('pause-btn-' + runId);
    if (stillThere) {
      stillThere.disabled = false;
      stillThere.textContent = priorLabel === 'Pause' ? '❙❙ Pause' : '▶ Resume';
    }
  }, 20000);
}

var _dlCallback = null;
export function showDownloadOptions(title, callback) {
  document.getElementById('dl-options-title').textContent = title || 'Download Options';
  var radios = document.getElementsByName('dl-filter');
  for (var i = 0; i < radios.length; i++) {
    radios[i].checked = (radios[i].value === 'all');
  }
  _dlCallback = callback;
  document.getElementById('download-options-overlay').classList.add('open');
}
export function closeDownloadOptions() {
  document.getElementById('download-options-overlay').classList.remove('open');
  _dlCallback = null;
}
// Set up confirm click handler
export function __init_L16846() {
document.getElementById('dl-confirm-btn').onclick = function() {
  var selected = 'all';
  var radios = document.getElementsByName('dl-filter');
  for (var i = 0; i < radios.length; i++) {
    if (radios[i].checked) {
      selected = radios[i].value;
      break;
    }
  }
  var cb = _dlCallback; // capture before closeDownloadOptions nulls it
  closeDownloadOptions();
  if (cb) {
    cb(selected);
  }
};
}


// triggerDownload creates a temporary <a>, sets href/download, and clicks
// it to start a browser save-as -- the DOM-manipulation core every
// download*/export*Xxx function below shares (previously each of the 12
// call sites hand-wrote this same create/append/click/remove sequence).
// Callers that build the href from a Blob (URL.createObjectURL) keep that
// object URL in their own local variable so they can revoke it afterward
// -- triggerDownload only takes the final href string, nothing more.
export function triggerDownload(href, filename) {
  var a = document.createElement('a');
  a.href = href;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}
// buildReportFilename mirrors the backend's identically-named Go helper
// (internal/api/handlers.go) so every downloaded report -- whether the
// server streams it directly or the browser saves it via an <a download>
// link -- gets the same consistent, sortable, self-explanatory name:
// Audspect_<ReportType>_<Scope>_<YYYY-MM-DD_HH-mm-ss>.<ext>.
export function buildReportFilename(reportType, scope, ext) {
  var safe = (scope || '').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 80);
  if (!safe) safe = 'report';
  var d = new Date();
  var pad = function(n) { return String(n).padStart(2, '0'); };
  var ts = d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) +
    '_' + pad(d.getUTCHours()) + '-' + pad(d.getUTCMinutes()) + '-' + pad(d.getUTCSeconds());
  return 'Audspect_' + reportType + '_' + safe + '_' + ts + '.' + ext;
}

export function exportRunJSON(runId) {
  triggerDownload(
    '/api/scenarios/runs/' + encodeURIComponent(runId) + '/export',
    buildReportFilename('Run_Export', runId.substring(0, 8), 'json')
  );
}
export function openRunReport(runId) {
  showDownloadOptions('Simulation HTML Report', function(filter) {
    var query = filter ? '?filter=' + encodeURIComponent(filter) : '';
    window.open('/api/scenarios/runs/' + encodeURIComponent(runId) + '/report' + query, '_blank');
  });
}
// downloadRunReport saves the report as an actual .pdf file instead of just
// opening the HTML inline -- previously the only option was "open in a new
// tab" (openRunReport above), with no way to save a copy without knowing to
// use the browser's own "Save Page As". PDF (not HTML) is what enterprises
// expect from a "download report" action; the report content/design is
// identical either way, this only changes the file format, via the
// already-built /pdf endpoint (same headless-Chromium render as every other
// PDF export in this app).
export function downloadRunReport(runId) {
  showDownloadOptions('Simulation Report', function(filter) {
    var query = filter ? '?filter=' + encodeURIComponent(filter) : '';
    triggerDownload(
      '/api/scenarios/runs/' + encodeURIComponent(runId) + '/pdf' + query,
      buildReportFilename('BAS_Report', runId.substring(0, 8), 'pdf')
    );
  });
}
export function openCampaignReport(id) {
  showDownloadOptions('Campaign Report', function(filter) {
    var query = filter ? '?filter=' + encodeURIComponent(filter) : '';
    window.open('/api/campaigns/' + encodeURIComponent(id) + '/report' + query, '_blank');
  });
}
// downloadCampaignReport mirrors downloadRunReport for the campaign report.
export function downloadCampaignReport(id) {
  showDownloadOptions('Campaign Report', function(filter) {
    var query = filter ? '?filter=' + encodeURIComponent(filter) : '';
    triggerDownload(
      '/api/campaigns/' + encodeURIComponent(id) + '/pdf' + query,
      buildReportFilename('Campaign_Report', id.substring(0, 8), 'pdf')
    );
  });
}
// downloadSweepReport mirrors downloadCampaignReport for the sweep report.
export function downloadSweepReport(id) {
  triggerDownload(
    '/api/vex/sweeps/' + encodeURIComponent(id) + '/pdf',
    buildReportFilename('Variant_Sweep', id.substring(0, 8), 'pdf')
  );
}
// downloadEMSweepReport mirrors downloadSweepReport for the EM sweep's combined report.
export function downloadEMSweepReport(id) {
  triggerDownload(
    '/api/em/sweeps/' + encodeURIComponent(id) + '/pdf',
    buildReportFilename('Endpoint_Mastery_Sweep', id.substring(0, 8), 'pdf')
  );
}
export function downloadCampaignCSV(id) {
  showDownloadOptions('Campaign Forensic CSV', function(filter) {
    var query = filter ? '?filter=' + encodeURIComponent(filter) : '';
    var suffix = (filter && filter !== 'all') ? '-' + filter : '';
    triggerDownload(
      '/api/campaigns/' + encodeURIComponent(id) + '/forensic.csv' + query,
      buildReportFilename('Campaign_Forensic', id.substring(0, 8) + suffix, 'csv')
    );
  });
}
export function downloadRunCSV(runId) {
  showDownloadOptions('Simulation Forensic CSV', function(filter) {
    var query = filter ? '?filter=' + encodeURIComponent(filter) : '';
    var suffix = (filter && filter !== 'all') ? '-' + filter : '';
    triggerDownload(
      '/api/scenarios/runs/' + encodeURIComponent(runId) + '/forensic.csv' + query,
      buildReportFilename('BAS_Forensic', runId.substring(0, 8) + suffix, 'csv')
    );
  });
}
function frameworkDisplayName(fw) {
  return { art: 'Atomic Red Team', caldera: 'Caldera', posture: 'Posture Checks', steps: 'Custom Steps' }[fw] || fw || 'Unknown';
}

function genBatchId() {
  if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  return 'batch-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
}

export function confirmRun() {
  var scenarioId = state._modalScId || document.getElementById('modal-sc').value;
  var groupTargeted = (state._targetMode === 'group' || state._targetMode === 'all');
  var agentIds;
  if (groupTargeted) {
    var resolved = state._targetMode === 'group' ? resolvedGroupTargetIds() : resolvedAllTargetIds();
    agentIds = resolved.eligible.map(function(a) { return a.agentId; });
    if (!scenarioId || !agentIds.length) { showToast('Select scenario and at least one eligible agent', 'err'); return; }
  } else {
    var primaryId = document.getElementById('modal-agent').value;
    if (!scenarioId || !primaryId) { showToast('Select scenario and agent', 'err'); return; }
    agentIds = [primaryId].concat(additionalAgentIds());
  }
  var multi = agentIds.length > 1;

  var sc = state.scenarios.find(function(s) { return s.id === scenarioId; });
  var modeWrap = document.getElementById('modal-mode-wrap');
  var mode = (modeWrap.style.display !== 'none') ? document.getElementById('modal-mode').value : 'posture';
  var confirmLive = false, confirmLab = false;

  var agentListText = agentIds.map(function(id) {
    var a = state.agents.find(function(ag) { return ag.agentId === id; });
    return '• ' + (a ? a.agentId + ' — ' + a.hostname : id);
  }).join('\n');
  var header = 'Scenario: ' + (sc ? sc.name : scenarioId) + '\nFramework: ' + frameworkDisplayName(scenarioFramework(sc));

  // Group/All targeting can silently resolve to far more agents than a user
  // manually checking boxes would ever pick, so it always gets its own explicit
  // confirm regardless of run mode. In posture mode this REPLACES the existing
  // manual-multi-agent confirm below (same purpose, group-aware wording) rather
  // than showing two confirms back to back. In telemetry/lab mode it is
  // additional to — shown before — those modes' own existing confirms.
  if (groupTargeted) {
    var groupCount = state._targetMode === 'group'
      ? Object.keys(state._groupSel).filter(function(k) { return state._groupSel[k]; }).length : 0;
    var blastMsg = state._targetMode === 'all'
      ? 'This will run on all ' + agentIds.length + ' eligible agent(s).\n\nProceed?'
      : 'This will run on ' + agentIds.length + ' agent(s) across ' + groupCount + ' group(s).\n\nProceed?';
    if (!confirm(blastMsg)) return;
  }

  if (mode === 'telemetry') {
    var telemetryMsg = multi
      ? 'TELEMETRY mode runs real, identity-safe techniques and WILL generate EDR/SIEM alerts.\n\n' +
        header + '\n\nAgents (' + agentIds.length + '):\n' + agentListText +
        '\n\nProceed only on approved, monitored targets. Continue?'
      : 'TELEMETRY mode runs real, identity-safe techniques and WILL generate EDR/SIEM alerts.\n\nProceed only on an approved, monitored target. Continue?';
    if (!confirm(telemetryMsg)) return;
    confirmLive = true;
  } else if (mode === 'lab') {
    var labMsg = multi
      ? 'LAB mode runs FULL-FIDELITY techniques (LSASS dump, allowlisted spray) and will trigger EDR.\n\n' +
        header + '\n\nAgents (' + agentIds.length + '):\n' + agentListText +
        '\n\nISOLATED AD RANGE ONLY — never production. Continue?'
      : 'LAB mode runs FULL-FIDELITY techniques (LSASS dump, allowlisted spray) and will trigger EDR.\n\nISOLATED AD RANGE ONLY — never production. Continue?';
    if (!confirm(labMsg)) return;
    if (!confirm('Second confirmation required for LAB mode.\n\nConfirm the target is an isolated lab/range with a snapshot?')) return;
    confirmLive = true; confirmLab = true;
  } else if (multi && !groupTargeted) {
    // Posture mode has zero confirmation for a single agent today; a batch of 2+
    // manually-picked targets is a bigger blast radius, so gate it with one
    // lightweight confirm. Group/All targeting already showed its own
    // group-aware blast-radius confirm above, so it's excluded here to avoid
    // asking the operator to confirm the same dispatch twice.
    var postureMsg = 'Run scenario?\n\n' + header + '\n\nAgents (' + agentIds.length + '):\n' + agentListText + '\n\nProceed?';
    if (!confirm(postureMsg)) return;
  }

  var reasonEl = document.getElementById('modal-reason');
  var reason = (mode !== 'posture' && reasonEl) ? reasonEl.value.trim() : '';
  var variantDepthEl = document.getElementById('modal-variant-depth');
  var variantDepth = (variantDepthEl && document.getElementById('modal-variant-wrap').style.display !== 'none')
    ? variantDepthEl.value : 'none';

  var baseBody = { mode: mode, confirmLive: confirmLive, confirmLab: confirmLab,
                    reason: reason, variantDepth: variantDepth, batchId: genBatchId() };
  var maxPrivEl2 = document.getElementById('modal-max-privilege');
  if (maxPrivEl2 && maxPrivEl2.value) {
    baseBody.executionPolicy = { maxPrivilege: maxPrivEl2.value };
  }
  if (state._runSelection && state._runSelection.scId === scenarioId && state._runSelection.ids.length) {
    if (state._runSelection.fw === 'art') baseBody.techniques = state._runSelection.ids;
    else if (state._runSelection.fw === 'caldera') baseBody.abilities = state._runSelection.ids;
    else if (state._runSelection.fw === 'steps') baseBody.steps = state._runSelection.ids.map(Number);
    else if (state._runSelection.fw === 'posture') baseBody.checks = state._runSelection.ids;
    if (state._runSelection.locked && state._runSelection.ids.length === 1) {
      baseBody.runLabel = state._runSelection.ids[0] + ' — Re-validate';
    }
  }

  var runBtn = document.getElementById('modal-run-btn');
  if (multi) {
    runBtn.disabled = true;
    runBtn.innerHTML = 'Dispatching to ' + agentIds.length + ' agents…';
  }

  // Each dispatch is independent: a rejected promise or a {error:...} response
  // body is normalized into a resolved {ok:false} result so one agent's failure
  // can never abort or block the others (equivalent to Promise.allSettled).
  var dispatches = agentIds.map(function(agentId) {
    var body = Object.assign({ agentId: agentId }, baseBody);
    return apicall('/api/scenarios/' + encodeURIComponent(scenarioId) + '/run', {
      method: 'POST', body: JSON.stringify(body)
    }).then(function(res) {
      if (res && res.error) return { agentId: agentId, ok: false, error: res.error };
      return { agentId: agentId, ok: true, runId: res && res.runId, mode: res && res.mode };
    }).catch(function(e) {
      return { agentId: agentId, ok: false, error: e.message };
    });
  });

  Promise.all(dispatches).then(function(results) {
    if (multi) { runBtn.disabled = false; runBtn.innerHTML = '&#9654; Run'; }
    var ok = results.filter(function(r) { return r.ok; });
    var failed = results.filter(function(r) { return !r.ok; });

    if (!multi) {
      if (failed.length) { showToast('Run failed: ' + failed[0].error, 'err'); return; }
      closeModal();
      showToast('Dispatched (' + (ok[0].mode || mode) + ') — Run ID: ' + ok[0].runId, 'ok');
      showTab('runs'); loadRuns();
      return;
    }

    closeModal();
    if (!failed.length) {
      showToast('Dispatched to ' + ok.length + ' agents.', 'ok');
    } else if (ok.length) {
      showToast('Dispatched to ' + ok.length + '/' + agentIds.length + ' agents. Failed: ' +
        failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
    } else {
      showToast('All ' + agentIds.length + ' dispatches failed. ' +
        failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
    }
    // Successful runs (if any) are real and worth seeing, same as the single-agent path.
    showTab('runs'); loadRuns();
  });
}

export function connectWS() {
  if (state.socket) state.socket.close();
  var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  state.socket = new WebSocket(proto + '//' + location.host + '/ws/browser');
  state.socket.onopen = function() {
    document.getElementById('ws-dot').classList.add('on');
    document.getElementById('ws-label').textContent = 'live';
  };
  state.socket.onclose = function() {
    document.getElementById('ws-dot').classList.remove('on');
    document.getElementById('ws-label').textContent = 'reconnecting';
    setTimeout(connectWS, 5000);
  };
  state.socket.onmessage = function(evt) {
    try {
      var msg = JSON.parse(evt.data);
      if (msg.type === 'run_event') {
        window.onRunEvent(msg);
        // A paused/resumed confirmation must refresh the Live Runs table --
        // window.onRunEvent above only updates the Live drawer (scoped to
        // whichever single run's drawer, if any, is currently open). Filtered
        // to this rare event type so it doesn't fire loadRuns() on every
        // routine step-level event.
        if ((msg.data.events || []).some(function(e) { return e.type === 'paused' || e.type === 'resumed'; })) {
          _pausePending = {}; // any pending fallback for this batch's run(s) is now resolved
          loadRuns();
        }
        return;
      }
      if (msg.type === 'agentUpdate')        requestAgentsLiveRefresh();
      if (msg.type === 'scenario_result')    { loadRuns(); requestAgentsLiveRefresh(); refreshDashboardCampaigns(); }
      if (msg.type === 'tamper_alert')       { showTamperBanner(msg.data); }
      if (msg.type === 'attackpath_collected') { _apOnCollected(msg); }
      if (msg.type === 'ap_job_update')   { _apOnJobUpdate(msg); }
      if (msg.type === 'ap_job_progress') { _apOnProgress(msg); }
      if (msg.type === 'revalidation_started')     { _onRevalidationStarted(msg); }
      if (msg.type === 'siem_correlation_complete') { _onSIEMCorrelationComplete(msg); }
    } catch(e) {}
  };
}

/* ── Command palette (Ctrl/Cmd-K) ─────────────────────────────────────────
   Launcher routing to existing tabs + global actions, plus live search
   (Global Search Phase 2) over GET /api/search -- results merge into the
   same flat/selectable/run mechanism the static nav list already uses, so
   keyboard nav and click-to-select work identically for both. Respects
   role: Users/Settings (admin) and New scenario (admin/analyst) appear only
   when permitted — same gating as the sidebar. */
var _cmdkOpen = false;
function cmdkCommands() {
  var nav = [
    { t: 'Dashboard',   fn: function() { showTab('dashboard'); } },
    { t: 'Scenarios',   fn: function() { showTab('scenarios'); } },
    { t: 'Live Runs',   fn: function() { showTab('runs'); } },
    { t: 'Compliance',  fn: function() { showTab('compliance'); } },
    { t: 'Agents',      fn: function() { showTab('agents'); } }
  ];
  if (ROLE === 'admin') {
    nav.push({ t: 'Users & roles', fn: function() { showTab('settings'); showSettingsSection('users'); } });
    nav.push({ t: 'Settings', fn: function() { showTab('settings'); } });
  }
  var actions = [{ t: 'Run simulation', fn: function() { openModal(null, null); } }];
  if (ROLE === 'admin' || ROLE === 'analyst') {
    actions.unshift({ t: 'New scenario', fn: function() { openBuilder(); } });
  }
  return [{ sec: 'Navigate', items: nav }, { sec: 'Actions', items: actions }];
}

// CMDK_SEARCH_LABELS maps a search result's docType to its section header.
// "campaign" -> "Threat Campaigns", deliberately not "Campaigns" -- the
// sidebar's existing Campaigns tab is internal/campaign (BAS execution
// rollups), a different concept from intelligence_campaigns.
var CMDK_SEARCH_LABELS = {
  scenario: 'Scenarios', run: 'Runs', finding: 'Findings',
  actor: 'Threat Actors', campaign: 'Threat Campaigns',
  malware: 'Malware', tool: 'Tools', technique: 'Techniques',
  rule: 'Detection Rules', compliance_control: 'Compliance Controls',
  detection_connector: 'Detection Connectors', action_connector: 'Response Connectors'
};

// cmdkOpenResult dispatches a selected search result to a real navigation
// action per docType, or the minimal fallback popup for the 3 types with
// no detail view anywhere in this app yet (campaign/malware/tool). Also
// fires a fire-and-forget selection-tracking call (Global Search Phase 3) --
// never blocks navigation, failures are silently swallowed.
function cmdkOpenResult(r) {
  apicall('/api/search/select', {
    method: 'POST',
    body: JSON.stringify({ docType: r.docType, sourceId: r.sourceId })
  }).catch(function() {});
  if (r.docType === 'run') {
    openRunReport(r.sourceId);
  } else if (r.docType === 'finding') {
    showTab('findings');
    setTimeout(function() { openFinding(r.sourceId); }, 150);
  } else if (r.docType === 'actor') {
    showTab('threat-priority');
    setTimeout(function() { showThreatPriorityDetail(r.title); }, 150);
  } else if (r.docType === 'technique') {
    // The 150ms delay matters here, not just as a defensive habit:
    // openTechnique() reads window._covSt[id], populated asynchronously by
    // loadCoverageMatrix() (kicked off by showTab('attack-coverage')) --
    // calling it too early shows a wrong "Untested" badge for a technique
    // that may actually be covered.
    showTab('attack-coverage');
    setTimeout(function() { openTechnique(r.sourceId); }, 150);
  } else if (r.docType === 'scenario') {
    // No true "open by ID" exists for scenarios -- they expand inline
    // within the Scenarios tab's own tile grid. Reuse the existing sc-search
    // filter box rather than building new expand-by-ID logic.
    showTab('scenarios');
    setTimeout(function() {
      document.getElementById('sc-search').value = r.title;
      renderScenarios();
    }, 150);
  } else {
    cmdkResultFallback(r);
  }
}

// cmdkResultFallback reuses the existing #results-overlay drawer (the same
// one openFinding/openTechnique already populate) to show a search result's
// own title/description/tags for entity types with no detail view built
// yet. No network request -- everything shown is already in `r`.
function cmdkResultFallback(r) {
  document.getElementById('results-overlay').classList.remove('run-mode');
  document.getElementById('results-title').textContent = r.title + ' — ' + CMDK_SEARCH_LABELS[r.docType];
  document.getElementById('results-export').innerHTML = '';
  document.getElementById('results-summary').innerHTML = '';
  document.getElementById('results-body').innerHTML =
    (r.description ? '<p style="margin-bottom:0.8rem">' + x(r.description) + '</p>' : '') +
    ((r.tags || []).length ? '<div style="display:flex;gap:0.4rem;flex-wrap:wrap">' +
      r.tags.map(function(t) { return '<span class="sbadge" style="background:transparent;border:1px solid var(--border)">' + x(t) + '</span>'; }).join('') +
      '</div>' : '');
  document.getElementById('results-overlay').classList.add('open');
}

// cmdkToggleFavorite calls POST /api/search/favorite for r, mutates
// r.favorited in place on success (r is a reference into whichever array
// it came from -- cmdkSearchResults or cmdkRecents inside openCmdk()'s
// closure -- so that array reflects the new state on the next render),
// then invokes onDone to trigger a repaint. Fails soft: a network error
// leaves r.favorited untouched but still calls onDone so the UI never hangs.
function cmdkToggleFavorite(r, onDone) {
  apicall('/api/search/favorite', {
    method: 'POST',
    body: JSON.stringify({ docType: r.docType, sourceId: r.sourceId })
  }).then(function(res) {
    r.favorited = !!(res && res.favorited);
    onDone();
  }).catch(function() { onDone(); });
}

export function openCmdk() {
  if (_cmdkOpen || !ROLE) return;
  _cmdkOpen = true;
  var cmds = cmdkCommands();
  var wrap = document.createElement('div');
  wrap.className = 'cmdk-scrim';
  wrap.innerHTML =
    '<div class="cmdk" role="dialog" aria-label="Command palette">' +
      '<div class="cmdk-in">' +
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>' +
        '<input id="cmdk-input" placeholder="Type a command or search…" autocomplete="off">' +
        '<span class="cmdk-esc">esc</span>' +
      '</div><div class="cmdk-list" id="cmdk-list"></div>' +
      '<div class="bld-mode-help" id="cmdk-ops-hint" style="display:none;margin:0;padding:8px 15px;border-top:1px solid var(--border)"></div>' +
    '</div>';
  document.body.appendChild(wrap);
  var input = wrap.querySelector('#cmdk-input');
  var list = wrap.querySelector('#cmdk-list');
  var flat = [], active = 0, currentQ = '';

  // Search state: cmdkSearchResults holds the last successful response
  // (kept across in-flight requests so results don't flicker to empty
  // while typing), null means the last request failed, [] means empty
  // query or genuinely no matches. cmdkSearchToken discards responses to
  // requests a newer keystroke has already superseded.
  var cmdkSearchResults = [];
  var cmdkSearchToken = 0;
  var cmdkSearchTimer = null;
  function cmdkSearch(q, onDone) {
    clearTimeout(cmdkSearchTimer);
    if (!q) { cmdkSearchResults = []; onDone(); return; }
    cmdkSearchTimer = setTimeout(function() {
      var token = ++cmdkSearchToken;
      apicall('/api/search?q=' + encodeURIComponent(q) + '&limit=20')
        .then(function(results) {
          if (token !== cmdkSearchToken) return;
          cmdkSearchResults = Array.isArray(results) ? results : null;
          onDone();
        })
        .catch(function() {
          if (token !== cmdkSearchToken) return;
          cmdkSearchResults = null;
          onDone();
        });
    }, 150);
  }

  // cmdkRecents holds the one-shot GET /api/search/recents response,
  // fetched once when the palette opens (not on every keystroke) and only
  // ever shown when the input is empty (Global Search Phase 3).
  var cmdkRecents = [];
  apicall('/api/search/recents').then(function(r) {
    cmdkRecents = Array.isArray(r) ? r : [];
    if (currentQ === '') render(currentQ);
  }).catch(function() { cmdkRecents = []; });

  // One-shot fetch of the supported search-box operators, rendered as a
  // persistent footer hint below the results list. Fails soft -- the hint
  // just stays hidden if the request errors, never blocks the palette.
  apicall('/api/search/operators').then(function(r) {
    var ops = (r && Array.isArray(r.operators)) ? r.operators : [];
    var typeOp = ops.filter(function(o) { return o.name === 'type' && Array.isArray(o.values) && o.values.length; })[0];
    if (!typeOp) return;
    var hint = wrap.querySelector('#cmdk-ops-hint');
    hint.textContent = 'Tip: ' + typeOp.values.map(function(v) { return 'type:' + v; }).join(', ') + ' to filter by type.';
    hint.style.display = '';
  }).catch(function() { /* fails soft -- footer just stays hidden */ });

  function selectable() { return flat.map(function(f, i) { return f.sec ? -1 : i; }).filter(function(i) { return i >= 0; }); }
  function paint() {
    var nodes = list.querySelectorAll('[data-ci]');
    Array.prototype.forEach.call(nodes, function(n) { n.classList.toggle('active', +n.dataset.ci === active); });
  }

  function staticFlatFor(q) {
    var out = [];
    cmds.forEach(function(c) {
      var items = c.items.filter(function(i) { return i.t.toLowerCase().indexOf(q) >= 0; });
      if (items.length) { out.push({ sec: c.sec }); items.forEach(function(i) { out.push(i); }); }
    });
    return out;
  }

  // recentsFlat only contributes rows when the input is empty -- it's
  // prepended above the static Navigate/Actions list, which keeps
  // rendering unchanged from Phase 2 (see render()'s concat order below).
  function recentsFlat(q) {
    if (q !== '' || !cmdkRecents.length) return [];
    var out = [{ sec: 'Recents' }];
    cmdkRecents.forEach(function(r) {
      out.push({ t: r.title, docType: r.docType, sourceId: r.sourceId, fav: r.favorited, ref: r, fn: function() { cmdkOpenResult(r); } });
    });
    return out;
  }

  function searchFlat() {
    var out = [];
    if (cmdkSearchResults === null) { out.push({ sec: 'Search unavailable' }); return out; }
    var byType = {};
    cmdkSearchResults.forEach(function(r) { (byType[r.docType] = byType[r.docType] || []).push(r); });
    ['scenario', 'run', 'finding', 'actor', 'campaign', 'malware', 'tool', 'technique',
     'rule', 'compliance_control', 'detection_connector', 'action_connector'].forEach(function(dt) {
      var items = byType[dt];
      if (!items || !items.length) return;
      out.push({ sec: CMDK_SEARCH_LABELS[dt] });
      items.forEach(function(r) { out.push({ t: r.title, docType: r.docType, sourceId: r.sourceId, fav: r.favorited, ref: r, fn: function() { cmdkOpenResult(r); } }); });
    });
    return out;
  }

  function render(q) {
    flat = recentsFlat(q).concat(staticFlatFor(q)).concat(searchFlat());
    var sel = selectable(); active = sel.length ? sel[0] : 0;
    if (!flat.length) { list.innerHTML = '<div class="cmdk-empty">No matches</div>'; return; }
    list.innerHTML = flat.map(function(f, i) {
      if (f.sec) return '<div class="cmdk-sec">' + x(f.sec) + '</div>';
      // f.docType is only set for search-result/recents rows (Phase 3) --
      // static Navigate/Actions rows never get the star affordance.
      var star = f.docType
        ? '<span data-fav-ci="' + i + '" style="cursor:pointer;margin-right:0.5rem;color:' + (f.fav ? 'var(--warning)' : 'var(--muted)') + '">★</span>'
        : '';
      return '<div class="cmdk-item" data-ci="' + i + '">' + star + x(f.t) + '</div>';
    }).join('');
    Array.prototype.forEach.call(list.querySelectorAll('[data-ci]'), function(node) {
      node.onmousemove = function() { active = +node.dataset.ci; paint(); };
      node.onclick = function() { run(+node.dataset.ci); };
    });
    Array.prototype.forEach.call(list.querySelectorAll('[data-fav-ci]'), function(node) {
      node.onclick = function(e) {
        e.stopPropagation(); // don't also trigger the parent row's onclick (navigation)
        var it = flat[+node.dataset.favCi];
        if (!it || !it.ref) return;
        cmdkToggleFavorite(it.ref, function() { render(currentQ); });
      };
    });
    paint();
  }

  function draw(q) {
    q = (q || '').toLowerCase();
    currentQ = q;
    render(q);
    cmdkSearch(input.value, function() { render(q); });
  }

  function move(dir) {
    var sel = selectable(); if (!sel.length) return;
    var pos = sel.indexOf(active); if (pos < 0) pos = 0;
    active = sel[(pos + dir + sel.length) % sel.length]; paint();
    var node = list.querySelector('[data-ci="' + active + '"]'); if (node) node.scrollIntoView({ block: 'nearest' });
  }
  function run(i) { var it = flat[i]; if (!it || it.sec) return; close(); it.fn(); }
  function close() { _cmdkOpen = false; document.removeEventListener('keydown', onKey, true); wrap.remove(); }
  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
    else if (e.key === 'Enter') { e.preventDefault(); run(active); }
  }
  wrap.addEventListener('mousedown', function(e) { if (e.target === wrap) close(); });
  document.addEventListener('keydown', onKey, true);
  input.addEventListener('input', function() { draw(input.value); });
  draw('');
  setTimeout(function() { input.focus(); }, 20);
}

var ROLE_LABELS = { admin: 'Admin', analyst: 'Analyst', viewer: 'Viewer' };

export function loadUsers() {
  apicall('/api/users').then(function(data) {
    document.getElementById('users-cnt').textContent = data.length;
    var tbody = document.getElementById('users-body');
    if (!data.length) { tbody.innerHTML = '<tr><td colspan="6" class="empty">No users found.</td></tr>'; return; }
    tbody.innerHTML = data.map(function(u) {
      var statusBadge = u.isActive ? '<span class="sbadge s-completed">Active</span>' : '<span class="sbadge s-offline">Disabled</span>';
      var mustPw = u.mustChangePw ? ' <span class="tag u-warning">pw reset</span>' : '';
      var actions =
        '<button class="btn btn-outline btn-sm" onclick="openEditUser(\'' + x(u.id) + '\',\'' + x(u.username) + '\',\'' + x(u.role) + '\')">Edit</button>' +
        ' <button class="btn btn-outline btn-sm" onclick="doResetPassword(\'' + x(u.id) + '\',\'' + x(u.username) + '\')" style="margin-left:0.3rem">Reset PW</button>' +
        ' <button class="btn btn-outline-' + (u.isActive ? 'red' : 'green') + ' btn-sm" onclick="toggleUserActive(\'' + x(u.id) + '\',' + !u.isActive + ')" style="margin-left:0.3rem">' + (u.isActive ? 'Disable' : 'Enable') + '</button>';
      return '<tr>' +
        '<td><strong>' + x(u.username) + '</strong>' + mustPw + '</td>' +
        '<td>' + (ROLE_LABELS[u.role] || x(u.role)) + '</td>' +
        '<td>' + statusBadge + '</td>' +
        '<td style="color:var(--muted);font-size:0.78rem">' + fmtDate(u.createdAt) + '</td>' +
        '<td style="color:var(--muted);font-size:0.78rem">' + (u.lastLogin ? fmtDate(u.lastLogin) : 'Never') + '</td>' +
        '<td>' + actions + '</td></tr>';
    }).join('');
  }).catch(function(e) { showToast('Failed to load users: ' + e.message, 'err'); });
}

export function openCreateUser() {
  document.getElementById('cu-username').value = '';
  document.getElementById('cu-password').value = '';
  document.getElementById('cu-role').value = 'analyst';
  document.getElementById('cu-err').textContent = '';
  document.getElementById('create-user-overlay').classList.add('open');
}
export function closeCreateUser() { document.getElementById('create-user-overlay').classList.remove('open'); }

export function submitCreateUser() {
  var username = document.getElementById('cu-username').value.trim();
  var password = document.getElementById('cu-password').value;
  var role     = document.getElementById('cu-role').value;
  document.getElementById('cu-err').textContent = '';
  if (!username || !password) { document.getElementById('cu-err').textContent = 'Username and password are required.'; return; }
  apicall('/api/users', { method: 'POST', body: JSON.stringify({ username: username, password: password, role: role }) })
  .then(function(res) {
    if (res.error) throw new Error(res.error);
    closeCreateUser(); showToast('User ' + username + ' created', 'ok'); loadUsers();
  })
  .catch(function(e) { document.getElementById('cu-err').textContent = e.message; });
}

export function openEditUser(id, username, role) {
  state._editUserId = id;
  document.getElementById('edit-user-title').textContent = 'Edit: ' + username;
  document.getElementById('edit-user-sub').textContent = 'Change role for ' + username;
  document.getElementById('eu-role').value = role;
  document.getElementById('eu-err').textContent = '';
  document.getElementById('edit-user-overlay').classList.add('open');
}
export function closeEditUser() { document.getElementById('edit-user-overlay').classList.remove('open'); state._editUserId = null; }

export function submitEditUser() {
  if (!state._editUserId) return;
  var role = document.getElementById('eu-role').value;
  apicall('/api/users/' + encodeURIComponent(state._editUserId), { method: 'PUT', body: JSON.stringify({ role: role }) })
  .then(function(res) {
    if (res.error) throw new Error(res.error);
    closeEditUser(); showToast('Role updated', 'ok'); loadUsers();
  })
  .catch(function(e) { document.getElementById('eu-err').textContent = e.message; });
}

export function toggleUserActive(id, active) {
  apicall('/api/users/' + encodeURIComponent(id), { method: 'PUT', body: JSON.stringify({ isActive: active }) })
  .then(function(res) {
    if (res.error) throw new Error(res.error);
    showToast('Account ' + (active ? 'enabled' : 'disabled'), 'ok'); loadUsers();
  })
  .catch(function(e) { showToast(e.message, 'err'); });
}

export function doResetPassword(id, username) {
  var pw = prompt('Set temporary password for ' + username + ' (min 8 characters):');
  if (!pw) return;
  if (pw.length < 8) { showToast('Password must be at least 8 characters', 'err'); return; }
  apicall('/api/users/' + encodeURIComponent(id) + '/reset-password', { method: 'POST', body: JSON.stringify({ newPassword: pw }) })
  .then(function(res) {
    if (res.error) throw new Error(res.error);
    showToast('Password reset for ' + username, 'ok'); loadUsers();
  })
  .catch(function(e) { showToast(e.message, 'err'); });
}

// donutSVG renders a stacked donut from [{v,color}] segments (no chart lib).
function donutSVG(segs, size, stroke) {
  size = size || 124; stroke = stroke || 16;
  var r = (size - stroke) / 2, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r;
  var total = segs.reduce(function(s, seg) { return s + seg.v; }, 0) || 1, off = 0;
  var c = '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="var(--elevated)" stroke-width="' + stroke + '"/>';
  segs.forEach(function(s) {
    var len = s.v / total * C;
    c += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + s.color + '" stroke-width="' + stroke +
         '" stroke-dasharray="' + len + ' ' + (C - len) + '" stroke-dashoffset="' + (-off) + '" transform="rotate(-90 ' + cx + ' ' + cy + ')"/>';
    off += len;
  });
  return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '">' + c + '</svg>';
}

// sparkSVG — minimal sparkline (polyline + soft fill) for KPI tiles.
function sparkSVG(data, w, h, color) {
  w = w || 110; h = h || 32; color = color || 'var(--accent)';
  if (!data || data.length < 2) return '<svg width="' + w + '" height="' + h + '"></svg>';
  var max = Math.max.apply(null, data), min = Math.min.apply(null, data), rng = (max - min) || 1;
  var pts = data.map(function(v, i) { return [i / (data.length - 1) * w, h - ((v - min) / rng) * (h - 6) - 3]; });
  var d = pts.map(function(p, i) { return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join(' ');
  return '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">' +
    '<path d="' + d + ' L' + w + ' ' + h + ' L0 ' + h + ' Z" fill="' + color + '" opacity="0.12"/>' +
    '<path d="' + d + '" fill="none" stroke="' + color + '" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

// gaugeSVG — 270° arc gauge for a 0–100 value. Colour reflects the band.
export function gaugeSVG(value, size, stroke) {
  size = size || 124; stroke = stroke || 14;
  var r = (size - stroke) / 2, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r;
  var arc = C * 0.75, len = Math.max(0, Math.min(100, value)) / 100 * arc;
  var col = value >= 75 ? 'var(--teal)' : value >= 50 ? 'var(--warning)' : 'var(--danger)';
  return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '">' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="var(--elevated)" stroke-width="' + stroke +
      '" stroke-dasharray="' + arc + ' ' + C + '" stroke-linecap="round" transform="rotate(135 ' + cx + ' ' + cy + ')"/>' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + col + '" stroke-width="' + stroke +
      '" stroke-dasharray="' + len + ' ' + C + '" stroke-linecap="round" transform="rotate(135 ' + cx + ' ' + cy + ')" style="transition:stroke-dasharray .8s cubic-bezier(.2,.8,.2,1)"/></svg>';
}

// miniBars — small labelled bar chart (e.g. score across recent runs).
function miniBars(data, w, h) {
  w = w || 300; h = h || 70;
  if (!data || !data.length) return '<svg width="100%" height="' + h + '"></svg>';
  var max = Math.max.apply(null, data.map(function(d) { return d.v; })) || 1, bw = w / data.length, out = '';
  data.forEach(function(d, i) {
    var bh = d.v / max * (h - 16);
    out += '<rect x="' + (i * bw + bw * 0.18).toFixed(1) + '" y="' + (h - bh - 12).toFixed(1) + '" width="' + (bw * 0.64).toFixed(1) +
      '" height="' + bh.toFixed(1) + '" rx="2" fill="' + (d.color || 'var(--accent)') + '"/>' +
      '<text x="' + (i * bw + bw / 2).toFixed(1) + '" y="' + (h - 2) + '" text-anchor="middle" font-size="8.5" fill="var(--muted)" font-family="var(--font-mono)">' + x(d.l) + '</text>';
  });
  return '<svg width="100%" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' + out + '</svg>';
}

export function loadDashboard() {
  Promise.all([apicall('/api/agents'), apicall('/api/scenarios/runs')])
  .then(function(res) {
    var ag = res[0] || [], runs = res[1] || [];

    // Hero subtitle — agents, distinct techniques exercised, and last assessment.
    // tacticSet is the cumulative union of ATT&CK tactics ever exercised across
    // every run (not just the recent scored window below) -- used for the
    // Prevention Score tile's kill-chain-breadth caveat.
    var techSet = {}, tacticSet = {};
    runs.forEach(function(r) {
      (r.results || []).forEach(function(c) {
        var id = c.technique && c.technique.id;
        if (id) techSet[id] = true;
        var tac = c.technique && c.technique.tactic;
        if (tac) tacticSet[tac] = true;
      });
    });
    var techCount = Object.keys(techSet).length;
    var lastRun = runs[0];
    var lastStr = lastRun ? ago(lastRun.completedAt || lastRun.startedAt) : '';
    var subEl = document.getElementById('dash-subtitle');
    if (subEl) {
      subEl.textContent = 'Continuous validation across ' + ag.length + ' agent' + (ag.length === 1 ? '' : 's') +
        ' and ' + techCount + ' ATT&CK technique' + (techCount === 1 ? '' : 's') + '.' +
        (lastStr ? ' Last assessment ' + lastStr + '.' : ' No runs yet.');
    }

    // KPI — Prevention score: weighted aggregate across the last ~8 scored runs
    // (weighted by technique count, not a flat average of percentages) + trend
    // chip + sparkline of the same window (oldest→newest).
    // Only include runs with at least one scoreable result (pass OR fail).
    // A run where everything errored/skipped has preventionScore=0 but that 0
    // means "no data", not "0% prevention" — exclude it from the gauge.
    var scored = runs.filter(function(r) {
      if (!r.score) return false;
      if (r.score.preventionScore == null && r.score.riskScore == null) return false;
      return (r.score.passedTechniques || 0) + (r.score.failedTechniques || 0) > 0;
    });
    var prevPctOf = function(r) { return Math.round(r.score.preventionScore != null ? r.score.preventionScore : r.score.preventionEffectiveness || 0); };
    // techWeightOf: how many scored techniques (pass+fail) a run contributes —
    // used to weight the aggregate below so a 50-technique run counts more
    // than a 1-technique run, same principle as the server-side weighted score.
    var techWeightOf = function(r) { return (r.score.passedTechniques || 0) + (r.score.failedTechniques || 0); };
    if (scored.length) {
      // Aggregate Prevention Score across a recent window of runs (weighted by
      // technique count), not just the single most-recently-completed run --
      // a full-sweep dispatches one scenario_runs row per variant, so "latest
      // run" during a sweep is often a single low-N sample (e.g. one variant
      // that happened to bypass) rather than the fleet's real recent posture.
      // See project_docs_freshness_audit / the Variant Sweep dashboard report
      // this fixed 2026-08-10.
      var windowRuns = scored.slice(0, 8);
      var totalWeight = 0, weightedSum = 0;
      windowRuns.forEach(function(r) {
        var w = techWeightOf(r);
        totalWeight += w;
        weightedSum += prevPctOf(r) * w;
      });
      var prevPct = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : prevPctOf(scored[0]);
      var prevCol = prevPct >= 80 ? 'var(--teal)' : prevPct >= 50 ? 'var(--warning)' : 'var(--danger)';
      document.getElementById('kpi-score-val').textContent = prevPct + '%';
      document.getElementById('kpi-score-val').style.color = prevCol;
      document.getElementById('kpi-score-sub').textContent = 'across last ' + windowRuns.length +
        ' run' + (windowRuns.length === 1 ? '' : 's');

      // Coverage caveat: this score only speaks for tactics you've actually
      // exercised (cumulatively, across every run -- not just this window).
      // A high Prevention Score from a handful of tested scenarios does not
      // mean the fleet is broadly prepared; it means those specific controls
      // are effective. ENTERPRISE_TACTICS mirrors the same 14-tactic MITRE
      // ATT&CK Enterprise set internal/models/score.go's enterpriseTacticCount
      // is defined against, so this is directly comparable to a single run's
      // own killChainCoverage figure, just accumulated across run history.
      var ENTERPRISE_TACTICS = ['reconnaissance', 'resource-development', 'initial-access', 'execution',
        'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery',
        'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];
      var testedTacticCount = Object.keys(tacticSet).filter(function(t) { return ENTERPRISE_TACTICS.indexOf(t) !== -1; }).length;
      var killChainPct = Math.round(testedTacticCount / ENTERPRISE_TACTICS.length * 100);
      var covEl = document.getElementById('kpi-score-coverage');
      if (covEl) {
        covEl.textContent = killChainPct < 50
          ? 'Based on ' + testedTacticCount + '/' + ENTERPRISE_TACTICS.length + ' ATT&CK tactics tested — see Technique Coverage for gaps'
          : '';
      }

      // Trend: compare the newer half of the window against the older half
      // (both weighted the same way) rather than reusing a single run's
      // server-computed trend, which only ever compared that one run to its
      // immediate predecessor.
      var tEl = document.getElementById('kpi-score-trend');
      var mid = Math.ceil(windowRuns.length / 2);
      var newerHalf = windowRuns.slice(0, mid), olderHalf = windowRuns.slice(mid);
      var aggOf = function(list) {
        var tw = 0, ws = 0;
        list.forEach(function(r) { var w = techWeightOf(r); tw += w; ws += prevPctOf(r) * w; });
        return tw > 0 ? ws / tw : null;
      };
      var newerAgg = aggOf(newerHalf), olderAgg = aggOf(olderHalf);
      var trend = 'Stable';
      if (newerAgg != null && olderAgg != null) {
        if (newerAgg - olderAgg >= 3) trend = 'Improving';
        else if (olderAgg - newerAgg >= 3) trend = 'Degrading';
      }
      if (trend === 'Improving')      tEl.innerHTML = '<span class="trend up">▲</span> ';
      else if (trend === 'Degrading') tEl.innerHTML = '<span class="trend down">▼</span> ';
      else                            tEl.innerHTML = '<span class="trend flat">—</span> ';
      var prevSeries = windowRuns.map(prevPctOf).reverse();
      document.getElementById('kpi-score-spark').innerHTML = sparkSVG(prevSeries, 110, 30, 'var(--teal)');

      // Posture card — ring gauge + trend + run-history mini-bars.
      document.getElementById('dash-gauge').innerHTML = gaugeSVG(prevPct, 124, 14) +
        '<div class="ring-c"><span class="rv" style="color:' + prevCol + '">' + prevPct + '</span><span class="rl">of 100</span></div>';
      document.getElementById('dash-posture-trend').textContent = trend;
      var barRuns = scored.slice(0, 6).reverse();
      var barData = barRuns.map(function(r) {
        var d = new Date(r.completedAt || r.startedAt);
        var v = prevPctOf(r);
        return { l: isNaN(d) ? '' : (d.getMonth() + 1) + '/' + d.getDate(), v: v,
                 color: v >= 80 ? 'var(--teal)' : v >= 50 ? 'var(--warning)' : 'var(--danger)' };
      });
      document.getElementById('dash-posture-bars').innerHTML = miniBars(barData, 320, 64);
      document.getElementById('dash-posture-cap').textContent = 'Prevention across the last ' + barRuns.length +
        ' validated run' + (barRuns.length === 1 ? '' : 's') + '.';
    }

    // KPI — ATT&CK coverage: share of distinct exercised techniques prevented at
    // least once (pass|blocked). Sparkline = per-run prevention rate, last ~8.
    var techCov = {};
    runs.forEach(function(r) {
      (r.results || []).forEach(function(c) {
        var id = c.technique && c.technique.id;
        if (!id) return;
        if (c.result === 'pass' || c.result === 'blocked') { techCov[id] = techCov[id] || {}; techCov[id].exercised = true; techCov[id].prevented = true; }
        else if (c.result === 'fail') { techCov[id] = techCov[id] || {}; techCov[id].exercised = true; }
      });
    });
    var exIds = Object.keys(techCov).filter(function(k) { return techCov[k].exercised; });
    var prevIds = exIds.filter(function(k) { return techCov[k].prevented; });
    var covPct = exIds.length ? Math.round(prevIds.length / exIds.length * 100) : 0;
    var covCol = covPct >= 80 ? 'var(--teal)' : covPct >= 50 ? 'var(--warning)' : 'var(--danger)';
    document.getElementById('kpi-cov-val').textContent = exIds.length ? covPct + '%' : '—';
    document.getElementById('kpi-cov-val').style.color = exIds.length ? covCol : '';
    document.getElementById('kpi-cov-sub').textContent = exIds.length + ' technique' + (exIds.length === 1 ? '' : 's') + ' tested';
    var covSeries = runs.slice(0, 8).map(function(r) {
      var p = 0, f = 0;
      (r.results || []).forEach(function(c) { if (c.result === 'pass' || c.result === 'blocked') p++; else if (c.result === 'fail') f++; });
      return (p + f) ? Math.round(p / (p + f) * 100) : 0;
    }).reverse();
    document.getElementById('kpi-cov-spark').innerHTML = sparkSVG(covSeries, 110, 30, 'var(--warning)');

    // Control effectiveness donut — 4-way verdict split across all runs.
    // Prevented = pass|blocked; a fail is Detected-only when the blue team still
    // caught it (run.detectedTechs[id]) else Missed; Not-tested = error|skipped.
    var eff = { prevented: 0, detected: 0, missed: 0, other: 0 };
    runs.forEach(function(r) {
      var det = r.detectedTechs || {};
      (r.results || []).forEach(function(c) {
        if (c.result === 'pass' || c.result === 'blocked') eff.prevented++;
        else if (c.result === 'fail') {
          var id = c.technique && c.technique.id;
          if (id && det[id]) eff.detected++; else eff.missed++;
        }
        else eff.other++;
      });
    });
    var effTotal = eff.prevented + eff.detected + eff.missed + eff.other;
    var donutEl = document.getElementById('dash-donut');
    if (!effTotal) {
      donutEl.innerHTML = '<div class="empty">No run data yet.</div>';
    } else {
      var prevPctEff = Math.round(eff.prevented / (eff.prevented + eff.detected + eff.missed || 1) * 100);
      var lg = function(color, label, val) {
        return '<div style="display:flex;align-items:center;gap:0.5rem;font-size:0.82rem">' +
          '<span style="width:10px;height:10px;border-radius:3px;background:' + color + ';flex-shrink:0"></span>' +
          label + '<span style="margin-left:auto;font-weight:600;color:var(--text)">' + val + '</span></div>';
      };
      donutEl.style.display = 'flex';
      donutEl.style.gap = '1.5rem';
      donutEl.style.alignItems = 'center';
      donutEl.innerHTML =
        '<div style="position:relative;flex-shrink:0">' +
          donutSVG([
            { v: eff.prevented, color: 'var(--teal)' },
            { v: eff.detected, color: 'var(--warning)' },
            { v: eff.missed, color: 'var(--danger)' },
            { v: eff.other, color: 'var(--elevated)' }
          ]) +
          '<div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">' +
            '<span style="font-size:1.5rem;font-weight:700;line-height:1;color:' + (prevPctEff >= 80 ? 'var(--teal)' : prevPctEff >= 50 ? 'var(--warning)' : 'var(--danger)') + '">' + prevPctEff + '%</span>' +
            '<span style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted)">prevented</span>' +
          '</div>' +
        '</div>' +
        '<div style="flex:1;display:flex;flex-direction:column;gap:0.55rem;min-width:160px">' +
          lg('var(--teal)',    'Prevented',     eff.prevented) +
          (eff.detected > 0 ? lg('var(--warning)', 'Detected only', eff.detected) : '') +
          lg('var(--danger)', 'Missed',         eff.missed) +
          (eff.other > 0    ? lg('var(--elevated)', 'Not tested',   eff.other)    : '') +
          (eff.detected === 0 ? '<div style="font-size:0.63rem;color:var(--muted);margin-top:0.3rem;line-height:1.4">Detected-only appears once a SIEM/EDR integration is reporting alerts.</div>' : '') +
        '</div>';
    }

    // Attack flow — dual-rail kill-chain of the latest completed/partial run.
    var afEl = document.getElementById('dash-attackflow');
    var lastDone = runs.filter(function(r) { return r.status === 'completed' || r.status === 'partial'; })[0];
    if (afEl && lastDone) {
      document.getElementById('dash-attackflow-title').textContent = 'Attack flow · ' + (lastDone.name || lastDone.scenarioId || 'latest run');
      apicall('/api/scenarios/runs/' + encodeURIComponent(lastDone.id) + '/report.json').then(function(rep) {
        if (document.getElementById('dash-attackflow') !== afEl) return;
        var kc = (rep && rep.killChain) || [];
        if (!kc.length) { afEl.innerHTML = '<div class="empty" style="padding:1.5rem">No kill-chain data for the latest run.</div>'; return; }
        afEl.innerHTML = '<div class="killchain">' + killChainNodes(kc) + '</div>';
        var openLink = document.getElementById('dash-attackflow-open');
        if (openLink) { openLink.style.display = ''; openLink.onclick = function() { viewRunResults(lastDone); }; }
      }).catch(function() { afEl.innerHTML = '<div class="empty" style="padding:1.5rem">Attack flow unavailable.</div>'; });
    }

    // Recent runs (last 5)
    var recent = runs.slice(0, 5);
    var rrEl = document.getElementById('dash-recent-runs');
    if (!recent.length) {
      rrEl.innerHTML = '<div class="empty" style="padding:1.5rem">No runs yet.</div>';
    } else {
      rrEl.innerHTML = recent.map(function(r) {
        var cnt = (r.results || []).length;
        var fail = (r.results || []).filter(function(c) { return c.result === 'fail'; }).length;
        var scoreStr = '—';
        var scol = 'var(--text-dim)';
        if (r.score && r.score.preventionScore != null) {
          var pp = Math.round(r.score.preventionScore);
          var ta = r.score.trend === 'Improving' ? ' ↑' : r.score.trend === 'Degrading' ? ' ↓' : '';
          scoreStr = pp + '%' + ta;
          scol = pp >= 80 ? 'var(--teal)' : pp >= 50 ? 'var(--warning)' : 'var(--danger)';
        } else if (r.score && r.score.riskScore != null) {
          scoreStr = r.score.riskScore;
          scol = r.score.classification === 'Protected' ? 'var(--teal)' :
                 r.score.classification === 'Medium Risk' ? 'var(--warning)' : 'var(--danger)';
        }
        var dashPaused = r.status === 'running' && r.paused;
        return '<div class="dash-run-row">' +
          '<span class="sbadge ' + (dashPaused ? 's-paused' : 's-' + x(r.status)) + '" style="flex-shrink:0">' + (dashPaused ? 'paused' : x(r.status)) + '</span>' +
          '<span class="dash-run-name">' + x(r.name) + '</span>' +
          (cnt ? '<span style="font-size:0.72rem;color:var(--danger)">' + fail + ' fail</span>' : '') +
          '<span style="font-size:0.8rem;font-weight:600;color:' + scol + ';flex-shrink:0">' + scoreStr + '</span>' +
          '</div>';
      }).join('');
    }

    // Top failing techniques
    var techMap = {};
    runs.forEach(function(r) {
      (r.results || []).forEach(function(c) {
        var id = (c.technique && c.technique.id) || c.name || 'unknown';
        var name = (c.technique && c.technique.name) || c.name || id;
        if (!techMap[id]) techMap[id] = { name: name, fail: 0, pass: 0 };
        if (c.result === 'fail') techMap[id].fail++;
        else if (c.result === 'pass') techMap[id].pass++;
      });
    });
    var topFails = Object.keys(techMap)
      .map(function(id) { return techMap[id]; })
      .filter(function(t) { return t.fail > 0; })
      .sort(function(a, b) { return b.fail - a.fail; })
      .slice(0, 6);
    var tfEl = document.getElementById('dash-top-fails');
    if (!topFails.length) {
      tfEl.innerHTML = '<div class="empty" style="padding:1.5rem">No failures recorded.</div>';
    } else {
      var maxFail = topFails[0].fail;
      tfEl.innerHTML = topFails.map(function(t) {
        var pct = Math.round((t.fail / (t.fail + t.pass)) * 100);
        var w = Math.round((t.fail / maxFail) * 100);
        return '<div class="bar-row">' +
          '<div class="bar-label"><span style="color:var(--text-dim)">' + x(t.name) + '</span><span>' + t.fail + ' fail &middot; ' + pct + '%</span></div>' +
          '<div class="bar-track"><div class="bar-fill" style="width:' + w + '%;background:var(--danger);opacity:0.7"></div></div>' +
          '</div>';
      }).join('');
    }

    // ATT&CK tactic coverage
    var tacticMap = {};
    runs.forEach(function(r) {
      (r.results || []).forEach(function(c) {
        var tactic = (c.technique && c.technique.tactic) || 'other';
        if (!tacticMap[tactic]) tacticMap[tactic] = { pass: 0, fail: 0 };
        if (c.result === 'pass') tacticMap[tactic].pass++;
        else if (c.result === 'fail') tacticMap[tactic].fail++;
      });
    });
    var tactics = Object.keys(tacticMap);
    var attckEl = document.getElementById('dash-attck');
    if (!tactics.length) {
      attckEl.innerHTML = '<div class="empty" style="padding:1.5rem;grid-column:1/-1">No run data yet.</div>';
    } else {
      attckEl.innerHTML = tactics.map(function(tactic) {
        var d = tacticMap[tactic];
        var total = d.pass + d.fail;
        var pct = total ? Math.round((d.pass / total) * 100) : 0;
        var col = _riskScoreColor(pct);
        return '<div class="bar-row">' +
          '<div class="bar-label"><span style="text-transform:capitalize">' + x(tactic) + '</span><span style="color:' + col + '">' + pct + '%</span></div>' +
          '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:' + col + '"></div></div>' +
          '<div style="font-size:0.68rem;color:var(--muted);margin-top:0.15rem">' + d.pass + ' pass &middot; ' + d.fail + ' fail</div>' +
          '</div>';
      }).join('');
    }

    // Open findings KPI + Top exposure gaps
    apicall('/api/findings').then(function(fs) {
      var open = (fs || []).filter(function(f) { return f.status === 'open'; });
      var el = document.getElementById('kpi-findings-val');
      if (el) { el.textContent = open.length; el.style.color = open.length ? 'var(--danger)' : 'var(--success)'; }
      var sub = document.getElementById('kpi-findings-sub');
      if (sub) { var crit = open.filter(function(f) { return f.severity === 'Critical'; }).length; sub.textContent = crit ? crit + ' critical' : (open.length ? 'awaiting triage' : 'none open'); }
      var maxAge = 0;
      var oldestFinding = null;
      open.forEach(function(f) {
        var age = daysAgo(f.firstSeen);
        if (age > maxAge) {
          maxAge = age;
          oldestFinding = f;
        }
      });
      var surfEl = document.getElementById('kpi-surface-val');
      if (surfEl) {
        surfEl.textContent = open.length ? maxAge + 'd' : '0d';
        surfEl.style.color = maxAge >= 90 ? 'var(--danger)' : maxAge >= 30 ? 'var(--warning)' : 'var(--success)';
      }
      var surfSub = document.getElementById('kpi-surface-sub');
      if (surfSub) {
        if (open.length && oldestFinding) {
          surfSub.textContent = 'oldest: ' + (oldestFinding.techniqueId || 'unknown');
          surfSub.title = 'Oldest exposed weakness: ' + (oldestFinding.techniqueName || oldestFinding.techniqueId) + ' on ' + oldestFinding.agentId;
        } else {
          surfSub.textContent = 'no open weaknesses';
          surfSub.title = '';
        }
      }
      var gaps = document.getElementById('dash-gaps');
      if (gaps) {
        gaps.classList.remove('dash-soon');
        var bodyEl = gaps.querySelector('.dash-panel-body');
        var top = open.slice(0, 5);
        if (bodyEl) {
          bodyEl.innerHTML = top.length ? top.map(function(f) {
            return '<div class="lrow u-pointer" onclick="showTab(\'findings\');setTimeout(function(){openFinding(\'' + x(f.id) + '\')},150)">' +
              '<div class="lmain"><div class="lt">' + x(f.techniqueName || f.techniqueId) + '</div>' +
              '<div class="ls"><span class="tech-id">' + x(f.techniqueId) + '</span> · ' + x(f.controlClass) + ' · ' + x(f.agentId) + '</div></div>' +
              '<div class="lr">' + findingSevBadge(f.severity, f.exposureState) + '</div></div>';
          }).join('') : '<div class="empty" style="padding:1.5rem">No open findings.</div>';
        }
      }
    }).catch(function() {});

    loadRansomwareReadiness(runs);
    refreshDashboardCampaigns();
    loadComplianceScores();
    loadDashboardITSM();
    loadKEVWidget();
    loadEndpointPostureWidget();
    loadReadinessTrends();
  })
  .catch(function(e) { showToast('Dashboard load failed: ' + e.message, 'err'); });
}