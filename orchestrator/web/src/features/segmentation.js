// Segmentation lab: the packs the lab can run, a Run control for admins, the run history, and each run's per-probe
// verdicts exactly as the server stored them. Everything from the server is escaped on the way into markup. The page
// never decides a verdict; it shows the one it was given.
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { card, pill, empty, kv } from '../core/kit.js';

var S = { enabled: false, canRun: false, packs: [], runs: [], sel: '', detail: null, timer: null, busy: false };
var VERDICT_TONE = { PASS: 'ok', FAIL: 'bad', UNKNOWN: 'warn', ERROR: 'muted' };

function el(id) { return document.getElementById(id); }

function setHTML(id, html) { var n = el(id); if (n) n.innerHTML = html; }

function errorText(r) { return r && r.error ? String(r.error) : 'The server returned an unexpected answer.'; }

export function loadSegmentation() {
  return Promise.all([
    apicall('/api/segmentation/packs'),
    apicall('/api/segmentation/runs'),
  ]).then(function(res) {
    var p = res[0] || {};
    var r = res[1] || {};
    S.enabled = !!p.enabled;
    S.canRun = !!p.can_run;
    S.packs = Array.isArray(p.packs) ? p.packs : [];
    S.runs = Array.isArray(r.runs) ? r.runs : [];
    renderPacks();
    renderRuns();
    if (S.sel) return loadDetail(S.sel);
    renderDetail();
    scheduleRefresh();
    return true;
  }).catch(function(e) {
    setHTML('seg-packs', card('Packs', empty('warn', 'Could not reach the server', e && e.message ? e.message : 'request failed')));
    return false;
  });
}

export function segRefresh() { loadSegmentation(); }

function renderPacks() {
  if (!S.enabled) {
    setHTML('seg-packs', card('Lab not configured', empty('warn', 'The segmentation lab is not configured on this server', 'An administrator sets SEGMENTATION_LAB_DIR to a lab checkout to enable it.')));
    return;
  }
  var cards = S.packs.map(function(p) {
    var run = S.canRun ? '<button type="button" class="btn btn-outline"' + on('click', 'segRun', p.id) + '>Run pack</button>' : '';
    return '<div class="seg-pack"><b>' + x(p.name) + '</b><p>' + x(p.description) + '</p><div class="seg-pack-run">' + run + '</div></div>';
  }).join('');
  var note = S.canRun ? '' : '<p class="seg-note">Only administrators can start a run. You can read the results below.</p>';
  setHTML('seg-packs', card('Packs', note + '<div class="seg-packs">' + cards + '</div>'));
}

function statusTone(s) { return s === 'completed' ? 'ok' : s === 'failed' ? 'bad' : 'warn'; }

function renderRuns() {
  if (!S.runs.length) {
    setHTML('seg-runs', card('Runs', empty('clock', 'No runs yet', 'Run a pack to see its verdicts here.')));
    return;
  }
  var rows = S.runs.map(function(r) {
    var stable = r.stable === null || r.stable === undefined ? '—' : (r.stable ? 'stable' : 'unstable');
    return '<tr class="seg-row' + (r.id === S.sel ? ' is-sel' : '') + '"' + on('click', 'segSelect', r.id) + '>' +
      '<td>' + x(fmtDate(r.created_at)) + '</td>' +
      '<td>' + x(r.pack_id) + '</td>' +
      '<td>' + pill(r.status, statusTone(r.status)) + '</td>' +
      '<td>' + x(stable) + '</td>' +
      '<td>' + x(String(r.runs || 0)) + '</td>' +
      '<td>' + x(r.requested_by) + '</td></tr>';
  }).join('');
  setHTML('seg-runs', card('Runs', '<div class="seg-table-wrap"><table class="seg-table"><thead><tr><th>Started</th><th>Pack</th><th>Status</th><th>Repeatability</th><th>Passes</th><th>Requested by</th></tr></thead><tbody>' + rows + '</tbody></table></div>'));
}

export function segSelect(id) {
  S.sel = id;
  renderRuns();
  loadDetail(id);
}

function loadDetail(id) {
  return apicall('/api/segmentation/runs/' + encodeURIComponent(id)).then(function(r) {
    if (!r || !r.run) {
      setHTML('seg-detail', card('Run', empty('warn', 'The run could not be loaded', errorText(r))));
      return false;
    }
    S.detail = r;
    renderDetail();
    scheduleRefresh();
    return true;
  }).catch(function(e) {
    setHTML('seg-detail', card('Run', empty('warn', 'The run could not be loaded', e && e.message ? e.message : 'request failed')));
    return false;
  });
}

function renderDetail() {
  if (!S.detail) {
    setHTML('seg-detail', card('Run detail', empty('shield', 'Select a run', 'Its per-probe verdicts and the firewall rules that decided them appear here.')));
    return;
  }
  var run = S.detail.run;
  var head = kv([
    ['Pack', run.pack_id],
    ['Status', run.status],
    ['Passes', String(run.runs || 0)],
    ['Repeatability', run.stable === null || run.stable === undefined ? 'not yet known' : (run.stable ? 'identical across passes' : 'verdicts changed between passes')],
    ['Requested by', run.requested_by],
    ['Failure', run.failure_reason || '—'],
  ]);
  var rows = (S.detail.probes || []).map(function(p) {
    var rules = (p.rule_ids && p.rule_ids.length) ? p.rule_ids.join(', ') : '—';
    return '<tr><td>' + x(String(p.run_index + 1)) + '</td>' +
      '<td>' + x(p.probe_id) + '</td>' +
      '<td>' + x(p.src + ' → ' + p.dst + ':' + p.dst_port + '/' + p.proto) + '</td>' +
      '<td>' + x(p.expect) + '</td>' +
      '<td>' + pill(p.verdict, VERDICT_TONE[p.verdict] || 'muted') + '</td>' +
      '<td>' + x(rules) + '</td>' +
      '<td>' + x(p.reason) + '</td></tr>';
  }).join('');
  var table = rows
    ? '<div class="seg-table-wrap"><table class="seg-table"><thead><tr><th>Pass</th><th>Probe</th><th>Route</th><th>Expect</th><th>Verdict</th><th>Rule</th><th>Reason</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
    : empty('clock', 'No verdicts yet', 'The run has not stored any probe results.');
  setHTML('seg-detail', card('Run ' + run.id.slice(0, 8), head + table));
}

// While a run is queued or running, refresh until it finishes.
function scheduleRefresh() {
  if (S.timer) { clearTimeout(S.timer); S.timer = null; }
  var active = S.runs.some(function(r) { return r.status === 'queued' || r.status === 'running'; });
  if (!active) return;
  S.timer = setTimeout(function() { S.timer = null; loadSegmentation(); }, 3000);
}

export function segRun(pack) {
  if (S.busy) return;
  S.busy = true;
  apicall('/api/segmentation/runs', { method: 'POST', body: JSON.stringify({ pack: pack }) }).then(function(r) {
    if (r && r.id) {
      showToast('Run started for ' + pack + '.', 'ok');
      S.sel = r.id;
      return loadSegmentation();
    }
    showToast(errorText(r), 'err');
    return false;
  }).catch(function(e) {
    showToast('Could not start the run: ' + (e && e.message ? e.message : 'request failed'), 'err');
  }).then(function() { S.busy = false; });
}
