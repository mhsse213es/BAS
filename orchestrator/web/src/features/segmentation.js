// Segmentation lab: the packs the lab can run, a Run control for admins, the run history, and each run's per-probe
// verdicts exactly as the server stored them. Everything from the server is escaped on the way into markup. The page
// never decides a verdict; it shows the one it was given.
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { card, pill, empty, icon } from '../core/kit.js';

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
  if (!S.packs.length) {
    setHTML('seg-packs', card('Packs', empty('shield', 'No packs available', 'The lab reports no packs to run yet.')));
    return;
  }
  var cards = S.packs.map(function(p) {
    var mine = S.runs.filter(function(r) { return r.pack_id === p.id; });
    var last = mine.reduce(function(a, r) { return !a || String(r.created_at) > a ? String(r.created_at) : a; }, '');
    var meta = mine.length + (mine.length === 1 ? ' run' : ' runs') + (last ? ' · last ' + x(fmtDate(last)) : ' · never run');
    var run = S.canRun ? '<button type="button" class="btn btn-primary seg-run-btn"' + on('click', 'segRun', p.id) + '>' + icon('play') + 'Run pack</button>' : '';
    return '<div class="seg-pack"><div class="seg-pack-top"><span class="seg-pack-ico">' + icon('shield') + '</span>' +
      '<div><b>' + x(p.name) + '</b><span class="seg-pack-meta">' + meta + '</span></div></div>' +
      '<p>' + x(p.description) + '</p><div class="seg-pack-run">' + run + '</div></div>';
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
    var stable = r.stable === null || r.stable === undefined ? pill('not yet known', 'muted') : (r.stable ? pill('stable', 'ok') : pill('unstable', 'warn'));
    return '<tr class="seg-row' + (r.id === S.sel ? ' is-sel' : '') + '"' + on('click', 'segSelect', r.id) + '>' +
      '<td class="seg-cell-date">' + x(fmtDate(r.created_at)) + '</td>' +
      '<td><span class="seg-chip">' + x(r.pack_id) + '</span></td>' +
      '<td>' + pill(r.status, statusTone(r.status)) + '</td>' +
      '<td>' + stable + '</td>' +
      '<td class="seg-num">' + x(String(r.runs || 0)) + '</td>' +
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

var VERDICT_ORDER = ['PASS', 'FAIL', 'UNKNOWN', 'ERROR'];

function renderDetail() {
  if (!S.detail) {
    setHTML('seg-detail', card('Run detail', empty('shield', 'Select a run', 'Its per-probe verdicts and the firewall rules that decided them appear here.')));
    return;
  }
  var run = S.detail.run;
  var probes = S.detail.probes || [];
  var counts = { PASS: 0, FAIL: 0, UNKNOWN: 0, ERROR: 0 };
  probes.forEach(function(p) { if (counts[p.verdict] !== undefined) counts[p.verdict]++; });
  var total = probes.length;
  var stats = VERDICT_ORDER.map(function(v) {
    return '<div class="seg-stat tone-' + VERDICT_TONE[v] + '"><span>' + v + '</span><b>' + counts[v] + '</b></div>';
  }).join('');
  var bar = total ? VERDICT_ORDER.map(function(v) {
    var w = Math.round(counts[v] * 1000 / total) / 10;
    return w ? '<span class="seg-bar-seg seg-bar-' + VERDICT_TONE[v] + '" style="width:' + w + '%" title="' + v + ': ' + counts[v] + '"></span>' : '';
  }).join('') : '';
  var repeat = run.stable === null || run.stable === undefined ? pill('not yet known', 'muted') : (run.stable ? pill('identical across passes', 'ok') : pill('verdicts changed between passes', 'warn'));
  var facts = '<div class="seg-facts">' +
    '<div><span>Pack</span><b>' + x(run.pack_id) + '</b></div>' +
    '<div><span>Status</span><b>' + pill(run.status, statusTone(run.status)) + '</b></div>' +
    '<div><span>Passes</span><b>' + x(String(run.runs || 0)) + '</b></div>' +
    '<div><span>Repeatability</span><b>' + repeat + '</b></div>' +
    '<div><span>Requested by</span><b>' + x(run.requested_by) + '</b></div>' +
    '<div><span>Failure</span><b>' + (run.failure_reason ? x(run.failure_reason) : '—') + '</b></div>' +
    '</div>';
  var head = '<div class="seg-summary"><div class="seg-stats">' + stats + '</div>' +
    (total ? '<p class="seg-caption">' + total + ' probe ' + (total === 1 ? 'result' : 'results') + ' across ' + (run.runs || 0) + ' ' + ((run.runs || 0) === 1 ? 'pass' : 'passes') + '</p><div class="seg-bar" role="img" aria-label="Verdict mix">' + bar + '</div>' : '') + '</div>' + facts;
  var rows = (S.detail.probes || []).map(function(p) {
    var rules = (p.rule_ids && p.rule_ids.length) ? p.rule_ids.map(function(r) { return '<span class="seg-rule">' + x(r) + '</span>'; }).join('') : '<span class="seg-none">none matched</span>';
    var expect = String(p.expect || '').toLowerCase() === 'allow' ? 'seg-expect-allow' : 'seg-expect-deny';
    return '<tr><td class="seg-num">' + x(String(p.run_index + 1)) + '</td>' +
      '<td><strong>' + x(p.probe_id) + '</strong></td>' +
      '<td><code class="seg-route">' + x(p.src + ' → ' + p.dst + ':' + p.dst_port + '/' + p.proto) + '</code></td>' +
      '<td><span class="seg-expect ' + expect + '">' + x(p.expect) + '</span></td>' +
      '<td>' + pill(p.verdict, VERDICT_TONE[p.verdict] || 'muted') + '</td>' +
      '<td>' + rules + '</td>' +
      '<td class="seg-reason">' + x(p.reason) + '</td></tr>';
  }).join('');
  var table = rows
    ? '<div class="seg-table-wrap"><table class="seg-table"><thead><tr><th>Pass</th><th>Probe</th><th>Route</th><th>Expect</th><th>Verdict</th><th>Rule</th><th>Reason</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
    : empty('clock', 'No verdicts yet', 'The run has not stored any probe results.');
  setHTML('seg-detail', card('Run ' + run.id.slice(0, 8) + ' · ' + run.pack_id, head + table));
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
