import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { pill, empty } from '../core/kit.js';
import { setDisplay } from '../core/inline-style.js';
import * as G from './gap-model.js';

// ── Detection gaps ───────────────────────────────────────────────────────────
// The panel under the verification queue: for the selected run, which techniques ran and were not detected (a
// reviewed verification found no alert), and the SigmaHQ rules and per-SIEM queries that could close each gap.
// The server (/api/scenarios/runs/{id}/detection-gaps) decides every status from evidence; this only shows it.

var S = { runId: '', backend: '', data: null, seq: 0 };

function el(id) { return document.getElementById(id); }

// Called by the verification page whenever the selected run changes ('' clears the panel).
export function gapLoad(runId) {
  S.runId = runId || '';
  S.data = null;
  var box = el('gap-panel');
  if (!box) return;
  if (!S.runId) { box.innerHTML = ''; setDisplay(box, 'none'); return; }
  setDisplay(box, '');
  box.innerHTML = '<section class="rk-card">' + empty('refresh', 'Loading detection gaps…') + '</section>';
  var seq = ++S.seq; // a slow answer for an earlier run must not overwrite the current one
  apicall(G.gapsUrl(S.runId, S.backend)).then(function(d) {
    if (seq !== S.seq) return;
    if (d && d.error) { box.innerHTML = '<section class="rk-card">' + empty('alert', 'Could not load detection gaps', d.error) + '</section>'; return; }
    S.data = d;
    render();
  }).catch(function(e) {
    if (seq !== S.seq) return;
    box.innerHTML = '<section class="rk-card">' + empty('alert', 'Could not load detection gaps', e.message) + '</section>';
  });
}

function backendSelect() {
  var opts = '<option value="">All SIEMs</option>' + G.BACKENDS.map(function(b) {
    return '<option value="' + x(b) + '"' + (b === S.backend ? ' selected' : '') + '>' + x(G.backendLabel(b)) + '</option>';
  }).join('');
  return '<select id="gap-backend" aria-label="SIEM"' + on('change', 'gapSetBackend') + '>' + opts + '</select>';
}

function ruleRow(r) {
  var buttons = (r.backends || []).map(function(b) {
    return '<button type="button" class="btn btn-sm btn-outline" title="' + x(G.backendNote(b)) + '"' +
      on('click', 'gapCopy', b.exportUrl) + '>Copy ' + x(b.language) + ' · ' + x(G.backendLabel(b.backend)) + '</button>';
  }).join(' ');
  var notes = (r.backends || []).filter(function(b, i, a) { return a.findIndex(function(o) { return G.backendNote(o) === G.backendNote(b); }) === i; })
    .map(function(b) { return '<div class="tiny muted">' + x(G.backendLabel(b.backend)) + ': ' + x(G.backendNote(b)) + '</div>'; }).join('');
  var lic = r.source && r.source.license ? ' · ' + x(r.source.name) + ' ' + x(r.source.license) : '';
  return '<tr><td><b>' + x(r.title) + '</b><div class="tiny muted">' + x(r.id) + ' · ' + x(r.sigmaId) + lic +
    (G.matchNote(r.match) ? '<br>' + x(G.matchNote(r.match)) : '') + '</div></td>' +
    '<td>' + pill(r.severity || 'n/a', G.severityTone(r.severity)) + '</td>' +
    '<td class="gap-copy">' + (buttons || '<span class="muted">No translation for this SIEM</span>') + notes + '</td></tr>';
}

function techniqueBlock(t) {
  var head = '<div class="gap-t-head"><b>' + x(t.techniqueId) + '</b> ' + x(t.name || '') + ' ' +
    pill(t.status, G.statusTone(t.status)) + ' ' + pill(t.ruleAvailability, G.availabilityTone(t.ruleAvailability)) + ' ' +
    pill(t.effectiveness, 'muted') + '</div><div class="tiny muted gap-reason">' + x(t.reason) + '</div>';
  if (!t.rules || !t.rules.length) {
    var why = t.ruleAvailability === 'No rule available'
      ? 'The rule library has no Sigma rule for this technique. Nothing is invented: this needs a rule written by your detection engineers.'
      : (t.ruleAvailability === 'Backend translation unavailable' ? 'Rules exist, but none translates to the selected SIEM.' : '');
    return '<div class="gap-t">' + head + (why ? '<div class="gap-none">' + x(why) + '</div>' : '') + '</div>';
  }
  var more = t.ruleCount > t.rules.length ? '<div class="tiny muted">Showing ' + t.rules.length + ' of ' + t.ruleCount + ' rules, highest severity first. Export for more.</div>' : '';
  return '<div class="gap-t">' + head + '<div class="tbl-wrap"><table><thead><tr><th>Rule</th><th>Severity</th><th>Query</th></tr></thead><tbody>' +
    t.rules.map(ruleRow).join('') + '</tbody></table></div>' + more + '</div>';
}

function render() {
  var box = el('gap-panel');
  var d = S.data;
  if (!box || !d) return;
  var tiles = G.summaryTiles(d.summary).map(function(t) {
    return '<div class="gap-tile tone-' + x(t.tone) + '"><div class="gap-n">' + t.count + '</div><div class="gap-l">' + x(t.status) + '</div></div>';
  }).join('');
  var gaps = (d.techniques || []).filter(function(t) { return t.status === 'Detection gap'; });
  var rest = (d.techniques || []).filter(function(t) { return t.status !== 'Detection gap'; });
  var lib = d.library && d.library.loaded
    ? 'Rules: SigmaHQ commit ' + x(String(d.library.sigmaCommit || '').slice(0, 10)) + ', licence ' + x(d.library.license || '') + ' (attribution retained in exports).'
    : 'The rule library is not loaded on this server.';
  var exportBtn = G.canExport(d.summary)
    ? '<button type="button" class="btn btn-sm btn-primary"' + on('click', 'gapExport') + '>Export gaps (.zip)</button>' : '';
  var restRows = rest.length
    ? '<details class="gap-rest"><summary>' + rest.length + ' other technique' + (rest.length === 1 ? '' : 's') + ' (not gaps)</summary><div class="tbl-wrap"><table><thead><tr><th>Technique</th><th>Status</th><th>Why</th></tr></thead><tbody>' +
      rest.map(function(t) {
        return '<tr><td><b>' + x(t.techniqueId) + '</b> ' + x(t.name || '') + '</td><td>' + pill(t.status, G.statusTone(t.status)) + '</td><td class="muted">' + x(t.reason) + '</td></tr>';
      }).join('') + '</tbody></table></div></details>' : '';
  box.innerHTML = '<section class="rk-card gap-card"><div class="rk-hd"><h2>Detection gaps</h2><div class="gap-actions">' + backendSelect() + ' ' + exportBtn + '</div></div>' +
    '<p class="dc-sub">' + x(G.HELP) + '</p><div class="gap-tiles">' + tiles + '</div>' +
    (gaps.length ? gaps.map(techniqueBlock).join('') : '<div class="gap-clear">' + empty('check', 'No detection gap in this run',
      'No technique ran and was confirmed undetected by a reviewed verification. Unverified techniques are listed below as Unknown.') + '</div>') +
    restRows + '<div class="tiny muted gap-lib">' + lib + '</div></section>';
}

export function gapSetBackend(elm) {
  S.backend = String((elm && elm.value) || '');
  if (S.runId) gapLoad(S.runId);
}

function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
  return new Promise(function(resolve, reject) {
    var ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy') ? resolve() : reject(new Error('copy blocked')); } catch (e) { reject(e); } finally { document.body.removeChild(ta); }
  });
}

// Fetches the query as text from the export endpoint (the server owns what a rule's query is) and copies it.
export function gapCopy(exportUrl) {
  if (!exportUrl) return;
  fetch(exportUrl, { credentials: 'same-origin' }).then(function(r) {
    if (!r.ok) throw new Error('Could not fetch the query (' + r.status + ')');
    var source = r.headers.get('X-Audspect-Data-Source');
    return r.text().then(function(t) { return { text: t, source: source }; });
  }).then(function(q) {
    return copyText(q.text).then(function() {
      showToast(q.source ? 'Query copied. It only matches if you collect: ' + q.source : 'Query copied. Generic query: adapt the field names to your schema.', 'ok');
    });
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function gapExport() {
  if (!S.runId) return;
  fetch(G.exportZipUrl(S.runId, S.backend), { credentials: 'same-origin' }).then(function(r) {
    if (!r.ok) return r.json().then(function(j) { throw new Error((j && j.error) || 'Export failed'); });
    return r.blob();
  }).then(function(blob) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'detection-gaps-' + S.runId + '.zip';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
    showToast('Exported. The bundle includes the licence notice.', 'ok');
  }).catch(function(e) { showToast(e.message, 'err'); });
}
