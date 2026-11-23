import { apicall, apicallOk } from '../core/api.js';
import { openConfirmDiffModal } from './compliance.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast, fmtDate } from '../core/util.js';
import { pill, empty } from '../core/kit.js';
import { setDisplay } from '../core/inline-style.js';
import * as G from './gap-model.js';

// ── Detection gaps ───────────────────────────────────────────────────────────
// The panel under the verification queue: for the selected run, which techniques ran and were not detected (a
// reviewed verification found no alert), and the SigmaHQ rules and per-SIEM queries that could close each gap.
// The server (/api/scenarios/runs/{id}/detection-gaps) decides every status from evidence; this only shows it.

var S = { runId: '', backend: '', data: null, deps: { retest: null, deployments: [] }, seq: 0, keepOpen: [] };

function el(id) { return document.getElementById(id); }

// Called by the verification page whenever the selected run changes ('' clears the panel).
// openTechniqueIds lists the technique rows that are open in the panel as it is now.
function openTechniqueIds(box) {
  return Array.prototype.map.call(box.querySelectorAll('details.gap-t[open]'), function(n) { return n.getAttribute('data-tid'); });
}

export function gapLoad(runId) {
  var again = !!runId && runId === S.runId; // the same run reloaded (after Mark deployed, a re-test or a SIEM change), not a different run
  S.runId = runId || '';
  S.data = null;
  S.deps = { retest: null, deployments: [] };
  var box = el('gap-panel');
  if (!box) return;
  if (!S.runId) { box.innerHTML = ''; setDisplay(box, 'none'); S.keepOpen = []; return; }
  // The panel is replaced by a loading placeholder below, so what the person had open must be remembered first. While a load is
  // already in flight there are no rows on the page, so what was remembered then is kept.
  if (!again) S.keepOpen = [];
  else if (box.querySelector('details.gap-t')) S.keepOpen = openTechniqueIds(box);
  setDisplay(box, '');
  box.innerHTML = '<section class="rk-card">' + empty('refresh', 'Loading detection gaps…') + '</section>';
  var seq = ++S.seq; // a slow answer for an earlier run must not overwrite the current one
  // Deployments are secondary: if they cannot be loaded the gaps still show, without the tracking.
  var depsReq = apicallOk(G.deploymentsUrl(S.runId)).catch(function() { return null; });
  Promise.all([apicallOk(G.gapsUrl(S.runId, S.backend)), depsReq]).then(function(res) {
    var d = res[0], deps = res[1];
    if (seq !== S.seq) return;
    if (d && d.error) { box.innerHTML = '<section class="rk-card">' + empty('alert', 'Could not load detection gaps', d.error) + '</section>'; return; }
    S.data = d;
    S.deps = deps && !deps.error ? { retest: deps.retest || null, deployments: deps.deployments || [] } : { retest: null, deployments: [] };
    render();
  }).catch(function(e) {
    if (seq !== S.seq) return;
    box.innerHTML = '<section class="rk-card">' + empty('alert', 'Could not load detection gaps', e.message || 'unknown error') + '<div class="dc-retry"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'gapReload') + '>Try again</button></div></section>';
  });
}
export function gapReload() { if (S.runId) gapLoad(S.runId); }

function backendSelect() {
  var opts = '<option value="">All SIEMs</option>' + G.BACKENDS.map(function(b) {
    return '<option value="' + x(b) + '"' + (b === S.backend ? ' selected' : '') + '>' + x(G.backendLabel(b)) + '</option>';
  }).join('');
  return '<select id="gap-backend" aria-label="SIEM"' + on('change', 'gapSetBackend') + '>' + opts + '</select>';
}

function ruleRow(r, techniqueId) {
  var deploy = (r.backends || []).map(function(b) {
    return '<button type="button" class="btn btn-sm btn-outline" title="Record that you deployed this rule to ' + x(G.backendLabel(b.backend)) + '. This does not prove it detects anything; re-test to find out."' +
      on('click', 'gapDeploy', techniqueId, r.id, b.backend) + '>Mark deployed · ' + x(G.backendLabel(b.backend)) + '</button>';
  }).join(' ');
  var buttons = (r.backends || []).map(function(b) {
    return '<button type="button" class="btn btn-sm btn-outline" title="' + x(G.backendNote(b)) + '"' +
      on('click', 'gapCopy', b.exportUrl) + '>Copy ' + x(b.language) + ' · ' + x(G.backendLabel(b.backend)) + '</button>' +
      (b.dslExportUrl ? ' <button type="button" class="btn btn-sm btn-outline" title="Elasticsearch Query DSL: matches case-insensitively, as Sigma does. The Lucene query is case-sensitive on keyword fields."' +
        on('click', 'gapCopy', b.dslExportUrl) + '>Copy DSL · ' + x(G.backendLabel(b.backend)) + ' (case-insensitive)</button>' : '');
  }).join(' ');
  var notes = (r.backends || []).filter(function(b, i, a) { return a.findIndex(function(o) { return G.backendNote(o) === G.backendNote(b); }) === i; })
    .map(function(b) { return '<div class="tiny muted">' + x(G.backendLabel(b.backend)) + ': ' + x(G.backendNote(b)) + '</div>'; }).join('');
  var lic = r.source && r.source.license ? ' · ' + x(r.source.name) + ' ' + x(r.source.license) : '';
  return '<tr><td><b>' + x(r.title) + '</b><div class="tiny muted">' + x(r.id) + ' · ' + x(r.sigmaId) + lic +
    (G.matchNote(r.match) ? '<br>' + x(G.matchNote(r.match)) : '') + '</div></td>' +
    '<td>' + pill(r.severity || 'n/a', G.severityTone(r.severity)) + '</td>' +
    '<td class="gap-copy">' + (buttons || '<span class="muted">No translation for this SIEM</span>') + notes +
    (deploy ? '<div class="gap-deploy">' + deploy + '</div>' : '') + '</td></tr>';
}

function deploymentRow(d) {
  var retest = G.canRetest(d.status)
    ? ' <button type="button" class="btn btn-sm btn-primary"' + on('click', 'gapRetest', d.id) + '>Re-test</button>' : '';
  var link = d.retestRunId ? ' <span class="tiny muted">re-test run ' + x(String(d.retestRunId).slice(0, 8)) + '</span>' : '';
  return '<div class="gap-dep"><div>' + pill(d.status, G.deploymentTone(d.status)) + ' <b>' + x(d.ruleTitle || d.ruleId) + '</b> · ' +
    x(d.backendLabel || d.backend) + ' <span class="tiny muted">' + x(d.ruleId) + ' · ' + x(d.deployedAt ? fmtDate(d.deployedAt) : '') + (d.deployedBy ? ' · ' + x(d.deployedBy) : '') + '</span>' +
    retest + link + '</div><div class="tiny muted">' + x(d.detail || '') + (d.note ? ' Note: ' + x(d.note) : '') + '</div></div>';
}

// Each technique is one collapsed row showing only its title and status. The reason, rules and copy buttons open on
// click, so a run with many gaps reads as a short list instead of a long scroll of queries.
function techniqueBlock(t) {
  var head = '<summary class="gap-t-head"><span class="gap-chev" aria-hidden="true"></span><b>' + x(t.techniqueId) + '</b> ' + x(t.name || '') + ' ' +
    pill(t.status, G.statusTone(t.status)) + ' ' + pill(t.ruleAvailability, G.availabilityTone(t.ruleAvailability)) + ' ' +
    pill(t.effectiveness, 'muted') + '</summary><div class="tiny muted gap-reason">' + x(t.reason) + '</div>';
  if (!t.rules || !t.rules.length) {
    var why = t.ruleAvailability === 'No rule available'
      ? 'The rule library has no Sigma rule for this technique. Nothing is invented: this needs a rule written by your detection engineers.'
      : (t.ruleAvailability === 'Backend translation unavailable' ? 'Rules exist, but none translates to the selected SIEM.' : '');
    return '<details class="gap-t" data-tid="' + x(t.techniqueId) + '">' + head + (why ? '<div class="gap-none">' + x(why) + '</div>' : '') + '</details>';
  }
  var deps = G.deploymentsFor(S.deps.deployments, t.techniqueId);
  var depBlock = deps.length ? '<div class="gap-deps"><div class="tiny muted">Deployed rules</div>' + deps.map(deploymentRow).join('') + '</div>' : '';
  var more = t.ruleCount > t.rules.length ? '<div class="tiny muted">Showing ' + t.rules.length + ' of ' + t.ruleCount + ' rules, highest severity first. The export includes up to 25 per technique.</div>' : '';
  return '<details class="gap-t" data-tid="' + x(t.techniqueId) + '">' + head + '<div class="tbl-wrap"><table><thead><tr><th>Rule</th><th>Severity</th><th>Query</th></tr></thead><tbody>' +
    t.rules.map(function(r) { return ruleRow(r, t.techniqueId); }).join('') + '</tbody></table></div>' + more + depBlock + '</details>';
}

function render() {
  var box = el('gap-panel');
  var d = S.data;
  if (!box || !d) return;
  // Re-rendering (after Mark deployed, a re-test, or switching SIEM) must not fold away what the person had open.
  var openIds = box.querySelector('details.gap-t') ? openTechniqueIds(box) : S.keepOpen;
  S.keepOpen = [];
  var tiles = G.summaryTiles(d.summary).map(function(t) {
    return '<div class="gap-tile tone-' + x(t.tone) + '"><div class="gap-n">' + x(String(t.count)) + '</div><div class="gap-l">' + x(t.status) + '</div></div>';
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
  openIds.forEach(function(id) {
    Array.prototype.forEach.call(box.querySelectorAll('details.gap-t'), function(n) { if (n.getAttribute('data-tid') === id) n.open = true; });
  });
}

// Records that the customer deployed a recommended rule. It claims nothing about detection: the server answers
// "Deployed" until a re-test is linked and reviewed.
export function gapDeploy(techniqueId, ruleId, backend) {
  if (!S.runId) return;
  apicallOk(G.deploymentsUrl(S.runId), { method: 'POST', body: JSON.stringify({ techniqueId: techniqueId, ruleId: ruleId, backend: backend }) })
    .then(function() {
      showToast('Deployment recorded. Re-test to find out whether the gap is closed.', 'ok');
      gapLoad(S.runId);
    }).catch(function(e) { showToast('Could not record the deployment: ' + (e.message || 'error'), 'err'); });
}

// Starts the re-test through the normal run endpoint (same scenario, agent and mode as the run that found the gap,
// with the same confirmations a live run needs), then links the new run to the deployment.
export function gapRetest(deploymentId) {
  var plan = G.retestPlan(S.deps.retest);
  if (!plan || !S.runId) { showToast('This run cannot be re-tested from here.', 'err'); return; }
  var r = S.deps.retest || {};
  // One in-page confirmation that says what will run, then one more for each warning a live or lab run needs.
  var steps = ['This starts a new run of scenario ' + (r.scenarioId || '') + ' on agent ' + (r.agentId || '') + ' in ' + (plan.body.mode || 'posture') + ' mode, to find out whether the deployed rule closes the gap.'].concat(plan.confirms);
  var ask = function(i) {
    if (i >= steps.length) { startRetest(deploymentId, plan); return; }
    var last = i === steps.length - 1;
    openConfirmDiffModal(i === 0 ? 'Start the re-test?' : 'Confirm before continuing',
      '<p class="tiny">' + x(steps[i]).replace(/[\r\n]+/g, '</p><p class="tiny">') + '</p>',
      function() { ask(i + 1); },
      { sub: steps.length > 1 ? 'Step ' + (i + 1) + ' of ' + steps.length : 'It runs on the agent now.', confirmLabel: last ? 'Start re-test' : 'Continue' });
  };
  ask(0);
}

function startRetest(deploymentId, plan) {
  var runId = S.runId;
  apicallOk('/api/scenarios/' + encodeURIComponent(plan.scenarioId) + '/run', { method: 'POST', body: JSON.stringify(plan.body) })
    .then(function(started) {
      if (!started || !started.runId) throw new Error('The re-test run did not start');
      return apicallOk(G.retestLinkUrl(runId, deploymentId), { method: 'POST', body: JSON.stringify({ retestRunId: started.runId }) });
    }).then(function() {
      showToast('Re-test started. Review its verifications to find out whether the gap is closed.', 'ok');
      gapLoad(runId);
    }).catch(function(e) { showToast('Re-test did not start: ' + (e.message || 'error'), 'err'); });
}

export function gapSetBackend(elm) {
  S.backend = String((elm && elm.value) || '');
  if (S.runId) gapLoad(S.runId);
}

function legacyCopy(text) {
  return new Promise(function(resolve, reject) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy') ? resolve() : reject(new Error('copy blocked')); } catch (e) { reject(e); } finally { document.body.removeChild(ta); }
  });
}
// The clipboard API needs a secure page and the browser's permission; when it refuses, the older route still works.
function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text).catch(function() { return legacyCopy(text); });
  return legacyCopy(text);
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
  }).catch(function(e) { showToast('Could not copy the query: ' + (e.message || 'error') + '. Select it and copy by hand.', 'err'); });
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
