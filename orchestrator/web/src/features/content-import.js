// Import detection content: Sigma and YARA rules become DRAFT scenarios, and reviewed steps can be chained. A draft cannot
// run anywhere until an Admin approves it. The server does all the generation; this panel only sends the text and shows
// what came back, so nothing here decides what is safe.
//
// Everything shown comes from user-supplied rules, so it is built with DOM nodes and textContent, never as HTML.
import { apicall } from '../core/api.js';
import { showToast } from '../core/util.js';
import { setDisplay } from '../core/inline-style.js';
import { loadScenarios } from './attack-path.js';
import { resultRows, parseChainLines, commandPreview, statusLabel } from './content-import-model.js';

var STATUS_TONE = { draft: 'info', 'already-waiting': 'warn', 'not-emulable': 'muted', error: 'bad' };
var STATUS_TEXT = { draft: 'Draft created', 'already-waiting': 'Already waiting', 'not-emulable': 'Cannot be reproduced', error: 'Error' };

function el(id) { return document.getElementById(id); }

function node(tag, cls, text) {
  var n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}

function chipNode(text, tone) { return node('span', 'rk-chip tone-' + tone, text); }

function showErr(msg) {
  var e = el('ci-err');
  e.textContent = msg || '';
  setDisplay(e, msg ? '' : 'none');
}

export function openContentImport() {
  el('ci-text').value = '';
  el('ci-results').replaceChildren();
  showErr('');
  ciKindChange();
  el('ci-overlay').classList.add('open');
  loadImportDrafts();
}
export function closeContentImport() { el('ci-overlay').classList.remove('open'); }
export function closeContentImportOnBackdrop(elm, event) { if (event.target === elm) closeContentImport(); }

// ciKindChange shows only the inputs the chosen kind needs.
export function ciKindChange() {
  var kind = el('ci-kind').value;
  setDisplay(el('ci-os-wrap'), kind === 'yara' ? '' : 'none');
  setDisplay(el('ci-name-wrap'), kind === 'chain' ? '' : 'none');
  setDisplay(el('ci-tech-wrap'), kind === 'chain' ? 'none' : '');
  el('ci-text').placeholder = kind === 'chain'
    ? 'One stage per line:  scenario-id | step number | always, prev_allowed or prev_blocked\nimp-sigma-certutil-download-1a2b3c4d | 1\nimp-yara-demo-5e6f7a8b | 1 | prev_allowed'
    : kind === 'yara' ? 'Paste one or more YARA rules' : 'Paste one or more Sigma rules (separate several with a line containing only ---)';
}

function fail(e) { showErr((e && e.message) || 'Request failed'); }

function unwrap(res) {
  if (res && res.error) throw new Error(res.error);
  return res;
}

export function submitContentImport() {
  var kind = el('ci-kind').value;
  var text = el('ci-text').value;
  showErr('');
  var path, body;
  if (kind === 'chain') {
    var parsed = parseChainLines(text);
    if (parsed.errors.length) { showErr(parsed.errors.join('\n')); return; }
    if (parsed.stages.length < 2) { showErr('A chain needs at least two stages.'); return; }
    var name = el('ci-name').value.trim();
    if (!name) { showErr('Give the chain a name.'); return; }
    path = '/api/content-import/chain';
    body = { name: name, stages: parsed.stages };
  } else {
    if (!text.trim()) { showErr('Paste at least one rule.'); return; }
    path = '/api/content-import/' + kind;
    body = { source: text, technique: el('ci-tech').value.trim() };
    if (kind === 'yara') body.os = el('ci-os').value;
  }
  var btn = el('ci-submit-btn');
  btn.disabled = true;
  apicall(path, { method: 'POST', body: JSON.stringify(body) })
    .then(unwrap)
    .then(function(res) {
      btn.disabled = false;
      renderResults(resultRows(res.results));
      loadImportDrafts();
    })
    .catch(function(e) { btn.disabled = false; fail(e); });
}

function renderResults(rows) {
  el('ci-results').replaceChildren.apply(el('ci-results'), rows.map(function(r) {
    var row = node('div', 'ci-row');
    row.appendChild(chipNode(STATUS_TEXT[r.status] || r.status, STATUS_TONE[r.status] || 'muted'));
    row.appendChild(document.createTextNode(' '));
    row.appendChild(node('strong', '', r.title));
    if (r.detail) row.appendChild(node('div', 'sub2', r.detail));
    return row;
  }));
}

export function loadImportDrafts() {
  apicall('/api/content-import/drafts?status=draft').then(unwrap).then(function(res) {
    var drafts = res.drafts || [];
    var box = el('ci-drafts');
    if (!drafts.length) { box.replaceChildren(node('div', 'empty', 'Nothing is waiting for review.')); return; }
    box.replaceChildren.apply(box, drafts.map(draftCard));
  }).catch(fail);
}

function actionButton(label, cls, action, id) {
  var b = node('button', 'btn btn-sm ' + cls, label);
  b.type = 'button';
  b.setAttribute('data-on-click', action);
  b.setAttribute('data-args', JSON.stringify([id]));
  return b;
}

function draftCard(d) {
  var cov = {};
  try { cov = typeof d.coverage === 'string' ? JSON.parse(d.coverage) : (d.coverage || {}); } catch (e) { cov = {}; }
  var p = commandPreview(d);
  var gaps = (cov.notEmulated || []).concat(cov.notes || []);
  var card = node('div', 'ci-draft');
  var head = node('div');
  head.appendChild(chipNode(String(d.kind || '').toUpperCase(), 'accent'));
  head.appendChild(document.createTextNode(' '));
  head.appendChild(chipNode(statusLabel(d.status), 'info'));
  head.appendChild(document.createTextNode(' '));
  head.appendChild(node('strong', '', d.title));
  card.appendChild(head);
  if (gaps.length) card.appendChild(node('div', 'sub2', 'Not reproduced: ' + gaps.join('; ')));
  card.appendChild(node('div', 'sub2', p.executor + ' step. Read it before approving:'));
  card.appendChild(node('pre', 'ci-cmd', p.text));
  var actions = node('div', 'ci-actions');
  actions.appendChild(actionButton('Approve', 'btn-primary', 'approveImportDraft', d.id));
  actions.appendChild(actionButton('Reject', 'btn-outline', 'rejectImportDraft', d.id));
  card.appendChild(actions);
  return card;
}

function review(id, action, doneMsg) {
  apicall('/api/content-import/drafts/' + encodeURIComponent(id) + '/' + action, { method: 'POST', body: JSON.stringify({}) })
    .then(unwrap)
    .then(function() {
      showToast(doneMsg, 'ok');
      loadImportDrafts();
      if (action === 'approve') loadScenarios();
    })
    .catch(function(e) { showToast((e && e.message) || 'Request failed', 'err'); });
}

export function approveImportDraft(id) { review(id, 'approve', 'Approved: the scenario is now available'); }
export function rejectImportDraft(id) { review(id, 'reject', 'Draft rejected'); }
