import { apicall } from '../core/api.js';
import { showToast } from '../core/util.js';

// Per-host, single-use enrollment tokens (audit F-03). Tokens are returned once by the server, so they live only in
// this module's memory and the results table until the operator clears them; nothing is stored in the browser.
var _tokens = [];

// parseEnrollHostnames splits a pasted list on lines and commas and drops blanks. Names are kept exactly as typed:
// the agent ID is derived from the hostname as the operating system reports it, so the spelling matters.
export function parseEnrollHostnames(text) {
  return String(text || '').split(/[\r\n,]+/).map(function(s) { return s.trim(); }).filter(function(s) { return s !== ''; });
}

function csvCell(v) {
  var s = String(v == null ? '' : v);
  // A cell that starts with = + - @ (or tab/CR) would be run as a formula by a spreadsheet.
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

export function enrollTokensToCsv(rows) {
  var lines = ['hostname,agentId,token,expiresAt'];
  rows.forEach(function(r) {
    lines.push([r.hostname, r.agentId, r.token, r.expiresAt].map(csvCell).join(','));
  });
  return lines.join('\n') + '\n';
}

function renderResults(duplicates) {
  var box = document.getElementById('enroll-tok-results');
  box.textContent = '';
  var warn = document.getElementById('enroll-tok-warning');
  if (!_tokens.length) { warn.textContent = ''; return; }
  warn.textContent = 'These tokens are shown once and cannot be retrieved later. Each is single use, works only for its own host and expires. ' +
    'Give each to the person installing that host; never put one in a shared script, image or installer package.';
  var table = document.createElement('table');
  var head = document.createElement('tr');
  ['Host', 'Agent ID', 'Token', ''].forEach(function(h) { var th = document.createElement('th'); th.textContent = h; head.appendChild(th); });
  table.appendChild(head);
  _tokens.forEach(function(t, i) {
    var tr = document.createElement('tr');
    [t.hostname, t.agentId, t.token].forEach(function(v) { var td = document.createElement('td'); td.textContent = v; tr.appendChild(td); });
    var td = document.createElement('td');
    var b = document.createElement('button');
    b.className = 'btn btn-sm btn-outline';
    b.textContent = 'Copy';
    b.setAttribute('data-on-click', 'copyEnrollmentToken');
    b.setAttribute('data-args', JSON.stringify([i]));
    td.appendChild(b);
    tr.appendChild(td);
    table.appendChild(tr);
  });
  // Collapsed by default so a large batch does not take over the page; Download CSV and Clear work either way.
  var details = document.createElement('details');
  var summary = document.createElement('summary');
  summary.textContent = _tokens.length + (_tokens.length === 1 ? ' token' : ' tokens') + ' generated (click to show)';
  details.appendChild(summary);
  details.appendChild(table);
  box.appendChild(details);
  if (duplicates && duplicates.length) {
    var d = document.createElement('div');
    d.textContent = 'Listed more than once, one token issued: ' + duplicates.join(', ');
    box.appendChild(d);
  }
}

export function generateEnrollmentTokens() {
  var hostnames = parseEnrollHostnames(document.getElementById('enroll-tok-hosts').value);
  if (!hostnames.length) { showToast('Enter at least one hostname', 'err'); return; }
  var ttl = parseInt(document.getElementById('enroll-tok-ttl').value, 10);
  var body = { hostnames: hostnames, ttlHours: isNaN(ttl) ? 24 : ttl, note: document.getElementById('enroll-tok-note').value.trim() };
  var btn = document.getElementById('enroll-tok-generate');
  btn.disabled = true;
  apicall('/api/enrollment-tokens/bulk', { method: 'POST', body: JSON.stringify(body) }).then(function(resp) {
    if (!resp || !Array.isArray(resp.tokens)) { showToast((resp && resp.error) || 'Could not create tokens', 'err'); return; }
    _tokens = resp.tokens;
    renderResults(resp.duplicates);
    showToast(_tokens.length + ' token(s) created', 'ok');
  }).catch(function(e) { showToast('Could not create tokens: ' + (e.message || 'error'), 'err'); })
    .then(function() { btn.disabled = false; });
}

export function clearEnrollmentTokens() {
  _tokens = [];
  document.getElementById('enroll-tok-results').textContent = '';
  document.getElementById('enroll-tok-warning').textContent = '';
  document.getElementById('enroll-tok-hosts').value = '';
  document.getElementById('enroll-tok-note').value = '';
}

export function downloadEnrollmentTokensCsv() {
  if (!_tokens.length) { showToast('No tokens to download', 'err'); return; }
  var blob = new Blob([enrollTokensToCsv(_tokens)], { type: 'text/csv' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'enrollment-tokens.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 0);
}

export function copyEnrollmentToken(i) {
  var t = _tokens[i];
  if (!t) return;
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(t.token).then(function() { showToast('Token copied', 'ok'); }, function() { showToast('Copy failed', 'err'); });
  } else {
    showToast('Copy needs HTTPS; use Download CSV instead', 'err');
  }
}
