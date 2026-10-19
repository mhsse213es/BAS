import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { ROLE } from './shell.js';

// Installation-wide default for the in-process host language-mode policy.
// Runs dispatched after a change use the new value. Each run keeps the value it
// was dispatched with, so a change never rewrites a finished run's verdict.
// An empty value means not stated, and the in-process verdict stays UNVERIFIED.
var EP_OPTIONS = [
  { value: '', label: 'Not stated (in-process verdict stays UNVERIFIED)' },
  { value: 'restricted', label: 'Restricted: custom hosts must run ConstrainedLanguage' },
  { value: 'unrestricted', label: 'Unrestricted: FullLanguage is permitted' }
];

function epLabel(value) {
  for (var i = 0; i < EP_OPTIONS.length; i++) {
    if (EP_OPTIONS[i].value === value) return EP_OPTIONS[i].label;
  }
  return value;
}

export function loadExecutionPolicyDefault() {
  var panel = document.getElementById('execution-policy-panel');
  if (!panel || ROLE !== 'admin') { if (panel) panel.innerHTML = ''; return; }
  apicall('/api/execution-policy/default').then(function(res) {
    if (res.error) throw new Error(res.error);
    renderExecutionPolicy(panel, res.inProcessPolicy || '');
  }).catch(function(e) {
    showToast('Failed to load execution policy: ' + (e.message || 'error'), 'err');
  });
}

function renderExecutionPolicy(panel, current) {
  var options = EP_OPTIONS.map(function(o) {
    return '<option value="' + x(o.value) + '"' + (o.value === current ? ' selected' : '') + '>' + x(o.label) + '</option>';
  }).join('');
  panel.innerHTML =
    '<div class="kpi-row">' +
      '<select id="execution-policy-select" class="inp-sm u-flex1" aria-label="Installation execution policy">' + options + '</select>' +
      '<button class="btn btn-primary btn-sm"' + on('click', 'saveExecutionPolicyDefault') + '>Save</button>' +
    '</div>' +
    '<div class="tiny muted">Applies to runs dispatched after this change. A run keeps the policy it was dispatched with, so changing this never rewrites a finished run. Runs without an explicit policy inherit this value.</div>' +
    '<div id="execution-policy-result" class="tiny muted"></div>';
}

export function saveExecutionPolicyDefault() {
  var sel = document.getElementById('execution-policy-select');
  var resultEl = document.getElementById('execution-policy-result');
  if (!sel) return;
  var value = sel.value;
  apicall('/api/execution-policy/default', {
    method: 'PUT',
    body: JSON.stringify({ inProcessPolicy: value })
  }).then(function(res) {
    if (res.error) throw new Error(res.error);
    if (resultEl) resultEl.textContent = 'Saved: ' + epLabel(value);
    showToast('Execution policy saved', 'ok');
  }).catch(function(e) {
    if (resultEl) resultEl.textContent = 'Not saved: ' + (e.message || 'error');
    showToast('Execution policy not saved: ' + (e.message || 'error'), 'err');
  });
}
