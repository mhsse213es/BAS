import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { showToast } from '../core/util.js';

// ── Kubernetes state-changing scenarios ──────────────────────────────────────
// Plan -> approve -> execute. The server enforces every rule (licence, cluster and namespace allow-list,
// self-approval, requester-only execution, single-use approvals). The controls here only offer the valid next
// step. Visibility is decided by the licence (Enterprise cloud product) in shell.js; the API refuses it too.

var K8S_ACTIONS = {
  'pod-create-unprivileged': { label: 'Create unprivileged pod', params: ['name'] },
  'configmap-patch-labelled': { label: 'Patch labelled ConfigMap', params: ['name', 'value'] },
  'sa-token-probe': { label: 'Mint and discard a probe token', params: [] }
};

// Each state maps to a dashboard badge modifier and a label.
var K8S_STATES = {
  PLANNED: { badge: 'v-warning', label: 'Awaiting approval' },
  APPROVED: { badge: 's-enrolling', label: 'Approved, ready to execute' },
  CLEANED: { badge: 's-active', label: 'Cleaned up and verified' },
  DISCARDED_NOT_REVOKED: { badge: 's-restricted', label: 'Token discarded, not revoked' },
  CLEANUP_FAILED: { badge: 's-quarantined', label: 'Cleanup failed: check the cluster' },
  FAILED: { badge: 'v-failure', label: 'Failed' },
  REFUSED: { badge: 'v-failure', label: 'Refused' },
  DRY_RUN_PLANNED: { badge: 'v-muted', label: 'Planned (dry run)' }
};

function stateBadge(state) {
  var s = K8S_STATES[state] || { badge: 'v-muted', label: state };
  return '<span class="sbadge ' + s.badge + '">' + x(s.label) + '</span>';
}

// The signed-in user, from the values stored at login. Used only to decide which controls to show; the
// server enforces every rule again on each request.
function currentUser() {
  var role = '', userId = '';
  try {
    role = localStorage.getItem('bas_role') || '';
    userId = localStorage.getItem('bas_user_id') || '';
  } catch (e) {}
  return { role: role, userId: userId };
}

// Shows only the control the signed-in user can use for this run. Approval belongs to an admin who did not
// plan the run; execution belongs to the person who planned it, if their role may execute.
function runActions(r) {
  var me = currentUser();
  var mine = r.requester === me.userId;
  if (r.state === 'PLANNED') {
    if (me.role === 'admin' && !mine) {
      return '<button class="btn btn-outline btn-sm" data-k8s-approve="' + x(r.id) + '">Approve</button>';
    }
    return mine
      ? '<span class="tiny muted">Waiting for a different admin to approve</span>'
      : '<span class="tiny muted">Awaiting approval by an admin</span>';
  }
  if (r.state === 'APPROVED') {
    if (mine && (me.role === 'admin' || me.role === 'analyst')) {
      return '<button class="btn btn-primary btn-sm" data-k8s-execute="' + x(r.id) + '">Execute</button>';
    }
    return '<span class="tiny muted">Only the requester can execute</span>';
  }
  return '';
}

function setCount(n) {
  var c = document.getElementById('k8s-cnt');
  if (c) c.textContent = String(n);
}

function setHost(html) {
  var host = document.getElementById('k8s-runs');
  if (host) host.innerHTML = html;
}

// Shows only the fields the chosen action uses.
function syncActionFields() {
  var action = (document.getElementById('k8s-action') || {}).value || '';
  var spec = K8S_ACTIONS[action];
  var used = spec ? spec.params : [];
  ['name', 'value'].forEach(function(p) {
    var field = document.getElementById('k8s-field-' + p);
    if (field) field.classList.toggle('is-hidden', used.indexOf(p) === -1);
  });
}

export function loadK8sRuns() {
  syncActionFields();
  setHost('<div class="empty">Loading…</div>');
  apicall('/api/k8s-scenarios/runs').then(function(body) {
    if (!Array.isArray(body)) throw new Error(body && body.error ? body.error : 'unexpected response');
    renderK8sRuns(body);
  }).catch(function(err) {
    setCount(0);
    setHost('<div class="empty">Kubernetes scenarios are unavailable: ' + x(err.message || 'request failed') + '</div>');
  });
}

export function renderK8sRuns(runs) {
  setCount(runs.length);
  if (!runs.length) {
    setHost('<div class="empty">No runs yet. Plan one above. Nothing is written to a cluster until it is approved and executed.</div>');
    return;
  }
  var rows = runs.map(function(r) {
    var target = x(r.cluster) + ' / ' + x(r.namespace);
    var btn = runActions(r);
    var action = K8S_ACTIONS[r.action] ? K8S_ACTIONS[r.action].label : r.action;
    var plan = (r.detail || '').split('\n').filter(Boolean).map(x).join('<br>');
    return '<tr>' +
      '<td><code>' + x(r.id) + '</code></td>' +
      '<td>' + x(action) + '</td>' +
      '<td class="k8s-target">' + target + '</td>' +
      '<td>' + x(r.requester) + '</td>' +
      '<td>' + stateBadge(r.state) + '</td>' +
      '<td class="k8s-plan">' + plan + '</td>' +
      '<td class="k8s-row-actions">' + btn + '</td>' +
      '</tr>';
  }).join('');
  setHost('<table><thead><tr>' +
    '<th>Run</th><th>Action</th><th>Target</th><th>Requested by</th><th>State</th><th>Plan and outcome</th><th></th>' +
    '</tr></thead><tbody>' + rows + '</tbody></table>');
}

export function planK8sRun() {
  var action = (document.getElementById('k8s-action') || {}).value || '';
  var cluster = ((document.getElementById('k8s-cluster') || {}).value || '').trim();
  var namespace = ((document.getElementById('k8s-namespace') || {}).value || '').trim();
  var spec = K8S_ACTIONS[action];
  if (!spec) { showToast('Choose an action', 'error'); return; }
  var params = {};
  for (var i = 0; i < spec.params.length; i++) {
    var p = spec.params[i];
    var v = ((document.getElementById('k8s-param-' + p) || {}).value || '').trim();
    if (!v) { showToast('Enter ' + p, 'error'); return; }
    params[p] = v;
  }
  apicall('/api/k8s-scenarios/runs', {
    method: 'POST',
    body: JSON.stringify({ cluster: cluster, namespace: namespace, action: action, params: params })
  }).then(function(body) {
    if (body.error) throw new Error(body.error);
    showToast('Planned. Nothing has been written to the cluster.', 'success');
    loadK8sRuns();
  }).catch(function(err) {
    showToast(err.message || 'Plan refused', 'error');
  });
}

function postRunAction(runId, verb, message) {
  apicall('/api/k8s-scenarios/runs/' + encodeURIComponent(runId) + '/' + verb, { method: 'POST' }).then(function(body) {
    if (body.error) throw new Error(body.error);
    showToast(message, 'success');
    loadK8sRuns();
  }).catch(function(err) {
    showToast(err.message || verb + ' refused', 'error');
    loadK8sRuns();
  });
}

// Delegated handlers: the plan and refresh buttons, approve and execute in the run table.
document.addEventListener('click', function(e) {
  var t = e.target;
  if (!t || !t.getAttribute) return;
  if (t.getAttribute('data-k8s-plan')) { planK8sRun(); return; }
  if (t.getAttribute('data-k8s-refresh')) { loadK8sRuns(); return; }
  var approveId = t.getAttribute('data-k8s-approve');
  if (approveId) { postRunAction(approveId, 'approve', 'Approved. Another operator must now execute it.'); return; }
  var executeId = t.getAttribute('data-k8s-execute');
  if (executeId) { postRunAction(executeId, 'execute', 'Execution finished. See the run state.'); }
});

document.addEventListener('change', function(e) {
  if (e.target && e.target.id === 'k8s-action') syncActionFields();
});
