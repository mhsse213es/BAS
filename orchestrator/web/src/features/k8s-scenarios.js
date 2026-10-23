import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { showToast } from '../core/util.js';

// ── Kubernetes state-changing scenarios ──────────────────────────────────────
// Plan -> approve -> execute. The server enforces every rule (cluster and namespace allow-list, self-approval,
// requester-only execution, single-use approvals). The buttons here only offer the valid next step.
// Only the kind lab is allowed until the design is approved for production.

var K8S_ACTIONS = {
  'pod-create-unprivileged': { label: 'Create unprivileged pod (sandbox)', params: ['name'] },
  'configmap-patch-labelled': { label: 'Patch labelled ConfigMap (sandbox)', params: ['name', 'value'] }
};

var K8S_STATE_LABELS = {
  PLANNED: 'Awaiting approval',
  APPROVED: 'Approved, ready to run',
  CLEANED: 'Ran, verified, cleaned up',
  CLEANUP_FAILED: 'Cleanup FAILED: check the cluster',
  FAILED: 'Failed',
  REFUSED: 'Refused',
  DRY_RUN_PLANNED: 'Planned (dry run)'
};

export function loadK8sRuns() {
  var host = document.getElementById('k8s-runs');
  if (!host) return;
  apicall('/api/k8s-scenarios/runs').then(function(body) {
    if (!Array.isArray(body)) throw new Error(body && body.error ? body.error : 'unexpected response');
    renderK8sRuns(body);
  }).catch(function(err) {
    host.innerHTML = '<p class="muted">Kubernetes scenarios are unavailable: ' + x(err.message || 'request failed') + '</p>';
  });
}

export function renderK8sRuns(runs) {
  var host = document.getElementById('k8s-runs');
  if (!host) return;
  if (!runs.length) {
    host.innerHTML = '<p class="muted">No runs yet. Plan one above; nothing is written to a cluster until it is approved and executed.</p>';
    return;
  }
  var rows = runs.map(function(r) {
    var target = x(r.cluster) + ' / ' + x(r.namespace);
    var btn = '';
    if (r.state === 'PLANNED') {
      btn = '<button class="btn" data-k8s-approve="' + x(r.id) + '">Approve (writes to ' + target + ')</button>';
    } else if (r.state === 'APPROVED') {
      btn = '<button class="btn primary" data-k8s-execute="' + x(r.id) + '">Execute on ' + target + '</button>';
    }
    return '<tr>' +
      '<td><code>' + x(r.id) + '</code></td>' +
      '<td>' + x(K8S_ACTIONS[r.action] ? K8S_ACTIONS[r.action].label : r.action) + '</td>' +
      '<td>' + target + '</td>' +
      '<td>' + x(r.requester) + '</td>' +
      '<td>' + x(K8S_STATE_LABELS[r.state] || r.state) + '</td>' +
      '<td><pre class="k8s-detail">' + x(r.detail || '') + '</pre></td>' +
      '<td>' + btn + '</td>' +
      '</tr>';
  }).join('');
  host.innerHTML = '<table class="tbl"><thead><tr><th>Run</th><th>Action</th><th>Target</th><th>Requested by</th>' +
    '<th>State</th><th>Plan / detail</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>';
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

// Event delegation for the Approve and Execute buttons rendered into the run table.
document.addEventListener('click', function(e) {
  var t = e.target;
  if (!t || !t.getAttribute) return;
  if (t.getAttribute('data-k8s-plan')) { planK8sRun(); return; }
  var approveId = t.getAttribute('data-k8s-approve');
  if (approveId) { postRunAction(approveId, 'approve', 'Approved. Another operator must now execute it.'); return; }
  var executeId = t.getAttribute('data-k8s-execute');
  if (executeId) { postRunAction(executeId, 'execute', 'Execution finished. See the run state.'); }
});

