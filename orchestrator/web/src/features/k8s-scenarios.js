import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { showToast } from '../core/util.js';
import { kpi as kitKpi, grid, card, hbars, pill } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';

// ── Kubernetes state-changing scenarios ──────────────────────────────────────
// Plan -> approve -> execute. The server enforces every rule (licence, cluster and namespace allow-list,
// self-approval, requester-only execution, single-use approvals). The controls here only offer the valid next
// step. Visibility is decided by the licence (Enterprise cloud product) in shell.js; the API refuses it too.

var K8S_ACTIONS = {
  'pod-create-unprivileged': { label: 'Create unprivileged pod', params: ['name'] },
  'configmap-patch-labelled': { label: 'Patch labelled ConfigMap', params: ['name', 'value'] },
  'sa-token-probe': { label: 'Mint and discard a probe token', params: [] },
  'synthetic-secret-read': { label: 'Read synthetic secret as probe', params: [] }
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

var K8S_TONE = { PLANNED: 'warn', APPROVED: 'info', CLEANED: 'ok', DISCARDED_NOT_REVOKED: 'warn', CLEANUP_FAILED: 'bad', FAILED: 'bad', REFUSED: 'bad', DRY_RUN_PLANNED: 'muted' };

function stateBadge(state) {
  var s = K8S_STATES[state] || { label: state };
  return pill(s.label, K8S_TONE[state] || 'muted');
}

// k8sRunCounts: runs per outcome group for the summary strip.
export function k8sRunCounts(runs) {
  var c = { total: 0, pending: 0, ready: 0, clean: 0, problem: 0 };
  (runs || []).forEach(function(r) {
    c.total++;
    if (r.state === 'PLANNED' || r.state === 'DRY_RUN_PLANNED') c.pending++;
    else if (r.state === 'APPROVED') c.ready++;
    else if (r.state === 'CLEANED') c.clean++;
    else c.problem++;
  });
  return c;
}

function renderK8sSummary(runs) {
  var el = document.getElementById('k8s-summary');
  if (!el) return;
  if (!runs.length) { el.innerHTML = ''; return; }
  var c = k8sRunCounts(runs);
  var segs = [
    { label: 'Awaiting approval', value: c.pending, color: CHART_COLORS.warn },
    { label: 'Ready to execute', value: c.ready, color: CHART_COLORS.info },
    { label: 'Cleaned up', value: c.clean, color: CHART_COLORS.ok },
    { label: 'Failed or needs attention', value: c.problem, color: CHART_COLORS.bad },
  ].filter(function(g) { return g.value > 0; });
  el.innerHTML = grid(4, [
    kitKpi({ label: 'Runs', value: c.total, icon: 'play', tone: 'accent' }),
    kitKpi({ label: 'Awaiting approval', value: c.pending, icon: 'clock', tone: 'warn' }),
    kitKpi({ label: 'Ready to execute', value: c.ready, icon: 'bolt', tone: 'info' }),
    kitKpi({ label: 'Failed or needs attention', value: c.problem, icon: 'warn', tone: c.problem ? 'bad' : 'muted' }),
  ]) + card('Runs by state', chartSlot({ type: 'donut', segments: segs, center: String(c.total), centerSub: 'runs', legend: true, h: 140 }));
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
  renderK8sSummary(runs);
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

// ── Read-only analysis ───────────────────────────────────────────────────────
// Runs the server's discovery-and-analysis report. Every value is configured state; nothing here writes to the cluster.
// The server serialises nested fields under their Go names (for example Role, Subject), so this code uses those names.

var k8sAnalysisLast = null;

// shortId turns a canonical ID into "namespace/name" (or "kind/name" for cluster-scoped objects) for display.
function shortId(id) {
  var p = String(id || '').replace(/^k8s:\/\/[^/]+\//, '').split('/');
  if (p.length < 3) return String(id || '');
  return p[0] === '_cluster' ? p[1] + '/' + p[2] : p[0] + '/' + p[2];
}

// isBuiltIn marks objects that belong to the Kubernetes platform itself (system:* roles and identities).
function isBuiltIn(v) {
  return JSON.stringify(v || {}).indexOf('/system:') !== -1;
}

function idCell(id) {
  return '<span title="' + x(id) + '">' + x(shortId(id)) + '</span>';
}

function listOrNone(items, render) {
  if (!items.length) return '<div class="empty">None.</div>';
  return '<div class="tbl-wrap"><table><thead><tr>' + render.head + '</tr></thead><tbody>' +
    items.map(render.row).join('') + '</tbody></table></div>';
}

function section(title, count, html) {
  return '<h3 class="k8s-an-h">' + x(title) + ' <span class="cnt">' + count + '</span></h3>' + html;
}

function renderK8sAnalysis() {
  var a = k8sAnalysisLast;
  var body = document.getElementById('k8s-an-body');
  var kpis = document.getElementById('k8s-an-kpis');
  var meta = document.getElementById('k8s-an-meta');
  if (!a || !body) return;
  var showSystem = !!(document.getElementById('k8s-an-system') || {}).checked;
  var hidden = 0;
  function keep(list) {
    return list.filter(function(v) {
      if (showSystem || !isBuiltIn(v)) return true;
      hidden++;
      return false;
    });
  }
  var wild = keep(a.wildcards || []);
  var breadth = keep((a.breadth || []).filter(function(b) { return b.Broad; }));
  var cross = keep(a.crossNamespace || []);
  var create = keep(a.workloadCreation || []);
  var esc = keep(a.escalation || []);
  var paths = keep(a.attackPaths || []);
  var pods = keep(a.podConfig || []);
  var tokens = keep((a.tokenExposure || []).filter(function(t) { return t.Unneeded; }));

  var completeNote = a.complete ? 'discovery complete' : 'discovery INCOMPLETE: ' + ((a.gaps || []).length) + ' gap(s)';
  meta.innerHTML = x(a.cluster || '') + ' · observed ' + x(a.observedAt ? new Date(a.observedAt).toLocaleString() : '') +
    ' · ' + x(completeNote) + (hidden ? ' · ' + hidden + ' built-in hidden' : '');

  var cats = [['Wildcard grants', wild.length, 'lock'], ['Broad ServiceAccounts', breadth.length, 'users'], ['Cross-namespace grants', cross.length, 'path'],
    ['Escalation actions', esc.length, 'bolt'], ['Pods with host access', pods.length, 'server'], ['Unused mounted tokens', tokens.length, 'key']];
  var catMax = Math.max.apply(null, cats.map(function(c) { return c[1]; }).concat([1]));
  kpis.innerHTML = grid(3, cats.map(function(c) {
    return kitKpi({ label: c[0], value: c[1], icon: c[2], tone: c[1] ? 'warn' : 'muted' });
  })) + card('Findings by category', hbars(cats.map(function(c) { return [c[0], c[1] / catMax * 100, c[1] ? 'warn' : 'muted', c[1]]; })));

  body.innerHTML =
    section('Wildcard RBAC', wild.length, listOrNone(wild, {
      head: '<th>Role</th><th>Kind</th><th>Rule</th><th>Verbs</th><th>Resources</th><th>Bound to</th>',
      row: function(f) {
        return '<tr><td>' + idCell(f.Role) + '</td><td>' + x(f.RoleKind) + '</td><td>' + f.Rule + '</td><td>' +
          x((f.Verbs || []).join(', ')) + '</td><td>' + x((f.Resources || []).join(', ')) + '</td><td>' +
          x((f.Subjects || []).map(shortId).join(', ') || 'no bindings') + '</td></tr>';
      }})) +
    section('Service accounts with broad grants', breadth.length, listOrNone(breadth, {
      head: '<th>ServiceAccount</th><th>Namespaces</th><th>Reasons</th>',
      row: function(b) {
        return '<tr><td>' + idCell(b.Subject) + '</td><td>' + x((b.Namespaces || []).join(', ') || '—') + '</td><td>' +
          x((b.Reasons || []).join(', ')) + '</td></tr>';
      }})) +
    section('Grants outside the home namespace', cross.length, listOrNone(cross, {
      head: '<th>ServiceAccount</th><th>Home</th><th>Scope</th><th>Binding</th><th>Rules</th>',
      row: function(f) {
        return '<tr><td>' + idCell(f.Subject) + '</td><td>' + x(f.Home) + '</td><td>' + x(f.Scope) + '</td><td>' +
          x(f.Binding) + '</td><td>' + x((f.Rules || []).join(', ')) + '</td></tr>';
      }})) +
    section('Workload creation outside the home namespace', create.length, listOrNone(create, {
      head: '<th>ServiceAccount</th><th>Namespace</th><th>Creates</th><th>Granted by</th>',
      row: function(f) {
        return '<tr><td>' + idCell(f.Subject) + '</td><td>' + x(f.Namespace) + '</td><td>' + x(f.Resource) +
          '</td><td>' + x((f.Evidence || []).join(', ')) + '</td></tr>';
      }})) +
    section('Escalation actions', esc.length, listOrNone(esc, {
      head: '<th>Subject</th><th>Action</th><th>Namespace</th><th>Granted by</th>',
      row: function(f) {
        return '<tr><td>' + idCell(f.Subject) + '</td><td>' + x(f.Capability) + '</td><td>' + x(f.Namespace || 'cluster') +
          '</td><td>' + x((f.Evidence || []).join(', ')) + '</td></tr>';
      }})) +
    section('Configured attack paths to secret-reading targets', paths.length, listOrNone(paths, {
      head: '<th>Workload</th><th>Route</th><th>Reaches</th>',
      row: function(p) {
        return '<tr><td>' + idCell(p.Workload) + '</td><td>' + x(p.Prerequisite) + '</td><td>' + idCell(p.Target) + '</td></tr>';
      }})) +
    section('Pods with host access or privileged settings', pods.length, listOrNone(pods, {
      head: '<th>Pod</th><th>Namespace</th><th>Settings</th>',
      row: function(p) {
        return '<tr><td>' + idCell(p.Workload) + '</td><td>' + x(p.Namespace) + '</td><td>' + x((p.Reasons || []).join(', ')) + '</td></tr>';
      }})) +
    section('Mounted tokens with no bindings (unused)', tokens.length, listOrNone(tokens, {
      head: '<th>Pod</th><th>ServiceAccount</th>',
      row: function(t) {
        return '<tr><td>' + idCell(t.Workload) + '</td><td>' + idCell(t.Subject) + '</td></tr>';
      }}));
}

// renderK8sAnalysisReport shows one report from the server. Exported so the rendering can be tested without a request.
export function renderK8sAnalysisReport(report) {
  k8sAnalysisLast = report;
  renderK8sAnalysis();
}

export function runK8sAnalysis() {
  var meta = document.getElementById('k8s-an-meta');
  if (meta) meta.textContent = 'Running read-only analysis…';
  apicall('/api/k8s-discovery/analysis').then(function(body) {
    if (body.error) throw new Error(body.error);
    renderK8sAnalysisReport(body);
  }).catch(function(err) {
    k8sAnalysisLast = null;
    if (meta) meta.textContent = 'Analysis unavailable: ' + (err.message || 'request failed');
    var body = document.getElementById('k8s-an-body');
    if (body) body.innerHTML = '';
    var kpis = document.getElementById('k8s-an-kpis');
    if (kpis) kpis.innerHTML = '';
  });
}

document.addEventListener('click', function(e) {
  var t = e.target;
  if (t && t.getAttribute && t.getAttribute('data-k8s-analysis-run')) runK8sAnalysis();
});

document.addEventListener('change', function(e) {
  if (e.target && e.target.id === 'k8s-an-system') renderK8sAnalysis();
});
