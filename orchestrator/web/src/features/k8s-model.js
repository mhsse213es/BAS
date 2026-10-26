// Pure helpers for the redesigned Kubernetes Scenarios page: run groups, hero numbers, cluster cards, the
// table filter and the drawer's rows. No DOM, no network: everything comes from the rows
// /api/k8s-scenarios/runs already returned.

// stateGroup puts a run state in one outcome group.
export function stateGroup(state) {
  if (state === 'PLANNED' || state === 'DRY_RUN_PLANNED') return 'pending';
  if (state === 'APPROVED') return 'ready';
  if (state === 'CLEANED') return 'clean';
  return 'problem';
}

// k8sRunCounts: runs per outcome group for the summary donut.
export function k8sRunCounts(runs) {
  var c = { total: 0, pending: 0, ready: 0, clean: 0, problem: 0 };
  (runs || []).forEach(function(r) { c.total++; c[stateGroup(r.state)]++; });
  return c;
}

export function heroStats(runs) {
  var c = k8sRunCounts(runs), seen = {};
  (runs || []).forEach(function(r) { if (r.cluster) seen[r.cluster] = 1; });
  return { clusters: Object.keys(seen).length, runs: c.total, pending: c.pending + c.ready, problem: c.problem };
}

// clusterCards: one card per cluster that appears in the runs, busiest first.
export function clusterCards(runs) {
  var by = {};
  (runs || []).forEach(function(r) {
    var k = r.cluster || '';
    if (!k) return;
    var e = by[k] || (by[k] = { id: k, runs: 0, namespaces: {}, pending: 0, ready: 0, clean: 0, problem: 0 });
    e.runs++; e.namespaces[r.namespace || ''] = 1; e[stateGroup(r.state)]++;
  });
  return Object.keys(by).map(function(k) {
    var e = by[k];
    e.nsCount = Object.keys(e.namespaces).length;
    e.cleanPct = Math.round(e.clean / e.runs * 100);
    e.tone = e.problem ? 'bad' : (e.pending || e.ready) ? 'warn' : 'ok';
    e.label = e.problem ? 'Needs attention' : (e.pending || e.ready) ? 'In progress' : 'All clean';
    return e;
  }).sort(function(a, b) { return b.runs - a.runs || (a.id < b.id ? -1 : 1); });
}

export function clusterOptions(runs) { return clusterCards(runs).map(function(c) { return c.id; }); }

// filterRuns applies the search box, the cluster card / select and the state group.
export function filterRuns(runs, f, labelOf) {
  var q = String((f && f.q) || '').trim().toLowerCase();
  return (runs || []).filter(function(r) {
    if (f && f.cluster && r.cluster !== f.cluster) return false;
    if (f && f.group && stateGroup(r.state) !== f.group) return false;
    if (!q) return true;
    var hay = [r.id, r.action, labelOf ? labelOf(r.action) : '', r.cluster, r.namespace, r.requester].join(' ').toLowerCase();
    return hay.indexOf(q) !== -1;
  });
}

// planSteps splits a run's plan-and-outcome text into the lines the drawer lists.
export function planSteps(detail) { return String(detail || '').split('\n').map(function(s) { return s.trim(); }).filter(Boolean); }

// paramRows: the run's parameters as label/value rows.
export function paramRows(params) {
  var p = params || {};
  return Object.keys(p).sort().map(function(k) { return [k, String(p[k])]; });
}
