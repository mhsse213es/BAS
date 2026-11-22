// Dummy-data overrides, page group 9 (Kubernetes Scenarios page redesign). Real response shapes, sample values.
//   GET /api/k8s-scenarios/runs     -> the demo-b runs plus params and approvalId (the shape the drawer reads).
//   GET /api/k8s-discovery/analysis -> one read-only analysis report (nested fields use their Go names).
import { DEMO as demoB } from './demo-b.mjs';

const PARAMS = {
  'pod-create-unprivileged': { name: 'bas-probe-7f2' },
  'configmap-patch-labelled': { name: 'bas-probe-cfg', value: 'on' },
  'sa-token-probe': {},
  'synthetic-secret-read': {},
};
const runs = demoB['GET /api/k8s-scenarios/runs'].map((r, i) => ({
  ...r,
  params: PARAMS[r.action] || {},
  approvalId: r.state === 'PLANNED' || r.state === 'REFUSED' ? '' : 'appr-' + (9100 + i),
}));

const C = 'k8s://prod-eks-eu1/';
const analysis = {
  cluster: 'prod-eks-eu1', observedAt: '2026-10-23T08:00:00Z', complete: true, gaps: [],
  wildcards: [
    { Role: C + 'payments/role/ops-all', RoleKind: 'Role', Rule: 0, Verbs: ['*'], Resources: ['secrets', 'pods'], Subjects: [C + 'payments/serviceaccount/ops-bot'] },
    { Role: C + '_cluster/clusterrole/legacy-admin', RoleKind: 'ClusterRole', Rule: 1, Verbs: ['*'], Resources: ['*'], Subjects: [C + 'kube-system/serviceaccount/tiller'] },
    { Role: C + '_cluster/clusterrole/system:controller:gc', RoleKind: 'ClusterRole', Rule: 0, Verbs: ['*'], Resources: ['*'], Subjects: [] },
  ],
  breadth: [
    { Subject: C + 'kube-system/serviceaccount/tiller', Namespaces: ['kube-system', 'payments'], Reasons: ['cluster-admin binding', 'wildcard verbs'], Broad: true },
    { Subject: C + 'payments/serviceaccount/ops-bot', Namespaces: ['payments'], Reasons: ['reads secrets'], Broad: true },
  ],
  crossNamespace: [
    { Subject: C + 'payments/serviceaccount/ops-bot', Home: 'payments', Scope: 'bas-sandbox', Binding: 'ops-bot-sandbox', Rules: ['get secrets', 'list pods'] },
  ],
  workloadCreation: [
    { Subject: C + 'payments/serviceaccount/ops-bot', Namespace: 'bas-sandbox', Resource: 'pods', Evidence: ['rolebinding/ops-bot-sandbox'] },
  ],
  escalation: [
    { Subject: C + 'kube-system/serviceaccount/tiller', Capability: 'bind clusterroles', Namespace: '', Evidence: ['clusterrolebinding/tiller'] },
  ],
  attackPaths: [
    { Workload: C + 'payments/pod/ops-bot-6d9', Prerequisite: 'mounted ServiceAccount token', Target: C + 'payments/secret/db-credentials' },
  ],
  podConfig: [
    { Workload: C + 'kube-system/pod/node-agent-x2', Namespace: 'kube-system', Reasons: ['hostPath /var/run', 'privileged'] },
  ],
  tokenExposure: [
    { Workload: C + 'payments/pod/report-job-88c', Subject: C + 'payments/serviceaccount/default', Unneeded: true },
  ],
};

export const DEMO = {
  'GET /api/k8s-scenarios/runs': runs,
  'GET /api/k8s-discovery/analysis': analysis,
};
