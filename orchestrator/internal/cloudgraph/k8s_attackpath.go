package cloudgraph

// Phase 3 (first increment): read-only attack-path modelling over the configured RBAC graph.
//
// A path is: workload -> service account -> prerequisite capability -> target. It says that the collected
// policy would let the workload's service account reach a target that can read secrets. It is configured
// permission only. Nothing is executed. A path is not evidence that the route works, that admission or other
// authorizers allow it, or that the workload can reach the cluster.
//
// Routes modelled (each needs the prerequisite to be granted; an unknown prerequisite yields no path):
//   bind-clusterroles         bind verb on ClusterRoles -> a ClusterRole that lists secrets
//   escalate-clusterroles     escalate verb on ClusterRoles -> a ClusterRole that lists secrets
//   impersonate-serviceaccounts  impersonate verb on serviceaccounts -> a service account that lists secrets
//   create-pods               create pods in a namespace -> a service account in that namespace that lists secrets
//   request-serviceaccount-token  create serviceaccounts/token -> a same-namespace service account that lists secrets
//   exec-into-pods            create pods/exec -> a pod in that namespace running a service account that lists secrets
//   proxy-nodes               get nodes/proxy -> a pod on any node running a service account that lists secrets (kubelet access)
//
// Not modelled: admission policy (see QA log O-14).

// K8sAttackPath is one configured path from a workload to a secret-reaching target.
type K8sAttackPath struct {
	Workload       string
	Subject        string
	Prerequisite   string   // route, e.g. "bind-clusterroles"
	Target         string   // canonical ID of the ClusterRole or service account the path reaches
	Evidence       []string // bindings that grant the prerequisite
	PolicyComplete bool     // false when discovery was incomplete, so the path may be incomplete too
	Class          string
}

// k8sSATarget is a service account whose configured rules list secrets in its own namespace.
type k8sSATarget struct {
	ID        string
	Namespace string
}

// K8sAttackPaths returns the configured paths for every pod's service account.
func K8sAttackPaths(inv *K8sInventory, rep *K8sDiscoveryReport) []K8sAttackPath {
	// Role targets: ClusterRoles whose rules list secrets cluster-wide.
	var roleTargets []string
	for _, r := range inv.Resources {
		if r.Kind != "k8s:clusterrole" {
			continue
		}
		if EvaluateRBAC(inv.Roles[r.CanonicalID], RBACRequest{Resource: "secrets", Verb: "list"}, true, 0) == RBACGranted {
			roleTargets = append(roleTargets, r.CanonicalID)
		}
	}

	// Service-account targets: accounts that can list secrets in their own namespace.
	var saTargets []k8sSATarget
	for _, id := range inv.Identities {
		if id.Kind != "k8s:serviceaccount" {
			continue
		}
		ns := id.Attributes["namespace"]
		if AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: id.CanonicalID, Namespace: ns, Request: RBACRequest{Resource: "secrets", Verb: "list"}}).Decision == RBACGranted {
			saTargets = append(saTargets, k8sSATarget{ID: id.CanonicalID, Namespace: ns})
		}
	}

	var out []K8sAttackPath
	for _, r := range inv.Resources {
		if r.Kind != "k8s:pod" {
			continue
		}
		ns := r.Attributes["namespace"]
		subject := k8sCanonicalID(rep.ClusterName, ns, "serviceaccount", r.Attributes["serviceAccount"])

		add := func(route string, req RBACRequest, reqNS string, targets []string) {
			pre := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: subject, Namespace: reqNS, Request: req})
			if pre.Decision != RBACGranted {
				return
			}
			for _, target := range targets {
				if target == subject {
					continue
				}
				out = append(out, K8sAttackPath{
					Workload:       r.CanonicalID,
					Subject:        subject,
					Prerequisite:   route,
					Target:         target,
					Evidence:       pre.Evidence,
					PolicyComplete: rep.Complete,
					Class:          k8sClassConfigured,
				})
			}
		}
		rbac := "rbac.authorization.k8s.io"
		add("bind-clusterroles", RBACRequest{APIGroup: rbac, Resource: "clusterroles", Verb: "bind"}, "", roleTargets)
		add("escalate-clusterroles", RBACRequest{APIGroup: rbac, Resource: "clusterroles", Verb: "escalate"}, "", roleTargets)
		add("impersonate-serviceaccounts", RBACRequest{Resource: "serviceaccounts", Verb: "impersonate"}, "", saIDs(saTargets, ""))
		add("create-pods", RBACRequest{Resource: "pods", Verb: "create"}, ns, saIDs(saTargets, ns))
		add("request-serviceaccount-token", RBACRequest{Resource: "serviceaccounts/token", Verb: "create"}, ns, saIDs(saTargets, ns))
		add("exec-into-pods", RBACRequest{Resource: "pods/exec", Verb: "create"}, ns, podIDs(inv, rep.ClusterName, saTargets, ns))
		add("proxy-nodes", RBACRequest{Resource: "nodes/proxy", Verb: "get"}, "", podIDs(inv, rep.ClusterName, saTargets, ""))
	}
	return out
}

// saIDs returns the IDs of service-account targets. An empty namespace selects every target.
func saIDs(targets []k8sSATarget, ns string) []string {
	var ids []string
	for _, t := range targets {
		if ns == "" || t.Namespace == ns {
			ids = append(ids, t.ID)
		}
	}
	return ids
}

// podIDs returns the pods in a namespace (all namespaces when ns is empty) that run a service account which can list secrets.
func podIDs(inv *K8sInventory, cluster string, targets []k8sSATarget, ns string) []string {
	saSet := map[string]bool{}
	for _, t := range targets {
		saSet[t.ID] = true
	}
	var ids []string
	for _, r := range inv.Resources {
		if r.Kind != "k8s:pod" || (ns != "" && r.Attributes["namespace"] != ns) {
			continue
		}
		sa := k8sCanonicalID(cluster, r.Attributes["namespace"], "serviceaccount", r.Attributes["serviceAccount"])
		if saSet[sa] {
			ids = append(ids, r.CanonicalID)
		}
	}
	return ids
}
