package cloudgraph

import "sort"

// Scenario 5: workload creation outside the intended namespace. A ServiceAccount's intended namespace is its own.
// For every namespace (or cluster scope) where it holds a cross-namespace grant, this checks whether that grant
// lets it create workloads there. Each check uses AnalyseK8sAccess, so API groups are matched as Kubernetes matches
// them. It reads only the discovered inventory and writes nothing. Results are configured permission, not proof
// that a workload could be created and run.

// k8sWorkloadCatalog lists the workload kinds checked, with their API groups.
var k8sWorkloadCatalog = []struct {
	Group    string
	Resource string
}{
	{"", "pods"},
	{"apps", "deployments"},
	{"apps", "daemonsets"},
	{"apps", "statefulsets"},
	{"apps", "replicasets"},
	{"batch", "jobs"},
	{"batch", "cronjobs"},
}

// K8sWorkloadCreationFinding is one workload kind a ServiceAccount is configured to create outside its own namespace.
type K8sWorkloadCreationFinding struct {
	Subject   string // canonical ServiceAccount ID
	Home      string // the namespace the ServiceAccount lives in
	Namespace string // the namespace the grant applies in, or "cluster"
	Group     string // API group of the workload resource
	Resource  string // workload resource, e.g. "deployments"
	Decision  RBACDecision
	Evidence  []string // bindings that grant the create
	// Complete is false when discovery was incomplete, so the grant may be missing from the picture.
	Complete bool
}

// K8sWorkloadCreationFindings returns, for each cross-namespace scope a ServiceAccount holds, the workload kinds
// it is configured to create there. Each scope is evaluated once.
func K8sWorkloadCreationFindings(inv *K8sInventory, rep *K8sDiscoveryReport) []K8sWorkloadCreationFinding {
	complete := rep != nil && rep.Complete
	seen := map[string]bool{}
	var out []K8sWorkloadCreationFinding
	for _, x := range K8sCrossNamespaceFindings(inv, rep) {
		// A cluster-scoped grant is evaluated with an empty namespace, which only ClusterRoleBindings match.
		reqNS := x.Scope
		if reqNS == "cluster" {
			reqNS = ""
		}
		key := x.Subject + "|" + x.Scope
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, w := range k8sWorkloadCatalog {
			res := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: x.Subject, Namespace: reqNS,
				Request: RBACRequest{APIGroup: w.Group, Resource: w.Resource, Verb: "create"}})
			if res.Decision == RBACNotGranted {
				continue
			}
			out = append(out, K8sWorkloadCreationFinding{
				Subject:   x.Subject,
				Home:      x.Home,
				Namespace: x.Scope,
				Group:     w.Group,
				Resource:  w.Resource,
				Decision:  res.Decision,
				Evidence:  res.Evidence,
				Complete:  complete,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}
