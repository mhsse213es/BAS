package cloudgraph

// Phase 3 (first increment): read-only attack-path modelling over the configured RBAC graph.
//
// A path is: workload -> service account -> prerequisite capability -> target role. It says that the
// collected policy would let the workload's service account bind a ClusterRole that grants secret reads.
// It is configured permission only. Nothing is executed. The path is not evidence that the escalation
// works, that admission or other authorizers allow it, or that the workload can reach the cluster.
//
// The model checks the bind verb on ClusterRoles. A subject with that verb can bind any ClusterRole it names.
// Other escalation routes (creating bindings to roles whose rules the subject already holds, or the
// escalate verb) are not modelled. Unknown prerequisites produce no path, so no path is inferred from absence.

// K8sAttackPath is one configured path from a workload to a secret-reading ClusterRole.
type K8sAttackPath struct {
	Workload       string
	Subject        string
	Prerequisite   string   // capability the subject is configured to have
	Target         string   // canonical ID of the ClusterRole the path reaches
	Evidence       []string // bindings that grant the prerequisite
	PolicyComplete bool     // false when discovery was incomplete, so the path may be incomplete too
	Class          string
}

// K8sAttackPaths returns the configured paths for every pod's service account.
func K8sAttackPaths(inv *K8sInventory, rep *K8sDiscoveryReport) []K8sAttackPath {
	// Targets: every ClusterRole whose rules list secrets cluster-wide.
	var targets []string
	for _, r := range inv.Resources {
		if r.Kind != "k8s:clusterrole" {
			continue
		}
		if EvaluateRBAC(inv.Roles[r.CanonicalID], RBACRequest{Resource: "secrets", Verb: "list"}, true, 0) == RBACGranted {
			targets = append(targets, r.CanonicalID)
		}
	}
	if len(targets) == 0 {
		return nil
	}

	var out []K8sAttackPath
	for _, r := range inv.Resources {
		if r.Kind != "k8s:pod" {
			continue
		}
		ns := r.Attributes["namespace"]
		subject := k8sCanonicalID(rep.ClusterName, ns, "serviceaccount", r.Attributes["serviceAccount"])

		prereq := AnalyseK8sAccess(inv, rep, K8sAccessQuery{
			Subject:   subject,
			Namespace: "",
			Request:   RBACRequest{APIGroup: "rbac.authorization.k8s.io", Resource: "clusterroles", Verb: "bind"},
		})
		if prereq.Decision != RBACGranted {
			continue
		}
		for _, target := range targets {
			out = append(out, K8sAttackPath{
				Workload:       r.CanonicalID,
				Subject:        subject,
				Prerequisite:   "bind-clusterroles",
				Target:         target,
				Evidence:       prereq.Evidence,
				PolicyComplete: rep.Complete,
				Class:          k8sClassConfigured,
			})
		}
	}
	return out
}
