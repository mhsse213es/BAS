package cloudgraph

// Scenario 6: privilege-escalation permission analysis, for the capabilities K8sAttackPaths does not model.
//
// K8sAttackPaths already reports bind and escalate on ClusterRoles, pod creation, token requests, exec and node
// proxy, but only when such a route reaches a target that can read secrets. This check covers what it leaves out:
// impersonating users, groups or service accounts, and creating RoleBindings or ClusterRoleBindings. Each result
// is configured permission from AnalyseK8sAccess. None proves the escalation can be carried out end to end.

import (
	"sort"
)

// Scenario 6: privilege-escalation permission analysis. For each subject that has a binding, this checks a catalog
// of actions that let it gain more access than it was given: impersonating other identities, binding or escalating
// roles, creating bindings, minting ServiceAccount tokens, and creating pods or exec sessions (which can run as a
// ServiceAccount of their choosing). Each check is a configured-permission answer from AnalyseK8sAccess. None of
// them proves the escalation can be carried out end to end.

// k8sEscalationCatalog lists the escalation actions checked for every subject, excluding those K8sAttackPaths covers.
var k8sEscalationCatalog = []struct {
	Capability string
	Request    RBACRequest
}{
	{"impersonate-users", RBACRequest{Resource: "users", Verb: "impersonate"}},
	{"impersonate-groups", RBACRequest{Resource: "groups", Verb: "impersonate"}},
	{"create-rolebindings", RBACRequest{APIGroup: "rbac.authorization.k8s.io", Resource: "rolebindings", Verb: "create"}},
	{"create-clusterrolebindings", RBACRequest{APIGroup: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Verb: "create"}},
}

// K8sEscalationFinding is one escalation action a subject is configured to be granted in one namespace.
type K8sEscalationFinding struct {
	Subject    string
	Capability string
	Namespace  string // "" for cluster scope
	Decision   RBACDecision
	Evidence   []string // bindings whose role grants the action
	// Complete is false when discovery was incomplete, so the grant may be missing from the picture.
	Complete bool
}

// K8sEscalationFindings checks every subject that has a binding against the escalation catalog. A subject is
// checked in each namespace where it has a RoleBinding, plus cluster scope, since a RoleBinding applies only in
// its own namespace and a ClusterRoleBinding applies everywhere.
func K8sEscalationFindings(inv *K8sInventory, rep *K8sDiscoveryReport) []K8sEscalationFinding {
	complete := rep != nil && rep.Complete

	// Subjects with at least one binding, and the namespaces each is bound in.
	nsOf := map[string]map[string]bool{}
	for _, p := range inv.Permissions {
		if p == nil || p.Source == nil || p.Target == nil {
			continue
		}
		if nsOf[p.Source.CanonicalID] == nil {
			nsOf[p.Source.CanonicalID] = map[string]bool{}
		}
		if ns := p.Attributes["namespace"]; p.Attributes["bindingKind"] == "RoleBinding" && ns != "" {
			nsOf[p.Source.CanonicalID][ns] = true
		}
	}

	subjects := make([]string, 0, len(nsOf))
	for s := range nsOf {
		subjects = append(subjects, s)
	}
	sort.Strings(subjects)

	var out []K8sEscalationFinding
	for _, s := range subjects {
		namespaces := []string{""} // cluster scope is always checked
		for ns := range nsOf[s] {
			namespaces = append(namespaces, ns)
		}
		sort.Strings(namespaces[1:])
		for _, ns := range namespaces {
			for _, c := range k8sEscalationCatalog {
				res := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: s, Namespace: ns, Request: c.Request})
				if res.Decision == RBACNotGranted {
					continue
				}
				out = append(out, K8sEscalationFinding{
					Subject:    s,
					Capability: c.Capability,
					Namespace:  ns,
					Decision:   res.Decision,
					Evidence:   res.Evidence,
					Complete:   complete,
				})
			}
		}
	}
	return out
}
