package cloudgraph

import (
	"slices"
	"sort"
)

// Scenario 2: excessive service-account permissions. This measures how broad each ServiceAccount's configured
// grants are, from the inventory discovery already collected. It does not decide what a workload needs, so it
// never says a grant is "unnecessary": it reports the breadth factors it can measure. Each reason is a fact
// about the configured policy, not proof that the access can be exercised.

// writeVerbs are the verbs that change state. "*" is included, since it grants every verb.
var writeVerbs = []string{"create", "update", "patch", "delete", "deletecollection", "escalate", "bind", "impersonate", "*"}

// K8sServiceAccountBreadth summarises the configured grants of one ServiceAccount.
type K8sServiceAccountBreadth struct {
	Subject      string   // canonical ServiceAccount ID
	Namespaces   []string // namespaces of the RoleBindings that grant it, sorted
	ClusterWide  bool     // a ClusterRoleBinding grants it
	WriteVerbs   bool     // a state-changing verb is granted on some resource
	SecretAccess bool     // any verb is granted on secrets
	Reasons      []string // breadth factors that apply; empty when none do
	Broad        bool     // len(Reasons) > 0
	// Complete is false when discovery was incomplete, so the grants may be a partial picture.
	Complete bool
}

// K8sServiceAccountBreadthFindings returns the breadth of every ServiceAccount that has at least one grant,
// sorted by subject. Rules limited by resourceNames are left out, as in the wildcard analysis.
func K8sServiceAccountBreadthFindings(inv *K8sInventory, rep *K8sDiscoveryReport) []K8sServiceAccountBreadth {
	complete := rep != nil && rep.Complete
	type acc struct {
		namespaces   map[string]bool
		clusterWide  bool
		writeVerbs   bool
		secretAccess bool
	}
	bySubject := map[string]*acc{}
	for _, p := range inv.Permissions {
		if p == nil || p.Source == nil || p.Target == nil || p.Source.Kind != "k8s:serviceaccount" {
			continue
		}
		a := bySubject[p.Source.CanonicalID]
		if a == nil {
			a = &acc{namespaces: map[string]bool{}}
			bySubject[p.Source.CanonicalID] = a
		}
		if p.Attributes["bindingKind"] == "clusterrolebindings" {
			a.clusterWide = true
		} else if ns := p.Attributes["namespace"]; ns != "" {
			a.namespaces[ns] = true
		}
		for _, r := range inv.Roles[p.Target.CanonicalID] {
			if len(r.ResourceNames) > 0 {
				continue
			}
			if anyOf(r.Verbs, writeVerbs) {
				a.writeVerbs = true
			}
			if slices.Contains(r.Resources, "secrets") || slices.Contains(r.Resources, "*") {
				a.secretAccess = true
			}
		}
	}

	subjects := make([]string, 0, len(bySubject))
	for s := range bySubject {
		subjects = append(subjects, s)
	}
	sort.Strings(subjects)

	out := make([]K8sServiceAccountBreadth, 0, len(subjects))
	for _, s := range subjects {
		a := bySubject[s]
		b := K8sServiceAccountBreadth{Subject: s, ClusterWide: a.clusterWide, WriteVerbs: a.writeVerbs,
			SecretAccess: a.secretAccess, Complete: complete}
		for ns := range a.namespaces {
			b.Namespaces = append(b.Namespaces, ns)
		}
		sort.Strings(b.Namespaces)
		if a.clusterWide {
			b.Reasons = append(b.Reasons, "cluster-wide binding")
		}
		if a.writeVerbs {
			b.Reasons = append(b.Reasons, "write verbs")
		}
		if a.secretAccess {
			b.Reasons = append(b.Reasons, "secret access")
		}
		b.Broad = len(b.Reasons) > 0
		out = append(out, b)
	}
	return out
}

// anyOf reports whether list contains any of the wanted values.
func anyOf(list, wanted []string) bool {
	for _, v := range wanted {
		if slices.Contains(list, v) {
			return true
		}
	}
	return false
}
