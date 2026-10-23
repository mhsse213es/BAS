package cloudgraph

import (
	"fmt"
	"sort"
	"strings"
)

// Scenario 3: cross-namespace access. A ServiceAccount's intended namespace is its own. This reports each grant
// that reaches beyond it: a RoleBinding in a different namespace, or a ClusterRoleBinding (which applies everywhere).
// It reads only the inventory discovery already collected, so it makes no API call and writes nothing. It is
// configured permission, not proof that the access can be exercised.

// K8sCrossNamespaceFinding is one grant that reaches outside the subject's own namespace.
type K8sCrossNamespaceFinding struct {
	Subject string   // canonical ServiceAccount ID
	Home    string   // the namespace the ServiceAccount lives in
	Scope   string   // the namespace the binding grants in, or "cluster" for a ClusterRoleBinding
	Binding string   // binding name
	Role    string   // canonical role ID
	Rules   []string // granted "resource:verb" pairs, sorted; rules limited by resourceNames are left out
	// Complete is false when discovery was incomplete, so the grant may be a partial picture.
	Complete bool
}

// K8sCrossNamespaceFindings returns every cross-namespace grant held by a ServiceAccount that grants at least one
// rule not limited by resourceNames, sorted by subject, scope and binding.
func K8sCrossNamespaceFindings(inv *K8sInventory, rep *K8sDiscoveryReport) []K8sCrossNamespaceFinding {
	complete := rep != nil && rep.Complete
	var out []K8sCrossNamespaceFinding
	for _, p := range inv.Permissions {
		if p == nil || p.Source == nil || p.Target == nil || p.Source.Kind != "k8s:serviceaccount" {
			continue
		}
		home := serviceAccountNamespace(p.Source.CanonicalID)
		scope := p.Attributes["namespace"]
		if p.Attributes["bindingKind"] == "ClusterRoleBinding" {
			scope = "cluster"
		} else if scope == "" || scope == home {
			continue // a RoleBinding in the subject's own namespace is not cross-namespace
		}
		rules := grantedPairs(inv.Roles[p.Target.CanonicalID])
		if len(rules) == 0 {
			continue
		}
		out = append(out, K8sCrossNamespaceFinding{
			Subject:  p.Source.CanonicalID,
			Home:     home,
			Scope:    scope,
			Binding:  p.Attributes["binding"],
			Role:     p.Target.CanonicalID,
			Rules:    rules,
			Complete: complete,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Binding < out[j].Binding
	})
	return out
}

// serviceAccountNamespace reads the namespace from a canonical ServiceAccount ID "k8s://cluster/<ns>/serviceaccount/<name>".
func serviceAccountNamespace(id string) string {
	parts := strings.SplitN(id, "/", 6)
	if len(parts) == 6 {
		return parts[3]
	}
	return ""
}

// grantedPairs lists the "resource:verb" pairs a role grants, sorted and de-duplicated. Rules limited by
// resourceNames are skipped, since they grant named objects only.
func grantedPairs(rules []RBACRule) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rules {
		if len(r.ResourceNames) > 0 {
			continue
		}
		for _, res := range r.Resources {
			for _, v := range r.Verbs {
				pair := fmt.Sprintf("%s:%s", res, v)
				if !seen[pair] {
					seen[pair] = true
					out = append(out, pair)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}
