package cloudgraph

import (
	"testing"
)

const (
	wildRole  = "k8s://kind-bas-lab/default/role/wild"
	wildCRole = "k8s://kind-bas-lab/_cluster/clusterrole/wild-cluster"
	wildSA    = "k8s://kind-bas-lab/default/serviceaccount/app"
)

// wildInventory builds a minimal inventory: one Role bound to one ServiceAccount, with the given rules.
func wildInventory(roleID string, rules []RBACRule) *K8sInventory {
	role := &CloudResource{CanonicalID: roleID, Kind: "k8s:role"}
	sa := &CloudIdentity{CanonicalID: wildSA, Kind: "k8s:serviceaccount"}
	return &K8sInventory{
		Roles:     map[string][]RBACRule{roleID: rules},
		Resources: []*CloudResource{role},
		Permissions: []*CloudPermission{{
			Source:     sa,
			Target:     role,
			Action:     "k8s:bind",
			Attributes: map[string]string{"binding": "app-binding"},
		}},
	}
}

func completeReport() *K8sDiscoveryReport { return &K8sDiscoveryReport{Complete: true} }

// TestK8sWildcard_FlagsWildcardVerbAndNamesBoundSubject checks a "*" verb is reported with the subject and binding.
func TestK8sWildcard_FlagsWildcardVerbAndNamesBoundSubject(t *testing.T) {
	inv := wildInventory(wildRole, []RBACRule{{Resources: []string{"pods"}, Verbs: []string{"*"}}})
	got := K8sWildcardFindings(inv, completeReport())
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(got), got)
	}
	f := got[0]
	if !f.WildVerb || f.WildResource || f.WildGroup {
		t.Fatalf("flags = verb:%v resource:%v group:%v, want only verb", f.WildVerb, f.WildResource, f.WildGroup)
	}
	if len(f.Subjects) != 1 || f.Subjects[0] != wildSA || len(f.Bindings) != 1 || f.Bindings[0] != "app-binding" {
		t.Fatalf("subjects/bindings = %v / %v, want the app ServiceAccount via app-binding", f.Subjects, f.Bindings)
	}
	if f.RoleKind != "Role" || !f.Complete {
		t.Fatalf("role kind = %q complete = %v, want Role and complete", f.RoleKind, f.Complete)
	}
}

// TestK8sWildcard_FlagsWildcardResource checks a "*" resource is reported.
func TestK8sWildcard_FlagsWildcardResource(t *testing.T) {
	inv := wildInventory(wildRole, []RBACRule{{Resources: []string{"*"}, Verbs: []string{"get"}}})
	got := K8sWildcardFindings(inv, completeReport())
	if len(got) != 1 || !got[0].WildResource || got[0].WildVerb {
		t.Fatalf("findings = %+v, want one wildcard-resource finding", got)
	}
}

// TestK8sWildcard_FlagsWildcardAPIGroupOnly checks a "*" API group alone is reported as its own flag.
func TestK8sWildcard_FlagsWildcardAPIGroupOnly(t *testing.T) {
	inv := wildInventory(wildRole, []RBACRule{{APIGroups: []string{"*"}, Resources: []string{"pods"}, Verbs: []string{"get"}}})
	got := K8sWildcardFindings(inv, completeReport())
	if len(got) != 1 || !got[0].WildGroup || got[0].WildVerb || got[0].WildResource {
		t.Fatalf("findings = %+v, want one wildcard-group finding", got)
	}
}

// TestK8sWildcard_ResourceNamesRestrictTheGrant checks a wildcard limited to named objects is not reported.
func TestK8sWildcard_ResourceNamesRestrictTheGrant(t *testing.T) {
	inv := wildInventory(wildRole, []RBACRule{{Resources: []string{"*"}, Verbs: []string{"*"}, ResourceNames: []string{"one-pod"}}})
	if got := K8sWildcardFindings(inv, completeReport()); len(got) != 0 {
		t.Fatalf("a named-object grant must not be reported as wildcard: %+v", got)
	}
}

// TestK8sWildcard_NoWildcardNoFinding checks an exact rule is not reported.
func TestK8sWildcard_NoWildcardNoFinding(t *testing.T) {
	inv := wildInventory(wildRole, []RBACRule{{Resources: []string{"pods"}, Verbs: []string{"get", "list"}}})
	if got := K8sWildcardFindings(inv, completeReport()); len(got) != 0 {
		t.Fatalf("an exact rule was reported: %+v", got)
	}
}

// TestK8sWildcard_ClusterRoleKindAndIncompleteDiscovery checks ClusterRoles are labelled, and an incomplete
// discovery marks the finding as not complete instead of silently reporting it as the whole picture.
func TestK8sWildcard_ClusterRoleKindAndIncompleteDiscovery(t *testing.T) {
	inv := wildInventory(wildCRole, []RBACRule{{Resources: []string{"*"}, Verbs: []string{"*"}}})
	got := K8sWildcardFindings(inv, &K8sDiscoveryReport{Complete: false, Gaps: []string{"pods: forbidden"}})
	if len(got) != 1 || got[0].RoleKind != "ClusterRole" || got[0].Complete {
		t.Fatalf("findings = %+v, want one ClusterRole finding marked incomplete", got)
	}
}
