package cloudgraph

import (
	"testing"
)

const (
	xnsDefault  = "k8s://kind-bas-lab/default/serviceaccount/"
	xnsRoleA    = "k8s://kind-bas-lab/default/role/read-pods"
	xnsRoleB    = "k8s://kind-bas-lab/default/role/read-secrets"
	xnsClusterR = "k8s://kind-bas-lab/_cluster/clusterrole/read-pods-all"
)

// xnsInventory: "local" is bound inside its own namespace only; "leaky" is bound in another namespace; "wide" holds
// a ClusterRoleBinding; "limited" is bound in another namespace but only to named objects.
func xnsInventory() *K8sInventory {
	sa := func(name string) *CloudIdentity {
		return &CloudIdentity{CanonicalID: xnsDefault + name, Kind: "k8s:serviceaccount"}
	}
	roleA := &CloudResource{CanonicalID: xnsRoleA, Kind: "k8s:role"}
	roleB := &CloudResource{CanonicalID: xnsRoleB, Kind: "k8s:role"}
	clusterR := &CloudResource{CanonicalID: xnsClusterR, Kind: "k8s:clusterrole"}
	return &K8sInventory{
		Roles: map[string][]RBACRule{
			xnsRoleA:    {{Resources: []string{"pods"}, Verbs: []string{"get", "list"}}},
			xnsRoleB:    {{Resources: []string{"secrets"}, Verbs: []string{"get"}}},
			xnsClusterR: {{Resources: []string{"pods"}, Verbs: []string{"get"}}},
		},
		Permissions: []*CloudPermission{
			{Source: sa("local"), Target: roleA, Action: "k8s:bind", Attributes: map[string]string{"binding": "local-b", "bindingKind": "RoleBinding", "namespace": "default"}},
			{Source: sa("leaky"), Target: roleB, Action: "k8s:bind", Attributes: map[string]string{"binding": "leaky-b", "bindingKind": "RoleBinding", "namespace": "other"}},
			{Source: sa("wide"), Target: clusterR, Action: "k8s:bind", Attributes: map[string]string{"binding": "wide-b", "bindingKind": "ClusterRoleBinding"}},
			{Source: sa("limited"), Target: roleA, Action: "k8s:bind", Attributes: map[string]string{"binding": "limited-b", "bindingKind": "RoleBinding", "namespace": "other"}},
		},
	}
}

func xnsFor(got []K8sCrossNamespaceFinding, name string) []K8sCrossNamespaceFinding {
	var out []K8sCrossNamespaceFinding
	for _, f := range got {
		if f.Subject == xnsDefault+name {
			out = append(out, f)
		}
	}
	return out
}

// TestK8sCrossNS_OwnNamespaceBindingIsNotCrossNamespace checks a binding in the service account's own namespace
// is not reported.
func TestK8sCrossNS_OwnNamespaceBindingIsNotCrossNamespace(t *testing.T) {
	got := K8sCrossNamespaceFindings(xnsInventory(), completeReport())
	if f := xnsFor(got, "local"); len(f) != 0 {
		t.Fatalf("local findings = %+v, want none", f)
	}
}

// TestK8sCrossNS_RoleBindingInAnotherNamespaceIsReported checks a RoleBinding in another namespace is reported
// with that namespace as the scope, and the granted rules as the evidence.
func TestK8sCrossNS_RoleBindingInAnotherNamespaceIsReported(t *testing.T) {
	got := K8sCrossNamespaceFindings(xnsInventory(), completeReport())
	leaky := xnsFor(got, "leaky")
	if len(leaky) != 1 || leaky[0].Scope != "other" || leaky[0].Binding != "leaky-b" {
		t.Fatalf("leaky findings = %+v, want one finding scoped to other via leaky-b", leaky)
	}
	if len(leaky[0].Rules) != 1 || leaky[0].Rules[0] != "secrets:get" {
		t.Fatalf("rules = %v, want [secrets:get]", leaky[0].Rules)
	}
}

// TestK8sCrossNS_ClusterRoleBindingIsClusterScope checks a ClusterRoleBinding is reported with cluster scope.
func TestK8sCrossNS_ClusterRoleBindingIsClusterScope(t *testing.T) {
	got := K8sCrossNamespaceFindings(xnsInventory(), completeReport())
	wide := xnsFor(got, "wide")
	if len(wide) != 1 || wide[0].Scope != "cluster" {
		t.Fatalf("wide findings = %+v, want one cluster-scope finding", wide)
	}
}

// TestK8sCrossNS_NamedObjectGrantIsNotReported checks a cross-namespace grant limited to named objects is left out.
func TestK8sCrossNS_NamedObjectGrantIsNotReported(t *testing.T) {
	inv := xnsInventory()
	inv.Roles[xnsRoleA] = []RBACRule{{Resources: []string{"pods"}, Verbs: []string{"get"}, ResourceNames: []string{"one"}}}
	got := K8sCrossNamespaceFindings(inv, completeReport())
	if f := xnsFor(got, "limited"); len(f) != 0 {
		t.Fatalf("limited findings = %+v, want none", f)
	}
}
