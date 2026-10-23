package cloudgraph

import (
	"testing"
)

const (
	escSA      = "k8s://kind-bas-lab/default/serviceaccount/"
	escImpRole = "k8s://kind-bas-lab/default/role/impersonator"
	escBinder  = "k8s://kind-bas-lab/_cluster/clusterrole/binder"
	escReadRol = "k8s://kind-bas-lab/default/role/reader"
)

// escInventory: "imp" is bound in default to a role that impersonates; "binder" is cluster-wide and can create
// ClusterRoleBindings; "reader" only reads pods.
func escInventory() *K8sInventory {
	sa := func(name string) *CloudIdentity {
		return &CloudIdentity{CanonicalID: escSA + name, Kind: "k8s:serviceaccount"}
	}
	imp := &CloudResource{CanonicalID: escImpRole, Kind: "k8s:role"}
	binder := &CloudResource{CanonicalID: escBinder, Kind: "k8s:clusterrole"}
	reader := &CloudResource{CanonicalID: escReadRol, Kind: "k8s:role"}
	return &K8sInventory{
		Roles: map[string][]RBACRule{
			escImpRole: {{APIGroups: []string{""}, Resources: []string{"users", "groups"}, Verbs: []string{"impersonate"}}},
			escBinder:  {{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterrolebindings"}, Verbs: []string{"create"}}},
			escReadRol: {{Resources: []string{"pods"}, Verbs: []string{"get", "list"}}},
		},
		Permissions: []*CloudPermission{
			{Source: sa("imp"), Target: imp, Action: "k8s:bind", Attributes: map[string]string{"binding": "imp-b", "bindingKind": "RoleBinding", "namespace": "default"}},
			{Source: sa("binder"), Target: binder, Action: "k8s:bind", Attributes: map[string]string{"binding": "binder-b", "bindingKind": "ClusterRoleBinding"}},
			{Source: sa("reader"), Target: reader, Action: "k8s:bind", Attributes: map[string]string{"binding": "reader-b", "bindingKind": "RoleBinding", "namespace": "default"}},
		},
	}
}

func escFindingsFor(got []K8sEscalationFinding, subject string) []K8sEscalationFinding {
	var out []K8sEscalationFinding
	for _, f := range got {
		if f.Subject == subject {
			out = append(out, f)
		}
	}
	return out
}

func hasEscalation(fs []K8sEscalationFinding, capability, namespace string) bool {
	for _, f := range fs {
		if f.Capability == capability && f.Namespace == namespace {
			return true
		}
	}
	return false
}

// TestK8sEscalation_ImpersonationInItsNamespaceOnly checks a RoleBinding's impersonation is reported in its own
// namespace and not at cluster scope.
func TestK8sEscalation_ImpersonationInItsNamespaceOnly(t *testing.T) {
	got := K8sEscalationFindings(escInventory(), completeReport())
	imp := escFindingsFor(got, escSA+"imp")
	if !hasEscalation(imp, "impersonate-users", "default") || !hasEscalation(imp, "impersonate-groups", "default") {
		t.Fatalf("imp findings = %+v, want impersonation of users and groups in default", imp)
	}
	if hasEscalation(imp, "impersonate-users", "") {
		t.Fatalf("a RoleBinding's impersonation must not be reported at cluster scope: %+v", imp)
	}
}

// TestK8sEscalation_ClusterRoleBindingCanCreateBindings checks a cluster-wide grant to create ClusterRoleBindings is
// reported at cluster scope, with the decision and the binding name as evidence.
func TestK8sEscalation_ClusterRoleBindingCanCreateBindings(t *testing.T) {
	got := K8sEscalationFindings(escInventory(), completeReport())
	b := escFindingsFor(got, escSA+"binder")
	if !hasEscalation(b, "create-clusterrolebindings", "") {
		t.Fatalf("binder findings = %+v, want create-clusterrolebindings at cluster scope", b)
	}
	for _, f := range b {
		if f.Decision != RBACGranted || len(f.Evidence) != 1 || f.Evidence[0] != "binder-b" {
			t.Fatalf("finding %+v, want granted with binder-b as evidence", f)
		}
	}
}

// TestK8sEscalation_ReadOnlySubjectHasNoFindings checks a read-only account produces no escalation findings.
func TestK8sEscalation_ReadOnlySubjectHasNoFindings(t *testing.T) {
	got := K8sEscalationFindings(escInventory(), completeReport())
	if rd := escFindingsFor(got, escSA+"reader"); len(rd) != 0 {
		t.Fatalf("reader findings = %+v, want none", rd)
	}
}
