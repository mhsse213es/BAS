package cloudgraph

import (
	"slices"
	"testing"
)

const (
	breadthNS      = "k8s://kind-bas-lab/default/serviceaccount/"
	breadthReader  = "k8s://kind-bas-lab/default/role/reader"
	breadthCRole   = "k8s://kind-bas-lab/_cluster/clusterrole/cluster-get"
	breadthWriter  = "k8s://kind-bas-lab/default/role/writer"
	breadthSecrets = "k8s://kind-bas-lab/default/role/secrets"
)

// breadthInventory builds one ServiceAccount per case, each bound to a role at the given scope.
func breadthInventory() *K8sInventory {
	reader := &CloudResource{CanonicalID: breadthReader, Kind: "k8s:role"}
	cget := &CloudResource{CanonicalID: breadthCRole, Kind: "k8s:clusterrole"}
	writer := &CloudResource{CanonicalID: breadthWriter, Kind: "k8s:role"}
	secrets := &CloudResource{CanonicalID: breadthSecrets, Kind: "k8s:role"}
	sa := func(name string) *CloudIdentity {
		return &CloudIdentity{CanonicalID: breadthNS + name, Kind: "k8s:serviceaccount"}
	}
	return &K8sInventory{
		Roles: map[string][]RBACRule{
			breadthReader:  {{Resources: []string{"pods"}, Verbs: []string{"get", "list"}}},
			breadthCRole:   {{Resources: []string{"pods"}, Verbs: []string{"get"}}},
			breadthWriter:  {{Resources: []string{"deployments"}, Verbs: []string{"create", "patch"}}},
			breadthSecrets: {{Resources: []string{"secrets"}, Verbs: []string{"get"}}},
		},
		Permissions: []*CloudPermission{
			{Source: sa("reader"), Target: reader, Action: "k8s:bind", Attributes: map[string]string{"binding": "reader-b", "bindingKind": "RoleBinding", "namespace": "default"}},
			{Source: sa("cluster"), Target: cget, Action: "k8s:bind", Attributes: map[string]string{"binding": "cluster-b", "bindingKind": "ClusterRoleBinding"}},
			{Source: sa("writer"), Target: writer, Action: "k8s:bind", Attributes: map[string]string{"binding": "writer-b", "bindingKind": "RoleBinding", "namespace": "default"}},
			{Source: sa("secrets"), Target: secrets, Action: "k8s:bind", Attributes: map[string]string{"binding": "secrets-b", "bindingKind": "RoleBinding", "namespace": "default"}},
		},
	}
}

func breadthFor(t *testing.T, got []K8sServiceAccountBreadth, name string) K8sServiceAccountBreadth {
	t.Helper()
	for _, b := range got {
		if b.Subject == breadthNS+name {
			return b
		}
	}
	t.Fatalf("no breadth entry for %s in %+v", name, got)
	return K8sServiceAccountBreadth{}
}

// TestK8sBreadth_ReadOnlyNamespacedGrantIsNotBroad checks a namespaced read-only grant has no breadth reasons.
func TestK8sBreadth_ReadOnlyNamespacedGrantIsNotBroad(t *testing.T) {
	got := K8sServiceAccountBreadthFindings(breadthInventory(), completeReport())
	b := breadthFor(t, got, "reader")
	if b.Broad || len(b.Reasons) != 0 || b.ClusterWide || len(b.Namespaces) != 1 || b.Namespaces[0] != "default" {
		t.Fatalf("reader = %+v, want not broad, scoped to default", b)
	}
}

// TestK8sBreadth_ClusterWideBindingIsBroad checks a ClusterRoleBinding is reported as cluster-wide.
func TestK8sBreadth_ClusterWideBindingIsBroad(t *testing.T) {
	got := K8sServiceAccountBreadthFindings(breadthInventory(), completeReport())
	b := breadthFor(t, got, "cluster")
	if !b.Broad || !b.ClusterWide || !slices.Contains(b.Reasons, "cluster-wide binding") {
		t.Fatalf("cluster = %+v, want broad with a cluster-wide reason", b)
	}
}

// TestK8sBreadth_WriteVerbIsBroad checks a write verb on any resource is a breadth reason.
func TestK8sBreadth_WriteVerbIsBroad(t *testing.T) {
	got := K8sServiceAccountBreadthFindings(breadthInventory(), completeReport())
	b := breadthFor(t, got, "writer")
	if !b.Broad || !b.WriteVerbs || !slices.Contains(b.Reasons, "write verbs") {
		t.Fatalf("writer = %+v, want broad with a write-verb reason", b)
	}
}

// TestK8sBreadth_SecretAccessIsBroad checks any access to secrets is a breadth reason.
func TestK8sBreadth_SecretAccessIsBroad(t *testing.T) {
	got := K8sServiceAccountBreadthFindings(breadthInventory(), completeReport())
	b := breadthFor(t, got, "secrets")
	if !b.Broad || !b.SecretAccess || !slices.Contains(b.Reasons, "secret access") {
		t.Fatalf("secrets = %+v, want broad with a secret-access reason", b)
	}
}

// TestK8sBreadth_IncompleteDiscoveryIsMarked checks an incomplete discovery is carried into each entry.
func TestK8sBreadth_IncompleteDiscoveryIsMarked(t *testing.T) {
	got := K8sServiceAccountBreadthFindings(breadthInventory(), &K8sDiscoveryReport{Complete: false})
	for _, b := range got {
		if b.Complete {
			t.Fatalf("entry %s marked complete under incomplete discovery", b.Subject)
		}
	}
}
