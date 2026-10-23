package cloudgraph

import (
	"testing"
)

const (
	wcDefault = "k8s://kind-bas-lab/default/serviceaccount/"
	wcRoleApp = "k8s://kind-bas-lab/other/role/deployer"
	wcRoleBad = "k8s://kind-bas-lab/other/role/wrong-group"
	wcCluster = "k8s://kind-bas-lab/_cluster/clusterrole/pod-maker"
)

// wcInventory: "deployer" may create deployments in the apps group in another namespace; "wrong" names deployments
// under the core group, which does not match; "pods" holds a cluster-wide grant to create pods; "local" stays home.
func wcInventory() *K8sInventory {
	sa := func(name string) *CloudIdentity {
		return &CloudIdentity{CanonicalID: wcDefault + name, Kind: "k8s:serviceaccount"}
	}
	deployer := &CloudResource{CanonicalID: wcRoleApp, Kind: "k8s:role"}
	wrong := &CloudResource{CanonicalID: wcRoleBad, Kind: "k8s:role"}
	podMaker := &CloudResource{CanonicalID: wcCluster, Kind: "k8s:clusterrole"}
	local := &CloudResource{CanonicalID: "k8s://kind-bas-lab/default/role/local", Kind: "k8s:role"}
	return &K8sInventory{
		Roles: map[string][]RBACRule{
			wcRoleApp:                               {{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}}},
			wcRoleBad:                               {{APIGroups: []string{""}, Resources: []string{"deployments"}, Verbs: []string{"create"}}},
			wcCluster:                               {{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}},
			"k8s://kind-bas-lab/default/role/local": {{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}}},
		},
		Permissions: []*CloudPermission{
			{Source: sa("deployer"), Target: deployer, Action: "k8s:bind", Attributes: map[string]string{"binding": "deployer-b", "bindingKind": "RoleBinding", "namespace": "other"}},
			{Source: sa("wrong"), Target: wrong, Action: "k8s:bind", Attributes: map[string]string{"binding": "wrong-b", "bindingKind": "RoleBinding", "namespace": "other"}},
			{Source: sa("pods"), Target: podMaker, Action: "k8s:bind", Attributes: map[string]string{"binding": "pods-b", "bindingKind": "ClusterRoleBinding"}},
			{Source: sa("local"), Target: local, Action: "k8s:bind", Attributes: map[string]string{"binding": "local-b", "bindingKind": "RoleBinding", "namespace": "default"}},
		},
	}
}

func wcFor(got []K8sWorkloadCreationFinding, name string) []K8sWorkloadCreationFinding {
	var out []K8sWorkloadCreationFinding
	for _, f := range got {
		if f.Subject == wcDefault+name {
			out = append(out, f)
		}
	}
	return out
}

// TestK8sWorkloadCreate_DeploymentCreateInAnotherNamespaceIsReported checks create on deployments in the apps group
// is reported in the namespace where the grant applies.
func TestK8sWorkloadCreate_DeploymentCreateInAnotherNamespaceIsReported(t *testing.T) {
	got := K8sWorkloadCreationFindings(wcInventory(), completeReport())
	d := wcFor(got, "deployer")
	if len(d) != 1 || d[0].Namespace != "other" || d[0].Resource != "deployments" || d[0].Group != "apps" {
		t.Fatalf("deployer findings = %+v, want create deployments in apps in other", d)
	}
	if len(d[0].Evidence) != 1 || d[0].Evidence[0] != "deployer-b" {
		t.Fatalf("evidence = %v, want deployer-b", d[0].Evidence)
	}
}

// TestK8sWorkloadCreate_APIGroupMustMatch checks a rule naming deployments under the core group does not count.
func TestK8sWorkloadCreate_APIGroupMustMatch(t *testing.T) {
	got := K8sWorkloadCreationFindings(wcInventory(), completeReport())
	if w := wcFor(got, "wrong"); len(w) != 0 {
		t.Fatalf("wrong-group findings = %+v, want none: deployments are in the apps group", w)
	}
}

// TestK8sWorkloadCreate_ClusterWideCreateIsClusterScope checks a ClusterRoleBinding granting create pods is
// reported at cluster scope.
func TestK8sWorkloadCreate_ClusterWideCreateIsClusterScope(t *testing.T) {
	got := K8sWorkloadCreationFindings(wcInventory(), completeReport())
	p := wcFor(got, "pods")
	if len(p) != 1 || p[0].Namespace != "cluster" || p[0].Resource != "pods" {
		t.Fatalf("pods findings = %+v, want create pods at cluster scope", p)
	}
}

// TestK8sWorkloadCreate_HomeNamespaceIsNotReported checks a ServiceAccount creating workloads in its own namespace
// is not reported, since that is its intended scope.
func TestK8sWorkloadCreate_HomeNamespaceIsNotReported(t *testing.T) {
	got := K8sWorkloadCreationFindings(wcInventory(), completeReport())
	if l := wcFor(got, "local"); len(l) != 0 {
		t.Fatalf("local findings = %+v, want none", l)
	}
}
