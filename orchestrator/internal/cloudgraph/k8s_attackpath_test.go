package cloudgraph

import "testing"

// secretReaderRole is a ClusterRole whose rules list secrets cluster-wide: the path target.
const secretReaderRole = `{"items":[{"metadata":{"name":"secret-reader"},"rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get","list"]}]},{"metadata":{"name":"view"},"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["get"]}]},{"metadata":{"name":"binder"},"rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"]}]}]}`

// webBindsCluster binds the web service account to the binder ClusterRole cluster-wide.
const webBindsCluster = `{"items":[{"metadata":{"name":"web-binds"},"subjects":[{"kind":"ServiceAccount","name":"web","namespace":"default"}],"roleRef":{"kind":"ClusterRole","name":"binder"}}]}`

func TestK8sAttackPath_BindPrerequisiteReachesSecretReadingRole(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/clusterroles":        secretReaderRole,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": webBindsCluster,
	})
	paths := K8sAttackPaths(inv, rep)
	var found bool
	for _, p := range paths {
		if p.Workload != testWebPod || p.Subject != testWebSA {
			t.Fatalf("path attached to the wrong workload or subject: %+v", p)
		}
		if p.Target == "k8s://kind-bas-lab/_cluster/clusterrole/secret-reader" {
			found = true
			if p.Prerequisite != "bind-clusterroles" {
				t.Fatalf("prerequisite = %q, want bind-clusterroles", p.Prerequisite)
			}
			if p.Class != k8sClassConfigured {
				t.Fatalf("class = %q, want configured-permission", p.Class)
			}
			if !p.PolicyComplete {
				t.Fatal("the path comes from a complete policy and must say so")
			}
		}
	}
	if !found {
		t.Fatalf("no path to secret-reader in %+v", paths)
	}
}

func TestK8sAttackPath_NoPrerequisiteNoPath(t *testing.T) {
	// The default fixtures grant the web account no bind verb, so no escalation path exists.
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/clusterroles": secretReaderRole,
	})
	if paths := K8sAttackPaths(inv, rep); len(paths) != 0 {
		t.Fatalf("no bind prerequisite, yet paths = %+v", paths)
	}
}

func TestK8sAttackPath_IncompleteDiscoveryIsMarked(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/clusterroles":        secretReaderRole,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": webBindsCluster,
		"/apis/apps/v1/deployments":                              `{"items":[]}`,
	})
	if rep.Complete {
		t.Fatal("fixture should be incomplete")
	}
	paths := K8sAttackPaths(inv, rep)
	if len(paths) == 0 {
		t.Fatal("a granted prerequisite still yields a path under incomplete discovery")
	}
	for _, p := range paths {
		if p.PolicyComplete {
			t.Fatal("a path found under incomplete discovery must say the policy is incomplete")
		}
	}
}
