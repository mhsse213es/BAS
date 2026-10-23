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

const (
	// opsServiceAccounts lists the web and ops service accounts in the default namespace.
	opsServiceAccounts = `{"items":[{"metadata":{"name":"web","namespace":"default"}},{"metadata":{"name":"ops","namespace":"default"}}]}`
	// escalatorRoles adds the escalate and impersonate verbs as ClusterRoles, alongside the secret reader.
	escalatorRoles = `{"items":[{"metadata":{"name":"secret-reader"},"rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get","list"]}]},{"metadata":{"name":"escalator"},"rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["escalate"]}]},{"metadata":{"name":"impersonator"},"rules":[{"apiGroups":[""],"resources":["serviceaccounts"],"verbs":["impersonate"]}]}]}`
)

func TestK8sEscalation_EscalateVerbReachesSecretReadingRole(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/clusterroles":        escalatorRoles,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": `{"items":[{"metadata":{"name":"web-escalates"},"subjects":[{"kind":"ServiceAccount","name":"web","namespace":"default"}],"roleRef":{"kind":"ClusterRole","name":"escalator"}}]}`,
	})
	var found bool
	for _, p := range K8sAttackPaths(inv, rep) {
		if p.Prerequisite == "escalate-clusterroles" && p.Target == "k8s://kind-bas-lab/_cluster/clusterrole/secret-reader" {
			found = true
		}
	}
	if !found {
		t.Fatal("escalate on ClusterRoles should reach the secret-reading ClusterRole")
	}
}

func TestK8sEscalation_ImpersonateReachesSecretReadingServiceAccount(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/clusterroles": escalatorRoles,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": `{"items":[` +
			`{"metadata":{"name":"web-impersonates"},"subjects":[{"kind":"ServiceAccount","name":"web","namespace":"default"}],"roleRef":{"kind":"ClusterRole","name":"impersonator"}},` +
			`{"metadata":{"name":"ops-secrets"},"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"default"}],"roleRef":{"kind":"ClusterRole","name":"secret-reader"}}]}`,
		"/api/v1/serviceaccounts": opsServiceAccounts,
	})
	var found bool
	for _, p := range K8sAttackPaths(inv, rep) {
		if p.Prerequisite == "impersonate-serviceaccounts" && p.Target == "k8s://kind-bas-lab/default/serviceaccount/ops" {
			found = true
		}
	}
	if !found {
		t.Fatal("impersonation should reach a service account that can read secrets")
	}
}

func TestK8sEscalation_CreatePodsReachesSameNamespaceServiceAccount(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/clusterroles":        escalatorRoles,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": `{"items":[{"metadata":{"name":"ops-secrets"},"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"default"}],"roleRef":{"kind":"ClusterRole","name":"secret-reader"}}]}`,
		"/api/v1/serviceaccounts":                                opsServiceAccounts,
		"/apis/rbac.authorization.k8s.io/v1/roles":               `{"items":[{"metadata":{"name":"reader","namespace":"default"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]},{"metadata":{"name":"maker","namespace":"default"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]}]}`,
		"/apis/rbac.authorization.k8s.io/v1/rolebindings":        `{"items":[{"metadata":{"name":"web-makes","namespace":"default"},"subjects":[{"kind":"ServiceAccount","name":"web","namespace":"default"}],"roleRef":{"kind":"Role","name":"maker"}}]}`,
	})
	var found bool
	for _, p := range K8sAttackPaths(inv, rep) {
		if p.Prerequisite == "create-pods" && p.Target == "k8s://kind-bas-lab/default/serviceaccount/ops" {
			found = true
		}
	}
	if !found {
		t.Fatal("pod creation in a namespace should reach a same-namespace service account that reads secrets")
	}
}

func TestK8sEscalation_TokenRequestReachesSecretReadingServiceAccount(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/clusterroles":        escalatorRoles,
		"/api/v1/serviceaccounts":                                opsServiceAccounts,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": `{"items":[{"metadata":{"name":"ops-secrets"},"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"default"}],"roleRef":{"kind":"ClusterRole","name":"secret-reader"}}]}`,
		"/apis/rbac.authorization.k8s.io/v1/roles":               `{"items":[{"metadata":{"name":"reader","namespace":"default"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]},{"metadata":{"name":"tokener","namespace":"default"},"rules":[{"apiGroups":[""],"resources":["serviceaccounts/token"],"verbs":["create"]}]}]}`,
		"/apis/rbac.authorization.k8s.io/v1/rolebindings":        `{"items":[{"metadata":{"name":"web-tokens","namespace":"default"},"subjects":[{"kind":"ServiceAccount","name":"web","namespace":"default"}],"roleRef":{"kind":"Role","name":"tokener"}}]}`,
	})
	var found bool
	for _, p := range K8sAttackPaths(inv, rep) {
		if p.Prerequisite == "request-serviceaccount-token" && p.Target == "k8s://kind-bas-lab/default/serviceaccount/ops" {
			found = true
		}
	}
	if !found {
		t.Fatal("requesting a token should reach a same-namespace service account that reads secrets")
	}
}

func TestK8sEscalation_ExecReachesPodRunningSecretReadingServiceAccount(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/clusterroles":        escalatorRoles,
		"/api/v1/serviceaccounts":                                opsServiceAccounts,
		"/api/v1/pods":                                           `{"items":[{"metadata":{"name":"web-1","namespace":"default"},"spec":{"serviceAccountName":"web"}},{"metadata":{"name":"ops-1","namespace":"default"},"spec":{"serviceAccountName":"ops"}}]}`,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": `{"items":[{"metadata":{"name":"ops-secrets"},"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"default"}],"roleRef":{"kind":"ClusterRole","name":"secret-reader"}}]}`,
		"/apis/rbac.authorization.k8s.io/v1/roles":               `{"items":[{"metadata":{"name":"reader","namespace":"default"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]},{"metadata":{"name":"execer","namespace":"default"},"rules":[{"apiGroups":[""],"resources":["pods/exec"],"verbs":["create"]}]}]}`,
		"/apis/rbac.authorization.k8s.io/v1/rolebindings":        `{"items":[{"metadata":{"name":"web-execs","namespace":"default"},"subjects":[{"kind":"ServiceAccount","name":"web","namespace":"default"}],"roleRef":{"kind":"Role","name":"execer"}}]}`,
	})
	var found bool
	for _, p := range K8sAttackPaths(inv, rep) {
		if p.Prerequisite == "exec-into-pods" && p.Target == "k8s://kind-bas-lab/default/pod/ops-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("exec into a pod running a secret-reading service account should be a path")
	}
}

func TestK8sEscalation_NodeProxyReachesPodRunningSecretReadingServiceAccount(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/clusterroles": `{"items":[{"metadata":{"name":"secret-reader"},"rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get","list"]}]},{"metadata":{"name":"node-proxier"},"rules":[{"apiGroups":[""],"resources":["nodes/proxy"],"verbs":["get"]}]}]}`,
		"/api/v1/serviceaccounts": opsServiceAccounts,
		"/api/v1/pods": `{"items":[{"metadata":{"name":"web-1","namespace":"default"},"spec":{"serviceAccountName":"web","nodeName":"n1"}},{"metadata":{"name":"ops-1","namespace":"default"},"spec":{"serviceAccountName":"ops","nodeName":"n1"}}]}`,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": `{"items":[{"metadata":{"name":"web-proxies"},"subjects":[{"kind":"ServiceAccount","name":"web","namespace":"default"}],"roleRef":{"kind":"ClusterRole","name":"node-proxier"}},{"metadata":{"name":"ops-secrets"},"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"default"}],"roleRef":{"kind":"ClusterRole","name":"secret-reader"}}]}`,
	})
	var found bool
	for _, p := range K8sAttackPaths(inv, rep) {
		if p.Prerequisite == "proxy-nodes" && p.Target == "k8s://kind-bas-lab/default/pod/ops-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("node proxy should reach a pod running a secret-reading service account")
	}
	if got := findRes(inv.Resources, "k8s://kind-bas-lab/default/pod/ops-1").Attributes["node"]; got != "n1" {
		t.Fatalf("pod node = %q, want n1", got)
	}
}
