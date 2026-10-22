package cloudgraph

import (
	"context"
	"net/http"
	"testing"
)

const (
	testWebSA  = "k8s://kind-bas-lab/default/serviceaccount/web"
	testAlice  = "k8s://kind-bas-lab/_cluster/user/alice"
	testWebPod = "k8s://kind-bas-lab/default/pod/web-1"
)

// analysisFor runs discovery against the fixture cluster with optional route overrides.
func analysisFor(t *testing.T, overrides map[string]string) (*K8sInventory, *K8sDiscoveryReport) {
	t.Helper()
	srv, _ := newK8sTestServer(t, serveRoutes(overrides))
	inv, rep, err := k8sClient(t, srv, nil).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return inv, rep
}

func TestK8sAccess_NamespacedRoleOnlyInItsNamespace(t *testing.T) {
	inv, rep := analysisFor(t, nil)
	got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testWebSA, Namespace: "default", Request: RBACRequest{Resource: "pods", Verb: "get", Name: "web-1"}})
	if got.Decision != RBACGranted || len(got.Evidence) != 1 || got.Evidence[0] != "web-reads" {
		t.Fatalf("get pods in default = %+v, want granted via web-reads", got)
	}
	other := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testWebSA, Namespace: "other", Request: RBACRequest{Resource: "pods", Verb: "get"}})
	if other.Decision != RBACNotGranted {
		t.Fatalf("a RoleBinding must not apply in another namespace: %+v", other)
	}
}

func TestK8sAccess_ClusterRoleBoundByRoleBindingStaysInItsNamespace(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/rolebindings": `{"items":[{"metadata":{"name":"web-view","namespace":"default"},"subjects":[{"kind":"ServiceAccount","name":"web","namespace":"default"}],"roleRef":{"kind":"ClusterRole","name":"view"}}]}`,
	})
	req := RBACRequest{Resource: "secrets", Verb: "get"}
	if got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testWebSA, Namespace: "default", Request: req}); got.Decision != RBACGranted {
		t.Fatalf("view via RoleBinding in default = %+v, want granted", got)
	}
	if got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testWebSA, Namespace: "other", Request: req}); got.Decision != RBACNotGranted {
		t.Fatalf("a ClusterRole bound by a RoleBinding must not apply in another namespace: %+v", got)
	}
	if got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testWebSA, Namespace: "", Request: req}); got.Decision != RBACNotGranted {
		t.Fatalf("a RoleBinding must not grant a cluster-scoped request: %+v", got)
	}
}

func TestK8sAccess_ClusterRoleBindingAppliesEverywhere(t *testing.T) {
	inv, rep := analysisFor(t, nil)
	get := RBACRequest{Resource: "secrets", Verb: "get"}
	for _, ns := range []string{"default", "other", ""} {
		if got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testAlice, Namespace: ns, Request: get}); got.Decision != RBACGranted {
			t.Fatalf("alice (view) in namespace %q = %+v, want granted", ns, got)
		}
	}
	create := RBACRequest{Resource: "pods", Verb: "create"}
	if got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testAlice, Namespace: "default", Request: create}); got.Decision != RBACNotGranted {
		t.Fatalf("view grants get only, not create: %+v", got)
	}
}

func TestK8sAccess_UnresolvedBindingIsUnknownNotDenied(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/roles": `{"items":[]}`,
	})
	got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testWebSA, Namespace: "default", Request: RBACRequest{Resource: "secrets", Verb: "get"}})
	if got.Decision != RBACUnknown {
		t.Fatalf("decision = %s, want unknown", got.Decision)
	}
	if len(got.Unresolved) != 1 || got.Unresolved[0] != "web-reads" {
		t.Fatalf("unresolved = %v, want [web-reads]", got.Unresolved)
	}
}

func TestK8sAccess_IncompleteDiscoveryIsUnknown(t *testing.T) {
	serve := serveRoutes(nil)
	srv, _ := newK8sTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *k8sRecorder) {
		if r.URL.Path == "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		serve(w, r, rec)
	})
	inv, rep, err := k8sClient(t, srv, nil).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testAlice, Request: RBACRequest{Resource: "secrets", Verb: "get"}}); got.Decision != RBACUnknown {
		t.Fatalf("alice's binding was never read, so absence must be unknown; got %s", got.Decision)
	}
	if got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testWebSA, Namespace: "default", Request: RBACRequest{Resource: "pods", Verb: "get"}}); got.Decision != RBACGranted {
		t.Fatalf("a grant found under incomplete discovery must stay granted; got %s", got.Decision)
	}
}

func TestK8sAccess_GroupBindingReachesServiceAccounts(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": `{"items":[{"metadata":{"name":"sa-view"},"subjects":[{"kind":"Group","name":"system:serviceaccounts","apiGroup":"rbac.authorization.k8s.io"}],"roleRef":{"kind":"ClusterRole","name":"view"}}]}`,
	})
	got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testWebSA, Request: RBACRequest{Resource: "configmaps", Verb: "get"}})
	if got.Decision != RBACGranted || len(got.Evidence) != 1 || got.Evidence[0] != "sa-view" {
		t.Fatalf("system:serviceaccounts group binding = %+v, want granted via sa-view", got)
	}
	if got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testAlice, Request: RBACRequest{Resource: "configmaps", Verb: "get"}}); got.Decision != RBACNotGranted {
		t.Fatalf("alice is not a service account and must not inherit system:serviceaccounts: %+v", got)
	}
}

func TestK8sAccess_ResourceNameRestrictionIsHonoured(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/roles": `{"items":[{"metadata":{"name":"reader","namespace":"default"},"rules":[{"apiGroups":[""],"resources":["secrets"],"resourceNames":["app-db"],"verbs":["get"]}]}]}`,
	})
	decide := func(name, verb string) RBACDecision {
		return AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testWebSA, Namespace: "default", Request: RBACRequest{Resource: "secrets", Verb: verb, Name: name}}).Decision
	}
	if got := decide("app-db", "get"); got != RBACGranted {
		t.Fatalf("get the named secret app-db = %s, want granted", got)
	}
	if got := decide("other", "get"); got != RBACNotGranted {
		t.Fatalf("get a different secret = %s, want not-granted", got)
	}
	if got := decide("", "get"); got != RBACNotGranted {
		t.Fatalf("a get without a name is not the named secret = %s, want not-granted", got)
	}
	if got := decide("app-db", "list"); got != RBACNotGranted {
		t.Fatalf("list is not granted by a get-only rule = %s, want not-granted", got)
	}
}

func TestK8sAccess_MultipleBindingsAreAdditiveWithEvidence(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/rolebindings": `{"items":[{"metadata":{"name":"web-reads","namespace":"default"},"subjects":[{"kind":"ServiceAccount","name":"web","namespace":"default"}],"roleRef":{"kind":"Role","name":"reader"}},{"metadata":{"name":"web-view","namespace":"default"},"subjects":[{"kind":"ServiceAccount","name":"web","namespace":"default"}],"roleRef":{"kind":"ClusterRole","name":"view"}}]}`,
	})
	got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testWebSA, Namespace: "default", Request: RBACRequest{Resource: "pods", Verb: "get"}})
	if got.Decision != RBACGranted || len(got.Evidence) != 2 {
		t.Fatalf("both bindings grant get pods; got %+v", got)
	}
}

func TestK8sPrivilegeFindings_WorkloadPathsAreConfiguredPermissions(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/roles": `{"items":[{"metadata":{"name":"reader","namespace":"default"},"rules":[{"apiGroups":[""],"resources":["pods","secrets"],"verbs":["get","list"]}]}]}`,
	})
	caps := map[string]bool{}
	for _, f := range K8sPrivilegeFindings(inv, rep) {
		if f.Workload != testWebPod || f.Subject != testWebSA {
			t.Fatalf("finding attached to the wrong workload or subject: %+v", f)
		}
		if f.Class != k8sClassConfigured {
			t.Fatalf("class = %q, want configured-permission", f.Class)
		}
		caps[f.Capability] = true
	}
	if !caps["list-secrets"] || !caps["get-secrets"] {
		t.Fatalf("expected the secret-read findings, got %v", caps)
	}
	if caps["create-pods"] || caps["exec-into-pods"] || caps["create-rolebindings"] {
		t.Fatalf("no write or exec capability was granted, got %v", caps)
	}
}
