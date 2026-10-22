package cloudgraph

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// k8sFixtures is a small, complete cluster: one namespace, a pod, a service account, a Role,
// a ClusterRole, a RoleBinding to the service account and a ClusterRoleBinding to a user.
var k8sFixtures = map[string]string{
	"/api/v1/namespaces": `{"items":[{"metadata":{"name":"default"}}]}`,
	"/api/v1/pods": `{"items":[{"metadata":{"name":"web-1","namespace":"default",
		"ownerReferences":[{"kind":"ReplicaSet","name":"web-7d"}]},"spec":{"serviceAccountName":"web"}}]}`,
	"/api/v1/serviceaccounts": `{"items":[{"metadata":{"name":"web","namespace":"default"}}]}`,
	"/apis/rbac.authorization.k8s.io/v1/roles": `{"items":[{"metadata":{"name":"reader","namespace":"default"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]}]}`,
	"/apis/rbac.authorization.k8s.io/v1/clusterroles": `{"items":[{"metadata":{"name":"view"},
		"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["get"]}]}]}`,
	"/apis/rbac.authorization.k8s.io/v1/rolebindings": `{"items":[{"metadata":{"name":"web-reads","namespace":"default"},
		"subjects":[{"kind":"ServiceAccount","name":"web","namespace":"default"}],
		"roleRef":{"kind":"Role","name":"reader"}}]}`,
	"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": `{"items":[{"metadata":{"name":"alice-views"},
		"subjects":[{"kind":"User","name":"alice","apiGroup":"rbac.authorization.k8s.io"}],
		"roleRef":{"kind":"ClusterRole","name":"view"}}]}`,
}

// k8sRecorder records every request method the discovery client makes.
type k8sRecorder struct {
	mu      sync.Mutex
	methods []string
}

func (r *k8sRecorder) add(m string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.methods = append(r.methods, m)
}

// newK8sTestServer serves the routes over TLS. Requests without the right bearer token get 401.
func newK8sTestServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, rec *k8sRecorder)) (*httptest.Server, *k8sRecorder) {
	t.Helper()
	rec := &k8sRecorder{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Method)
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler(w, r, rec)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

// serveRoutes answers from a route table; overrides replace individual routes.
func serveRoutes(overrides map[string]string) func(w http.ResponseWriter, r *http.Request, rec *k8sRecorder) {
	routes := map[string]string{}
	for k, v := range k8sFixtures {
		routes[k] = v
	}
	for k, v := range overrides {
		routes[k] = v
	}
	return func(w http.ResponseWriter, r *http.Request, _ *k8sRecorder) {
		body, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func k8sCAPEM(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func k8sClient(t *testing.T, srv *httptest.Server, mutate func(*K8sDiscoveryConfig)) *K8sDiscoveryClient {
	t.Helper()
	cfg := K8sDiscoveryConfig{ClusterName: "kind-bas-lab", APIServer: srv.URL, Token: "test-token", CAPEM: k8sCAPEM(srv)}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := NewK8sDiscoveryClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func findRes(list []*CloudResource, id string) *CloudResource {
	for _, r := range list {
		if r.CanonicalID == id {
			return r
		}
	}
	return nil
}

func findIdent(list []*CloudIdentity, id string) *CloudIdentity {
	for _, i := range list {
		if i.CanonicalID == id {
			return i
		}
	}
	return nil
}

func containsGap(gaps []string, s string) bool {
	for _, g := range gaps {
		if strings.Contains(g, s) {
			return true
		}
	}
	return false
}

func TestK8sDiscovery_CompleteInventoryFromFixtures(t *testing.T) {
	srv, _ := newK8sTestServer(t, serveRoutes(nil))
	inv, rep, err := k8sClient(t, srv, nil).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Complete || len(rep.Gaps) != 0 {
		t.Fatalf("complete=%v gaps=%v, want complete with no gaps", rep.Complete, rep.Gaps)
	}
	if rep.Source != "kubernetes-api" || rep.ClusterName != "kind-bas-lab" || rep.ObservedAt.IsZero() {
		t.Fatalf("report lacks source, cluster or timestamp: %+v", rep)
	}
	if findRes(inv.Resources, "k8s://kind-bas-lab/default/pod/web-1") == nil {
		t.Fatal("pod missing from inventory")
	}
	if findRes(inv.Resources, "k8s://kind-bas-lab/default/role/reader") == nil {
		t.Fatal("Role missing from inventory")
	}
	if findRes(inv.Resources, "k8s://kind-bas-lab/_cluster/clusterrole/view") == nil {
		t.Fatal("ClusterRole missing from inventory")
	}
	if findIdent(inv.Identities, "k8s://kind-bas-lab/default/serviceaccount/web") == nil {
		t.Fatal("service account missing from inventory")
	}
	if findIdent(inv.Identities, "k8s://kind-bas-lab/_cluster/user/alice") == nil {
		t.Fatal("user subject missing from inventory")
	}
	if len(inv.Permissions) != 2 {
		t.Fatalf("permissions = %d, want 2 (one per binding subject)", len(inv.Permissions))
	}
	for _, p := range inv.Permissions {
		if p.Provenance == nil || !strings.HasPrefix(p.Provenance.Source, "kubernetes-api:") {
			t.Fatalf("permission lacks kubernetes provenance: %+v", p.Provenance)
		}
		if p.Target == nil || p.Source == nil {
			t.Fatal("permission must link an identity to a role")
		}
	}
}

func TestK8sDiscovery_ForbiddenListIsIncompleteNotComplete(t *testing.T) {
	serve := serveRoutes(nil)
	srv, _ := newK8sTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *k8sRecorder) {
		if r.URL.Path == "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		serve(w, r, rec)
	})
	_, rep, err := k8sClient(t, srv, nil).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete {
		t.Fatal("a forbidden list must never be reported as complete coverage")
	}
	if !containsGap(rep.Gaps, "clusterrolebindings") {
		t.Fatalf("gaps %v do not name the forbidden list", rep.Gaps)
	}
}

func TestK8sDiscovery_PagedListFollowsContinueToTheEnd(t *testing.T) {
	serve := serveRoutes(map[string]string{
		"/api/v1/pods": `{"metadata":{"continue":"page2"},"items":[{"metadata":{"name":"a","namespace":"default"}}]}`,
	})
	srv, _ := newK8sTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *k8sRecorder) {
		if r.URL.Path == "/api/v1/pods" && r.URL.Query().Get("continue") == "page2" {
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"b","namespace":"default"}}]}`))
			return
		}
		serve(w, r, rec)
	})
	inv, rep, err := k8sClient(t, srv, nil).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if findRes(inv.Resources, "k8s://kind-bas-lab/default/pod/a") == nil || findRes(inv.Resources, "k8s://kind-bas-lab/default/pod/b") == nil {
		t.Fatal("pods from both pages must be discovered")
	}
	if !rep.Complete {
		t.Fatalf("a fully paged list should be complete, gaps=%v", rep.Gaps)
	}
}

func TestK8sDiscovery_PageCapMarksInventoryPartial(t *testing.T) {
	serve := serveRoutes(map[string]string{
		"/api/v1/pods": `{"metadata":{"continue":"more"},"items":[]}`,
	})
	srv, _ := newK8sTestServer(t, serve)
	_, rep, err := k8sClient(t, srv, func(cfg *K8sDiscoveryConfig) { cfg.MaxPages = 2 }).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete {
		t.Fatal("hitting the page cap must make the inventory partial")
	}
	if !containsGap(rep.Gaps, "partial") {
		t.Fatalf("gaps %v do not say the inventory is partial", rep.Gaps)
	}
}

func TestK8sDiscovery_RejectedCredentialsAreAnError(t *testing.T) {
	srv, _ := newK8sTestServer(t, serveRoutes(nil))
	_, _, err := k8sClient(t, srv, func(cfg *K8sDiscoveryConfig) { cfg.Token = "wrong" }).Discover(context.Background())
	if !errors.Is(err, ErrK8sUnauthorized) {
		t.Fatalf("err = %v, want ErrK8sUnauthorized", err)
	}
}

func TestK8sDiscovery_IsReadOnly_OnlyGetRequests(t *testing.T) {
	srv, rec := newK8sTestServer(t, serveRoutes(nil))
	if _, _, err := k8sClient(t, srv, nil).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.methods) == 0 {
		t.Fatal("discovery made no requests")
	}
	for _, m := range rec.methods {
		if m != http.MethodGet {
			t.Fatalf("discovery issued a %s request; discovery must be read-only", m)
		}
	}
}

func TestK8sDiscovery_UnlistedRoleReferenceIsAGap(t *testing.T) {
	srv, _ := newK8sTestServer(t, serveRoutes(map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/roles": `{"items":[]}`,
	}))
	_, rep, err := k8sClient(t, srv, nil).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete || !containsGap(rep.Gaps, "reader") {
		t.Fatalf("a binding to a role that was not listed must be a gap; complete=%v gaps=%v", rep.Complete, rep.Gaps)
	}
}

func TestNewK8sDiscoveryClient_RequiresHTTPSAndToken(t *testing.T) {
	base := K8sDiscoveryConfig{ClusterName: "c", APIServer: "http://insecure", Token: "t"}
	if _, err := NewK8sDiscoveryClient(base); err == nil {
		t.Fatal("plain http API server must be refused")
	}
	base.APIServer = "https://10.0.0.1:6443"
	base.Token = ""
	if _, err := NewK8sDiscoveryClient(base); err == nil {
		t.Fatal("missing token must be refused")
	}
}
