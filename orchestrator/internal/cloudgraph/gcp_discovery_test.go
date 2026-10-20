package cloudgraph

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/api/option"
)

const gcpProject = "proj-1"

// gcpRoute matches a request path by substring (suffix when suffix is true).
// Routes are tried in order and the first match wins, so specific paths sit
// before general ones.
type gcpRoute struct {
	needle string
	suffix bool
	body   string
}

// gcpFakeAPI serves canned Google API responses. failRole makes one role's
// lookup return 500 on every attempt.
type gcpFakeAPI struct {
	routes   []gcpRoute
	failRole string
}

func (f *gcpFakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.failRole != "" && strings.Contains(r.URL.Path, "/roles/"+f.failRole) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `{"error":{"message":"backend unavailable"}}`)
		return
	}
	for _, rt := range f.routes {
		matched := strings.Contains(r.URL.Path, rt.needle)
		if rt.suffix {
			matched = strings.HasSuffix(r.URL.Path, rt.needle)
		}
		if matched {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, rt.body)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, `{"error":{"message":"no route for `+r.URL.Path+`"}}`)
}

func gcpStandardRoutes() []gcpRoute {
	return []gcpRoute{
		{needle: ":getIamPolicy", body: `{"bindings":[{"role":"roles/storage.objectViewer","members":["user:alice@example.com","allUsers"]},{"role":"roles/owner","members":["group:ops@example.com"],"condition":{"expression":"request.time < timestamp(\"2030-01-01T00:00:00Z\")"}}]}`},
		{needle: "/b/corp-backups/iam", body: `{"bindings":[{"role":"roles/storage.admin","members":["serviceAccount:backup@proj-1.iam.gserviceaccount.com"]}]}`},
		{needle: "/roles/storage.objectViewer", body: `{"name":"roles/storage.objectViewer","includedPermissions":["storage.objects.get","storage.objects.list"]}`},
		{needle: "/roles/storage.admin", body: `{"name":"roles/storage.admin","includedPermissions":["storage.objects.delete","storage.buckets.update"]}`},
		{needle: "/roles/owner", body: `{"name":"roles/owner","includedPermissions":["resourcemanager.projects.delete"]}`},
		{needle: "serviceAccounts", body: `{"accounts":[{"email":"backup@proj-1.iam.gserviceaccount.com"}]}`},
		{needle: "denypolicies", body: `{"policies":[{"name":"deny-alice","rules":[{"denyRule":{"deniedPrincipals":["principal://goog/subject/alice@example.com"],"deniedPermissions":["storage.googleapis.com/objects.get"]}}]}]}`},
		{needle: "/b", suffix: true, body: `{"items":[{"name":"corp-backups"}]}`},
	}
}

func newTestGCPClient(t *testing.T, api *gcpFakeAPI) (*GCPDiscoveryClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	client, err := NewGCPDiscoveryClient(context.Background(), gcpProject,
		option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("NewGCPDiscoveryClient: %v", err)
	}
	return client, srv
}

func gcpPerm(g *DiscoveredGraph, source, action, scope string) *CloudPermission {
	for _, p := range g.Permissions {
		if p.Source.CanonicalID == source && p.Action == action && p.Target.CanonicalID == scope {
			return p
		}
	}
	return nil
}

func TestGCPDiscover_BindingsBecomeEvaluableEdges(t *testing.T) {
	client, _ := newTestGCPClient(t, &gcpFakeAPI{routes: gcpStandardRoutes()})

	graph, stats, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	projectScope := "projects/" + gcpProject
	bucketScope := projectScope + "/buckets/corp-backups"

	alice := gcpPerm(graph, "gcp:user:alice@example.com", "storage.objects.list", projectScope)
	if alice == nil {
		t.Fatal("expected alice storage.objects.list at project scope")
	}
	if got := (&GCPEvaluator{}).EvaluatePermission(alice, &RequestContext{}).State; got != PolicySupported {
		t.Errorf("alice list state = %s, want policy_supported", got)
	}

	backup := gcpPerm(graph, "gcp:serviceAccount:backup@proj-1.iam.gserviceaccount.com", "storage.objects.delete", bucketScope)
	if backup == nil {
		t.Fatal("expected backup SA delete on the bucket scope")
	}
	if got := (&GCPEvaluator{}).EvaluatePermission(backup, &RequestContext{}).State; got != PolicySupported {
		t.Errorf("backup delete state = %s, want policy_supported", got)
	}

	if stats.ConditionalBindings != 1 {
		t.Errorf("ConditionalBindings = %d, want 1 (owner binding carries a condition)", stats.ConditionalBindings)
	}
	if stats.UnmappedMembers != 1 {
		t.Errorf("UnmappedMembers = %d, want 1 (allUsers)", stats.UnmappedMembers)
	}
}

func TestGCPDiscover_ConditionalBindingProducesNoEdges(t *testing.T) {
	client, _ := newTestGCPClient(t, &gcpFakeAPI{routes: gcpStandardRoutes()})
	graph, _, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, p := range graph.Permissions {
		if p.Source.CanonicalID == "gcp:group:ops@example.com" {
			t.Fatalf("conditional owner binding leaked an edge: %s", p.Action)
		}
	}
}

func TestGCPDiscover_DenyRuleBlocksMatchingEdge(t *testing.T) {
	client, _ := newTestGCPClient(t, &gcpFakeAPI{routes: gcpStandardRoutes()})

	graph, stats, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if stats.DenyRules != 1 {
		t.Errorf("DenyRules = %d, want 1", stats.DenyRules)
	}
	projectScope := "projects/" + gcpProject
	denied := gcpPerm(graph, "gcp:user:alice@example.com", "storage.objects.get", projectScope)
	if denied == nil {
		t.Fatal("expected alice storage.objects.get edge")
	}
	if got := (&GCPEvaluator{}).EvaluatePermission(denied, &RequestContext{}).State; got != Blocked {
		t.Errorf("denied edge state = %s, want blocked by deny policy", got)
	}
	// The same deny must not reach a permission it does not name.
	list := gcpPerm(graph, "gcp:user:alice@example.com", "storage.objects.list", projectScope)
	if list == nil {
		t.Fatal("expected alice storage.objects.list edge")
	}
	if got := (&GCPEvaluator{}).EvaluatePermission(list, &RequestContext{}).State; got != PolicySupported {
		t.Errorf("undenied permission state = %s, want policy_supported", got)
	}
}

func TestGCPDiscover_UnreadableRoleFailsPass(t *testing.T) {
	client, _ := newTestGCPClient(t, &gcpFakeAPI{routes: gcpStandardRoutes(), failRole: "storage.admin"})
	graph, _, err := client.Discover(context.Background())
	if err == nil {
		t.Fatal("an unreadable role must fail the pass, not drop its grants")
	}
	if graph != nil {
		t.Error("a failed pass must not return a partial graph")
	}
	if !strings.Contains(err.Error(), "storage.admin") {
		t.Errorf("error should name the role, got %v", err)
	}
}

func TestGCPDiscover_TransientFailureIsRetried(t *testing.T) {
	var fails atomic.Int32
	api := &gcpFakeAPI{routes: gcpStandardRoutes()}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "serviceAccounts") && fails.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		api.ServeHTTP(w, r)
	}))
	defer srv.Close()

	client, err := NewGCPDiscoveryClient(context.Background(), gcpProject,
		option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("NewGCPDiscoveryClient: %v", err)
	}
	if _, _, err := client.Discover(context.Background()); err != nil {
		t.Fatalf("two 503s then success should pass after retry, got %v", err)
	}
	if fails.Load() < 3 {
		t.Errorf("service-account listing attempts = %d, want at least 3", fails.Load())
	}
}

func TestGCPDenyPermissionNormalised(t *testing.T) {
	cases := map[string]string{
		"storage.googleapis.com/objects.delete": "storage.objects.delete",
		"resourcemanager.projects.delete":       "resourcemanager.projects.delete",
	}
	for in, want := range cases {
		if got := gcpDenyPermission(in); got != want {
			t.Errorf("gcpDenyPermission(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGCPDenyPrincipalMapping(t *testing.T) {
	if m, ok := gcpDenyPrincipal("principal://goog/subject/alice@example.com"); !ok || m != "user:alice@example.com" {
		t.Errorf("user mapping = %q, %v", m, ok)
	}
	if _, ok := gcpDenyPrincipal("principalSet://goog/public:allAuthenticatedUsers"); ok {
		t.Error("public principal sets must stay unmapped")
	}
}
