package api

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/k8sscenario"
)

func namespaceRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.Get("/api/k8s-scenarios/clusters/{id}/namespaces", h.ListK8sClusterNamespaces)
	return r
}

func pemOf(srv *httptest.Server) []byte {
	cert := srv.Certificate()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// fakeAPIServer answers the namespace list and checks the bearer token it receives.
func fakeAPIServer(t *testing.T, wantToken string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+wantToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			http.Error(w, "boom", status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{
			map[string]any{"metadata": map[string]any{"name": "zeta"}},
			map[string]any{"metadata": map[string]any{"name": "alpha"}},
		}})
	}))
}

func namespacesRequest(t *testing.T, h *Handler, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/k8s-scenarios/clusters/"+id+"/namespaces", nil)
	rec := httptest.NewRecorder()
	namespaceRouter(h).ServeHTTP(rec, req)
	return rec
}

func TestListK8sClusterNamespaces_ReturnsSortedNames(t *testing.T) {
	srv := fakeAPIServer(t, "tok-1", http.StatusOK)
	defer srv.Close()
	reg := &fakeClusterRegistry{clusters: []k8sscenario.ClusterRecord{
		{ID: "k8sc-1", DisplayName: "lab-east", ServerURL: srv.URL, Class: k8sscenario.ClassLab},
	}}
	h := &Handler{k8sScenario: &K8sScenarioService{Registry: reg,
		Credentials: func(name string) (string, []byte, error) {
			if name != "lab-east" {
				t.Errorf("credential asked for %q", name)
			}
			return "tok-1", pemOf(srv), nil
		}}}
	rec := namespacesRequest(t, h, "k8sc-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Namespaces []string `json:"namespaces"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Namespaces) != 2 || out.Namespaces[0] != "alpha" || out.Namespaces[1] != "zeta" {
		t.Errorf("want sorted [alpha zeta], got %v", out.Namespaces)
	}
}

func TestListK8sClusterNamespaces_Refusals(t *testing.T) {
	srv := fakeAPIServer(t, "tok-1", http.StatusOK)
	defer srv.Close()
	reg := &fakeClusterRegistry{clusters: []k8sscenario.ClusterRecord{
		{ID: "k8sc-1", DisplayName: "lab-east", ServerURL: srv.URL, Class: k8sscenario.ClassLab},
	}}
	noCred := func(string) (string, []byte, error) { return "", nil, ErrK8sClusterNoCredential }

	cases := []struct {
		name string
		h    *Handler
		id   string
		want int
	}{
		{"unknown cluster", &Handler{k8sScenario: &K8sScenarioService{Registry: reg, Credentials: noCred}}, "nope", http.StatusNotFound},
		{"no credential configured", &Handler{k8sScenario: &K8sScenarioService{Registry: reg, Credentials: noCred}}, "k8sc-1", http.StatusConflict},
		{"no credential source at all", &Handler{k8sScenario: &K8sScenarioService{Registry: reg}}, "k8sc-1", http.StatusConflict},
		{"registry not configured", &Handler{k8sScenario: &K8sScenarioService{}}, "k8sc-1", http.StatusServiceUnavailable},
		{"wrong token from source", &Handler{k8sScenario: &K8sScenarioService{Registry: reg,
			Credentials: func(string) (string, []byte, error) { return "bad", pemOf(srv), nil }}}, "k8sc-1", http.StatusBadGateway},
	}
	for _, c := range cases {
		if rec := namespacesRequest(t, c.h, c.id); rec.Code != c.want {
			t.Errorf("%s: want %d, got %d: %s", c.name, c.want, rec.Code, rec.Body.String())
		}
	}
}

func TestListK8sClusterNamespaces_ServerErrorIs502(t *testing.T) {
	srv := fakeAPIServer(t, "tok-1", http.StatusInternalServerError)
	defer srv.Close()
	reg := &fakeClusterRegistry{clusters: []k8sscenario.ClusterRecord{
		{ID: "k8sc-1", DisplayName: "lab-east", ServerURL: srv.URL, Class: k8sscenario.ClassLab},
	}}
	h := &Handler{k8sScenario: &K8sScenarioService{Registry: reg,
		Credentials: func(string) (string, []byte, error) { return "tok-1", pemOf(srv), nil }}}
	if rec := namespacesRequest(t, h, "k8sc-1"); rec.Code != http.StatusBadGateway {
		t.Errorf("want 502, got %d", rec.Code)
	}
}
