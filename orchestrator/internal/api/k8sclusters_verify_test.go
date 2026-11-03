package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/k8sscenario"
)

func verifyRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.Post("/api/k8s-scenarios/clusters/{id}/verify", h.VerifyK8sCluster)
	return r
}

func verifyRequest(t *testing.T, h *Handler, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/clusters/"+id+"/verify", nil)
	rec := httptest.NewRecorder()
	verifyRouter(h).ServeHTTP(rec, req)
	return rec
}

func versionServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"gitVersion":"v1.30.4"}`))
	}))
}

func TestVerifyK8sCluster_PinsIdentityThenAcceptsSameAndRefusesChange(t *testing.T) {
	srv := versionServer(t, "tok")
	defer srv.Close()
	reg := &fakeClusterRegistry{clusters: []k8sscenario.ClusterRecord{
		{ID: "k8sc-1", DisplayName: "lab-east", ServerURL: srv.URL, Class: k8sscenario.ClassLab},
	}}
	h := &Handler{k8sScenario: &K8sScenarioService{Registry: reg,
		Credentials: func(string) (string, []byte, error) { return "tok", pemOf(srv), nil }}}

	rec := verifyRequest(t, h, "k8sc-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("first verify: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var view k8sClusterView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Version != "v1.30.4" || view.SPKIHash == "" || view.CAFingerprint == "" || view.VerifiedAt == nil {
		t.Errorf("identity not recorded: %+v", view)
	}
	if reg.clusters[0].SPKIHash != view.SPKIHash {
		t.Error("identity was not stored")
	}

	// Same server again: the pinned identity still matches.
	if rec := verifyRequest(t, h, "k8sc-1"); rec.Code != http.StatusOK {
		t.Errorf("re-verify of the same cluster: want 200, got %d", rec.Code)
	}

	// The stored identity is now a different one (simulating a cluster whose CA or key changed).
	reg.clusters[0].SPKIHash = "pinned-something-else"
	if rec := verifyRequest(t, h, "k8sc-1"); rec.Code != http.StatusConflict {
		t.Errorf("changed identity: want 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestVerifyK8sCluster_Refusals(t *testing.T) {
	srv := versionServer(t, "tok")
	defer srv.Close()
	wrongCA := unrelatedCAPEM(t)
	reg := &fakeClusterRegistry{clusters: []k8sscenario.ClusterRecord{
		{ID: "k8sc-1", DisplayName: "lab-east", ServerURL: srv.URL, Class: k8sscenario.ClassLab},
	}}
	cases := []struct {
		name string
		h    *Handler
		id   string
		want int
	}{
		{"unknown cluster", &Handler{k8sScenario: &K8sScenarioService{Registry: reg}}, "nope", http.StatusNotFound},
		{"no credential", &Handler{k8sScenario: &K8sScenarioService{Registry: reg,
			Credentials: func(string) (string, []byte, error) { return "", nil, ErrK8sClusterNoCredential }}}, "k8sc-1", http.StatusConflict},
		{"certificate does not verify against the CA", &Handler{k8sScenario: &K8sScenarioService{Registry: reg,
			Credentials: func(string) (string, []byte, error) { return "tok", wrongCA, nil }}}, "k8sc-1", http.StatusBadGateway},
		{"credential rejected", &Handler{k8sScenario: &K8sScenarioService{Registry: reg,
			Credentials: func(string) (string, []byte, error) { return "wrong", pemOf(srv), nil }}}, "k8sc-1", http.StatusBadGateway},
		{"registry not configured", &Handler{k8sScenario: &K8sScenarioService{}}, "k8sc-1", http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		if rec := verifyRequest(t, c.h, c.id); rec.Code != c.want {
			t.Errorf("%s: want %d, got %d: %s", c.name, c.want, rec.Code, rec.Body.String())
		}
	}
	if reg.clusters[0].SPKIHash != "" {
		t.Error("a failed verification must not store an identity")
	}
}
