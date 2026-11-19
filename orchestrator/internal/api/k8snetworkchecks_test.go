package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/audspect/bas/internal/k8sscenario"
)

func networkHandler(srv *httptest.Server, class string, token string) *Handler {
	reg := &fakeClusterRegistry{clusters: []k8sscenario.ClusterRecord{
		{ID: "k8sc-1", DisplayName: "lab-east", ServerURL: srv.URL, Class: class},
	}}
	return &Handler{k8sScenario: &K8sScenarioService{Registry: reg,
		Credentials: func(string) (string, []byte, error) { return token, pemOf(srv), nil }}}
}

func runNetwork(t *testing.T, h *Handler, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/network-checks/run", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.RunK8sNetworkCheck(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// A non-lab cluster must be refused before any request reaches it. The server counts every request it receives.
func TestRunK8sNetworkCheck_NonLabClusterSeesNoRequests(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	for _, class := range []string{k8sscenario.ClassNonProduction, k8sscenario.ClassProduction} {
		code, out := runNetwork(t, networkHandler(srv, class, "tok"),
			`{"clusterId":"k8sc-1","checkId":"api-server-reachability-from-workload","namespace":"np-app"}`)
		if code != http.StatusForbidden {
			t.Errorf("%s: want 403, got %d: %v", class, code, out)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("a non-lab cluster received %d requests; none may", hits.Load())
	}
}

func TestRunK8sNetworkCheck_Refusals(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	lab := networkHandler(srv, k8sscenario.ClassLab, "tok")
	noCred := &Handler{k8sScenario: &K8sScenarioService{Registry: lab.k8sScenario.Registry,
		Credentials: func(string) (string, []byte, error) { return "", nil, ErrK8sClusterNoCredential }}}
	cases := []struct {
		name string
		h    *Handler
		body string
		want int
	}{
		{"unknown check", lab, `{"clusterId":"k8sc-1","checkId":"delete-everything","namespace":"np-app"}`, http.StatusBadRequest},
		{"bad probe namespace", lab, `{"clusterId":"k8sc-1","checkId":"api-server-reachability-from-workload","namespace":"Bad/NS"}`, http.StatusBadRequest},
		{"bad target namespace", lab, `{"clusterId":"k8sc-1","checkId":"cross-namespace-service-reachability","namespace":"np-app","targetNamespace":"x y"}`, http.StatusBadRequest},
		{"unknown cluster", lab, `{"clusterId":"nope","checkId":"api-server-reachability-from-workload","namespace":"np-app"}`, http.StatusNotFound},
		{"no credential", noCred, `{"clusterId":"k8sc-1","checkId":"api-server-reachability-from-workload","namespace":"np-app"}`, http.StatusConflict},
		{"unknown field", lab, `{"clusterId":"k8sc-1","checkId":"api-server-reachability-from-workload","namespace":"np-app","x":1}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		if code, out := runNetwork(t, c.h, c.body); code != c.want {
			t.Errorf("%s: want %d, got %d: %v", c.name, c.want, code, out)
		}
	}
}
