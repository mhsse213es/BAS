package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/k8sscenario"
)

// fakeClusterRegistry is an in-memory registry that enforces the same unique display name and server URL rules.
type fakeClusterRegistry struct {
	mu       sync.Mutex
	clusters []k8sscenario.ClusterRecord
}

func (f *fakeClusterRegistry) Insert(_ context.Context, c k8sscenario.ClusterRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.clusters {
		if e.DisplayName == c.DisplayName || e.ServerURL == c.ServerURL {
			return db.ErrK8sClusterExists
		}
	}
	f.clusters = append(f.clusters, c)
	return nil
}
func (f *fakeClusterRegistry) List(context.Context) ([]k8sscenario.ClusterRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]k8sscenario.ClusterRecord(nil), f.clusters...), nil
}
func (f *fakeClusterRegistry) Get(_ context.Context, id string) (k8sscenario.ClusterRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.clusters {
		if c.ID == id {
			return c, true, nil
		}
	}
	return k8sscenario.ClusterRecord{}, false, nil
}

func clusterHandler(reg K8sClusterRegistry) *Handler {
	return &Handler{k8sScenario: &K8sScenarioService{Registry: reg}}
}

func postCluster(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/clusters", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.RegisterK8sCluster(rec, req)
	return rec
}

func TestRegisterK8sCluster_StoresCanonicalCluster(t *testing.T) {
	reg := &fakeClusterRegistry{}
	h := clusterHandler(reg)
	rec := postCluster(t, h, `{"displayName":"lab-east","serverUrl":"https://K8s.Lab.Example:6443/","class":"lab"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var got k8sClusterView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.ID, "k8sc-") || got.ServerURL != "https://k8s.lab.example:6443" || got.Class != "lab" {
		t.Errorf("unexpected view: %+v", got)
	}
	if len(got.AllowedProfiles) != 3 {
		t.Errorf("lab should allow safe, lab and controlled; got %v", got.AllowedProfiles)
	}
}

func TestRegisterK8sCluster_RefusesDuplicateNameOrServer(t *testing.T) {
	reg := &fakeClusterRegistry{}
	h := clusterHandler(reg)
	if rec := postCluster(t, h, `{"displayName":"prod","serverUrl":"https://a.example","class":"production"}`); rec.Code != http.StatusCreated {
		t.Fatalf("first registration: %d", rec.Code)
	}
	for _, body := range []string{
		`{"displayName":"prod","serverUrl":"https://b.example","class":"lab"}`,
		`{"displayName":"other","serverUrl":"https://a.example","class":"lab"}`,
	} {
		if rec := postCluster(t, h, body); rec.Code != http.StatusConflict {
			t.Errorf("duplicate %s: want 409, got %d", body, rec.Code)
		}
	}
}

func TestRegisterK8sCluster_RefusesInvalidInput(t *testing.T) {
	h := clusterHandler(&fakeClusterRegistry{})
	for name, body := range map[string]string{
		"plain http":    `{"displayName":"x","serverUrl":"http://a.example","class":"lab"}`,
		"missing class": `{"displayName":"x","serverUrl":"https://a.example"}`,
		"unknown class": `{"displayName":"x","serverUrl":"https://a.example","class":"prod"}`,
		"bad name":      `{"displayName":"a/b","serverUrl":"https://a.example","class":"lab"}`,
		"not json":      `{`,
		"unknown field": `{"displayName":"x","serverUrl":"https://a.example","class":"lab","extra":1}`,
	} {
		if rec := postCluster(t, h, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, rec.Code)
		}
	}
}

func TestRegisterK8sCluster_UnconfiguredIs503(t *testing.T) {
	h := &Handler{}
	if rec := postCluster(t, h, `{}`); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/k8s-scenarios/clusters", nil)
	rec := httptest.NewRecorder()
	h.ListK8sClusters(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("list: want 503, got %d", rec.Code)
	}
}

func TestListK8sClusters_ReturnsProfilesPerClass(t *testing.T) {
	reg := &fakeClusterRegistry{}
	h := clusterHandler(reg)
	postCluster(t, h, `{"displayName":"prod","serverUrl":"https://a.example","class":"production"}`)
	req := httptest.NewRequest(http.MethodGet, "/api/k8s-scenarios/clusters", nil)
	rec := httptest.NewRecorder()
	h.ListK8sClusters(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var out []k8sClusterView
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || len(out[0].AllowedProfiles) != 1 || out[0].AllowedProfiles[0] != "safe" {
		t.Errorf("production must list only safe; got %+v", out)
	}
}
