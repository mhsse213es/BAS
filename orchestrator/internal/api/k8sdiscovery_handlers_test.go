package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudgraph"
)

type fakeAnalysisRunner struct {
	res cloudgraph.K8sAnalysis
	err error
}

func (f fakeAnalysisRunner) Run(context.Context) (cloudgraph.K8sAnalysis, error) { return f.res, f.err }

func analysisRouter(h *Handler) *chi.Mux {
	r := chi.NewRouter()
	r.Get("/api/k8s-discovery/analysis", h.GetK8sAnalysis)
	return r
}

func getAnalysis(t *testing.T, r http.Handler, role auth.Role) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/k8s-discovery/analysis", strings.NewReader(""))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "u", Role: role}))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// TestK8sAnalysis_ReturnsTheReport checks a successful run is returned as JSON with the cluster name.
func TestK8sAnalysis_ReturnsTheReport(t *testing.T) {
	h := (&Handler{}).WithK8sAnalysis(fakeAnalysisRunner{res: cloudgraph.K8sAnalysis{Cluster: "kind-bas-lab", Complete: true}})
	rec := getAnalysis(t, analysisRouter(h), auth.RoleAnalyst)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var got cloudgraph.K8sAnalysis
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Cluster != "kind-bas-lab" || !got.Complete {
		t.Fatalf("report = %+v, want the kind-bas-lab report", got)
	}
}

// TestK8sAnalysis_UnconfiguredIs503 checks the route answers 503 when no discovery is configured.
func TestK8sAnalysis_UnconfiguredIs503(t *testing.T) {
	rec := getAnalysis(t, analysisRouter(&Handler{}), auth.RoleAnalyst)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
}

// TestK8sAnalysis_FailureDoesNotEchoTheError checks a failed discovery returns a generic message, never the error text,
// which can carry request detail.
func TestK8sAnalysis_FailureDoesNotEchoTheError(t *testing.T) {
	const secret = "TOKEN-IN-ERROR-TEXT"
	h := (&Handler{}).WithK8sAnalysis(fakeAnalysisRunner{err: errors.New("GET /api/v1/pods: Bearer " + secret)})
	rec := getAnalysis(t, analysisRouter(h), auth.RoleAnalyst)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("the error text reached the response: %s", rec.Body.String())
	}
}
