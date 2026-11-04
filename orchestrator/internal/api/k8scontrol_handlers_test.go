package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/k8sscenario"
)

// controlRouter mounts the switch and cancel handlers on the harness.
func controlRouter(s *scenarioHarness) *chi.Mux {
	r := chi.NewRouter()
	r.Get("/api/k8s-scenarios/controlled-switch", s.h.GetK8sControlledSwitch)
	r.Post("/api/k8s-scenarios/controlled-switch", s.h.SetK8sControlledSwitch)
	r.Post("/api/k8s-scenarios/runs/{id}/cancel", s.h.CancelK8sRun)
	return r
}

// Only the requester may cancel a run. Anyone else is refused before the engine is asked.
func TestCancelK8sRun_OnlyTheRequesterMayCancel(t *testing.T) {
	s := newScenarioHarness(t)
	s.runs.m["r-cancel"] = K8sRun{ID: "r-cancel", RequesterID: "operator-1", Cluster: "kind-bas-lab", ClusterID: "k8sc-lab",
		Namespace: "bas-sandbox", ActionID: "configmap-patch-labelled", State: "APPROVED", CreatedAt: time.Now()}
	rec := httptest.NewRecorder()
	controlRouter(s).ServeHTTP(rec, asAdmin(httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/runs/r-cancel/cancel", nil), "operator-9"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d %s, want 403 for a non-requester", rec.Code, rec.Body.String())
	}
}

// A run that is not executing cannot be cancelled: there is nothing to stop, and the answer says so.
func TestCancelK8sRun_IdleRunIsAConflict(t *testing.T) {
	s := newScenarioHarness(t)
	s.runs.m["r-idle"] = K8sRun{ID: "r-idle", RequesterID: "operator-1", Cluster: "kind-bas-lab", ClusterID: "k8sc-lab",
		Namespace: "bas-sandbox", ActionID: "configmap-patch-labelled", State: "APPROVED", CreatedAt: time.Now()}
	rec := httptest.NewRecorder()
	controlRouter(s).ServeHTTP(rec, asAdmin(httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/runs/r-idle/cancel", nil), "operator-1"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d %s, want 409 for an idle run", rec.Code, rec.Body.String())
	}
}

// The switch body must say true or false. Anything else is refused and the switch does not change.
func TestSetControlledSwitch_RejectsAmbiguousBody(t *testing.T) {
	s := newScenarioHarness(t)
	sw := &fakeSwitch{on: false}
	s.h.k8sScenario.ControlledSwitch = sw
	for _, body := range []string{`{}`, `{"enabled":"yes"}`, `not json`} {
		rec := httptest.NewRecorder()
		req := asAdmin(httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/controlled-switch", strings.NewReader(body)), "admin-1")
		controlRouter(s).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
	if sw.on {
		t.Fatal("a refused request must not change the switch")
	}
}

// Turning the switch on changes it and reports no stopped runs; the read reflects the change.
func TestSetControlledSwitch_OnThenRead(t *testing.T) {
	s := newScenarioHarness(t)
	sw := &fakeSwitch{on: false}
	s.h.k8sScenario.ControlledSwitch = sw
	rec := httptest.NewRecorder()
	controlRouter(s).ServeHTTP(rec, asAdmin(httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/controlled-switch",
		strings.NewReader(`{"enabled":true}`)), "admin-1"))
	if rec.Code != http.StatusOK || !sw.on {
		t.Fatalf("set on: status = %d, switch on = %v; body %s", rec.Code, sw.on, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	controlRouter(s).ServeHTTP(rec, asAdmin(httptest.NewRequest(http.MethodGet, "/api/k8s-scenarios/controlled-switch", nil), "admin-1"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("read: status = %d body %s", rec.Code, rec.Body.String())
	}
}

var _ = k8sscenario.ErrControlledDisabled
