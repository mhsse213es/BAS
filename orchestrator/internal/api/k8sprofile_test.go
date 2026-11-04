package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/k8sscenario"
)

// recordingAudit keeps every event written to it.
type recordingAudit struct{ events []k8sscenario.Event }

func (a *recordingAudit) Write(_ context.Context, e k8sscenario.Event) error {
	a.events = append(a.events, e)
	return nil
}

func TestRefuseProfile_RefusesAndRecordsOnce(t *testing.T) {
	audit := &recordingAudit{}
	svc := &K8sScenarioService{Audit: audit}
	prod := k8sscenario.ClusterRecord{ID: "k8sc-9", DisplayName: "prod-east", Class: k8sscenario.ClassProduction}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	if !refuseProfile(rec, req, svc, prod, "lab", "probe-1") {
		t.Fatal("a lab request against a production cluster must be refused")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
	if len(audit.events) != 1 || audit.events[0].Type != "k8s.profile.refused" {
		t.Errorf("the refusal must be recorded exactly once: %+v", audit.events)
	}

	rec2 := httptest.NewRecorder()
	if refuseProfile(rec2, req, svc, prod, "safe", "probe-2") {
		t.Error("a safe request against a production cluster must be allowed")
	}
	if len(audit.events) != 1 {
		t.Errorf("an allowed request must not be recorded as a refusal: %d events", len(audit.events))
	}
}
