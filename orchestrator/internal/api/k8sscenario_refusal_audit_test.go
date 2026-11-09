package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/k8sscenario"
)

// captureAudit records every audit event written through the scenario service.
type captureAudit struct {
	mu     sync.Mutex
	events []k8sscenario.Event
}

func (c *captureAudit) Write(_ context.Context, e k8sscenario.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

// refusalsFor returns the refusal events recorded for a run.
func (c *captureAudit) refusalsFor(runID string) []k8sscenario.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []k8sscenario.Event
	for _, e := range c.events {
		if e.Type == k8sscenario.EventRefused && e.RunID == runID {
			out = append(out, e)
		}
	}
	return out
}

// A self-approval is refused and the refusal is audited with the run's identity.
func TestRefusalAudit_SelfApprovalIsRecorded(t *testing.T) {
	s := newScenarioHarness(t)
	audit := &captureAudit{}
	s.h.k8sScenario.Audit = audit
	s.runs.m["r-self"] = K8sRun{ID: "r-self", RequesterID: "admin-2", ClusterID: "k8sc-lab", AuthorizationID: "k8sa-1",
		CustomerRef: "cust-1", Cluster: "kind-bas-lab", Namespace: "bas-sandbox", ActionID: "configmap-patch-labelled",
		State: "PLANNED", CreatedAt: time.Now()}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, asAdmin(httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/runs/r-self/approve", nil), "admin-2"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	ev := audit.refusalsFor("r-self")
	if len(ev) != 1 || ev[0].Fields["reason"] != "self-approval" {
		t.Fatalf("want one self-approval refusal, got %v", ev)
	}
	if ev[0].Fields["clusterId"] != "k8sc-lab" || ev[0].Fields["customerRef"] != "cust-1" || ev[0].Fields["actor"] != "admin-2" {
		t.Errorf("refusal must carry the run identity: %v", ev[0].Fields)
	}
}

// Approving a run that is not awaiting approval is refused and audited.
func TestRefusalAudit_NotAwaitingApprovalIsRecorded(t *testing.T) {
	s := newScenarioHarness(t)
	audit := &captureAudit{}
	s.h.k8sScenario.Audit = audit
	s.runs.m["r-done"] = K8sRun{ID: "r-done", RequesterID: "operator-1", ClusterID: "k8sc-lab", State: "CLEANED",
		CreatedAt: time.Now()}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, asAdmin(httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/runs/r-done/approve", nil), "admin-2"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if ev := audit.refusalsFor("r-done"); len(ev) != 1 || !strings.Contains(ev[0].Fields["reason"], "not awaiting") {
		t.Fatalf("want one not-awaiting refusal, got %v", ev)
	}
}

// A run planned before cluster identity was stored is refused at execution and the refusal is audited. It is never
// resolved by name.
func TestRefusalAudit_LegacyRunRefusedAtExecutionIsRecorded(t *testing.T) {
	s := newScenarioHarness(t)
	audit := &captureAudit{}
	s.h.k8sScenario.Audit = audit
	s.runs.m["r-legacy"] = K8sRun{ID: "r-legacy", RequesterID: "operator-1", Cluster: "kind-bas-lab", Namespace: "bas-sandbox",
		ActionID: "configmap-patch-labelled", ApprovalID: "appr-x", State: "APPROVED", CreatedAt: time.Now()}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, asAdmin(httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/runs/r-legacy/execute", nil), "operator-1"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d %s, want 409", rec.Code, rec.Body.String())
	}
	ev := audit.refusalsFor("r-legacy")
	if len(ev) != 1 || !strings.Contains(ev[0].Fields["reason"], "before cluster identity") {
		t.Fatalf("want one legacy refusal, got %v", ev)
	}
}

// With no audit writer configured, a refusal is still refused (no panic, no write).
func TestRefusalAudit_NoWriterStillRefuses(t *testing.T) {
	s := newScenarioHarness(t)
	s.h.k8sScenario.Audit = nil
	s.runs.m["r-none"] = K8sRun{ID: "r-none", RequesterID: "operator-1", State: "CLEANED", CreatedAt: time.Now()}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, asAdmin(httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/runs/r-none/approve", nil), "admin-2"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}
