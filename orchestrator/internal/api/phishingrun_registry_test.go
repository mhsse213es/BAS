package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishval"
)

func TestLookupPhishingRunExecutor_PHDET002Registered(t *testing.T) {
	_, ok := LookupPhishingRunExecutor("PH-DET-002")
	if !ok {
		t.Fatal("PH-DET-002 must be registered as executable")
	}
}

func TestLookupPhishingRunExecutor_UnregisteredCatalogScenario_NotFound(t *testing.T) {
	// PH-BEC-002 is a real, adapter-tested catalog scenario with no
	// executor wired yet in this slice -- it must not appear executable
	// merely because it exists in phishcatalog.
	_, ok := LookupPhishingRunExecutor("PH-BEC-002")
	if ok {
		t.Fatal("PH-BEC-002 must not be executable in this slice")
	}
}

func TestExecutePHDET002_TicketCreated_Pass(t *testing.T) {
	env := PhishingRunExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
		ExecutionID: "exec-1", TargetID: "target-1", TicketCreated: true, Timestamp: time.Now(),
	}})}
	outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": "exec-1", "targetId": "target-1"})
	if err != nil {
		t.Fatalf("executePHDET002: %v", err)
	}
	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictPass)
	}
}

func TestExecutePHDET002_NoEvidence_NotTested(t *testing.T) {
	env := PhishingRunExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider(nil)}
	outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": "exec-1", "targetId": "target-1"})
	if err != nil {
		t.Fatalf("executePHDET002: %v", err)
	}
	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q (absent evidence must never become Pass or Fail)", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}

// TestExecutePHDET002_NilProvider_NotTestedNeverPanics proves the
// as-shipped, unconfigured-by-default production path (Handler.New
// without a WithPhishingRun call -- confirmed via grep that
// cmd/server/main.go never calls it) degrades to NotTested exactly
// like "provider configured but found no evidence," never a panic on
// a nil-interface method call.
func TestExecutePHDET002_NilProvider_NotTestedNeverPanics(t *testing.T) {
	env := PhishingRunExecutorEnv{ReportTicketProvider: nil}
	outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": "exec-1", "targetId": "target-1"})
	if err != nil {
		t.Fatalf("executePHDET002: %v", err)
	}
	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q (an unconfigured provider must never panic or fabricate a verdict)", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}

func TestExecutePHDET002_TicketNotCreated_Fail(t *testing.T) {
	env := PhishingRunExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
		ExecutionID: "exec-1", TargetID: "target-1", TicketCreated: false, Timestamp: time.Now(),
	}})}
	outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": "exec-1", "targetId": "target-1"})
	if err != nil {
		t.Fatalf("executePHDET002: %v", err)
	}
	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictFail)
	}
}
