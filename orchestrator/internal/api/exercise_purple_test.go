package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/verification"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The purple-team debrief is built from the verification records of the BAS runs an exercise started, and is absent
// when it started none.
func TestPurpleDebrief_FromStepRunIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		vs := verification.NewStore(pool)
		h.WithVerificationStore(vs)
		ctx := context.Background()

		for _, in := range []verification.AttestInput{
			{RunID: "run-1", ExpectationID: "e1", TechniqueID: "T1003", Domain: "endpoint", Provider: "defender", Result: verification.ResultDetected, WorkflowState: verification.StateApproved, Source: verification.SourceAutomatic, VerifiedBy: "automatic"},
			{RunID: "run-1", ExpectationID: "e2", TechniqueID: "T1558.003", Domain: "siem", Provider: "sentinel", Result: verification.ResultNotDetected, WorkflowState: verification.StateApproved, Source: verification.SourceManual, VerifiedBy: "analyst"},
		} {
			if _, err := vs.Attest(ctx, in); err != nil {
				t.Fatalf("attest: %v", err)
			}
		}

		steps := []exercise.StepExecution{
			{StepID: "run", Result: map[string]any{"bas_run_id": "run-1"}},
			{StepID: "wait", Result: map[string]any{"bas_run_id": "run-1"}}, // the same run twice must count once
			{StepID: "approve"},
		}
		d := h.purpleDebrief(ctx, &exercise.Plan{}, steps)
		if d == nil {
			t.Fatal("expected a debrief")
		}
		if d.Detected != 1 || d.Missed != 1 || d.DetectionRate == nil || *d.DetectionRate != 50 {
			t.Fatalf("got detected=%d missed=%d rate=%v", d.Detected, d.Missed, d.DetectionRate)
		}

		if got := h.purpleDebrief(ctx, &exercise.Plan{}, []exercise.StepExecution{{StepID: "approve"}}); got != nil {
			t.Fatalf("an exercise that started no BAS run must have no debrief, got %+v", got)
		}
	})
}

func TestExerciseReportJSON_HasNoPurpleWithoutRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		h.WithVerificationStore(verification.NewStore(pool))
		execID := launchedExecution(t, h, []exercise.PlanStep{minimalStep("a")})
		rec := httptest.NewRecorder()
		h.GetExerciseReportJSON(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", execID))
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"purple"`) {
			t.Fatalf("status %d, body has purple: %v", rec.Code, strings.Contains(rec.Body.String(), `"purple"`))
		}
	})
}
