package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// Delivery, enforcement, and detection are graded from their own evidence. Evidence in one
// dimension must not pass another. These tests feed the read-back one dimension at a time.
func gradeReadbackWith(t *testing.T, pool *pgxpool.Pool, res emailgwefficacy.EfficacyResult) phishval.Outcome {
	t.Helper()
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	runID := "indep-" + time.Now().Format("150405.000000000")
	seedEmailGWRun(t, pool, runID, "EG-002.known-good", raw)
	exec, ok := LookupPhishingRunExecutor("PH-BEC-001")
	if !ok {
		t.Fatalf("PH-BEC-001 is not registered")
	}
	out, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1", map[string]any{"emailGwRunId": runID})
	if err != nil {
		t.Fatalf("grade: %v", err)
	}
	return out
}

func TestIndependence_DetectionAlertDoesNotPassDeliveryOrEnforcement(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		exp, _ := emailgwefficacy.ExpectationByID("EG-002.known-good")
		res := emailgwefficacy.EfficacyResult{
			Expectation: exp,
			Detection: []emailgwefficacy.DetectionEvidence{{AlertGenerated: true, Product: "siem",
				Timestamp: time.Now().UTC()}},
		}
		out := gradeReadbackWith(t, pool, res)
		if out.Delivery.Verdict == phishval.VerdictPass {
			t.Errorf("an alert with no delivery record graded delivery as pass")
		}
		if out.Enforcement.Verdict == phishval.VerdictPass {
			t.Errorf("an alert with no enforcement record graded enforcement as pass")
		}
	})
}

func TestIndependence_EnforcementDoesNotPassDetection(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		exp, _ := emailgwefficacy.ExpectationByID("EG-002.known-good")
		res := emailgwefficacy.EfficacyResult{
			Expectation: exp,
			Enforcement: []emailgwefficacy.EnforcementEvidence{{Action: "quarantine", ControlProduct: "gateway",
				Timestamp: time.Now().UTC()}},
			Detection: []emailgwefficacy.DetectionEvidence{{AlertGenerated: false, Product: "siem",
				Timestamp: time.Now().UTC()}},
		}
		out := gradeReadbackWith(t, pool, res)
		if out.Detection.Verdict == phishval.VerdictPass {
			t.Errorf("a quarantine with no alert graded detection as pass")
		}
	})
}
