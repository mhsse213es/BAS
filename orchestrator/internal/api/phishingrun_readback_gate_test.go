package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// The read-back grader must never produce a pass from absence of evidence. For every
// EmailGW-linked phishing scenario, a completed run whose efficacy result holds no
// delivery, enforcement, or detection record must grade no dimension as a pass.
// This is the evidence-to-verdict check the audit asked for. It covers all 13 mapped
// scenarios, not a sample.
func TestReadbackGate_NoEvidenceNeverPasses_AllMappedScenarios(t *testing.T) {
	ids := make([]string, 0, len(phishEmailGWExpectation))
	for id := range phishEmailGWExpectation {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		for _, phID := range ids {
			egID := phishEmailGWExpectation[phID]
			t.Run(phID, func(t *testing.T) {
				exp, ok := emailgwefficacy.ExpectationByID(egID)
				if !ok {
					t.Fatalf("EmailGW expectation %s missing", egID)
				}
				provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil)
				result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, readbackScenarioWindow())
				raw, err := json.Marshal(result)
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				runID := fmt.Sprintf("gate-%s", phID)
				seedEmailGWRun(t, pool, runID, egID, raw)

				exec, ok := LookupPhishingRunExecutor(phID)
				if !ok {
					t.Fatalf("%s is not registered", phID)
				}
				outcome, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
					map[string]any{"emailGwRunId": runID})
				if err != nil {
					t.Fatalf("executor refused a completed run with a result: %v", err)
				}
				for name, d := range map[string]phishval.DimensionResult{
					"Delivery": outcome.Delivery, "Enforcement": outcome.Enforcement, "Detection": outcome.Detection,
				} {
					if d.Verdict == phishval.VerdictPass {
						t.Errorf("%s: %s = pass with no evidence (reason %q)", phID, name, d.Reason)
					}
				}
				if outcome.Provenance == nil || outcome.Provenance.EmailGWRunID != runID {
					t.Errorf("%s: provenance = %+v, want the graded run %s", phID, outcome.Provenance, runID)
				}
			})
		}
	})
}

// For every mapped scenario, a run that has not completed is refused, not graded.
func TestReadbackGate_IncompleteRunRefusedForEveryMappedScenario(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		for phID, egID := range phishEmailGWExpectation {
			runID := "gate-running-" + phID
			if _, err := pool.Exec(context.Background(),
				`INSERT INTO email_gw_runs (id, scenario_id, status) VALUES ($1, $2, 'running')`, runID, egID); err != nil {
				t.Fatalf("seed %s: %v", runID, err)
			}
			exec, _ := LookupPhishingRunExecutor(phID)
			if _, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
				map[string]any{"emailGwRunId": runID}); err == nil {
				t.Errorf("%s: a running EmailGW run was graded; it must be refused", phID)
			}
		}
	})
}
