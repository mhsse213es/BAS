package analytics

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func addTechnique(t *testing.T, pool *pgxpool.Pool, threatID, technique, status string) {
	t.Helper()
	reason := "supported"
	if status == "retracted" {
		reason = "source_retraction"
	}
	mustExec(t, pool, `INSERT INTO threat_techniques (threat_id, technique_id, last_seen_at, status, status_reason)
		VALUES ($1, $2, NOW(), $3, $4)`, threatID, technique, status, reason)
}

func TestThreatsMapped_CountsOnlyThreatsWithAnActiveTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedThreatWithActor(t, pool, "tm-active", "Actor TM 1")
		seedThreatWithActor(t, pool, "tm-two", "Actor TM 2") // two techniques still counts once
		seedThreatWithActor(t, pool, "tm-retracted", "Actor TM 3")
		seedThreatWithActor(t, pool, "tm-none", "Actor TM 4")
		addTechnique(t, pool, "tm-active", "T1059", "active")
		addTechnique(t, pool, "tm-two", "T1059", "active")
		addTechnique(t, pool, "tm-two", "T1003", "active")
		addTechnique(t, pool, "tm-retracted", "T1059", "retracted")

		window := 30 * 24 * time.Hour
		got, err := factoryThroughput(context.Background(), pool, time.Now().Add(-window), window)
		if err != nil {
			t.Fatalf("factoryThroughput: %v", err)
		}
		if got.ThreatsMapped.State != DataMeasured || *got.ThreatsMapped.Value != 2 {
			t.Fatalf("ThreatsMapped = %+v, want 2 (retracted-only and unmapped threats excluded)", got.ThreatsMapped)
		}
	})
}

func addEvent(t *testing.T, pool *pgxpool.Pool, versionID, to, actor, reasonCode string, age time.Duration) {
	t.Helper()
	var rc any
	if reasonCode != "" {
		rc = reasonCode
	}
	mustExec(t, pool, `INSERT INTO content_version_events (content_version_id, to_lifecycle, to_trust, actor, reason_code, at)
		VALUES ($1, $2, 'UNTRUSTED', $3, $4, $5)`, versionID, to, actor, rc, time.Now().Add(-age))
}

func TestFactoryThroughput_ValidatedAndRejectedAreWindowThroughputWithReasonBreakdown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		v1 := seedPublishedAt(t, pool, "th-v1", time.Hour)
		v2 := seedPublishedAt(t, pool, "th-v2", time.Hour)
		v3 := seedPublishedAt(t, pool, "th-v3", time.Hour)
		old := seedPublishedAt(t, pool, "th-old", time.Hour)

		// v1 validated twice (re-validation) still counts once; old validation is outside the window.
		addEvent(t, pool, v1, "VALIDATED", "system:validator", "", time.Hour)
		addEvent(t, pool, v1, "VALIDATED", "system:validator", "", 2*time.Hour)
		addEvent(t, pool, old, "VALIDATED", "system:validator", "", 40*24*time.Hour)
		addEvent(t, pool, v2, "REJECTED", "user:a", "relevance", time.Hour)
		addEvent(t, pool, v3, "REJECTED", "user:a", "relevance", time.Hour)
		addEvent(t, pool, old, "REJECTED", "user:a", "unsupported_platform", 40*24*time.Hour)

		window := 30 * 24 * time.Hour
		got, err := factoryThroughput(context.Background(), pool, time.Now().Add(-window), window)
		if err != nil {
			t.Fatalf("factoryThroughput: %v", err)
		}
		if *got.CandidatesValidated.Value != 1 {
			t.Fatalf("CandidatesValidated = %v, want 1 (distinct, in window)", *got.CandidatesValidated.Value)
		}
		if *got.CandidatesRejected.Value != 2 {
			t.Fatalf("CandidatesRejected = %v, want 2 (old rejection excluded)", *got.CandidatesRejected.Value)
		}
		if got.RejectedByReason["relevance"] != 2 || len(got.RejectedByReason) != 1 {
			t.Fatalf("RejectedByReason = %v, want only relevance:2", got.RejectedByReason)
		}
		if got.CandidatesRejectedPerDay.State != DataMeasured {
			t.Fatalf("CandidatesRejectedPerDay = %+v, want measured", got.CandidatesRejectedPerDay)
		}
	})
}

func addExecValidation(t *testing.T, pool *pgxpool.Pool, versionID, outcome string) {
	t.Helper()
	var runID any
	if outcome == "PASS" { // schema requires a run for an EXECUTION PASS
		var id string
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO scenario_runs (scenario_id, agent_id, status, completed_at) VALUES ('s-exec','a1','completed',NOW()) RETURNING id`).Scan(&id); err != nil {
			t.Fatalf("seed run: %v", err)
		}
		runID = id
	}
	mustExec(t, pool, `INSERT INTO content_validations (content_version_id, level, outcome, run_id, validator, validator_version)
		VALUES ($1, 'EXECUTION', $2, $3, 'test', '1')`, versionID, outcome, runID)
}

func TestExecutionValidationPassRate_ExcludesErrorsAndInflight(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		v := seedPublishedAt(t, pool, "ev-v", time.Hour)
		addExecValidation(t, pool, v, "PASS")
		addExecValidation(t, pool, v, "PASS")
		addExecValidation(t, pool, v, "PASS")
		addExecValidation(t, pool, v, "FAIL")
		addExecValidation(t, pool, v, "ERROR")   // environment problem: not in the rate
		addExecValidation(t, pool, v, "NO_DATA") // in flight: not an outcome

		window := 30 * 24 * time.Hour
		got, err := factoryThroughput(context.Background(), pool, time.Now().Add(-window), window)
		if err != nil {
			t.Fatalf("factoryThroughput: %v", err)
		}
		if got.ExecutionValidationPassRate.State != DataMeasured || *got.ExecutionValidationPassRate.Value != 0.75 {
			t.Fatalf("ExecutionValidationPassRate = %+v, want 0.75 (3 PASS of 4 PASS+FAIL)", got.ExecutionValidationPassRate)
		}
		if *got.ExecutionValidationErrors.Value != 1 {
			t.Fatalf("ExecutionValidationErrors = %v, want 1", *got.ExecutionValidationErrors.Value)
		}
	})
}

func TestExecutionValidationPassRate_NoDataWhenNothingResolved(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		window := 30 * 24 * time.Hour
		got, err := factoryThroughput(context.Background(), pool, time.Now().Add(-window), window)
		if err != nil {
			t.Fatalf("factoryThroughput: %v", err)
		}
		if got.ExecutionValidationPassRate.State != DataNoData {
			t.Fatalf("ExecutionValidationPassRate = %+v, want NO_DATA", got.ExecutionValidationPassRate)
		}
	})
}
