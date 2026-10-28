package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/scenario"
)

const attemptTechnique = "T1490"

// seedAttempt builds one run whose single attempt is (technique, stepName).
// executions become the run's stored results; a nil source omits
// executedAtSource entirely, which is how legacy results look.
type seededExecution struct {
	executedAt string
	source     string // "" = legacy (no executedAtSource field)
}

func seedAttempt(t *testing.T, pool *pgxpool.Pool, id, stepName string, hasMeta bool, hostname, ip string, executions []seededExecution) rwevidence.AttemptKey {
	t.Helper()
	ctx := context.Background()
	agentID := "agent-" + id
	runID := "run-" + id
	action := scenario.TaskID(attemptTechnique, stepName)

	seedRunRow(t, pool, runID, "attempt-context-scenario", agentID, "completed")
	if _, err := pool.Exec(ctx, `UPDATE agents SET hostname=$2, ip_address=$3 WHERE agent_id=$1`, agentID, hostname, ip); err != nil {
		t.Fatalf("seed agent host: %v", err)
	}

	if hasMeta {
		meta := map[string]scenario.StepMeta{action: {TechniqueID: attemptTechnique, Name: stepName, Framework: "custom"}}
		raw, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE scenario_runs SET step_meta=$2 WHERE id=$1`, runID, raw); err != nil {
			t.Fatalf("seed step_meta: %v", err)
		}
	}

	results := make([]map[string]any, 0, len(executions))
	for _, e := range executions {
		row := map[string]any{
			"technique":  map[string]any{"id": attemptTechnique},
			"stepName":   stepName,
			"executedAt": e.executedAt,
		}
		if e.source != "" {
			row["executedAtSource"] = e.source
		}
		results = append(results, row)
	}
	raw, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scenario_runs SET results=$2 WHERE id=$1`, runID, raw); err != nil {
		t.Fatalf("seed results: %v", err)
	}
	return rwevidence.AttemptKey{RunID: runID, TechniqueID: attemptTechnique, Action: action}
}

func resolveForTest(t *testing.T, pool *pgxpool.Pool, key rwevidence.AttemptKey) (hostName, hostIP string, execZero bool, execUTC string, hostProblem, timeProblem string) {
	t.Helper()
	got, err := attemptContextSource{pool: pool}.AttemptContextFor(context.Background(), key)
	if err != nil {
		t.Fatalf("AttemptContextFor: %v", err)
	}
	s := ""
	if !got.ExecutedAt.IsZero() {
		s = got.ExecutedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return got.HostName, got.HostIP, got.ExecutedAt.IsZero(), s, got.HostProblem, got.TimeProblem
}

func TestAttemptContext_AgentSourcedSingleExecutionIsAuthoritative(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		key := seedAttempt(t, pool, "agent-single", "vss-delete-a", true, "HOST-A", "10.0.0.5",
			[]seededExecution{{executedAt: "2026-10-28T09:15:00Z", source: models.ExecutedAtSourceAgent}})

		host, ip, zero, when, hp, tp := resolveForTest(t, pool, key)
		if host != "HOST-A" || ip != "10.0.0.5" || hp != "" {
			t.Fatalf("host = %q/%q hostProblem=%q", host, ip, hp)
		}
		if zero || when != "2026-10-28T09:15:00Z" || tp != "" {
			t.Fatalf("time = %q zero=%v timeProblem=%q, want the agent timestamp", when, zero, tp)
		}
	})
}

func TestAttemptContext_LegacyResultWithoutProvenanceIsInconclusiveButKeepsHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		key := seedAttempt(t, pool, "legacy", "vss-delete-legacy", true, "HOST-L", "10.0.0.6",
			[]seededExecution{{executedAt: "2026-10-01T08:00:00Z", source: ""}})

		host, _, zero, _, hp, tp := resolveForTest(t, pool, key)
		if host != "HOST-L" || hp != "" {
			t.Fatalf("host must be retained for a legacy result: host=%q hostProblem=%q", host, hp)
		}
		if !zero {
			t.Fatal("a legacy result with no provenance must not yield an event time")
		}
		if !strings.Contains(tp, "unknown timestamp provenance") {
			t.Fatalf("timeProblem = %q, want it to say the provenance is unknown", tp)
		}
	})
}

func TestAttemptContext_OrchestratorFallbackIsNeverAuthoritative(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		key := seedAttempt(t, pool, "fallback", "vss-delete-fb", true, "HOST-F", "10.0.0.7",
			[]seededExecution{{executedAt: "2026-10-28T10:00:00Z", source: models.ExecutedAtSourceOrchestratorFallback}})

		_, _, zero, _, _, tp := resolveForTest(t, pool, key)
		if !zero {
			t.Fatal("a submission-time fallback must never become an event time")
		}
		if !strings.Contains(tp, "fallback") {
			t.Fatalf("timeProblem = %q, want it to name the fallback", tp)
		}
	})
}

func TestAttemptContext_MixedAgentAndFallbackForSameStepIsAmbiguous(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		key := seedAttempt(t, pool, "mixed", "vss-delete-mixed", true, "HOST-M", "10.0.0.8",
			[]seededExecution{
				{executedAt: "2026-10-28T11:00:00Z", source: models.ExecutedAtSourceAgent},
				{executedAt: "2026-10-28T11:05:00Z", source: models.ExecutedAtSourceOrchestratorFallback},
			})

		_, _, zero, _, _, tp := resolveForTest(t, pool, key)
		if !zero {
			t.Fatal("a fallback alongside an agent timestamp must not let either become authoritative")
		}
		if !strings.Contains(tp, "fallback") {
			t.Fatalf("timeProblem = %q, want it to name the fallback", tp)
		}
	})
}

func TestAttemptContext_DistinctAgentExecutionsAreAmbiguous(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		key := seedAttempt(t, pool, "retries", "vss-delete-retry", true, "HOST-R", "10.0.0.9",
			[]seededExecution{
				{executedAt: "2026-10-28T12:00:00Z", source: models.ExecutedAtSourceAgent},
				{executedAt: "2026-10-28T12:03:00Z", source: models.ExecutedAtSourceAgent},
			})

		_, _, zero, _, _, tp := resolveForTest(t, pool, key)
		if !zero {
			t.Fatal("two distinct agent timestamps must not be guessed between")
		}
		if !strings.Contains(tp, "2 distinct") {
			t.Fatalf("timeProblem = %q, want it to report the duplicate count", tp)
		}
	})
}

func TestAttemptContext_IdenticalDuplicateAgentTimestampsAreOneEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		key := seedAttempt(t, pool, "same-twice", "vss-delete-same", true, "HOST-S", "10.0.0.10",
			[]seededExecution{
				{executedAt: "2026-10-28T13:00:00Z", source: models.ExecutedAtSourceAgent},
				{executedAt: "2026-10-28T13:00:00Z", source: models.ExecutedAtSourceAgent},
			})

		_, _, zero, when, _, tp := resolveForTest(t, pool, key)
		if zero || when != "2026-10-28T13:00:00Z" || tp != "" {
			t.Fatalf("time = %q zero=%v timeProblem=%q, want the single distinct timestamp", when, zero, tp)
		}
	})
}

func TestAttemptContext_MissingStepMetaIsReported(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		key := seedAttempt(t, pool, "nometa", "vss-delete-nometa", false, "HOST-N", "10.0.0.11",
			[]seededExecution{{executedAt: "2026-10-28T14:00:00Z", source: models.ExecutedAtSourceAgent}})

		host, _, zero, _, _, tp := resolveForTest(t, pool, key)
		if host != "HOST-N" {
			t.Fatalf("host = %q, want it retained", host)
		}
		if !zero || !strings.Contains(tp, "step metadata missing") {
			t.Fatalf("zero=%v timeProblem=%q, want missing step metadata reported", zero, tp)
		}
	})
}

func TestAttemptContext_NoMatchingExecutionIsReported(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		key := seedAttempt(t, pool, "noexec", "vss-delete-noexec", true, "HOST-E", "10.0.0.12", nil)

		_, _, zero, _, _, tp := resolveForTest(t, pool, key)
		if !zero || !strings.Contains(tp, "no execution recorded") {
			t.Fatalf("zero=%v timeProblem=%q, want no execution reported", zero, tp)
		}
	})
}

func TestAttemptContext_EmptyRegistrationRecordIsReportedAsHostProblem(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		key := seedAttempt(t, pool, "nohost", "vss-delete-nohost", true, "", "",
			[]seededExecution{{executedAt: "2026-10-28T15:00:00Z", source: models.ExecutedAtSourceAgent}})

		host, ip, zero, when, hp, _ := resolveForTest(t, pool, key)
		if host != "" || ip != "" || hp == "" {
			t.Fatalf("host=%q/%q hostProblem=%q, want a host problem and no host", host, ip, hp)
		}
		if zero || when != "2026-10-28T15:00:00Z" {
			t.Fatal("a missing host must not discard an otherwise valid event time")
		}
	})
}

func TestAttemptContext_UnknownRunIsReportedNotAnError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		key := rwevidence.AttemptKey{RunID: "run-does-not-exist", TechniqueID: attemptTechnique, Action: "deadbeef"}
		host, _, zero, _, hp, tp := resolveForTest(t, pool, key)
		if host != "" || !zero || hp == "" || tp == "" {
			t.Fatalf("host=%q zero=%v hostProblem=%q timeProblem=%q, want both reported", host, zero, hp, tp)
		}
	})
}
