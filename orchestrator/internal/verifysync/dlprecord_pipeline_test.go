package verifysync

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/dlpreport"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

// dlpExp is an automatic, dlp-family expectation: the shape the DLP verifier
// actually resolves (OutcomeFamily "dlp"), not a fixture-only shortcut.
func dlpExp(id, expected string) scenario.ExpectedDetection {
	return scenario.ExpectedDetection{
		ID:              id,
		Type:            scenario.DomainEndpoint,
		OutcomeFamily:   "dlp",
		ExpectedOutcome: expected,
		Verification:    scenario.VerificationAutomatic,
		Confidence:      scenario.ConfidenceRequired,
		Finding:         scenario.ExpectedFinding{Title: id, Severity: "High", Remediation: "fix"},
	}
}

// TestDLPRecords_ThroughTickSeam drives the real entry point: a completed
// scenario_runs row is picked up by Tick, which runs processRun.
func TestDLPRecords_ThroughTickSeam(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		const runID, scID = "run-dlprec-1", "sc-dlprec"

		steps := []scenario.Step{
			{Name: "Block test", TechniqueID: "T1048.002"},
			{Name: "Allow test", TechniqueID: "T1567.002"},
			{Name: "Override test", TechniqueID: "T1567.004"},
			{Name: "Unobserved test", TechniqueID: "T1052.001"},
			{Name: "Endpoint test", TechniqueID: "T1003"},
		}
		ids := scenario.ResolvedTaskIDs(steps)
		resolver := fakeResolver{
			sc: &scenario.Scenario{ID: scID, Steps: steps},
			exp: map[string][]scenario.ExpectedDetection{
				"T1048.002": {dlpExp("exp-block", "Block")},
				"T1567.002": {dlpExp("exp-allow", "Allow")},
				"T1567.004": {dlpExp("exp-override", "Block")},
				"T1052.001": {dlpExp("exp-unobserved", "Block")},
				"T1003":     {endpointExp("exp-endpoint", "microsoft_defender")},
			},
		}

		results := []map[string]any{
			{"id": ids[0], "stepName": steps[0].Name, "rawOutput": "DLP_OBSERVATION: OperationBlocked"},
			{"id": ids[1], "stepName": steps[1].Name, "rawOutput": "DLP_OBSERVATION: OperationSucceeded"},
			{"id": ids[2], "stepName": steps[2].Name, "rawOutput": "DLP_OBSERVATION: OperationBlocked",
				"overrideOccurred": true, "overrideAuthorizedBy": "jdoe", "overrideReason": "business need"},
			{"id": ids[3], "stepName": steps[3].Name, "rawOutput": ""},
			{"id": ids[4], "stepName": steps[4].Name, "detectionVerdict": "undetected"},
		}
		raw, err := json.Marshal(results)
		if err != nil {
			t.Fatal(err)
		}

		seedRun(t, ctx, pool, runID, scID, raw)

		NewJob(pool, verification.NewStore(pool), resolver).Tick(ctx)

		rows, err := pool.Query(ctx,
			`SELECT expectation_id, record FROM dlp_evidence_records WHERE run_id = $1 ORDER BY expectation_id`, runID)
		if err != nil {
			t.Fatalf("query dlp_evidence_records: %v", err)
		}
		got := map[string]DLPRecordEntry{}
		for rows.Next() {
			var expID, rec string
			if err := rows.Scan(&expID, &rec); err != nil {
				rows.Close()
				t.Fatalf("scan: %v", err)
			}
			var e DLPRecordEntry
			if err := json.Unmarshal([]byte(rec), &e); err != nil {
				rows.Close()
				t.Fatalf("unmarshal %s: %v", expID, err)
			}
			got[expID] = e
		}
		rows.Close()

		// Exactly the four DLP expectations; the endpoint expectation writes nothing.
		if len(got) != 4 {
			t.Fatalf("got %d dlp records, want 4: %v", len(got), keysOf(got))
		}
		if _, ok := got["exp-endpoint"]; ok {
			t.Fatal("non-DLP expectation produced a DLP record")
		}

		want := map[string]dlpreport.EnforcementOutcome{
			"exp-block":      dlpreport.EnforcementBlocked,
			"exp-allow":      dlpreport.EnforcementUnknown, // self-reported success, never Allowed
			"exp-override":   dlpreport.EnforcementOverridden,
			"exp-unobserved": dlpreport.EnforcementUnknown,
		}
		for id, enf := range want {
			e, ok := got[id]
			if !ok {
				t.Fatalf("missing record for %s", id)
			}
			if e.Record.Enforcement != enf {
				t.Errorf("%s enforcement = %s, want %s", id, e.Record.Enforcement, enf)
			}
			if err := e.Record.Validate(); err != nil {
				t.Errorf("%s fails Validate: %v", id, err)
			}
		}
		// The unobserved step keeps the MissingEvidence distinction, not Mismatch.
		if got["exp-unobserved"].Comparison != "MissingEvidence" {
			t.Errorf("unobserved comparison = %q, want MissingEvidence", got["exp-unobserved"].Comparison)
		}
		if got["exp-block"].Comparison != "Match" {
			t.Errorf("block comparison = %q, want Match", got["exp-block"].Comparison)
		}

		// Retry the same evaluation: the primary key keeps it to one row per expectation.
		job := NewJob(pool, verification.NewStore(pool), resolver)
		if err := job.processRun(ctx, runID, scID, raw); err != nil {
			t.Fatalf("retry processRun: %v", err)
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM dlp_evidence_records WHERE run_id = $1`, runID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 4 {
			t.Fatalf("after retry: %d rows, want 4 (no duplicates)", n)
		}

		// The read path returns the same four entries, in expectation order.
		read, err := DLPRecordsForRun(ctx, pool, runID)
		if err != nil {
			t.Fatalf("DLPRecordsForRun: %v", err)
		}
		if len(read) != 4 {
			t.Fatalf("DLPRecordsForRun returned %d entries, want 4", len(read))
		}
		for i := 1; i < len(read); i++ {
			prev, cur := read[i-1], read[i]
			if prev.TaskID > cur.TaskID || (prev.TaskID == cur.TaskID && prev.ExpectationID >= cur.ExpectationID) {
				t.Fatalf("entries not in (task, expectation) order: %s/%s before %s/%s", prev.TaskID, prev.ExpectationID, cur.TaskID, cur.ExpectationID)
			}
		}
		none, err := DLPRecordsForRun(ctx, pool, "run-dlprec-unknown")
		if err != nil || len(none) != 0 {
			t.Fatalf("unknown run: got %d entries, err=%v, want empty and nil", len(none), err)
		}
	})
}

func seedRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, runID, scID string, results []byte) {
	t.Helper()
	agent := fmt.Sprintf("agent-%s", runID)
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (agent_id, hostname, ip_address, os_version, status, state, last_update)
		 VALUES ($1, 'DLPHOST', '10.0.0.9', 'Windows 11', 'idle', 'active', NOW())`, agent); err != nil {
		t.Fatalf("seed agents: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO scenario_runs (id, agent_id, scenario_id, name, status, results, started_at)
		 VALUES ($1, $2, $3, 'n', 'completed', $4, NOW())`, runID, agent, scID, string(results)); err != nil {
		t.Fatalf("seed scenario_runs: %v", err)
	}
}

// TestDLPRecords_SharedExpectationAcrossSteps_KeepsEveryStep covers the real
// DLP profile shape: one profile applied to several steps gives every step
// the same expectation ID. Each step is a separate evaluation and must keep
// its own record. Keying by (run, expectation) silently dropped all but one.
func TestDLPRecords_SharedExpectationAcrossSteps_KeepsEveryStep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		const runID, scID = "run-dlprec-shared", "sc-dlprec-shared"

		steps := []scenario.Step{
			{Name: "Upload one", TechniqueID: "T1567.002"},
			{Name: "Upload two", TechniqueID: "T1567.002"},
		}
		ids := scenario.ResolvedTaskIDs(steps)
		shared := dlpExp("dlp-usb-block", "Block")
		resolver := fakeResolver{
			sc:  &scenario.Scenario{ID: scID, Steps: steps},
			exp: map[string][]scenario.ExpectedDetection{"T1567.002": {shared}},
		}
		results := []map[string]any{
			{"id": ids[0], "stepName": steps[0].Name, "rawOutput": "DLP_OBSERVATION: OperationBlocked"},
			{"id": ids[1], "stepName": steps[1].Name, "rawOutput": "DLP_OBSERVATION: OperationSucceeded"},
		}
		raw, err := json.Marshal(results)
		if err != nil {
			t.Fatal(err)
		}
		seedRun(t, ctx, pool, runID, scID, raw)

		NewJob(pool, verification.NewStore(pool), resolver).Tick(ctx)

		read, err := DLPRecordsForRun(ctx, pool, runID)
		if err != nil {
			t.Fatalf("DLPRecordsForRun: %v", err)
		}
		if len(read) != 2 {
			t.Fatalf("got %d records for two steps sharing one expectation, want 2: a step's record was dropped", len(read))
		}
		seen := map[string]bool{}
		for _, e := range read {
			seen[e.TaskID] = true
		}
		if !seen[ids[0]] || !seen[ids[1]] {
			t.Fatalf("records not attributed to each step: %+v", read)
		}
	})
}

func keysOf(m map[string]DLPRecordEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
