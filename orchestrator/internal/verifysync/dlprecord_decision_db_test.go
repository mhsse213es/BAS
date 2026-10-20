package verifysync

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPersistDLPRecords_WritesDecisionColumns checks decision_class,
// evidence_source and rule_version are written. A nil decision class (outside
// the approved table) must stay NULL, not be filled with a default.
func TestPersistDLPRecords_WritesDecisionColumns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		const runID = "run-decision-cols"
		fn := "FN"
		src := "sink-receipt"
		rule := dlpDecisionRuleVersion

		classified := DLPRecordEntry{
			TaskID: "task-fn", ExpectationID: "dlp-usb-block", TechniqueID: "T1052.001",
			DecisionClass: &fn, EvidenceSource: &src, RuleVersion: &rule,
		}
		classified.Record.ScenarioID = "sc-dec"
		unclassified := DLPRecordEntry{
			TaskID: "task-warn", ExpectationID: "dlp-warn", TechniqueID: "T1052.001",
			EvidenceSource: &src, RuleVersion: &rule,
		}
		unclassified.Record.ScenarioID = "sc-dec"

		if err := persistDLPRecords(ctx, pool, runID, []DLPRecordEntry{classified, unclassified}); err != nil {
			t.Fatalf("persist: %v", err)
		}

		var gotClass, gotSrc, gotRule *string
		if err := pool.QueryRow(ctx,
			`SELECT decision_class, evidence_source, rule_version FROM dlp_evidence_records
			 WHERE run_id = $1 AND task_id = 'task-fn'`, runID).Scan(&gotClass, &gotSrc, &gotRule); err != nil {
			t.Fatalf("read classified row: %v", err)
		}
		if gotClass == nil || *gotClass != "FN" || gotSrc == nil || *gotSrc != "sink-receipt" || gotRule == nil || *gotRule != dlpDecisionRuleVersion {
			t.Fatalf("classified row = class %v source %v rule %v", gotClass, gotSrc, gotRule)
		}

		var nullClass *string
		if err := pool.QueryRow(ctx,
			`SELECT decision_class FROM dlp_evidence_records WHERE run_id = $1 AND task_id = 'task-warn'`,
			runID).Scan(&nullClass); err != nil {
			t.Fatalf("read unclassified row: %v", err)
		}
		if nullClass != nil {
			t.Fatalf("decision_class for an unapproved expectation must be NULL, got %q", *nullClass)
		}
	})
}
