package models

import "testing"

func TestBackfillFraudVerdictsRewritesStoredRows(t *testing.T) {
	stored := []SimulationResult{
		{ID: "a", Result: ResultPass, Technique: AttackTechnique{ID: "T1565.002"},
			FraudControl: &FraudControl{Verdict: "FAIL", Reason: "no flag or alert from the fraud controls"}},
		{ID: "b", Result: ResultPass, Technique: AttackTechnique{ID: "T1078"},
			FraudControl: &FraudControl{Verdict: "SKIPPED", Reason: "ledger not called"}},
		{ID: "c", Result: ResultPass, Technique: AttackTechnique{ID: "T1057"}}, // no fraud record
		{ID: "d", Result: ResultPass, Technique: AttackTechnique{ID: "T1078"},
			FraudControl: &FraudControl{Verdict: "PASS"}},
	}
	out, changed := BackfillFraudVerdicts(stored)
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if out[0].Result != ResultFail || out[0].EndpointResult != ResultPass {
		t.Errorf("a: result=%q endpoint=%q, want fail/pass", out[0].Result, out[0].EndpointResult)
	}
	if out[1].Result != ResultSkipped {
		t.Errorf("b: result=%q, want skipped", out[1].Result)
	}
	if out[2].Result != ResultPass || out[2].EndpointResult != "" {
		t.Errorf("c: a result with no fraud record must be untouched, got %+v", out[2])
	}
	if out[3].Result != ResultPass {
		t.Errorf("d: fraud PASS must stay pass, got %q", out[3].Result)
	}
}

func TestBackfillFraudVerdictsIsIdempotent(t *testing.T) {
	stored := []SimulationResult{{ID: "a", Result: ResultPass,
		FraudControl: &FraudControl{Verdict: "FAIL", Reason: "x"}}}
	once, _ := BackfillFraudVerdicts(stored)
	twice, changed := BackfillFraudVerdicts(once)
	if changed {
		t.Fatal("second backfill reported changes; it must be a no-op")
	}
	if twice[0].Result != once[0].Result || twice[0].Details != once[0].Details {
		t.Fatalf("second backfill altered the row: %+v vs %+v", once[0], twice[0])
	}
}
