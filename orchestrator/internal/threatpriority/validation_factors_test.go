package threatpriority

import (
	"context"
	"testing"
	"time"
)

func TestPreventionSuccessFactor_Score(t *testing.T) {
	f := PreventionSuccessFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059", "T1105", "T1566"},
		shared: &sharedIndexes{preventionVerdict: map[string]VerdictEntry{
			"T1059": {Verdict: "pass"}, // control blocked it
			"T1105": {Verdict: "fail"}, // ran through unblocked
			// T1566 never tested -- excluded from the denominator
		}},
	}
	raw, explanation, available, err := f.Score(context.Background(), tctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Fatal("expected available=true")
	}
	if raw != 50 {
		t.Fatalf("raw = %.2f, want 50 (1 of 2 tested techniques prevented)", raw)
	}
	if explanation != "1 of 2 validated techniques prevented" {
		t.Fatalf("explanation = %q", explanation)
	}
}

func TestPreventionSuccessFactor_NoneTested_Unavailable(t *testing.T) {
	f := PreventionSuccessFactor{}
	_, _, available, _ := f.Score(context.Background(), Context{
		TechniqueIDs: []string{"T1059"},
		shared:       &sharedIndexes{preventionVerdict: map[string]VerdictEntry{}},
	})
	if available {
		t.Fatal("expected available=false when nothing tested")
	}
}

func TestValidationSuccessFactor_Score(t *testing.T) {
	f := ValidationSuccessFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059", "T1105"},
		shared: &sharedIndexes{validationVerdict: map[string]VerdictEntry{
			"T1059": {Verdict: "Detected"},
			"T1105": {Verdict: "NotDetected"},
		}},
	}
	raw, explanation, available, err := f.Score(context.Background(), tctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available || raw != 50 {
		t.Fatalf("raw=%.2f available=%v, want 50/true", raw, available)
	}
	if explanation != "1 of 2 validated techniques validated" {
		t.Fatalf("explanation = %q", explanation)
	}
}

func TestValidationPct_IgnoresAtWhenComparingVerdict(t *testing.T) {
	f := PreventionSuccessFactor{}
	oldTime := time.Now().Add(-999 * time.Hour)
	tctx := Context{
		TechniqueIDs: []string{"T1059"},
		shared: &sharedIndexes{preventionVerdict: map[string]VerdictEntry{
			"T1059": {Verdict: "fail", At: oldTime}, // stale timestamp, but Verdict is what's compared
		}},
	}
	raw, _, available, _ := f.Score(context.Background(), tctx)
	if !available || raw != 0 {
		t.Fatalf("raw=%.2f available=%v, want 0/true (fail is not success regardless of At)", raw, available)
	}
}

func TestValidationFactors_WeightScalesWithBlend(t *testing.T) {
	f := PreventionSuccessFactor{}
	low := f.Weight(Context{ValidatedCount: 0})    // validation=0.10 -> 0.10*0.85/2
	high := f.Weight(Context{ValidatedCount: 100}) // validation=0.80 -> 0.80*0.85/2
	if high <= low {
		t.Fatalf("expected validation weight to grow as validated evidence grows: low=%.4f high=%.4f", low, high)
	}
}
