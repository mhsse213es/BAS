package rwscore

import "testing"

func TestBucketDimension_AllPassIsPassRateOne(t *testing.T) {
	rows := []CoverageRow{{Capability: "prevention", Verdict: "PASS", Count: 5}}
	ds := bucketDimension(DimensionPrevention, rows)
	if ds.PassRate != 1.0 {
		t.Fatalf("PassRate = %v, want 1.0", ds.PassRate)
	}
	if ds.Pass != 5 {
		t.Fatalf("Pass = %d, want 5", ds.Pass)
	}
}

func TestBucketDimension_AllFailIsPassRateZero(t *testing.T) {
	rows := []CoverageRow{{Capability: "recovery", Verdict: "FAIL", Count: 3}}
	ds := bucketDimension(DimensionRecovery, rows)
	if ds.PassRate != 0.0 {
		t.Fatalf("PassRate = %v, want 0.0", ds.PassRate)
	}
	if ds.Fail != 3 {
		t.Fatalf("Fail = %d, want 3", ds.Fail)
	}
}

func TestBucketDimension_UnknownLowersPassRateBelowNaiveExclusion(t *testing.T) {
	// Acceptance criterion 3: insufficient_evidence (UNKNOWN) rows must stay
	// in the denominator. A WRONG implementation using a naive
	// Pass/(Pass+Fail) calculation (excluding Unknown from the denominator)
	// would compute 1.0 here, since there are zero Fail rows -- this test
	// fails against that wrong implementation and passes only against the
	// correct one (Pass/(Pass+Fail+Error+Unknown)).
	rows := []CoverageRow{
		{Capability: "detection", Verdict: "PASS", Count: 2},
		{Capability: "detection", Verdict: "SKIPPED", SkipReason: "insufficient_evidence", Count: 2},
	}
	ds := bucketDimension(DimensionDetection, rows)
	if ds.PassRate != 0.5 {
		t.Fatalf("PassRate = %v, want 0.5 (2 pass / (2 pass + 2 unknown) -- a naive Pass/(Pass+Fail) calc would wrongly give 1.0)", ds.PassRate)
	}
	if ds.Unknown != 2 {
		t.Fatalf("Unknown = %d, want 2", ds.Unknown)
	}
}

func TestBucketDimension_NotApplicableNeverChangesPassRate(t *testing.T) {
	withNA := []CoverageRow{
		{Capability: "containment", Verdict: "PASS", Count: 4},
		{Capability: "containment", Verdict: "SKIPPED", SkipReason: "not_applicable", Count: 100},
	}
	withoutNA := []CoverageRow{
		{Capability: "containment", Verdict: "PASS", Count: 4},
	}
	dsWith := bucketDimension(DimensionContainment, withNA)
	dsWithout := bucketDimension(DimensionContainment, withoutNA)
	if dsWith.PassRate != dsWithout.PassRate {
		t.Fatalf("PassRate with not_applicable rows = %v, without = %v -- not_applicable must be neutral", dsWith.PassRate, dsWithout.PassRate)
	}
	if dsWith.NotApplicable != 100 {
		t.Fatalf("NotApplicable = %d, want 100", dsWith.NotApplicable)
	}
}

func TestBucketDimension_EmptyDenominatorIsZeroNotNaN(t *testing.T) {
	rows := []CoverageRow{{Capability: "data_protection", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 10}}
	ds := bucketDimension(DimensionDataProtection, rows)
	if ds.PassRate != 0.0 {
		t.Fatalf("PassRate = %v, want 0.0 (not NaN) when nothing was evaluated", ds.PassRate)
	}
	if ds.NotTested != 10 {
		t.Fatalf("NotTested = %d, want 10", ds.NotTested)
	}
}

func TestBucketDimension_ErrorCountsSeparatelyFromUnknown(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "detection", Verdict: "ERROR", Count: 1},
		{Capability: "detection", Verdict: "SKIPPED", SkipReason: "insufficient_evidence", Count: 1},
	}
	ds := bucketDimension(DimensionDetection, rows)
	if ds.Error != 1 || ds.Unknown != 1 {
		t.Fatalf("Error=%d Unknown=%d, want 1/1 -- an evaluator that ran and failed operationally must stay distinct from ambiguous evidence", ds.Error, ds.Unknown)
	}
	if ds.PassRate != 0.0 {
		t.Fatalf("PassRate = %v, want 0.0 (0 pass / (0+0+1+1))", ds.PassRate)
	}
}

func TestBucketDimension_IgnoresRowsForOtherDimensions(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 99},
		{Capability: "recovery", Verdict: "FAIL", Count: 1},
	}
	ds := bucketDimension(DimensionRecovery, rows)
	if ds.Pass != 0 || ds.Fail != 1 {
		t.Fatalf("Pass=%d Fail=%d, want 0/1 -- a row for a different capability must never be counted", ds.Pass, ds.Fail)
	}
}
