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

func TestScoreRun_FullWeightedAverageAllDimensionsPresent(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 10}, // PassRate 1.0
		{Capability: "detection", Verdict: "FAIL", Count: 10},  // PassRate 0.0
		{Capability: "containment", Verdict: "PASS", Count: 5},
		{Capability: "containment", Verdict: "FAIL", Count: 5},      // PassRate 0.5
		{Capability: "recovery", Verdict: "PASS", Count: 10},        // PassRate 1.0
		{Capability: "data_protection", Verdict: "PASS", Count: 10}, // PassRate 1.0
	}
	score := ScoreRun(rows)
	// Overall = 100 * (0.25*1.0 + 0.20*0.0 + 0.20*0.5 + 0.25*1.0 + 0.10*1.0)
	//         = 100 * (0.25 + 0 + 0.10 + 0.25 + 0.10) = 100 * 0.70 = 70
	if score.Overall != 70.0 {
		t.Fatalf("Overall = %v, want 70.0", score.Overall)
	}
	if score.Rating != RatingAtRisk { // 50 <= 70 < 80
		t.Fatalf("Rating = %q, want at_risk", score.Rating)
	}
	if len(score.Dimensions) != 5 {
		t.Fatalf("got %d dimensions, want 5", len(score.Dimensions))
	}
}

func TestScoreRun_EmptyDimensionExcludedAndWeightRedistributed(t *testing.T) {
	// Recovery has zero evaluated rows (entirely not_tested). Spec section
	// C requires its 0.25 weight to be EXCLUDED and the remaining weights
	// (Prevention .25 + Detection .20 + Containment .20 + DataProtection
	// .10 = 0.75) rescaled to sum to 1.0 -- not Recovery counted as a hard
	// 0. With all 4 remaining PassRates at 1.0, the correct redistributed
	// Overall is 100.0. A WRONG implementation that instead counts the
	// empty Recovery dimension as a hard 0 with its original 0.25 weight
	// would compute 100*(0.25+0.20+0.20+0+0.10) = 75.0 -- a different,
	// distinguishable number, not just "doesn't error."
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 10},
		{Capability: "detection", Verdict: "PASS", Count: 10},
		{Capability: "containment", Verdict: "PASS", Count: 10},
		{Capability: "recovery", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 10},
		{Capability: "data_protection", Verdict: "PASS", Count: 10},
	}
	score := ScoreRun(rows)
	if score.Overall != 100.0 {
		t.Fatalf("Overall = %v, want 100.0 (redistributed) -- a hard-0 implementation would give 75.0 instead", score.Overall)
	}
}

func TestScoreRun_AllDimensionsEmptyGivesZeroAndVulnerable(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 1},
		{Capability: "detection", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 1},
		{Capability: "containment", Verdict: "SKIPPED", SkipReason: "not_applicable", Count: 1},
		{Capability: "recovery", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 1},
		{Capability: "data_protection", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 1},
	}
	score := ScoreRun(rows)
	if score.Overall != 0.0 {
		t.Fatalf("Overall = %v, want 0.0", score.Overall)
	}
	if score.Rating != RatingVulnerable {
		t.Fatalf("Rating = %q, want vulnerable -- absence of evidence must never read as safety", score.Rating)
	}
}

func TestScoreRun_RecoveryFailureCapsRatingAtAtRiskEvenWithHighOverall(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 10},
		{Capability: "detection", Verdict: "PASS", Count: 10},
		{Capability: "containment", Verdict: "PASS", Count: 10},
		{Capability: "recovery", Verdict: "FAIL", TechniqueID: "T1490", Count: 1},
		{Capability: "data_protection", Verdict: "PASS", Count: 10},
	}
	score := ScoreRun(rows)
	if score.Rating != RatingAtRisk {
		t.Fatalf("Rating = %q, want at_risk -- a failed critical Recovery test must never allow Protected regardless of the numeric score", score.Rating)
	}
	if !score.GateTriggered {
		t.Fatal("GateTriggered = false, want true")
	}
}

func TestScoreRun_GateNeverUpgradesALowRating(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "FAIL", Count: 10},
		{Capability: "detection", Verdict: "FAIL", Count: 10},
		{Capability: "containment", Verdict: "FAIL", Count: 10},
		{Capability: "recovery", Verdict: "FAIL", TechniqueID: "T1490", Count: 1},
		{Capability: "data_protection", Verdict: "FAIL", Count: 10},
	}
	score := ScoreRun(rows)
	if score.Rating != RatingVulnerable {
		t.Fatalf("Rating = %q, want vulnerable -- the gate is a ceiling, never an upgrade", score.Rating)
	}
}

func TestScoreRun_CriticalFailuresNameTheExactTechniqueAndCount(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 10},
		{Capability: "detection", Verdict: "PASS", Count: 10},
		{Capability: "containment", Verdict: "PASS", Count: 10},
		{Capability: "recovery", Verdict: "FAIL", TechniqueID: "T1490", Count: 2},
		{Capability: "data_protection", Verdict: "PASS", Count: 10},
	}
	score := ScoreRun(rows)
	if len(score.CriticalFailures) != 1 || score.CriticalFailures[0] != "Recovery FAILED for T1490 (2 attempt(s))" {
		t.Fatalf("CriticalFailures = %v, want [\"Recovery FAILED for T1490 (2 attempt(s))\"]", score.CriticalFailures)
	}
}

func TestScoreRun_NoCriticalFailuresWhenGateNotTriggered(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "recovery", Verdict: "PASS", Count: 10},
	}
	score := ScoreRun(rows)
	if len(score.CriticalFailures) != 0 {
		t.Fatalf("CriticalFailures = %v, want empty", score.CriticalFailures)
	}
	if score.GateTriggered {
		t.Fatal("GateTriggered = true, want false")
	}
}
