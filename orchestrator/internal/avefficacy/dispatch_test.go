package avefficacy

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

func dispatchClaim() avval.Expectation {
	return avval.Expectation{Claim: avval.ClaimPrevention, PolicyBasis: "test"}
}

func dispatchKey() avval.CorrelationKey {
	return avval.CorrelationKey{TestExecutionID: "AV-BEHAV-001", Target: "AV-BEHAV-001"}
}

// Review Focus: a "pass" (blocked) dispatch result, with no detection
// evidence at all, must still resolve to VerifiedProtection on its own --
// derivePrevention's Blocked case never needs the Detection axis.
func TestBuildCollectionResultsFromDispatch_Pass_ResolvesVerifiedProtection(t *testing.T) {
	results, err := BuildCollectionResultsFromDispatch(DispatchedStepResult{
		PreventionSource: avval.ControlSourceNGAVBehavioral,
		Provider:         "harness",
		CheckResult:      "pass",
		Details:          "PASS: remote memory allocation/write was denied or prevented. detection=UNAVAILABLE [BAS-SIM-AVBEHAV001]",
		ObservedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("BuildCollectionResultsFromDispatch: %v", err)
	}
	res := avval.EvaluateClaim(dispatchClaim(), results, dispatchKey())
	if res.Finding != avval.FindingVerifiedProtection {
		t.Errorf("Finding = %q, want %q", res.Finding, avval.FindingVerifiedProtection)
	}
}

// Review Focus: the exact caveat the user raised -- a "fail" (allowed)
// dispatch result with NO detection evidence source at all must NOT be
// equated with a confirmed gap. It must resolve Inconclusive under
// avval's own real derivePrevention logic (the Detection axis never
// resolved to AxisAgree), never a fabricated ConfirmedGap.
func TestBuildCollectionResultsFromDispatch_FailWithNoDetectionSource_ResolvesInconclusive_NotConfirmedGap(t *testing.T) {
	results, err := BuildCollectionResultsFromDispatch(DispatchedStepResult{
		PreventionSource: avval.ControlSourceNGAVBehavioral,
		Provider:         "harness",
		CheckResult:      "fail",
		Details:          "FAIL: VirtualAllocEx + WriteProcessMemory into a disposable process succeeded unblocked [BAS-SIM-AVBEHAV001]",
		ObservedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("BuildCollectionResultsFromDispatch: %v", err)
	}
	res := avval.EvaluateClaim(dispatchClaim(), results, dispatchKey())
	if res.Finding != avval.FindingInconclusive {
		t.Errorf("Finding = %q, want %q (successful execution alone must never be equated with a detection failure)", res.Finding, avval.FindingInconclusive)
	}
}

// Review Focus: a "fail" result PLUS a real detection check that genuinely
// searched the local Defender log and verified nothing was found
// ("detection=NOT_OBSERVED") earns ConfirmedGap -- this is the one path
// where a gap is legitimately established, because the evidence coverage
// actually justifies the conclusion.
func TestBuildCollectionResultsFromDispatch_FailWithDetectionNotObserved_ResolvesConfirmedGap(t *testing.T) {
	results, err := BuildCollectionResultsFromDispatch(DispatchedStepResult{
		PreventionSource: avval.ControlSourceNGAVBehavioral,
		DetectionSource:  avval.ControlSourceAVEngine,
		Provider:         "harness",
		CheckResult:      "fail",
		Details:          "FAIL: ... detection=NOT_OBSERVED [BAS-SIM-AVBEHAV001]",
		ObservedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("BuildCollectionResultsFromDispatch: %v", err)
	}
	res := avval.EvaluateClaim(dispatchClaim(), results, dispatchKey())
	if res.Finding != avval.FindingConfirmedGap {
		t.Errorf("Finding = %q, want %q", res.Finding, avval.FindingConfirmedGap)
	}
}

// Review Focus: a "fail" result where the local Defender log genuinely
// recorded a correlating detection event ("detection=DETECTED") is an
// enforcement gap -- detected but not blocked -- also a real,
// evidence-justified ConfirmedGap, distinct in reason from the
// NOT_OBSERVED case.
func TestBuildCollectionResultsFromDispatch_FailWithDetectionDetected_ResolvesConfirmedGap(t *testing.T) {
	results, err := BuildCollectionResultsFromDispatch(DispatchedStepResult{
		PreventionSource: avval.ControlSourceNGAVBehavioral,
		DetectionSource:  avval.ControlSourceAVEngine,
		Provider:         "harness",
		CheckResult:      "fail",
		Details:          "FAIL: ... detection=DETECTED [BAS-SIM-AVBEHAV001]",
		ObservedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("BuildCollectionResultsFromDispatch: %v", err)
	}
	res := avval.EvaluateClaim(dispatchClaim(), results, dispatchKey())
	if res.Finding != avval.FindingConfirmedGap {
		t.Errorf("Finding = %q, want %q", res.Finding, avval.FindingConfirmedGap)
	}
	if !strings.Contains(res.Reason, "detected but not blocked") {
		t.Errorf("Reason = %q, want it to distinguish the detected-but-allowed case", res.Reason)
	}
}

// Review Focus: when the detection-telemetry source itself was
// unavailable (the local Defender log could not be queried), the
// resulting CollectionResult must carry CoverageSourceUnavailable, not a
// verified negative -- an unreachable source is never read as "searched
// and found nothing".
func TestBuildCollectionResultsFromDispatch_DetectionUnavailable_IsSourceUnavailable_NotVerifiedNone(t *testing.T) {
	results, err := BuildCollectionResultsFromDispatch(DispatchedStepResult{
		PreventionSource: avval.ControlSourceNGAVBehavioral,
		DetectionSource:  avval.ControlSourceAVEngine,
		Provider:         "harness",
		CheckResult:      "fail",
		Details:          "FAIL: ... detection=UNAVAILABLE [BAS-SIM-AVBEHAV001]",
		ObservedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("BuildCollectionResultsFromDispatch: %v", err)
	}
	var detectionResult *avval.CollectionResult
	for i := range results {
		if results[i].ControlSource == avval.ControlSourceAVEngine {
			detectionResult = &results[i]
		}
	}
	if detectionResult == nil {
		t.Fatal("no detection CollectionResult found")
	}
	if detectionResult.Coverage != avval.CoverageSourceUnavailable {
		t.Errorf("Coverage = %q, want %q", detectionResult.Coverage, avval.CoverageSourceUnavailable)
	}
	res := avval.EvaluateClaim(dispatchClaim(), results, dispatchKey())
	if res.Finding != avval.FindingInconclusive {
		t.Errorf("Finding = %q, want %q (an unreachable detection source must never justify a gap)", res.Finding, avval.FindingInconclusive)
	}
}

// Review Focus: "skipped" (an environment prerequisite was missing, e.g.
// no .NET compiler or no disposable target) must carry zero observations
// and resolve Inconclusive via CompletenessInsufficient -- missing
// evidence, never a fabricated finding.
func TestBuildCollectionResultsFromDispatch_Skipped_ResolvesInconclusive(t *testing.T) {
	results, err := BuildCollectionResultsFromDispatch(DispatchedStepResult{
		PreventionSource: avval.ControlSourceNGAVBehavioral,
		CheckResult:      "skipped",
		Details:          "SKIP: could not compile P/Invoke probe (no .NET compiler available).",
		ObservedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("BuildCollectionResultsFromDispatch: %v", err)
	}
	if len(results) != 1 || len(results[0].Observations) != 0 {
		t.Fatalf("results = %+v, want exactly one CollectionResult with zero Observations", results)
	}
	res := avval.EvaluateClaim(dispatchClaim(), results, dispatchKey())
	if res.Finding != avval.FindingInconclusive {
		t.Errorf("Finding = %q, want %q", res.Finding, avval.FindingInconclusive)
	}
	if res.Completeness != avval.CompletenessInsufficient {
		t.Errorf("Completeness = %q, want %q", res.Completeness, avval.CompletenessInsufficient)
	}
}

// Review Focus: "error" is a dispatch/operational failure (the agent
// couldn't run the step at all), not security evidence -- it must come
// back as a Go error, never silently fabricated into a finding.
func TestBuildCollectionResultsFromDispatch_Error_ReturnsGoError(t *testing.T) {
	_, err := BuildCollectionResultsFromDispatch(DispatchedStepResult{
		PreventionSource: avval.ControlSourceNGAVBehavioral,
		CheckResult:      "error",
		Details:          "agent unreachable",
	})
	if err == nil {
		t.Fatal("want a non-nil error for CheckResult=error")
	}
}

func TestBuildCollectionResultsFromDispatch_UnrecognizedCheckResult_ReturnsGoError(t *testing.T) {
	_, err := BuildCollectionResultsFromDispatch(DispatchedStepResult{
		PreventionSource: avval.ControlSourceNGAVBehavioral,
		CheckResult:      "vetoed",
	})
	if err == nil {
		t.Fatal("want a non-nil error for an unrecognized CheckResult")
	}
}

// Review Focus: contradictory evidence -- two DIFFERENT control sources'
// dispatch-derived observations disagreeing on Prevention -- must resolve
// Inconclusive through avval's real cross-source contradiction logic, the
// same real evaluator this bridge feeds everywhere else.
func TestBuildCollectionResultsFromDispatch_ContradictoryAcrossControlSources_ResolvesInconclusive(t *testing.T) {
	blocked, err := BuildCollectionResultsFromDispatch(DispatchedStepResult{
		PreventionSource: avval.ControlSourceNGAVBehavioral,
		CheckResult:      "pass",
		Details:          "PASS: denied",
		ObservedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("BuildCollectionResultsFromDispatch (blocked leg): %v", err)
	}
	allowed, err := BuildCollectionResultsFromDispatch(DispatchedStepResult{
		PreventionSource: avval.ControlSourceEDR,
		CheckResult:      "fail",
		Details:          "FAIL: succeeded unblocked",
		ObservedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("BuildCollectionResultsFromDispatch (allowed leg): %v", err)
	}
	combined := append(blocked, allowed...)
	res := avval.EvaluateClaim(dispatchClaim(), combined, dispatchKey())
	if res.Finding != avval.FindingInconclusive {
		t.Errorf("Finding = %q, want %q", res.Finding, avval.FindingInconclusive)
	}
	if res.View.PreventionAx.State != avval.AxisContradictory {
		t.Errorf("PreventionAx.State = %q, want %q", res.View.PreventionAx.State, avval.AxisContradictory)
	}
}

// Review Focus: delayed evidence -- a real detection observation that
// arrives after the vector's declared DetectionSLA -- must flow through
// internal/avefficacy's own existing evaluateDetectionLatency and resolve
// LatencySLABreached, exercised here against the REAL AV-BEHAV-001 vector
// from the catalog, not a synthetic one.
func TestBuildCollectionResultsFromDispatch_DelayedDetection_ResolvesLatencySLABreached(t *testing.T) {
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	var vector avcatalog.Vector
	for _, v := range catalog {
		if v.ID == "AV-BEHAV-001" {
			vector = v
		}
	}
	if vector.ID == "" {
		t.Fatal("AV-BEHAV-001 not found in catalog")
	}

	executedAt := time.Now()
	detectedAt := executedAt.Add(2 * time.Hour) // well beyond any reasonable SLA

	results, err := BuildCollectionResultsFromDispatch(DispatchedStepResult{
		PreventionSource: avval.ControlSourceNGAVBehavioral,
		DetectionSource:  avval.ControlSourceAVEngine,
		Provider:         "harness",
		CheckResult:      "fail",
		Details:          "FAIL: ... detection=DETECTED [BAS-SIM-AVBEHAV001]",
		ObservedAt:       detectedAt,
	})
	if err != nil {
		t.Fatalf("BuildCollectionResultsFromDispatch: %v", err)
	}

	outcome, err := EvaluateVector(vector, "test", VectorFixture{
		PreventionEvidence: results,
		TestExecutedAt:     executedAt,
		DetectionSLA:       5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.DetectionLatency != LatencySLABreached {
		t.Errorf("DetectionLatency = %q, want %q", outcome.DetectionLatency, LatencySLABreached)
	}
}
