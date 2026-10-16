package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestEvaluateContributingVector_BlockedEvidence_ReturnsBlocked(t *testing.T) {
	results := []wafval.CollectionResult{
		{
			Mechanism: wafval.MechanismWAFEngine,
			Coverage:  wafval.CoverageFound,
			Observations: []wafval.Observation{
				{Mechanism: wafval.MechanismWAFEngine, Enforcement: wafval.EnforcementBlocked, EvidenceKind: wafval.EvidenceObserved},
			},
		},
	}
	result, err := EvaluateContributingVector("V-1", results)
	if err != nil {
		t.Fatalf("EvaluateContributingVector: %v", err)
	}
	if result.Verdict != wafval.VerdictBlocked {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictBlocked)
	}
}

func TestEvaluateContributingVector_MissedEvidence_ReturnsMissed(t *testing.T) {
	results := []wafval.CollectionResult{
		{
			Mechanism: wafval.MechanismWAFEngine,
			Coverage:  wafval.CoverageSearchedVerifiedNone,
			Observations: []wafval.Observation{
				{Mechanism: wafval.MechanismWAFEngine, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, EvidenceKind: wafval.EvidenceObserved},
			},
		},
	}
	result, err := EvaluateContributingVector("V-2", results)
	if err != nil {
		t.Fatalf("EvaluateContributingVector: %v", err)
	}
	if result.Verdict != wafval.VerdictMissed {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictMissed)
	}
}

func TestEvaluateContributingVector_NoWAFEvidence_ReturnsInconclusive(t *testing.T) {
	result, err := EvaluateContributingVector("V-3", []wafval.CollectionResult{})
	if err != nil {
		t.Fatalf("EvaluateContributingVector: %v", err)
	}
	if result.Verdict != wafval.VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictInconclusive)
	}
}
