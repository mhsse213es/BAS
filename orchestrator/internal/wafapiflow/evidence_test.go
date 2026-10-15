package wafapiflow

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestAPIFlowVector_Expectations_WithBenignCounterpart_ReturnsTwoLegs(t *testing.T) {
	v := mustVector(t, "APIFLOW-001")
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 2 {
		t.Fatalf("len(legs) = %d, want 2", len(legs))
	}
	if legs[0].Leg != LegMalicious || legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want LegMalicious with ClaimPrevention", legs[0])
	}
	if legs[1].Leg != LegBenign || legs[1].Expectation.Claim != wafval.ClaimFalsePositive {
		t.Errorf("legs[1] = %+v, want LegBenign with ClaimFalsePositive", legs[1])
	}
}

// Review Focus: Expectations must never pad to 2 entries when there is no
// BenignCounterpart -- exactly 1 (the malicious leg), always first.
func TestAPIFlowVector_Expectations_NoBenignCounterpart_ReturnsOneLeg(t *testing.T) {
	v, err := NewAPIFlowVector("APIFLOW-004", 1, CategoryGraphQLAbuse, "x", SeverityHigh, "x", validMalicious(), nil, "no legitimate lookalike for this probe", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAPIFlowVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 1 {
		t.Fatalf("len(legs) = %d, want 1", len(legs))
	}
	if legs[0].Leg != LegMalicious || legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want LegMalicious with ClaimPrevention", legs[0])
	}
}

func TestAPIFlowVector_Expectations_VectorIDCarriedOnEachLeg(t *testing.T) {
	v := mustVector(t, "APIFLOW-001")
	legs := v.Expectations("owasp-crs-default")
	for _, leg := range legs {
		if leg.VectorID != "APIFLOW-001" {
			t.Errorf("leg.VectorID = %q, want %q", leg.VectorID, "APIFLOW-001")
		}
	}
}
