package wafverify

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// ReproductionScenario is the claim that a finding can be reproduced:
// re-running the same scenario produces the same verdict.
type ReproductionScenario struct {
	ID          string
	Description string
	Provenance  string
}

// NewReproductionScenario validates at construction time, never at
// render time.
func NewReproductionScenario(id string, description string, provenance string) (ReproductionScenario, error) {
	if id == "" {
		return ReproductionScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return ReproductionScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return ReproductionScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return ReproductionScenario{ID: id, Description: description, Provenance: provenance}, nil
}

// ReproductionStatus is the outcome of comparing an original finding's
// verdict against a reproduction attempt's verdict.
type ReproductionStatus string

const (
	ReproductionConfirmed    ReproductionStatus = "confirmed"
	ReproductionNotConfirmed ReproductionStatus = "not_confirmed"
	ReproductionInconclusive ReproductionStatus = "inconclusive"
)

// EvaluateReproduction compares original and attempt by exact equality,
// not by rank -- reproducibility applies uniformly to any verdict,
// including ClaimFalsePositive-shaped ones, which the ranked shapes
// (Regression/Benchmark/Remediation) cannot handle. A VerdictInconclusive
// on either side has nothing to confirm or deny.
func EvaluateReproduction(scenario ReproductionScenario, original wafval.Verdict, attempt wafval.Verdict) (ReproductionStatus, string, error) {
	if original == wafval.VerdictInconclusive || attempt == wafval.VerdictInconclusive {
		return ReproductionInconclusive, fmt.Sprintf("original verdict %q or reproduction-attempt verdict %q is itself inconclusive; nothing to confirm or deny", original, attempt), nil
	}
	if original == attempt {
		return ReproductionConfirmed, fmt.Sprintf("reproduction attempt verdict %q matches the original finding's verdict %q", attempt, original), nil
	}
	return ReproductionNotConfirmed, fmt.Sprintf("reproduction attempt verdict %q does not match the original finding's verdict %q", attempt, original), nil
}
