package wafverify

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// RemediationScenario is the claim that a previously-identified issue's
// fix can be confirmed by re-testing it.
type RemediationScenario struct {
	ID          string
	Description string
	Provenance  string
}

// NewRemediationScenario validates at construction time, never at
// render time.
func NewRemediationScenario(id string, description string, provenance string) (RemediationScenario, error) {
	if id == "" {
		return RemediationScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return RemediationScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return RemediationScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return RemediationScenario{ID: id, Description: description, Provenance: provenance}, nil
}

// RemediationStatus is the outcome of comparing a baseline (pre-fix)
// verdict against a retest (post-fix) verdict. Unchanged is deliberately
// neutral: it applies whether the pair sits at a low (still-broken) or
// high (already-fixed) rank, never implying "still broken" on its own.
type RemediationStatus string

const (
	RemediationFixed        RemediationStatus = "fixed"
	RemediationUnchanged    RemediationStatus = "unchanged"
	RemediationRegressed    RemediationStatus = "regressed"
	RemediationInconclusive RemediationStatus = "inconclusive"
)

// EvaluateRemediation ranks both verdicts; either side unrankable
// resolves to RemediationInconclusive rather than guessing a direction.
func EvaluateRemediation(scenario RemediationScenario, baseline wafval.Verdict, retest wafval.Verdict) (RemediationStatus, string, error) {
	baselineRank, baselineOK := verdictRank(baseline)
	retestRank, retestOK := verdictRank(retest)
	if !baselineOK || !retestOK {
		return RemediationInconclusive, fmt.Sprintf("baseline verdict %q or retest verdict %q is not a ClaimPrevention-shaped verdict this comparison can rank", baseline, retest), nil
	}
	switch {
	case retestRank > baselineRank:
		return RemediationFixed, fmt.Sprintf("retest verdict %q ranks above baseline verdict %q", retest, baseline), nil
	case retestRank < baselineRank:
		return RemediationRegressed, fmt.Sprintf("retest verdict %q ranks below baseline verdict %q", retest, baseline), nil
	default:
		return RemediationUnchanged, fmt.Sprintf("retest verdict %q matches baseline verdict %q", retest, baseline), nil
	}
}
