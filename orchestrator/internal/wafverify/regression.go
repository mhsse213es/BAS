// Package wafverify is a meta-validation layer covering waf.txt Phase
// 10's independent-verification-and-continuous-mastery items: regression
// suites, vendor/version benchmarks, finding reproduction, remediation
// retests, and coverage-quality gates. This is the final phase of the
// waf.txt 10-phase roadmap. Unlike every attack-content phase, it is
// generic over any already-computed wafval.Verdict regardless of which
// attack vector, evasion technique, or profile produced it, so it
// depends only on internal/wafval and never cross-references
// internal/wafcatalog or any sibling WAF-phase package. There is no
// cross-run persistence here: "before/after" is expressed purely as two
// function arguments, never a stored history.
package wafverify

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// verdictRank orders ClaimPrevention-shaped verdicts only: Missed (0) <
// DetectedButAllowed (1) < Blocked (2). VerdictAllowed and
// VerdictIncorrectlyBlocked are ClaimFalsePositive-shaped -- their
// "better" direction runs the opposite way, so mixing them onto this
// scale would conflate two different claim types. VerdictInconclusive
// has no direction at all. All three report ok=false rather than
// falling through to a default rank.
func verdictRank(v wafval.Verdict) (rank int, ok bool) {
	switch v {
	case wafval.VerdictMissed:
		return 0, true
	case wafval.VerdictDetectedButAllowed:
		return 1, true
	case wafval.VerdictBlocked:
		return 2, true
	default:
		return 0, false
	}
}

// RegressionScenario is the claim that a scenario's verdict stays
// stable (or improves) over time, rather than silently regressing.
type RegressionScenario struct {
	ID          string
	Description string
	Provenance  string
}

// NewRegressionScenario validates at construction time, never at render
// time.
func NewRegressionScenario(id string, description string, provenance string) (RegressionScenario, error) {
	if id == "" {
		return RegressionScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return RegressionScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return RegressionScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return RegressionScenario{ID: id, Description: description, Provenance: provenance}, nil
}

// RegressionStatus is the outcome of comparing a baseline verdict
// against a current one for the same scenario.
type RegressionStatus string

const (
	RegressionStable       RegressionStatus = "stable"
	RegressionImproved     RegressionStatus = "improved"
	RegressionRegressed    RegressionStatus = "regressed"
	RegressionInconclusive RegressionStatus = "inconclusive"
)

// EvaluateRegression ranks both verdicts; either side unrankable
// resolves to RegressionInconclusive rather than guessing a direction.
func EvaluateRegression(scenario RegressionScenario, baseline wafval.Verdict, current wafval.Verdict) (RegressionStatus, string, error) {
	baselineRank, baselineOK := verdictRank(baseline)
	currentRank, currentOK := verdictRank(current)
	if !baselineOK || !currentOK {
		return RegressionInconclusive, fmt.Sprintf("baseline verdict %q or current verdict %q is not a ClaimPrevention-shaped verdict this comparison can rank", baseline, current), nil
	}
	switch {
	case currentRank < baselineRank:
		return RegressionRegressed, fmt.Sprintf("current verdict %q ranks below baseline verdict %q", current, baseline), nil
	case currentRank > baselineRank:
		return RegressionImproved, fmt.Sprintf("current verdict %q ranks above baseline verdict %q", current, baseline), nil
	default:
		return RegressionStable, fmt.Sprintf("current verdict %q matches baseline verdict %q", current, baseline), nil
	}
}
