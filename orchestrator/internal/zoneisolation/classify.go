package zoneisolation

import (
	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkpath"
)

// IsolationSeverity classifies one ZonePairIsolation's check result.
type IsolationSeverity string

const (
	// SeverityConfirmedViolation: a real observation demonstrates the
	// pair is actually reachable (cloudgraph.Observed). The strongest,
	// least disputable finding.
	SeverityConfirmedViolation IsolationSeverity = "confirmed-violation"

	// SeverityUnconfirmedExposure: policy/routing evidence permits a
	// path but nothing has actually observed it being used
	// (cloudgraph.PolicySupported). Deliberately reported as a
	// DISTINCT, weaker severity from SeverityConfirmedViolation --
	// never collapsed into it -- per this initiative's standing "never
	// let a weaker signal masquerade as a stronger one" discipline.
	SeverityUnconfirmedExposure IsolationSeverity = "unconfirmed-exposure"

	// SeverityNoViolationFound: cloudgraph.Blocked, or
	// cloudgraph.Unknown (no known route at all). These are NOT the
	// same claim -- see ClassifyIsolation's Limitations text. "No
	// known route" is never reported as "confirmed isolated": missing
	// topology data is not proof of isolation.
	SeverityNoViolationFound IsolationSeverity = "no-violation-found"
)

// IsolationCheckResult is one declared pair's classified result,
// carrying the full composed path as its evidence.
type IsolationCheckResult struct {
	ZonePairIsolation ZonePairIsolation      `json:"zonePairIsolation"`
	Severity          IsolationSeverity      `json:"severity"`
	Path              networkpath.PathResult `json:"path"`
	Limitations       string                 `json:"limitations,omitempty"`
}

// ClassifyIsolation is a pure function of an already-composed path --
// it never finds a route or composes evidence itself (mirrors
// otsafety.ValidateRequiredTransits's own decoupling from whichever
// routing engine produced the routes it checks). cloudgraph.Candidate
// and cloudgraph.ConditionallyReachable are never produced by
// networkpolicy.EvaluatePolicyMatrix and are not reachable through
// this phase's own composition; they fall into the default case
// defensively, alongside PolicySupported.
func ClassifyIsolation(pair ZonePairIsolation, path networkpath.PathResult) IsolationCheckResult {
	result := IsolationCheckResult{ZonePairIsolation: pair, Path: path}
	switch path.State {
	case cloudgraph.Observed:
		result.Severity = SeverityConfirmedViolation
	case cloudgraph.Blocked:
		result.Severity = SeverityNoViolationFound
	case cloudgraph.Unknown:
		result.Severity = SeverityNoViolationFound
		result.Limitations = "no known route was found between these zones -- this is not proof of isolation, only an absence of evidence"
	default: // PolicySupported, Candidate, ConditionallyReachable
		result.Severity = SeverityUnconfirmedExposure
	}
	return result
}
