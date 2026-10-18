package reporting

import "regexp"

// Observed outcomes emitted by an application-control behavioral step as an
// APPCTL_OUTCOME line. Expected intents come from the test contract.
const (
	AppCtlBlockedAsExpected = "blocked_as_expected"
	AppCtlAllowedUnexpected = "allowed_unexpectedly"
	AppCtlAllowedByPolicy   = "allowed_by_policy"
	AppCtlNotEnforced       = "not_enforced"
	AppCtlInconclusive      = "inconclusive"
	AppCtlNotApplicable     = "not_applicable"

	AppCtlExpectBlocked = "blocked"
	AppCtlExpectAllowed = "allowed"
)

var appCtlObservedValues = map[string]bool{
	AppCtlBlockedAsExpected: true, AppCtlAllowedUnexpected: true,
	AppCtlAllowedByPolicy: true, AppCtlNotEnforced: true,
	AppCtlInconclusive: true, AppCtlNotApplicable: true,
}

var appCtlOutcomeRe = regexp.MustCompile(`(?m)^APPCTL_OUTCOME:\s*(\S+)\s*$`)

// ParseAppControlOutcome returns the single observed outcome a step emitted.
// Missing, malformed, or multiple differing markers are not parseable: an
// ambiguous result must not reach the comparator as a verdict.
func ParseAppControlOutcome(output string) (string, bool) {
	matches := appCtlOutcomeRe.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return "", false
	}
	value := matches[0][1]
	for _, m := range matches[1:] {
		if m[1] != value {
			return "", false
		}
	}
	if !appCtlObservedValues[value] {
		return "", false
	}
	return value, true
}

// appcontrolComparator maps a contract's declared intent against an observed
// outcome. Inconclusive is never a Match, and blocked-as-expected only
// matches a contract that expected a block.
type appcontrolComparator struct{}

func (appcontrolComparator) Compare(expected, observed string) ComparisonResult {
	if !appCtlObservedValues[observed] {
		return Unknown
	}
	switch observed {
	case AppCtlInconclusive:
		return MissingEvidence
	case AppCtlNotApplicable:
		return NotApplicable
	}
	switch expected {
	case AppCtlExpectBlocked:
		if observed == AppCtlBlockedAsExpected {
			return Match
		}
		return Mismatch
	case AppCtlExpectAllowed:
		if observed == AppCtlAllowedByPolicy {
			return Match
		}
		return Mismatch
	}
	return Unknown
}

func init() {
	RegisterComparator("appcontrol", appcontrolComparator{})
}

// AppControlEvidence is the evidence a behavioral application-control result
// carries. Mirrors DLPEvidence: Limitations is always populated.
type AppControlEvidence struct {
	CollectionMethod        string
	CorrelationID           string
	FixtureID               string
	EffectivePolicySnapshot string
	CaptureTimestamp        string
	PolicyEvaluated         bool
	Limitations             string
}

const appControlDefaultLimitations = "Results hold only for the tested Windows build, policy version, and execution path. They do not generalize to other paths, policy scopes, or products. Attribution depends on the control's event log being retained and readable."

// NewAppControlEvidence builds evidence with the standard limitations text.
func NewAppControlEvidence(method, correlationID, fixtureID, policySnapshot, capturedAt string, evaluated bool) AppControlEvidence {
	return AppControlEvidence{
		CollectionMethod:        method,
		CorrelationID:           correlationID,
		FixtureID:               fixtureID,
		EffectivePolicySnapshot: policySnapshot,
		CaptureTimestamp:        capturedAt,
		PolicyEvaluated:         evaluated,
		Limitations:             appControlDefaultLimitations,
	}
}
