package dlpresilience

import (
	"fmt"
	"time"
)

// FailureMode is the declared contract for what a product should do
// when the classification or policy service it depends on becomes
// unavailable. An open string, never a closed enum with an assumed
// "correct" default -- the right mode is policy- and
// product-dependent, decided by whoever authors the expectation.
type FailureMode string

const (
	FailOpen        FailureMode = "fail-open"        // operation proceeds as if no policy applied
	FailClosed      FailureMode = "fail-closed"      // operation is blocked/denied outright
	Defer           FailureMode = "defer"            // operation is held/queued until the service returns
	IndeterminateOK FailureMode = "indeterminate-ok" // any classified mode is an accepted outcome for this expectation
)

// ServiceUnavailabilityExpectation declares what should happen for one
// dependency (classification or policy) when it is unavailable.
type ServiceUnavailabilityExpectation struct {
	ExpectationID string
	Dependency    string // "classification" | "policy"
	ExpectedMode  FailureMode
	Note          string
}

// ServiceUnavailabilityEvidence is one observed record of what
// actually happened while the named dependency was unavailable.
type ServiceUnavailabilityEvidence struct {
	ExpectationID string
	Dependency    string
	ObservedMode  FailureMode // "" = outcome could not be classified into any known mode
	Timestamp     time.Time
	Source        EvidenceSource
}

type EvidenceSource string

const SourceFixture EvidenceSource = "recorded-fixture"

// ServiceUnavailabilityProvider supplies service-unavailability
// evidence for an expectation ID and time window. A returned error
// means collection failed -- distinct from a successful search that
// found nothing (nil error, empty slice).
type ServiceUnavailabilityProvider interface {
	ServiceUnavailabilityEvidenceFor(expectationID string, window TimeWindow) ([]ServiceUnavailabilityEvidence, error)
}

type TimeWindow struct{ Start, End time.Time }

// FixtureServiceUnavailabilityProvider wraps an in-memory slice of
// hand-built ServiceUnavailabilityEvidence values -- no real service
// is ever taken offline by this package; it evaluates a declared
// contract against evidence, fixture or otherwise supplied.
type FixtureServiceUnavailabilityProvider struct {
	events []ServiceUnavailabilityEvidence
}

func NewFixtureServiceUnavailabilityProvider(events []ServiceUnavailabilityEvidence) *FixtureServiceUnavailabilityProvider {
	return &FixtureServiceUnavailabilityProvider{events: events}
}

func (p *FixtureServiceUnavailabilityProvider) ServiceUnavailabilityEvidenceFor(expectationID string, window TimeWindow) ([]ServiceUnavailabilityEvidence, error) {
	var out []ServiceUnavailabilityEvidence
	for _, e := range p.events {
		if e.ExpectationID != expectationID {
			continue
		}
		if e.Timestamp.Before(window.Start) || e.Timestamp.After(window.End) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// ResilienceOutcome is this package's own independent verdict
// vocabulary -- never reporting.ComparisonResult, never
// dlpclassify.DLPCLSOutcome, never dlppolicy's verdict type.
type ResilienceOutcome string

const (
	OutcomeModeMatched    ResilienceOutcome = "mode-matched"
	OutcomeModeMismatched ResilienceOutcome = "mode-mismatched"
	OutcomeInconclusive   ResilienceOutcome = "inconclusive"
)

type ResilienceVerdict struct {
	Outcome ResilienceOutcome
	Reason  string
}

// VerifyServiceUnavailabilityExpectation compares a declared
// failure-mode contract against observed evidence. IndeterminateOK
// matches any non-empty ObservedMode -- that is its entire meaning,
// not itself a 5th real-world failure mode.
func VerifyServiceUnavailabilityExpectation(exp ServiceUnavailabilityExpectation, provider ServiceUnavailabilityProvider, window TimeWindow) ResilienceVerdict {
	if exp.ExpectedMode == "" {
		return ResilienceVerdict{Outcome: OutcomeInconclusive, Reason: "expectation declares no failure mode"}
	}

	records, err := provider.ServiceUnavailabilityEvidenceFor(exp.ExpectationID, window)
	if err != nil {
		return ResilienceVerdict{Outcome: OutcomeInconclusive, Reason: fmt.Sprintf("service-unavailability evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return ResilienceVerdict{Outcome: OutcomeInconclusive, Reason: "no service-unavailability evidence found for this expectation in the window"}
	}
	latest := latestResilienceEvidenceByTimestamp(records)

	if latest.ObservedMode == "" {
		return ResilienceVerdict{Outcome: OutcomeInconclusive, Reason: "observed behavior could not be classified into a known failure mode"}
	}
	if exp.ExpectedMode == IndeterminateOK {
		return ResilienceVerdict{Outcome: OutcomeModeMatched}
	}
	if latest.ObservedMode == exp.ExpectedMode {
		return ResilienceVerdict{Outcome: OutcomeModeMatched}
	}
	return ResilienceVerdict{Outcome: OutcomeModeMismatched, Reason: fmt.Sprintf("expected failure mode %q, observed %q", exp.ExpectedMode, latest.ObservedMode)}
}

func latestResilienceEvidenceByTimestamp(records []ServiceUnavailabilityEvidence) ServiceUnavailabilityEvidence {
	latest := records[0]
	for _, r := range records[1:] {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	return latest
}
