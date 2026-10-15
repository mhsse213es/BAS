package webgwefficacy

import (
	"fmt"
	"time"
)

// ExpectedFailureBehavior is what a gateway deployment was declared
// to be expected to do for its OWN traffic when the gateway service
// itself becomes unreachable -- a system-level claim, never a
// per-request policy decision.
type ExpectedFailureBehavior string

const (
	ExpectedFailClosed ExpectedFailureBehavior = "fail-closed"
	ExpectedFailOpen   ExpectedFailureBehavior = "fail-open"
)

// FailureModeExpectation is a declared "when this gateway becomes
// unreachable, traffic should fail open/closed" claim for one named
// outage scenario.
type FailureModeExpectation struct {
	ScenarioLabel    string                  `json:"scenarioLabel"`
	ExpectedBehavior ExpectedFailureBehavior `json:"expectedBehavior"`
	ControlProduct   string                  `json:"controlProduct"`
	Note             string                  `json:"note,omitempty"`
}

// FailureModeEvidence is one normalized record of what a gateway
// deployment actually did during a specific outage scenario.
type FailureModeEvidence struct {
	ScenarioLabel    string                  `json:"scenarioLabel"`
	ObservedBehavior ExpectedFailureBehavior `json:"observedBehavior"`
	Timestamp        time.Time               `json:"timestamp"`
	Source           EvidenceSource          `json:"source"`
}

// FailureModeEvidenceProvider supplies failure-mode evidence for a
// named outage scenario and time window.
type FailureModeEvidenceProvider interface {
	FailureModeEvidenceFor(scenarioLabel string, window TimeWindow) ([]FailureModeEvidence, error)
}

// FixtureFailureModeProvider wraps an in-memory slice of hand-built
// FailureModeEvidence values -- no real outage is induced in this
// phase.
type FixtureFailureModeProvider struct {
	events []FailureModeEvidence
}

func NewFixtureFailureModeProvider(events []FailureModeEvidence) *FixtureFailureModeProvider {
	return &FixtureFailureModeProvider{events: events}
}

func (p *FixtureFailureModeProvider) FailureModeEvidenceFor(scenarioLabel string, window TimeWindow) ([]FailureModeEvidence, error) {
	var out []FailureModeEvidence
	for _, e := range p.events {
		if e.ScenarioLabel != scenarioLabel {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyFailureModeExpectation checks one declared failure-mode
// expectation against evidence. Never infers fail-open/fail-closed
// from an absence of evidence -- an outage that produced no evidence
// is Inconclusive, not a pass.
func VerifyFailureModeExpectation(
	exp FailureModeExpectation,
	provider FailureModeEvidenceProvider,
	window TimeWindow,
) VerdictDetail {
	records, err := provider.FailureModeEvidenceFor(exp.ScenarioLabel, window)
	if err != nil {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("failure-mode evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no failure-mode evidence found for this outage scenario in the window",
		}
	}
	latest := latestByTimestamp(records, func(e FailureModeEvidence) time.Time { return e.Timestamp })
	if latest.ObservedBehavior == exp.ExpectedBehavior {
		return VerdictDetail{Verdict: VerdictPass}
	}
	return VerdictDetail{
		Verdict: VerdictFail,
		Reason:  fmt.Sprintf("observed failure behavior %q did not match expected %q", latest.ObservedBehavior, exp.ExpectedBehavior),
	}
}
