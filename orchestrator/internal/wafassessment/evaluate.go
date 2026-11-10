package wafassessment

import "github.com/audspect/bas/internal/wafval"

// EvidenceSource names where a VectorAssertion's evidence came from.
type EvidenceSource string

const (
	EvidenceSourceFixture       EvidenceSource = "fixture"
	EvidenceSourceLiveExecution EvidenceSource = "live_execution"
)

// VectorFixture is one contributing vector's evidence. EvidenceSource
// labels where Results actually came from -- left unset (the zero value)
// by every hand-authored fixture in this package, which EvaluateScenarioWithSeverities
// defaults to EvidenceSourceFixture; a caller driving real traffic (e.g.
// internal/wafmodsec) sets it to EvidenceSourceLiveExecution explicitly so
// the resulting VectorAssertion -- and anything rendering it, like
// internal/api's JSON handlers -- never mislabels live evidence as a fixture.
type VectorFixture struct {
	VectorID       string
	Results        []wafval.CollectionResult
	EvidenceSource EvidenceSource
}

// EvaluateContributingVector grades one contributing vector's evidence
// as a prevention claim, via the real wafval.EvaluateClaim -- this
// package never derives a verdict itself.
func EvaluateContributingVector(vectorID string, results []wafval.CollectionResult) (wafval.Result, error) {
	exp := wafval.Expectation{Claim: wafval.ClaimPrevention, PolicyVerified: false}
	key := wafval.CorrelationKey{TestExecutionID: vectorID, RequestID: vectorID}
	return wafval.EvaluateClaim(exp, results, key), nil
}
