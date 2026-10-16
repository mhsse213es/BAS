package wafassessment

import "github.com/audspect/bas/internal/wafval"

// EvidenceSource names where a VectorAssertion's evidence came from.
// EvidenceSourceLiveExecution is declared for forward compatibility
// only -- no code in this package can produce it; every assertion
// this phase renders is EvidenceSourceFixture.
type EvidenceSource string

const (
	EvidenceSourceFixture       EvidenceSource = "fixture"
	EvidenceSourceLiveExecution EvidenceSource = "live_execution"
)

// VectorFixture is one contributing vector's synthetic evidence.
type VectorFixture struct {
	VectorID string
	Results  []wafval.CollectionResult
}

// EvaluateContributingVector grades one contributing vector's evidence
// as a prevention claim, via the real wafval.EvaluateClaim -- this
// package never derives a verdict itself.
func EvaluateContributingVector(vectorID string, results []wafval.CollectionResult) (wafval.Result, error) {
	exp := wafval.Expectation{Claim: wafval.ClaimPrevention, PolicyVerified: false}
	key := wafval.CorrelationKey{TestExecutionID: vectorID, RequestID: vectorID}
	return wafval.EvaluateClaim(exp, results, key), nil
}
