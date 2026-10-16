package wafassessment

import (
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// ScenarioOutcome is the scenario-level result of EvaluateScenario, a
// pure precedence rule: ScenarioFail always wins over
// ScenarioIncomplete, which always wins over ScenarioPass. There is no
// numeric score anywhere in this type -- a critical miss can never be
// diluted by vectors that passed elsewhere.
type ScenarioOutcome string

const (
	ScenarioPass       ScenarioOutcome = "pass"
	ScenarioFail       ScenarioOutcome = "fail"
	ScenarioIncomplete ScenarioOutcome = "incomplete"
)

// VectorAssertion is one contributing vector's evaluated outcome,
// carrying its real severity from the catalog alongside the verdict so
// a reader never has to cross-reference a separate table to judge it.
type VectorAssertion struct {
	VectorID       string
	Severity       wafcatalog.Severity
	Verdict        wafval.Verdict
	EvidenceSource EvidenceSource
	Reason         string
}

// ScenarioResult is EvaluateScenario's output. UntestedVectorIDs is
// never silently folded into a pass -- a contributing vector with no
// fixture is never evaluated at all.
type ScenarioResult struct {
	ScenarioID        string
	Outcome           ScenarioOutcome
	Assertions        []VectorAssertion
	UntestedVectorIDs []string
	Summary           string
}

// failingVerdict reports whether v is a real failure under either
// claim shape this package evaluates: for a prevention claim, the WAF
// either let the request through after detecting it, or missed it
// outright; for a false-positive claim (see EvaluateLegitimateTrafficScenario),
// a legitimate request was incorrectly blocked.
func failingVerdict(v wafval.Verdict) bool {
	return v == wafval.VerdictDetectedButAllowed || v == wafval.VerdictMissed || v == wafval.VerdictIncorrectlyBlocked
}

// EvaluateScenario grades scenario's contributing vectors against
// fixtures by precedence, never by averaging: any failing verdict
// forces ScenarioFail regardless of how many other vectors passed;
// any inconclusive verdict or untested vector (with no failure already
// present) forces ScenarioIncomplete; only every contributing vector
// both supplied and Blocked reaches ScenarioPass.
func EvaluateScenario(scenario EnterpriseScenario, fixtures map[string]VectorFixture, catalog []wafcatalog.AttackVector) (ScenarioResult, error) {
	severityByID := make(map[string]wafcatalog.Severity, len(catalog))
	for _, v := range catalog {
		severityByID[v.ID] = v.Severity
	}
	return EvaluateScenarioWithSeverities(scenario, fixtures, severityByID)
}

// EvaluateScenarioWithSeverities is EvaluateScenario's catalog-agnostic
// core: callers supply a vectorID -> Severity lookup directly, built
// from however many catalog packages a scenario bundles (wafcatalog,
// wafapiflow, wafbotabuse, ... -- each package's own Severity type
// converts losslessly to wafcatalog.Severity since all of them are
// plain critical/high/medium/low string enums). The non-offsetting
// precedence rule is identical to EvaluateScenario's.
func EvaluateScenarioWithSeverities(scenario EnterpriseScenario, fixtures map[string]VectorFixture, severityByID map[string]wafcatalog.Severity) (ScenarioResult, error) {
	knownIDs := make(map[string]bool, len(severityByID))
	for id := range severityByID {
		knownIDs[id] = true
	}
	if err := ValidateAgainstKnownIDs(scenario, knownIDs); err != nil {
		return ScenarioResult{}, fmt.Errorf("evaluating scenario %q: %w", scenario.ID, err)
	}
	return aggregateByPrecedence(scenario, func(vectorID string) (VectorAssertion, bool, error) {
		fixture, ok := fixtures[vectorID]
		if !ok {
			return VectorAssertion{}, false, nil
		}
		result, err := EvaluateContributingVector(vectorID, fixture.Results)
		if err != nil {
			return VectorAssertion{}, false, fmt.Errorf("evaluating vector %q: %w", vectorID, err)
		}
		return VectorAssertion{
			VectorID:       vectorID,
			Severity:       severityByID[vectorID],
			Verdict:        result.Verdict,
			EvidenceSource: EvidenceSourceFixture,
			Reason:         result.Reason,
		}, true, nil
	})
}

// aggregateByPrecedence is the non-offsetting precedence core shared
// by every scenario evaluator, regardless of what claim/verdict shape
// its per-vector evaluate callback actually drives underneath
// (ClaimPrevention via EvaluateContributingVector, or a genuinely
// different shape like wafpolicygap's paired/coverage-gap dispatch).
// evaluate returns found=false for a contributing ID with no fixture
// -- that ID becomes an untested vector, never evaluated, and can
// never silently count as a pass.
func aggregateByPrecedence(scenario EnterpriseScenario, evaluate func(vectorID string) (assertion VectorAssertion, found bool, err error)) (ScenarioResult, error) {
	var assertions []VectorAssertion
	var untested []string
	sawFailure := false
	sawIncomplete := false

	for _, vectorID := range scenario.ContributingVectorIDs {
		assertion, found, err := evaluate(vectorID)
		if err != nil {
			return ScenarioResult{}, err
		}
		if !found {
			untested = append(untested, vectorID)
			sawIncomplete = true
			continue
		}
		assertions = append(assertions, assertion)
		if failingVerdict(assertion.Verdict) {
			sawFailure = true
		}
		if assertion.Verdict == wafval.VerdictInconclusive {
			sawIncomplete = true
		}
	}

	outcome := ScenarioPass
	if sawIncomplete {
		outcome = ScenarioIncomplete
	}
	if sawFailure {
		outcome = ScenarioFail
	}

	summary := buildSummary(scenario, outcome, assertions, untested)
	return ScenarioResult{
		ScenarioID:        scenario.ID,
		Outcome:           outcome,
		Assertions:        assertions,
		UntestedVectorIDs: untested,
		Summary:           summary,
	}, nil
}

// fixtureOnlyDisclosure is a fixed, always-rendered caveat, mirroring
// wafefficacy.CoverageReport's own noLiveExecutionDisclosure
// discipline: interpolated directly into Summary's return value, never
// left to a doc comment that a future edit could drop.
const fixtureOnlyDisclosure = "every assertion here is fixture-validated only; this is not a claim about a deployed WAF's live efficacy"

func buildSummary(scenario EnterpriseScenario, outcome ScenarioOutcome, assertions []VectorAssertion, untested []string) string {
	s := fmt.Sprintf("scenario %q: %s", scenario.ID, outcome)
	var failing []string
	for _, a := range assertions {
		if failingVerdict(a.Verdict) {
			failing = append(failing, fmt.Sprintf("%s (%s, %s)", a.VectorID, a.Severity, a.Verdict))
		}
	}
	if len(failing) > 0 {
		s += fmt.Sprintf("; failing: %s", strings.Join(failing, ", "))
	}
	if len(untested) > 0 {
		s += fmt.Sprintf("; untested: %s", strings.Join(untested, ", "))
	}
	s += "; " + fixtureOnlyDisclosure
	return s
}
