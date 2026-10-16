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

// failingVerdict reports whether v is a prevention-claim failure --
// the WAF either let the request through after detecting it, or
// missed it outright.
func failingVerdict(v wafval.Verdict) bool {
	return v == wafval.VerdictDetectedButAllowed || v == wafval.VerdictMissed
}

// EvaluateScenario grades scenario's contributing vectors against
// fixtures by precedence, never by averaging: any failing verdict
// forces ScenarioFail regardless of how many other vectors passed;
// any inconclusive verdict or untested vector (with no failure already
// present) forces ScenarioIncomplete; only every contributing vector
// both supplied and Blocked reaches ScenarioPass.
func EvaluateScenario(scenario EnterpriseScenario, fixtures map[string]VectorFixture, catalog []wafcatalog.AttackVector) (ScenarioResult, error) {
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		return ScenarioResult{}, fmt.Errorf("evaluating scenario %q: %w", scenario.ID, err)
	}
	severityByID := make(map[string]wafcatalog.Severity, len(catalog))
	for _, v := range catalog {
		severityByID[v.ID] = v.Severity
	}

	var assertions []VectorAssertion
	var untested []string
	sawFailure := false
	sawIncomplete := false

	for _, vectorID := range scenario.ContributingVectorIDs {
		fixture, ok := fixtures[vectorID]
		if !ok {
			untested = append(untested, vectorID)
			sawIncomplete = true
			continue
		}
		result, err := EvaluateContributingVector(vectorID, fixture.Results)
		if err != nil {
			return ScenarioResult{}, fmt.Errorf("evaluating vector %q: %w", vectorID, err)
		}
		assertions = append(assertions, VectorAssertion{
			VectorID:       vectorID,
			Severity:       severityByID[vectorID],
			Verdict:        result.Verdict,
			EvidenceSource: EvidenceSourceFixture,
			Reason:         result.Reason,
		})
		if failingVerdict(result.Verdict) {
			sawFailure = true
		}
		if result.Verdict == wafval.VerdictInconclusive {
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
