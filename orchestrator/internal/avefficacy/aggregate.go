package avefficacy

import (
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

// ScenarioOutcome is the scenario-level result of EvaluateEfficacyScenario,
// a pure precedence rule: ScenarioFail always wins over ScenarioIncomplete,
// which always wins over ScenarioPass. There is no numeric score anywhere
// in this type -- a confirmed critical failure can never be diluted by
// vectors that passed elsewhere.
type ScenarioOutcome string

const (
	ScenarioPass       ScenarioOutcome = "pass"
	ScenarioFail       ScenarioOutcome = "fail"
	ScenarioIncomplete ScenarioOutcome = "incomplete"
)

// ScenarioResult is EvaluateEfficacyScenario's output. UntestedVectorIDs is
// never silently folded into a pass -- a contributing vector with no
// fixture is never evaluated at all.
type ScenarioResult struct {
	ScenarioID        string
	Outcome           ScenarioOutcome
	VectorOutcomes    []VectorOutcome
	UntestedVectorIDs []string
	Summary           string
}

// failingOutcome reports whether o is a real failure on ANY of its
// independent dimensions. Dimensions are checked independently and
// combined with OR, never averaged: a vector with FindingConfirmedGap
// still fails the scenario even if its Response was a clean Remediated --
// a prevention failure is never erased by a good cleanup (av.txt §4: "do
// not collapse everything into a single pass/fail field").
func failingOutcome(o VectorOutcome) bool {
	if o.Finding == avval.FindingConfirmedGap {
		return true
	}
	if o.Response == avval.ResponseFailed {
		return true
	}
	if o.Configuration == avval.ConfigurationPolicyGap || o.Configuration == avval.ConfigurationDrift {
		return true
	}
	return false
}

// inconclusiveOutcome reports whether o lacks enough evidence on any
// dimension to be trusted as a pass, without itself being a confirmed
// failure. Telemetry that is anything short of Complete is inconclusive,
// never a failure on its own (av.txt §4: "no alert found" is not
// automatically a confirmed detection failure). DetectionLatency is
// deliberately excluded here: an SLA breach is reported, never treated as
// missing evidence.
func inconclusiveOutcome(o VectorOutcome) bool {
	if o.Finding == avval.FindingInconclusive {
		return true
	}
	if o.Response == avval.ResponseUnknown {
		return true
	}
	if o.Telemetry != avval.TelemetryComplete {
		return true
	}
	if o.Configuration == avval.ConfigurationUnknown {
		return true
	}
	return false
}

// describeFailing names which dimension(s) of o are failing and why, so a
// report never has to say only "this vector failed" without saying which
// independent axis did.
func describeFailing(o VectorOutcome) string {
	var reasons []string
	if o.Finding == avval.FindingConfirmedGap {
		reasons = append(reasons, "prevention/detection: "+o.FindingReason)
	}
	if o.Response == avval.ResponseFailed {
		reasons = append(reasons, "response: "+o.ResponseReason)
	}
	if o.Configuration == avval.ConfigurationPolicyGap || o.Configuration == avval.ConfigurationDrift {
		reasons = append(reasons, "configuration: "+o.ConfigurationReason)
	}
	return strings.Join(reasons, "; ")
}

// fixtureOnlyDisclosure is a fixed, always-rendered caveat, interpolated
// directly into Summary's return value, never left to a doc comment a
// future edit could drop.
const fixtureOnlyDisclosure = "every outcome here is fixture-validated only; this is not a claim about a deployed AV/NGAV product's live efficacy"

func buildSummary(scenario EfficacyScenario, outcome ScenarioOutcome, outcomes []VectorOutcome, untested []string) string {
	s := fmt.Sprintf("scenario %q: %s", scenario.ID, outcome)
	var failing []string
	for _, o := range outcomes {
		if failingOutcome(o) {
			failing = append(failing, fmt.Sprintf("%s (%s): %s", o.VectorID, o.Severity, describeFailing(o)))
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

// EvaluateEfficacyScenario grades scenario's contributing vectors against
// fixtures by precedence, never by averaging: any vector with a failing
// dimension forces ScenarioFail regardless of how many other vectors
// passed; any inconclusive dimension or untested vector (with no failure
// already present) forces ScenarioIncomplete; only every contributing
// vector both supplied and clean on every dimension reaches ScenarioPass.
func EvaluateEfficacyScenario(scenario EfficacyScenario, policyBasis string, fixtures map[string]VectorFixture, catalog []avcatalog.Vector) (ScenarioResult, error) {
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		return ScenarioResult{}, fmt.Errorf("evaluating scenario %q: %w", scenario.ID, err)
	}
	byID := make(map[string]avcatalog.Vector, len(catalog))
	for _, v := range catalog {
		byID[v.ID] = v
	}

	var outcomes []VectorOutcome
	var untested []string
	sawFailure, sawIncomplete := false, false

	for _, vectorID := range scenario.ContributingVectorIDs {
		fixture, ok := fixtures[vectorID]
		if !ok {
			untested = append(untested, vectorID)
			sawIncomplete = true
			continue
		}
		outcome, err := EvaluateVector(byID[vectorID], policyBasis, fixture)
		if err != nil {
			return ScenarioResult{}, fmt.Errorf("evaluating vector %q: %w", vectorID, err)
		}
		outcome.EvidenceSource = EvidenceSourceFixture
		outcomes = append(outcomes, outcome)

		if failingOutcome(outcome) {
			sawFailure = true
		}
		if inconclusiveOutcome(outcome) {
			sawIncomplete = true
		}
	}

	result := ScenarioPass
	if sawIncomplete {
		result = ScenarioIncomplete
	}
	if sawFailure {
		result = ScenarioFail
	}

	summary := buildSummary(scenario, result, outcomes, untested)
	return ScenarioResult{
		ScenarioID:        scenario.ID,
		Outcome:           result,
		VectorOutcomes:    outcomes,
		UntestedVectorIDs: untested,
		Summary:           summary,
	}, nil
}
