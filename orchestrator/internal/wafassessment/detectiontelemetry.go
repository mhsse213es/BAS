package wafassessment

import (
	"fmt"
	"strings"
	"time"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafdetection"
	"github.com/audspect/bas/internal/wafval"
)

// DetectionFixture is one contributing detection/telemetry scenario's
// evidence. Which fields matter depends on which of wafdetection's
// three catalogs the scenario ID belongs to: CompletenessEvidence for
// a CompletenessScenario, UnderlyingVerdict+AlertEvidence for an
// AlertScenario, EventObservedAt+AlertObservedAt for a TimingScenario.
type DetectionFixture struct {
	CompletenessEvidence wafval.CollectionResult
	UnderlyingVerdict    wafval.Verdict
	AlertEvidence        wafval.CollectionResult
	EventObservedAt      time.Time
	AlertObservedAt      time.Time
}

// detectionOutcomeClass classifies a detection/telemetry verdict as
// failing or inconclusive. wafdetection's three evaluation shapes each
// have their own closed verdict taxonomy (CompletenessVerdict/
// AlertVerdict/TimingVerdict) -- none of them is a wafval.Verdict, and
// their failing values ("lost", "missing", "spurious", "sla_breached")
// share no string with wafval.Verdict's own failing values
// ("detected_but_allowed", "missed"). Reusing wafval's failingVerdict
// check here would silently misclassify a real detection-pipeline
// failure as a pass -- this function exists specifically so that never
// happens.
func detectionOutcomeClass(shape, verdict string) (failing, inconclusive bool) {
	switch shape {
	case "completeness":
		switch wafdetection.CompletenessVerdict(verdict) {
		case wafdetection.EvidenceLost:
			return true, false
		case wafdetection.EvidenceInconclusive:
			return false, true
		}
	case "alert":
		switch wafdetection.AlertVerdict(verdict) {
		case wafdetection.AlertMissing, wafdetection.AlertSpurious:
			return true, false
		case wafdetection.AlertInconclusive:
			return false, true
		}
	case "timing":
		switch wafdetection.TimingVerdict(verdict) {
		case wafdetection.TimingSLABreached:
			return true, false
		case wafdetection.TimingInconclusive:
			return false, true
		}
	}
	return false, false
}

type detectionCatalogs struct {
	completenessByID map[string]wafdetection.CompletenessScenario
	alertByID        map[string]wafdetection.AlertScenario
	timingByID       map[string]wafdetection.TimingScenario
}

func loadDetectionCatalogs() (detectionCatalogs, error) {
	completeness, alert, timing, err := wafdetection.AudspectWAFDetectionCatalog()
	if err != nil {
		return detectionCatalogs{}, fmt.Errorf("loading detection catalog: %w", err)
	}
	c := detectionCatalogs{
		completenessByID: make(map[string]wafdetection.CompletenessScenario, len(completeness)),
		alertByID:        make(map[string]wafdetection.AlertScenario, len(alert)),
		timingByID:       make(map[string]wafdetection.TimingScenario, len(timing)),
	}
	for _, s := range completeness {
		c.completenessByID[s.ID] = s
	}
	for _, s := range alert {
		c.alertByID[s.ID] = s
	}
	for _, s := range timing {
		c.timingByID[s.ID] = s
	}
	return c, nil
}

func (c detectionCatalogs) knownIDs() map[string]bool {
	known := make(map[string]bool, len(c.completenessByID)+len(c.alertByID)+len(c.timingByID))
	for id := range c.completenessByID {
		known[id] = true
	}
	for id := range c.alertByID {
		known[id] = true
	}
	for id := range c.timingByID {
		known[id] = true
	}
	return known
}

// evaluateContributingDetectionVector dispatches scenarioID to
// whichever of wafdetection's three real evaluation functions its
// catalog membership calls for, returning (shape, verdict string,
// reason, error) -- this package never derives a detection verdict
// itself.
func (c detectionCatalogs) evaluateContributingDetectionVector(scenarioID string, fixture DetectionFixture) (shape string, verdict string, reason string, err error) {
	if s, ok := c.completenessByID[scenarioID]; ok {
		v, r, err := wafdetection.EvaluateCompleteness(s, fixture.CompletenessEvidence)
		if err != nil {
			return "", "", "", err
		}
		return "completeness", string(v), r, nil
	}
	if _, ok := c.alertByID[scenarioID]; ok {
		v, r, err := wafdetection.EvaluateAlertCorrelation(fixture.UnderlyingVerdict, fixture.AlertEvidence)
		if err != nil {
			return "", "", "", err
		}
		return "alert", string(v), r, nil
	}
	if s, ok := c.timingByID[scenarioID]; ok {
		v, r, err := wafdetection.EvaluateResponseTiming(s, fixture.EventObservedAt, fixture.AlertObservedAt)
		if err != nil {
			return "", "", "", err
		}
		return "timing", string(v), r, nil
	}
	return "", "", "", fmt.Errorf("scenario ID %q not found in any detection/telemetry catalog", scenarioID)
}

// EvaluateDetectionTelemetryScenario grades scenario's contributing
// WAFDETECT-* IDs by the same non-offsetting precedence principle as
// EvaluateScenario -- any failing verdict forces ScenarioFail, any
// inconclusive verdict or untested scenario (with no failure already
// present) forces ScenarioIncomplete -- but computed with
// detectionOutcomeClass's own correct classification, never
// wafval-specific failingVerdict logic that these verdict taxonomies
// don't share. The result is packaged into the same ScenarioResult/
// VectorAssertion shape every other scenario uses, purely for display:
// VectorAssertion.Severity is left empty (no catalog severity concept
// applies here) and VectorAssertion.Verdict carries the real
// completeness/alert/timing verdict string, not a wafval.Verdict.
func EvaluateDetectionTelemetryScenario(scenario EnterpriseScenario, fixtures map[string]DetectionFixture) (ScenarioResult, error) {
	catalogs, err := loadDetectionCatalogs()
	if err != nil {
		return ScenarioResult{}, err
	}
	if err := ValidateAgainstKnownIDs(scenario, catalogs.knownIDs()); err != nil {
		return ScenarioResult{}, fmt.Errorf("evaluating scenario %q: %w", scenario.ID, err)
	}

	var assertions []VectorAssertion
	var failingIDs []string
	var untested []string
	sawFailure := false
	sawIncomplete := false

	for _, id := range scenario.ContributingVectorIDs {
		fixture, ok := fixtures[id]
		if !ok {
			untested = append(untested, id)
			sawIncomplete = true
			continue
		}
		shape, verdict, reason, err := catalogs.evaluateContributingDetectionVector(id, fixture)
		if err != nil {
			return ScenarioResult{}, fmt.Errorf("evaluating detection scenario %q: %w", id, err)
		}
		assertions = append(assertions, VectorAssertion{
			VectorID:       id,
			Severity:       wafcatalog.Severity(""),
			Verdict:        wafval.Verdict(verdict),
			EvidenceSource: EvidenceSourceFixture,
			Reason:         reason,
		})
		failing, inconclusive := detectionOutcomeClass(shape, verdict)
		if failing {
			sawFailure = true
			failingIDs = append(failingIDs, fmt.Sprintf("%s (%s)", id, verdict))
		}
		if inconclusive {
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

	summary := buildDetectionSummary(scenario, outcome, failingIDs, untested)
	return ScenarioResult{
		ScenarioID:        scenario.ID,
		Outcome:           outcome,
		Assertions:        assertions,
		UntestedVectorIDs: untested,
		Summary:           summary,
	}, nil
}

// buildDetectionSummary mirrors buildSummary's shape but takes
// already-classified failingIDs directly rather than re-deriving them
// from VectorAssertion.Verdict via wafval-specific failingVerdict --
// which would silently miss every one of this scenario's real failure
// values.
func buildDetectionSummary(scenario EnterpriseScenario, outcome ScenarioOutcome, failingIDs []string, untested []string) string {
	s := fmt.Sprintf("scenario %q: %s", scenario.ID, outcome)
	if len(failingIDs) > 0 {
		s += fmt.Sprintf("; failing: %s", strings.Join(failingIDs, ", "))
	}
	if len(untested) > 0 {
		s += fmt.Sprintf("; untested: %s", strings.Join(untested, ", "))
	}
	s += "; " + fixtureOnlyDisclosure
	return s
}
