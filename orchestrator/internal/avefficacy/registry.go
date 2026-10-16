package avefficacy

import "fmt"

// scenarioLoader fully owns its own evaluation path -- it loads whatever
// seed scenario/fixtures/catalog it needs and evaluates them however is
// correct for that scenario. The registry and everything built on it
// (reporting, API handlers) only ever sees the resulting
// (EfficacyScenario, ScenarioResult).
type scenarioLoader func() (EfficacyScenario, ScenarioResult, error)

// scenarioRegistry is the slug -> loader lookup every console-facing
// efficacy scenario registers itself in. The slug is the console-facing
// identifier (used in URLs); it is deliberately distinct from
// EfficacyScenario.ID, which is the catalog-facing identifier.
var scenarioRegistry = map[string]scenarioLoader{
	"av-assessment":         loadAVAssessmentScenario,
	"recovery-remediation":  loadRecoveryRemediationScenario,
	"multi-stage-execution": loadMultiStageExecutionScenario,
}

// EvaluateScenarioBySlug looks up slug in the registry and returns its
// real, current seed scenario and evaluated result.
func EvaluateScenarioBySlug(slug string) (EfficacyScenario, ScenarioResult, error) {
	loader, ok := scenarioRegistry[slug]
	if !ok {
		return EfficacyScenario{}, ScenarioResult{}, fmt.Errorf("unknown efficacy scenario slug %q", slug)
	}
	scenario, result, err := loader()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, fmt.Errorf("evaluating scenario %q: %w", slug, err)
	}
	return scenario, result, nil
}
