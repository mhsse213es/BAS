package correlation

import (
	"strings"

	"github.com/audspect/bas/internal/scenario"
)

// scenariosForTechnique mirrors coverage.BuildSimulationIndex's iteration
// over scenarioEngine.List()/sc.Steps, but appends a ScenarioRef per
// matching scenario instead of setting a bool -- the correlation engine
// needs to know WHICH scenario(s) cover a technique, not just whether one
// does. A scenario with multiple steps for the same technique contributes
// exactly one ScenarioRef (the inner break), matching BuildSimulationIndex's
// own per-scenario-not-per-step semantics.
func scenariosForTechnique(scenarioEngine *scenario.Engine, techniqueID string) []ScenarioRef {
	var out []ScenarioRef
	for _, sc := range scenarioEngine.List() {
		for _, step := range sc.Steps {
			if strings.EqualFold(step.TechniqueID, techniqueID) {
				out = append(out, ScenarioRef{ID: sc.ID, Name: sc.Name})
				break
			}
		}
	}
	return out
}
