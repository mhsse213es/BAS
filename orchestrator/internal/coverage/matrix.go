// Package coverage computes, for a set of ATT&CK techniques, whether a
// simulation, detection profile, purple-team exercise, or compliance
// mapping exists -- a read-only diagnostic view, not a new storage model.
// Every Build*Index function derives its set from data the caller already
// has loaded (scenarios, detection profiles); Compute is a pure join with
// no I/O of its own, so it's trivially testable with map literals.
package coverage

import "github.com/audspect/bas/internal/scenario"

// Row is one ATT&CK technique's coverage status across five dimensions.
type Row struct {
	TechniqueID             string `json:"techniqueId"`
	SimulationExists        bool   `json:"simulationExists"`
	DetectionProfileExists  bool   `json:"detectionProfileExists"`
	PurpleExerciseExists    bool   `json:"purpleExerciseExists"`
	ComplianceMappingExists bool   `json:"complianceMappingExists"`

	// ResponsePlaybookExists is always nil -- renders as "N/A" in the UI.
	// internal/actions (EPP isolate/kill/quarantine) has no technique-level
	// linkage today; faking a bool here would be a false negative for
	// every technique, which is worse than an honest N/A.
	ResponsePlaybookExists *bool `json:"responsePlaybookExists"`
}

// Compute joins four precomputed technique-ID membership sets into one row
// per requested technique ID, in the order given.
func Compute(techniqueIDs []string, simulation, profile, purpleExercise, compliance map[string]bool) []Row {
	rows := make([]Row, 0, len(techniqueIDs))
	for _, id := range techniqueIDs {
		rows = append(rows, Row{
			TechniqueID:             id,
			SimulationExists:        simulation[id],
			DetectionProfileExists:  profile[id],
			PurpleExerciseExists:    purpleExercise[id],
			ComplianceMappingExists: compliance[id],
			ResponsePlaybookExists:  nil,
		})
	}
	return rows
}

// BuildSimulationIndex returns the set of technique IDs covered by at
// least one step across the given scenarios.
func BuildSimulationIndex(scenarios []*scenario.Scenario) map[string]bool {
	idx := make(map[string]bool)
	for _, sc := range scenarios {
		for _, step := range sc.Steps {
			if step.TechniqueID != "" {
				idx[step.TechniqueID] = true
			}
		}
	}
	return idx
}

// BuildComplianceIndex returns the set of technique IDs covered by at
// least one step in a scenario tagged "compliance" -- the existing tag
// convention already used by cis-ubuntu-l1.yaml and cscrf-mii-drill.yaml.
func BuildComplianceIndex(scenarios []*scenario.Scenario) map[string]bool {
	idx := make(map[string]bool)
	for _, sc := range scenarios {
		if !containsTag(sc.Tags, "compliance") {
			continue
		}
		for _, step := range sc.Steps {
			if step.TechniqueID != "" {
				idx[step.TechniqueID] = true
			}
		}
	}
	return idx
}

// BuildProfileIndex returns the set of technique IDs declared by at least
// one loaded detection profile's TechniqueIDs.
func BuildProfileIndex(profiles map[string]*scenario.DetectionProfile) map[string]bool {
	idx := make(map[string]bool)
	for _, p := range profiles {
		for _, tid := range p.TechniqueIDs {
			idx[tid] = true
		}
	}
	return idx
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
