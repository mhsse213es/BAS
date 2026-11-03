package scenario

import "sort"

// ValidationProfile names the scope of a factory validation run. VALIDATED
// means "the recorded profile passed" -- for representative that is a bounded
// subset, and the coverage limits stay in the evidence (see
// docs/superpowers/specs/2026-11-03-factory-representative-validation-design.md).
type ValidationProfile string

const (
	// ValidationProfileRepresentative runs a bounded, deterministic subset --
	// the routine factory-validation profile.
	ValidationProfileRepresentative ValidationProfile = "representative"
	// ValidationProfileFull runs the complete scenario. Defined for evidence
	// honesty and reserved for deeper validation; the routine lab does not
	// dispatch it yet.
	ValidationProfileFull ValidationProfile = "full"
)

// RepresentativeLimits bounds a representative selection.
type RepresentativeLimits struct {
	// MaxSteps is the hard cap on selected steps across the whole scenario.
	MaxSteps int
	// PerTechnique is the max steps kept per distinct ATT&CK technique.
	PerTechnique int
}

// DefaultRepresentativeLimits is the routine factory-validation budget: one
// representative atomic per technique, capped at 25 steps total.
func DefaultRepresentativeLimits() RepresentativeLimits {
	return RepresentativeLimits{MaxSteps: 25, PerTechnique: 1}
}

// ValidationCoverage is the auditable accounting of a representative
// selection, bound to a run (and copied into the content_validations
// evidence). A PASS with this attached means the selected subset passed, not
// that every step/variant was tested.
type ValidationCoverage struct {
	Profile            string `json:"profile"`
	TotalSteps         int    `json:"total_steps"`
	SelectedSteps      int    `json:"selected_steps"`
	SkippedSteps       int    `json:"skipped_steps"`
	TechniquesTotal    int    `json:"techniques_total"`
	TechniquesSelected int    `json:"techniques_selected"`
	// Truncated is true when the global MaxSteps cap dropped steps the
	// per-technique rule would otherwise have kept (coverage was reduced
	// specifically by the hard cap).
	Truncated bool `json:"truncated"`
}

// SelectRepresentative returns a deterministic, bounded subset of steps
// covering distinct techniques, plus coverage accounting over the input.
//
// Selection is reproducible for a fixed content version: steps are stable-
// sorted by (TechniqueID, ProxyTechniqueID, TaskID) -- TaskID is a stable
// content-bound hash -- then at most PerTechnique are kept per distinct
// TechniqueID, then a global MaxSteps cap is applied in the same order.
func SelectRepresentative(steps []ScenarioStep, lim RepresentativeLimits) ([]ScenarioStep, ValidationCoverage) {
	cov := ValidationCoverage{Profile: string(ValidationProfileRepresentative), TotalSteps: len(steps)}
	if lim.PerTechnique < 1 {
		lim.PerTechnique = 1
	}

	// Count distinct techniques in the full input (the honest denominator).
	seenAll := make(map[string]struct{}, len(steps))
	for _, s := range steps {
		seenAll[s.TechniqueID] = struct{}{}
	}
	cov.TechniquesTotal = len(seenAll)

	if len(steps) == 0 {
		return nil, cov
	}

	// Stable, reproducible ordering. Sort a copy so the caller's slice is
	// never reordered.
	ordered := make([]ScenarioStep, len(steps))
	copy(ordered, steps)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.TechniqueID != b.TechniqueID {
			return a.TechniqueID < b.TechniqueID
		}
		if a.ProxyTechniqueID != b.ProxyTechniqueID {
			return a.ProxyTechniqueID < b.ProxyTechniqueID
		}
		return a.TaskID < b.TaskID
	})

	// Keep <=PerTechnique per technique, in order.
	perTech := make(map[string]int, cov.TechniquesTotal)
	kept := make([]ScenarioStep, 0, len(ordered))
	for _, s := range ordered {
		if perTech[s.TechniqueID] >= lim.PerTechnique {
			continue
		}
		perTech[s.TechniqueID]++
		kept = append(kept, s)
	}

	// Global hard cap. If it drops any of the per-technique keepers, flag it.
	if lim.MaxSteps > 0 && len(kept) > lim.MaxSteps {
		kept = kept[:lim.MaxSteps]
		cov.Truncated = true
	}

	seenSel := make(map[string]struct{}, len(kept))
	for _, s := range kept {
		seenSel[s.TechniqueID] = struct{}{}
	}
	cov.SelectedSteps = len(kept)
	cov.SkippedSteps = cov.TotalSteps - cov.SelectedSteps
	cov.TechniquesSelected = len(seenSel)
	return kept, cov
}
