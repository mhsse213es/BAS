package api

import (
	"context"
	"log"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/scenario"
)

// ransomwareScenarioIDs are the exact 8 scenarios/drills this sub-project's
// spec scopes the integration to (design doc section "Scope"). Gating here
// keeps every other scenario in the product (AD, lateral movement, lolbin,
// credential-access, ...) untouched by this integration -- without it,
// classifyRansomwareStep's technique_not_mapped path would still write 5
// SKIPPED/not_tested rows for every step of every unrelated scenario run
// system-wide, which is both out of the spec's defined scope and needless
// write load on every dispatch in the product, not just ransomware's.
var ransomwareScenarioIDs = map[string]bool{
	"akira-kill-chain":           true,
	"blackcat-kill-chain":        true,
	"clop-kill-chain":            true,
	"lockbit-kill-chain":         true,
	"play-kill-chain":            true,
	"ransomhub-kill-chain":       true,
	"ransomware-drill":           true,
	"em-07-ransomware-readiness": true,
	"linux-ransomware-drill":     true,
	"black-basta-kill-chain":     true,
}

// recordRWEvidence is additive and best-effort toward scoring (there is no
// scoring yet to feed), but never silent about failure: a write error is
// logged, never swallowed, and never allowed to touch sim/the caller's
// legacy result in any way. All observers are fakes in this sub-project --
// real-observer wiring is a later, separate piece of work. A no-op for any
// scenario outside ransomwareScenarioIDs.
func (h *Handler) recordRWEvidence(ctx context.Context, runID, scenarioID string, step scenario.Step, sim models.SimulationResult) {
	if !ransomwareScenarioIDs[scenarioID] {
		return
	}
	in := rwevidence.StepInput{
		RunID:       runID,
		Action:      scenario.TaskID(step.TechniqueID, step.Name),
		TechniqueID: models.NormalizeID(step.TechniqueID),
		StepName:    step.Name,
		CheckResult: string(sim.Result),
		Details:     sim.Details + " " + sim.RawOutput,
	}
	deps := rwevidence.StepDependencies{
		Prevention:     &controlval.FakeProvider{},
		Recovery:       &rwevidence.FakeRecoveryObserver{},
		Containment:    &rwevidence.FakeContainmentObserver{},
		Detection:      &rwevidence.FakeDetectionLookup{},
		DataProtection: &rwevidence.FakeDataProtectionLookup{},
	}
	results := rwevidence.EvaluateStep(in, deps)
	if err := db.WriteRWCapabilityResults(ctx, h.db, runID, in.Action, results); err != nil {
		// Handler has no structured logger -- this codebase's existing idiom
		// throughout handlers.go is stdlib log.Printf with a bracketed tag,
		// matched here rather than inventing a logging dependency this
		// package doesn't have.
		log.Printf("[rwevidence] rw_capability_results write failed for run %s action %s technique %s: %v", runID, in.Action, in.TechniqueID, err)
	}
}
