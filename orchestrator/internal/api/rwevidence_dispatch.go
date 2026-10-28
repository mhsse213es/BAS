package api

import (
	"context"
	"log"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rwcontain"
	"github.com/audspect/bas/internal/rwdetect"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/rwrecover"
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
	"akira-kill-chain":                 true,
	"blackcat-kill-chain":              true,
	"clop-kill-chain":                  true,
	"lockbit-kill-chain":               true,
	"play-kill-chain":                  true,
	"ransomhub-kill-chain":             true,
	"ransomware-drill":                 true,
	"em-07-ransomware-readiness":       true,
	"linux-ransomware-drill":           true,
	"black-basta-kill-chain":           true,
	"medusa-kill-chain":                true,
	"rhysida-kill-chain":               true,
	"hunters-international-kill-chain": true,
}

// recordRWEvidence is additive and best-effort toward scoring (there is no
// scoring yet to feed), but never silent about failure: a write error is
// logged, never swallowed, and never allowed to touch sim/the caller's
// legacy result in any way. All observers are fakes in this sub-project --
// real-observer wiring is a later, separate piece of work. A no-op for any
// scenario outside ransomwareScenarioIDs.
func (h *Handler) recordRWEvidence(ctx context.Context, runID, scenarioID string, step scenario.Step, sim models.SimulationResult) {
	h.recordRWEvidenceWith(ctx, runID, scenarioID, step, sim, &rwevidence.FakeRecoveryObserver{})
}

func (h *Handler) recordRWEvidenceWith(ctx context.Context, runID, scenarioID string, step scenario.Step, sim models.SimulationResult, recovery rwevidence.RecoveryObserver) {
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
		Recovery:       recovery,
		Containment:    h.containmentObserverFor(sim),
		Detection:      h.detectionLookupFor(sim),
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

// detectionLookupFor backs the Detection capability with the configured
// connector, or leaves it honestly NotTested when none is configured.
func (h *Handler) detectionLookupFor(sim models.SimulationResult) rwevidence.DetectionLookup {
	if h.detectionConnector == nil {
		return &rwevidence.FakeDetectionLookup{}
	}
	return rwdetect.NewConnectorLookup(h.detectionConnector, inlineAttemptContextSource{pool: h.db, sim: sim})
}

// containmentObserverFor backs the Containment capability with the configured
// EDR device source, or leaves it honestly NotTested when none is configured.
func (h *Handler) containmentObserverFor(sim models.SimulationResult) rwevidence.ContainmentObserver {
	if h.containmentDevices == nil {
		return &rwevidence.FakeContainmentObserver{}
	}
	return rwcontain.Observer{Devices: h.containmentDevices, Context: inlineAttemptContextSource{pool: h.db, sim: sim}}
}

// rwStep pairs a dispatched step with its interpreted result, so the whole
// run's results can be read together once every step is in hand.
type rwStep struct {
	Step scenario.Step
	Sim  models.SimulationResult
}

// recordRecoveryBatch grades Recovery for a VSS deletion attempt from the same
// run's enumeration and survival steps. Those steps may be submitted after the
// deletion, so this runs once all results are known and overwrites the
// deletion's Recovery row. Scoped to ransomwareScenarioIDs and to steps that
// carry the enumerate, vss_delete and survival action keys.
func (h *Handler) recordRecoveryBatch(ctx context.Context, runID, scenarioID string, batch []rwStep) {
	if !ransomwareScenarioIDs[scenarioID] {
		return
	}
	var enumerate, deletion, survival *rwStep
	for i := range batch {
		s := &batch[i]
		if models.NormalizeID(s.Step.TechniqueID) != "T1490" {
			continue
		}
		switch s.Step.ActionKey {
		case "enumerate":
			enumerate = s
		case "vss_delete":
			deletion = s
		case "survival":
			survival = s
		}
	}
	if deletion == nil || survival == nil {
		return
	}
	enumerateOut := ""
	if enumerate != nil {
		enumerateOut = enumerate.Sim.RawOutput
	}
	grade := rwrecover.Grade(deletion.Sim.Result == models.ResultFail, enumerateOut, survival.Sim.RawOutput)
	h.recordRWEvidenceWith(ctx, runID, scenarioID, deletion.Step, deletion.Sim, rwevidence.FixedRecoveryObserver{Result: grade})
}
