package api

import (
	"context"
	"log"

	"github.com/audspect/bas/internal/adefficacy"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
)

// adControlScenarioIDs scopes native control-decision evidence recording to
// the specific scenarios built for it, mirroring recordRWEvidence's
// ransomwareScenarioIDs gate -- every other AD scenario (and every scenario
// outside the AD product line) is untouched.
var adControlScenarioIDs = map[string]bool{
	"dcsync-replication-rights-live-verification": true,
}

// adPrimitiveByTechnique maps a technique ID to the single adprimitive.ID
// its real evidence belongs to. Only DCSync (T1003.006) has a real,
// agent-executed verification scenario today; adding a technique here
// without adefficacy.ParseDRSUAPIResult-equivalent parsing for its own
// output format would silently record wrong decisions, so this map and the
// parser are added together, not ahead of each other.
var adPrimitiveByTechnique = map[string]string{
	"T1003.006": "dcsync",
}

// recordADEvidence persists a real adefficacy.ControlDecision, parsed from
// this step's own agent output, as this run's evidence for the AD primitive
// its technique maps to. Best-effort: a parse or write failure is logged,
// never allowed to touch sim or the caller's result. A no-op for any
// scenario outside adControlScenarioIDs or any technique with no mapped
// primitive.
func (h *Handler) recordADEvidence(ctx context.Context, runID, scenarioID string, step scenario.Step, sim models.SimulationResult) {
	if !adControlScenarioIDs[scenarioID] {
		return
	}
	techniqueID := models.NormalizeID(step.TechniqueID)
	primitiveID, ok := adPrimitiveByTechnique[techniqueID]
	if !ok {
		return
	}
	// sim.Details is the interpreter's OWN rewritten verdict text (interpretCustom
	// looks for its own pass:/fail:/skip: convention, not this scenario's
	// EXEC/SKIP tags) -- RawOutput is the real, unrewritten agent stdout our
	// tags actually appear in. Same reason recordRWEvidence matches against
	// Details+RawOutput rather than Details alone.
	result, parsed := adefficacy.ParseDRSUAPIResult(sim.RawOutput)
	if !parsed {
		return
	}
	actionKey := step.ActionKey
	if actionKey == "" {
		actionKey = "default"
	}
	action := techniqueID + ":" + actionKey
	d := db.ADControlDecision{
		DRSUAPIResult: string(result),
		Corroboration: string(adefficacy.CorroborationUnknown),
		Correlated:    true,
		Detail:        sim.RawOutput,
	}
	if err := db.WriteADControlVerification(ctx, h.db, runID, primitiveID, techniqueID, action, d); err != nil {
		log.Printf("[adevidence] ad_control_verifications write failed for run %s action %s primitive %s: %v", runID, action, primitiveID, err)
	}
}
