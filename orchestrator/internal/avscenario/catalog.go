package avscenario

import (
	"fmt"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/scenario"
)

// dispatchableSeedVectorIDs are the real seed catalog vectors that are
// concretely dispatchable today through a standard agent executor. It
// deliberately excludes AV-BEHAV-001, whose ExecutionTemplate names a
// test-harness binary that does not exist yet (see catalog_behavioral.go).
var dispatchableSeedVectorIDs = map[string]bool{
	"AV-FILE-001": true, "AV-FILE-002": true,
	"AV-SCRIPT-001": true, "AV-SCRIPT-002": true,
	"AV-BEHAV-002":   true,
	"AV-NET-001":     true,
	"AV-PERSIST-001": true, "AV-PERSIST-002": true,
	"AV-FP-001": true, "AV-FP-002": true,
}

// AudspectAVAssessmentScenario builds the real, dispatchable AV/NGAV
// assessment scenario.Scenario from the current seed catalog's concretely
// dispatchable vectors -- the same shape the agent dispatch path already
// consumes from scenarios/endpoint-mastery/em-*.yaml.
func AudspectAVAssessmentScenario() (scenario.Scenario, error) {
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		return scenario.Scenario{}, fmt.Errorf("load catalog: %w", err)
	}
	var vectors []avcatalog.Vector
	for _, v := range catalog {
		if dispatchableSeedVectorIDs[v.ID] {
			vectors = append(vectors, v)
		}
	}
	return BuildScenario(
		"av-ngav-assessment", "AV/NGAV Assessment",
		"Antivirus and next-gen AV assessment built from avcatalog's concretely dispatchable seed vectors",
		vectors,
	)
}
