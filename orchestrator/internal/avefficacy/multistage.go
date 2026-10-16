package avefficacy

import (
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

// StageVector names one ordered step of a multi-stage attack chain (av.txt
// §3 "Multi-stage execution": "Document -> script interpreter -> suspicious
// child process") and the catalog vector that represents it. Each stage is
// evaluated independently via its own real vector/fixture -- this composes
// already-validated vectors in declared sequence; it does not claim a
// single continuous process tree spanning all stages in one dispatch.
type StageVector struct {
	VectorID string
	Label    string
}

// MultiStageScenario is an EfficacyScenario whose ContributingVectorIDs are
// ordered stages rather than an unordered bundle, with a human-readable
// label per stage.
type MultiStageScenario struct {
	EfficacyScenario
	StageLabels []string // parallel to ContributingVectorIDs, same order
}

// NewMultiStageScenario validates via NewEfficacyScenario (every string
// non-empty, vector IDs non-empty/non-duplicate) and additionally requires
// every stage to carry a non-empty label.
func NewMultiStageScenario(id, name, objective string, stages []StageVector, prerequisites, evidenceRequirement, provenance string) (MultiStageScenario, error) {
	if len(stages) == 0 {
		return MultiStageScenario{}, fmt.Errorf("stages must not be empty")
	}
	ids := make([]string, 0, len(stages))
	labels := make([]string, 0, len(stages))
	for i, s := range stages {
		if strings.TrimSpace(s.Label) == "" {
			return MultiStageScenario{}, fmt.Errorf("stage %d: label must not be empty", i+1)
		}
		ids = append(ids, s.VectorID)
		labels = append(labels, s.Label)
	}
	base, err := NewEfficacyScenario(id, name, objective, ids, prerequisites, evidenceRequirement, provenance)
	if err != nil {
		return MultiStageScenario{}, err
	}
	return MultiStageScenario{EfficacyScenario: base, StageLabels: labels}, nil
}

// EvaluateMultiStageScenario evaluates scenario's stages in declared order,
// stopping advancement the moment a stage is blocked (VerifiedProtection --
// the chain is interrupted, later stages were never reached), a stage is
// inconclusive (we cannot responsibly claim the chain continued), or a
// stage's fixture is missing (untested, same honesty rule as the generic
// scenario). A stage that resolves ConfirmedGap (allowed through) lets the
// chain advance to the next stage -- and is still reported as its own real
// failure, never erased by a later stage catching the chain (av.txt §4's
// non-offsetting rule applies within a single chain exactly as it does
// across a scenario's independent vectors).
func EvaluateMultiStageScenario(scenario MultiStageScenario, policyBasis string, fixtures map[string]VectorFixture, catalog []avcatalog.Vector) (ScenarioResult, error) {
	if err := ValidateAgainstCatalog(scenario.EfficacyScenario, catalog); err != nil {
		return ScenarioResult{}, fmt.Errorf("evaluating scenario %q: %w", scenario.ID, err)
	}
	byID := make(map[string]avcatalog.Vector, len(catalog))
	for _, v := range catalog {
		byID[v.ID] = v
	}

	var outcomes []VectorOutcome
	var untested []string
	sawFailure, sawIncomplete := false, false
	chainStopped := false
	stoppedAtLabel := ""

	for i, vectorID := range scenario.ContributingVectorIDs {
		label := scenario.StageLabels[i]
		stageOrder := i + 1

		if chainStopped {
			outcomes = append(outcomes, VectorOutcome{
				VectorID: vectorID, Severity: byID[vectorID].Severity,
				StageOrder: stageOrder, StageSkipped: true,
				FindingReason: fmt.Sprintf("stage %q not reached -- chain already interrupted at %q", label, stoppedAtLabel),
			})
			continue
		}

		fixture, ok := fixtures[vectorID]
		if !ok {
			untested = append(untested, vectorID)
			sawIncomplete = true
			chainStopped = true
			stoppedAtLabel = label + " (untested)"
			continue
		}

		outcome, err := EvaluateVector(byID[vectorID], policyBasis, fixture)
		if err != nil {
			return ScenarioResult{}, fmt.Errorf("evaluating vector %q: %w", vectorID, err)
		}
		outcome.EvidenceSource = EvidenceSourceFixture
		outcome.StageOrder = stageOrder
		outcomes = append(outcomes, outcome)

		if failingOutcome(outcome) {
			sawFailure = true
		}
		if inconclusiveOutcome(outcome) {
			sawIncomplete = true
			chainStopped = true
			stoppedAtLabel = label + " (inconclusive)"
			continue
		}
		if outcome.Finding == avval.FindingVerifiedProtection {
			chainStopped = true
			stoppedAtLabel = label
		}
		// FindingConfirmedGap: the chain advances to the next stage.
	}

	result := ScenarioPass
	if sawIncomplete {
		result = ScenarioIncomplete
	}
	if sawFailure {
		result = ScenarioFail
	}

	summary := buildSummary(scenario.EfficacyScenario, result, outcomes, untested)
	if stoppedAtLabel != "" {
		summary += fmt.Sprintf("; chain interrupted at stage %q", stoppedAtLabel)
	} else {
		summary += "; chain fully executed with no interrupting stage"
	}

	return ScenarioResult{
		ScenarioID: scenario.ID, Outcome: result, VectorOutcomes: outcomes,
		UntestedVectorIDs: untested, Summary: summary,
	}, nil
}
