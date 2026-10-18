package dlpcorrelate

import (
	"github.com/audspect/bas/internal/dlpclassify"
	"github.com/audspect/bas/internal/reporting"
)

// Campaign04DepartingEmployeeDataExposure is dlp.txt §3C's Campaign 04:
// "Departing employee data exposure." "Use a dedicated test identity
// with realistic but synthetic access" is this campaign's SETUP clause
// (which actor runs the scenario), not an evaluated stage -- exactly
// parallel to Campaign 01's own "Seed synthetic customer records" setup
// clause. No RBAC/IAM access-boundary evaluator exists in this repo for
// verifying a synthetic identity's permission scope (confirmed by repo
// search, 2026-10-18); the test identity's scope is a property of how
// the scenario is authored, not a stage this chain evaluates. Stage 3
// is permanently StageNotTested -- the same telemetry/SIEM-correlation
// gap already named in docs/dlp-mastery-qa-log.md item 6.
var Campaign04DepartingEmployeeDataExposure = CorrelationChain{
	ID:   "DLPCORRELATE-CAMPAIGN-04",
	Name: "Departing employee data exposure",
	Stages: []StageDefinition{
		{Label: "access seeded business dataset via scoped test identity", Dimension: "DLP-CLS"},
		{Label: "exercise authorized export and controlled external-sharing cases", Dimension: "DLP-ENF"},
		{Label: "correlate identity, data, channel and alerts", Dimension: ""},
	},
}

// EvaluateCampaign04 translates 2 already-computed real evaluator
// verdicts (classification, enforcement comparison) into this chain's
// StageResult currency, reusing classificationOutcome/enforcementOutcome
// from campaign01.go directly rather than re-deriving equivalent logic --
// both campaigns ask the identical 2 translation questions. It never
// calls dlpclassify.VerifyClassificationSample or any internal/reporting
// Verify function itself.
func EvaluateCampaign04(classVerdict dlpclassify.DLPCLSVerdict, enfComparison reporting.ComparisonResult, enfReason string) (ChainResult, error) {
	chain := Campaign04DepartingEmployeeDataExposure
	var reached []StageResult

	stage1 := StageResult{
		StageOrder: 1,
		Label:      chain.Stages[0].Label,
		Dimension:  "DLP-CLS",
		Outcome:    classificationOutcome(classVerdict.Outcome),
		Reason:     classVerdict.Reason,
	}
	reached = append(reached, stage1)
	if stage1.Outcome.stops() {
		return EvaluateCorrelationChain(chain, reached)
	}

	stage2 := StageResult{
		StageOrder: 2,
		Label:      chain.Stages[1].Label,
		Dimension:  "DLP-ENF",
		Outcome:    enforcementOutcome(enfComparison),
		Reason:     enfReason,
	}
	reached = append(reached, stage2)
	return EvaluateCorrelationChain(chain, reached)
}
