package dlpcorrelate

import (
	"github.com/audspect/bas/internal/dlpclassify"
	"github.com/audspect/bas/internal/reporting"
)

// Campaign01SensitiveRecordToExternalDisclosure is dlp.txt §3C's Campaign
// 01: "Seed synthetic customer records -> classify the data -> move it
// through a supported document workflow -> attempt an unauthorized
// external share -> verify enforcement -> verify the security event and
// case evidence." Stage 4 is permanently StageNotTested today -- no
// DLP-specific telemetry/case-correlation evaluator exists anywhere in
// this repo (see the design spec's Goals §3).
var Campaign01SensitiveRecordToExternalDisclosure = CorrelationChain{
	ID:   "DLPCORRELATE-CAMPAIGN-01",
	Name: "Sensitive record to external disclosure",
	Stages: []StageDefinition{
		{Label: "classify the seeded record", Dimension: "DLP-CLS"},
		{Label: "verify classification persists through document workflow", Dimension: "DLP-CLS-LABEL"},
		{Label: "attempt unauthorized external share, verify enforcement", Dimension: "DLP-ENF"},
		{Label: "verify security event and case evidence", Dimension: ""},
	},
}

// EvaluateCampaign01 translates 3 already-computed real evaluator
// verdicts (classification, label-lifecycle, enforcement comparison)
// into this chain's StageResult currency and evaluates it. It never
// calls dlpclassify.VerifyClassificationSample, VerifyLabelExpectation,
// or any internal/reporting Verify function itself -- the caller already
// ran those; this function only sequences and aggregates their outputs.
func EvaluateCampaign01(classVerdict, labelVerdict dlpclassify.DLPCLSVerdict, enfComparison reporting.ComparisonResult, enfReason string) (ChainResult, error) {
	chain := Campaign01SensitiveRecordToExternalDisclosure
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
		Dimension:  "DLP-CLS-LABEL",
		Outcome:    labelOutcome(labelVerdict.Outcome),
		Reason:     labelVerdict.Reason,
	}
	reached = append(reached, stage2)
	if stage2.Outcome.stops() {
		return EvaluateCorrelationChain(chain, reached)
	}

	stage3 := StageResult{
		StageOrder: 3,
		Label:      chain.Stages[2].Label,
		Dimension:  "DLP-ENF",
		Outcome:    enforcementOutcome(enfComparison),
		Reason:     enfReason,
	}
	reached = append(reached, stage3)
	return EvaluateCorrelationChain(chain, reached)
}

// classificationOutcome translates a dlpclassify classification-accuracy
// verdict into this chain's currency. OutcomeTruePositive/TrueNegative
// mean the product correctly classified the seeded record -- the data
// kept moving through the chain. False positive/negative and
// misclassified are confirmed classification failures: recorded, chain
// still advances. Anything else (inconclusive/unsupported/not-tested) is
// missing evidence -- the chain stops here.
func classificationOutcome(o dlpclassify.DLPCLSOutcome) StageOutcome {
	switch o {
	case dlpclassify.OutcomeTruePositive, dlpclassify.OutcomeTrueNegative:
		return StageContinues
	case dlpclassify.OutcomeFalsePositive, dlpclassify.OutcomeFalseNegative, dlpclassify.OutcomeMisclassified:
		return StageFailed
	default:
		return StageInconclusive
	}
}

// labelOutcome translates a dlpclassify label-lifecycle verdict into this
// chain's currency. OutcomeLabelCurrent means the classification/label
// survived the document workflow -- the data kept moving. Every other
// named label-lifecycle outcome is a confirmed failure of that
// persistence. Anything else (inconclusive) is missing evidence.
func labelOutcome(o dlpclassify.DLPCLSOutcome) StageOutcome {
	switch o {
	case dlpclassify.OutcomeLabelCurrent:
		return StageContinues
	case dlpclassify.OutcomeLabelMissing, dlpclassify.OutcomeLabelIncorrect, dlpclassify.OutcomeLabelWrongInheritance, dlpclassify.OutcomeLabelStale:
		return StageFailed
	default:
		return StageInconclusive
	}
}

// enforcementOutcome translates a reporting.ComparisonResult into this
// chain's currency. Match means the observed outcome matched the
// expected Block -- the unauthorized disclosure was caught, stopping the
// chain. Mismatch means the disclosure succeeded despite an expected
// block -- a confirmed enforcement failure, never confused with Caught.
// Anything else (MissingEvidence/NotApplicable/Unknown) is inconclusive.
func enforcementOutcome(c reporting.ComparisonResult) StageOutcome {
	switch c {
	case reporting.Match:
		return StageCaught
	case reporting.Mismatch:
		return StageFailed
	default:
		return StageInconclusive
	}
}
