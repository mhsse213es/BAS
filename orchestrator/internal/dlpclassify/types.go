package dlpclassify

import "time"

// SensitivityClass is an open, corpus-author-defined classification
// label -- never a closed enum, so a confusion matrix can distinguish
// "classified as the wrong sensitive type" from "classified correctly."
// SensitivityClassNone means the sample is intentionally benign.
// SensitivityClassAmbiguous is reserved for a sample whose own ground
// truth declares it cannot be scored against a single right answer.
type SensitivityClass string

const (
	SensitivityClassNone      SensitivityClass = "none"
	SensitivityClassAmbiguous SensitivityClass = "ambiguous"
)

// ClassificationDecision is what the evaluated product actually
// reported for one sample -- never collapsed to a bare label, because
// "no sensitive label applied" has five distinguishable causes.
type ClassificationDecision string

const (
	// DecisionExplicitSensitive: the product applied a sensitive
	// classification and exposed it. The only decision that can
	// produce a TruePositive/FalsePositive/Misclassified outcome.
	DecisionExplicitSensitive ClassificationDecision = "explicit-sensitive"
	// DecisionExplicitBenign: the product explicitly classified the
	// sample as non-sensitive. The only decision that can produce a
	// TrueNegative/FalseNegative outcome.
	DecisionExplicitBenign ClassificationDecision = "explicit-benign"
	// DecisionLabelOnly: a label was applied but the underlying
	// classification decision/rationale was never exposed -- cannot
	// be scored as a classifier outcome.
	DecisionLabelOnly ClassificationDecision = "label-only"
	// DecisionInspectionFailed: the product attempted but failed to
	// inspect the file (parse error, timeout, corruption, etc.).
	DecisionInspectionFailed ClassificationDecision = "inspection-failed"
	// DecisionUnsupportedFormat: the product explicitly does not
	// support this format or operation -- a coverage limitation, not
	// a classification failure.
	DecisionUnsupportedFormat ClassificationDecision = "unsupported-format"
	// DecisionNoEvidenceReturned: the product gave no usable evidence
	// either way.
	DecisionNoEvidenceReturned ClassificationDecision = "no-evidence-returned"
)

// DLPCLSOutcome is this package's own independently-defined verdict
// vocabulary -- structurally parallel to dlppolicy.DLPPOLVerdict, but
// never the same type, and never imported from there.
type DLPCLSOutcome string

const (
	OutcomeTruePositive  DLPCLSOutcome = "true-positive"
	OutcomeFalsePositive DLPCLSOutcome = "false-positive"
	OutcomeFalseNegative DLPCLSOutcome = "false-negative"
	OutcomeTrueNegative  DLPCLSOutcome = "true-negative"
	// OutcomeMisclassified: a confusion-matrix off-diagonal cell --
	// the sample IS sensitive, the product DID classify it as
	// sensitive, but as the wrong SensitivityClass. Never collapsed
	// into TruePositive.
	OutcomeMisclassified DLPCLSOutcome = "misclassified"
	OutcomeInconclusive  DLPCLSOutcome = "inconclusive"
	OutcomeUnsupported   DLPCLSOutcome = "unsupported"
	OutcomeNotTested     DLPCLSOutcome = "not-tested"
)

// evaluated reports whether outcome counts toward the accuracy
// denominator (precision/recall/confusion matrix).
func (o DLPCLSOutcome) evaluated() bool {
	switch o {
	case OutcomeTruePositive, OutcomeFalsePositive, OutcomeFalseNegative, OutcomeTrueNegative, OutcomeMisclassified:
		return true
	default:
		return false
	}
}

type DLPCLSVerdict struct {
	Outcome DLPCLSOutcome `json:"outcome"`
	Reason  string        `json:"reason,omitempty"` // required whenever Outcome is not TruePositive/TrueNegative
}

type EvidenceSource string

const (
	SourceFixture EvidenceSource = "recorded-fixture"
	SourceLive    EvidenceSource = "live" // reserved; unused by any provider in this spec's buildable scope
)

type ProvenanceKind string

const (
	ProvenanceObserved ProvenanceKind = "observed"
	ProvenanceInferred ProvenanceKind = "inferred"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Provenance struct {
	Kind       ProvenanceKind `json:"kind"`
	Confidence Confidence     `json:"confidence"`
	Basis      string         `json:"basis,omitempty"`
}

// Rate is a ratio that may be undefined (zero denominator). A rate
// with Defined == false must never be reported as 0 -- "never fired a
// positive classification" and "fired many, all wrong" are different
// findings that a bare 0.0 would conflate.
type Rate struct {
	Value   float64 `json:"value"`
	Defined bool    `json:"defined"`
}

type TimeWindow struct{ Start, End time.Time }
