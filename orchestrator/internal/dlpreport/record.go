// Package dlpreport holds dlp.txt §6's unified evidence record shape --
// one record shape any scenario can be rendered into, independent of
// which campaign or evaluator produced it. It never calls a live
// evaluator and never derives Enforcement/Telemetry/Response from
// another package's type: those 3 dimensions are always caller-supplied.
// See docs/superpowers/specs/2026-10-18-dlpreport-result-model-design.md
// for why only Classification gets a safe translation helper.
package dlpreport

import (
	"fmt"
	"time"

	"github.com/audspect/bas/internal/dlpclassify"
)

// EnforcementOutcome is §6's enforcement vocabulary: "Allowed, blocked,
// quarantined, encrypted, challenged, overridden or unknown." Always
// caller-supplied -- see the package doc comment.
type EnforcementOutcome string

const (
	EnforcementAllowed     EnforcementOutcome = "Allowed"
	EnforcementBlocked     EnforcementOutcome = "Blocked"
	EnforcementQuarantined EnforcementOutcome = "Quarantined"
	EnforcementEncrypted   EnforcementOutcome = "Encrypted"
	EnforcementChallenged  EnforcementOutcome = "Challenged"
	EnforcementOverridden  EnforcementOutcome = "Overridden"
	EnforcementUnknown     EnforcementOutcome = "Unknown"
)

// ClassificationOutcome is §6's classification vocabulary: "Correct,
// incorrect, not evaluated, unsupported or unknown."
type ClassificationOutcome string

const (
	ClassificationCorrect      ClassificationOutcome = "Correct"
	ClassificationIncorrect    ClassificationOutcome = "Incorrect"
	ClassificationNotEvaluated ClassificationOutcome = "NotEvaluated"
	ClassificationUnsupported  ClassificationOutcome = "Unsupported"
	ClassificationUnknown      ClassificationOutcome = "Unknown"
)

// TelemetryOutcome is §6's telemetry vocabulary: "Event absent, present,
// delayed, incomplete or unverifiable." Always caller-supplied -- see
// the package doc comment.
type TelemetryOutcome string

const (
	TelemetryAbsent       TelemetryOutcome = "Absent"
	TelemetryPresent      TelemetryOutcome = "Present"
	TelemetryDelayed      TelemetryOutcome = "Delayed"
	TelemetryIncomplete   TelemetryOutcome = "Incomplete"
	TelemetryUnverifiable TelemetryOutcome = "Unverifiable"
)

// ResponseOutcome is §6's response vocabulary: "Alert, case, escalation
// and remediation state." Always caller-supplied -- see the package doc
// comment. ResponseNotTested is this package's own addition for when no
// response evidence exists at all (never defaulted silently).
type ResponseOutcome string

const (
	ResponseAlerted     ResponseOutcome = "Alerted"
	ResponseCaseCreated ResponseOutcome = "CaseCreated"
	ResponseEscalated   ResponseOutcome = "Escalated"
	ResponseRemediated  ResponseOutcome = "Remediated"
	ResponseNotTested   ResponseOutcome = "NotTested"
)

// EvidenceProvenance is §6's "Evidence provenance" dimension: "Timestamp,
// source system, correlation ID, integrity hash and collection method."
type EvidenceProvenance struct {
	Timestamp        time.Time
	SourceSystem     string
	CorrelationID    string
	IntegrityHash    string
	CollectionMethod string
}

// Record is dlp.txt §6's unified, structured, independently reviewable
// evidence record -- one record per scenario execution, with every
// dimension kept separate rather than collapsed into one green/red
// status.
type Record struct {
	ScenarioID            string
	ScenarioVersion       string
	ControlObjective      string
	Preconditions         string
	SyntheticDataManifest string
	ActionAttempted       string

	Enforcement    EnforcementOutcome
	Classification ClassificationOutcome
	Telemetry      TelemetryOutcome
	Response       ResponseOutcome

	Provenance EvidenceProvenance

	Confidence  string
	Limitations string
}

// ClassificationOutcomeFromDLPCLS is the one safe translation helper this
// package defines -- see the design spec for why Enforcement/Telemetry/
// Response get no equivalent. TruePositive/TrueNegative both mean
// "classified correctly," a non-lossy coarsening. Misclassified is
// deliberately Incorrect, never Correct, per dlpclassify's own doc
// comment ("never collapsed into TruePositive"). The 5 label-lifecycle
// outcomes belong to a different measurement dimension (label lifecycle,
// not classification accuracy) and map to Unknown, as does any
// unrecognized future value.
func ClassificationOutcomeFromDLPCLS(o dlpclassify.DLPCLSOutcome) ClassificationOutcome {
	switch o {
	case dlpclassify.OutcomeTruePositive, dlpclassify.OutcomeTrueNegative:
		return ClassificationCorrect
	case dlpclassify.OutcomeFalsePositive, dlpclassify.OutcomeFalseNegative, dlpclassify.OutcomeMisclassified:
		return ClassificationIncorrect
	case dlpclassify.OutcomeUnsupported:
		return ClassificationUnsupported
	case dlpclassify.OutcomeNotTested, dlpclassify.OutcomeInconclusive:
		return ClassificationNotEvaluated
	default:
		return ClassificationUnknown
	}
}

// Validate reports a defect in r; it never mutates r. It flags a Record
// whose uncertain dimension (EnforcementUnknown, ClassificationUnknown/
// NotEvaluated, TelemetryUnverifiable, or ResponseNotTested) has no
// Limitations explaining why -- mirroring internal/reporting/dlp.go's
// DLPEvidence.Limitations discipline ("Always populated") at this
// package's own level, conditional on uncertainty existing rather than
// an unconditional non-empty requirement.
func (r Record) Validate() error {
	uncertain := r.Enforcement == EnforcementUnknown ||
		r.Classification == ClassificationUnknown ||
		r.Classification == ClassificationNotEvaluated ||
		r.Telemetry == TelemetryUnverifiable ||
		r.Response == ResponseNotTested

	if uncertain && r.Limitations == "" {
		return fmt.Errorf("dlpreport: Record has an uncertain dimension (Enforcement=%s, Classification=%s, Telemetry=%s, Response=%s) but Limitations is empty", r.Enforcement, r.Classification, r.Telemetry, r.Response)
	}
	return nil
}
