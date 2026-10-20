package pipelinecheck

import "time"

// Stage names one capability of the detection pipeline. Each is reported on its own, so
// a passing ingestion check can never stand in for normalisation, correlation or alerting.
type Stage string

const (
	StageConnectivity    Stage = "connectivity"
	StageIngestion       Stage = "ingestion"
	StageNormalization   Stage = "normalization"
	StageCorrelation     Stage = "correlation"
	StageAlert           Stage = "alert"
	StageCase            Stage = "case"
	StageRouting         Stage = "routing"
	StageAcknowledgement Stage = "acknowledgement"
	StageEscalation      Stage = "escalation"
)

// PipelineStages lists every stage in pipeline order. A campaign report must include each
// one, so none can be silently dropped.
var PipelineStages = []Stage{
	StageConnectivity, StageIngestion, StageNormalization, StageCorrelation,
	StageAlert, StageCase, StageRouting, StageAcknowledgement, StageEscalation,
}

// StageStatus is the outcome of one stage.
//
//   - Verified: the stage was checked and the required evidence was found.
//   - Inconclusive: a check ran and produced evidence, but the evidence cannot establish
//     the outcome (for example, zero matches inside a window that may still be filling).
//   - Error: the check could not run correctly (query failed, permission denied, connector
//     unreachable). Never a pass.
//   - NotTested: the stage was not checked. This is the default for any stage without a
//     check, and for any stage that depends on a stage that did not verify.
type StageStatus string

const (
	StatusVerified     StageStatus = "VERIFIED"
	StatusInconclusive StageStatus = "INCONCLUSIVE"
	StatusError        StageStatus = "ERROR"
	StatusNotTested    StageStatus = "NOT_TESTED"
)

// StageReport is one stage's outcome with the evidence behind it. Reason is the
// connector-specific explanation, so a reviewer can see why a verdict was reached.
type StageReport struct {
	Stage     Stage
	Status    StageStatus
	Reason    string
	Evidence  Evidence
	CheckedAt time.Time
}

// Evidence is what a read-only check observed. Only fields the check actually obtained
// are set; an absent field is never filled in with a guess.
type Evidence struct {
	Connector     string    // for example "elastic"
	Target        string    // index pattern or endpoint, never a credential
	Field         string    // the field matched on
	Identifier    string    // the stable event identifier searched for
	WindowFrom    time.Time // query window start
	WindowTo      time.Time // query window end
	MatchCount    int64     // total matches reported by the connector
	EventIDs      []string  // matched document IDs, up to the page size
	SourceTimes   []time.Time
	HTTPStatus    int    // zero when no response was received
	ErrorDetail   string // connector error, with credentials removed
	ResponseBytes int    // size of the connector response body, for the audit trail
}

// NotTestedReport is the default report for a stage that no check covers.
func NotTestedReport(s Stage, reason string, now time.Time) StageReport {
	return StageReport{Stage: s, Status: StatusNotTested, Reason: reason, CheckedAt: now}
}
