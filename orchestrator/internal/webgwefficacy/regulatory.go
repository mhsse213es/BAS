package webgwefficacy

import "time"

// RegulatoryObligation is one regulatory requirement from a named
// jurisdiction's regulator, together with the single WebGW capability
// (ControlLabel, a plain string tag -- never an imported type) that
// evidences it. This package has zero Go dependency on
// internal/regobligation; it imitates that package's PATTERN
// (immutable evidence snapshots, versioned obligations) without
// importing its types, the same independence webgwefficacy already
// keeps from internal/networkefficacy and internal/detectverify.
type RegulatoryObligation struct {
	ID              string    `json:"id"`
	Jurisdiction    string    `json:"jurisdiction"`
	Regulator       string    `json:"regulator"`
	Title           string    `json:"title"`
	SourceReference string    `json:"sourceReference"`
	Version         string    `json:"version"`
	EffectiveDate   time.Time `json:"effectiveDate"`
	ControlLabel    string    `json:"controlLabel"`
	Note            string    `json:"note,omitempty"`
}

// ObligationSnapshotStatus distinguishes a snapshot that genuinely
// captured a scenario's verdict from one that could not -- the same
// "nothing here means inconclusive, not failing" discipline this
// package already applies everywhere else.
type ObligationSnapshotStatus string

const (
	ObligationSnapshotCaptured   ObligationSnapshotStatus = "captured"
	ObligationSnapshotIncomplete ObligationSnapshotStatus = "incomplete"
)

// ObligationEvidenceSnapshot is an immutable, point-in-time record
// that a specific webgwefficacy scenario's own verdict was captured
// as evidence for a regulatory obligation. It is never re-executed or
// re-derived -- only ever created fresh by
// MapObligationToScenarioEvidence.
type ObligationEvidenceSnapshot struct {
	ObligationID    string                   `json:"obligationId"`
	ScenarioLabel   string                   `json:"scenarioLabel"`
	CapturedVerdict WebGWVerdict             `json:"capturedVerdict"`
	Status          ObligationSnapshotStatus `json:"status"`
	CapturedAt      time.Time                `json:"capturedAt"`
}

// MapObligationToScenarioEvidence captures one already-computed
// scenario verdict as an immutable evidence snapshot for the given
// obligation. capturedAt is an explicit parameter, never time.Now()
// read internally, matching VerifyPolicyBaselineExpectation's own
// determinism discipline. An Inconclusive or Unsupported verdict is
// captured as Incomplete, never silently treated as if the obligation
// had been proven met; a Fail is still Captured, since a failed
// control is a genuine finding, not missing evidence.
func MapObligationToScenarioEvidence(
	obligation RegulatoryObligation,
	scenarioLabel string,
	verdict WebGWVerdict,
	capturedAt time.Time,
) ObligationEvidenceSnapshot {
	status := ObligationSnapshotCaptured
	if verdict == VerdictInconclusive || verdict == VerdictUnsupported {
		status = ObligationSnapshotIncomplete
	}
	return ObligationEvidenceSnapshot{
		ObligationID:    obligation.ID,
		ScenarioLabel:   scenarioLabel,
		CapturedVerdict: verdict,
		Status:          status,
		CapturedAt:      capturedAt,
	}
}
