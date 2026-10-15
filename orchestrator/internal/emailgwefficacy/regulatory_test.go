package emailgwefficacy

import (
	"testing"
	"time"
)

func TestIndiaRBISecureMailObligation_FieldsPopulated(t *testing.T) {
	obligation := IndiaRBISecureMailObligation()
	if obligation.Jurisdiction != "India" {
		t.Errorf("Jurisdiction = %q, want %q", obligation.Jurisdiction, "India")
	}
	if obligation.ID == "" || obligation.SourceReference == "" || obligation.ControlLabel == "" {
		t.Errorf("obligation = %+v, want ID/SourceReference/ControlLabel all populated", obligation)
	}
}

func TestUAECBUAEEmailSpoofingObligation_FieldsPopulated(t *testing.T) {
	obligation := UAECBUAEEmailSpoofingObligation()
	if obligation.Jurisdiction != "UAE" {
		t.Errorf("Jurisdiction = %q, want %q", obligation.Jurisdiction, "UAE")
	}
	if obligation.ID == "" || obligation.SourceReference == "" || obligation.ControlLabel == "" {
		t.Errorf("obligation = %+v, want ID/SourceReference/ControlLabel all populated", obligation)
	}
}

func TestMapObligationToScenarioEvidence_ConfirmedSuccess_StatusCaptured(t *testing.T) {
	obligation := RegulatoryObligation{ID: "test-obligation"}
	snapshot := MapObligationToScenarioEvidence(obligation, "some-scenario", VerdictConfirmedSuccess, time.Now())

	if snapshot.Status != ObligationSnapshotCaptured {
		t.Errorf("Status = %q, want %q", snapshot.Status, ObligationSnapshotCaptured)
	}
}

// TestMapObligationToScenarioEvidence_ConfirmedFailure_StatusCaptured
// confirms a failure is still a genuinely captured result -- the
// obligation's control was tested and found NOT to hold, which is
// itself a real, reportable finding, never discarded as if it were
// missing evidence.
func TestMapObligationToScenarioEvidence_ConfirmedFailure_StatusCaptured(t *testing.T) {
	obligation := RegulatoryObligation{ID: "test-obligation"}
	snapshot := MapObligationToScenarioEvidence(obligation, "some-scenario", VerdictConfirmedFailure, time.Now())

	if snapshot.Status != ObligationSnapshotCaptured {
		t.Errorf("Status = %q, want %q -- a confirmed failure is a genuine finding, not missing evidence", snapshot.Status, ObligationSnapshotCaptured)
	}
}

func TestMapObligationToScenarioEvidence_NotApplicable_StatusCaptured(t *testing.T) {
	obligation := RegulatoryObligation{ID: "test-obligation"}
	snapshot := MapObligationToScenarioEvidence(obligation, "some-scenario", VerdictNotApplicable, time.Now())

	if snapshot.Status != ObligationSnapshotCaptured {
		t.Errorf("Status = %q, want %q -- NotApplicable is a deliberate, justified exclusion, not an absence of evidence", snapshot.Status, ObligationSnapshotCaptured)
	}
}

func TestMapObligationToScenarioEvidence_Inconclusive_StatusIncomplete(t *testing.T) {
	obligation := RegulatoryObligation{ID: "test-obligation"}
	snapshot := MapObligationToScenarioEvidence(obligation, "some-scenario", VerdictInconclusive, time.Now())

	if snapshot.Status != ObligationSnapshotIncomplete {
		t.Errorf("Status = %q, want %q -- an Inconclusive verdict must never be captured as if proven", snapshot.Status, ObligationSnapshotIncomplete)
	}
}

func TestMapObligationToScenarioEvidence_NotTested_StatusIncomplete(t *testing.T) {
	obligation := RegulatoryObligation{ID: "test-obligation"}
	snapshot := MapObligationToScenarioEvidence(obligation, "some-scenario", VerdictNotTested, time.Now())

	if snapshot.Status != ObligationSnapshotIncomplete {
		t.Errorf("Status = %q, want %q", snapshot.Status, ObligationSnapshotIncomplete)
	}
}

func TestMapObligationToScenarioEvidence_FieldsCarryThrough(t *testing.T) {
	obligation := RegulatoryObligation{ID: "rbi-test"}
	capturedAt := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	snapshot := MapObligationToScenarioEvidence(obligation, "SPFAlignmentExpectation(false)", VerdictConfirmedSuccess, capturedAt)

	if snapshot.ObligationID != "rbi-test" {
		t.Errorf("ObligationID = %q, want %q", snapshot.ObligationID, "rbi-test")
	}
	if snapshot.ScenarioLabel != "SPFAlignmentExpectation(false)" {
		t.Errorf("ScenarioLabel = %q, want %q", snapshot.ScenarioLabel, "SPFAlignmentExpectation(false)")
	}
	if !snapshot.CapturedAt.Equal(capturedAt) {
		t.Errorf("CapturedAt = %v, want %v -- must use the explicit parameter, never time.Now()", snapshot.CapturedAt, capturedAt)
	}
}

// TestIndiaUAEObligations_MapEndToEndThroughARealScenarioVerdict
// proves the full obligation -> control -> scenario -> evidence chain
// Phase 5's own exit criterion requires, for both jurisdictions, using
// Phase 3a's real SPF scenario and VerifyMailExpectation pipeline --
// not a hand-built verdict.
func TestIndiaUAEObligations_MapEndToEndThroughARealScenarioVerdict(t *testing.T) {
	now := time.Now()
	exp := SPFAlignmentExpectation(false) // known-bad: spoofed sender, expected quarantine
	provider := NewFixtureMailEvidenceProvider(
		[]EnforcementEvidence{{Message: exp.Ref(), Action: string(exp.ExpectedAction), Timestamp: now, Source: SourceFixture}},
		nil,
	)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, scenarioWindow())
	if result.Prevention.Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Prevention.Verdict = %q, want %q", result.Prevention.Verdict, VerdictConfirmedSuccess)
	}

	for _, obligation := range []RegulatoryObligation{IndiaRBISecureMailObligation(), UAECBUAEEmailSpoofingObligation()} {
		snapshot := MapObligationToScenarioEvidence(obligation, "SPFAlignmentExpectation(false)", result.Prevention.Verdict, now)
		if snapshot.Status != ObligationSnapshotCaptured {
			t.Errorf("obligation %q: Status = %q, want %q", obligation.ID, snapshot.Status, ObligationSnapshotCaptured)
		}
		if snapshot.CapturedVerdict != VerdictConfirmedSuccess {
			t.Errorf("obligation %q: CapturedVerdict = %q, want %q", obligation.ID, snapshot.CapturedVerdict, VerdictConfirmedSuccess)
		}
	}
}
