package phishbridge

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// TestPHDET001_EndToEnd_KnownGood_SIEMCorroboratesDetection proves
// PH-DET-001's own objective ("verify normalized alerts reach the SOC")
// by running a real detected-and-caught scenario through
// emailgwefficacy.CorrelateWithSIEM before bridging -- the existing
// FromEmailGWEfficacyResult bridge needs no new code, because
// CorrelateWithSIEM already mutates the EfficacyResult it reads from.
func TestPHDET001_EndToEnd_KnownGood_SIEMCorroboratesDetection(t *testing.T) {
	exp := emailgwefficacy.SupplierPaymentDiversionExpectation(true)
	result := efficacyResultForAction(t, exp, "quarantine", boolPtr(true), nil)

	siemProvider := emailgwefficacy.NewFixtureSIEMProvider([]emailgwefficacy.SIEMEvidence{{
		Message: exp.Ref(), EventType: "phishing-detected", Timestamp: time.Now(), Source: emailgwefficacy.SourceFixture,
	}})
	correlated := emailgwefficacy.CorrelateWithSIEM(result, siemProvider, scenarioWindow())

	obs := FromEmailGWEfficacyResult(correlated)
	outcome := phishval.Evaluate("run-ph-det-001", "known-good", catalogExpectation(t, "PH-DET-001"), obs)
	if outcome.Detection.Verdict != phishval.VerdictPass {
		t.Errorf("Detection.Verdict = %q (%s), want %q", outcome.Detection.Verdict, outcome.Detection.Reason, phishval.VerdictPass)
	}
}

// TestPHDET001_EndToEnd_KnownBad_UncorroboratedBySIEM_NeverFabricatesDetected
// is PH-DET-001's actual differentiator: the email product alone claimed
// detection, but no independent SIEM record corroborates it reaching the
// SOC -- CorrelateWithSIEM downgrades DetectionVerdict to Inconclusive,
// which the bridge must carry through as NotTested, never a confident
// Pass.
func TestPHDET001_EndToEnd_KnownBad_UncorroboratedBySIEM_NeverFabricatesDetected(t *testing.T) {
	exp := emailgwefficacy.SupplierPaymentDiversionExpectation(true)
	result := efficacyResultForAction(t, exp, "quarantine", boolPtr(true), nil)

	correlated := emailgwefficacy.CorrelateWithSIEM(result, emailgwefficacy.NewFixtureSIEMProvider(nil), scenarioWindow())

	obs := FromEmailGWEfficacyResult(correlated)
	outcome := phishval.Evaluate("run-ph-det-001", "known-bad", catalogExpectation(t, "PH-DET-001"), obs)
	if outcome.Detection.Verdict != phishval.VerdictNotTested {
		t.Errorf("Detection.Verdict = %q, want %q (uncorroborated detection must never be fabricated as Pass)", outcome.Detection.Verdict, phishval.VerdictNotTested)
	}
}

// TestPHIR004_EndToEnd_KnownGood_TicketingConfirmsEscalation mirrors
// PH-DET-001's structure for Response/escalation instead of Detection.
func TestPHIR004_EndToEnd_KnownGood_TicketingConfirmsEscalation(t *testing.T) {
	exp := emailgwefficacy.SupplierPaymentDiversionExpectation(true)
	result := efficacyResultForAction(t, exp, "quarantine", nil, boolPtr(true))

	ticketProvider := emailgwefficacy.NewFixtureTicketProvider([]emailgwefficacy.TicketEvidence{{
		Message: exp.Ref(), IncidentCreated: true, System: "ServiceNow", Timestamp: time.Now(), Source: emailgwefficacy.SourceFixture,
	}})
	correlated := emailgwefficacy.CorrelateWithTicketing(result, ticketProvider, scenarioWindow())

	obs := FromEmailGWEfficacyResult(correlated)
	outcome := phishval.Evaluate("run-ph-ir-004", "known-good", catalogExpectation(t, "PH-IR-004"), obs)
	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q (%s), want %q", outcome.Response.Verdict, outcome.Response.Reason, phishval.VerdictPass)
	}
}

func TestPHIR004_EndToEnd_KnownBad_RemediatedButNotEscalated_NeverFabricatesPass(t *testing.T) {
	exp := emailgwefficacy.SupplierPaymentDiversionExpectation(true)
	result := efficacyResultForAction(t, exp, "quarantine", nil, boolPtr(true))

	correlated := emailgwefficacy.CorrelateWithTicketing(result, emailgwefficacy.NewFixtureTicketProvider(nil), scenarioWindow())

	obs := FromEmailGWEfficacyResult(correlated)
	outcome := phishval.Evaluate("run-ph-ir-004", "known-bad", catalogExpectation(t, "PH-IR-004"), obs)
	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q (remediation alone must never be fabricated as escalation proof)", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}
