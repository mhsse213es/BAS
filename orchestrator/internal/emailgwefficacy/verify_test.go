package emailgwefficacy

import (
	"errors"
	"testing"
	"time"
)

// erroringProvider lets each leg (enforcement/detection) fail or
// succeed independently -- used to prove VerifyMailExpectation
// computes Prevention and DetectionVerdict from disjoint evidence
// calls.
type erroringProvider struct {
	enforcement    []EnforcementEvidence
	enforcementErr error
	detection      []DetectionEvidence
	detectionErr   error
}

func (p erroringProvider) EnforcementEvidenceFor(msg MessageRef, window TimeWindow) ([]EnforcementEvidence, error) {
	return p.enforcement, p.enforcementErr
}

func (p erroringProvider) DetectionEvidenceFor(msg MessageRef, window TimeWindow) ([]DetectionEvidence, error) {
	return p.detection, p.detectionErr
}

func fullWindow() TimeWindow {
	now := time.Now()
	return TimeWindow{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}
}

func TestVerifyMailExpectation_ResponseAlwaysNotTestedInThisPhase(t *testing.T) {
	exp := MailExpectation{SenderProfile: "spoofed-exec", Recipient: "cfo@example.com", MessageClass: "spf-fail", ExpectedAction: ExpectedQuarantine}
	provider := NewFixtureMailEvidenceProvider(nil, nil)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, fullWindow())

	if result.ResponseVerdict.Verdict != VerdictNotTested {
		t.Errorf("ResponseVerdict.Verdict = %q, want %q -- no response-evidence integration exists until Phase 3+", result.ResponseVerdict.Verdict, VerdictNotTested)
	}
	if result.ResponseVerdict.Reason == "" {
		t.Error("ResponseVerdict.Reason is empty, want a stated reason since Verdict != ConfirmedSuccess")
	}
}

func TestVerifyMailExpectation_EnforcementProviderError_PreventionInconclusive(t *testing.T) {
	exp := MailExpectation{SenderProfile: "spoofed-exec", Recipient: "cfo@example.com", MessageClass: "spf-fail", ExpectedAction: ExpectedQuarantine}
	provider := erroringProvider{enforcementErr: errors.New("tenant API unreachable")}
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, fullWindow())

	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q", result.Prevention.Verdict, VerdictInconclusive)
	}
	if len(result.Enforcement) != 0 {
		t.Errorf("Enforcement = %+v, want empty -- records must never be captured when the provider also returned an error", result.Enforcement)
	}
}

func TestVerifyMailExpectation_DetectionProviderError_DetectionInconclusive_PreventionUnaffected(t *testing.T) {
	now := time.Now()
	exp := MailExpectation{SenderProfile: "spoofed-exec", Recipient: "cfo@example.com", MessageClass: "spf-fail", ExpectedAction: ExpectedQuarantine}
	provider := erroringProvider{
		enforcement:  []EnforcementEvidence{{Message: exp.Ref(), Action: "quarantine", Timestamp: now}},
		detectionErr: errors.New("SIEM API unreachable"),
	}
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, fullWindow())

	if result.DetectionVerdict.Verdict != VerdictInconclusive {
		t.Errorf("DetectionVerdict.Verdict = %q, want %q", result.DetectionVerdict.Verdict, VerdictInconclusive)
	}
	if result.Prevention.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Prevention.Verdict = %q, want %q -- a detection-side failure must never affect the Prevention verdict (disjoint evidence calls)", result.Prevention.Verdict, VerdictConfirmedSuccess)
	}
}

// TestVerifyMailExpectation_StructuralRule_MissingDetectionNeverAffectsPrevention
// is the architecture spec's own named Phase 2 exit criterion: an
// empty DetectionEvidence slice must never be read as proof the
// gateway failed to block a message (emailGW.txt §3's closing
// instruction, enforced structurally here, not by convention).
func TestVerifyMailExpectation_StructuralRule_MissingDetectionNeverAffectsPrevention(t *testing.T) {
	now := time.Now()
	exp := MailExpectation{SenderProfile: "spoofed-exec", Recipient: "cfo@example.com", MessageClass: "spf-fail", ExpectedAction: ExpectedQuarantine}
	provider := NewFixtureMailEvidenceProvider(
		[]EnforcementEvidence{{Message: exp.Ref(), Action: "quarantine", Timestamp: now, Source: SourceFixture}},
		nil, // zero detection evidence anywhere
	)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, fullWindow())

	if result.Prevention.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Prevention.Verdict = %q, want %q -- the gateway correctly quarantined the message; missing SIEM telemetry must never be read as proof the gateway failed to block it", result.Prevention.Verdict, VerdictConfirmedSuccess)
	}
	if result.DetectionVerdict.Verdict != VerdictInconclusive {
		t.Errorf("DetectionVerdict.Verdict = %q, want %q", result.DetectionVerdict.Verdict, VerdictInconclusive)
	}
}

func TestVerifyMailExpectation_NoEnforcementEvidence_PreventionInconclusiveNeverAssumed(t *testing.T) {
	exp := MailExpectation{SenderProfile: "spoofed-exec", Recipient: "cfo@example.com", MessageClass: "spf-fail", ExpectedAction: ExpectedQuarantine}
	provider := NewFixtureMailEvidenceProvider(nil, nil)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, fullWindow())

	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q -- absence of enforcement evidence must never be read as either a healthy or a failed control", result.Prevention.Verdict, VerdictInconclusive)
	}
}

func TestVerifyMailExpectation_ActionMatches_ConfirmedSuccess(t *testing.T) {
	now := time.Now()
	exp := MailExpectation{SenderProfile: "spoofed-exec", Recipient: "cfo@example.com", MessageClass: "spf-fail", ExpectedAction: ExpectedQuarantine}
	provider := NewFixtureMailEvidenceProvider(
		[]EnforcementEvidence{{Message: exp.Ref(), Action: "quarantine", Timestamp: now, Source: SourceFixture}},
		[]DetectionEvidence{{Message: exp.Ref(), AlertGenerated: true, Timestamp: now, Source: SourceFixture}},
	)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, fullWindow())

	if result.Prevention.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Prevention.Verdict = %q, want %q", result.Prevention.Verdict, VerdictConfirmedSuccess)
	}
	if result.DetectionVerdict.Verdict != VerdictConfirmedSuccess {
		t.Errorf("DetectionVerdict.Verdict = %q, want %q", result.DetectionVerdict.Verdict, VerdictConfirmedSuccess)
	}
}

func TestVerifyMailExpectation_DeliveredCase_ActionMatchesAllow(t *testing.T) {
	now := time.Now()
	exp := MailExpectation{SenderProfile: "known-partner", Recipient: "ap@example.com", MessageClass: "legitimate-invoice", ExpectedAction: ExpectedDeliver}
	provider := NewFixtureMailEvidenceProvider(
		[]EnforcementEvidence{{Message: exp.Ref(), Action: "deliver", Timestamp: now, Source: SourceFixture}},
		[]DetectionEvidence{{Message: exp.Ref(), AlertGenerated: false, Timestamp: now, Source: SourceFixture}},
	)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, fullWindow())

	if result.Prevention.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Prevention.Verdict = %q, want %q -- the delivered (known-good) case must be proven end-to-end, same as the quarantined case", result.Prevention.Verdict, VerdictConfirmedSuccess)
	}
	// AlertGenerated:false here is expected and correct (legitimate mail
	// should not alert) -- DetectionVerdict's "ConfirmedFailure" meaning
	// ("an alert was declared expected and didn't fire") is scenario-
	// specific and computed by the scenario layer, not this function;
	// this function only reports what the provider asserted.
	if result.DetectionVerdict.Verdict != VerdictConfirmedFailure {
		t.Errorf("DetectionVerdict.Verdict = %q, want %q -- the provider explicitly asserted no alert fired", result.DetectionVerdict.Verdict, VerdictConfirmedFailure)
	}
}

func TestVerifyMailExpectation_ActionMismatch_PreventionConfirmedFailure(t *testing.T) {
	now := time.Now()
	exp := MailExpectation{SenderProfile: "spoofed-exec", Recipient: "cfo@example.com", MessageClass: "spf-fail", ExpectedAction: ExpectedQuarantine}
	provider := NewFixtureMailEvidenceProvider(
		[]EnforcementEvidence{{Message: exp.Ref(), Action: "deliver", Timestamp: now, Source: SourceFixture}},
		nil,
	)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, fullWindow())

	if result.Prevention.Verdict != VerdictConfirmedFailure {
		t.Errorf("Prevention.Verdict = %q, want %q -- the gateway delivered a message expected to be quarantined", result.Prevention.Verdict, VerdictConfirmedFailure)
	}
	if result.Prevention.Reason == "" {
		t.Error("Prevention.Reason is empty, want a stated reason since Verdict != ConfirmedSuccess")
	}
}

func TestVerifyMailExpectation_NoDetectionAlertAsserted_DetectionConfirmedFailure(t *testing.T) {
	now := time.Now()
	exp := MailExpectation{SenderProfile: "spoofed-exec", Recipient: "cfo@example.com", MessageClass: "spf-fail", ExpectedAction: ExpectedQuarantine}
	provider := NewFixtureMailEvidenceProvider(
		[]EnforcementEvidence{{Message: exp.Ref(), Action: "quarantine", Timestamp: now, Source: SourceFixture}},
		[]DetectionEvidence{{Message: exp.Ref(), AlertGenerated: false, Timestamp: now, Source: SourceFixture}},
	)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, fullWindow())

	if result.DetectionVerdict.Verdict != VerdictConfirmedFailure {
		t.Errorf("DetectionVerdict.Verdict = %q, want %q -- the provider explicitly checked and confirmed no alert fired, a stronger claim than silence", result.DetectionVerdict.Verdict, VerdictConfirmedFailure)
	}
}

func TestVerifyMailExpectation_MultipleMatchingRecords_MostRecentWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	exp := MailExpectation{SenderProfile: "spoofed-exec", Recipient: "cfo@example.com", MessageClass: "spf-fail", ExpectedAction: ExpectedQuarantine}
	provider := NewFixtureMailEvidenceProvider(
		[]EnforcementEvidence{
			{Message: exp.Ref(), Action: "deliver", Timestamp: older, Source: SourceFixture},
			{Message: exp.Ref(), Action: "quarantine", Timestamp: newer, Source: SourceFixture},
		},
		nil,
	)
	window := TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)}
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Prevention.Verdict = %q, want %q -- the most recent record (quarantine) must win over the stale earlier one (deliver)", result.Prevention.Verdict, VerdictConfirmedSuccess)
	}
}

func TestVerifyMailExpectation_ZeroValueExpectation_DoesNotPanic(t *testing.T) {
	provider := NewFixtureMailEvidenceProvider(nil, nil)
	result := VerifyMailExpectation(MailExpectation{}, OriginDeliveryObservation{}, provider, TimeWindow{})

	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q for a zero-value expectation with no matching evidence", result.Prevention.Verdict, VerdictInconclusive)
	}
}
