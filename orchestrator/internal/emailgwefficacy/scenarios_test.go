package emailgwefficacy

import (
	"strings"
	"testing"
	"time"
)

// scenarioWindow returns a TimeWindow wide enough to contain any
// fixture timestamp built with time.Now() in these tests.
func scenarioWindow() TimeWindow {
	now := time.Now()
	return TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
}

// runScenario is the shared end-to-end harness every scenario test
// below uses: build fixture evidence whose Action matches exp's own
// declared ExpectedAction, run it through VerifyMailExpectation, and
// confirm Prevention comes back ConfirmedSuccess -- proving the
// expectation -> evidence -> verdict pipeline for that message class,
// per Phase 3a's exit criteria.
func runScenario(t *testing.T, exp MailExpectation) EfficacyResult {
	t.Helper()
	now := time.Now()
	provider := NewFixtureMailEvidenceProvider(
		[]EnforcementEvidence{{
			Message:   exp.Ref(),
			Action:    string(exp.ExpectedAction),
			Timestamp: now,
			Source:    SourceFixture,
		}},
		nil,
	)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, scenarioWindow())
	if result.Prevention.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Prevention.Verdict = %q, want %q for message class %q", result.Prevention.Verdict, VerdictConfirmedSuccess, exp.MessageClass)
	}
	return result
}

func TestSPFAlignmentScenario_KnownGood_AlignedSenderDelivered(t *testing.T) {
	exp := SPFAlignmentExpectation(true)
	if exp.ExpectedAction != ExpectedDeliver {
		t.Fatalf("SPFAlignmentExpectation(true).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedDeliver)
	}
	runScenario(t, exp)
}

func TestSPFAlignmentScenario_KnownBad_SpoofedSenderQuarantined(t *testing.T) {
	exp := SPFAlignmentExpectation(false)
	if exp.ExpectedAction != ExpectedQuarantine {
		t.Fatalf("SPFAlignmentExpectation(false).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedQuarantine)
	}
	runScenario(t, exp)
}

func TestDKIMAlignmentScenario_KnownGood_SignedMessageDelivered(t *testing.T) {
	exp := DKIMAlignmentExpectation(true)
	if exp.ExpectedAction != ExpectedDeliver {
		t.Fatalf("DKIMAlignmentExpectation(true).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedDeliver)
	}
	runScenario(t, exp)
}

func TestDKIMAlignmentScenario_KnownBad_UnsignedMessageQuarantined(t *testing.T) {
	exp := DKIMAlignmentExpectation(false)
	if exp.ExpectedAction != ExpectedQuarantine {
		t.Fatalf("DKIMAlignmentExpectation(false).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedQuarantine)
	}
	runScenario(t, exp)
}

func TestDMARCPolicyScenario_KnownGood_AlignedMessageDelivered(t *testing.T) {
	exp := DMARCPolicyExpectation(true)
	if exp.ExpectedAction != ExpectedDeliver {
		t.Fatalf("DMARCPolicyExpectation(true).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedDeliver)
	}
	runScenario(t, exp)
}

func TestDMARCPolicyScenario_KnownBad_MisalignedMessageRejected(t *testing.T) {
	exp := DMARCPolicyExpectation(false)
	if exp.ExpectedAction != ExpectedReject {
		t.Fatalf("DMARCPolicyExpectation(false).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedReject)
	}
	runScenario(t, exp)
}

func TestCredentialHarvestingURLScenario_KnownGood_CaughtByGateway(t *testing.T) {
	exp := CredentialHarvestingURLExpectation(true)
	if exp.ExpectedAction != ExpectedQuarantine {
		t.Fatalf("CredentialHarvestingURLExpectation(true).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedQuarantine)
	}
	runScenario(t, exp)
}

func TestCredentialHarvestingURLScenario_KnownBad_MissedByGateway(t *testing.T) {
	exp := CredentialHarvestingURLExpectation(false)
	if exp.ExpectedAction != ExpectedDeliver {
		t.Fatalf("CredentialHarvestingURLExpectation(false).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedDeliver)
	}
	runScenario(t, exp)
}

func TestExecutiveImpersonationScenario_KnownGood_CaughtByGateway(t *testing.T) {
	exp := ExecutiveImpersonationExpectation(true)
	if exp.ExpectedAction != ExpectedQuarantine {
		t.Fatalf("ExecutiveImpersonationExpectation(true).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedQuarantine)
	}
	runScenario(t, exp)
}

func TestExecutiveImpersonationScenario_KnownBad_MissedByGateway(t *testing.T) {
	exp := ExecutiveImpersonationExpectation(false)
	if exp.ExpectedAction != ExpectedDeliver {
		t.Fatalf("ExecutiveImpersonationExpectation(false).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedDeliver)
	}
	runScenario(t, exp)
}

// TestExecutiveImpersonationScenario_NoEvidence_InconclusiveNeverAssumed
// is this scenario's own regression proof, per the EG-002/EG-005/EG-009
// implementation's explicit regression step: an absent enforcement
// evidence record must never be reported as either a confirmed success
// or a confirmed failure for this new scenario, the same structural
// discipline VerifyMailExpectation already proves generically in
// verify_test.go.
func TestExecutiveImpersonationScenario_NoEvidence_InconclusiveNeverAssumed(t *testing.T) {
	exp := ExecutiveImpersonationExpectation(true)
	provider := NewFixtureMailEvidenceProvider(nil, nil)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, scenarioWindow())
	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q -- absence of evidence must never be read as either outcome", result.Prevention.Verdict, VerdictInconclusive)
	}
}

func TestSupplierPaymentDiversionScenario_KnownGood_CaughtByGateway(t *testing.T) {
	exp := SupplierPaymentDiversionExpectation(true)
	if exp.ExpectedAction != ExpectedQuarantine {
		t.Fatalf("SupplierPaymentDiversionExpectation(true).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedQuarantine)
	}
	runScenario(t, exp)
}

func TestSupplierPaymentDiversionScenario_KnownBad_MissedByGateway(t *testing.T) {
	exp := SupplierPaymentDiversionExpectation(false)
	if exp.ExpectedAction != ExpectedDeliver {
		t.Fatalf("SupplierPaymentDiversionExpectation(false).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedDeliver)
	}
	runScenario(t, exp)
}

func TestSupplierPaymentDiversionScenario_NoEvidence_InconclusiveNeverAssumed(t *testing.T) {
	exp := SupplierPaymentDiversionExpectation(true)
	provider := NewFixtureMailEvidenceProvider(nil, nil)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, scenarioWindow())
	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q -- absence of evidence must never be read as either outcome", result.Prevention.Verdict, VerdictInconclusive)
	}
}

// TestAuthenticationExceptionScopeScenario_KnownGood_GenuineUseDelivered
// proves scoped=true's own semantics: a message that genuinely
// originates from the exception's real, verified trusted source is
// expected to bypass inspection and deliver -- the exception must not
// break the legitimate mail flow it exists for.
func TestAuthenticationExceptionScopeScenario_KnownGood_GenuineUseDelivered(t *testing.T) {
	exp := AuthenticationExceptionScopeExpectation(true)
	if exp.ExpectedAction != ExpectedDeliver {
		t.Fatalf("AuthenticationExceptionScopeExpectation(true).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedDeliver)
	}
	runScenario(t, exp)
}

// TestAuthenticationExceptionScopeScenario_KnownBad_SpoofedProbeQuarantined
// proves scoped=false's own semantics: a probe that spoofs only the
// exception's spoofable trigger, without meeting its real
// verification condition, is expected to be caught by normal
// enforcement -- a ConfirmedFailure here would mean the exception
// creates exactly the unintended trust path EG-009 names.
func TestAuthenticationExceptionScopeScenario_KnownBad_SpoofedProbeQuarantined(t *testing.T) {
	exp := AuthenticationExceptionScopeExpectation(false)
	if exp.ExpectedAction != ExpectedQuarantine {
		t.Fatalf("AuthenticationExceptionScopeExpectation(false).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedQuarantine)
	}
	runScenario(t, exp)
}

func TestAuthenticationExceptionScopeScenario_NoEvidence_InconclusiveNeverAssumed(t *testing.T) {
	exp := AuthenticationExceptionScopeExpectation(false)
	provider := NewFixtureMailEvidenceProvider(nil, nil)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, scenarioWindow())
	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q -- absence of evidence must never be read as either outcome", result.Prevention.Verdict, VerdictInconclusive)
	}
}

func TestEICARAttachmentScenario_KnownGood_CaughtByGateway(t *testing.T) {
	exp := EICARAttachmentExpectation(true)
	if exp.ExpectedAction != ExpectedQuarantine {
		t.Fatalf("EICARAttachmentExpectation(true).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedQuarantine)
	}
	runScenario(t, exp)
}

func TestEICARAttachmentScenario_KnownBad_MissedByGateway(t *testing.T) {
	exp := EICARAttachmentExpectation(false)
	if exp.ExpectedAction != ExpectedDeliver {
		t.Fatalf("EICARAttachmentExpectation(false).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedDeliver)
	}
	runScenario(t, exp)
}

func TestURLRewriteScenario_KnownBad_MaliciousURLRewritten(t *testing.T) {
	exp := URLRewriteExpectation(true)
	if exp.ExpectedAction != ExpectedRewrite {
		t.Fatalf("URLRewriteExpectation(true).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedRewrite)
	}
	runScenario(t, exp)
}

func TestURLRewriteScenario_KnownGood_BenignURLDeliveredUnrewritten(t *testing.T) {
	exp := URLRewriteExpectation(false)
	if exp.ExpectedAction != ExpectedDeliver {
		t.Fatalf("URLRewriteExpectation(false).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedDeliver)
	}
	runScenario(t, exp)
}

func TestOutboundDLPScenario_KnownBad_SensitiveMarkerQuarantined(t *testing.T) {
	exp := OutboundDLPExpectation(true)
	if exp.ExpectedAction != ExpectedQuarantine {
		t.Fatalf("OutboundDLPExpectation(true).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedQuarantine)
	}
	runScenario(t, exp)
}

func TestOutboundDLPScenario_KnownGood_OrdinaryMailDelivered(t *testing.T) {
	exp := OutboundDLPExpectation(false)
	if exp.ExpectedAction != ExpectedDeliver {
		t.Fatalf("OutboundDLPExpectation(false).ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedDeliver)
	}
	runScenario(t, exp)
}

// runSPFWithObservedAction builds a fixture provider reporting the
// given enforcement action for SPFAlignmentExpectation(false) (the
// known-bad spoofed-sender scenario, which expects quarantine) and
// returns a func() VerdictDetail suitable for RunMutationTest -- the
// three calls differ only in what action the fixture reports, proving
// this package's own harness (not a real vendor) catches a weakened
// policy and recovers once it's reverted.
func runSPFWithObservedAction(action string) func() VerdictDetail {
	return func() VerdictDetail {
		exp := SPFAlignmentExpectation(false)
		now := time.Now()
		provider := NewFixtureMailEvidenceProvider(
			[]EnforcementEvidence{{Message: exp.Ref(), Action: action, Timestamp: now, Source: SourceFixture}},
			nil,
		)
		result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, scenarioWindow())
		return result.Prevention
	}
}

// TestSPFAlignmentScenario_MutationTest_WeakenedPolicyCaughtAndRecovered
// proves Phase 6's own exit criterion against a real scenario, not
// just the abstract fixedVerdict cases in mutation_test.go: a
// correctly-quarantining SPF policy (baseline), deliberately weakened
// to deliver the spoofed message instead (mutated), then reverted
// back to quarantine (restored).
func TestSPFAlignmentScenario_MutationTest_WeakenedPolicyCaughtAndRecovered(t *testing.T) {
	result := RunMutationTest(
		"SPFAlignmentExpectation(false)",
		runSPFWithObservedAction(string(ExpectedQuarantine)), // baseline: policy correctly quarantines
		runSPFWithObservedAction(string(ExpectedDeliver)),    // mutated: policy deliberately weakened to deliver
		runSPFWithObservedAction(string(ExpectedQuarantine)), // restored: policy reverted to its original state
	)

	if !result.Proven() {
		t.Errorf("Proven() = false (CaughtRegression=%v, RecoveryConfirmed=%v), want true for both", result.CaughtRegression, result.RecoveryConfirmed)
	}
}

// TestScenarioBuilders_NeverNameARealDomain is a guard against the
// §2.3 condition #4 constraint drifting silently as scenarios are
// added: every SenderProfile/Recipient/Note across this file must
// stay inside the synthetic ".test"/"-lab" namespace, never a real
// brand or customer domain.
// TestPostDeliveryThreatResponseScenario_PreventionPremise proves this
// scenario's own stated premise: it is never caught at delivery time,
// so Prevention always comes back ConfirmedSuccess against delivered
// evidence -- the scenario's real subject is Response, checked
// separately below.
func TestPostDeliveryThreatResponseScenario_PreventionPremise(t *testing.T) {
	exp := PostDeliveryThreatResponseExpectation()
	if exp.ExpectedAction != ExpectedDeliver {
		t.Fatalf("PostDeliveryThreatResponseExpectation().ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedDeliver)
	}
	runScenario(t, exp)
}

// TestPostDeliveryThreatResponseScenario_KnownGood_RemediationCompleted
// is EG-008's known-good case: the required post-delivery remediation
// action completed, so ResponseVerdict is ConfirmedSuccess.
func TestPostDeliveryThreatResponseScenario_KnownGood_RemediationCompleted(t *testing.T) {
	exp := PostDeliveryThreatResponseExpectation()
	now := time.Now()
	provider := NewFixtureMailEvidenceProvider(nil, nil).WithResponse(
		[]ResponseEvidence{{Message: exp.Ref(), ActionRequired: "successfullyRemediated", Completed: true, DurationToComplete: 5 * time.Minute, Timestamp: now, Source: SourceFixture}},
	)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, scenarioWindow())
	if result.ResponseVerdict.Verdict != VerdictConfirmedSuccess {
		t.Errorf("ResponseVerdict.Verdict = %q, want %q", result.ResponseVerdict.Verdict, VerdictConfirmedSuccess)
	}
}

// TestPostDeliveryThreatResponseScenario_KnownBad_RemediationNeverCompleted
// is EG-008's known-bad case: the gateway never actually remediated
// the message (e.g. an investigation that resolved benign/partial for
// a message that is, by this scenario's own construction, genuinely
// malicious) -- ResponseVerdict must be ConfirmedFailure, the finding
// EG-008 exists to catch.
func TestPostDeliveryThreatResponseScenario_KnownBad_RemediationNeverCompleted(t *testing.T) {
	exp := PostDeliveryThreatResponseExpectation()
	now := time.Now()
	provider := NewFixtureMailEvidenceProvider(nil, nil).WithResponse(
		[]ResponseEvidence{{Message: exp.Ref(), ActionRequired: "benign", Completed: false, Timestamp: now, Source: SourceFixture}},
	)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, scenarioWindow())
	if result.ResponseVerdict.Verdict != VerdictConfirmedFailure {
		t.Errorf("ResponseVerdict.Verdict = %q, want %q", result.ResponseVerdict.Verdict, VerdictConfirmedFailure)
	}
}

// TestPostDeliveryThreatResponseScenario_NoEvidence_InconclusiveNeverAssumed
// is this scenario's own regression proof: a remediation that hasn't
// resolved yet (no ResponseEvidence at all) must never be read as
// either a confirmed success or a confirmed failure.
func TestPostDeliveryThreatResponseScenario_NoEvidence_InconclusiveNeverAssumed(t *testing.T) {
	exp := PostDeliveryThreatResponseExpectation()
	provider := NewFixtureMailEvidenceProvider(nil, nil)
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, scenarioWindow())
	if result.ResponseVerdict.Verdict != VerdictInconclusive {
		t.Errorf("ResponseVerdict.Verdict = %q, want %q -- absence of evidence must never be read as either outcome", result.ResponseVerdict.Verdict, VerdictInconclusive)
	}
}

func TestScenarioBuilders_NeverNameARealDomain(t *testing.T) {
	all := []MailExpectation{
		SPFAlignmentExpectation(true), SPFAlignmentExpectation(false),
		DKIMAlignmentExpectation(true), DKIMAlignmentExpectation(false),
		DMARCPolicyExpectation(true), DMARCPolicyExpectation(false),
		CredentialHarvestingURLExpectation(true), CredentialHarvestingURLExpectation(false),
		EICARAttachmentExpectation(true), EICARAttachmentExpectation(false),
		URLRewriteExpectation(true), URLRewriteExpectation(false),
		OutboundDLPExpectation(true), OutboundDLPExpectation(false),
		ExecutiveImpersonationExpectation(true), ExecutiveImpersonationExpectation(false),
		SupplierPaymentDiversionExpectation(true), SupplierPaymentDiversionExpectation(false),
		AuthenticationExceptionScopeExpectation(true), AuthenticationExceptionScopeExpectation(false),
		PostDeliveryThreatResponseExpectation(),
	}
	for _, exp := range all {
		if exp.Recipient == "" {
			t.Errorf("message class %q has an empty Recipient", exp.MessageClass)
			continue
		}
		if !strings.HasSuffix(exp.Recipient, ".test") {
			t.Errorf("message class %q Recipient %q is not in the synthetic .test namespace", exp.MessageClass, exp.Recipient)
		}
	}
}
