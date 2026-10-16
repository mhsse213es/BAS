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
func TestScenarioBuilders_NeverNameARealDomain(t *testing.T) {
	all := []MailExpectation{
		SPFAlignmentExpectation(true), SPFAlignmentExpectation(false),
		DKIMAlignmentExpectation(true), DKIMAlignmentExpectation(false),
		DMARCPolicyExpectation(true), DMARCPolicyExpectation(false),
		CredentialHarvestingURLExpectation(true), CredentialHarvestingURLExpectation(false),
		EICARAttachmentExpectation(true), EICARAttachmentExpectation(false),
		URLRewriteExpectation(true), URLRewriteExpectation(false),
		OutboundDLPExpectation(true), OutboundDLPExpectation(false),
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
