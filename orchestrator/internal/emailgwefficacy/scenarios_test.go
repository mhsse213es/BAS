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
