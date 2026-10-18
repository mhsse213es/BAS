package phishbridge

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishcatalog"
	"github.com/audspect/bas/internal/phishval"
)

// catalogExpectation resolves one catalog entry's declared Expectation by
// ID, the same real-catalog-not-a-duplicate discipline phBEC002Expectation
// already established.
func catalogExpectation(t *testing.T, id string) phishval.Expectation {
	t.Helper()
	catalog, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("AudspectPhishingCatalog() error = %v", err)
	}
	s, ok := phishcatalog.ByID(catalog, id)
	if !ok {
		t.Fatalf("%s not found in catalog", id)
	}
	return s.Expectation
}

// bridgeKnownGood builds a single-record fixture provider whose
// EnforcementEvidence.Action literally equals observedAction, verifies
// exp against it, and bridges the result into a phishval.Observation --
// the Phase 2 wrap-only proof mechanism every table-driven case below
// shares.
func bridgeKnownGood(t *testing.T, exp emailgwefficacy.MailExpectation, observedAction string) phishval.Observation {
	t.Helper()
	now := time.Now()
	provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
		[]emailgwefficacy.EnforcementEvidence{{
			Message: exp.Ref(), Action: observedAction, ControlProduct: exp.ControlProduct,
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}},
		nil,
	)
	result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, scenarioWindow())
	return FromEmailGWEfficacyResult(result)
}

// TestPhase2WrapOnlyScenarios_KnownGood_AllPassDeliveryAndEnforcement
// proves every Phase 2 CoverageFixtureTested catalog entry: feeding the
// exact action its catalog Expectation declares produces a Pass on both
// Delivery and Enforcement through the real emailgwefficacy builder, the
// Phase 1 bridge, and phishval's evaluator -- with zero new bridge code,
// confirming FromEmailGWEfficacyResult generalizes across every
// MailExpectation-shaped scenario, not just PH-BEC-002.
func TestPhase2WrapOnlyScenarios_KnownGood_AllPassDeliveryAndEnforcement(t *testing.T) {
	cases := []struct {
		id             string
		exp            emailgwefficacy.MailExpectation
		observedAction string
	}{
		{"PH-AUTH-002", emailgwefficacy.SPFAlignmentExpectation(false), "quarantine"},
		{"PH-AUTH-003", emailgwefficacy.DKIMAlignmentExpectation(false), "quarantine"},
		{"PH-AUTH-004", emailgwefficacy.DMARCPolicyExpectation(false), "reject"},
		{"PH-BEC-001", emailgwefficacy.ExecutiveImpersonationExpectation(true), "quarantine"},
		{"PH-URL-001", emailgwefficacy.CredentialHarvestingURLExpectation(true), "quarantine"},
		{"PH-URL-005", emailgwefficacy.URLRewriteExpectation(true), "rewrite-link"},
		{"PH-ATT-001", emailgwefficacy.EICARAttachmentExpectation(true), "quarantine"},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			obs := bridgeKnownGood(t, c.exp, c.observedAction)
			outcome := phishval.Evaluate("run-"+c.id, "known-good", catalogExpectation(t, c.id), obs)
			if outcome.Delivery.Verdict != phishval.VerdictPass {
				t.Errorf("Delivery.Verdict = %q (%s), want %q", outcome.Delivery.Verdict, outcome.Delivery.Reason, phishval.VerdictPass)
			}
			if outcome.Enforcement.Verdict != phishval.VerdictPass {
				t.Errorf("Enforcement.Verdict = %q (%s), want %q", outcome.Enforcement.Verdict, outcome.Enforcement.Reason, phishval.VerdictPass)
			}
		})
	}
}

// TestPhase2WrapOnlyScenarios_KnownBad_DeliveredUninspectedFails is the
// mirror known-bad case: every Phase 2 scenario must also FAIL when the
// control simply allows the message through, proving the bridge
// distinguishes catch from miss for each wrapped scenario, not only for
// PH-BEC-002.
func TestPhase2WrapOnlyScenarios_KnownBad_DeliveredUninspectedFails(t *testing.T) {
	cases := []struct {
		id  string
		exp emailgwefficacy.MailExpectation
	}{
		{"PH-AUTH-002", emailgwefficacy.SPFAlignmentExpectation(false)},
		{"PH-AUTH-003", emailgwefficacy.DKIMAlignmentExpectation(false)},
		{"PH-AUTH-004", emailgwefficacy.DMARCPolicyExpectation(false)},
		{"PH-BEC-001", emailgwefficacy.ExecutiveImpersonationExpectation(true)},
		{"PH-URL-001", emailgwefficacy.CredentialHarvestingURLExpectation(true)},
		{"PH-ATT-001", emailgwefficacy.EICARAttachmentExpectation(true)},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			obs := bridgeKnownGood(t, c.exp, "deliver")
			outcome := phishval.Evaluate("run-"+c.id, "known-bad", catalogExpectation(t, c.id), obs)
			if outcome.Delivery.Verdict != phishval.VerdictFail {
				t.Errorf("Delivery.Verdict = %q, want %q", outcome.Delivery.Verdict, phishval.VerdictFail)
			}
			if outcome.Enforcement.Verdict != phishval.VerdictFail {
				t.Errorf("Enforcement.Verdict = %q, want %q", outcome.Enforcement.Verdict, phishval.VerdictFail)
			}
		})
	}
}
