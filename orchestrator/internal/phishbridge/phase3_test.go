package phishbridge

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// TestPHAUTH008_EndToEnd_KnownGood_ExceptionScopeAbuseCaught proves the
// Phase 3 correction: AuthenticationExceptionScopeExpectation (EG-009) is
// a real, dispatchable MailExpectation -- PH-AUTH-008 does not need the
// deferred policy-baseline bridge an earlier Phase 2 pass mistakenly
// pointed it at.
func TestPHAUTH008_EndToEnd_KnownGood_ExceptionScopeAbuseCaught(t *testing.T) {
	exp := emailgwefficacy.AuthenticationExceptionScopeExpectation(false) // scoped=false: spoofed trigger, expected to be caught
	obs := bridgeKnownGood(t, exp, "quarantine")
	outcome := phishval.Evaluate("run-ph-auth-008", "known-good", catalogExpectation(t, "PH-AUTH-008"), obs)
	if outcome.Delivery.Verdict != phishval.VerdictPass {
		t.Errorf("Delivery.Verdict = %q (%s), want %q", outcome.Delivery.Verdict, outcome.Delivery.Reason, phishval.VerdictPass)
	}
	if outcome.Enforcement.Verdict != phishval.VerdictPass {
		t.Errorf("Enforcement.Verdict = %q (%s), want %q", outcome.Enforcement.Verdict, outcome.Enforcement.Reason, phishval.VerdictPass)
	}
}

func TestPHAUTH008_EndToEnd_KnownBad_ExceptionScopeAbuseMissed(t *testing.T) {
	exp := emailgwefficacy.AuthenticationExceptionScopeExpectation(false)
	obs := bridgeKnownGood(t, exp, "deliver")
	outcome := phishval.Evaluate("run-ph-auth-008", "known-bad", catalogExpectation(t, "PH-AUTH-008"), obs)
	if outcome.Delivery.Verdict != phishval.VerdictFail {
		t.Errorf("Delivery.Verdict = %q, want %q", outcome.Delivery.Verdict, phishval.VerdictFail)
	}
	if outcome.Enforcement.Verdict != phishval.VerdictFail {
		t.Errorf("Enforcement.Verdict = %q, want %q", outcome.Enforcement.Verdict, phishval.VerdictFail)
	}
}

// TestPHATT010_EndToEnd_KnownGood_RetroactiveRemediationCompleted proves
// PH-ATT-010's Response-only Expectation: a message not caught at
// delivery, later remediated, grades Pass on Response alone --
// Delivery/Enforcement stay NotApplicable regardless of what enforcement
// evidence exists, because PH-ATT-010's catalog Expectation declares no
// assertion for either.
func TestPHATT010_EndToEnd_KnownGood_RetroactiveRemediationCompleted(t *testing.T) {
	exp := emailgwefficacy.PostDeliveryThreatResponseExpectation()
	now := time.Now()
	provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil).WithResponse([]emailgwefficacy.ResponseEvidence{{
		Message: exp.Ref(), ActionRequired: "purge", Completed: true,
		Timestamp: now, Source: emailgwefficacy.SourceFixture,
		Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
	}})
	result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, scenarioWindow())
	obs := FromEmailGWEfficacyResult(result)
	outcome := phishval.Evaluate("run-ph-att-010", "known-good", catalogExpectation(t, "PH-ATT-010"), obs)

	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q (%s), want %q", outcome.Response.Verdict, outcome.Response.Reason, phishval.VerdictPass)
	}
	if outcome.Delivery.Verdict != phishval.VerdictNotApplicable {
		t.Errorf("Delivery.Verdict = %q, want %q (no Delivery assertion declared)", outcome.Delivery.Verdict, phishval.VerdictNotApplicable)
	}
	if outcome.Enforcement.Verdict != phishval.VerdictNotApplicable {
		t.Errorf("Enforcement.Verdict = %q, want %q (no Enforcement assertion declared)", outcome.Enforcement.Verdict, phishval.VerdictNotApplicable)
	}
}

func TestPHATT010_EndToEnd_KnownBad_RetroactiveRemediationFailed(t *testing.T) {
	exp := emailgwefficacy.PostDeliveryThreatResponseExpectation()
	now := time.Now()
	provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil).WithResponse([]emailgwefficacy.ResponseEvidence{{
		Message: exp.Ref(), ActionRequired: "purge", Completed: false,
		Timestamp: now, Source: emailgwefficacy.SourceFixture,
		Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
	}})
	result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, scenarioWindow())
	obs := FromEmailGWEfficacyResult(result)
	outcome := phishval.Evaluate("run-ph-att-010", "known-bad", catalogExpectation(t, "PH-ATT-010"), obs)

	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictFail)
	}
}
