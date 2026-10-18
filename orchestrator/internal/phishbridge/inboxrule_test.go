package phishbridge

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

func TestPHAUTH009_EndToEnd_KnownGood_AutoForwardDetected(t *testing.T) {
	exp := emailgwefficacy.SuspiciousAutoForwardExpectation(true)
	provider := emailgwefficacy.NewFixtureInboxRuleProvider([]emailgwefficacy.InboxRuleEvidence{{
		Mailbox: exp.Mailbox, RuleDetected: true, DetectionSource: "Defender alert",
		Timestamp: time.Now(), Source: emailgwefficacy.SourceFixture,
		Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
	}})

	verdict := emailgwefficacy.VerifyInboxRuleExpectation(exp, provider, scenarioWindow())
	obs := FromInboxRuleVerdict(verdict)
	outcome := phishval.Evaluate("run-ph-auth-009", "known-good", catalogExpectation(t, "PH-AUTH-009"), obs)

	if outcome.Detection.Verdict != phishval.VerdictPass {
		t.Errorf("Detection.Verdict = %q (%s), want %q", outcome.Detection.Verdict, outcome.Detection.Reason, phishval.VerdictPass)
	}
}

func TestPHAUTH009_EndToEnd_KnownBad_AutoForwardUndetected(t *testing.T) {
	exp := emailgwefficacy.SuspiciousAutoForwardExpectation(true)
	provider := emailgwefficacy.NewFixtureInboxRuleProvider([]emailgwefficacy.InboxRuleEvidence{{
		Mailbox: exp.Mailbox, RuleDetected: false,
		Timestamp: time.Now(), Source: emailgwefficacy.SourceFixture,
		Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
	}})

	verdict := emailgwefficacy.VerifyInboxRuleExpectation(exp, provider, scenarioWindow())
	obs := FromInboxRuleVerdict(verdict)
	outcome := phishval.Evaluate("run-ph-auth-009", "known-bad", catalogExpectation(t, "PH-AUTH-009"), obs)

	if outcome.Detection.Verdict != phishval.VerdictFail {
		t.Errorf("Detection.Verdict = %q, want %q", outcome.Detection.Verdict, phishval.VerdictFail)
	}
}

func TestFromInboxRuleVerdict_NoEvidenceInconclusive_NeverFabricatesDetectedOrUndetected(t *testing.T) {
	exp := emailgwefficacy.SuspiciousAutoForwardExpectation(true)
	provider := emailgwefficacy.NewFixtureInboxRuleProvider(nil)

	verdict := emailgwefficacy.VerifyInboxRuleExpectation(exp, provider, scenarioWindow())
	obs := FromInboxRuleVerdict(verdict)
	outcome := phishval.Evaluate("run-ph-auth-009", "no-evidence", catalogExpectation(t, "PH-AUTH-009"), obs)

	if outcome.Detection.Verdict != phishval.VerdictInconclusive {
		t.Errorf("Detection.Verdict = %q, want %q (absence of evidence is not proof of either outcome)", outcome.Detection.Verdict, phishval.VerdictInconclusive)
	}
}
