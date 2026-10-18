package phishbridge

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

func TestPHAUTH010_EndToEnd_KnownGood_DelegatedAccessDetected(t *testing.T) {
	exp := emailgwefficacy.SuspiciousDelegatedMailboxAccessExpectation(true)
	provider := emailgwefficacy.NewFixtureDelegatedMailboxAccessProvider([]emailgwefficacy.DelegatedMailboxAccessEvidence{{
		Mailbox: exp.Mailbox, GrantDetected: true, DetectionSource: "Defender alert",
		Timestamp: time.Now(), Source: emailgwefficacy.SourceFixture,
		Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
	}})

	verdict := emailgwefficacy.VerifyDelegatedMailboxAccessExpectation(exp, provider, scenarioWindow())
	obs := FromSingleDimensionDetectionVerdict(verdict, "emailgwefficacy-delegatedmailboxaccess")
	outcome := phishval.Evaluate("run-ph-auth-010", "known-good", catalogExpectation(t, "PH-AUTH-010"), obs)

	if outcome.Detection.Verdict != phishval.VerdictPass {
		t.Errorf("Detection.Verdict = %q (%s), want %q", outcome.Detection.Verdict, outcome.Detection.Reason, phishval.VerdictPass)
	}
}

func TestPHAUTH010_EndToEnd_KnownBad_DelegatedAccessUndetected(t *testing.T) {
	exp := emailgwefficacy.SuspiciousDelegatedMailboxAccessExpectation(true)
	provider := emailgwefficacy.NewFixtureDelegatedMailboxAccessProvider([]emailgwefficacy.DelegatedMailboxAccessEvidence{{
		Mailbox: exp.Mailbox, GrantDetected: false,
		Timestamp: time.Now(), Source: emailgwefficacy.SourceFixture,
		Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
	}})

	verdict := emailgwefficacy.VerifyDelegatedMailboxAccessExpectation(exp, provider, scenarioWindow())
	obs := FromSingleDimensionDetectionVerdict(verdict, "emailgwefficacy-delegatedmailboxaccess")
	outcome := phishval.Evaluate("run-ph-auth-010", "known-bad", catalogExpectation(t, "PH-AUTH-010"), obs)

	if outcome.Detection.Verdict != phishval.VerdictFail {
		t.Errorf("Detection.Verdict = %q, want %q", outcome.Detection.Verdict, phishval.VerdictFail)
	}
}

func TestPHAUTH010_NoEvidence_Inconclusive_NeverFabricatesEitherOutcome(t *testing.T) {
	exp := emailgwefficacy.SuspiciousDelegatedMailboxAccessExpectation(true)
	provider := emailgwefficacy.NewFixtureDelegatedMailboxAccessProvider(nil)

	verdict := emailgwefficacy.VerifyDelegatedMailboxAccessExpectation(exp, provider, scenarioWindow())
	obs := FromSingleDimensionDetectionVerdict(verdict, "emailgwefficacy-delegatedmailboxaccess")
	outcome := phishval.Evaluate("run-ph-auth-010", "no-evidence", catalogExpectation(t, "PH-AUTH-010"), obs)

	if outcome.Detection.Verdict != phishval.VerdictInconclusive {
		t.Errorf("Detection.Verdict = %q, want %q (absence of evidence is not proof of either outcome)", outcome.Detection.Verdict, phishval.VerdictInconclusive)
	}
}
