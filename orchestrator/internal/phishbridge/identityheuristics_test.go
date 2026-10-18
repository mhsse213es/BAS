package phishbridge

import (
	"testing"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

func TestPHID004_EndToEnd_KnownGood_FatigueBurstDetected(t *testing.T) {
	obs := FromMFAFatigueHeuristic(phishidentity.MFAFatigueSuspected, "5 MFA denial events within 10m0s")
	outcome := phishval.Evaluate("run-ph-id-004", "known-good", catalogExpectation(t, "PH-ID-004"), obs)

	if outcome.Detection.Verdict != phishval.VerdictPass {
		t.Errorf("Detection.Verdict = %q (%s), want %q", outcome.Detection.Verdict, outcome.Detection.Reason, phishval.VerdictPass)
	}
	if outcome.Detection.Evidence != phishval.EvidenceInferred {
		t.Errorf("Detection.Evidence = %q, want %q (must never claim verified_telemetry for a non-Microsoft-documented heuristic)", outcome.Detection.Evidence, phishval.EvidenceInferred)
	}
}

func TestPHID004_EndToEnd_KnownBad_NoBurstObserved(t *testing.T) {
	obs := FromMFAFatigueHeuristic(phishidentity.MFAFatigueNotObserved, "2 MFA denial event(s) observed, none met the burst threshold")
	outcome := phishval.Evaluate("run-ph-id-004", "known-bad", catalogExpectation(t, "PH-ID-004"), obs)

	if outcome.Detection.Verdict != phishval.VerdictFail {
		t.Errorf("Detection.Verdict = %q, want %q", outcome.Detection.Verdict, phishval.VerdictFail)
	}
}

func TestPHID004_NoEvidence_Inconclusive_NeverFabricatesEitherOutcome(t *testing.T) {
	obs := FromMFAFatigueHeuristic(phishidentity.MFAFatigueUnknown, "no MFA denial events observed in this window")
	outcome := phishval.Evaluate("run-ph-id-004", "no-evidence", catalogExpectation(t, "PH-ID-004"), obs)

	if outcome.Detection.Verdict != phishval.VerdictInconclusive {
		t.Errorf("Detection.Verdict = %q, want %q", outcome.Detection.Verdict, phishval.VerdictInconclusive)
	}
}

func TestPHID005_EndToEnd_KnownGood_SessionsContainedAfterRiskyEvent(t *testing.T) {
	obs := FromSessionTheftResponseHeuristic(phishidentity.SessionTheftRevokedAfterRiskyEvent, "sessions revoked 5m0s after risky sign-in")
	outcome := phishval.Evaluate("run-ph-id-005", "known-good", catalogExpectation(t, "PH-ID-005"), obs)

	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q (%s), want %q", outcome.Response.Verdict, outcome.Response.Reason, phishval.VerdictPass)
	}
	if outcome.Response.Evidence != phishval.EvidenceInferred {
		t.Errorf("Response.Evidence = %q, want %q (must never claim a verified causal signal Microsoft doesn't document)", outcome.Response.Evidence, phishval.EvidenceInferred)
	}
}

func TestPHID005_EndToEnd_KnownBad_SessionsNeverContained(t *testing.T) {
	obs := FromSessionTheftResponseHeuristic(phishidentity.SessionTheftNotRevoked, "1 risky sign-in observed, sessions not revoked")
	outcome := phishval.Evaluate("run-ph-id-005", "known-bad", catalogExpectation(t, "PH-ID-005"), obs)

	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictFail)
	}
}

func TestPHID005_NoEvidence_NotTested_NeverFabricatesEitherOutcome(t *testing.T) {
	obs := FromSessionTheftResponseHeuristic(phishidentity.SessionTheftUnknown, "no risky sign-in observed")
	outcome := phishval.Evaluate("run-ph-id-005", "no-evidence", catalogExpectation(t, "PH-ID-005"), obs)

	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}
