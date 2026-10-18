package phishbridge

import (
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

func TestPHID002_EndToEnd_KnownGood_NoRiskyTenantWideGrant(t *testing.T) {
	grants := []phishidentity.OAuthConsentGrant{
		{ID: "grant-1", ClientID: "sp-benign", ConsentType: "Principal", PrincipalID: "user-1", Scope: "User.Read"},
	}
	obs := FromOAuthConsentGrants(grants, time.Now())
	outcome := phishval.Evaluate("run-ph-id-002", "known-good", catalogExpectation(t, "PH-ID-002"), obs)
	if outcome.Enforcement.Verdict != phishval.VerdictPass {
		t.Errorf("Enforcement.Verdict = %q (%s), want %q", outcome.Enforcement.Verdict, outcome.Enforcement.Reason, phishval.VerdictPass)
	}
}

func TestPHIR002_EndToEnd_KnownGood_ContainmentDispatchedAndVerified(t *testing.T) {
	now := time.Now()
	result := phishidentity.RevocationResult{
		Baseline: now, After: now.Add(time.Hour), Verification: phishidentity.RevocationVerified,
		Detail: "signInSessionsValidFromDateTime advanced",
	}
	obs := FromIdentityContainment(result, time.Now())
	outcome := phishval.Evaluate("run-ph-ir-002", "known-good", catalogExpectation(t, "PH-IR-002"), obs)
	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q (%s), want %q", outcome.Response.Verdict, outcome.Response.Reason, phishval.VerdictPass)
	}
}

func TestPHIR002_EndToEnd_KnownBad_DispatchRejected(t *testing.T) {
	result := phishidentity.RevocationResult{DispatchErr: errors.New("graph: 403 forbidden")}
	obs := FromIdentityContainment(result, time.Now())
	outcome := phishval.Evaluate("run-ph-ir-002", "known-bad", catalogExpectation(t, "PH-IR-002"), obs)
	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictFail)
	}
}

// TestPHIR002_EndToEnd_KnownBad_MarkerNeverAdvanced is the confirmed-
// negative case: Graph accepted the dispatch, but the independent
// re-read proves the revocation never actually took effect.
func TestPHIR002_EndToEnd_KnownBad_MarkerNeverAdvanced(t *testing.T) {
	now := time.Now()
	result := phishidentity.RevocationResult{
		Baseline: now, After: now, Verification: phishidentity.RevocationNotVerified,
		Detail: "signInSessionsValidFromDateTime did not advance",
	}
	obs := FromIdentityContainment(result, time.Now())
	outcome := phishval.Evaluate("run-ph-ir-002", "known-bad", catalogExpectation(t, "PH-IR-002"), obs)
	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q (a confirmed non-advance must grade as a failure, not a softer verdict)", outcome.Response.Verdict, phishval.VerdictFail)
	}
}

// TestPHIR002_InconclusiveRead_NeverFabricatesContainedOrFailed is the
// core non-negotiable this bridge exists to enforce: an inconclusive
// verification read (never a successful dispatch alone) must never be
// read as either confirmed containment or confirmed failure.
func TestPHIR002_InconclusiveRead_NeverFabricatesContainedOrFailed(t *testing.T) {
	result := phishidentity.RevocationResult{Verification: phishidentity.RevocationUnknown, Detail: "could not read post-revocation marker"}
	obs := FromIdentityContainment(result, time.Now())
	outcome := phishval.Evaluate("run-ph-ir-002", "unverified", catalogExpectation(t, "PH-IR-002"), obs)
	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q (an inconclusive read must never grade as Contained or Failed)", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}

func TestPHID002_EndToEnd_KnownBad_RiskyTenantWideGrantExists(t *testing.T) {
	grants := []phishidentity.OAuthConsentGrant{
		{ID: "grant-1", ClientID: "sp-attacker-app", ConsentType: "AllPrincipals", Scope: "Mail.Read Files.ReadWrite.All"},
	}
	obs := FromOAuthConsentGrants(grants, time.Now())
	outcome := phishval.Evaluate("run-ph-id-002", "known-bad", catalogExpectation(t, "PH-ID-002"), obs)
	if outcome.Enforcement.Verdict != phishval.VerdictFail {
		t.Errorf("Enforcement.Verdict = %q, want %q (risky tenant-wide grant must grade as a control gap)", outcome.Enforcement.Verdict, phishval.VerdictFail)
	}
}
