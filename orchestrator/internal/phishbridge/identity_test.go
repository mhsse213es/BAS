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
	verified := ContainmentVerificationConfirmed
	obs := FromIdentityContainment(nil, &verified, time.Now())
	outcome := phishval.Evaluate("run-ph-ir-002", "known-good", catalogExpectation(t, "PH-IR-002"), obs)
	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q (%s), want %q", outcome.Response.Verdict, outcome.Response.Reason, phishval.VerdictPass)
	}
}

func TestPHIR002_EndToEnd_KnownBad_DispatchRejected(t *testing.T) {
	obs := FromIdentityContainment(errors.New("graph: 403 forbidden"), nil, time.Now())
	outcome := phishval.Evaluate("run-ph-ir-002", "known-bad", catalogExpectation(t, "PH-IR-002"), obs)
	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictFail)
	}
}

// TestPHIR002_DispatchAcceptedButUnverified_NeverFabricatesContained is
// the core non-negotiable this bridge exists to enforce: a successful
// Graph 2xx alone must never be read as confirmed containment.
func TestPHIR002_DispatchAcceptedButUnverified_NeverFabricatesContained(t *testing.T) {
	obs := FromIdentityContainment(nil, nil, time.Now())
	outcome := phishval.Evaluate("run-ph-ir-002", "unverified", catalogExpectation(t, "PH-IR-002"), obs)
	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q (dispatch acceptance alone must never grade as Contained)", outcome.Response.Verdict, phishval.VerdictNotTested)
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
