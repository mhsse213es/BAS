package phishbridge

import (
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
