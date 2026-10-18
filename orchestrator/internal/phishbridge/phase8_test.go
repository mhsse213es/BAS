package phishbridge

import (
	"testing"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// TestPHAUTH008_BusinessContinuity_LegitimateTrustedSenderNotBlocked is
// Phase 8's false-positive/business-continuity pairing proof for
// PH-AUTH-008. emailgwefficacy.AuthenticationExceptionScopeExpectation
// already ships both halves of this pair (scoped=false, the abuse
// probe PH-AUTH-008's own catalog Expectation already bridges; and
// scoped=true, the genuine trusted-source message) -- but scoped=true
// had never been wired into Phishing BAS Mastery anywhere before this
// test. Its own Note documents exactly why this half matters: "proving
// the documented exception does not break the legitimate mail flow it
// exists for."
//
// This deliberately grades against a LOCAL Expectation{Enforcement:
// Allowed}, not PH-AUTH-008's own catalog Expectation (Enforcement:
// Blocked) -- business-continuity pairing is inherently a second,
// opposite-polarity expectation layered onto the same control, not a
// restatement of the attack-framed one. Encoding it as a second
// catalog entry would misrepresent it as an independent scenario rather
// than this scenario's own false-positive counterpart.
func TestPHAUTH008_BusinessContinuity_LegitimateTrustedSenderNotBlocked(t *testing.T) {
	exp := emailgwefficacy.AuthenticationExceptionScopeExpectation(true) // scoped=true: genuine trusted source
	result := efficacyResultForAction(t, exp, "deliver", boolPtr(false), nil)

	obs := FromEmailGWEfficacyResult(result)
	businessContinuityExpectation := phishval.Expectation{
		ScenarioID: "PH-AUTH-008", Enforcement: ptrEnforcementLocal(phishval.EnforcementAllowed),
	}
	outcome := phishval.Evaluate("run-ph-auth-008-fp", "business-continuity", businessContinuityExpectation, obs)
	if outcome.Enforcement.Verdict != phishval.VerdictPass {
		t.Errorf("Enforcement.Verdict = %q (%s), want %q (the documented exception must not block the legitimate mail flow it exists for)",
			outcome.Enforcement.Verdict, outcome.Enforcement.Reason, phishval.VerdictPass)
	}
}

func ptrEnforcementLocal(v phishval.EnforcementOutcome) *phishval.EnforcementOutcome { return &v }

// TestPHURL005_BusinessContinuity_BenignURLNotRewritten is the second
// false-positive/business-continuity pairing proof: PH-URL-005's own
// catalog mapping only ever wires URLRewriteExpectation(true) (the
// malicious-URL case). URLRewriteExpectation(false) -- the benign-URL,
// "no rewriting needed" case per dispatch.go's own
// "EG-003.url-rewrite.known-good" naming -- had never been bridged
// either, the same unwired-counterpart gap as PH-AUTH-008's.
func TestPHURL005_BusinessContinuity_BenignURLNotRewritten(t *testing.T) {
	exp := emailgwefficacy.URLRewriteExpectation(false) // the benign-URL/false-positive case
	result := efficacyResultForAction(t, exp, "deliver", boolPtr(false), nil)

	obs := FromEmailGWEfficacyResult(result)
	businessContinuityExpectation := phishval.Expectation{
		ScenarioID: "PH-URL-005", Delivery: deliveryPtr(phishval.DeliveryDelivered),
	}
	outcome := phishval.Evaluate("run-ph-url-005-fp", "business-continuity", businessContinuityExpectation, obs)
	if outcome.Delivery.Verdict != phishval.VerdictPass {
		t.Errorf("Delivery.Verdict = %q (%s), want %q (a benign URL must not be treated as the malicious case)",
			outcome.Delivery.Verdict, outcome.Delivery.Reason, phishval.VerdictPass)
	}
}
