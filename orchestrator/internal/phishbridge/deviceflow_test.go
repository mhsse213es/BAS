package phishbridge

import (
	"testing"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

func TestPHID003_EndToEnd_KnownGood_DeviceCodeBlocked(t *testing.T) {
	signIns := []phishidentity.SignInEvent{{
		ID: "signin-1", AuthenticationProtocol: "deviceCode",
		AppliedConditionalAccessPolicies: []phishidentity.AppliedConditionalAccessPolicy{
			{DisplayName: "Block legacy authentication and device code flow", Result: "failure"},
		},
	}}
	outcome, detail := phishidentity.EvaluateDeviceCodeEnforcement(signIns)
	obs := FromDeviceCodeEnforcement(outcome, detail)
	result := phishval.Evaluate("run-ph-id-003", "known-good", catalogExpectation(t, "PH-ID-003"), obs)

	if result.Enforcement.Verdict != phishval.VerdictPass {
		t.Errorf("Enforcement.Verdict = %q (%s), want %q", result.Enforcement.Verdict, result.Enforcement.Reason, phishval.VerdictPass)
	}
}

func TestPHID003_EndToEnd_KnownBad_DeviceCodeAllowed(t *testing.T) {
	signIns := []phishidentity.SignInEvent{{
		ID: "signin-1", AuthenticationProtocol: "deviceCode", ConditionalAccessEvidence: true,
		AppliedConditionalAccessPolicies: []phishidentity.AppliedConditionalAccessPolicy{
			{DisplayName: "Require MFA for all users", Result: "success"},
		},
	}}
	outcome, detail := phishidentity.EvaluateDeviceCodeEnforcement(signIns)
	obs := FromDeviceCodeEnforcement(outcome, detail)
	result := phishval.Evaluate("run-ph-id-003", "known-bad", catalogExpectation(t, "PH-ID-003"), obs)

	if result.Enforcement.Verdict != phishval.VerdictFail {
		t.Errorf("Enforcement.Verdict = %q, want %q", result.Enforcement.Verdict, phishval.VerdictFail)
	}
}

func TestPHID003_NoDeviceCodeSignIns_Inconclusive_NeverFabricatesEitherOutcome(t *testing.T) {
	outcome, detail := phishidentity.EvaluateDeviceCodeEnforcement(nil)
	obs := FromDeviceCodeEnforcement(outcome, detail)
	result := phishval.Evaluate("run-ph-id-003", "no-evidence", catalogExpectation(t, "PH-ID-003"), obs)

	if result.Enforcement.Verdict != phishval.VerdictInconclusive {
		t.Errorf("Enforcement.Verdict = %q, want %q (no observed deviceCode sign-in is not proof of either outcome)", result.Enforcement.Verdict, phishval.VerdictInconclusive)
	}
}

// An omitted Conditional Access property must reach the scenario as inconclusive
// evidence, never as a pass or a fail.
func TestPHID003_EndToEnd_OmittedCA_IsInconclusiveNeverPass(t *testing.T) {
	signIns := []phishidentity.SignInEvent{{
		ID: "signin-1", AuthenticationProtocol: "deviceCode", ConditionalAccessEvidence: false,
	}}
	outcome, detail := phishidentity.EvaluateDeviceCodeEnforcement(signIns)
	obs := FromDeviceCodeEnforcement(outcome, detail)
	result := phishval.Evaluate("run-ph-id-003", "omitted-ca", catalogExpectation(t, "PH-ID-003"), obs)

	if result.Enforcement.Verdict == phishval.VerdictPass {
		t.Fatalf("Enforcement.Verdict = pass for an omitted CA property; an omitted property must never count as a pass")
	}
	if result.Enforcement.Verdict != phishval.VerdictInconclusive {
		t.Errorf("Enforcement.Verdict = %q, want %q", result.Enforcement.Verdict, phishval.VerdictInconclusive)
	}
}
