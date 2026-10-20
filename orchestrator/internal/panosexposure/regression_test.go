package panosexposure

import "testing"

// An unknown configuration fact must never produce a mitigated or vulnerable
// verdict on an affected version. It must stay unknown. Each condition is
// checked on its own, so one unknown cannot be hidden by another fact.
func TestRegression_UnknownConditionNeverMitigatedOrVulnerable(t *testing.T) {
	adv, err := LoadBuiltinAdvisory("CVE-2026-0257")
	if err != nil {
		t.Fatal(err)
	}
	for _, unknown := range []string{"globalProtect", "authOverride", "sharedOverrideCert"} {
		a := Asset{ID: "fw", Product: Product, Version: "11.2.8",
			GlobalProtect: TriYes, AuthOverride: TriYes, SharedOverrideCert: TriYes}
		switch unknown {
		case "globalProtect":
			a.GlobalProtect = TriUnknown
		case "authOverride":
			a.AuthOverride = TriUnknown
		case "sharedOverrideCert":
			a.SharedOverrideCert = TriUnknown
		}
		r := AssessAt(a, adv, fixedTime)
		if r.Verdict != VerdictUnknown {
			t.Errorf("unknown %s: verdict = %s, want unknown", unknown, r.Verdict)
		}
	}
}

// A confirmed "no" on a condition is a mitigation even if another condition is
// unknown. Only the confirmed fact may decide.
func TestRegression_ConfirmedAbsentWinsOverUnknownOther(t *testing.T) {
	adv, _ := LoadBuiltinAdvisory("CVE-2026-0257")
	a := Asset{ID: "fw", Product: Product, Version: "11.2.8",
		GlobalProtect: TriYes, AuthOverride: TriUnknown, SharedOverrideCert: TriNo}
	if r := AssessAt(a, adv, fixedTime); r.Verdict != VerdictMitigated {
		t.Fatalf("verdict = %s, want mitigated", r.Verdict)
	}
}

// Version-only verdicts do not depend on configuration. An unknown certificate
// fact must not turn a not-affected release into something else.
func TestRegression_UnknownConfigDoesNotChangeVersionOnlyVerdict(t *testing.T) {
	adv, _ := LoadBuiltinAdvisory("CVE-2026-0257")
	a := Asset{ID: "fw", Product: Product, Version: "11.2.12",
		GlobalProtect: TriUnknown, AuthOverride: TriUnknown, SharedOverrideCert: TriUnknown}
	if r := AssessAt(a, adv, fixedTime); r.Verdict != VerdictNotAffected {
		t.Fatalf("verdict = %s, want not_affected", r.Verdict)
	}
}

// The result must carry the advisory status that was used, so the verdict can be
// read as verified or unverified data without consulting the registry.
func TestRegression_ResultStatusIsSetByCaller(t *testing.T) {
	adv, _ := LoadBuiltinAdvisory("CVE-2026-0257")
	r := AssessAt(exposedBase(), adv, fixedTime)
	if r.AdvisoryStatus != "" {
		t.Fatalf("AssessAt must not invent a status; got %q", r.AdvisoryStatus)
	}
}
