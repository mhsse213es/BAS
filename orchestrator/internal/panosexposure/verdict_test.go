package panosexposure

import (
	"strings"
	"testing"
)

// All version ranges and versions here are synthetic test fixtures. They are
// not vendor data for any real CVE.
var testAdvisory = Advisory{
	CVE:      "CVE-TEST-0001",
	Source:   "fixture: synthetic advisory",
	Affected: []VersionRange{{Introduced: "10.2.0", FixedIn: "10.2.4-h2"}},
	Conditions: Conditions{
		RequireGlobalProtect: true,
		RequireAuthOverride:  true,
		RequireSharedCert:    true,
	},
}

func exposedAsset(version string) Asset {
	return Asset{
		ID:                 "fw-1",
		Product:            Product,
		Version:            version,
		GlobalProtect:      TriYes,
		AuthOverride:       TriYes,
		SharedOverrideCert: TriYes,
	}
}

func TestAssess_VulnerableWhenAffectedAndAllConditionsConfirmed(t *testing.T) {
	r := Assess(exposedAsset("10.2.1"), testAdvisory)
	if r.Verdict != VerdictVulnerable {
		t.Fatalf("verdict = %s, want %s (reason: %s)", r.Verdict, VerdictVulnerable, r.Reason)
	}
}

func TestAssess_NotAffectedAtOrAfterFixedRelease(t *testing.T) {
	for _, v := range []string{"10.2.4-h2", "10.2.5", "11.0.0"} {
		r := Assess(exposedAsset(v), testAdvisory)
		if r.Verdict != VerdictNotAffected {
			t.Fatalf("version %s: verdict = %s, want %s", v, r.Verdict, VerdictNotAffected)
		}
	}
}

func TestAssess_NotAffectedBeforeIntroducedRelease(t *testing.T) {
	r := Assess(exposedAsset("10.1.9"), testAdvisory)
	if r.Verdict != VerdictNotAffected {
		t.Fatalf("verdict = %s, want %s", r.Verdict, VerdictNotAffected)
	}
}

func TestAssess_MitigatedWhenGlobalProtectDisabled(t *testing.T) {
	a := exposedAsset("10.2.1")
	a.GlobalProtect = TriNo
	r := Assess(a, testAdvisory)
	if r.Verdict != VerdictMitigated {
		t.Fatalf("verdict = %s, want %s", r.Verdict, VerdictMitigated)
	}
}

func TestAssess_MitigatedWhenOverrideDisabledEvenIfGlobalProtectUnknown(t *testing.T) {
	a := exposedAsset("10.2.1")
	a.GlobalProtect = TriUnknown
	a.AuthOverride = TriNo
	r := Assess(a, testAdvisory)
	if r.Verdict != VerdictMitigated {
		t.Fatalf("a confirmed 'no' must win over an unknown: verdict = %s, want %s", r.Verdict, VerdictMitigated)
	}
}

func TestAssess_UnknownWhenNamedConditionCannotBeEstablished(t *testing.T) {
	a := exposedAsset("10.2.1")
	a.AuthOverride = TriUnknown
	r := Assess(a, testAdvisory)
	if r.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %s, want %s: an unknown must never read as safe", r.Verdict, VerdictUnknown)
	}
}

func TestAssess_InvalidTriValueIsTreatedAsUnknown(t *testing.T) {
	a := exposedAsset("10.2.1")
	a.SharedOverrideCert = Tri("maybe")
	r := Assess(a, testAdvisory)
	if r.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %s, want %s for an invalid value", r.Verdict, VerdictUnknown)
	}
}

func TestAssess_UnknownForUnparseableVersion(t *testing.T) {
	for _, v := range []string{"", "10.2", "10.2.x", "10.2.1-h0", "v10.2.1"} {
		r := Assess(exposedAsset(v), testAdvisory)
		if r.Verdict != VerdictUnknown {
			t.Fatalf("version %q: verdict = %s, want %s", v, r.Verdict, VerdictUnknown)
		}
	}
}

func TestAssess_NotApplicableForOtherProducts(t *testing.T) {
	a := exposedAsset("10.2.1")
	a.Product = "fortinet"
	r := Assess(a, testAdvisory)
	if r.Verdict != VerdictNotApplicable {
		t.Fatalf("verdict = %s, want %s", r.Verdict, VerdictNotApplicable)
	}
}

func TestAssess_UnknownWhenRangeHasNoFixedRelease(t *testing.T) {
	adv := testAdvisory
	adv.Affected = []VersionRange{{Introduced: "10.2.0", FixedIn: ""}}
	r := Assess(exposedAsset("10.2.1"), adv)
	if r.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %s, want %s: no fixed release means the range is not assessable", r.Verdict, VerdictUnknown)
	}
}

func TestAssess_UnknownWhenAdvisoryHasNoRanges(t *testing.T) {
	adv := testAdvisory
	adv.Affected = nil
	r := Assess(exposedAsset("10.2.1"), adv)
	if r.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %s, want %s", r.Verdict, VerdictUnknown)
	}
}

func TestAssess_VersionOnlyWhenAdvisoryNamesNoConditions(t *testing.T) {
	adv := testAdvisory
	adv.Conditions = Conditions{}
	a := exposedAsset("10.2.1")
	a.GlobalProtect = TriUnknown
	r := Assess(a, adv)
	if r.Verdict != VerdictVulnerable {
		t.Fatalf("verdict = %s, want %s when no conditions are named", r.Verdict, VerdictVulnerable)
	}
	if !strings.Contains(strings.Join(r.Limitations, " "), "names no exposure conditions") {
		t.Fatalf("limitation not recorded: %v", r.Limitations)
	}
}

func TestAssess_EveryResultCarriesScopeLimitation(t *testing.T) {
	r := Assess(exposedAsset("10.2.1"), testAdvisory)
	if !strings.Contains(strings.Join(r.Limitations, " "), "not an exploitation check") {
		t.Fatalf("scope limitation missing: %v", r.Limitations)
	}
}

func TestAssess_EvidenceCitesAdvisorySource(t *testing.T) {
	r := Assess(exposedAsset("10.2.1"), testAdvisory)
	if !strings.Contains(strings.Join(r.Evidence, " "), testAdvisory.Source) {
		t.Fatalf("advisory source not cited: %v", r.Evidence)
	}
}
