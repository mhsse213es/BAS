package panosexposure

import "testing"

// Boundary cases checked against the verified CVE-2026-0257 advisory data.
// Every version is taken from the advisory's own thresholds or fixed releases.
func TestCVE20260257_BoundariesMatchAdvisory(t *testing.T) {
	adv, err := LoadBuiltinAdvisory("CVE-2026-0257")
	if err != nil {
		t.Fatal(err)
	}
	exposed := func(version string) Asset {
		return Asset{
			ID: "fw", Product: Product, Version: version,
			GlobalProtect: TriYes, AuthOverride: TriYes, SharedOverrideCert: TriYes,
		}
	}
	cases := []struct {
		version string
		want    Verdict
	}{
		// 10.2 train boundaries
		{"10.2.7-h33", VerdictVulnerable},
		{"10.2.7-h34", VerdictNotAffected},
		{"10.2.8", VerdictVulnerable},
		{"10.2.10-h35", VerdictVulnerable},
		{"10.2.10-h36", VerdictNotAffected},
		{"10.2.17", VerdictVulnerable},
		{"10.2.18-h5", VerdictVulnerable},
		{"10.2.18-h6", VerdictNotAffected},
		// 10.2.18 base conflicts in the advisory itself
		{"10.2.18", VerdictUnknown},
		// 11.1 train boundaries
		{"11.1.4-h32", VerdictVulnerable},
		{"11.1.4-h33", VerdictNotAffected},
		{"11.1.14", VerdictVulnerable},
		{"11.1.15", VerdictNotAffected},
		// 11.2 train boundaries
		{"11.2.11", VerdictVulnerable},
		{"11.2.12", VerdictNotAffected},
		// 12.1 train boundaries
		{"12.1.4-h5", VerdictVulnerable},
		{"12.1.4-h6", VerdictNotAffected},
		{"12.1.5", VerdictVulnerable},
		{"12.1.7", VerdictNotAffected},
		// older unsupported releases are affected per the advisory wording
		{"10.1.0", VerdictVulnerable},
		// branches the advisory does not cover must never read as not-affected
		{"11.0.4", VerdictUnknown},
		{"12.0.1", VerdictUnknown},
	}
	for _, c := range cases {
		r := Assess(exposed(c.version), adv)
		if r.Verdict != c.want {
			t.Errorf("version %s: verdict = %s, want %s (reason: %s)", c.version, r.Verdict, c.want, r.Reason)
		}
	}
}

func TestCVE20260257_MitigationsChangeTheVerdict(t *testing.T) {
	adv, err := LoadBuiltinAdvisory("CVE-2026-0257")
	if err != nil {
		t.Fatal(err)
	}
	a := Asset{ID: "fw", Product: Product, Version: "11.2.8",
		GlobalProtect: TriYes, AuthOverride: TriYes, SharedOverrideCert: TriNo}
	if r := Assess(a, adv); r.Verdict != VerdictMitigated {
		t.Errorf("dedicated override certificate: verdict = %s, want %s", r.Verdict, VerdictMitigated)
	}
	a.SharedOverrideCert = TriYes
	a.AuthOverride = TriNo
	if r := Assess(a, adv); r.Verdict != VerdictMitigated {
		t.Errorf("override disabled: verdict = %s, want %s", r.Verdict, VerdictMitigated)
	}
}

func TestLoadBuiltinAdvisory_RejectsUnknownCVE(t *testing.T) {
	if _, err := LoadBuiltinAdvisory("CVE-9999-0000"); err == nil {
		t.Fatal("an advisory that is not shipped must be an error, never a guess")
	}
}
