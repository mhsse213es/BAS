package ubuntumatch

import (
	"testing"
)

func TestDpkgCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0-1", -1},
		{"1:0.5", "2.0", 1},
		{"1.0a", "1.0b", -1},
		{"1.0", "1.0a", -1},
		{"1.0+dfsg", "1.0", 1},
		{"2.10", "2.9", 1},
		{"5.16.1-1ubuntu0.1", "5.16.1-1ubuntu0.1~esm1", 1},
		{"97.0.2+build1-0ubuntu0.20.04.1", "97.0.2+build1-0ubuntu0.20.04.1", 0},
		{"1.4.2+dfsg.1-1", "1.4.3+dfsg.1-1ubuntu0.1~esm1", -1},
	}
	for _, c := range cases {
		if got := DpkgCompare(c.a, c.b); got != c.want {
			t.Errorf("DpkgCompare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := DpkgCompare(c.b, c.a); got != -c.want {
			t.Errorf("DpkgCompare(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func approved(id string) Mapping {
	return Mapping{
		ID: id, CVE: "CVE-TEST-1", Status: StatusApproved,
		Curator: "Alice", IndependentReviewer: "Bob", ReviewDate: "2026-11-10",
		Releases: map[string]ReleaseFix{
			"jammy": {Corresponding: []string{"roundcube"},
				Fixed: []PackageFix{{Package: "roundcube", Version: "1.4.3+dfsg.1-1ubuntu0.1"}}},
		},
	}
}

func TestEligibleGate(t *testing.T) {
	cases := []struct {
		name string
		edit func(m *Mapping)
		want bool
	}{
		{"approved with independent reviewer and date", func(m *Mapping) {}, true},
		{"status not approved", func(m *Mapping) { m.Status = "PENDING_HUMAN_REVIEW" }, false},
		{"self-recorded curator as reviewer", func(m *Mapping) { m.IndependentReviewer = "Alice" }, false},
		{"reviewer says none", func(m *Mapping) { m.IndependentReviewer = "none (curator only)" }, false},
		{"no reviewer", func(m *Mapping) { m.IndependentReviewer = "" }, false},
		{"no review date", func(m *Mapping) { m.ReviewDate = "" }, false},
		{"malformed review date", func(m *Mapping) { m.ReviewDate = "11/10/2026" }, false},
	}
	for _, c := range cases {
		m := approved("X")
		c.edit(&m)
		if got := m.Eligible(); got != c.want {
			t.Errorf("%s: Eligible() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMatchVerdicts(t *testing.T) {
	reg := &Register{Mappings: []Mapping{approved("UBUNTU-TEST")}}

	exposed := Match(reg, Host{Release: "jammy", Packages: map[string]string{"roundcube": "1.4.2+dfsg-1"}})
	if len(exposed) != 1 || exposed[0].Verdict != Exposed {
		t.Fatalf("older installed version: got %+v, want one EXPOSED", exposed)
	}

	fixed := Match(reg, Host{Release: "jammy", Packages: map[string]string{"roundcube": "1.4.3+dfsg.1-1ubuntu0.1"}})
	if len(fixed) != 1 || fixed[0].Verdict != NotExposed {
		t.Fatalf("fixed installed version: got %+v, want one NOT_EXPOSED", fixed)
	}

	missing := Match(reg, Host{Release: "jammy", Packages: map[string]string{}})
	if len(missing) != 1 || missing[0].Verdict != Unknown {
		t.Fatalf("package absent from inventory: got %+v, want UNKNOWN, never NOT_EXPOSED", missing)
	}

	otherRelease := Match(reg, Host{Release: "focal", Packages: map[string]string{"roundcube": "1.0"}})
	if len(otherRelease) != 1 || otherRelease[0].Verdict != Unknown {
		t.Fatalf("release without data: got %+v, want UNKNOWN", otherRelease)
	}
}

func TestMatchIgnoresIneligibleMappings(t *testing.T) {
	m := approved("UBUNTU-PENDING")
	m.Status = "PENDING_HUMAN_REVIEW"
	reg := &Register{Mappings: []Mapping{m}}
	got := Match(reg, Host{Release: "jammy", Packages: map[string]string{"roundcube": "1.0"}})
	if len(got) != 0 {
		t.Fatalf("ineligible mapping produced results: %+v", got)
	}
}

func TestMatchDisagreeingFixesAreUnknown(t *testing.T) {
	m := approved("UBUNTU-SPLIT")
	m.Releases["jammy"] = ReleaseFix{
		Corresponding: []string{"roundcube"},
		Fixed: []PackageFix{
			{Package: "roundcube", Version: "1.4.3"},
			{Package: "roundcube", Version: "1.0"},
		},
	}
	reg := &Register{Mappings: []Mapping{m}}
	got := Match(reg, Host{Release: "jammy", Packages: map[string]string{"roundcube": "1.2"}})
	if len(got) != 1 || got[0].Verdict != Unknown {
		t.Fatalf("disagreeing fixed versions: got %+v, want UNKNOWN", got)
	}
}

// The real register must produce no results while no row has an independent
// reviewer. This test is the gate: it fails if a row becomes eligible without review data.
func TestRealRegisterProducesNoResultsYet(t *testing.T) {
	reg, err := LoadRegister("../../../docs/superpowers/specs/req021-spike/reviewed_mappings.yaml")
	if err != nil {
		t.Fatalf("load real register: %v", err)
	}
	for _, m := range reg.Mappings {
		if m.Eligible() {
			t.Fatalf("mapping %s is eligible, but no independent review is on record", m.ID)
		}
	}
	host := Host{Release: "jammy", Packages: map[string]string{"firefox": "1.0", "roundcube": "1.0"}}
	if got := Match(reg, host); len(got) != 0 {
		t.Fatalf("real register produced %d results before independent review: %+v", len(got), got)
	}
}
