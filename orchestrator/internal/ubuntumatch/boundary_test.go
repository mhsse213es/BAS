package ubuntumatch

import "testing"

func TestMatchEqualToFixedVersionIsNotExposed(t *testing.T) {
	reg := &Register{Mappings: []Mapping{approved("UBUNTU-BOUNDARY")}}
	got := Match(reg, Host{Release: "jammy", Packages: map[string]string{"roundcube": "1.4.3+dfsg.1-1ubuntu0.1"}})
	if len(got) != 1 || got[0].Verdict != NotExposed {
		t.Fatalf("installed equal to fixed version: got %+v, want NOT_EXPOSED", got)
	}
}

func TestMalformedVersionsAreUnknown(t *testing.T) {
	cases := []struct {
		name      string
		installed string
		fixed     string
	}{
		{"empty installed version", "", "1.4.3"},
		{"non-numeric epoch on installed", "x:1.0", "1.4.3"},
		{"space in installed version", "1.4 2", "1.4.3"},
		{"empty upstream in installed version", "-1", "1.4.3"},
		{"non-numeric epoch on fixed version", "1.0", "y:1.4.3"},
	}
	for _, c := range cases {
		m := approved("UBUNTU-MALFORMED")
		m.Releases["jammy"] = ReleaseFix{
			Corresponding: []string{"roundcube"},
			Fixed:         []PackageFix{{Package: "roundcube", Version: c.fixed}},
		}
		reg := &Register{Mappings: []Mapping{m}}
		got := Match(reg, Host{Release: "jammy", Packages: map[string]string{"roundcube": c.installed}})
		if len(got) != 1 || got[0].Verdict != Unknown {
			t.Errorf("%s: got %+v, want UNKNOWN", c.name, got)
		}
	}
}
