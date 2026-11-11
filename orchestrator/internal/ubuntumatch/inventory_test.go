package ubuntumatch

import (
	"errors"
	"testing"
)

func TestParseDpkgInventoryKeepsInstalledOnly(t *testing.T) {
	raw := "roundcube|1.4.2+dfsg-1|all|installed\n" +
		"oldpkg|0.1|amd64|config-files\n" +
		"firefox|97.0.2+build1-0ubuntu0.20.04.1|amd64|installed\n"
	got, err := ParseDpkgInventory(raw, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["roundcube"] != "1.4.2+dfsg-1" || got["firefox"] == "" {
		t.Errorf("installed packages missing: %v", got)
	}
	if _, ok := got["oldpkg"]; ok {
		t.Errorf("config-files (removed) package must not be in the inventory: %v", got)
	}
}

func TestParseDpkgInventoryRejectsTruncatedOutput(t *testing.T) {
	_, err := ParseDpkgInventory("roundcube|1.4|all|installed\n", true)
	if !errors.Is(err, ErrIncompleteInventory) {
		t.Fatalf("truncated output: got %v, want ErrIncompleteInventory", err)
	}
}

func TestParseDpkgInventoryRejectsMalformedLines(t *testing.T) {
	cases := []string{
		"roundcube|1.4|all\n",        // three fields
		"|1.4|all|installed\n",       // empty name
		"roundcube||all|installed\n", // empty version
		"roundcube|1.4||installed\n", // empty architecture
	}
	for _, raw := range cases {
		if _, err := ParseDpkgInventory(raw, false); err == nil {
			t.Errorf("malformed line accepted: %q", raw)
		}
	}
}

func TestParseDpkgInventoryMarksArchConflictAmbiguous(t *testing.T) {
	raw := "libfoo|1.0-1|amd64|installed\n" +
		"libfoo|1.0-2|i386|installed\n"
	got, err := ParseDpkgInventory(raw, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["libfoo"] != AmbiguousVersion {
		t.Fatalf("conflicting arch versions: got %q, want %q", got["libfoo"], AmbiguousVersion)
	}
}

func TestAmbiguousInstalledVersionIsUnknown(t *testing.T) {
	m := approved("UBUNTU-AMBIG")
	reg := &Register{Mappings: []Mapping{m}}
	got := Match(reg, Host{Release: "jammy", Packages: map[string]string{"roundcube": AmbiguousVersion}})
	if len(got) != 1 || got[0].Verdict != Unknown {
		t.Fatalf("ambiguous installed version: got %+v, want UNKNOWN", got)
	}
}
