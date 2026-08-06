package correlation

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

func TestResolveCanonicalTechnique_KnownID_MatchesAttackdata(t *testing.T) {
	want := attackdata.Lookup("T1059.001")
	if want == nil {
		t.Fatal("test fixture assumption broken: T1059.001 not in the bundled ATT&CK data")
	}
	got := resolveCanonicalTechnique("T1059.001")
	if got.ID != "T1059.001" {
		t.Errorf("ID = %q, want %q", got.ID, "T1059.001")
	}
	if got.Name != want.Name {
		t.Errorf("Name = %q, want %q (must match attackdata.Lookup exactly, never drift)", got.Name, want.Name)
	}
	if len(got.Platforms) != len(want.Platforms) {
		t.Errorf("Platforms = %v, want %v", got.Platforms, want.Platforms)
	}
}

func TestResolveCanonicalTechnique_UnknownID_NeverBlank(t *testing.T) {
	got := resolveCanonicalTechnique("T9999.999")
	if got.ID != "T9999.999" {
		t.Errorf("ID = %q, want %q", got.ID, "T9999.999")
	}
	if got.Name == "" {
		t.Fatal("Name must never be blank -- the never-blank invariant -- want ID-echo fallback")
	}
	if got.Name != "T9999.999" {
		t.Errorf("Name = %q, want the ID itself as the fallback", got.Name)
	}
}

func TestResolveCanonicalTechnique_SubTechniqueFallback_KeepsQueriedID(t *testing.T) {
	// attackdata.go's own Lookup docstring documents T1003.099 as an example
	// of a sub-technique with no enrichment of its own, falling back to its
	// parent T1003's data. This test proves resolveCanonicalTechnique keeps
	// the ORIGINALLY QUERIED ID (T1003.099), not the parent's ID (T1003) that
	// attackdata.Lookup's returned Enrichment.TechniqueID would carry -- using
	// the fallback entry's own ID here would misidentify which technique this is.
	parent := attackdata.Lookup("T1003")
	if parent == nil {
		t.Fatal("test fixture assumption broken: T1003 not in the bundled ATT&CK data")
	}
	got := resolveCanonicalTechnique("T1003.099")
	if got.ID != "T1003.099" {
		t.Errorf("ID = %q, want %q (the queried sub-technique, not the parent it fell back to)", got.ID, "T1003.099")
	}
	if got.Name != parent.Name {
		t.Errorf("Name = %q, want %q (inherited from parent, per attackdata's documented fallback)", got.Name, parent.Name)
	}
}

func TestResolveCanonicalTechnique_NormalizesCase(t *testing.T) {
	got := resolveCanonicalTechnique(strings.ToLower("T1059.001"))
	if got.ID != "T1059.001" {
		t.Errorf("ID = %q, want uppercase %q", got.ID, "T1059.001")
	}
}
