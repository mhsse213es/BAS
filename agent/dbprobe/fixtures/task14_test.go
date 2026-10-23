package fixtures

import (
	"testing"

	"audspect/agent/dbprobe"
)

// The probe catalog names its fixtures by constant (dbprobe cannot import this
// package); this pins them to the real catalog.
func TestTask14ProbeFixtureConstantsMatchTheCatalog(t *testing.T) {
	if dbprobe.ClassifiedFixtureKind != KindClassifiedPII || dbprobe.RevokeFixtureKind != KindEmpty {
		t.Fatalf("kind constants drifted: %q %q", dbprobe.ClassifiedFixtureKind, dbprobe.RevokeFixtureKind)
	}
	s, ok := Lookup(dbprobe.ClassifiedFixtureKind)
	if !ok {
		t.Fatal("classified fixture missing")
	}
	found := false
	for _, tb := range s.Tables {
		if tb.Name == dbprobe.ClassifiedFixtureTable {
			found = true
		}
	}
	if !found {
		t.Fatalf("fixture %q has no table %q", dbprobe.ClassifiedFixtureKind, dbprobe.ClassifiedFixtureTable)
	}
	if _, ok := Lookup(dbprobe.RevokeFixtureKind); !ok {
		t.Fatal("revoke fixture missing")
	}
}
