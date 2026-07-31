package artifactgen

import (
	"testing"

	"github.com/audspect/bas/internal/iocregistry"
)

func TestLookup_UnknownKey_ReturnsFalse(t *testing.T) {
	_, ok := Lookup("T0000", "no such test", "no_such_arg")
	if ok {
		t.Error("Lookup for an unseeded key = true, want false")
	}
}

func TestLookup_SeededKey_ReturnsTypeAndTrue(t *testing.T) {
	key := ArgKey{TechniqueID: "T0000", TestName: "Example Test", ArgName: "output_file"}
	cleanup := SeedForTest(key, iocregistry.TypeFilename)
	defer cleanup()

	got, ok := Lookup("T0000", "Example Test", "output_file")
	if !ok || got != iocregistry.TypeFilename {
		t.Errorf("Lookup = (%v, %v), want (%v, true)", got, ok, iocregistry.TypeFilename)
	}
}

func TestCuratedFor_ReturnsOnlyMatchingTechnique(t *testing.T) {
	keyA := ArgKey{TechniqueID: "T0000", TestName: "Test A", ArgName: "arg_a"}
	keyB := ArgKey{TechniqueID: "T0000", TestName: "Test B", ArgName: "arg_b"}
	keyOther := ArgKey{TechniqueID: "T0001", TestName: "Test C", ArgName: "arg_c"}
	cleanupA := SeedForTest(keyA, iocregistry.TypeFilename)
	defer cleanupA()
	cleanupB := SeedForTest(keyB, iocregistry.TypeMutex)
	defer cleanupB()
	cleanupOther := SeedForTest(keyOther, iocregistry.TypeService)
	defer cleanupOther()

	got := CuratedFor("T0000")
	if len(got) != 2 {
		t.Fatalf("CuratedFor(T0000) = %+v, want 2 entries", got)
	}
	if got[keyA] != iocregistry.TypeFilename || got[keyB] != iocregistry.TypeMutex {
		t.Errorf("CuratedFor(T0000) = %+v, want keyA=filename keyB=mutex", got)
	}
	if _, found := got[keyOther]; found {
		t.Errorf("CuratedFor(T0000) included a T0001 entry: %+v", got)
	}
}
