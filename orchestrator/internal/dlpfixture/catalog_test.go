package dlpfixture

import "testing"

func TestAllFixtures_ReturnsThirtySevenFixtures(t *testing.T) {
	fixtures, err := AllFixtures()
	if err != nil {
		t.Fatalf("AllFixtures: %v", err)
	}
	if len(fixtures) != 37 {
		t.Fatalf("len(fixtures) = %d, want 37", len(fixtures))
	}
}

func TestAllFixtures_ValidatesCleanAgainstItself(t *testing.T) {
	fixtures, err := AllFixtures()
	if err != nil {
		t.Fatalf("AllFixtures: %v", err)
	}
	if err := ValidateCatalog(fixtures); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}

// Review Focus: the catalog's total occurrence count must equal the real
// step count across every scenarios/dlp-exfiltration-*.yaml file (83 steps across 18 scenario files,
// confirmed by direct enumeration 2026-10-20) -- too few means a real
// step is uncatalogued (an "unregistered fixture value"), too many means
// a duplicate or a stale reference slipped in.
func TestAllFixtures_TotalOccurrenceCountMatchesRealStepCount(t *testing.T) {
	fixtures, err := AllFixtures()
	if err != nil {
		t.Fatalf("AllFixtures: %v", err)
	}
	total := 0
	for _, f := range fixtures {
		total += len(f.Occurrences)
	}
	const wantTotalRealSteps = 83
	if total != wantTotalRealSteps {
		t.Errorf("total occurrences = %d, want %d", total, wantTotalRealSteps)
	}
}

func TestAllFixtures_EveryNoteIsNonEmpty(t *testing.T) {
	fixtures, err := AllFixtures()
	if err != nil {
		t.Fatalf("AllFixtures: %v", err)
	}
	for _, f := range fixtures {
		if f.Note == "" {
			t.Errorf("fixture %q has an empty Note", f.ID)
		}
	}
}
