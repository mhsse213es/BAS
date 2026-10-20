package scenario

import (
	"strings"
	"testing"
)

func markerScenario(id string, steps ...Step) *Scenario {
	return &Scenario{ID: id, Name: "m", Steps: steps}
}

func TestMarker_ValidFormatAndPresentInCommandPasses(t *testing.T) {
	s := markerScenario("mk-ok", Step{TechniqueID: "T1003", Command: "echo cred-ident-01", Marker: "cred-ident-01"})
	if err := s.ValidateMarkers(); err != nil {
		t.Fatalf("valid marker refused: %v", err)
	}
}

// A step with no marker produces no execution evidence. It is valid as it is.
func TestMarker_AbsentIsAllowed(t *testing.T) {
	s := markerScenario("mk-none", Step{TechniqueID: "T1003", Command: "echo hi"})
	if err := s.ValidateMarkers(); err != nil {
		t.Fatalf("no marker must be allowed: %v", err)
	}
}

// Only [a-z0-9-] survives every executor's quoting. Anything else is refused.
func TestMarker_FormatIsRestrictedToSafeCharacters(t *testing.T) {
	bad := map[string]string{
		"uppercase":  "CRED-01",
		"underscore": "cred_ident_01",
		"too short":  "abc",
		"too long":   strings.Repeat("a", 41),
		"quote":      "cred'01x",
		"space":      "cred 01x",
		"semicolon":  "cred;01x",
	}
	for name, m := range bad {
		s := markerScenario("mk-bad", Step{TechniqueID: "T1", Command: "echo " + m, Marker: m})
		if err := s.ValidateMarkers(); err == nil {
			t.Errorf("%s: marker %q was accepted", name, m)
		}
	}
}

// A marker the command does not contain is a step that claims evidence it cannot
// produce. It is refused at load.
func TestMarker_MustAppearLiterallyInCommand(t *testing.T) {
	s := markerScenario("mk-absent", Step{TechniqueID: "T1", Command: "echo other", Marker: "cred-ident-01"})
	if err := s.ValidateMarkers(); err == nil || !strings.Contains(err.Error(), "does not appear") {
		t.Fatalf("err = %v, want the missing-from-command refusal", err)
	}
}

// Two steps in one scenario sharing a marker would make one evidence record match two
// steps. It is refused.
func TestMarker_DuplicateWithinScenarioIsRefused(t *testing.T) {
	s := markerScenario("mk-dup",
		Step{TechniqueID: "T1", Command: "a m-one-0001", Marker: "m-one-0001"},
		Step{TechniqueID: "T2", Command: "b m-one-0001", Marker: "m-one-0001"})
	if err := s.ValidateMarkers(); err == nil || !strings.Contains(err.Error(), "more than one step") {
		t.Fatalf("err = %v, want duplicate refusal", err)
	}
}

// Across scenarios, the first claim keeps the marker. A later scenario that reuses it
// is refused, and the reason names the first owner.
func TestMarker_UniqueAcrossScenarios(t *testing.T) {
	a := markerScenario("mk-a", Step{TechniqueID: "T1", Command: "x shared-tok-01", Marker: "shared-tok-01"})
	b := markerScenario("mk-b", Step{TechniqueID: "T1", Command: "y shared-tok-01", Marker: "shared-tok-01"})
	refused := CheckMarkerUniqueness([]*Scenario{a, b})
	if len(refused) != 1 || refused[0].ID != "mk-b" || !strings.Contains(refused[0].Reason, "mk-a") {
		t.Fatalf("refused = %+v, want mk-b refused naming mk-a", refused)
	}
}
