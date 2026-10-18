// Package dlpfixture is a reference/catalog layer centralizing the
// canonical definitions of every synthetic data fixture value already
// embedded in scenarios/dlp-exfiltration-*.yaml -- it does not change
// scenario runtime behavior, YAML content, or signatures (Phase 1 scope
// boundary; see the design spec). Its job is to eliminate inline
// duplication at the knowledge level (one authoritative source instead
// of re-grepping YAML by hand each time, which caused a real Critical
// finding during dlpprofile's own final review) and to catch drift
// between this catalog and the live scenario files via dlpfixture_test's
// semantic drift test.
package dlpfixture

import (
	"fmt"
	"slices"
)

// Occurrence names one real (scenario, step) location where a Fixture's
// Values are expected to appear, verbatim, inside that step's Command
// field -- never a blind whole-file string search.
type Occurrence struct {
	ScenarioID string
	StepName   string
}

// Fixture is one canonical synthetic data value (or closely related
// value set) and every real scenario location it appears in today.
type Fixture struct {
	ID          string
	DataType    string
	Values      []string
	Occurrences []Occurrence
	Note        string
}

// NewFixture validates at construction time, never at render time.
func NewFixture(id string, dataType string, values []string, occurrences []Occurrence, note string) (Fixture, error) {
	if id == "" {
		return Fixture{}, fmt.Errorf("id must not be empty")
	}
	if dataType == "" {
		return Fixture{}, fmt.Errorf("dataType must not be empty")
	}
	if len(values) == 0 {
		return Fixture{}, fmt.Errorf("values must not be empty")
	}
	if slices.Contains(values, "") {
		return Fixture{}, fmt.Errorf("values must not contain an empty string")
	}
	if len(occurrences) == 0 {
		return Fixture{}, fmt.Errorf("occurrences must not be empty")
	}
	seen := make(map[Occurrence]bool, len(occurrences))
	for _, o := range occurrences {
		if o.ScenarioID == "" || o.StepName == "" {
			return Fixture{}, fmt.Errorf("an occurrence has an empty ScenarioID or StepName")
		}
		if seen[o] {
			return Fixture{}, fmt.Errorf("occurrences contains a duplicate (%q, %q)", o.ScenarioID, o.StepName)
		}
		seen[o] = true
	}
	if note == "" {
		return Fixture{}, fmt.Errorf("note must not be empty")
	}
	return Fixture{ID: id, DataType: dataType, Values: values, Occurrences: occurrences, Note: note}, nil
}

// ValidateCatalog rejects a duplicate Fixture.ID and a (ScenarioID,
// StepName) occurrence claimed by more than one Fixture -- two catalog
// entries disagreeing about what one real step actually contains is a
// drift bug in the catalog itself, independent of the real YAML files.
func ValidateCatalog(fixtures []Fixture) error {
	seenID := make(map[string]bool, len(fixtures))
	seenOcc := make(map[Occurrence]string)
	for _, f := range fixtures {
		if seenID[f.ID] {
			return fmt.Errorf("duplicate fixture ID %q", f.ID)
		}
		seenID[f.ID] = true
		for _, o := range f.Occurrences {
			if owner, ok := seenOcc[o]; ok {
				return fmt.Errorf("occurrence (%q, %q) claimed by both fixture %q and %q", o.ScenarioID, o.StepName, owner, f.ID)
			}
			seenOcc[o] = f.ID
		}
	}
	return nil
}
