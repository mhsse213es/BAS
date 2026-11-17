package main

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

// execclass classifies by action key; make sure none of the generated steps is
// classified destructive (the scenario is read-only).
func TestGeneratedStepsNotClassifiedDestructive(t *testing.T) {
	sc, err := scenario.ParseYAML(gen(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sc.Steps {
		if !s.ProductionSafe {
			t.Errorf("%s: production_safe must be true", s.Name)
		}
	}
}
