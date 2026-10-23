package dbbuild

import (
	"testing"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/scenario"
)

// destructiveProbeAllowlist names probes allowed to sign as ExecutionClass
// destructive. The agent's B5 gate vetoes every destructive step with no
// approval path, so such a probe could never run: adding one here requires a
// conscious B5/approval design decision. Currently empty.
var destructiveProbeAllowlist = map[string]bool{}

func TestNoRegisteredProbeSignsDestructiveWithoutAllowlist(t *testing.T) {
	for _, id := range dbsim.ProbeIDs() {
		e, _ := dbsim.LookupProbeEntry(id)
		if ExpectedExecutionClass(e.Class) == scenario.ClassDestructive && !destructiveProbeAllowlist[id] {
			t.Errorf("probe %q (class %s) signs as destructive; the agent's B5 gate would veto it unconditionally. A conscious B5/approval design decision is required", id, e.Class)
		}
	}
}
