package models

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// TestTacticMap_CoversEveryAttackdataTechnique guards against TacticMap
// drifting out of sync with the authoritative MITRE dataset again: any
// parent technique attackdata knows about but TacticMap doesn't resolves to
// "" -> Severity("") defaults to "Medium" -> silently excluded from Key
// Findings (buildTopFindings only includes Critical/High), even on a
// genuine fail. Found 29 such gaps on 2026-08-11; this test would have
// caught them.
func TestTacticMap_CoversEveryAttackdataTechnique(t *testing.T) {
	seen := map[string]bool{}
	var missing []string
	for _, ref := range attackdata.All() {
		base := ref.ID
		if i := strings.IndexByte(base, '.'); i > 0 {
			base = base[:i]
		}
		if seen[base] {
			continue
		}
		seen[base] = true
		if TacticMap[base] == "" {
			missing = append(missing, base)
		}
	}
	if len(missing) > 0 {
		t.Errorf("TacticMap is missing %d technique(s) attackdata knows about: %v", len(missing), missing)
	}
}

// TestLookupTactic_StripsSubtechniqueSuffix locks in existing behavior:
// a sub-technique resolves via its parent's tactic.
func TestLookupTactic_StripsSubtechniqueSuffix(t *testing.T) {
	if got := LookupTactic("T1059.001"); got != "execution" {
		t.Errorf("LookupTactic(T1059.001) = %q, want execution", got)
	}
}

// TestLookupTactic_PreviouslyMissingTechniquesNowResolve spot-checks a few
// of the 29 technique IDs found missing from TacticMap on 2026-08-11,
// confirming they now resolve to the correct authoritative tactic instead
// of silently defaulting to "". Includes both a Critical/High case (proving
// the technique is no longer wrongly excluded from Key Findings) and a
// legitimate Medium case (discovery isn't in either high-severity bucket --
// T1526 correctly resolving to Medium is not itself a bug).
func TestLookupTactic_PreviouslyMissingTechniquesNowResolve(t *testing.T) {
	cases := map[string]struct{ tactic, severity string }{
		"T1556": {"credential-access", "Critical"}, // Modify Authentication Process
		"T1602": {"collection", "High"},            // Data from Configuration Repository
		"T1659": {"command-and-control", "High"},   // Content Injection
		"T1525": {"persistence", "High"},           // Implant Internal Image
		"T1205": {"defense-evasion", "High"},       // Traffic Signaling
		"T1526": {"discovery", "Medium"},           // Cloud Service Discovery -- legitimately Medium
	}
	for id, want := range cases {
		got := LookupTactic(id)
		if got != want.tactic {
			t.Errorf("LookupTactic(%s) = %q, want %q", id, got, want.tactic)
		}
		if sev := Severity(got); sev != want.severity {
			t.Errorf("Severity(LookupTactic(%s)) = %q, want %q", id, sev, want.severity)
		}
	}
}
