package coverage

import (
	"strings"
	"testing"
)

// The known gaps must appear in every report, so an open limit can never drop out of the output silently.
func TestKnownGapsAlwaysPrinted(t *testing.T) {
	out := Format(Report{})
	if !strings.Contains(out, "Known gaps (open; none counted as validated):") {
		t.Fatal("report has no known-gaps section")
	}
	for _, g := range KnownGaps {
		if !strings.Contains(out, g) {
			t.Errorf("known gap missing from the report: %q", g)
		}
	}
	if len(KnownGaps) != 5 {
		t.Errorf("known gaps: %d entries, want the five open gaps", len(KnownGaps))
	}
}
