package reporting

import (
	"bytes"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
)

// TestGenerateHTML_CoverageBreakdownRenders guards a template regression: the
// Coverage Analytics per-tactic table compared numeric fields (.missed,
// .attempted) against an INTEGER literal 0, but those fields arrive as float64
// after the FullReport is JSON round-tripped into the template's data map, and
// Go's text/template refuses to compare float64 with int — a 500 that only
// surfaced once a report actually had detection data (Attempted>0). This builds
// exactly that shape and asserts the report renders without error.
func TestGenerateHTML_CoverageBreakdownRenders(t *testing.T) {
	r := &FullReport{
		Agent: models.Agent{AgentID: "WIN-01", Hostname: "WIN-01"},
		CoverageBreakdown: CoverageBreakdown{
			HasData:           true,
			Attempted:         10,
			Prevented:         3,
			DetectedOnly:      2,
			Missed:            5,
			PreventionRate:    30,
			DetectionCoverage: 50,
			ByTactic: []TacticBreakdown{
				{Tactic: "credential-access", Attempted: 4, Prevented: 1, DetectedOnly: 1, Missed: 2},
				{Tactic: "impact", Attempted: 2, Prevented: 0, DetectedOnly: 1, Missed: 1},
			},
		},
	}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, r, nil); err != nil {
		t.Fatalf("GenerateHTML with coverage breakdown failed: %v", err)
	}
	if !strings.Contains(buf.String(), "<!DOCTYPE html>") {
		t.Error("expected a complete HTML document")
	}
}
