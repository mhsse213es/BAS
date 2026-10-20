package verifysync

import (
	"testing"

	"github.com/audspect/bas/internal/reporting"
)

// TestDeriveDecisionClass_ApprovedTable checks each row of the B1 derivation
// table in docs/superpowers/plans/2026-10-20-dlp-record-schema-change-plan.md.
func TestDeriveDecisionClass_ApprovedTable(t *testing.T) {
	cases := []struct {
		name, expected, collection, observed, want string
	}{
		{"block, sink receipt present -> FN", "Block", "sink-receipt", reporting.ObservationSucceeded, "FN"},
		{"allow, sink receipt present -> TN", "Allow", "sink-receipt", reporting.ObservationSucceeded, "TN"},
		{"block, sink receipt absent -> Inconclusive", "Block", "sink-receipt", reporting.ObservationBlocked, "Inconclusive"},
		{"allow, sink receipt absent -> Inconclusive", "Allow", "sink-receipt", reporting.ObservationBlocked, "Inconclusive"},
		{"block, local marker only -> Inconclusive", "Block", "local-marker", reporting.ObservationBlocked, "Inconclusive"},
		{"allow, local marker only -> Inconclusive", "Allow", "local-marker", reporting.ObservationSucceeded, "Inconclusive"},
		{"block, no observation -> Untested", "Block", "", reporting.ObservationUnknown, "Untested"},
		{"allow, skipped step -> Untested", "Allow", "", reporting.ObservationUnknown, "Untested"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := deriveDecisionClass(c.expected, c.collection, c.observed)
			if got == nil || *got != c.want {
				t.Fatalf("decision_class = %v, want %s", got, c.want)
			}
		})
	}
}

// TestDeriveDecisionClass_UnclassifiedExpectationStaysNull checks expectations
// outside the approved Block/Allow table get no class, rather than a guessed one.
func TestDeriveDecisionClass_UnclassifiedExpectationStaysNull(t *testing.T) {
	for _, expected := range []string{"Warn", "Quarantine", "Encrypt", ""} {
		if got := deriveDecisionClass(expected, "sink-receipt", reporting.ObservationSucceeded); got != nil {
			t.Fatalf("expected %q: decision_class = %q, want NULL", expected, *got)
		}
	}
}

// TestDeriveDecisionClass_NeverTPOrFP is the plan's core invariant: with the
// current evidence model, no combination of inputs can yield a TP or FP, because
// a block is only ever evidenced by a missing sink receipt or a local marker.
func TestDeriveDecisionClass_NeverTPOrFP(t *testing.T) {
	expecteds := []string{"Block", "Allow"}
	collections := []string{"", "sink-receipt", "local-marker"}
	observeds := []string{reporting.ObservationSucceeded, reporting.ObservationBlocked, reporting.ObservationUnknown}
	for _, e := range expecteds {
		for _, c := range collections {
			for _, o := range observeds {
				got := deriveDecisionClass(e, c, o)
				if got == nil {
					t.Fatalf("expected=%s collection=%q observed=%s: unexpectedly NULL", e, c, o)
				}
				if *got == "TP" || *got == "FP" {
					t.Fatalf("expected=%s collection=%q observed=%s produced %s, which the current evidence model cannot support", e, c, o, *got)
				}
			}
		}
	}
}

// TestEvidenceSourceFor maps the collection method to the plan's allowed values.
func TestEvidenceSourceFor(t *testing.T) {
	cases := map[string]string{"sink-receipt": "sink-receipt", "local-marker": "local-marker", "": "none"}
	for in, want := range cases {
		if got := evidenceSourceFor(in); got != want {
			t.Fatalf("evidenceSourceFor(%q) = %q, want %q", in, got, want)
		}
	}
}
