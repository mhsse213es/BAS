package admatrix

import "testing"

func TestReport_CoversEveryEntryWithAName(t *testing.T) {
	r := Report()
	if len(r.Capabilities) != len(AllEntries()) {
		t.Fatalf("report must cover every matrix entry: %d vs %d", len(r.Capabilities), len(AllEntries()))
	}
	for _, c := range r.Capabilities {
		if c.PrimitiveID == "" || c.Name == "" {
			t.Fatalf("capability missing id/name: %+v", c)
		}
		if c.ValidationLevel == "" || c.CoverageStatus == "" {
			t.Fatalf("capability %s missing status fields", c.PrimitiveID)
		}
		if len(c.Limitations) == 0 {
			t.Fatalf("capability %s must state its limitations honestly", c.PrimitiveID)
		}
	}
}

func TestReport_CoverageStatusDerivedHonestly(t *testing.T) {
	byID := map[string]CapabilityCoverage{}
	for _, c := range Report().Capabilities {
		byID[c.PrimitiveID] = c
	}
	// DCSync has reusable executable content (ART atomic) -> scenario_composable.
	if got := byID["dcsync"].CoverageStatus; got != StatusScenarioComposable {
		t.Fatalf("dcsync should be scenario_composable (reusable ART content), got %q", got)
	}
	// ESC1 is only a synthetic predicate -> modeled, never overclaimed as executed.
	if got := byID["adcs-esc1"].CoverageStatus; got != StatusModeled {
		t.Fatalf("adcs-esc1 should be modeled, got %q", got)
	}
	// Nothing may claim executed/telemetry-observed today.
	for _, c := range Report().Capabilities {
		if c.CoverageStatus == StatusExecuted || c.CoverageStatus == StatusTelemetryObserved {
			t.Fatalf("%s overclaims coverage status %q with no real execution/telemetry", c.PrimitiveID, c.CoverageStatus)
		}
	}
}

func TestReport_SummaryIsMeasurableAndTraceable(t *testing.T) {
	r := Report()
	if r.Summary.Total != len(r.Capabilities) {
		t.Fatalf("summary total %d != capabilities %d", r.Summary.Total, len(r.Capabilities))
	}
	// ByCoverageStatus counts must sum to Total (every capability counted once).
	sum := 0
	for _, n := range r.Summary.ByCoverageStatus {
		sum += n
	}
	if sum != r.Summary.Total {
		t.Fatalf("coverage-status counts %d must sum to total %d", sum, r.Summary.Total)
	}
	if r.Summary.ByValidationLevel["model_simulated"] != r.Summary.Total {
		t.Fatalf("all capabilities must currently be model_simulated: %+v", r.Summary.ByValidationLevel)
	}
	if r.Summary.WithReusableContent != 1 {
		t.Fatalf("expected exactly 1 capability with reusable executable content, got %d", r.Summary.WithReusableContent)
	}
	// Traceability: the status counts must match an independent recount of entries.
	recount := map[CoverageStatus]int{}
	for _, c := range r.Capabilities {
		recount[c.CoverageStatus]++
	}
	for status, n := range recount {
		if r.Summary.ByCoverageStatus[string(status)] != n {
			t.Fatalf("summary count for %q (%d) not traceable to entries (%d)", status, r.Summary.ByCoverageStatus[string(status)], n)
		}
	}
}
