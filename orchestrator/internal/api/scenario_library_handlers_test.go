package api

import (
	"testing"

	"github.com/audspect/bas/internal/phishcatalog"
)

// Status and reason come from the dependencies the environment actually wires.
func TestPhishingLibraryEntries_StatusFromWiredDependencies(t *testing.T) {
	catalog := []phishcatalog.Scenario{
		{ID: "PH-ID-001", Name: "pool-only"},
		{ID: "PH-DET-002", Name: "needs ITSM"},
		{ID: "PH-CHN-001", Name: "not registered"},
	}
	entries := phishingLibraryEntries(catalog, poolOnly())
	want := map[string][2]string{
		"PH-ID-001":  {CapAvailable, ""},
		"PH-DET-002": {CapUnavailable, reasonITSMConnectorNotConfig},
		"PH-CHN-001": {CapCatalogOnly, reasonNotRegistered},
	}
	for _, e := range entries {
		w := want[e.ID]
		if e.Status != w[0] || e.Reason != w[1] {
			t.Errorf("%s: status=%q reason=%q, want %q/%q", e.ID, e.Status, e.Reason, w[0], w[1])
		}
	}
}

// With no identity client wired, no identity scenario is ever reported runnable,
// and an experimental one stays flagged experimental.
func TestPhishingLibraryEntries_ExperimentalFlagKeptWhenUnavailable(t *testing.T) {
	entries := phishingLibraryEntries([]phishcatalog.Scenario{
		{ID: "PH-ID-004", Name: "experimental", Experimental: true},
	}, poolOnly())
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Status != CapUnavailable || e.Reason != reasonIdentityNotConfigured || !e.Experimental {
		t.Errorf("got status=%q reason=%q experimental=%v, want unavailable/%s/true", e.Status, e.Reason, e.Experimental, reasonIdentityNotConfigured)
	}
}

// On this installation (no identity, calendar, or ITSM client wired) the real
// catalog must never report those scenarios runnable.
func TestPhishingLibraryEntries_RealCatalogNeverOverclaims(t *testing.T) {
	cat, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	unwired := map[string]bool{
		"PH-ID-002": true, "PH-ID-003": true, "PH-ID-004": true, "PH-ID-005": true,
		"PH-CHN-004": true, "PH-DET-002": true,
	}
	for _, e := range phishingLibraryEntries(cat, poolOnly()) {
		// PH-CHN-004 is catalog-only by decision (unregistered), which is also not runnable.
		if unwired[e.ID] && e.Status != CapUnavailable && !(e.ID == "PH-CHN-004" && e.Status == CapCatalogOnly) {
			t.Errorf("%s: status=%q, want unavailable on an installation without its connector", e.ID, e.Status)
		}
		if e.Status == CapAvailable && e.Experimental {
			t.Errorf("%s: experimental must never report as plain available", e.ID)
		}
	}
}

// LiveValidated comes from the catalog's coverage, never from a dependency check.
func TestPhishingLibraryEntries_LiveValidatedFromCoverageOnly(t *testing.T) {
	entries := phishingLibraryEntries([]phishcatalog.Scenario{
		{ID: "PH-ID-001", Name: "pool-only", Coverage: phishcatalog.CoverageLiveValidated},
		{ID: "PH-DET-002", Name: "needs ITSM", Coverage: phishcatalog.CoverageAdapterTested},
	}, poolOnly())
	if !entries[0].LiveValidated || entries[1].LiveValidated {
		t.Errorf("liveValidated = %v/%v, want true/false from coverage", entries[0].LiveValidated, entries[1].LiveValidated)
	}
}
