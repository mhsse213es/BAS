package api

import (
	"testing"

	"github.com/audspect/bas/internal/phishcatalog"
)

// A catalog entry is executable only when the phishing registry runs it.
// Presence in the catalog alone never makes it executable.
func TestPhishingLibraryEntries_TypedAndStatusFromRegistry(t *testing.T) {
	catalog := []phishcatalog.Scenario{
		{ID: "PH-DET-002", Name: "registered"},
		{ID: "PH-CHN-001", Name: "catalog only"},
		{ID: "PH-ID-004", Name: "registered experimental", Experimental: true},
	}
	executable := map[string]bool{"PH-DET-002": true, "PH-ID-004": true}
	entries := phishingLibraryEntries(catalog, func(id string) bool { return executable[id] })

	want := map[string]struct{ typ, status string }{
		"PH-DET-002": {"phishing", "executable"},
		"PH-CHN-001": {"phishing", "available"},
		"PH-ID-004":  {"phishing", "experimental"},
	}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d", len(entries), len(want))
	}
	for _, e := range entries {
		w, ok := want[e.ID]
		if !ok {
			t.Fatalf("unexpected entry %q", e.ID)
		}
		if e.Type != w.typ || e.Status != w.status {
			t.Errorf("%s: type=%q status=%q, want type=%q status=%q", e.ID, e.Type, e.Status, w.typ, w.status)
		}
	}
}

// Nothing that the registry cannot run may be reported as executable or
// experimental, whatever the catalog says.
func TestPhishingLibraryEntries_UnregisteredNeverExecutable(t *testing.T) {
	catalog := []phishcatalog.Scenario{
		{ID: "PH-CHN-004", Name: "x", Experimental: true},
		{ID: "PH-IR-002", Name: "y"},
	}
	for _, e := range phishingLibraryEntries(catalog, func(string) bool { return false }) {
		if e.Status != "available" {
			t.Errorf("%s: status %q, want available: the registry cannot run it", e.ID, e.Status)
		}
	}
}

// The real catalog must mark the two EXPERIMENTAL heuristics. Their status
// must be experimental, not plain executable, when the registry runs them.
func TestPhishingLibraryEntries_RealCatalogExperimentalFlag(t *testing.T) {
	cat, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	entries := phishingLibraryEntries(cat, func(id string) bool {
		_, ok := LookupPhishingRunExecutor(id)
		return ok
	})
	for _, e := range entries {
		if e.ID != "PH-ID-004" && e.ID != "PH-ID-005" {
			continue
		}
		if e.Status != "experimental" {
			t.Errorf("%s: status %q, want experimental", e.ID, e.Status)
		}
	}
}
