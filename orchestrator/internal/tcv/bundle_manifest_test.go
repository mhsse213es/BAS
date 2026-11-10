package tcv

import (
	"testing"
	"time"
)

func testManifest() BundleManifest {
	return BundleManifest{
		Schema:     1,
		BundleID:   "bundle-2026.11.10",
		PackagedAt: time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC),
		Entries: []BundleEntry{
			{Path: "scenarios/a.yaml", SHA256: "aaaa"},
			{Path: "scenarios/b.yaml", SHA256: "bbbb"},
			{Path: "scenarios/c.yaml", SHA256: "cccc"}, // not in the registry
		},
	}
}

func TestBundlePackagedEvents_OneEventPerMatchedEntry(t *testing.T) {
	m := testManifest()
	versions := map[string]string{"aaaa": "cv-a", "bbbb": "cv-b"}

	events, _ := BundlePackagedEvents(m, versions)

	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	e := events[0]
	if e.Type != EventBundlePackaged {
		t.Errorf("Type = %q, want bundle_packaged", e.Type)
	}
	if e.ContentVersionID != "cv-a" {
		t.Errorf("ContentVersionID = %q, want cv-a", e.ContentVersionID)
	}
	if !e.EventTime.Equal(m.PackagedAt) {
		t.Errorf("EventTime = %v, want packaged_at %v", e.EventTime, m.PackagedAt)
	}
	if e.SourceTable != "bundle_manifest" {
		t.Errorf("SourceTable = %q, want bundle_manifest", e.SourceTable)
	}
	if want := "bundle-2026.11.10/aaaa"; e.SourcePK != want {
		t.Errorf("SourcePK = %q, want %q", e.SourcePK, want)
	}
	if got := e.Payload["path"]; got != "scenarios/a.yaml" {
		t.Errorf("payload path = %v, want scenarios/a.yaml", got)
	}
}

func TestBundlePackagedEvents_UnmatchedHashesAreReturnedNotDropped(t *testing.T) {
	m := testManifest()
	versions := map[string]string{"aaaa": "cv-a", "bbbb": "cv-b"}

	_, unmatched := BundlePackagedEvents(m, versions)

	if len(unmatched) != 1 || unmatched[0] != "cccc" {
		t.Errorf("unmatched = %v, want [cccc]", unmatched)
	}
}

func TestBundlePackagedEvents_DuplicateHashYieldsOneEvent(t *testing.T) {
	m := testManifest()
	m.Entries = append(m.Entries, BundleEntry{Path: "scenarios/a-copy.yaml", SHA256: "aaaa"})
	versions := map[string]string{"aaaa": "cv-a"}

	events, _ := BundlePackagedEvents(m, versions)

	if len(events) != 1 {
		t.Fatalf("events = %d, want 1 (identical bytes must not double-count)", len(events))
	}
	if events[0].Payload["path"] != "scenarios/a.yaml" {
		t.Errorf("first path must win, got %v", events[0].Payload["path"])
	}
}

func TestValidateBundleManifest_RejectsBadInput(t *testing.T) {
	cases := map[string]func(*BundleManifest){
		"unknown schema":   func(m *BundleManifest) { m.Schema = 2 },
		"zero packaged_at": func(m *BundleManifest) { m.PackagedAt = time.Time{} },
		"empty bundle_id":  func(m *BundleManifest) { m.BundleID = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := testManifest()
			mutate(&m)
			if err := m.Validate(); err == nil {
				t.Errorf("Validate() = nil, want error for %s", name)
			}
		})
	}
	if err := testManifest().Validate(); err != nil {
		t.Errorf("valid manifest rejected: %v", err)
	}
}
