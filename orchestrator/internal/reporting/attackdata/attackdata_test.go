package attackdata

import "testing"

// The embedded ATT&CK dataset must load and carry authoritative enrichment for a
// well-known technique.
func TestLookupAuthoritative(t *testing.T) {
	e := Lookup("T1003.001")
	if e == nil {
		t.Fatal("T1003.001 not found in embedded dataset")
	}
	if len(e.Groups) == 0 || len(e.Software) == 0 || len(e.Mitigations) == 0 {
		t.Errorf("T1003.001 missing authoritative data: groups=%d software=%d mitig=%d",
			len(e.Groups), len(e.Software), len(e.Mitigations))
	}
	if e.URL == "" {
		t.Error("T1003.001 missing ATT&CK URL")
	}
}

// The curated overlay must merge onto authoritative data and be flagged Curated.
func TestLookupCuratedOverlayMerges(t *testing.T) {
	e := Lookup("T1003.001")
	if e == nil || !e.Curated {
		t.Fatalf("T1003.001 should carry curated overlay (Curated=%v)", e != nil && e.Curated)
	}
	if len(e.CWE) == 0 {
		t.Error("expected curated CWE on T1003.001")
	}
	// Authoritative data must survive the merge.
	if len(e.Groups) == 0 {
		t.Error("authoritative groups lost after overlay merge")
	}
}

// A sub-technique with no record of its own falls back to its parent.
func TestLookupSubtechniqueFallback(t *testing.T) {
	if e := Lookup("T1003.099"); e == nil || e.TechniqueID != "T1003" {
		t.Errorf("T1003.099 should fall back to parent T1003, got %v", e)
	}
}

func TestLookupUnknown(t *testing.T) {
	if e := Lookup("T9999"); e != nil {
		t.Errorf("T9999 should be nil, got %+v", e)
	}
}

// Documentation keys in the overlay must not become enrichment records.
func TestOverlayIgnoresUnderscoreKeys(t *testing.T) {
	if e := Lookup("_README"); e != nil {
		t.Errorf("_README should be ignored, got %+v", e)
	}
}
