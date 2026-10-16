package avcatalog

import "testing"

func TestLabRestrictedVectorIDs_EveryEntryHasANonEmptyReason(t *testing.T) {
	ids := LabRestrictedVectorIDs()
	if len(ids) == 0 {
		t.Fatal("want at least one lab-restricted vector")
	}
	for id, reason := range ids {
		if reason == "" {
			t.Errorf("vector %q has an empty reason", id)
		}
	}
}

// Review Focus: every ID this function names must be a real vector in
// the real catalog -- a stale entry here would silently protect nothing.
func TestLabRestrictedVectorIDs_EveryIDExistsInRealCatalog(t *testing.T) {
	catalog, err := AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	seen := map[string]bool{}
	for _, v := range catalog {
		seen[v.ID] = true
	}
	for id := range LabRestrictedVectorIDs() {
		if !seen[id] {
			t.Errorf("LabRestrictedVectorIDs names %q, but no real catalog vector has that ID -- stale entry", id)
		}
	}
}

func TestLabRestrictedVectorIDs_IncludesAVCONFIG003(t *testing.T) {
	ids := LabRestrictedVectorIDs()
	if _, ok := ids["AV-CONFIG-003"]; !ok {
		t.Fatal("AV-CONFIG-003 must be lab-restricted")
	}
}
