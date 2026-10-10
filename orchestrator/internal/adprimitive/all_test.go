package adprimitive

import "testing"

func TestAll_CoversEveryCatalogWithoutDuplicateIDs(t *testing.T) {
	all := All()
	if len(all) != 28 {
		t.Fatalf("expected 28 primitives across all catalogs, got %d", len(all))
	}
	seen := map[string]bool{}
	for _, p := range all {
		if p.ID == "" {
			t.Fatalf("primitive with empty ID: %+v", p)
		}
		if seen[p.ID] {
			t.Fatalf("duplicate primitive ID %q in All()", p.ID)
		}
		seen[p.ID] = true
	}
}
