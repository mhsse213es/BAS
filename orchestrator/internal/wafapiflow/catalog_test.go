package wafapiflow

import "testing"

func TestAudspectWAFAPIFlowCatalog_ReturnsFiveVectors(t *testing.T) {
	vectors, err := AudspectWAFAPIFlowCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAPIFlowCatalog: %v", err)
	}
	if len(vectors) != 5 {
		t.Fatalf("len(vectors) = %d, want 5", len(vectors))
	}
	if err := ValidateAPIFlowCatalog(vectors); err != nil {
		t.Errorf("ValidateAPIFlowCatalog: %v", err)
	}
}

// Review Focus: the catalog must cover all 5 distinct categories, not
// duplicate one and skip another.
func TestAudspectWAFAPIFlowCatalog_CoversAllFiveCategories(t *testing.T) {
	vectors, err := AudspectWAFAPIFlowCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAPIFlowCatalog: %v", err)
	}
	want := []APIFlowCategory{
		CategorySchemaConformance, CategoryAuthBoundary, CategorySensitiveWorkflow, CategoryGraphQLAbuse, CategoryResourceControl,
	}
	seen := make(map[APIFlowCategory]int)
	for _, v := range vectors {
		seen[v.Category]++
	}
	for _, w := range want {
		if seen[w] != 1 {
			t.Errorf("category %q appears %d times in the catalog, want exactly 1", w, seen[w])
		}
	}
}
