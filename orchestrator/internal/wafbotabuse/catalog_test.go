package wafbotabuse

import "testing"

func TestAudspectWAFBotAbuseCatalog_ReturnsFourVectors(t *testing.T) {
	vectors, err := AudspectWAFBotAbuseCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFBotAbuseCatalog: %v", err)
	}
	if len(vectors) != 4 {
		t.Fatalf("len(vectors) = %d, want 4", len(vectors))
	}
	if err := ValidateBotAbuseCatalog(vectors); err != nil {
		t.Errorf("ValidateBotAbuseCatalog: %v", err)
	}
}

// Review Focus: the catalog must cover all 4 distinct categories, not
// duplicate one and skip another.
func TestAudspectWAFBotAbuseCatalog_CoversAllFourCategories(t *testing.T) {
	vectors, err := AudspectWAFBotAbuseCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFBotAbuseCatalog: %v", err)
	}
	want := []BotAbuseCategory{
		CategoryBoundedAutomation, CategoryRateLimit, CategoryCredentialAbuse, CategoryDistributedEnforcement,
	}
	seen := make(map[BotAbuseCategory]int)
	for _, v := range vectors {
		seen[v.Category]++
	}
	for _, w := range want {
		if seen[w] != 1 {
			t.Errorf("category %q appears %d times in the catalog, want exactly 1", w, seen[w])
		}
	}
}
