package connector

import "testing"

// TestMergeActors_UnionsTechniques is the original, pure-name-match
// regression case (moved from scheduler_test.go, unchanged) -- proves
// today's exact-name-match behavior still works once aliases are also
// considered.
func TestMergeActors_UnionsTechniques(t *testing.T) {
	// Layering: same actor from the bundle floor and a live overlay → the
	// techniques are unioned, which is what makes bundle+live compose for free.
	merged := MergeActors([]ThreatActor{
		{Name: "APT36", Source: "bundle", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "APT36", Source: "misp", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	})
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor, got %d", len(merged))
	}
	if len(merged[0].Techniques) != 2 {
		t.Fatalf("want 2 unioned techniques, got %d: %+v", len(merged[0].Techniques), merged[0].Techniques)
	}
}

// TestMergeActors_MatchesViaOpenCTIProvidedAlias is the exact scenario this
// plan exists for: a MISP-style bare-named actor and an OpenCTI-style actor
// whose Aliases field lists that same name. Today's name-only matcher would
// keep these as two separate actors; the alias-aware matcher must merge
// them into one.
func TestMergeActors_MatchesViaOpenCTIProvidedAlias(t *testing.T) {
	merged := MergeActors([]ThreatActor{
		{Name: "Wizard Spider", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "Sangria Tempest", Aliases: []string{"Wizard Spider", "UNC1878"}, Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	})
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor, got %d: %+v", len(merged), merged)
	}
	if len(merged[0].Techniques) != 2 {
		t.Fatalf("want 2 unioned techniques, got %d: %+v", len(merged[0].Techniques), merged[0].Techniques)
	}
	if merged[0].Name != "Wizard Spider" {
		t.Errorf("Name = %q, want %q (first-arrival wins)", merged[0].Name, "Wizard Spider")
	}
	wantAliases := map[string]bool{"Sangria Tempest": true, "UNC1878": true}
	if len(merged[0].Aliases) != len(wantAliases) {
		t.Fatalf("Aliases = %v, want exactly %v", merged[0].Aliases, wantAliases)
	}
	for _, a := range merged[0].Aliases {
		if !wantAliases[a] {
			t.Errorf("unexpected alias %q in %v", a, merged[0].Aliases)
		}
		if a == "Wizard Spider" {
			t.Error("survivor's own name must not appear in its own Aliases")
		}
	}
}

// TestMergeActors_MatchesViaAlias_OrderIndependent is the same pair as
// above with arrival order reversed -- the merge must still happen, and
// whichever actor arrives first still wins the surviving Name (first-
// arrival-wins is unchanged; only the matching itself is new).
func TestMergeActors_MatchesViaAlias_OrderIndependent(t *testing.T) {
	merged := MergeActors([]ThreatActor{
		{Name: "Sangria Tempest", Aliases: []string{"Wizard Spider", "UNC1878"}, Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
		{Name: "Wizard Spider", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
	})
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor regardless of arrival order, got %d: %+v", len(merged), merged)
	}
	if len(merged[0].Techniques) != 2 {
		t.Fatalf("want 2 unioned techniques, got %d: %+v", len(merged[0].Techniques), merged[0].Techniques)
	}
	if merged[0].Name != "Sangria Tempest" {
		t.Errorf("Name = %q, want %q (first-arrival wins, and OpenCTI's entry arrived first this time)", merged[0].Name, "Sangria Tempest")
	}
}

// TestMergeActors_CaseAndPunctuationVariantsMatch proves the alias matcher
// reuses the exact same normalization actorKey has always used (lowercase,
// strip spaces and hyphens) -- no new normalization rules introduced.
func TestMergeActors_CaseAndPunctuationVariantsMatch(t *testing.T) {
	merged := MergeActors([]ThreatActor{
		{Name: "WIZARD-SPIDER", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "wizardspider", Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	})
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor (same normalized token), got %d: %+v", len(merged), merged)
	}
	if len(merged[0].Techniques) != 2 {
		t.Fatalf("want 2 unioned techniques, got %d", len(merged[0].Techniques))
	}
}

// TestMergeActors_MultipleAliasesOnlyOneOverlapping proves a match is found
// even when only one of several aliases overlaps -- the matcher must check
// every token, not just the first alias.
func TestMergeActors_MultipleAliasesOnlyOneOverlapping(t *testing.T) {
	merged := MergeActors([]ThreatActor{
		{Name: "FIN7", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{
			Name:       "Carbon Spider",
			Aliases:    []string{"Sangria Tempest", "FIN7", "ELBRUS"},
			Source:     "opencti",
			Techniques: []TechniqueRef{{ID: "T1566.001"}},
		},
	})
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor (FIN7 alias overlaps), got %d: %+v", len(merged), merged)
	}
	if len(merged[0].Techniques) != 2 {
		t.Fatalf("want 2 unioned techniques, got %d", len(merged[0].Techniques))
	}
}

// TestMergeActors_TransitiveAliasChainMergesAllThree locks in the
// transitive-chaining behavior as intentional: actor X's alias matches
// actor Y's name, and actor Y's alias matches actor Z's name, even though X
// and Z share no token directly.
func TestMergeActors_TransitiveAliasChainMergesAllThree(t *testing.T) {
	merged := MergeActors([]ThreatActor{
		{Name: "Actor X", Aliases: []string{"Actor Y"}, Source: "misp", Techniques: []TechniqueRef{{ID: "T1001"}}},
		{Name: "Actor Y", Aliases: []string{"Actor Z"}, Source: "opencti", Techniques: []TechniqueRef{{ID: "T1002"}}},
		{Name: "Actor Z", Source: "otx", Techniques: []TechniqueRef{{ID: "T1003"}}},
	})
	if len(merged) != 1 {
		t.Fatalf("want all 3 actors to merge transitively (X-Y-Z chained by shared aliases), got %d groups: %+v", len(merged), merged)
	}
	if len(merged[0].Techniques) != 3 {
		t.Fatalf("want 3 unioned techniques, got %d: %+v", len(merged[0].Techniques), merged[0].Techniques)
	}
}

// TestMergeActors_SimilarButDistinctNamesDoNotMerge guards against any
// accidental fuzzy-matching regression -- these names are close but not
// equal after normalization, and must never merge.
func TestMergeActors_SimilarButDistinctNamesDoNotMerge(t *testing.T) {
	merged := MergeActors([]ThreatActor{
		{Name: "APT28", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "APT29", Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	})
	if len(merged) != 2 {
		t.Fatalf("want 2 distinct actors (no fuzzy matching), got %d: %+v", len(merged), merged)
	}
}
