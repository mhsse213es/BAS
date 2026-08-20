package connector

import (
	"testing"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

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
//
// Uses fictional actor/alias names (not a real MITRE group like "Wizard
// Spider") deliberately -- attack_groups.json now ships real MITRE group
// data (see attackdata's Group doc comment), and a real group name here
// would pull in its own real MITRE-canonical aliases via the separate
// Project 2 bridge, making this test no longer isolated to the OpenCTI-
// alias-only matching layer it exists to pin.
func TestMergeActors_MatchesViaOpenCTIProvidedAlias(t *testing.T) {
	merged := MergeActors([]ThreatActor{
		{Name: "Frostbyte Jackal", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "Umbral Kestrel", Aliases: []string{"Frostbyte Jackal", "Shadow Finch"}, Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	})
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor, got %d: %+v", len(merged), merged)
	}
	if len(merged[0].Techniques) != 2 {
		t.Fatalf("want 2 unioned techniques, got %d: %+v", len(merged[0].Techniques), merged[0].Techniques)
	}
	if merged[0].Name != "Frostbyte Jackal" {
		t.Errorf("Name = %q, want %q (first-arrival wins)", merged[0].Name, "Frostbyte Jackal")
	}
	wantAliases := map[string]bool{"Umbral Kestrel": true, "Shadow Finch": true}
	if len(merged[0].Aliases) != len(wantAliases) {
		t.Fatalf("Aliases = %v, want exactly %v", merged[0].Aliases, wantAliases)
	}
	for _, a := range merged[0].Aliases {
		if !wantAliases[a] {
			t.Errorf("unexpected alias %q in %v", a, merged[0].Aliases)
		}
		if a == "Frostbyte Jackal" {
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
		{Name: "Umbral Kestrel", Aliases: []string{"Frostbyte Jackal", "Shadow Finch"}, Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
		{Name: "Frostbyte Jackal", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
	})
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor regardless of arrival order, got %d: %+v", len(merged), merged)
	}
	if len(merged[0].Techniques) != 2 {
		t.Fatalf("want 2 unioned techniques, got %d: %+v", len(merged[0].Techniques), merged[0].Techniques)
	}
	if merged[0].Name != "Umbral Kestrel" {
		t.Errorf("Name = %q, want %q (first-arrival wins, and OpenCTI's entry arrived first this time)", merged[0].Name, "Umbral Kestrel")
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

// TestMergeActors_BridgesViaCanonicalMITREGroupID_ZeroDirectOverlap is the
// core scenario this project exists for: two actors with NO shared
// name/alias token at all still merge, because MITRE's own data
// independently resolves both to the same canonical group.
func TestMergeActors_BridgesViaCanonicalMITREGroupID_ZeroDirectOverlap(t *testing.T) {
	canonicalIndex := map[string]string{
		"apt29":    "G0016",
		"cozybear": "G0016",
	}
	noGroups := func(string) *attackdata.Group { return nil }
	merged := mergeActorsWithCanonicalData([]ThreatActor{
		{Name: "APT29", Source: "misp", Techniques: []TechniqueRef{{ID: "T1078"}}},
		{Name: "Cozy Bear", Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	}, canonicalIndex, noGroups)
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor (bridged via canonical MITRE group ID, zero direct token overlap), got %d: %+v", len(merged), merged)
	}
	if merged[0].CanonicalGroupID != "G0016" {
		t.Errorf("CanonicalGroupID = %q, want G0016", merged[0].CanonicalGroupID)
	}
	if len(merged[0].Techniques) != 2 {
		t.Fatalf("want 2 unioned techniques, got %d", len(merged[0].Techniques))
	}
}

// TestMergeActors_ActorTokensSpanTwoDistinctMITREGroupsStaysUnresolved
// guards the per-actor ambiguity case: an actor's own name resolves to one
// MITRE group and its own alias resolves to a DIFFERENT one. Never force a
// pick.
func TestMergeActors_ActorTokensSpanTwoDistinctMITREGroupsStaysUnresolved(t *testing.T) {
	canonicalIndex := map[string]string{
		"apt29":  "G0016",
		"sofacy": "G0007",
	}
	noGroups := func(string) *attackdata.Group { return nil }
	merged := mergeActorsWithCanonicalData([]ThreatActor{
		{Name: "APT29", Aliases: []string{"Sofacy"}, Source: "misp", Techniques: []TechniqueRef{{ID: "T1078"}}},
	}, canonicalIndex, noGroups)
	if len(merged) != 1 {
		t.Fatalf("want 1 actor (nothing else to merge with), got %d", len(merged))
	}
	if merged[0].CanonicalGroupID != "" {
		t.Errorf("CanonicalGroupID = %q, want empty -- actor's own tokens span two distinct MITRE groups, must not force one", merged[0].CanonicalGroupID)
	}
}

// TestMergeActors_MergedGroupWithConflictingCanonicalIDsStaysUnresolved
// guards the merged-group ambiguity case: two actors merge via a direct
// alias-token match, but MITRE's own data disagrees about which group they
// belong to. The survivor must not arbitrarily pick one.
func TestMergeActors_MergedGroupWithConflictingCanonicalIDsStaysUnresolved(t *testing.T) {
	canonicalIndex := map[string]string{
		"actora": "G0001",
		"actorb": "G0002",
	}
	noGroups := func(string) *attackdata.Group { return nil }
	merged := mergeActorsWithCanonicalData([]ThreatActor{
		{Name: "Actor A", Aliases: []string{"Shared Alias"}, Source: "misp", Techniques: []TechniqueRef{{ID: "T1001"}}},
		{Name: "Actor B", Aliases: []string{"Shared Alias"}, Source: "opencti", Techniques: []TechniqueRef{{ID: "T1002"}}},
	}, canonicalIndex, noGroups)
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor (direct alias-token overlap on 'Shared Alias'), got %d: %+v", len(merged), merged)
	}
	if merged[0].CanonicalGroupID != "" {
		t.Errorf("CanonicalGroupID = %q, want empty -- members resolved to conflicting MITRE groups, must not force one", merged[0].CanonicalGroupID)
	}
}

// TestMergeActors_ActiveEnrichmentFoldsMITREAliasesIntoSurvivor proves that
// once an actor is canonically resolved, MITRE's own authoritative
// Name+Aliases for that group are folded into the survivor's Aliases too.
func TestMergeActors_ActiveEnrichmentFoldsMITREAliasesIntoSurvivor(t *testing.T) {
	canonicalIndex := map[string]string{"apt29": "G0016"}
	groupsByID := map[string]*attackdata.Group{
		"G0016": {ID: "G0016", Name: "APT29", Aliases: []string{"Cozy Bear", "The Dukes"}},
	}
	lookup := func(id string) *attackdata.Group { return groupsByID[id] }
	merged := mergeActorsWithCanonicalData([]ThreatActor{
		{Name: "APT29", Source: "misp", Techniques: []TechniqueRef{{ID: "T1078"}}},
	}, canonicalIndex, lookup)
	if len(merged) != 1 {
		t.Fatalf("want 1 actor, got %d", len(merged))
	}
	want := map[string]bool{"Cozy Bear": true, "The Dukes": true}
	if len(merged[0].Aliases) != len(want) {
		t.Fatalf("Aliases = %v, want exactly %v (MITRE's authoritative alias set folded in)", merged[0].Aliases, want)
	}
	for _, a := range merged[0].Aliases {
		if !want[a] {
			t.Errorf("unexpected alias %q", a)
		}
	}
}

// TestMergeActors_NoMatchingMITREGroupLeavesCanonicalGroupIDEmpty uses the
// real, public MergeActors -- exercising the actual
// attackdata.GroupCanonicalTokenIndex() against attack_groups.json's real
// MITRE data (regenerated 2026-08-20; this repo shipped it as an empty
// placeholder before that -- this test originally exercised that empty
// state, renamed now that real data exists). Fictional actor/alias names
// guarantee no entry in the real MITRE catalog, so this still confirms
// Project 1's alias-token matching is unaffected when nothing resolves --
// same invariant, now proven against real data instead of an empty file.
func TestMergeActors_NoMatchingMITREGroupLeavesCanonicalGroupIDEmpty(t *testing.T) {
	merged := MergeActors([]ThreatActor{
		{Name: "Obsidian Marmot", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "Velvet Tumbleweed", Aliases: []string{"Obsidian Marmot"}, Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	})
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor (Project 1 alias-token matching unaffected), got %d", len(merged))
	}
	if merged[0].CanonicalGroupID != "" {
		t.Errorf("CanonicalGroupID = %q, want empty (fictional actor has no real MITRE group match)", merged[0].CanonicalGroupID)
	}
}

// TestMergeActorsWithProvenance_GroupsMapBackToRawIndices is the core
// contract this whole project rests on: for each merged survivor, we must
// be able to recover exactly which raw input actors (and therefore which
// sources) collapsed into it. groups[i] is index-aligned with merged[i].
func TestMergeActorsWithProvenance_GroupsMapBackToRawIndices(t *testing.T) {
	raw := []ThreatActor{
		{Name: "Wizard Spider", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "Sangria Tempest", Aliases: []string{"Wizard Spider"}, Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	}
	merged, groups := MergeActorsWithProvenance(raw)
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor, got %d: %+v", len(merged), merged)
	}
	if len(groups) != len(merged) {
		t.Fatalf("groups len %d != merged len %d -- must be index-aligned", len(groups), len(merged))
	}
	if len(groups[0]) != 2 {
		t.Fatalf("groups[0] = %v, want both raw indices [0 1]", groups[0])
	}
	seen := map[int]bool{}
	for _, idx := range groups[0] {
		seen[idx] = true
	}
	if !seen[0] || !seen[1] {
		t.Errorf("groups[0] = %v, want it to contain both 0 and 1", groups[0])
	}
	// The survivor must be the first-arriving member of its own group.
	if merged[0].Name != raw[groups[0][0]].Name {
		t.Errorf("merged[0].Name = %q, want it to match raw[groups[0][0]].Name = %q", merged[0].Name, raw[groups[0][0]].Name)
	}
}

// TestMergeActorsWithProvenance_UnrelatedActorsEachGetOwnGroup proves the
// single-source case: two actors that share nothing produce two merged
// actors, each with a one-element group pointing at its own raw index.
func TestMergeActorsWithProvenance_UnrelatedActorsEachGetOwnGroup(t *testing.T) {
	raw := []ThreatActor{
		{Name: "APT28", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "APT29", Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	}
	merged, groups := MergeActorsWithProvenance(raw)
	if len(merged) != 2 || len(groups) != 2 {
		t.Fatalf("merged=%d groups=%d, want 2 and 2", len(merged), len(groups))
	}
	for i := range merged {
		if len(groups[i]) != 1 {
			t.Fatalf("groups[%d] = %v, want exactly one raw index", i, groups[i])
		}
		if merged[i].Name != raw[groups[i][0]].Name {
			t.Errorf("merged[%d].Name = %q, want %q", i, merged[i].Name, raw[groups[i][0]].Name)
		}
	}
}

func TestMergeActorsWithProvenance_EmptyInput(t *testing.T) {
	merged, groups := MergeActorsWithProvenance(nil)
	if merged != nil || groups != nil {
		t.Fatalf("merged=%v groups=%v, want nil/nil for empty input", merged, groups)
	}
}

// TestMergeActorsWithCanonicalDataAndProvenance_CanonicalBridgeGroupsBothRawActors
// covers the case the embedded (currently empty) MITRE dataset can't
// exercise: two actors with ZERO direct token overlap, bridged only by both
// resolving to the same canonical G####, must still land in one group with
// both raw indices recoverable.
func TestMergeActorsWithCanonicalDataAndProvenance_CanonicalBridgeGroupsBothRawActors(t *testing.T) {
	canonicalIndex := map[string]string{"apt29": "G0016", "cozybear": "G0016"}
	noGroups := func(string) *attackdata.Group { return nil }
	raw := []ThreatActor{
		{Name: "APT29", Source: "misp", Techniques: []TechniqueRef{{ID: "T1078"}}},
		{Name: "Cozy Bear", Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	}
	merged, groups := mergeActorsWithCanonicalDataAndProvenance(raw, canonicalIndex, noGroups)
	if len(merged) != 1 || len(groups) != 1 {
		t.Fatalf("merged=%d groups=%d, want 1 and 1", len(merged), len(groups))
	}
	if len(groups[0]) != 2 {
		t.Fatalf("groups[0] = %v, want both raw indices", groups[0])
	}
	if merged[0].CanonicalGroupID != "G0016" {
		t.Errorf("CanonicalGroupID = %q, want G0016", merged[0].CanonicalGroupID)
	}
}
