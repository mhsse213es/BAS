# Alias-Aware Actor Merge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `MergeActors` (in `orchestrator/internal/connector`) treat two fetched threat actors as the same identity when any of their normalized name/alias tokens match exactly, not just their primary names — using alias data connectors already fetch (OpenCTI) but the matcher currently ignores.

**Architecture:** A union-find (disjoint-set) over each actor's normalized identity tokens (`{name} ∪ {aliases}`), exact string match only, transitive by construction. Lives in a new file, `actor_merge.go`, replacing the current single-key-map implementation in `scheduler.go`. The merge policy for the surviving record is extended so `Aliases` gets unioned across a merged group (folding in every merged member's own `Name` as an alias on the survivor); every other field keeps today's first-arrival-wins / union / max behavior unchanged.

**Tech Stack:** Go, standard library only (`strings`), plain `testing.T` (no DB, no HTTP — `MergeActors` is a pure in-memory function over `[]ThreatActor`).

## Global Constraints

- Exact-match only. No fuzzy/similarity matching anywhere in this plan — every match is normalized-string equality (`actorKey`'s existing normalization: lowercase, strip spaces and hyphens), copied verbatim from today's behavior.
- Transitive matching (A↔B via a shared token, B↔C via a different shared token ⇒ A/B/C merge) is intentional and must be covered by an explicit test, not left as an untested side effect.
- `MergeActors`' exported signature (`func MergeActors(actors []ThreatActor) []ThreatActor`) does not change — callers in `scheduler.go` and `build_bundle.go` need no changes.
- No changes to `upsertActorProfiles`, the `threat_actor_profiles` table, or any cross-sync-cycle persistence behavior — this plan is scoped to in-memory matching within one sync cycle's already-fetched actor list, per the spec's Non-goals.
- No changes to the Project 2 (canonical MITRE Group-ID) scope — not part of this plan.

---

### Task 1: Alias-aware `MergeActors` in a new `actor_merge.go`

**Files:**
- Create: `orchestrator/internal/connector/actor_merge.go`
- Create: `orchestrator/internal/connector/actor_merge_test.go`
- Modify: `orchestrator/internal/connector/scheduler.go:315-338` (delete `MergeActors` and `actorKey`, defined nowhere else in the file after this change)
- Modify: `orchestrator/internal/connector/scheduler_test.go:111-124` (delete `TestMergeActors_UnionsTechniques` — moves to `actor_merge_test.go`)

**Interfaces:**
- Consumes: `ThreatActor` (`internal/connector/types.go:10-21`, fields used: `Name`, `Aliases`, `Techniques`, `LastSeen`; other fields — `Description`, `Sectors`, `Regions`, `Source`, `SourceID`, `Confidence` — are carried through untouched from whichever actor arrived first in a merged group). `TechniqueRef` (same file). `mergeTechniques(a, b []TechniqueRef) []TechniqueRef` (`internal/connector/misp.go:400-402`, dedupes by `TechniqueRef.ID`) — called as-is, no changes.
- Produces: `func MergeActors(actors []ThreatActor) []ThreatActor` — same signature as today, used by `scheduler.go:233` and `build_bundle.go:35`, both unchanged by this plan since the function moves file but not package or signature. `func actorKey(name string) string` — same signature as today, still package-private, still only referenced within `actor_merge.go` after this move (verified: `actorKey` has no callers outside `scheduler.go` today, so moving it has no other blast radius).

This is one task, not split further: the matching-algorithm change and the `Aliases` merge-policy extension are not independently reviewable — "matches via aliases but doesn't record the alias data on the merged result" isn't a coherent partial state, so both land together in one commit after all tests pass.

- [ ] **Step 1: Write the new test file with all alias-matching cases, and move the existing test into it**

Create `orchestrator/internal/connector/actor_merge_test.go`:

```go
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
```

Delete `TestMergeActors_UnionsTechniques` from `orchestrator/internal/connector/scheduler_test.go:111-124` (it now lives in `actor_merge_test.go` above — leaving it in both files is a duplicate-symbol compile error in the same package). Nothing else in `scheduler_test.go` references `MergeActors` or `actorKey` directly (confirmed this session via `grep -n "MergeActors\(|actorKey\("` across the package — the only other call sites are `scheduler.go:233` and `build_bundle.go:35`, both call sites, not definitions), so no other test in that file is affected by this deletion.

- [ ] **Step 2: Run the new tests and confirm the alias-matching cases fail against today's implementation**

`MergeActors`/`actorKey` still live in `scheduler.go` at this point (untouched) — the new test file just exercises them.

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestMergeActors' -v`

Expected: `TestMergeActors_UnionsTechniques` PASSes (today's name-only matcher already handles this case). `TestMergeActors_MatchesViaOpenCTIProvidedAlias`, `TestMergeActors_MatchesViaAlias_OrderIndependent`, `TestMergeActors_MultipleAliasesOnlyOneOverlapping`, and `TestMergeActors_TransitiveAliasChainMergesAllThree` all FAIL (each expects `len(merged) == 1` but today's matcher, which never looks at `Aliases`, returns 2 or 3 separate actors instead). `TestMergeActors_CaseAndPunctuationVariantsMatch` and `TestMergeActors_SimilarButDistinctNamesDoNotMerge` PASS already (today's `actorKey` normalization already handles case/punctuation on primary names, and distinct primary names already don't collide) — that's fine, they're regression coverage for behavior that isn't changing, not new-behavior proof.

- [ ] **Step 3: Implement the alias-aware matcher and merge-policy extension in `actor_merge.go`, removing the old implementation from `scheduler.go`**

Create `orchestrator/internal/connector/actor_merge.go`:

```go
package connector

import "strings"

// MergeActors deduplicates actors fetched from multiple sources within one
// sync cycle. Two actors are treated as the same identity if any of their
// normalized name/alias tokens match exactly -- primary name against
// primary name, primary name against alias, or alias against alias. This is
// transitive: if actor A shares a token with actor B, and actor B shares a
// different token with actor C, then A, B, and C all merge into one group,
// even if A and C share no token directly. Matching is exact-string-equality
// only on normalized tokens -- no fuzzy/similarity matching. See
// docs/superpowers/specs/2026-08-11-alias-aware-actor-merge-design.md.
func MergeActors(actors []ThreatActor) []ThreatActor {
	if len(actors) == 0 {
		return nil
	}

	uf := newTokenUnionFind()
	tokensByActor := make([][]string, len(actors))
	for i, a := range actors {
		toks := actorTokens(a)
		tokensByActor[i] = toks
		for j := 1; j < len(toks); j++ {
			uf.union(toks[0], toks[j])
		}
	}

	groupOf := make(map[string]int) // union-find root token -> index into groups
	var groups [][]int              // groups[g] = indices into actors, in original arrival order
	for i := range actors {
		root := uf.find(tokensByActor[i][0])
		g, ok := groupOf[root]
		if !ok {
			g = len(groups)
			groupOf[root] = g
			groups = append(groups, nil)
		}
		groups[g] = append(groups[g], i)
	}

	out := make([]ThreatActor, 0, len(groups))
	for _, idxs := range groups {
		out = append(out, mergeActorGroup(actors, idxs))
	}
	return out
}

// actorTokens returns an actor's normalized identity tokens: its own name
// first, followed by each of its aliases. The name is always index 0 so
// callers can rely on tokens[0] as "this actor's own primary key" when
// registering it in the union-find.
func actorTokens(a ThreatActor) []string {
	toks := make([]string, 0, 1+len(a.Aliases))
	toks = append(toks, actorKey(a.Name))
	for _, alias := range a.Aliases {
		toks = append(toks, actorKey(alias))
	}
	return toks
}

func actorKey(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, " ", ""), "-", ""))
}

// mergeActorGroup combines every actor at the given indices (already
// identified as the same real-world actor by MergeActors) into one
// ThreatActor. idxs[0] -- the actor that arrived first in the original
// input order -- seeds Name/Description/Sectors/Regions/Source/SourceID/
// Confidence: first-arrival wins for those fields, unchanged from
// MergeActors' behavior before alias matching existed. Techniques are
// unioned and LastSeen takes the max, also unchanged. Aliases is new:
// every other member's own Aliases AND its Name are folded into the
// survivor's Aliases, deduplicated by normalized token, excluding anything
// that normalizes to the survivor's own Name.
func mergeActorGroup(actors []ThreatActor, idxs []int) ThreatActor {
	survivor := actors[idxs[0]]
	survivorKey := actorKey(survivor.Name)

	seenAliasTokens := make(map[string]bool, len(survivor.Aliases))
	mergedAliases := make([]string, 0, len(survivor.Aliases))
	for _, alias := range survivor.Aliases {
		key := actorKey(alias)
		if key == survivorKey || seenAliasTokens[key] {
			continue
		}
		seenAliasTokens[key] = true
		mergedAliases = append(mergedAliases, alias)
	}

	for _, i := range idxs[1:] {
		member := actors[i]
		survivor.Techniques = mergeTechniques(survivor.Techniques, member.Techniques)
		if member.LastSeen.After(survivor.LastSeen) {
			survivor.LastSeen = member.LastSeen
		}

		candidates := make([]string, 0, 1+len(member.Aliases))
		candidates = append(candidates, member.Name)
		candidates = append(candidates, member.Aliases...)
		for _, candidate := range candidates {
			key := actorKey(candidate)
			if key == survivorKey || seenAliasTokens[key] {
				continue
			}
			seenAliasTokens[key] = true
			mergedAliases = append(mergedAliases, candidate)
		}
	}

	survivor.Aliases = mergedAliases
	return survivor
}

// tokenUnionFind is a simple disjoint-set over normalized identity tokens,
// used to group actors that share at least one name/alias token,
// transitively. Path compression keeps repeated find() calls cheap; no
// union-by-rank is needed at the actor-list sizes this runs over (dozens to
// a few hundred actors per sync, not millions).
type tokenUnionFind struct {
	parent map[string]string
}

func newTokenUnionFind() *tokenUnionFind {
	return &tokenUnionFind{parent: make(map[string]string)}
}

func (u *tokenUnionFind) find(token string) string {
	root, ok := u.parent[token]
	if !ok {
		u.parent[token] = token
		return token
	}
	if root == token {
		return token
	}
	root = u.find(root)
	u.parent[token] = root
	return root
}

func (u *tokenUnionFind) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[ra] = rb
	}
}
```

Now remove the old implementation from `orchestrator/internal/connector/scheduler.go:315-338` — delete this entire block (both functions, verbatim as it exists today):

```go
func MergeActors(actors []ThreatActor) []ThreatActor {
	byName := make(map[string]*ThreatActor)
	for _, a := range actors {
		key := actorKey(a.Name)
		if existing, ok := byName[key]; ok {
			existing.Techniques = mergeTechniques(existing.Techniques, a.Techniques)
			if a.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = a.LastSeen
			}
		} else {
			cp := a
			byName[key] = &cp
		}
	}
	out := make([]ThreatActor, 0, len(byName))
	for _, a := range byName {
		out = append(out, *a)
	}
	return out
}

func actorKey(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, " ", ""), "-", ""))
}
```

After deleting this block, check whether `scheduler.go` still uses the `strings` package anywhere else in the file (it very likely does, for other unrelated code) — if `go build` reports `"strings" imported and not used`, remove the now-unused import; otherwise leave `scheduler.go`'s imports untouched.

- [ ] **Step 4: Run the full connector package test suite and confirm everything passes**

Run: `cd orchestrator && go build ./... && go vet ./internal/connector/... && go test ./internal/connector/... -v -run 'TestMergeActors'`

Expected: `go build` succeeds (confirms `scheduler.go` still compiles after the deletion, and no other file in the package referenced `actorKey` or the old `MergeActors` body directly). All 8 tests in `actor_merge_test.go` PASS.

Then run the full package suite to catch any other regression (this package has container-backed tests too, per this session's earlier runs):

Run: `cd orchestrator && go test ./internal/connector/... -v 2>&1 | tail -60`

Expected: `PASS` overall, `ok github.com/audspect/bas/internal/connector`.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/connector/actor_merge.go internal/connector/actor_merge_test.go internal/connector/scheduler.go internal/connector/scheduler_test.go
git commit -m "$(cat <<'EOF'
fix(connector): match actors on aliases, not just primary name

MergeActors only compared normalized primary names, even though
OpenCTI already supplies each actor's Aliases and the field is
already persisted -- a MISP actor named "Wizard Spider" and an
OpenCTI actor named "Sangria Tempest" (aliased to "Wizard Spider")
survived as two separate profiles instead of one.

Replaces the single-key-map matcher with a union-find over each
actor's normalized name+alias token set, exact-match only, moved to
its own file. Merged actors now also carry each other's names/aliases
forward on the surviving record.

See docs/superpowers/specs/2026-08-11-alias-aware-actor-merge-design.md.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

## Self-Review Notes

- **Spec coverage:** Matching algorithm (union-find, exact-match, transitive) — Task 1 Step 3. `Aliases` merge-policy extension — same step, `mergeActorGroup`. All 7 spec test cases — Task 1 Step 1, one test function each (case/punctuation variant and no-aliases-regression confirmed to already pass pre-implementation, since they exercise behavior `actorKey` already had; this is called out explicitly in Step 2 rather than silently treated as "new"). File-structure move to `actor_merge.go` — Task 1 Steps 1 & 3. Non-goals (no fuzzy matching, no cross-cycle persistence change, no Project 2 scope) — nothing in this plan touches `upsertActorProfiles`, the DB schema, or any MITRE dataset; confirmed no task references them.
- **Placeholder scan:** No TBD/TODO markers; every step has literal, runnable code and exact commands.
- **Type consistency:** `MergeActors(actors []ThreatActor) []ThreatActor` matches its only two call sites (`scheduler.go:233`, `build_bundle.go:35}`) — signature unchanged throughout. `actorKey(name string) string` likewise unchanged. `mergeActorGroup(actors []ThreatActor, idxs []int) ThreatActor` and `tokenUnionFind` are new, used consistently within the single new file, not referenced elsewhere.
