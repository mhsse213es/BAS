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
