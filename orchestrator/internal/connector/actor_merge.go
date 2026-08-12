package connector

import (
	"log"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// MergeActors deduplicates actors fetched from multiple sources within one
// sync cycle. Two actors are treated as the same identity if any of their
// normalized name/alias tokens match exactly -- primary name against
// primary name, primary name against alias, or alias against alias -- or if
// MITRE's own authoritative Group-ID dataset independently resolves both to
// the same canonical ATT&CK group, even with zero direct token overlap
// between them. This is transitive by construction: if actor A shares a
// token (direct or canonical) with actor B, and actor B shares a different
// token with actor C, then A, B, and C all merge into one group. Matching
// is exact-string-equality only on normalized tokens -- no fuzzy/similarity
// matching, anywhere. See
// docs/superpowers/specs/2026-08-11-alias-aware-actor-merge-design.md and
// docs/superpowers/specs/2026-08-11-canonical-mitre-actor-identity-design.md.
func MergeActors(actors []ThreatActor) []ThreatActor {
	merged, _ := MergeActorsWithProvenance(actors)
	return merged
}

// MergeActorsWithProvenance is MergeActors plus the provenance grouping it
// otherwise discards: groups[i] holds the indices into the input actors
// slice that merged into merged[i], index-aligned by construction. Callers
// that only need the merged result use MergeActors; Scheduler.sync uses
// this to persist each source's own pre-merge record (see
// upsertActorSources and
// docs/superpowers/specs/2026-08-11-source-provenance-design.md).
func MergeActorsWithProvenance(actors []ThreatActor) ([]ThreatActor, [][]int) {
	return mergeActorsWithCanonicalDataAndProvenance(actors, attackdata.GroupCanonicalTokenIndex(), attackdata.GroupByID)
}

// mergeActorsWithCanonicalData is MergeActors' testable core -- the
// canonical-MITRE-data sources are passed in explicitly so tests can
// exercise the resolution/merge/enrichment logic against small fixture
// data without depending on the embedded MITRE dataset (which, in this
// repo, ships empty until someone runs the gen tool against a real STIX
// bundle -- see internal/reporting/attackdata/attack_groups.json).
func mergeActorsWithCanonicalData(actors []ThreatActor, canonicalIndex map[string]string, groupByID func(string) *attackdata.Group) []ThreatActor {
	merged, _ := mergeActorsWithCanonicalDataAndProvenance(actors, canonicalIndex, groupByID)
	return merged
}

// mergeActorsWithCanonicalDataAndProvenance is the real core: identical
// matching/merge/enrichment logic as before, but it also returns the
// union-find grouping it already computes internally. groups[i] lists the
// input indices that produced merged[i].
func mergeActorsWithCanonicalDataAndProvenance(actors []ThreatActor, canonicalIndex map[string]string, groupByID func(string) *attackdata.Group) ([]ThreatActor, [][]int) {
	if len(actors) == 0 {
		return nil, nil
	}

	uf := newTokenUnionFind()
	tokensByActor := make([][]string, len(actors))
	canonicalByActor := make([]string, len(actors)) // resolved G#### per actor, "" if unresolved
	for i, a := range actors {
		toks := actorTokens(a)
		canonicalByActor[i] = resolveCanonicalGroupID(toks, canonicalIndex)
		if canonicalByActor[i] != "" {
			// A synthetic token, namespaced so it can never collide with a
			// real name/alias token. Sharing it is what lets two actors
			// merge purely on MITRE's say-so, even with no direct token
			// overlap between their own fetched data.
			toks = append(toks, "canonical:"+canonicalByActor[i])
		}
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
		out = append(out, mergeActorGroup(actors, idxs, canonicalByActor, groupByID))
	}
	return out, groups
}

// resolveCanonicalGroupID checks an actor's own normalized tokens against
// MITRE's canonical index. Exactly one distinct G#### match resolves; zero
// or more than one both resolve to "" (unresolved) -- ambiguity must never
// force an identity.
func resolveCanonicalGroupID(tokens []string, canonicalIndex map[string]string) string {
	matched := map[string]bool{}
	for _, tok := range tokens {
		if id, ok := canonicalIndex[tok]; ok {
			matched[id] = true
		}
	}
	if len(matched) != 1 {
		return ""
	}
	for id := range matched {
		return id
	}
	return ""
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
// identified as the same real-world actor by mergeActorsWithCanonicalData)
// into one ThreatActor. idxs[0] -- the actor that arrived first in the
// original input order -- seeds Name/Description/Sectors/Regions/Source/
// SourceID/Confidence: first-arrival wins for those fields. Techniques are
// unioned and LastSeen takes the max. Aliases folds in every other member's
// own Aliases and Name, deduplicated by normalized token, excluding
// anything that normalizes to the survivor's own Name.
//
// CanonicalGroupID is resolved by consensus: if every member that resolved
// a canonical ID agrees, the survivor gets that ID; if none resolved, the
// survivor stays unresolved; if members resolved to DIFFERENT ids (a real
// contradiction -- they merged via a direct alias-token match, but MITRE's
// own data disagrees about which group they belong to), the survivor stays
// unresolved and the conflict is logged rather than silently picking one.
//
// When the survivor ends up with a resolved CanonicalGroupID, MITRE's own
// Name + Aliases for that group are folded into the survivor's Aliases too
// (active enrichment) -- so a canonically-resolved actor carries MITRE's
// authoritative alias set forward even in a future sync cycle where no
// connector happens to supply a bridging alias.
func mergeActorGroup(actors []ThreatActor, idxs []int, canonicalByActor []string, groupByID func(string) *attackdata.Group) ThreatActor {
	survivor := actors[idxs[0]]
	survivorKey := actorKey(survivor.Name)

	seenAliasTokens := make(map[string]bool, len(survivor.Aliases))
	mergedAliases := make([]string, 0, len(survivor.Aliases))
	fold := func(candidate string) {
		key := actorKey(candidate)
		if key == survivorKey || seenAliasTokens[key] {
			return
		}
		seenAliasTokens[key] = true
		mergedAliases = append(mergedAliases, candidate)
	}
	for _, alias := range survivor.Aliases {
		fold(alias)
	}

	for _, i := range idxs[1:] {
		member := actors[i]
		survivor.Techniques = mergeTechniques(survivor.Techniques, member.Techniques)
		if member.LastSeen.After(survivor.LastSeen) {
			survivor.LastSeen = member.LastSeen
		}
		fold(member.Name)
		for _, alias := range member.Aliases {
			fold(alias)
		}
	}

	resolved := map[string]bool{}
	for _, i := range idxs {
		if id := canonicalByActor[i]; id != "" {
			resolved[id] = true
		}
	}
	switch len(resolved) {
	case 1:
		for id := range resolved {
			survivor.CanonicalGroupID = id
		}
	case 0:
		survivor.CanonicalGroupID = ""
	default:
		ids := make([]string, 0, len(resolved))
		for id := range resolved {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		log.Printf("[connector] actor merge for %q: conflicting canonical MITRE group IDs %v -- leaving unresolved", survivor.Name, ids)
		survivor.CanonicalGroupID = ""
	}

	if survivor.CanonicalGroupID != "" {
		if g := groupByID(survivor.CanonicalGroupID); g != nil {
			fold(g.Name)
			for _, alias := range g.Aliases {
				fold(alias)
			}
		}
	}

	survivor.Aliases = mergedAliases
	return survivor
}

// tokenUnionFind is a simple disjoint-set over normalized identity tokens,
// used to group actors that share at least one name/alias/canonical token,
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
